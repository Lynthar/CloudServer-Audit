#!/usr/bin/env bash
#
# smoke_phaseb.sh — real-box smoke tests for the Phase B fix-mode safety work.
#
# These exercise the ACTUAL vpssec functions (not re-implementations) against
# controlled conditions, so they verify real behaviour:
#
#   * File-write / restore / backup logic runs against a temp sandbox (the
#     module path vars are overridden), and the service tools that decide the
#     success/failure branch (nginx, fail2ban-client, systemctl, confirm…) are
#     stubbed so BOTH branches can be triggered deterministically. You cannot
#     make `nginx -t` fail on demand otherwise — stubbing it is the only
#     rigorous way to prove the restore path actually restores.
#   * The SSH rescue port genuinely needs a daemon, so Tier 2 spawns REAL sshd
#     instances (a fake "production" one + the rescue one) and asserts on real
#     listening sockets and pids.
#   * The firewall path (Tier 3) drives REAL ufw when it is active.
#
# WHY IT IS SAFE TO RUN (on a throwaway box):
#   - All config writes target a mktemp sandbox, never real /etc, EXCEPT the
#     Tier 2 sshd spawn (isolated, killed on exit) and Tier 3 ufw rule (added
#     then removed). It still REFUSES to run without --yes, because it spawns
#     sshd and (optionally) touches ufw. Run it in a disposable VM/container.
#
# USAGE:
#   sudo ./tests/smoke_phaseb.sh --yes            # run everything available
#   sudo ./tests/smoke_phaseb.sh --yes --tier 1   # only the portable logic tier
#   ./tests/smoke_phaseb.sh --help
#
# EXIT: 0 if no test FAILED (skips are OK), 1 if any FAILED, 2 on bad usage.
#
# SC2329 ("function never invoked") is disabled file-wide: this harness defines
# many functions ShellCheck sees as uncalled because they are invoked
# INDIRECTLY — the stubs (nginx/systemctl/fail2ban-client/confirm/…) are called
# by the sourced production code, _cleanup runs via `trap`, and the tiers via
# `want_tier N && tierN`. Scoped here (not in .shellcheckrc) so SC2329 still
# guards real code in core/ and modules/.
# shellcheck disable=SC2329

set -uo pipefail   # NOT -e: the harness inspects non-zero results itself, which
                   # also matches how execute_fix runs fixes in production (in an
                   # `if`, i.e. with errexit suppressed for the call tree).

# ----------------------------------------------------------------------------
# Args / safety gate
# ----------------------------------------------------------------------------
FORCE=0
ONLY_TIER=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y) FORCE=1 ;;
        --tier)   ONLY_TIER="${2:-0}"; shift ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

if [[ $FORCE -ne 1 ]]; then
    cat >&2 <<'MSG'
This spawns real sshd instances and may add/remove a temporary ufw rule.
Run it ONLY on a throwaway VM/container, then re-run with --yes:

    sudo ./tests/smoke_phaseb.sh --yes
MSG
    exit 2
fi

SMOKE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SMOKE_DIR/.." && pwd)

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This smoke test must run on Linux (needs sshd/ss/nginx/etc.)." >&2
    exit 2
fi

# ----------------------------------------------------------------------------
# Sandbox + cleanup
# ----------------------------------------------------------------------------
SANDBOX=$(mktemp -d /tmp/vpssec-smoke.XXXXXX)
CLEANUP_PIDS=()
UFW_TEST_PORT=""

_cleanup() {
    local p
    for p in "${CLEANUP_PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
    done
    # Best-effort removal of a leaked Tier-3 ufw test rule.
    if [[ -n "$UFW_TEST_PORT" ]] && command -v ufw >/dev/null 2>&1; then
        ufw delete allow "$UFW_TEST_PORT/tcp" >/dev/null 2>&1 || true
    fi
    rm -rf "$SANDBOX"
}
trap _cleanup EXIT INT TERM

# ----------------------------------------------------------------------------
# Load vpssec exactly as the entry script does, then redirect state/backups
# into the sandbox (mirrors tests/helpers.bash: override AFTER sourcing).
# ----------------------------------------------------------------------------
export VPSSEC_LANG=en_US VPSSEC_COLOR=0 VPSSEC_JSON_ONLY=0 VPSSEC_QUIET_SCAN=1

# shellcheck source=/dev/null
source "$REPO/core/common.sh"
set +e   # common.sh enabled errexit; turn it back off for the harness.

export VPSSEC_STATE="$SANDBOX/state" VPSSEC_BACKUPS="$SANDBOX/backups" \
       VPSSEC_LOGS="$SANDBOX/logs"
mkdir -p "$VPSSEC_STATE" "$VPSSEC_BACKUPS" "$VPSSEC_LOGS"
chmod 700 "$VPSSEC_STATE"

for f in core/distro.sh core/state.sh core/engine.sh \
         modules/ssh.sh modules/webapp.sh modules/kernel.sh \
         modules/fail2ban.sh modules/filesystem.sh modules/baseline.sh; do
    # shellcheck source=/dev/null
    source "$REPO/$f" || { echo "failed to source $f" >&2; exit 1; }
done

# ----------------------------------------------------------------------------
# Mini harness
# ----------------------------------------------------------------------------
PASS=0; FAIL=0; SKIP=0; FAILED=()
section() { printf '\n=== %s ===\n' "$1"; }
ok()    { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
no()    { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
skip_() { printf '  [SKIP] %s — %s\n' "$1" "$2"; SKIP=$((SKIP+1)); }

want_tier() { [[ $ONLY_TIER -eq 0 || $ONLY_TIER -eq $1 ]]; }

# Save a shell function's current definition so a stub can be reverted to the
# real one afterwards (unset -f would delete the real function for good).
save_fn()    { declare -f "$1" 2>/dev/null; }
restore_fn() { local d="$1"; [[ -n "$d" ]] && eval "$d"; }

# ============================================================================
# Tier 1 — portable logic (temp paths + stubs; deterministic, no real services)
# ============================================================================
tier1() {
    section "Tier 1.1: engine confirm/risky gating (execute_fix)"
    local sentinel="$SANDBOX/sentinel"
    local s_smfc s_cc s_cf s_uf s_sf s_uw
    s_smfc=$(save_fn state_mark_fix_complete); state_mark_fix_complete() { :; }
    s_cc=$(save_fn confirm_critical)
    s_cf=$(save_fn confirm)
    s_uf=$(save_fn update_fix)
    s_sf=$(save_fn ssh_fix)
    s_uw=$(save_fn ufw_fix)
    # Stub the module dispatchers so we can detect whether the gate let the fix
    # reach the module (sentinel) without running any real fix.
    update_fix() { touch "$sentinel"; return 0; }
    ssh_fix()    { touch "$sentinel"; return 0; }
    ufw_fix()    { touch "$sentinel"; return 0; }

    # RISKY fix, confirm declines -> must NOT run the module fix.
    confirm_critical() { return 1; }
    rm -f "$sentinel"; execute_fix "update.apply_security" >/dev/null 2>&1; local rc=$?
    if [[ ! -e "$sentinel" && $rc -ne 0 ]]; then
        ok "risky fix blocked when confirm_critical declines (module fix not run)"
    else no "risky fix NOT blocked on decline (rc=$rc, sentinel=$([[ -e $sentinel ]] && echo yes || echo no))"; fi

    # RISKY fix, confirm accepts -> runs.
    confirm_critical() { return 0; }
    rm -f "$sentinel"; execute_fix "update.apply_security" >/dev/null 2>&1; rc=$?
    if [[ -e "$sentinel" && $rc -eq 0 ]]; then ok "risky fix runs once confirmed"
    else no "risky fix did not run when confirmed (rc=$rc)"; fi

    # SAFE fix -> never gated (even with both prompts set to decline).
    confirm_critical() { return 1; }; confirm() { return 1; }
    rm -f "$sentinel"; execute_fix "ssh.disable_empty_password" >/dev/null 2>&1; rc=$?
    if [[ -e "$sentinel" && $rc -eq 0 ]]; then ok "safe fix runs with no gate"
    else no "safe fix was unexpectedly gated (rc=$rc)"; fi

    # SELF-CONFIRM fix (in FIX_SELF_CONFIRMED) -> engine must NOT gate it.
    rm -f "$sentinel"; execute_fix "ssh.disable_password_auth" >/dev/null 2>&1; rc=$?
    if [[ -e "$sentinel" && $rc -eq 0 ]]; then ok "self-confirming fix not double-gated by engine"
    else no "self-confirming fix was gated by engine (rc=$rc)"; fi

    # CONFIRM-class fix -> gated by confirm(); decline blocks, accept runs.
    # ssh.harden_algorithms is a genuine CONFIRM fix dispatched via the
    # stubbed ssh_fix (ufw.set_default_deny was reclassified to RISKY).
    confirm() { return 1; }
    rm -f "$sentinel"; execute_fix "ssh.harden_algorithms" >/dev/null 2>&1; rc=$?
    if [[ ! -e "$sentinel" && $rc -ne 0 ]]; then ok "confirm-class fix blocked when declined"
    else no "confirm-class fix not blocked on decline (rc=$rc)"; fi
    confirm() { return 0; }
    rm -f "$sentinel"; execute_fix "ssh.harden_algorithms" >/dev/null 2>&1; rc=$?
    if [[ -e "$sentinel" && $rc -eq 0 ]]; then ok "confirm-class fix runs when confirmed"
    else no "confirm-class fix did not run when confirmed (rc=$rc)"; fi

    # RISKY reclassification: ufw.set_default_deny must be gated by
    # confirm_critical (which ignores --yes), NOT by confirm(). With confirm
    # accepting but confirm_critical declining, the fix must be blocked.
    confirm() { return 0; }; confirm_critical() { return 1; }
    rm -f "$sentinel"; execute_fix "ufw.set_default_deny" >/dev/null 2>&1; rc=$?
    if [[ ! -e "$sentinel" && $rc -ne 0 ]]; then ok "ufw.set_default_deny gated by confirm_critical, not confirm"
    else no "ufw.set_default_deny not gated by confirm_critical (rc=$rc)"; fi

    restore_fn "$s_smfc"; restore_fn "$s_cc"; restore_fn "$s_cf"
    restore_fn "$s_uf"; restore_fn "$s_sf"; restore_fn "$s_uw"

    section "Tier 1.2: SSH rescue-port selection avoids the live/in-use port"
    local s_gp s_gl
    s_gp=$(save_fn get_ssh_port); s_gl=$(save_fn get_listening_ports)
    get_ssh_port() { echo 2222; }
    get_listening_ports() { printf '2222\n'; }
    local port; port=$(_ssh_pick_rescue_port)
    if [[ -n "$port" && "$port" != "2222" ]]; then
        ok "picks a port other than the live SSH port 2222 (chose $port)"
    else no "picked the live port or nothing (chose '$port')"; fi
    restore_fn "$s_gp"; restore_fn "$s_gl"

    section "Tier 1.3: nginx server_tokens restore-on-failure"
    NGINX_CONF="$SANDBOX/nginx.conf"
    printf 'http {\n    sendfile on;\n}\n' > "$NGINX_CONF"
    local orig; orig=$(cat "$NGINX_CONF")
    nginx() { return 1; }; systemctl() { return 0; }   # force nginx -t failure
    _webapp_fix_nginx_server_tokens >/dev/null 2>&1; local rc=$?
    unset -f nginx systemctl
    if [[ "$(cat "$NGINX_CONF")" == "$orig" && $rc -ne 0 ]]; then
        ok "nginx.conf restored to original after nginx -t fails"
    else no "nginx.conf NOT restored on failure (rc=$rc)"; fi
    nginx() { return 0; }; systemctl() { return 0; }   # success branch
    _webapp_fix_nginx_server_tokens >/dev/null 2>&1; rc=$?
    unset -f nginx systemctl
    if grep -q 'server_tokens off' "$NGINX_CONF" && [[ $rc -eq 0 ]]; then
        ok "server_tokens edit kept when nginx -t passes"
    else no "success path did not keep the edit (rc=$rc)"; fi

    section "Tier 1.4: nginx security-headers restore/remove-on-failure"
    NGINX_CONFD="$SANDBOX/conf.d"; mkdir -p "$NGINX_CONFD"
    local hdr="$NGINX_CONFD/security-headers.conf"
    rm -f "$hdr"
    nginx() { return 1; }; systemctl() { return 0; }   # new file + failure -> remove
    _webapp_fix_nginx_security_headers >/dev/null 2>&1; rc=$?
    unset -f nginx systemctl
    if [[ ! -e "$hdr" && $rc -ne 0 ]]; then
        ok "newly written headers drop-in removed after nginx -t fails"
    else no "headers drop-in left behind on failure (rc=$rc)"; fi
    printf '# preexisting\n' > "$hdr"; local hdr_orig; hdr_orig=$(cat "$hdr")
    nginx() { return 1; }; systemctl() { return 0; }   # pre-existing + failure -> restore
    _webapp_fix_nginx_security_headers >/dev/null 2>&1; rc=$?
    unset -f nginx systemctl
    if [[ "$(cat "$hdr")" == "$hdr_orig" && $rc -ne 0 ]]; then
        ok "pre-existing headers drop-in restored after nginx -t fails"
    else no "pre-existing headers drop-in not restored (rc=$rc)"; fi

    section "Tier 1.5: kernel sysctl atomic write + backup"
    SYSCTL_D="$SANDBOX/sysctl.d"; VPSSEC_SYSCTL_CONF="$SYSCTL_D/99-vpssec-hardening.conf"
    mkdir -p "$SYSCTL_D"
    _kernel_write_sysctl "net.ipv4.tcp_syncookies" "1"
    _kernel_write_sysctl "kernel.kptr_restrict" "2"
    if grep -q 'net.ipv4.tcp_syncookies = 1' "$VPSSEC_SYSCTL_CONF" 2>/dev/null \
       && grep -q 'kernel.kptr_restrict = 2' "$VPSSEC_SYSCTL_CONF" 2>/dev/null; then
        ok "both sysctl params persisted to the drop-in"
    else no "sysctl drop-in missing expected params"; fi
    if [[ -n "$(find "$VPSSEC_BACKUPS" -name '99-vpssec-hardening.conf' 2>/dev/null)" ]]; then
        ok "prior sysctl drop-in was backed up before the second write"
    else no "no backup created for the sysctl drop-in"; fi

    section "Tier 1.6: fail2ban jail.local validate + restore-on-failure"
    F2B_JAIL_LOCAL="$SANDBOX/jail.local"
    printf '# original jail.local\n[sshd]\nenabled = true\n' > "$F2B_JAIL_LOCAL"
    local jail_orig; jail_orig=$(cat "$F2B_JAIL_LOCAL")
    # Deterministic detect helpers + service stubs.
    local s_lp s_be s_ba s_act s_en s_gp2
    s_lp=$(save_fn _f2b_detect_ssh_logpath); s_be=$(save_fn _f2b_detect_backend)
    s_ba=$(save_fn _f2b_detect_banaction);   s_act=$(save_fn _f2b_service_active)
    s_en=$(save_fn _f2b_ssh_jail_enabled);   s_gp2=$(save_fn get_ssh_port)
    _f2b_detect_ssh_logpath() { echo /var/log/auth.log; }
    _f2b_detect_backend() { echo systemd; }
    _f2b_detect_banaction() { echo iptables-multiport; }
    _f2b_service_active() { return 1; }
    _f2b_ssh_jail_enabled() { return 0; }
    get_ssh_port() { echo 22; }
    fail2ban-client() { [[ "${1:-}" == "-t" ]] && return 1; return 0; }   # config test fails
    systemctl() { return 0; }
    _f2b_fix_configure_ssh_jail >/dev/null 2>&1; rc=$?
    if [[ "$(cat "$F2B_JAIL_LOCAL")" == "$jail_orig" && $rc -ne 0 ]]; then
        ok "jail.local restored after fail2ban-client -t fails"
    else no "jail.local NOT restored on validation failure (rc=$rc)"; fi
    fail2ban-client() { return 0; }   # -t passes now
    _f2b_fix_configure_ssh_jail >/dev/null 2>&1; rc=$?
    if grep -q 'vpssec fail2ban configuration' "$F2B_JAIL_LOCAL" 2>/dev/null && [[ $rc -eq 0 ]]; then
        ok "new jail.local written when config test passes"
    else no "success path did not write the new jail.local (rc=$rc)"; fi
    unset -f fail2ban-client systemctl
    restore_fn "$s_lp"; restore_fn "$s_be"; restore_fn "$s_ba"
    restore_fn "$s_act"; restore_fn "$s_en"; restore_fn "$s_gp2"

    section "Tier 1.7: filesystem backs up before chmod (mode recoverable)"
    # NOTE: _fs_fix_sensitive_perms also scans /etc/sudoers.d and
    # /etc/ssh/sshd_config.d; on a correctly-configured box those are already
    # tight, so it changes nothing there. We point it at one sandbox file.
    local s_fsf; s_fsf=$(declare -p FS_SENSITIVE_FILES 2>/dev/null)
    local fakefile="$SANDBOX/fake-sensitive"
    : > "$fakefile"; chmod 0666 "$fakefile"
    FS_SENSITIVE_FILES=( ["$fakefile"]="600" )
    _fs_fix_sensitive_perms >/dev/null 2>&1
    local mode; mode=$(stat -c '%a' "$fakefile" 2>/dev/null)
    if [[ "$mode" == "600" ]]; then
        ok "sensitive file chmod applied (0666 -> 0$mode)"
    else
        no "sensitive file not chmod'd (mode=$mode)"
    fi
    if [[ -n "$(find "$VPSSEC_BACKUPS" -name 'fake-sensitive' 2>/dev/null)" ]]; then
        ok "sensitive file backed up before chmod (prior mode recoverable on rollback)"
    else
        no "no backup created before chmod"
    fi
    [[ -n "$s_fsf" ]] && eval "$s_fsf"
}

# ============================================================================
# Tier 2 — real sshd: rescue daemon bind, pid-verification, kill-by-pid safety
# ============================================================================
tier2() {
    section "Tier 2: SSH rescue daemon (real sshd)"
    if [[ ! -x /usr/sbin/sshd ]]; then
        skip_ "rescue daemon tests" "/usr/sbin/sshd not present (install openssh-server)"
        return
    fi
    # Preconditions for spawning sshd.
    command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -A >/dev/null 2>&1 || true
    mkdir -p /run/sshd 2>/dev/null || true

    # Choose a free "production" port (prefer 2222 to mirror the real bug).
    local prod_port=""
    local c
    for c in 2222 2022 2200 22022; do
        if ! ss -tln 2>/dev/null | grep -qE ":${c}[[:space:]]"; then prod_port="$c"; break; fi
    done
    if [[ -z "$prod_port" ]]; then
        skip_ "rescue daemon tests" "no free port available for a fake production sshd"
        return
    fi

    # Start a fake "production" sshd on prod_port.
    local prod_cfg="$SANDBOX/prod_sshd.conf" prod_pidfile="$SANDBOX/prod_sshd.pid"
    printf 'Port %s\nPidFile %s\n' "$prod_port" "$prod_pidfile" > "$prod_cfg"
    /usr/sbin/sshd -D -f "$prod_cfg" >/dev/null 2>&1 &
    local prod_pid=$!
    CLEANUP_PIDS+=("$prod_pid")
    local i
    for ((i=0; i<30; i++)); do
        ss -tln 2>/dev/null | grep -qE ":${prod_port}[[:space:]]" && break
        sleep 0.1
    done
    if ! kill -0 "$prod_pid" 2>/dev/null || ! ss -tln 2>/dev/null | grep -qE ":${prod_port}[[:space:]]"; then
        skip_ "rescue daemon tests" "could not start a fake production sshd (PrivSep/host keys?)"
        return
    fi
    ok "fake production sshd is listening on port $prod_port (pid $prod_pid)"

    # Make the rescue logic believe the live SSH port is prod_port, and keep the
    # firewall out of this tier (covered in Tier 3).
    local s_gp s_fw
    s_gp=$(save_fn get_ssh_port); s_fw=$(save_fn fw_backend)
    get_ssh_port() { echo "$prod_port"; }
    fw_backend() { echo none; }

    _ssh_open_rescue_port >/dev/null 2>&1
    local opened=$?
    if [[ $opened -ne 0 ]]; then
        no "rescue open failed (rc=$opened); skipping remaining rescue assertions"
        restore_fn "$s_gp"; restore_fn "$s_fw"
        kill "$prod_pid" 2>/dev/null || true
        return
    fi

    if [[ "${SSH_RESCUE_PORT:-}" != "$prod_port" ]]; then
        ok "rescue port ($SSH_RESCUE_PORT) differs from the live SSH port ($prod_port)"
    else
        no "rescue port collided with the live port ($prod_port)"
    fi

    # Directly verify the config-content fix: a standalone config with NO
    # Include of the live sshd_config (the Include re-imported the live Port and
    # caused the EADDRINUSE no-op), declaring our chosen Port.
    if [[ -f "${SSH_RESCUE_CONFIG:-/nonexistent}" ]]; then
        if ! grep -qiE '^[[:space:]]*Include' "$SSH_RESCUE_CONFIG" \
           && grep -qE "^Port ${SSH_RESCUE_PORT}\$" "$SSH_RESCUE_CONFIG"; then
            ok "rescue config is standalone (no Include) and declares Port $SSH_RESCUE_PORT"
        else
            no "rescue config unexpected (Include present, or Port missing)"
        fi
    else
        no "rescue config file not found for inspection"
    fi

    if _ssh_rescue_is_up; then
        ok "rescue daemon is up and OUR pid ($SSH_RESCUE_PID) owns the listening socket"
    else
        no "rescue daemon not verified up via our pid"
    fi

    # Capture identifiers before teardown.
    local rescue_pid="${SSH_RESCUE_PID:-}" rescue_port="${SSH_RESCUE_PORT:-}"
    _ssh_close_rescue_port >/dev/null 2>&1

    # kill(1) is asynchronous — poll (<=3s) for the daemon to exit and the port
    # to free before asserting, so a slow teardown doesn't cause a false fail.
    local i
    for ((i=0; i<30; i++)); do kill -0 "$rescue_pid" 2>/dev/null || break; sleep 0.1; done
    if [[ -n "$rescue_pid" ]] && ! kill -0 "$rescue_pid" 2>/dev/null; then
        ok "close killed the rescue daemon (pid $rescue_pid gone)"
    else
        no "rescue daemon still alive after close (pid $rescue_pid)"
    fi
    for ((i=0; i<30; i++)); do ss -tln 2>/dev/null | grep -qE ":${rescue_port}[[:space:]]" || break; sleep 0.1; done
    if [[ -n "$rescue_port" ]] && ! ss -tln 2>/dev/null | grep -qE ":${rescue_port}[[:space:]]"; then
        ok "rescue port $rescue_port no longer listening after close"
    else
        no "rescue port $rescue_port still listening after close"
    fi
    # The crucial regression: close must NOT have killed the production sshd.
    if kill -0 "$prod_pid" 2>/dev/null; then
        ok "production sshd (port $prod_port) survived rescue teardown (kill-by-pid, not port-grep)"
    else
        no "production sshd was killed by rescue teardown — kill-by-port regression!"
    fi

    restore_fn "$s_gp"; restore_fn "$s_fw"
    kill "$prod_pid" 2>/dev/null || true
}

# ============================================================================
# Tier 3 — real ufw: rescue firewall rule add + exact teardown
# ============================================================================
tier3() {
    section "Tier 3: rescue firewall rule (real ufw)"
    if ! command -v ufw >/dev/null 2>&1; then
        skip_ "ufw rescue rule test" "ufw not installed"; return
    fi
    if [[ "$(fw_backend 2>/dev/null)" != "ufw" ]]; then
        skip_ "ufw rescue rule test" "ufw is not the active firewall backend"; return
    fi
    # Pick a free high port for the rule.
    local p
    for p in 52222 52223 52224; do
        ss -tln 2>/dev/null | grep -qE ":${p}[[:space:]]" || break
    done
    UFW_TEST_PORT="$p"
    SSH_RESCUE_PORT="$p"; SSH_RESCUE_FW_RULE=""
    local s_ip; s_ip=$(save_fn get_current_ssh_ip)
    get_current_ssh_ip() { echo ""; }   # exercise the port-wide allow branch

    _ssh_rescue_allow_firewall >/dev/null 2>&1
    if ufw status 2>/dev/null | grep -qE "(^|[[:space:]])${p}/tcp"; then
        ok "rescue ufw rule for $p/tcp added"
    else
        no "rescue ufw rule for $p/tcp was not added"
    fi
    _ssh_rescue_remove_firewall >/dev/null 2>&1
    if ! ufw status 2>/dev/null | grep -qE "(^|[[:space:]])${p}/tcp"; then
        ok "rescue ufw rule for $p/tcp removed (exact teardown)"
    else
        no "rescue ufw rule for $p/tcp left behind after teardown"
    fi
    restore_fn "$s_ip"
    UFW_TEST_PORT=""
}

# ----------------------------------------------------------------------------
want_tier 1 && tier1
want_tier 2 && tier2
want_tier 3 && tier3

section "Summary"
printf '  PASS=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [[ $FAIL -gt 0 ]]; then
    printf '\nFailed checks:\n'
    for f in "${FAILED[@]}"; do printf '  - %s\n' "$f"; done
    exit 1
fi
echo "  OK"
exit 0
