#!/usr/bin/env bats
# "A failed query is not a clean result." An audit that cannot answer must report
# the non-observation (failed + info-category, unscored) or fail loudly — never
# fold it into the green path as "no updates" or "0 failed logins".

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
}

# ---- cloudflared -------------------------------------------------------

@test "cloudflared: a tunnel list that cannot be read is failed and unscored, not a pass" {
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"
    _vpssec_stub cloudflared 1

    # `run`: production calls audits in a condition, where a failed query does
    # not abort; bats' own errexit would.
    run _cloudflared_audit_tunnels

    run jq -r '.[] | select(.id == "cloudflared.tunnel_list_unavailable") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    [ "${CHECK_SCORE_CATEGORY[cloudflared.tunnel_list_unavailable]}" = "info" ]
}

# ---- update ------------------------------------------------------------

@test "update: query failure emits update.check_failed, not no_updates" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { return 1; }
    pkg_security_update_count() { return 1; }

    _update_audit_available

    run jq -r '.[] | select(.id == "update.check_failed") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "update.no_updates") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

@test "update: the refresh it suggests is this host's command, or none is named" {
    # Listing all three managers told Arch hosts `pacman -Sy`, a partial upgrade.
    source "$(_vpssec_repo_root)/core/distro.sh"
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { return 1; }
    pkg_security_update_count() { return 1; }

    VPSSEC_PKG_MGR=pacman
    _update_audit_available
    run jq -r '.[] | select(.id == "update.check_failed") | .suggestion' "$VPSSEC_STATE/checks.json"
    [ "$output" = "Refresh the package index (pacman -Syu) and re-run the audit" ]

    VPSSEC_PKG_MGR=unknown
    _update_audit_available
    run jq -r '[.[] | select(.id == "update.check_failed")] | last | .suggestion' "$VPSSEC_STATE/checks.json"
    [ "$output" = "Refresh the package index with the system package manager and re-run the audit" ]
}

@test "update: an unknown lock state names the tool this host's probe lacks" {
    # The dnf branch needs pgrep, not lsof, and no host is "APT" but Debian's.
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_manager_locked() { return 2; }

    VPSSEC_DISTRO_FAMILY=rhel VPSSEC_PKG_MGR=dnf
    _update_audit_apt_lock
    run jq -r '.[] | select(.id == "update.lock_state_unknown") | .desc + "|" + .suggestion' \
        "$VPSSEC_STATE/checks.json"
    [[ "$output" == *pgrep*"dnf install procps-ng"* ]]
    [[ "$output" != *lsof* ]]

    pkg_manager_locked() { return 1; }
    _update_audit_apt_lock
    run jq -r '.[] | select(.id == "update.apt_available") | .title' "$VPSSEC_STATE/checks.json"
    [ -n "$output" ]
    [[ "$output" != *APT* ]]
}

@test "update: a real zero still passes as no_updates" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { echo 0; }
    pkg_security_update_count() { echo 0; }
    pkg_index_age_days() { echo 1; }

    _update_audit_available

    run jq -r '.[] | select(.id == "update.no_updates") | "\(.status) \(.desc)"' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "passed Package index refreshed 1 day(s) ago" ]
}

# A fresh VPS often has no apt lists at all, and an apt query on them succeeds
# with nothing to install: zero from an index that cannot know is not "up to date".
@test "update: zero from an index never refreshed is unknown, not no_updates" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { echo 0; }
    pkg_security_update_count() { echo 0; }
    pkg_index_age_days() { return 0; }

    _update_audit_available

    run jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
    [ "$output" = "update.index_stale failed" ]
    [ "${CHECK_SCORE_CATEGORY[update.index_stale]}" = "info" ]
}

@test "update: zero from an index older than the stale limit is unknown too" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { echo 0; }
    pkg_security_update_count() { echo 0; }
    pkg_index_age_days() { echo $(( UPDATE_INDEX_STALE_DAYS + 1 )); }

    _update_audit_available

    run jq -r '.[] | "\(.id) \(.desc)"' "$VPSSEC_STATE/checks.json"
    [[ "$output" == "update.index_stale "*"$(( UPDATE_INDEX_STALE_DAYS + 1 )) days ago"* ]]

    rm -f "$VPSSEC_STATE/checks.json"; state_init
    pkg_index_age_days() { echo "$UPDATE_INDEX_STALE_DAYS"; }
    _update_audit_available
    run jq -r '.[].id' "$VPSSEC_STATE/checks.json"
    [ "$output" = "update.no_updates" ]
}

# ---- logging -----------------------------------------------------------

@test "logging: journalctl failure emits journal_unreadable, not ssh_logs_ok" {
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _vpssec_stub journalctl 1

    _logging_audit_ssh_logs

    run jq -r '.[] | select(.id == "logging.journal_unreadable") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "logging.ssh_logs_ok") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

@test "logging: working journalctl with zero failures still passes" {
    # A journal with nothing matching prints this line, never nothing.
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _vpssec_stub journalctl 0 "-- No entries --"

    _logging_audit_ssh_logs

    run jq -r '.[] | select(.id == "logging.ssh_logs_ok") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "passed" ]
}

# journalctl as systemd 249-255 answers with no journal files at all: the
# marker on stdout, the notice on stderr, and exit 0.
_journal_absent() {
    _vpssec_stub_script journalctl <<'SH'
echo "-- No entries --"
echo "No journal files were found." >&2
exit 0
SH
}

_logging_emitted() {
    jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
}

@test "logging: no journal at all is unreadable, not 0 failures and 1 sudo event" {
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _journal_absent

    _logging_audit_ssh_logs
    _logging_audit_sudo_logs
    [ "$(_logging_emitted)" = "logging.journal_unreadable failed" ]
}

@test "logging: no sudo entries is no events, not one" {
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _vpssec_stub journalctl 0 "-- No entries --"

    _logging_audit_sudo_logs
    [ "$(_logging_emitted)" = "logging.sudo_no_events passed" ]
}

@test "logging: one sudo command is one event, not its three journal lines" {
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _vpssec_stub_script journalctl <<'SH'
printf '%s\n' \
  "Oct 09 10:00:01 host sudo[812]:     root : PWD=/root ; USER=nobody ; COMMAND=/usr/bin/true" \
  "Oct 09 10:00:01 host sudo[812]: pam_unix(sudo:session): session opened for user nobody(uid=65534) by root(uid=0)" \
  "Oct 09 10:00:01 host sudo[812]: pam_unix(sudo:session): session closed for user nobody"
SH

    _logging_audit_sudo_logs
    [ "$(_logging_emitted)" = "logging.sudo_logging_ok passed" ]
    run jq -r '.[0].title' "$VPSSEC_STATE/checks.json"
    [ "$output" = "$(i18n 'logging.sudo_logs_active' 'count=1')" ]
}

# ---- users -------------------------------------------------------------

# users_audit over one fixture account database; $1 = 1 makes getent passwd fail.
_users_with() {
    source "$(_vpssec_repo_root)/modules/users.sh"
    VPSSEC_CLOUD_PROVIDER=unknown
    USERS_SHADOW_FILE="$BATS_TEST_TMPDIR/shadow"
    USERS_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"; : > "$USERS_LOGIN_DEFS"
    USERS_PWQUALITY_CONF="$BATS_TEST_TMPDIR/pwquality.conf"
    SUDOERS_FILE="$BATS_TEST_TMPDIR/sudoers"; : > "$SUDOERS_FILE"
    export FAKE_PASSWD="$BATS_TEST_TMPDIR/passwd" GETENT_FAILS="$1"
    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'eve::1001:1001::/home/eve:/bin/bash' > "$FAKE_PASSWD"
    _vpssec_stub_script getent <<'SH'
[[ "$1" == passwd && "$GETENT_FAILS" != 1 ]] || exit 2
[[ -z "${2:-}" ]] && { cat "$FAKE_PASSWD"; exit 0; }
awk -F: -v k="$2" '$1 == k { print; f = 1 } END { exit !f }' "$FAKE_PASSWD"
SH
    _users_audit
}

# As audit_module runs it: in a condition, so errexit is off as in production.
_users_audit() { if users_audit; then :; fi; }

_status_of() { jq -r --arg id "$1" '.[] | select(.id == $id) | .status' "$VPSSEC_STATE/checks.json"; }

@test "users: a failing getent passwd is unknown, not uid0_ok or no_empty_password" {
    : > "$BATS_TEST_TMPDIR/shadow"
    _users_with 1
    [ "$(_status_of users.uid0_unknown)" = failed ]
    [ "$(_status_of users.empty_password_unknown)" = failed ]
    [ -z "$(_status_of users.uid0_ok)" ]
    [ -z "$(_status_of users.no_empty_password)" ]
}

@test "users: an unreadable shadow is unknown, but an inline empty password is still found" {
    _users_with 0
    [ "$(_status_of users.uid0_ok)" = passed ]
    [ -z "$(_status_of users.no_empty_password)" ]
    [ "$(jq -r '.[] | select(.id == "users.empty_password") | .desc' "$VPSSEC_STATE/checks.json")" = eve ]

    sed -i 's/^eve::/eve:x:/' "$FAKE_PASSWD"
    state_init
    _users_audit
    [ "$(_status_of users.empty_password_unknown)" = failed ]
    [ -z "$(_status_of users.no_empty_password)" ]
}

@test "users: readable sources with no finding still pass" {
    : > "$BATS_TEST_TMPDIR/shadow"
    _users_with 0
    sed -i 's/^eve::/eve:x:/' "$FAKE_PASSWD"
    state_init
    _users_audit
    [ "$(_status_of users.uid0_ok)" = passed ]
    [ "$(_status_of users.no_empty_password)" = passed ]
}

# ---- kernel ------------------------------------------------------------

@test "kernel: zero readable sysctls emits network_params_unreadable, not OK" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _kernel_get_sysctl() { echo ""; }
    _kernel_ipv6_uses_ra() { return 1; }
    _kernel_ip_forward_needed() { return 1; }

    # `run`, not a bare call: the production engine dispatches audits inside
    # an `if` (errexit suppressed), and this function relies on that — an
    # assignment from rc-2 _kernel_check_param aborts it under bare set -e.
    run _kernel_audit_network_params

    run jq -r '.[] | select(.id == "kernel.network_params_unreadable") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "kernel.network_params_ok") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

# ---- networking: specific-public binds --------------------------------

@test "networking: dangerous service on a specific PUBLIC address is flagged" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _net_list_listeners() {
        printf 'tcp\tv4\t203.0.113.10\t3306\tmysqld\n'
        printf 'tcp\tv4\t192.168.1.5\t3306\tmysqld\n'
    }

    _net_audit_listeners

    run jq -r '.[] | select(.id == "networking.exposed_dangerous_ports") | .desc' \
        "$VPSSEC_STATE/checks.json"
    [[ "$output" == *"3306@203.0.113.10"* ]]
    # The RFC1918 bind must NOT appear — operator context required there.
    _vpssec_refute grep -q "192.168.1.5" <<<"$output"
}

@test "networking: private-only specific binds still produce no exposure finding" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _net_list_listeners() {
        printf 'tcp\tv4\t10.0.0.5\t3306\tmysqld\n'
    }

    _net_audit_listeners

    run jq -r '.[] | select(.id == "networking.exposed_dangerous_ports") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "networking: public/private address classifier boundaries" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _net_specific_addr_is_public v4 203.0.113.10
    _net_specific_addr_is_public v6 2001:db8::1
    _vpssec_refute _net_specific_addr_is_public v4 10.1.2.3
    _vpssec_refute _net_specific_addr_is_public v4 172.16.0.1
    # 172.32.x is PUBLIC (outside 172.16/12) — the boundary must not overreach
    _net_specific_addr_is_public v4 172.32.0.1
    _vpssec_refute _net_specific_addr_is_public v4 192.168.9.9
    _vpssec_refute _net_specific_addr_is_public v4 100.64.0.1
    _vpssec_refute _net_specific_addr_is_public v4 169.254.1.1
    _vpssec_refute _net_specific_addr_is_public v6 fe80::1
    _vpssec_refute _net_specific_addr_is_public v6 fd00::1
}

# ---- networking: a tool that failed is not "nothing found" ----------------

_net_emitted() {
    jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
}

@test "networking: ip failing is unknown, not 'no promiscuous interfaces'" {
    # A sandbox that blocks AF_NETLINK: ip exits 1, ss falls back to /proc.
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _vpssec_stub ip 1
    _vpssec_stub ss 0 ""

    networking_audit >/dev/null
    [ "$(_net_emitted)" = "networking.promisc_unknown failed" ]
    [ "${CHECK_SCORE_CATEGORY[networking.promisc_unknown]}" = "info" ]
}

@test "networking: ss failing both ways is unknown, not silence" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _vpssec_stub ss 1
    _vpssec_stub ip 0 "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN"

    networking_audit >/dev/null
    [ "$(_net_emitted)" = "networking.listeners_unknown failed,networking.no_promisc passed" ]
    [ "${CHECK_SCORE_CATEGORY[networking.listeners_unknown]}" = "info" ]
}

@test "networking: a promiscuous interface is still reported" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _vpssec_stub ss 0 ""
    _vpssec_stub ip 0 "2: eth0: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq state UP"

    networking_audit >/dev/null
    [ "$(_net_emitted)" = "networking.promiscuous_interface failed" ]
}

# ---- backup_file failure propagation -----------------------------------

@test "backup_file: cp failure returns 1 and echoes no path" {
    _vpssec_begin_backup_session
    local target="$BATS_TEST_TMPDIR/etcfile"
    echo "content" > "$target"
    _vpssec_stub cp 1

    run backup_file "$target"
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q "$VPSSEC_BACKUP_SESSION" <<<"$output"
}

@test "backup_restore: uncopyable entry counts as skipped, not restored" {
    # Occupy the restore DESTINATION's parent position with a regular file,
    # so `mkdir -p` fails for root and non-root alike (root ignores mode
    # bits, but a file where a directory must go stops everyone).
    local blockdir="$BATS_TEST_TMPDIR/blockdir"
    echo "i am a file, not a directory" > "$blockdir"

    local ts="$VPSSEC_TEST_BACKUP_SESSION_TS"
    local bdir="$VPSSEC_BACKUPS/$ts"
    mkdir -p "$bdir$blockdir"
    echo "old content" > "$bdir$blockdir/target"

    run backup_restore "$ts"
    # Nothing restored, one skip -> rc 1 and the "0 restored" error path.
    [ "$status" -eq 1 ]
}

# ---- update: auto-update state ------------------------------------------

@test "update: an unreadable auto-update state is reported as unknown, not disabled" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    auto_update_status() { echo "unknown"; return 1; }
    auto_update_installed() { return 0; }

    _update_audit_unattended

    run jq -r '.[] | select(.id == "update.unattended_state_unknown") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "update.unattended_disabled" or .id == "update.unattended_enabled") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
    [ "${CHECK_SCORE_CATEGORY[update.unattended_state_unknown]}" = "info" ]
}

# ---- kernel: IPv6 firewall ----------------------------------------------

# kernel's IPv6 audit on a host using IPv6 with no sysctl findings, so only the
# firewall line varies; the firewall tools answer as the test stubbed them.
_kernel_ipv6_fw_emitted() {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _kernel_ipv6_enabled() { return 0; }
    _kernel_ipv6_in_use() { return 0; }
    _kernel_ipv6_get_stats() { echo ""; }
    _kernel_ipv6_check_security() { echo ""; }
    _kernel_audit_ipv6 >/dev/null
    jq -r '[.[] | select(.id | startswith("kernel.ipv6_firewall")) | "\(.id) \(.status)"] | join(",")' \
        "$VPSSEC_STATE/checks.json"
}

# ip6tables with an accepting INPUT chain, answering `-L -n` and `-S INPUT` as
# the real tool does; with $1 = docker, FORWARD carries Docker's jumps.
_ip6tables_accepting() {
    local fwd=""
    [[ "${1:-}" == docker ]] && fwd='DOCKER-USER  all      ::/0                 ::/0
DOCKER-FORWARD  all      ::/0                 ::/0'
    printf '%s\n' "$fwd" > "$BATS_TEST_TMPDIR/ip6.fwd"
    _vpssec_stub_script ip6tables <<SH
case "\$*" in
    "-S INPUT") echo "-P INPUT ACCEPT" ;;
    "-L -n")
        printf '%s\n' "Chain INPUT (policy ACCEPT)" "target     prot opt source               destination" ""
        printf '%s\n' "Chain FORWARD (policy ACCEPT)" "target     prot opt source               destination"
        cat "$BATS_TEST_TMPDIR/ip6.fwd" ;;
esac
exit 0
SH
}

@test "kernel: firewalld filters IPv6, though ip6tables' own table is empty" {
    # RHEL: firewalld's rules live in nft's inet firewalld table, and it pulls
    # in iptables-nft, so ip6tables is there and lists nothing.
    _fw_probes_answer 'exit 0'
    _vpssec_stub systemctl 0
    _ip6tables_accepting
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_ok passed" ]
}

@test "kernel: an nftables inet table that drops input filters IPv6" {
    # Debian's stock /etc/nftables.conf, with ip6tables (xtables-nft) installed.
    _fw_probes_answer 'exit 0'
    _nft_ruleset 'table inet filter {' '	chain input {' \
        '		type filter hook input priority filter; policy drop;' '	}' '}'
    _ip6tables_accepting
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_ok passed" ]
}

@test "kernel: Docker's IPv6 forward chains are not an IPv6 firewall" {
    _fw_probes_answer 'exit 0'
    _ip6tables_accepting docker
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_missing failed" ]
}

@test "kernel: an IPv4-only nft table does not filter IPv6" {
    _fw_probes_answer 'exit 0'
    _nft_ruleset 'table ip filter {' '	chain input {' \
        '		type filter hook input priority filter; policy drop;' '	}' '}'
    _ip6tables_accepting
    run fw_backend
    [ "$output" = "nftables" ]
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_missing failed" ]
}

@test "kernel: an IPv6 INPUT drop in ip6tables filters IPv6" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub_script ip6tables <<<'[[ "$*" == "-S INPUT" ]] && echo "-P INPUT DROP"; exit 0'
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_ok passed" ]
}

@test "kernel: active ufw filters IPv6 only with IPV6=yes" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub ufw 0 "Status: active"
    DISTRO_UFW_DEFAULTS="$BATS_TEST_TMPDIR/ufw"
    printf 'IPV6=no\n#IPV6=yes\n' > "$DISTRO_UFW_DEFAULTS"
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_missing failed" ]

    state_init
    printf 'IPV6=yes\n' > "$DISTRO_UFW_DEFAULTS"
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_ok passed" ]

    state_init
    rm -f "$DISTRO_UFW_DEFAULTS"
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_unreadable failed" ]
}

@test "kernel: an ip6tables listing that fails is unknown, not an empty ruleset" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub ip6tables 1
    [ "$(_kernel_ipv6_fw_emitted)" = "kernel.ipv6_firewall_unreadable failed" ]
}

@test "kernel: an unreadable IPv6 firewall emits ipv6_firewall_unreadable, not missing" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _kernel_ipv6_enabled() { return 0; }
    _kernel_ipv6_in_use() { return 0; }
    _kernel_ipv6_get_stats() { echo ""; }
    _kernel_ipv6_check_security() { echo ""; }
    _kernel_ipv6_firewall_check() { echo "unknown"; }

    run _kernel_audit_ipv6

    run jq -r '.[] | select(.id == "kernel.ipv6_firewall_unreadable") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "kernel.ipv6_firewall_missing" or .id == "kernel.ipv6_firewall_ok") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

# ---- ufw: which firewall is active --------------------------------------

# Every probe answers: UFW installed but inactive, no nft tables, iptables per $1.
_fw_probes_answer() {
    source "$(_vpssec_repo_root)/core/distro.sh"
    source "$(_vpssec_repo_root)/modules/ufw.sh"
    _vpssec_stub ufw 0 "Status: inactive"
    _vpssec_stub systemctl 3
    _vpssec_stub nft 0
    _vpssec_stub_script iptables <<<"$1"
}

@test "ufw: a firewall query that fails is unknown, not no firewall" {
    _fw_probes_answer 'echo "iptables: Permission denied" >&2; exit 2'

    run fw_backend
    [ "$status" -eq 1 ]
    [ -z "$output" ]

    run ufw_audit
    [ "$status" -eq 0 ]
    run jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
    [ "$output" = "ufw.firewall_unknown failed" ]
    [ "${CHECK_SCORE_CATEGORY[ufw.firewall_unknown]}" = "info" ]
}

@test "ufw: any one failed status query with nothing found is unknown" {
    local tool
    for tool in ufw nft iptables; do
        _fw_probes_answer 'exit 0'
        _vpssec_stub "$tool" 1
        run fw_backend
        [ "$status" -eq 1 ] || { echo "$tool: rc=$status output=$output"; false; }
        [ -z "$output" ]
    done
}

@test "ufw: firewalld installed but unqueryable is unknown, not none" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub systemctl 1
    _fw_firewalld_installed() { return 0; }

    run fw_backend
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

@test "ufw: a failed systemctl query without firewalld installed is still none" {
    # A container or non-systemd host: flagging it unknown would be noise.
    _fw_probes_answer 'exit 0'
    _vpssec_stub systemctl 1
    _fw_firewalld_installed() { return 1; }

    run fw_backend
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "ufw: an inactive, failed or absent firewalld (exit 3) is none even when installed" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub systemctl 3
    _fw_firewalld_installed() { return 0; }

    run fw_backend
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "ufw: every probe answering with nothing active is still none" {
    _fw_probes_answer 'printf "%s\n" "Chain INPUT (policy ACCEPT)"'

    run fw_backend
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

# nft answering `list ruleset` with one line per argument.
_nft_ruleset() {
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/nft.ruleset"
    _vpssec_stub_script nft <<SH
[[ "\$*" == "list ruleset" ]] && cat "$BATS_TEST_TMPDIR/nft.ruleset"
exit 0
SH
}

# nft answering like a host where `ufw disable` left its skeleton behind: base
# chains with policy $1, jumping into emptied ufw chains, plus $2 as an extra
# line in the INPUT chain.
_nft_ufw_skeleton() {
    NFT_POLICY="$1" NFT_EXTRA="$2"
    _vpssec_stub_script nft <<SH
[[ "\$*" == "list ruleset" ]] || exit 0
printf '%s\n' 'table ip filter {' '	chain INPUT {' \
    '		type filter hook input priority filter; policy $NFT_POLICY;' \
    '		counter packets 3 bytes 180 jump ufw-before-input' \
    '		$NFT_EXTRA' '	}' '	chain ufw-before-input {' '	}' '}'
SH
}

@test "ufw: the empty chains ufw disable leaves behind are not an nftables firewall" {
    # They filter nothing; reading them as nftables skipped ufw.disabled and
    # passed ufw.firewall_active on a host with no filtering at all.
    _fw_probes_answer 'exit 0'
    _nft_ufw_skeleton accept ""
    VPSSEC_DISTRO_FAMILY=debian

    run fw_backend
    [ "$output" = "none" ]
    run ufw_audit
    run jq -r '[.[] | .id] | join(",")' "$VPSSEC_STATE/checks.json"
    [ "$output" = "ufw.disabled" ]
}

@test "ufw: bare accepting base chains, as a never-enabled ufw's disable leaves them, are none too" {
    _fw_probes_answer 'exit 0'
    _nft_ruleset 'table ip filter {' '	chain INPUT {' \
        '		type filter hook input priority filter; policy accept;' '	}' '}'
    run fw_backend
    [ "$output" = "none" ]
}

@test "ufw: an nft ruleset that cannot be listed is unknown, neither a firewall nor none" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub nft 1
    run fw_backend
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

@test "ufw: a drop rule or a drop policy beside that skeleton is still nftables" {
    _fw_probes_answer 'exit 0'
    _nft_ufw_skeleton accept "tcp dport 23 drop"
    run fw_backend
    [ "$output" = "nftables" ]

    _nft_ufw_skeleton drop ""
    run fw_backend
    [ "$output" = "nftables" ]
}

@test "ufw: accept rules under an accept policy filter nothing" {
    # The forgotten "policy drop": every port is still open.
    _fw_probes_answer 'exit 0'
    _nft_ufw_skeleton accept "tcp dport 22 accept"
    run fw_backend
    [ "$output" = "none" ]
}

@test "ufw: a backend found by a later probe wins over an earlier failed query" {
    _fw_probes_answer 'exit 0'
    _vpssec_stub ufw 1
    _nft_ruleset 'table inet filter {' '	chain input {' \
        '		type filter hook input priority 0; policy drop;' '	}' '}'

    run fw_backend
    [ "$status" -eq 0 ]
    [ "$output" = "nftables" ]
}

# ---- what fail2ban, tailscale and a container runtime leave in the ruleset ----
# None of them filters host ingress. fail2ban only rejects the IPs it banned,
# and it is what vpssec itself installs, so reading it as a firewall hid
# ufw.disabled / ufw.no_firewall on exactly the hosts that lack one.

# fail2ban's nftables actions: their own table, a chain on the input hook.
_nft_f2b_table() {
    _nft_ruleset 'table inet f2b-table {' \
        '	set addr-set-sshd {' '		type ipv4_addr' '		elements = { 198.51.100.7 }' '	}' \
        '	chain f2b-chain {' \
        '		type filter hook input priority filter - 1; policy accept;' \
        '		tcp dport 22 ip saddr @addr-set-sshd reject with icmp port-unreachable' \
        '	}' '}'
}

@test "fail2ban: its own nft table is not a firewall" {
    _fw_probes_answer 'exit 0'
    _nft_f2b_table
    VPSSEC_DISTRO_FAMILY=debian

    run fw_backend
    [ "$output" = "none" ]
    run ufw_audit
    run jq -r '[.[] | .id] | join(",")' "$VPSSEC_STATE/checks.json"
    [ "$output" = "ufw.disabled" ]
}

@test "fail2ban: its iptables jump, as iptables-nft lists it, is not a firewall" {
    _fw_probes_answer 'exit 0'
    _nft_ruleset 'table ip filter {' '	chain f2b-sshd {' \
        '		ip saddr 198.51.100.7 counter packets 0 bytes 0 reject' \
        '		counter packets 0 bytes 0 return' '	}' '	chain INPUT {' \
        '		type filter hook input priority filter; policy accept;' \
        '		meta l4proto tcp tcp dport 22 counter packets 9 bytes 540 jump f2b-sshd' \
        '	}' '}'
    run fw_backend
    [ "$output" = "none" ]
}

@test "fail2ban: its iptables jump and ban lines are not a firewall either" {
    # Any number of bans: the old probe counted REJECT lines in every chain.
    _fw_probes_answer 'printf "%s\n" "-P INPUT ACCEPT" "-N f2b-sshd" \
        "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd" \
        "-A f2b-sshd -s 198.51.100.1/32 -j REJECT" "-A f2b-sshd -s 198.51.100.2/32 -j REJECT" \
        "-A f2b-sshd -s 198.51.100.3/32 -j REJECT" "-A f2b-sshd -s 198.51.100.4/32 -j REJECT" \
        "-A f2b-sshd -j RETURN"'
    run fw_backend
    [ "$output" = "none" ]
}

@test "tailscale: its anti-spoofing chain is not a firewall" {
    _fw_probes_answer 'printf "%s\n" "-P INPUT ACCEPT" "-N ts-input" "-A INPUT -j ts-input"'
    run fw_backend
    [ "$output" = "none" ]
}

@test "a container runtime's forward and nat chains are not a firewall" {
    _fw_probes_answer 'exit 0'
    _nft_ruleset 'table ip nat {' '	chain POSTROUTING {' \
        '		type nat hook postrouting priority srcnat; policy accept;' \
        '		oifname != "docker0" ip saddr 172.17.0.0/16 counter masquerade' '	}' '}' \
        'table ip filter {' '	chain FORWARD {' \
        '		type filter hook forward priority filter; policy drop;' \
        '		counter jump DOCKER-USER' '	}' '}'
    run fw_backend
    [ "$output" = "none" ]
}

@test "iptables: a drop policy, a drop rule or a jump into an own chain is a firewall" {
    local rules
    for rules in '"-P INPUT DROP"' \
                 '"-P INPUT ACCEPT" "-A INPUT -p tcp --dport 23 -j REJECT"' \
                 '"-P INPUT ACCEPT" "-A INPUT -j my-firewall"'; do
        _fw_probes_answer "printf '%s\n' $rules"
        run fw_backend
        [ "$output" = "iptables" ] || { echo "$rules -> $output"; false; }
    done
}

@test "iptables: accept rules under an accept policy filter nothing" {
    _fw_probes_answer 'printf "%s\n" "-P INPUT ACCEPT" "-A INPUT -p tcp --dport 22 -j ACCEPT" "-A INPUT -i lo -j ACCEPT"'
    run fw_backend
    [ "$output" = "none" ]
}
