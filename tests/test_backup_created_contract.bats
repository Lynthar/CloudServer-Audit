#!/usr/bin/env bats
# The created-file contract, asserted by OUTCOME not by call shape: whatever
# appears on disk must match .vpssec_created, the only input backup_restore has
# when deciding what a rollback deletes. Every selectable fix_id is declared below.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    # Without this, i18n echoes the KEY, so any assertion on message text
    # matches the key name instead of the string an operator would read —
    # the defect that made a whole baseline suite assert nothing.
    i18n_load en_US
    etc=$(_vpssec_fake_etc)
    _vpssec_begin_backup_session
}

_load_module() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/$1.sh"
}

_manifest() {
    printf '%s\n' "$VPSSEC_BACKUP_SESSION/$VPSSEC_CREATED_MANIFEST"
}

# ==============================================================================
# docker — jq merge + mv, the ninth instance
# ==============================================================================

_setup_docker() {
    _load_module docker
    DOCKER_DAEMON_JSON="$etc/docker/daemon.json"
    _vpssec_stub systemctl
    # confirm_critical reads /dev/tty; a plain "no" keeps the restart out of
    # the way without changing which branch writes the file.
    confirm_critical() { return 1; }
}

@test "docker: a first-run daemon.json is tracked, so a rollback can delete it" {
    _setup_docker
    snap=$(_vpssec_tree_snapshot "$etc")

    run _docker_fix_enable_daemon_setting "live-restore" "true"

    [ -f "$DOCKER_DAEMON_JSON" ]
    _vpssec_assert_created_contract "$etc" "$snap"
}

@test "docker: rollback removes the daemon.json this fix created" {
    _setup_docker
    _docker_fix_enable_daemon_setting "live-restore" "true" || true
    [ -f "$DOCKER_DAEMON_JSON" ]

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"

    [ "$status" -eq 0 ]
    _vpssec_refute test -f "$DOCKER_DAEMON_JSON"
}

@test "docker: an existing daemon.json is snapshotted, not tracked as created" {
    # Snapshotting an existing file uses the two-argument form of validate_path,
    # which needs GNU `realpath -m`; tracking a created path works anywhere, which
    # is why only this test carries the guard.
    _vpssec_require_gnu_realpath
    _setup_docker
    mkdir -p "$(dirname "$DOCKER_DAEMON_JSON")"
    printf '%s' '{"log-driver":"journald"}' > "$DOCKER_DAEMON_JSON"

    _docker_fix_enable_daemon_setting "live-restore" "true" || true

    # Assert the fix did its job BEFORE asserting the rollback undoes it: a test
    # that only inspects the post-restore file passes just as happily when the fix
    # wrote nothing at all, because the restored content is the same either way.
    grep -q 'live-restore' "$DOCKER_DAEMON_JSON"
    grep -q 'journald' "$DOCKER_DAEMON_JSON"

    # Tracking a pre-existing file would make the rollback DELETE the
    # operator's own config instead of restoring it.
    _vpssec_refute grep -qxF "$DOCKER_DAEMON_JSON" "$(_manifest)"
    backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ -f "$DOCKER_DAEMON_JSON" ]
    grep -q 'journald' "$DOCKER_DAEMON_JSON"
    _vpssec_refute grep -q 'live-restore' "$DOCKER_DAEMON_JSON"
}

@test "docker: a malformed existing daemon.json is refused and leaves no trace" {
    _setup_docker
    mkdir -p "$(dirname "$DOCKER_DAEMON_JSON")"
    printf '%s' 'not json at all' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" "true"

    [ "$status" -eq 1 ]
    # Assert WHICH refusal, not merely that it failed. Skipping the validity check
    # also ends in status 1 (the jq merge fails a few lines later), so status alone
    # cannot tell "refused up front" from "backed the file up, then failed".
    [[ "$output" == *"not valid JSON"* ]]
    # The check runs BEFORE the backup on purpose: a file the fix refuses to
    # touch must leave no trace in the session at all.
    _vpssec_refute test -e "$(_manifest)"
    grep -q 'not json at all' "$DOCKER_DAEMON_JSON"
}

# ==============================================================================
# ssh — staged write + `sshd -t`, a primitive write_file_atomic never sees
# ==============================================================================

@test "ssh: a first-run hardening drop-in is tracked" {
    _load_module ssh
    SSH_CONFIG="$etc/ssh/sshd_config"
    SSH_DROPIN_DIR="$etc/ssh/sshd_config.d"
    SSH_HARDENING_DROPIN="$SSH_DROPIN_DIR/00-vpssec-hardening.conf"
    mkdir -p "$SSH_DROPIN_DIR"
    export TMPDIR="$BATS_TEST_TMPDIR"
    _vpssec_stub sshd 0
    snap=$(_vpssec_tree_snapshot "$etc")

    run _ssh_write_hardening_config "PasswordAuthentication" "no"

    [ "$status" -eq 0 ]
    [ -f "$SSH_HARDENING_DROPIN" ]
    _vpssec_assert_created_contract "$etc" "$snap"
}

# ==============================================================================
# nginx — openssl writes the products, and one of them is a symlink
# ==============================================================================

@test "nginx: the generated certificate and key are both tracked" {
    _load_module nginx
    NGINX_SSL_DIR="$etc/nginx/ssl"
    NGINX_CATCHALL_CERT="$NGINX_SSL_DIR/default.crt"
    NGINX_CATCHALL_KEY="$NGINX_SSL_DIR/default.key"
    # openssl is stubbed rather than run: the contract is about registration,
    # and a real 2048-bit keygen in a unit test buys nothing. The stub must
    # still CREATE both files, otherwise the assertion has nothing to see.
    _vpssec_stub_script openssl <<'SH'
out=""; key=""
while [ $# -gt 0 ]; do
    case "$1" in
        -out) out="$2"; shift ;;
        -keyout) key="$2"; shift ;;
    esac
    shift
done
[ -n "$out" ] && printf 'cert\n' > "$out"
[ -n "$key" ] && printf 'key\n' > "$key"
exit 0
SH
    snap=$(_vpssec_tree_snapshot "$etc")

    run _nginx_ensure_catchall_cert

    [ "$status" -eq 0 ]
    [ -f "$NGINX_CATCHALL_CERT" ]
    [ -f "$NGINX_CATCHALL_KEY" ]
    _vpssec_assert_created_contract "$etc" "$snap"
}

@test "nginx: a sites-enabled symlink is NOT tracked" {
    # backup_restore refuses to delete a tracked path that is a symlink and counts
    # it as skipped, turning a complete rollback into an exit-2 "partially
    # restored". Symlinks get a printed undo command; they never reach the manifest.
    _load_module nginx
    local link="$etc/nginx/sites-enabled/vpssec-catchall.conf"
    mkdir -p "$(dirname "$link")" "$etc/nginx/sites-available"
    printf 'server{}\n' > "$etc/nginx/sites-available/vpssec-catchall.conf"
    snap=$(_vpssec_tree_snapshot "$etc")

    ln -sf "$etc/nginx/sites-available/vpssec-catchall.conf" "$link"

    _vpssec_assert_created_contract "$etc" "$snap"
}

# ==============================================================================
# control — an atomic writer, to prove the assertion can pass and can fail
# ==============================================================================

@test "kernel: the sysctl drop-in an atomic writer creates is tracked" {
    _load_module kernel
    VPSSEC_SYSCTL_CONF="$etc/sysctl.d/99-vpssec-hardening.conf"
    _vpssec_stub sysctl
    snap=$(_vpssec_tree_snapshot "$etc")

    _kernel_write_sysctl "net.ipv4.tcp_syncookies" "1" || true

    [ -f "$VPSSEC_SYSCTL_CONF" ]
    _vpssec_assert_created_contract "$etc" "$snap"
}

@test "the contract assertion actually fails on an untracked file" {
    # Without this the suite could pass vacuously: every other test here asserts
    # that _vpssec_assert_created_contract succeeds, and an assertion that can
    # only succeed proves nothing.
    snap=$(_vpssec_tree_snapshot "$etc")
    mkdir -p "$etc/somewhere"
    printf 'x\n' > "$etc/somewhere/untracked.conf"

    run _vpssec_assert_created_contract "$etc" "$snap"

    [ "$status" -eq 1 ]
    [[ "$output" == *"created but not tracked"* ]]
}

# ==============================================================================
# the enumerable half
# ==============================================================================

# Fixes that create at least one file under /etc. Each must be exercised by
# some suite that asserts the created-file contract — this file for the four
# above, the per-module suites for the rest.
_CREATES_FILES=(
    docker.enable_live_restore          # daemon.json
    docker.enable_no_new_privileges     # daemon.json
    fail2ban.configure_ssh_jail         # jail.d/99-vpssec-sshd.local
    fail2ban.enable_ssh_jail            # delegates to configure_ssh_jail
    fail2ban.install                    # auto-configures when no custom config
    kernel.disable_core_dump            # coredump.conf.d drop-in
    kernel.enable_aslr                  # sysctl.d drop-in
    kernel.harden_ipv6                  # sysctl.d drop-in
    kernel.harden_kernel                # sysctl.d drop-in
    kernel.harden_network               # sysctl.d drop-in
    logging.enable_persistent_journal   # journald.conf.d drop-in
    logging.setup_audit_rules           # rules.d/99-vpssec.rules
    logging.setup_logrotate             # logrotate.conf when absent
    nginx.add_catchall                  # conf + cert + key (+ an untracked symlink)
    ssh.disable_empty_password          # all eight go through
    ssh.disable_password_auth           #   _ssh_write_hardening_config,
    ssh.disable_root_login              #   which creates the 00- drop-in
    ssh.disable_x11_forwarding          #   on a first run
    ssh.enable_pubkey
    ssh.harden_algorithms
    ssh.set_login_grace_time
    ssh.set_max_auth_tries
    timezone.set_locale                 # /etc/default/locale when absent
    timezone.set_timezone               # /etc/timezone (localtime is a symlink)
    update.enable_unattended            # 20auto-upgrades + the 52- drop-in
    webapp.nginx_hsts                   # snippets/
    webapp.nginx_security_headers       # conf.d/
    webapp.nginx_ssl_ciphers            # both dispatch to _webapp_fix_nginx_ssl,
    webapp.nginx_ssl_protocols          #   which writes snippets/
)

# Fixes that create nothing under /etc: they change modes, drive a service,
# install a package, edit an existing file in place, or write only into vpssec's
# own template directory. Listed rather than omitted, so none slips through.
_CREATES_NOTHING=(
    alerts.setup_config                 # vpssec's own template dir
    backup.generate_templates           # vpssec's own template dir
    baseline.disable_unused             # systemctl only
    baseline.enable_apparmor            # systemctl only
    baseline.selinux_set_enforcing      # setenforce + edits an existing file
    cloudflared.generate_config         # vpssec's own template dir
    cloudflared.setup_service           # systemctl only
    docker.generate_proxy_template      # vpssec's own template dir
    fail2ban.enable_service             # systemctl only
    filesystem.fix_sensitive_perms      # chmod only; .vpssec_modes covers it
    filesystem.fix_umask                # rewrites an existing login.defs
    logging.enable_auditd               # systemctl only
    logging.install_auditd              # apt only
    timezone.enable_ntp                 # apt + systemctl
    timezone.set_rtc_utc                # timedatectl only
    ufw.allow_ssh                       # firewall rules, not files
    ufw.enable                          # firewall rules, not files
    ufw.install                         # apt only
    ufw.set_default_deny                # firewall rules, not files
    update.apply_security               # apt only
    update.install_unattended           # apt only
    webapp.nginx_server_tokens          # rewrites an existing nginx.conf
)

_selectable_fix_ids() {
    local sl="$(_vpssec_repo_root)/core/security_levels.sh"
    awk '
        /^declare -gA FIX_(SAFE|CONFIRM|RISKY)=\(/ { inmap=1; next }
        inmap && /^\)/ { inmap=0 }
        inmap
    ' "$sl" | grep -oE '\["[a-zA-Z0-9_.]+"\]' | tr -d '["]' | sort -u
}

@test "every selectable fix_id is classified as creating files or not" {
    local declared unclassified="" fid
    declared=$(printf '%s\n' "${_CREATES_FILES[@]}" "${_CREATES_NOTHING[@]}" | sort -u)

    while read -r fid; do
        [[ -n "$fid" ]] || continue
        grep -qxF "$fid" <<<"$declared" || unclassified+="$fid "
    done < <(_selectable_fix_ids)

    [ -z "$unclassified" ] || {
        printf 'unclassified fix_id(s) — add to _CREATES_FILES or _CREATES_NOTHING with a reason: %s\n' \
            "$unclassified" >&2
        return 1
    }
}

@test "the two classification lists are disjoint and name only real fix_ids" {
    local selectable dupes fid stale=""
    selectable=$(_selectable_fix_ids)

    dupes=$(printf '%s\n' "${_CREATES_FILES[@]}" "${_CREATES_NOTHING[@]}" | sort | uniq -d)
    [ -z "$dupes" ] || {
        printf 'fix_id in both lists: %s\n' "$dupes" >&2
        return 1
    }

    # A stale entry is how a list quietly stops covering anything: the
    # fail2ban suite looked covered for months because a file name matched.
    for fid in "${_CREATES_FILES[@]}" "${_CREATES_NOTHING[@]}"; do
        grep -qxF "$fid" <<<"$selectable" || stale+="$fid "
    done
    [ -z "$stale" ] || {
        printf 'listed fix_id is not selectable (renamed or removed?): %s\n' "$stale" >&2
        return 1
    }
}
