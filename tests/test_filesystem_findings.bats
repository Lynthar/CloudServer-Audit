#!/usr/bin/env bats
# What the filesystem audit reports for paths a real host ships or an attacker
# can create: symlinked drop-ins, whitelisted names one directory off, extra
# capability clauses, and names holding a newline or a backslash.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    export TMPDIR="$BATS_TEST_TMPDIR"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/filesystem.sh"
    etc=$(_vpssec_fake_etc)
    FS_SUDOERS_D="$etc/sudoers.d"
    FS_SSHD_CONFIG_D="$etc/ssh/sshd_config.d"
    mkdir -p "$FS_SUDOERS_D" "$FS_SSHD_CONFIG_D" "$etc/lib"
    FS_SENSITIVE_FILES=()
}

_check() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | "\(.status) \(.title)"' "$VPSSEC_STATE/checks.json"
}

_desc() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

# find answers each walk with these NUL-separated paths.
_walk() {
    local kind="$1"; shift
    printf '%s\0' "$@" > "$BATS_TEST_TMPDIR/walk-$kind"
    _vpssec_stub_script find <<'SH'
d="$TMPDIR"
case "$*" in
    *"-perm -4000"*) f=suid ;;
    *"-perm -2000"*) f=sgid ;;
    *"-type d"*)     f=dirs ;;
    *"-perm -0002"*) f=ww ;;
    *) f=none ;;
esac
cat "$d/walk-$f" 2>/dev/null
exit 0
SH
}

# ---- symlinked drop-ins (Arch's systemd ships 20-systemd-userdb.conf as one) ----

@test "a symlinked sshd_config.d drop-in is judged by its 644 target, not the link's 777" {
    printf 'x\n' > "$etc/lib/20-systemd-userdb.conf"; chmod 644 "$etc/lib/20-systemd-userdb.conf"
    ln -s ../../lib/20-systemd-userdb.conf "$FS_SSHD_CONFIG_D/20-systemd-userdb.conf"
    printf 'x\n' > "$etc/lib/90-ops"; chmod 440 "$etc/lib/90-ops"
    ln -s ../lib/90-ops "$FS_SUDOERS_D/90-ops"
    _fs_audit_sensitive_perms
    [ "$(_check filesystem.sensitive_perms_ok)" != "" ]
}

@test "a symlink to a loose target is reported, and the fix converges on the target" {
    printf 'x\n' > "$etc/lib/90-ops"; chmod 666 "$etc/lib/90-ops"
    ln -s ../lib/90-ops "$FS_SUDOERS_D/90-ops"
    _fs_audit_sensitive_perms
    [[ "$(_desc filesystem.sensitive_perms_wrong)" == *"90-ops: mode 666 (expected 440)"* ]]
    _vpssec_begin_backup_session
    _fs_fix_sensitive_perms
    _fs_sensitive_perms_ok
    [ "$(stat -c %a "$etc/lib/90-ops")" = "440" ]
}

@test "the fix never loosens a symlinked drop-in whose target is stricter" {
    printf 'x\n' > "$etc/lib/90-ops"; chmod 400 "$etc/lib/90-ops"
    ln -s ../lib/90-ops "$FS_SUDOERS_D/90-ops"
    _vpssec_begin_backup_session
    _fs_fix_sensitive_perms
    [ "$(stat -c %a "$etc/lib/90-ops")" = "400" ]
}

# ---- whitelist globs stay inside one directory -------------------------------------

@test "a whitelisted SUID name one directory off is reported" {
    _walk suid /usr/sbin/unix_chkpwd /usr/local/bin/unix_chkpwd
    _fs_audit_suid
    [ "$(_check filesystem.suspicious_suid)" = "failed 1 suspicious SUID files found" ]
    [ "$(_desc filesystem.suspicious_suid)" = "Files: /usr/local/bin/unix_chkpwd " ]
}

@test "a whitelisted SGID name at another depth is reported" {
    _walk sgid /usr/lib/x86_64-linux-gnu/utempter/utempter /usr/lib/x/y/utempter/utempter
    _fs_audit_sgid
    [[ "$(_desc filesystem.suspicious_sgid)" == *" /usr/lib/x/y/utempter/utempter " ]]
    [[ "$(_desc filesystem.suspicious_sgid)" != *x86_64* ]]
}

# ---- capabilities: every clause getcap prints counts --------------------------------

_getcap() {
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/getcap.out"
    _vpssec_stub_script getcap <<'SH'
cat "$TMPDIR/getcap.out"
SH
}

@test "an extra clause on a whitelisted binary is not hidden by the first" {
    # libcap 2.66 prints a second flag set as its own clause.
    _getcap '/usr/bin/ping cap_net_raw=eip cap_sys_admin+ep'
    _fs_audit_caps
    [[ "$(_desc filesystem.dangerous_caps)" == *"/usr/bin/ping:cap_net_raw=eip cap_sys_admin+ep"* ]]
}

@test "every capability (=ep) on a whitelisted binary is reported" {
    _getcap '/usr/bin/ping =ep'
    _fs_audit_caps
    [ "$(_check filesystem.caps_ok)" = "" ]
}

@test "the whitelisted capability alone passes, in either getcap format" {
    _getcap '/usr/bin/ping cap_net_raw=ep' '/usr/sbin/arping = cap_net_raw+ep'
    _fs_audit_caps
    [ "$(_check filesystem.caps_ok)" != "" ]
}

@test "a whitelisted capability name one directory off is reported" {
    _getcap '/usr/local/sbin/arping cap_net_raw=ep'
    _fs_audit_caps
    [[ "$(_desc filesystem.non_standard_caps)" == *"/usr/local/sbin/arping"* ]]
}

# ---- names holding a newline or a backslash --------------------------------------

@test "a SUID name with a newline is one finding, shown quoted" {
    _walk suid /usr/bin/passwd $'/tmp/evil\n/usr/bin/passwd'
    _fs_audit_suid
    [ "$(_check filesystem.suspicious_suid)" = "failed 1 suspicious SUID files found" ]
    [ "$(_desc filesystem.suspicious_suid)" = "Files: \$'/tmp/evil\\n/usr/bin/passwd' " ]
}

@test "a backslash in a world-writable name does not cut the list short" {
    _walk ww '/srv/a\cb' /srv/c
    _walk dirs /srv/d
    _fs_audit_world_writable
    [[ "$(_desc filesystem.world_writable)" == *'/srv/a\cb /srv/c /srv/d'* ]]
}
