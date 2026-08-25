#!/usr/bin/env bats
# Coverage for filesystem's two fixes. Both are FIX_SAFE, so guide mode applies
# them with no prompt: /etc/login.defs is written atomically and post-checked,
# and the perms fix relies on .vpssec_modes to give a rollback the prior mode.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    export TMPDIR="$BATS_TEST_TMPDIR"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/filesystem.sh"

    etc=$(_vpssec_fake_etc)
    FS_LOGIN_DEFS="$etc/login.defs"
    FS_PROFILE="$etc/profile"
    FS_PAM_SESSION_FILES=("$etc/pam.d/common-session")
    FS_SUDOERS_D="$etc/sudoers.d"
    FS_SSHD_CONFIG_D="$etc/ssh/sshd_config.d"
    mkdir -p "$etc/pam.d" "$FS_SUDOERS_D" "$FS_SSHD_CONFIG_D"
}

_mode_of() { stat -c '%a' "$1"; }

# A login.defs with the directives the umask family reads.
_login_defs() {
    local umask_line="$1"
    {
        printf '# /etc/login.defs - shadow password suite configuration\n'
        printf 'MAIL_DIR\t/var/mail\n'
        [[ -n "$umask_line" ]] && printf '%s\n' "$umask_line"
        printf 'USERGROUPS_ENAB\tyes\n'
    } > "$FS_LOGIN_DEFS"
    chmod 644 "$FS_LOGIN_DEFS"
}

_pam_umask_enabled() {
    printf 'session\toptional\tpam_umask.so\n' > "$etc/pam.d/common-session"
}

# ==============================================================================
# filesystem.fix_umask  (FIX_SAFE — rewrites a file PAM reads at every login)
# ==============================================================================

@test "umask fix: a missing login.defs is reported, not created" {
    rm -f "$FS_LOGIN_DEFS"

    run _fs_fix_umask
    [ "$status" -eq 1 ]
    [ ! -f "$FS_LOGIN_DEFS" ]
}

@test "umask fix: an existing UMASK line is rewritten to 027" {
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    grep -qE '^UMASK[[:space:]]+027$' "$FS_LOGIN_DEFS"
    _vpssec_refute grep -qE '^UMASK[[:space:]]+022$' "$FS_LOGIN_DEFS"
}

@test "umask fix: exactly one UMASK line is left behind" {
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    [ "$(grep -c '^UMASK' "$FS_LOGIN_DEFS")" -eq 1 ]
}

@test "umask fix: a file with no UMASK line gets one appended" {
    _login_defs ""
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    grep -qE '^UMASK[[:space:]]+027$' "$FS_LOGIN_DEFS"
}

@test "umask fix: unrelated directives survive" {
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    grep -qE '^MAIL_DIR' "$FS_LOGIN_DEFS"
    grep -qE '^USERGROUPS_ENAB' "$FS_LOGIN_DEFS"
    grep -q '^# /etc/login.defs' "$FS_LOGIN_DEFS"
}

@test "umask fix: login.defs is backed up before it is edited" {
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled
    _vpssec_begin_backup_session

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    grep -qE '^UMASK[[:space:]]+022$' "${VPSSEC_BACKUP_SESSION}${FS_LOGIN_DEFS}"
}

@test "umask fix: the file's permissions are not widened" {
    # write_file_atomic copies the mode of the file it replaces. login.defs is
    # 644 on Debian; a host that tightened it to 600 must stay at 600.
    _login_defs "$(printf 'UMASK\t\t022')"
    chmod 600 "$FS_LOGIN_DEFS"
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$FS_LOGIN_DEFS")" = "600" ]
}

@test "umask fix: no staging file is left behind" {
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    # write_file_atomic stages as .vpssec.XXXXXX beside the target.
    run bash -c "ls -A '$etc' | grep -c '^\.vpssec\.'"
    [ "$output" = "0" ]
}

@test "umask fix: a write the atomic writer refuses is reported as failure" {
    # The lever is the final rename, not a '..' path: backup_file validates the
    # same path and aborts the fix before the write. The assertion is on the
    # MESSAGE — the postcondition also returns 1 here, so status cannot tell them apart.
    VPSSEC_QUIET_SCAN=0
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled
    _vpssec_stub mv 1

    run _fs_fix_umask
    [ "$status" -eq 1 ]
    grep -q 'umask is unchanged' <<<"$output"
    _vpssec_refute grep -q 'effective umask' <<<"$output"
    grep -qE '^UMASK[[:space:]]+022$' "$etc/login.defs"
}

@test "umask fix: staged content without a UMASK 027 line is refused" {
    # sed is stubbed because that is the only way to reach this guard: past the
    # ^UMASK gate real sed always produces the line. The guard stops a future
    # edit to the staging step from writing something arbitrary into a PAM file.
    VPSSEC_QUIET_SCAN=0
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled
    _vpssec_stub sed 0 'garbage'

    run _fs_fix_umask
    [ "$status" -eq 1 ]
    grep -q 'left unchanged' <<<"$output"
    grep -qE '^UMASK[[:space:]]+022$' "$FS_LOGIN_DEFS"
}

@test "umask fix: a write the audit still reads as weak is not reported as done" {
    # The postcondition asks the audit's own question rather than checking that
    # the write happened: the file DOES contain UMASK 027, but as the second
    # line, and the first occurrence is what a session gets.
    VPSSEC_QUIET_SCAN=0
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled
    _vpssec_stub_script sed <<'SH'
printf 'UMASK\t\t022\nUMASK\t\t027\n'
SH

    run _fs_fix_umask
    [ "$status" -eq 1 ]
    grep -q 'effective umask' <<<"$output"
}

@test "umask fix: the operator is warned when pam_umask is not enabled" {
    # Without pam_umask the value this fix just wrote reaches shell login
    # sessions only, which is the difference between "hardened" and "hardened
    # for interactive bash users". The container itself ships this way.
    VPSSEC_QUIET_SCAN=0
    _login_defs "$(printf 'UMASK\t\t022')"
    rm -f "$etc/pam.d/common-session"

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    # "not enabled in common-session", not just "pam_umask": the
    # USERGROUPS_ENAB note printed a few lines earlier also names the module,
    # so the looser pattern passed with this whole branch deleted.
    grep -q 'not enabled in common-session' <<<"$output"
}

@test "umask fix: no pam warning when pam_umask is enabled" {
    VPSSEC_QUIET_SCAN=0
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled

    run _fs_fix_umask
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'pam_umask is not enabled' <<<"$output"
}

# ==============================================================================
# The predicate the fix's postcondition shares with the audit
# ==============================================================================

@test "umask read: a duplicated UMASK line reads as the first, not both" {
    # The regression: every matching line was collected, so this returned
    # "077 022" and _fs_compute_effective_umask normalised it to garbage.
    _login_defs ""
    printf 'UMASK\t\t077\nUMASK\t\t022\n' >> "$FS_LOGIN_DEFS"

    run _fs_check_umask
    [ "$status" -eq 0 ]
    [ "$output" = "077" ]
}

@test "umask read: /etc/profile is consulted only when login.defs has none" {
    _login_defs ""
    printf 'umask 077\n' > "$FS_PROFILE"

    run _fs_check_umask
    [ "$output" = "077" ]

    _login_defs "$(printf 'UMASK\t\t027')"
    run _fs_check_umask
    [ "$output" = "027" ]
}

@test "umask read: the last umask in /etc/profile wins" {
    # Opposite rule to login.defs, deliberately: profile is a script, so the
    # last command executed is the one in effect.
    _login_defs ""
    printf 'umask 077\numask 022\n' > "$FS_PROFILE"

    run _fs_check_umask
    [ "$output" = "022" ]
}

@test "umask strictness: the audit's own predicate accepts world-denied masks" {
    run _fs_umask_is_strict 0027
    [ "$status" -eq 0 ]
    run _fs_umask_is_strict 0007
    [ "$status" -eq 0 ]
    run _fs_umask_is_strict 0022
    [ "$status" -eq 1 ]
    run _fs_umask_is_strict 0002
    [ "$status" -eq 1 ]
}

# ==============================================================================
# filesystem.fix_sensitive_perms  (FIX_SAFE — chmods files under /etc)
# ==============================================================================

# Point the sensitive-file map at the scratch tree. It is a global associative
# array, so a test can replace it wholesale without the module needing a path
# variable for every entry.
_sensitive() {
    FS_SENSITIVE_FILES=()
    local spec
    for spec in "$@"; do
        FS_SENSITIVE_FILES["$etc/${spec%%:*}"]="${spec##*:}"
    done
}

_make() {
    local path="$etc/$1" mode="$2"
    mkdir -p "$(dirname "$path")"
    printf 'x\n' > "$path"
    chmod "$mode" "$path"
}

@test "perms fix: an over-permissive file is tightened" {
    _make passwd 666
    _sensitive "passwd:644"

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/passwd")" = "644" ]
}

@test "perms fix: a file already more restrictive is left alone" {
    _make shadow 600
    _sensitive "shadow:640"

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/shadow")" = "600" ]
}

@test "perms fix: 0604 against an expected 0640 is tightened (regression)" {
    # The bitmask case: 0604 is numerically SMALLER than 0640, so the original
    # `((actual > expected))` test skipped it while the audit flagged it — a
    # world-readable /etc/shadow the fix would not touch.
    _make shadow 604
    _sensitive "shadow:640"

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/shadow")" = "640" ]
}

@test "perms fix: a setuid bit on a config file is stripped" {
    _make crontab 4600
    _sensitive "crontab:600"

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/crontab")" = "600" ]
}

@test "perms fix: a file that does not exist is skipped quietly" {
    _sensitive "not-here:600"

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
}

@test "perms fix: sudoers.d drop-ins are tightened to 440" {
    # The static map cannot hold globs, so drop-ins are walked separately.
    # A 666 file in sudoers.d is a direct privilege-escalation primitive.
    _sensitive
    _make "sudoers.d/90-cloud-init-users" 666

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$FS_SUDOERS_D/90-cloud-init-users")" = "440" ]
}

@test "perms fix: sshd_config.d drop-ins are tightened to 644" {
    _sensitive
    _make "ssh/sshd_config.d/50-cloud.conf" 666

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$FS_SSHD_CONFIG_D/50-cloud.conf")" = "644" ]
}

@test "perms fix: the pre-fix mode is recorded so rollback can restore it" {
    # The point of the backup here is the MODE, not the content — the fix does
    # not change a byte. Without .vpssec_modes a rollback returns every one of
    # these files at 600, and /etc/passwd at 600 breaks non-root name lookups.
    _make passwd 666
    _sensitive "passwd:644"
    _vpssec_begin_backup_session

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    grep -qxF "666 $etc/passwd" "${VPSSEC_BACKUP_SESSION}/.vpssec_modes"
}

@test "perms fix: a rollback puts the original mode back end to end" {
    _make passwd 666
    _sensitive "passwd:644"
    _vpssec_begin_backup_session

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/passwd")" = "644" ]

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/passwd")" = "666" ]
}

@test "perms fix: a file that was already correct is not backed up" {
    # Backing up an untouched file would put a spurious entry in the rollback
    # set, and (with the mode manifest) a spurious chmod on restore.
    _make passwd 644
    _sensitive "passwd:644"
    _vpssec_begin_backup_session

    run _fs_fix_sensitive_perms
    [ "$status" -eq 0 ]
    _vpssec_refute test -e "${VPSSEC_BACKUP_SESSION}${etc}/passwd"
}

@test "perms fix: a chmod that fails is counted and reported" {
    # chmod is an external command, so stubbing it is the honest way to model
    # an immutable file (chattr +i) or a read-only mount. Nothing else in this
    # path depends on chmod's status.
    _make passwd 666
    _sensitive "passwd:644"
    _vpssec_stub chmod 1

    run _fs_fix_sensitive_perms
    [ "$status" -eq 1 ]
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "filesystem_fix: an unknown fix id fails instead of silently doing nothing" {
    run filesystem_fix "filesystem.not_a_real_fix"
    [ "$status" -eq 1 ]
}

@test "filesystem_fix: both known ids reach their implementation" {
    _login_defs "$(printf 'UMASK\t\t022')"
    _pam_umask_enabled
    run filesystem_fix "filesystem.fix_umask"
    [ "$status" -eq 0 ]
    grep -qE '^UMASK[[:space:]]+027$' "$FS_LOGIN_DEFS"

    _make passwd 666
    _sensitive "passwd:644"
    run filesystem_fix "filesystem.fix_sensitive_perms"
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$etc/passwd")" = "644" ]
}

# ---- the backup contract ---------------------------------------------

@test "perms fix: a backup that cannot be taken is counted, not skipped" {
    # The loops that drive _fs_fix_one ignore its status, so the failure has
    # to reach the counter or the fix reports success for a file it never
    # backed up and then chmod'ed anyway.
    _vpssec_begin_backup_session
    _make passwd 666
    _sensitive "passwd:644"
    _vpssec_stub cp 1

    run _fs_fix_sensitive_perms
    [ "$status" -ne 0 ]
    [ "$(_mode_of "$etc/passwd")" = "666" ]
}

@test "umask fix: a backup that cannot be taken aborts the fix" {
    _vpssec_begin_backup_session
    printf 'UMASK\t\t022\n' > "$FS_LOGIN_DEFS"
    _vpssec_stub cp 1

    run _fs_fix_umask
    [ "$status" -ne 0 ]
    grep -q '022' "$FS_LOGIN_DEFS"
}

# Production expectations for the cron/at family. crontab(1) is setgid crontab
# and at(1) runs as daemon: both read these files through group or world bits,
# so stripping world-read from a root:root file locks non-root users out.

@test "perms table: cron/at family keeps the read bits its setgid readers need" {
    [ "${FS_SENSITIVE_FILES[/etc/at.deny]}" = "640" ]
    [ "${FS_SENSITIVE_FILES[/etc/crontab]}" = "644" ]
    [ "${FS_SENSITIVE_FILES[/etc/cron.allow]}" = "644" ]
    [ "${FS_SENSITIVE_FILES[/etc/cron.deny]}" = "644" ]
    [ "${FS_SENSITIVE_FILES[/etc/at.allow]}" = "644" ]
}

@test "perms audit: group daemon is flagged outside /etc/at.*" {
    [ "$(id -u)" = "0" ] || skip "ownership checks only run as root"

    local f="$BATS_TEST_TMPDIR/cron.allow"
    printf 'x\n' > "$f"
    chown root:daemon "$f"
    chmod 640 "$f"
    run _fs_check_sensitive_file "$f" 644
    [ "$status" -eq 1 ]
    [[ "$output" == *"group daemon grants access"* ]]
}

@test "perms audit: group crontab is flagged outside /etc/cron*" {
    [ "$(id -u)" = "0" ] || skip "ownership checks only run as root"
    getent group crontab >/dev/null || skip "no crontab group on this host"

    local f="$BATS_TEST_TMPDIR/at.deny"
    printf 'x\n' > "$f"
    chown root:crontab "$f"
    chmod 640 "$f"
    run _fs_check_sensitive_file "$f" 644
    [ "$status" -eq 1 ]
    [[ "$output" == *"group crontab grants access"* ]]
}

@test "perms audit: stock at.deny (root:daemon 640) passes clean" {
    [ "$(id -u)" = "0" ] || skip "ownership checks only run as root"
    [ -f /etc/at.deny ] || skip "at not installed"
    [ "$(stat -c '%U:%G' /etc/at.deny)" = "root:daemon" ] || skip "not the stock ownership"
    [ "$(stat -c '%a' /etc/at.deny)" = "640" ] || skip "not the stock mode"

    run _fs_check_sensitive_file /etc/at.deny "${FS_SENSITIVE_FILES[/etc/at.deny]}"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}
