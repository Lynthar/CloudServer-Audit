#!/usr/bin/env bats
#
# Regression tests for the umask audit helpers (M14 + M15).
#
# M15: _fs_audit_umask used to compare the literal UMASK in login.defs
#      against the recommended values, but on Debian (USERGROUPS_ENAB=yes
#      by default) pam_umask rewrites group bits to match owner bits at
#      session start — so configured 027 becomes effective 007. The audit
#      now reports the *effective* value.
# M14: pam_umask presence in /etc/pam.d/common-session* gates whether the
#      login.defs UMASK is even applied at session start. The audit now
#      surfaces this as info.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/filesystem.sh"

    # Redirect the paths this family reads. Until these became module
    # variables the two tests at the bottom of this file could not run at all:
    # one skipped on every host that has /etc/login.defs (i.e. all of CI), and
    # the other could only assert that a function existed.
    etc=$(_vpssec_fake_etc)
    FS_LOGIN_DEFS="$etc/login.defs"
    FS_PROFILE="$etc/profile"
    FS_PAM_SESSION_FILES=(
        "$etc/pam.d/common-session"
        "$etc/pam.d/common-session-noninteractive"
    )
    mkdir -p "$etc/pam.d"
}

# ---------- _fs_compute_effective_umask ----------

@test "umask: USERGROUPS_ENAB=no leaves 027 unchanged → 0027" {
    run _fs_compute_effective_umask 027 no
    [ "$status" -eq 0 ]
    [ "$output" = "0027" ]
}

@test "umask: USERGROUPS_ENAB=yes rewrites 027 → 0007 (regression)" {
    # The exact M15 case: configured 027, effective is 007 because
    # pam_umask copies owner bits (0) to group bits.
    run _fs_compute_effective_umask 027 yes
    [ "$status" -eq 0 ]
    [ "$output" = "0007" ]
}

@test "umask: USERGROUPS_ENAB=yes rewrites 022 → 0002" {
    run _fs_compute_effective_umask 022 yes
    [ "$status" -eq 0 ]
    [ "$output" = "0002" ]
}

@test "umask: USERGROUPS_ENAB=yes rewrites 077 → 0007" {
    # Per login.defs(5) example: 077 → 007.
    run _fs_compute_effective_umask 077 yes
    [ "$status" -eq 0 ]
    [ "$output" = "0007" ]
}

@test "umask: input is normalized to 4 digits" {
    run _fs_compute_effective_umask 27 no
    [ "$status" -eq 0 ]
    [ "$output" = "0027" ]
    run _fs_compute_effective_umask 0027 no
    [ "$status" -eq 0 ]
    [ "$output" = "0027" ]
    run _fs_compute_effective_umask 7 no
    [ "$status" -eq 0 ]
    [ "$output" = "0007" ]
}

@test "umask: empty input defaults to 022" {
    run _fs_compute_effective_umask "" no
    [ "$status" -eq 0 ]
    [ "$output" = "0022" ]
}

@test "umask: USERGROUPS_ENAB case-insensitive (Yes/YES/yes all rewrite)" {
    run _fs_compute_effective_umask 027 Yes
    [ "$output" = "0007" ]
    run _fs_compute_effective_umask 027 YES
    [ "$output" = "0007" ]
    run _fs_compute_effective_umask 027 yes
    [ "$output" = "0007" ]
}

# ---------- _fs_get_usergroups_enab ----------

@test "usergroups: missing login.defs → defaults to yes" {
    # This used to skip on every host that HAS /etc/login.defs, which is every
    # Linux host including CI — so the default-when-absent contract was never
    # actually exercised. With FS_LOGIN_DEFS pointed at a scratch path it runs
    # everywhere.
    [ ! -f "$FS_LOGIN_DEFS" ]

    run _fs_get_usergroups_enab
    [ "$status" -eq 0 ]
    [ "$output" = "yes" ]
}

@test "usergroups: an absent directive defaults to yes, an explicit no is read" {
    printf 'MAIL_DIR\t/var/mail\n' > "$FS_LOGIN_DEFS"
    run _fs_get_usergroups_enab
    [ "$output" = "yes" ]

    printf 'USERGROUPS_ENAB\tno\n' >> "$FS_LOGIN_DEFS"
    run _fs_get_usergroups_enab
    [ "$output" = "no" ]
}

@test "usergroups: the value is lowercased" {
    printf 'USERGROUPS_ENAB\tYES\n' > "$FS_LOGIN_DEFS"
    run _fs_get_usergroups_enab
    [ "$output" = "yes" ]
}

# ---------- _fs_check_pam_umask_enabled ----------

@test "pam_umask: an active session line is detected" {
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"
    run _fs_check_pam_umask_enabled
    [ "$status" -eq 0 ]
}

@test "pam_umask: a commented-out line does not count" {
    # The whole point of the regex: a distro that ships the line commented is
    # not applying login.defs UMASK at session start.
    printf '# session optional pam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"
    run _fs_check_pam_umask_enabled
    [ "$status" -eq 1 ]
}

@test "pam_umask: the noninteractive file is checked too" {
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[1]}"
    run _fs_check_pam_umask_enabled
    [ "$status" -eq 0 ]
}

@test "pam_umask: absent files mean not enabled" {
    # The Debian 12 verification container is exactly this shape — no
    # pam_umask line anywhere — so this is the common case, not a corner one.
    run _fs_check_pam_umask_enabled
    [ "$status" -eq 1 ]
}

@test "pam_umask: an unrelated pam module is not mistaken for it" {
    printf 'session\trequired\tpam_unix.so\n' > "${FS_PAM_SESSION_FILES[0]}"
    run _fs_check_pam_umask_enabled
    [ "$status" -eq 1 ]
}
