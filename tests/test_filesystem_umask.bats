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
    _vpssec_load core/security_levels.sh core/state.sh
    i18n_load en_US
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

# ---------- what _fs_audit_umask REPORTS ----------
#
# The model that turns configured 027 into effective 007 does not reproduce on
# Debian 12: with pam_umask enabled, USERGROUPS_ENAB=yes and a private-group
# user, configured 077 gave a session umask of 0077. Whether that holds for a
# full getty/sshd login was not established, so the model stays and the
# SEVERITY BRANCH is untouched — these tests pin that, because changing it
# would move every host's score. What changed is the wording: the rewrite is
# reported as a possibility, and only when pam_umask is in the session stack.

# The JSON key is `desc`, not `description` — see create_check_json.
_emitted_ids()  { jq -r '.[].id' "$VPSSEC_STATE/checks.json"; }
_emitted_desc() { jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"; }

@test "audit umask: the finding for a stock 022 host is unchanged" {
    # The whole point of a text-only change: this id, and therefore the score,
    # must be identical before and after.
    printf 'UMASK\t\t022\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    # The ids are captured first: `_vpssec_refute _emitted_ids | grep …` would
    # bind the pipe to the refutation, so _vpssec_refute would negate
    # _emitted_ids (which always succeeds) and the grep result would be
    # discarded — an assertion that asserts nothing.
    local ids
    ids=$(_emitted_ids)
    grep -qx 'filesystem.umask_default' <<<"$ids"
    _vpssec_refute grep -qx 'filesystem.umask_weak' <<<"$ids"
}

@test "audit umask: a hardened 027 host still passes" {
    printf 'UMASK\t\t027\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    _emitted_ids | grep -qx 'filesystem.umask_ok'
    [ "$(_emitted_desc filesystem.umask_ok)" != "" ]
}

@test "audit umask: the group-bit rewrite is reported as a possibility" {
    printf 'UMASK\t\t022\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    local d
    d=$(_emitted_desc filesystem.umask_default)
    grep -q 'possibly effective=0002' <<<"$d"
    grep -q 'confirm with' <<<"$d"
    # The old wording asserted it as fact. An operator can disprove that by
    # typing `umask`, which is the whole reason for this change.
    _vpssec_refute grep -q 'rewrites group bits' <<<"$d"
}

@test "audit umask: with pam_umask absent the report says the value is not applied" {
    # Stock Debian 12 ships no pam_umask line, so this is the common case.
    # Claiming any effective value here would describe a path that does not
    # exist on the host.
    printf 'UMASK\t\t022\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    rm -f "${FS_PAM_SESSION_FILES[0]}" "${FS_PAM_SESSION_FILES[1]}"

    _fs_audit_umask
    local d
    d=$(_emitted_desc filesystem.umask_default)
    grep -q 'not applied at PAM session start' <<<"$d"
    _vpssec_refute grep -q 'possibly effective' <<<"$d"
}

@test "audit umask: pam_umask absent still emits its own info check" {
    printf 'UMASK\t\t022\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    rm -f "${FS_PAM_SESSION_FILES[0]}" "${FS_PAM_SESSION_FILES[1]}"

    _fs_audit_umask
    _emitted_ids | grep -qx 'filesystem.pam_umask_disabled'
    # Same finding as before this change: the info check is not new.
    _emitted_ids | grep -qx 'filesystem.umask_default'
}

@test "audit umask: pam_umask present emits no pam info check" {
    printf 'UMASK\t\t022\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    local ids
    ids=$(_emitted_ids)
    _vpssec_refute grep -qx 'filesystem.pam_umask_disabled' <<<"$ids"
}

@test "audit umask: USERGROUPS_ENAB=no reports no rewrite at all" {
    # The regression this uncovered: `configured` is what the file says (027)
    # and `effective` is always four digits (0027), so comparing them raw
    # differed for every 3-digit value and the qualifier was emitted even here
    # — the old text read "effective=0027 (USERGROUPS_ENAB=no rewrites group
    # bits)", which contradicts itself.
    printf 'UMASK\t\t027\nUSERGROUPS_ENAB\tno\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    [ "$(_emitted_desc filesystem.umask_ok)" = "configured=027" ]
}

@test "audit umask: a permissive value still lands in the scored branch" {
    # umask_weak is the ONLY one of the three umask checks in a scored
    # category (`recommended`; umask_ok and umask_default are `info`), so it is
    # the branch any "this change moves no score" claim rests on. Nothing above
    # reached it, and a mutation that widened umask_default to swallow
    # everything survived until this test existed.
    #
    # 072 with USERGROUPS_ENAB=no is deliberate: it is one of the six values
    # (0b2 with b not in {0,2}) where the rewrite model and the measured
    # behaviour would classify differently, so pinning it with the rewrite
    # switched off keeps the assertion stable whichever way that question is
    # settled later.
    printf 'UMASK\t\t072\nUSERGROUPS_ENAB\tno\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    local ids
    ids=$(_emitted_ids)
    grep -qx 'filesystem.umask_weak' <<<"$ids"
    _vpssec_refute grep -qx 'filesystem.umask_default' <<<"$ids"
    grep -q 'too permissive' <<<"$(_emitted_desc filesystem.umask_weak)"
}

@test "audit umask: a rewrite that changes nothing is not reported" {
    # 007 already has group bits equal to owner bits, so the rewrite is a
    # no-op even with USERGROUPS_ENAB=yes. Nothing to qualify.
    printf 'UMASK\t\t007\nUSERGROUPS_ENAB\tyes\n' > "$FS_LOGIN_DEFS"
    printf 'session\toptional\tpam_umask.so\n' > "${FS_PAM_SESSION_FILES[0]}"

    _fs_audit_umask
    [ "$(_emitted_desc filesystem.umask_ok)" = "configured=007" ]
}
