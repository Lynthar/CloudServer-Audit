#!/usr/bin/env bats
#
# Regression tests for _find_recent_users.
#
# It used to derive "recently created" from the home directory's mtime alone,
# which is wrong in both directions: a first login writes ~/.cache and bumps
# mtime, so a years-old account reads as brand new, while `useradd -M` creates
# no home directory at all and the account became invisible — precisely the
# backdoor shape this check exists to surface.
#
# The replacement tries home birth time, then home mtime, and falls back to
# /etc/shadow's sp_lstchg ONLY for accounts with no home directory. That last
# restriction matters: sp_lstchg also moves on every password change, so
# consulting it for accounts that do have a home would swap one false positive
# for another.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/users.sh"

    etc=$(_vpssec_fake_etc)
    USERS_SHADOW_FILE="$etc/shadow"
    : > "$USERS_SHADOW_FILE"

    homes="$BATS_TEST_TMPDIR/home"
    mkdir -p "$homes"
}

# passwd lines come from `getent`, so a stub is all it takes to drive this.
_passwd_is() {
    _vpssec_stub_script getent <<SH
[[ "\$1" == "passwd" && -z "\${2:-}" ]] && printf '%s\n' $(printf '%q ' "$@")
exit 0
SH
}

_shadow_line() {
    printf '%s\n' "$1" >> "$USERS_SHADOW_FILE"
}

# Days since epoch, N days ago.
_lstchg_days_ago() {
    echo $(( ( $(date +%s) - $1 * 86400 ) / 86400 ))
}

# ---- home-directory signals ------------------------------------------
#
# Note on aging a directory: `touch -d '30 days ago'` moves mtime but cannot
# move birth time, and this checker prefers birth time where the filesystem
# records it (the container's overlayfs does). So "old account" is simulated
# by moving the WINDOW instead of the file — RECENT_USER_DAYS=-1 puts the
# cutoff a day in the future, which no real timestamp can beat. That keeps
# these assertions running everywhere instead of skipping on half of the
# filesystems the tool actually ships to.

@test "recent users: a freshly made home directory is reported" {
    mkdir -p "$homes/alice"
    _passwd_is "alice:x:1001:1001::$homes/alice:/bin/bash"

    run _find_recent_users
    [[ "$output" == alice\|1001\|* ]]
}

@test "recent users: an account outside the window is not reported" {
    RECENT_USER_DAYS=-1
    mkdir -p "$homes/bob"
    _passwd_is "bob:x:1002:1002::$homes/bob:/bin/bash"

    run _find_recent_users
    [ -z "${output//[[:space:]]/}" ]
}

@test "recent users: system accounts below UID 1000 are skipped" {
    mkdir -p "$homes/svc"
    _passwd_is "svc:x:999:999::$homes/svc:/bin/bash"

    run _find_recent_users
    [ -z "${output//[[:space:]]/}" ]
}

# ---- the useradd -M regression ---------------------------------------

@test "recent users: an account with no home directory is still found via shadow" {
    # `useradd -M evil` — no home dir, so every home-based signal is blind.
    # This is the case the old implementation missed entirely.
    _passwd_is "evil:x:1003:1003::$homes/nonexistent:/bin/bash"
    _shadow_line "evil:\$6\$abc\$def:$(_lstchg_days_ago 1):0:99999:7:::"

    run _find_recent_users
    [[ "$output" == evil\|1003\|* ]]
    [[ "$output" == *"|password-set" ]]
}

@test "recent users: a homeless account with an old password date is not reported" {
    _passwd_is "old:x:1004:1004::$homes/nonexistent:/bin/bash"
    _shadow_line "old:\$6\$abc\$def:$(_lstchg_days_ago 400):0:99999:7:::"

    run _find_recent_users
    [ -z "${output//[[:space:]]/}" ]
}

@test "recent users: nobody is not reported as a new account" {
    # Regression from the shadow fallback itself: nobody is UID 65534 with
    # no home directory and a shadow entry stamped when the image was built,
    # so it matched the new "homeless account with a recent password date"
    # rule on every container and cloud image.
    _passwd_is "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
    _shadow_line "nobody:*:$(_lstchg_days_ago 1):0:99999:7:::"

    run _find_recent_users
    [ -z "${output//[[:space:]]/}" ]
}

@test "recent users: a high-UID system account is not reported" {
    # RHEL ships the same id as nfsnobody, which the name-based list does
    # not know about.
    _passwd_is "nfsnobody:x:65534:65534::/var/lib/nfs:/sbin/nologin"
    _shadow_line "nfsnobody:*:$(_lstchg_days_ago 1):0:99999:7:::"

    run _find_recent_users
    [ -z "${output//[[:space:]]/}" ]
}

@test "recent users: shadow lstchg of 0 is not treated as a date" {
    # 0 means "must change password at next login", i.e. 1970-01-01.
    _passwd_is "forced:x:1005:1005::$homes/nonexistent:/bin/bash"
    _shadow_line "forced:\$6\$abc\$def:0:0:99999:7:::"

    run _find_recent_users
    [ -z "${output//[[:space:]]/}" ]
}

# ---- the false positive the fallback must NOT introduce --------------

@test "recent users: shadow is never consulted when a home directory exists" {
    # The precedence rule, stated directly. sp_lstchg moves on every password
    # change, so letting it speak for accounts that DO have a home directory
    # would report everyone who rotated a password as "recently created" —
    # trading the old false positive for a new one. The account below is
    # reported (its home is fresh), but the evidence must come from the home
    # directory, never from shadow.
    mkdir -p "$homes/veteran"
    _passwd_is "veteran:x:1006:1006::$homes/veteran:/bin/bash"
    _shadow_line "veteran:\$6\$abc\$def:$(_lstchg_days_ago 1):0:99999:7:::"

    run _find_recent_users
    [[ "$output" == veteran\|1006\|* ]]
    [[ "$output" == *"|home-created" || "$output" == *"|home-modified" ]]
    [[ "$output" != *"password-set"* ]]
}

# ---- output contract -------------------------------------------------

@test "recent users: every row carries five pipe-separated fields" {
    # Consumers read user|uid|date|home|evidence positionally; a field count
    # change silently corrupts the last variable.
    mkdir -p "$homes/carol"
    _passwd_is "carol:x:1007:1007::$homes/carol:/bin/bash"

    run _find_recent_users
    [ "$(awk -F'|' 'NF{print NF}' <<<"$output")" = "5" ]
}
