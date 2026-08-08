#!/usr/bin/env bats
#
# Tests for the package-manager lock predicate in core/distro.sh.
#
# The defect: the apt branch was three bare `lsof` calls ORed together. On a
# host without lsof each exits 127, the || chain yields 1, and the single
# caller (_update_audit_apt_lock) read that as "not locked" and emitted
# `update.apt_available` — status passed, category **required**, i.e. scored.
# So any host missing lsof was handed a scored pass for a question nobody had
# asked, and vpssec's own Debian verification container is such a host: that
# green line was in every smoke run this project has ever taken.
#
# The repair is two-part and both parts are pinned below:
#   1. /proc/locks became the primary source, which needs no package at all,
#      so the answer is real on a bare host rather than merely honest.
#   2. pkg_manager_locked gained a third return, 2 = could not determine, and
#      the audit emits an unscored info finding for it. "I could not tell"
#      must not be spelled the same as "no".

load helpers.bash

setup() {
    _vpssec_load core/distro.sh

    etc=$(_vpssec_fake_etc)
    lockfile="$etc/lock-frontend"
    : > "$lockfile"

    # Point the predicate at this test's files rather than the real apt ones.
    DISTRO_APT_LOCK_FILES=("$lockfile")
    VPSSEC_PKG_MGR=apt
}

teardown() {
    _release_lock
}

# Hold an flock on $1 from a LIVE process, and block until it really is held.
#
# `exec 9>f; flock -n 9` looks equivalent and is not. That idiom does take
# the lock — a second flock is refused — but the lock never appears in
# /proc/locks, because the kernel omits entries whose owning pid it cannot
# resolve in the READER's pid namespace, and the `flock` process that took
# it has already exited. Measured in the verification container, not assumed:
# the first draft of this suite used that idiom and three tests failed
# against correct production code.
#
# A live holder is also the case that matters: apt and dpkg hold their locks
# from a running process.
_hold_lock() {
    local f="$1" ready="$BATS_TEST_TMPDIR/lock-ready"
    rm -f "$ready"
    flock "$f" -c "touch '$ready'; sleep 30" &
    _lock_pid=$!
    local i=0
    while [[ ! -e "$ready" ]]; do
        if (( ++i > 200 )); then
            printf 'lock was never acquired\n' >&2
            return 1
        fi
        sleep 0.05
    done
}

_release_lock() {
    [[ -n "${_lock_pid:-}" ]] || return 0
    kill "$_lock_pid" 2>/dev/null || true
    wait "$_lock_pid" 2>/dev/null || true
    _lock_pid=""
}

# ---- _pkg_lock_held, against the REAL /proc/locks --------------------
#
# These two are the only place the dev:inode encoding is verified against
# the kernel rather than against our own arithmetic. Everything below them
# uses a fixture, which cannot prove the encoding is right.

@test "lock_held: a file another process holds an flock on reads as held" {
    [ -r /proc/locks ] || skip "no readable /proc/locks on this host"

    _hold_lock "$lockfile"
    run _pkg_lock_held "$lockfile"

    [ "$output" = "held" ]
}

@test "lock_held: the same file reads as free once the lock is released" {
    [ -r /proc/locks ] || skip "no readable /proc/locks on this host"

    _hold_lock "$lockfile"
    _release_lock

    run _pkg_lock_held "$lockfile"
    [ "$output" = "free" ]
}

# ---- _pkg_lock_held, branch logic ------------------------------------

@test "lock_held: a lock file that does not exist is free, not unknown" {
    run _pkg_lock_held "$etc/no-such-lock"
    [ "$output" = "free" ]
}

@test "lock_held: /proc/locks with no matching entry is free" {
    DISTRO_PROC_LOCKS="$etc/locks"
    printf '1: FLOCK  ADVISORY  WRITE 999 ff:ff:999999 0 EOF\n' > "$DISTRO_PROC_LOCKS"

    run _pkg_lock_held "$lockfile"
    [ "$output" = "free" ]
}

@test "lock_held: an unreadable /proc/locks falls back to lsof" {
    DISTRO_PROC_LOCKS="$etc/does-not-exist"
    _vpssec_stub lsof 0          # lsof reporting the file is open

    run _pkg_lock_held "$lockfile"
    [ "$output" = "held" ]
    _vpssec_stub_called lsof
}

@test "lock_held: the lsof fallback can also answer free" {
    DISTRO_PROC_LOCKS="$etc/does-not-exist"
    _vpssec_stub lsof 1

    run _pkg_lock_held "$lockfile"
    [ "$output" = "free" ]
}

@test "lock_held: no /proc/locks and no lsof is UNKNOWN, not free" {
    # The regression, stated at its narrowest. Before the fix this path
    # produced "not locked" and the caller published it as a scored pass.
    DISTRO_PROC_LOCKS="$etc/does-not-exist"
    _vpssec_absent_command lsof
    _vpssec_stub lsof 0          # on PATH, so "never called" is a real refutation

    run _pkg_lock_held "$lockfile"
    [ "$output" = "unknown" ]
    _vpssec_refute _vpssec_stub_called lsof
}

# ---- pkg_manager_locked: the three return values ---------------------

@test "pkg_manager_locked: apt with nothing held returns 1" {
    DISTRO_PROC_LOCKS="$etc/locks"
    : > "$DISTRO_PROC_LOCKS"

    run pkg_manager_locked
    [ "$status" -eq 1 ]
}

@test "pkg_manager_locked: apt with a held lock returns 0" {
    [ -r /proc/locks ] || skip "no readable /proc/locks on this host"

    _hold_lock "$lockfile"
    run pkg_manager_locked

    [ "$status" -eq 0 ]
}

@test "pkg_manager_locked: apt that cannot be measured returns 2, not 1" {
    DISTRO_PROC_LOCKS="$etc/does-not-exist"
    _vpssec_absent_command lsof

    run pkg_manager_locked
    [ "$status" -eq 2 ]
}

@test "pkg_manager_locked: a lock on a LATER file is still found" {
    # The loop must not stop at the first free file. apt takes three locks
    # and holds them at different points in a run, so the one that is held
    # is routinely not the first.
    [ -r /proc/locks ] || skip "no readable /proc/locks on this host"

    local first="$etc/first-lock"
    : > "$first"
    DISTRO_APT_LOCK_FILES=("$first" "$lockfile")

    _hold_lock "$lockfile"
    run pkg_manager_locked

    [ "$status" -eq 0 ]
}

@test "pkg_manager_locked: an unmeasurable file does not mask a held one" {
    # Mixed answers: the first file cannot be measured, the second is
    # genuinely locked. Returning 2 as soon as one file is unknown would
    # report "could not determine" for a host that demonstrably IS locked —
    # so the loop records the unknown and keeps going.
    #
    # Per-file unknown needs stat to fail for that file only, which is why
    # stat is stubbed by argv rather than /proc/locks being hidden (hiding
    # it makes EVERY file unknown and cannot construct this case).
    [ -r /proc/locks ] || skip "no readable /proc/locks on this host"

    local real_stat ghost="$etc/ghost-lock"
    real_stat="$(command -v stat)"
    : > "$ghost"
    DISTRO_APT_LOCK_FILES=("$ghost" "$lockfile")

    _vpssec_stub_script stat <<SH
case "\$*" in
    *ghost-lock*) exit 1 ;;
esac
exec "$real_stat" "\$@"
SH
    _vpssec_absent_command lsof

    _hold_lock "$lockfile"
    run pkg_manager_locked

    [ "$status" -eq 0 ]
}

@test "pkg_manager_locked: an unmeasurable file alone still returns 2" {
    # The companion to the test above: with nothing held, the unknown must
    # survive to the end rather than being rounded down to "not locked".
    local real_stat ghost="$etc/ghost-lock"
    real_stat="$(command -v stat)"
    : > "$ghost"
    DISTRO_APT_LOCK_FILES=("$ghost" "$lockfile")

    _vpssec_stub_script stat <<SH
case "\$*" in
    *ghost-lock*) exit 1 ;;
esac
exec "$real_stat" "\$@"
SH
    _vpssec_absent_command lsof

    run pkg_manager_locked
    [ "$status" -eq 2 ]
}

@test "pkg_manager_locked: dnf without pgrep returns 2, not 1" {
    VPSSEC_PKG_MGR=dnf
    _vpssec_absent_command pgrep
    _vpssec_stub pgrep 1

    run pkg_manager_locked
    [ "$status" -eq 2 ]
    _vpssec_refute _vpssec_stub_called pgrep
}

@test "pkg_manager_locked: an unrecognised package manager returns 2, not 1" {
    # We have not looked at anything, so "not locked" would be a claim.
    VPSSEC_PKG_MGR=zypper

    run pkg_manager_locked
    [ "$status" -eq 2 ]
}
