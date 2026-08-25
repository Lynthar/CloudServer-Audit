#!/usr/bin/env bats
# Regression tests for the bitmask permission comparison in
# modules/filesystem.sh. An arithmetic comparison is wrong: 0604 < 0640
# numerically, yet 0604 grants world-read, so /etc/shadow at 604 passed.

load helpers.bash

setup() {
    # _fs_check_sensitive_file uses `stat -c "%a"` (GNU stat). On macOS
    # dev machines BSD stat does not support `-c`; skip rather than
    # report misleading failures.
    if ! stat -c "%a" / >/dev/null 2>&1; then
        skip "GNU stat (-c) not available on this host"
    fi

    _vpssec_load core/state.sh
    # filesystem.sh defines FS_SENSITIVE_FILES and helpers we need.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/filesystem.sh"
}

# Run _fs_check_sensitive_file against a file we create in tmpdir,
# bypassing the FS_SENSITIVE_FILES list (which uses /etc paths).
_run_check_with_perm() {
    local actual_mode="$1"
    local expected_mode="$2"
    local f="$BATS_TEST_TMPDIR/sensitive"
    : >"$f"
    chmod "$actual_mode" "$f"
    _fs_check_sensitive_file "$f" "$expected_mode"
}

@test "sensitive perms: actual==expected passes" {
    run _run_check_with_perm 640 640
    [ "$status" -eq 0 ]
}

@test "sensitive perms: more restrictive than expected passes" {
    # 600 < 644 numerically AND has no extra bits → safe.
    run _run_check_with_perm 600 644
    [ "$status" -eq 0 ]
}

@test "sensitive perms: 0604 vs expected 0640 FAILS (regression)" {
    # The original arithmetic test let this slip: 388 < 416, so the
    # check passed. 0604 grants world-read that 0640 does not.
    run _run_check_with_perm 604 640
    [ "$status" -eq 1 ]
    [[ "$output" == *"mode 604 (expected 640)"* ]]
}

@test "sensitive perms: wrong owner FAILS even with correct mode (root only)" {
    # Ownership drift (a botched restore chowns /etc/shadow to nobody) is
    # as much of a leak as a weak mode. The check only enforces this as
    # root — the audit's production condition — so skip otherwise.
    if [[ "$(id -u)" != "0" ]]; then
        skip "owner check active only when running as root"
    fi
    local f="$BATS_TEST_TMPDIR/owned"
    : >"$f"
    chmod 640 "$f"
    chown nobody "$f"
    run _fs_check_sensitive_file "$f" "640"
    [ "$status" -eq 1 ]
    [[ "$output" == *"owner nobody (expected root)"* ]]
}

@test "sensitive perms: foreign group with group bits FAILS (root only)" {
    if [[ "$(id -u)" != "0" ]]; then
        skip "group check active only when running as root"
    fi
    # Pick a real non-system group present on all target images.
    local grp="daemon"
    getent group "$grp" >/dev/null 2>&1 || skip "group $grp missing"
    local f="$BATS_TEST_TMPDIR/grouped"
    : >"$f"
    chmod 640 "$f"
    chgrp "$grp" "$f"
    run _fs_check_sensitive_file "$f" "640"
    [ "$status" -eq 1 ]
    [[ "$output" == *"group $grp grants access"* ]]
}

@test "sensitive perms: shadow group with group bits passes (root only)" {
    if [[ "$(id -u)" != "0" ]]; then
        skip "group check active only when running as root"
    fi
    getent group shadow >/dev/null 2>&1 || skip "no shadow group on this distro"
    local f="$BATS_TEST_TMPDIR/shadowed"
    : >"$f"
    chmod 640 "$f"
    chgrp shadow "$f"
    run _fs_check_sensitive_file "$f" "640"
    [ "$status" -eq 0 ]
}

@test "sensitive perms: 0046 vs expected 0640 FAILS (world-write)" {
    # Maximum-impact case: 38 < 416 numerically, but 0046 means
    # group-read + world-write. World-write on /etc/gshadow is
    # disastrous; the old check passed it.
    run _run_check_with_perm 046 640
    [ "$status" -eq 1 ]
}

@test "sensitive perms: 0644 vs expected 0644 passes" {
    run _run_check_with_perm 644 644
    [ "$status" -eq 0 ]
}

@test "sensitive perms: 0666 vs expected 0644 FAILS (world-write extra)" {
    run _run_check_with_perm 666 644
    [ "$status" -eq 1 ]
}

@test "sensitive perms: 0404 vs expected 0440 FAILS (world-read on sudoers)" {
    # Real sudoers shape: expected 0440 (owner+group read only).
    # 0404 grants world-read; numerically 260 < 288 so the old check
    # let it through.
    run _run_check_with_perm 404 440
    [ "$status" -eq 1 ]
}

@test "sensitive perms: 0440 vs expected 0440 passes" {
    run _run_check_with_perm 440 440
    [ "$status" -eq 0 ]
}
