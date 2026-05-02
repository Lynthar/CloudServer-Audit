#!/usr/bin/env bats
#
# Regression tests for the bitmask permission comparison in
# modules/filesystem.sh. Catches the original arithmetic-comparison
# bug: actual=0604 < expected=0640 numerically, but 0604 grants
# world-read where 0640 does not, so /etc/shadow at mode 604 was
# silently passing the audit.

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
    [[ "$output" == *":604:640" ]]
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
