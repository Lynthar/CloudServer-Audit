#!/usr/bin/env bats
# Tests for input-validation helpers in core/common.sh. These are the boundary
# functions that gate every backup and write, so a silent regression here is
# high-impact.

load helpers

setup() {
    _vpssec_load
}

# ---- validate_ip -----------------------------------------------------

@test "validate_ip: 192.168.1.1 is valid" {
    run validate_ip "192.168.1.1"
    [ "$status" -eq 0 ]
}

@test "validate_ip: ::1 is valid (IPv6 loopback)" {
    run validate_ip "::1"
    [ "$status" -eq 0 ]
}

@test "validate_ip: empty is invalid" {
    run validate_ip ""
    [ "$status" -ne 0 ]
}

@test "validate_ip: garbage is invalid" {
    run validate_ip "not-an-ip"
    [ "$status" -ne 0 ]
}

# ---- validate_path ---------------------------------------------------

@test "validate_path: simple path is valid" {
    run validate_path "/etc/ssh/sshd_config"
    [ "$status" -eq 0 ]
}

@test "validate_path: '..' traversal is rejected" {
    run validate_path "/etc/../etc/passwd"
    [ "$status" -ne 0 ]
}

@test "validate_path: empty path is rejected" {
    run validate_path ""
    [ "$status" -ne 0 ]
}

@test "validate_path: leading whitespace rejected" {
    run validate_path " /etc/passwd"
    [ "$status" -ne 0 ]
}

@test "validate_path: trailing whitespace rejected" {
    run validate_path "/etc/passwd "
    [ "$status" -ne 0 ]
}

@test "validate_path: path under base_dir is accepted" {
    _vpssec_require_gnu_realpath
    local base="$BATS_TEST_TMPDIR/base"
    mkdir -p "$base/sub"
    run validate_path "$base/sub/file" "$base"
    [ "$status" -eq 0 ]
}

@test "validate_path: path outside base_dir is rejected" {
    _vpssec_require_gnu_realpath
    local base="$BATS_TEST_TMPDIR/base"
    mkdir -p "$base"
    run validate_path "/etc/passwd" "$base"
    [ "$status" -ne 0 ]
}

@test "validate_path: sibling sharing the base name prefix is rejected" {
    # Regression: a bare "$base"* prefix match accepted /…/base-evil/x as
    # being "under" /…/base. The boundary must be "$base" or "$base/".
    _vpssec_require_gnu_realpath
    local base="$BATS_TEST_TMPDIR/base"
    mkdir -p "${base}-evil"
    run validate_path "${base}-evil/x" "$base"
    [ "$status" -ne 0 ]
}

@test "validate_path: the base directory itself is accepted" {
    _vpssec_require_gnu_realpath
    local base="$BATS_TEST_TMPDIR/base"
    mkdir -p "$base"
    run validate_path "$base" "$base"
    [ "$status" -eq 0 ]
}

# validate_ip bounds. A shape-only check accepts 999.999.999.999 and "::::";
# this feeds ufw source scoping for the SSH rescue rule, so junk must be
# rejected rather than passed downstream.

@test "validate_ip: 999.999.999.999 is invalid (octet bounds)" {
    run validate_ip "999.999.999.999"
    [ "$status" -eq 1 ]
}

@test "validate_ip: 256.1.1.1 is invalid" {
    run validate_ip "256.1.1.1"
    [ "$status" -eq 1 ]
}

@test "validate_ip: '::::' is invalid" {
    run validate_ip "::::"
    [ "$status" -eq 1 ]
}

@test "validate_ip: full 8-group IPv6 is valid" {
    run validate_ip "2001:0db8:0000:0000:0000:0000:0000:0001"
    [ "$status" -eq 0 ]
}

@test "validate_ip: fe80::1 is valid" {
    run validate_ip "fe80::1"
    [ "$status" -eq 0 ]
}

@test "validate_ip: nine groups is invalid" {
    run validate_ip "1:2:3:4:5:6:7:8:9"
    [ "$status" -eq 1 ]
}

@test "validate_ip: two double-colons is invalid" {
    run validate_ip "1::2::3"
    [ "$status" -eq 1 ]
}

@test "validate_ip: two double-colons with eight groups is invalid" {
    # The discriminating specimen for the '::'-count rule: with the count check
    # gone, "1::2::3" still bounces off the 8-group requirement, but THIS input
    # satisfies it — only the double-colon counter rejects it.
    run validate_ip "1::2:3:4:5:6:7::8"
    [ "$status" -eq 1 ]
}

@test "validate_ip: seven groups without :: is invalid" {
    run validate_ip "1:2:3:4:5:6:7"
    [ "$status" -eq 1 ]
}
