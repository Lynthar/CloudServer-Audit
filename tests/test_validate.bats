#!/usr/bin/env bats
#
# Tests for input-validation helpers in core/common.sh.
# These are the boundary functions that gate every backup/write
# operation, so silent regressions here would be high-impact.

load helpers

setup() {
    _vpssec_load
}

# ---- validate_port ---------------------------------------------------

@test "validate_port: 22 is valid" {
    run validate_port 22
    [ "$status" -eq 0 ]
}

@test "validate_port: 1 is valid" {
    run validate_port 1
    [ "$status" -eq 0 ]
}

@test "validate_port: 65535 is valid (upper edge)" {
    run validate_port 65535
    [ "$status" -eq 0 ]
}

@test "validate_port: 0 is invalid (lower edge)" {
    run validate_port 0
    [ "$status" -ne 0 ]
}

@test "validate_port: 65536 is invalid (above max)" {
    run validate_port 65536
    [ "$status" -ne 0 ]
}

@test "validate_port: non-numeric is invalid" {
    run validate_port abc
    [ "$status" -ne 0 ]
}

@test "validate_port: empty is invalid" {
    run validate_port ""
    [ "$status" -ne 0 ]
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

# ---- validate_input --------------------------------------------------

@test "validate_input: empty pattern accepts within length limit" {
    run validate_input "anything goes" ""
    [ "$status" -eq 0 ]
}

@test "validate_input: matches required pattern" {
    run validate_input "abc123" '^[a-z0-9]+$'
    [ "$status" -eq 0 ]
}

@test "validate_input: rejects pattern mismatch" {
    run validate_input "ABC!" '^[a-z0-9]+$'
    [ "$status" -ne 0 ]
}

@test "validate_input: rejects when over max length" {
    local long
    long=$(printf 'x%.0s' {1..200})
    run validate_input "$long" "" 100
    [ "$status" -ne 0 ]
}

# ---- validate_ip: strengthened bounds (post-2026-08 review) -----------
# The old checks accepted 999.999.999.999 (shape only, no octet bounds)
# and "::::" (any hex-and-colon soup). This feeds ufw source scoping for
# the SSH rescue rule, so junk must be rejected, not passed downstream.

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
    # The discriminating specimen for the '::'-count rule: with the count
    # check gone, "1::2::3" still bounces off the 8-group requirement, but
    # THIS input satisfies it — only the double-colon counter rejects it.
    # (Found via a surviving mutant; lesson ⑥: fix the assertion's question.)
    run validate_ip "1::2:3:4:5:6:7::8"
    [ "$status" -eq 1 ]
}

@test "validate_ip: seven groups without :: is invalid" {
    run validate_ip "1:2:3:4:5:6:7"
    [ "$status" -eq 1 ]
}
