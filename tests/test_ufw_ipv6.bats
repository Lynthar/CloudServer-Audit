#!/usr/bin/env bats
#
# Tests for the new IPv6-consistency helpers (M6).
# /etc/default/ufw IPV6=no + host has global v6 = v6 traffic bypasses
# UFW entirely. These pure-data helpers are the primitives the audit
# function composes.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"
}

# ---------- _ufw_parse_ipv6_setting ----------

@test "ipv6 setting: explicit yes" {
    run _ufw_parse_ipv6_setting "IPV6=yes"
    [ "$status" -eq 0 ]
    [ "$output" = "yes" ]
}

@test "ipv6 setting: explicit no" {
    run _ufw_parse_ipv6_setting "IPV6=no"
    [ "$status" -eq 0 ]
    [ "$output" = "no" ]
}

@test "ipv6 setting: missing IPV6= → defaults to yes" {
    run _ufw_parse_ipv6_setting "DEFAULT_INPUT_POLICY=DROP
ENABLED=yes"
    [ "$status" -eq 0 ]
    [ "$output" = "yes" ]
}

@test "ipv6 setting: empty input → defaults to yes" {
    run _ufw_parse_ipv6_setting ""
    [ "$status" -eq 0 ]
    [ "$output" = "yes" ]
}

@test "ipv6 setting: case-insensitive (IPV6=YES → yes)" {
    run _ufw_parse_ipv6_setting "IPV6=YES"
    [ "$status" -eq 0 ]
    [ "$output" = "yes" ]
}

@test "ipv6 setting: quoted value handled (IPV6=\"no\")" {
    run _ufw_parse_ipv6_setting 'IPV6="no"'
    [ "$status" -eq 0 ]
    [ "$output" = "no" ]
}

@test "ipv6 setting: only the first IPV6= line is used" {
    run _ufw_parse_ipv6_setting "IPV6=no
IPV6=yes"
    [ "$status" -eq 0 ]
    [ "$output" = "no" ]
}

# ---------- _host_has_global_ipv6_from_text ----------

@test "global v6: detects scope global inet6" {
    local ip_out="2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP qlen 1000
    inet6 2001:db8::1/64 scope global
       valid_lft forever preferred_lft forever"
    run _host_has_global_ipv6_from_text "$ip_out"
    [ "$status" -eq 0 ]
}

@test "global v6: link-local only → not global" {
    # When `ip -6 addr show scope global` is invoked it filters out
    # link-local automatically, so this asserts our regex doesn't
    # falsely match link-local even if a caller doesn't filter.
    local ip_out="2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever"
    run _host_has_global_ipv6_from_text "$ip_out"
    [ "$status" -ne 0 ]
}

@test "global v6: empty output (no v6 at all) → not global" {
    run _host_has_global_ipv6_from_text ""
    [ "$status" -ne 0 ]
}

@test "global v6: multiple addresses, at least one global → detected" {
    local ip_out="2: eth0:
    inet6 fe80::1/64 scope link
    inet6 2001:db8::1/64 scope global"
    run _host_has_global_ipv6_from_text "$ip_out"
    [ "$status" -eq 0 ]
}
