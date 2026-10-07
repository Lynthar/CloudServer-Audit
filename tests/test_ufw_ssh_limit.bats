#!/usr/bin/env bats
# _ufw_admits_port reads ufw's own rule tuples, the one source both the audit
# and the three ufw fixes ask "is this port let in?". Reading an outbound rule
# as inbound coverage locks the operator out; missing a LIMIT rule rewrites it.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"
    UFW_USER_RULES="$BATS_TEST_TMPDIR/user.rules"
    UFW_USER6_RULES="$BATS_TEST_TMPDIR/user6.rules"
    : > "$UFW_USER_RULES"
    : > "$UFW_USER6_RULES"
}

# One tuple, in the format ufw writes to user.rules ($1) or user6.rules ($1=6).
_tuple() {
    local file="$UFW_USER_RULES"
    [[ "$1" == 6 ]] && { file="$UFW_USER6_RULES"; shift; }
    printf '### tuple ### %s\n' "$*" >> "$file"
}

@test "ALLOW and LIMIT on the port both count" {
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
    _ufw_admits_port 22
    : > "$UFW_USER_RULES"
    _tuple limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
    _ufw_admits_port 22 open
}

@test "a rule only in user6.rules still counts" {
    _tuple 6 limit tcp 22 ::/0 any ::/0 in
    _ufw_admits_port 22
}

@test "DENY, outbound and routed rules never count" {
    _tuple deny tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 out
    _tuple route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1
    _vpssec_refute _ufw_admits_port 22
}

@test "port lists, ranges and any-protocol rules are understood" {
    _tuple allow tcp 80,22,443 0.0.0.0/0 any 0.0.0.0/0 in
    _ufw_admits_port 22
    : > "$UFW_USER_RULES"
    _tuple allow tcp 2000:3000 0.0.0.0/0 any 0.0.0.0/0 in
    _ufw_admits_port 2222
    _vpssec_refute _ufw_admits_port 22
    : > "$UFW_USER_RULES"
    _tuple allow any 22 0.0.0.0/0 any 0.0.0.0/0 in
    _ufw_admits_port 22
}

@test "a UDP-only rule does not admit TCP" {
    _tuple allow udp 22 0.0.0.0/0 any 0.0.0.0/0 in
    _vpssec_refute _ufw_admits_port 22
}

@test "another port, or no rules at all, does not count" {
    _tuple allow tcp 2200 0.0.0.0/0 any 0.0.0.0/0 in
    _vpssec_refute _ufw_admits_port 22
    rm -f "$UFW_USER_RULES" "$UFW_USER6_RULES"
    _vpssec_refute _ufw_admits_port 22
}

@test "interface, source and destination limits count for 'any' but not for 'open'" {
    _tuple allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
    _ufw_admits_port 22
    _vpssec_refute _ufw_admits_port 22 open
    : > "$UFW_USER_RULES"
    _tuple allow any any 0.0.0.0/0 any 203.0.113.5 in
    _ufw_admits_port 22
    _vpssec_refute _ufw_admits_port 22 open
    : > "$UFW_USER_RULES"
    _tuple allow tcp 22 10.1.1.1 any 0.0.0.0/0 in
    _ufw_admits_port 22
    _vpssec_refute _ufw_admits_port 22 open
}

@test "an app profile rule carries its resolved port, and a comment field is skipped" {
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in comment=6f7073
    _ufw_admits_port 22
    _ufw_admits_port 22 open
}

@test "the SSH check needs every port sshd listens on, not just one" {
    get_ssh_ports() { printf '22\n2222\n'; }
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
    _vpssec_refute _ufw_ssh_allowed
    _tuple limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in
    _ufw_ssh_allowed
}
