#!/usr/bin/env bats
# Tests for the rescue-port SELECTION logic in modules/ssh.sh; the daemon spawn,
# firewall and pid verification need a real host. _ssh_pick_rescue_port must
# never hand back the live SSH port or an already-listening one.

load helpers

setup() {
    _vpssec_load modules/ssh.sh
}

@test "pick_rescue_port: prefers 2222 when free and not the live port" {
    get_ssh_port() { echo 22; }
    get_listening_ports() { printf '22\n80\n443\n'; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" = "2222" ]
}

@test "pick_rescue_port: avoids 2222 when it IS the live SSH port" {
    get_ssh_port() { echo 2222; }
    get_listening_ports() { printf '2222\n'; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" != "2222" ]
}

@test "pick_rescue_port: avoids 2222 when it is already listening" {
    get_ssh_port() { echo 22; }
    get_listening_ports() { printf '22\n2222\n'; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" != "2222" ]
}

@test "pick_rescue_port: skips the whole occupied range to the first free port" {
    get_ssh_port() { echo 2222; }
    # Live port 2222 plus 2200-2298 occupied; only 2299 is free in the 2200s.
    get_listening_ports() { printf '2222\n'; seq 2200 2298; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" = "2299" ]
}

@test "pick_rescue_port: fails cleanly when no candidate port is free" {
    get_ssh_port() { echo 22; }
    get_listening_ports() { echo 2222; seq 2200 2299; seq 22000 22099; }
    run _ssh_pick_rescue_port
    [ "$status" -ne 0 ]
}

# _ssh_valid_cidr: when the source IP cannot be detected the operator types the
# CIDR that may reach the rescue port, so this is the gate between their input
# and a `ufw allow from` rule.

@test "rescue cidr: plain IPv4 accepted" {
    _ssh_valid_cidr "203.0.113.7"
}

@test "rescue cidr: IPv4 with prefix accepted" {
    _ssh_valid_cidr "203.0.113.0/24"
}

@test "rescue cidr: IPv4 prefix over 32 rejected" {
    _vpssec_refute _ssh_valid_cidr "203.0.113.0/33"
}

@test "rescue cidr: IPv6 with prefix accepted" {
    _ssh_valid_cidr "2001:db8::/64"
}

@test "rescue cidr: IPv6 prefix over 128 rejected" {
    _vpssec_refute _ssh_valid_cidr "2001:db8::/129"
}

@test "rescue cidr: junk rejected" {
    _vpssec_refute _ssh_valid_cidr "not-a-cidr"
    _vpssec_refute _ssh_valid_cidr "999.1.1.1/24"
}
