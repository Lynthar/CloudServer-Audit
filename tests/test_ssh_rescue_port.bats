#!/usr/bin/env bats
#
# Tests for the rescue-port SELECTION logic in modules/ssh.sh.
#
# The daemon spawn, firewall manipulation and pid verification need a real
# Linux host (sshd/ss/ufw) and are validated on a VM, not here. What is pure
# logic and testable anywhere is _ssh_pick_rescue_port: it must never hand back
# the live SSH port or an already-listening port. That is the exact bug behind
# the old fixed-2222 rescue, which became a silent no-op when the audit's own
# "use a non-default port" advice had already put sshd on 2222.

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
