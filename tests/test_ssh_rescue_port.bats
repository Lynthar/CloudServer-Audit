#!/usr/bin/env bats
# Rescue-port selection and the firewall decision in modules/ssh.sh; the daemon
# spawn and pid verification need a real host. The port must never be the live
# SSH port or a listening one, and an unknown firewall state must be said.

load helpers

setup() {
    _vpssec_load modules/ssh.sh
}

@test "pick_rescue_port: prefers 2222 when free and not the live port" {
    get_ssh_ports() { echo 22; }
    get_listening_ports() { printf '22\n80\n443\n'; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" = "2222" ]
}

@test "pick_rescue_port: avoids 2222 when it IS the live SSH port" {
    get_ssh_ports() { echo 2222; }
    get_listening_ports() { printf '2222\n'; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" != "2222" ]
}

@test "pick_rescue_port: avoids 2222 when it is already listening" {
    get_ssh_ports() { echo 22; }
    get_listening_ports() { printf '22\n2222\n'; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" != "2222" ]
}

@test "pick_rescue_port: skips the whole occupied range to the first free port" {
    get_ssh_ports() { echo 2222; }
    # Live port 2222 plus 2200-2298 occupied; only 2299 is free in the 2200s.
    get_listening_ports() { printf '2222\n'; seq 2200 2298; }
    run _ssh_pick_rescue_port
    [ "$status" -eq 0 ]
    [ "$output" = "2299" ]
}

@test "pick_rescue_port: fails cleanly when no candidate port is free" {
    get_ssh_ports() { echo 22; }
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

# ---- the firewall decision --------------------------------------------------

_rescue_fw_with() {
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    SSH_RESCUE_PORT=2222
    SSH_RESCUE_FW_RULE=""
    get_current_ssh_ip() { echo ""; }
    FW_ANSWER="$1"
    fw_backend() { [[ "$FW_ANSWER" == unknown ]] && return 1; echo "$FW_ANSWER"; }
    _vpssec_stub ufw 0
}

@test "rescue firewall: an unknown firewall state is said, not treated as none" {
    _rescue_fw_with unknown

    run _ssh_rescue_allow_firewall
    [ "$status" -eq 0 ]
    grep -q 'Could not determine the firewall state' <<<"$output"
    _vpssec_refute grep -q 'Firewall is active' <<<"$output"
    _vpssec_refute _vpssec_stub_called ufw
}

@test "rescue firewall: no firewall adds nothing and says nothing" {
    _rescue_fw_with none

    run _ssh_rescue_allow_firewall
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    _vpssec_refute _vpssec_stub_called ufw
}

@test "rescue firewall: a firewall it does not manage is named as active" {
    _rescue_fw_with nftables

    run _ssh_rescue_allow_firewall
    [ "$status" -eq 0 ]
    grep -q 'Firewall is active' <<<"$output"
}

@test "rescue firewall: on a recognised cloud, its own firewall is named with the port" {
    # A cloud firewall drops the rescue port before any host backend sees it.
    i18n_load en_US
    SSH_RESCUE_PORT=2222
    VPSSEC_CLOUD_PROVIDER=azure

    run _ssh_rescue_cloud_hint
    [ "$status" -eq 0 ]
    [[ "$output" == *"network security group (NSG) allows TCP 2222"* ]]
}

@test "rescue firewall: off a recognised cloud, no cloud firewall is mentioned" {
    i18n_load en_US
    SSH_RESCUE_PORT=2222
    VPSSEC_CLOUD_PROVIDER=unknown

    run _ssh_rescue_cloud_hint
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "rescue firewall: a rule ufw would not delete is named with the command that does" {
    i18n_load en_US
    SSH_RESCUE_FW_RULE="ufw:203.0.113.9:2222"
    _vpssec_stub ufw 1

    run _ssh_rescue_remove_firewall
    [[ "$output" == *"remove it by hand: ufw delete allow from 203.0.113.9 to any port 2222 proto tcp"* ]]
}

@test "rescue firewall: a rule ufw deleted, or had already gone, is not reported" {
    # ufw answers 0 for a rule that is already gone, as after the watchdog's
    # teardown, so the parent's second delete stays quiet.
    i18n_load en_US
    SSH_RESCUE_FW_RULE="ufw::2222"
    _vpssec_stub ufw 0

    run _ssh_rescue_remove_firewall
    [ -z "$output" ]
    _vpssec_stub_called ufw 'delete allow 2222/tcp'
}

# ---- the rescue's lifetime bound --------------------------------------------

# True while $1 runs; a never-reaped zombie (its parent may be a PID 1 that
# does not reap) counts as gone. /proc, not ps: Rocky's image has no procps.
_alive() {
    local st
    st=$(cut -d' ' -f3 "/proc/$1/stat" 2>/dev/null) || return 1
    [[ -n "$st" && "$st" != Z ]]
}

# Opening and closing the rescue set and clear EXIT/INT/TERM/HUP traps in the
# calling shell, which here is bats' test process: put bats' traps back after,
# or a failed assertion that follows is never reported and the test vanishes.
_keeping_bats_traps() {
    local saved rc=0
    saved=$(trap -p EXIT INT TERM HUP)
    "$@" || rc=$?
    trap - EXIT INT TERM HUP
    eval "$saved"
    return "$rc"
}

# A stand-in vpssec that arms the watchdog over a fake rescue ($1), then blocks as
# at the confirmation prompt ($2 / $3: window and grace). Its parent never reaps
# it, so once killed it stays a zombie, as under a CI container's PID 1.
_vpssec_holding_rescue() {
    local pidfile="$BATS_TEST_TMPDIR/holder.pid" i
    bash -c 'bash -c "$1" _ "$2" "$3" "$4" "$5" & echo $! > "$6"; exec sleep 300' _ \
        'source "$1/core/common.sh"; source "$1/modules/ssh.sh"
        _log_file=/dev/null; VPSSEC_CONFIRM_TIMEOUT=$3; SSH_RESCUE_GRACE=$4
        SSH_RESCUE_PID=$2; SSH_RESCUE_PORT=2222; SSH_RESCUE_FW_RULE="ufw::2222"
        _ssh_rescue_start_watchdog; sleep 300' \
        "$(_vpssec_repo_root)" "$1" "${2:-300}" "${3:-120}" "$pidfile" \
        >/dev/null 2>&1 3>&- &
    for i in $(seq 1 50); do [[ -s "$pidfile" ]] && break; sleep 0.1; done
    cat "$pidfile"
}

@test "rescue watchdog: vpssec killed by SIGKILL does not leave the rescue running" {
    # No trap runs on SIGKILL; before the watchdog the root-and-password
    # daemon outlived vpssec until reboot, its firewall rule with it.
    _vpssec_stub ufw
    sleep 300 &
    local rescue=$! parent i
    parent=$(_vpssec_holding_rescue "$rescue")
    sleep 1
    kill -KILL "$parent"
    for i in $(seq 1 50); do _alive "$rescue" || break; sleep 0.1; done

    _vpssec_refute _alive "$rescue"
    _vpssec_stub_called ufw 'delete allow 2222/tcp'
}

@test "rescue watchdog: the rescue does not outlive the confirmation window" {
    # The session dropped silently: vpssec is still alive, blocked on a read
    # nobody will answer. The bound must not depend on it noticing.
    _vpssec_stub ufw
    sleep 300 &
    local rescue=$! parent i
    parent=$(_vpssec_holding_rescue "$rescue" 1 1)
    for i in $(seq 1 60); do _alive "$rescue" || break; sleep 0.1; done

    _vpssec_refute _alive "$rescue"
    _alive "$parent"
    kill "$parent" 2>/dev/null || true
}

@test "rescue watchdog: a normal close stops the watchdog with the rescue" {
    _vpssec_stub ufw
    sleep 300 &
    SSH_RESCUE_PID=$!
    SSH_RESCUE_FW_RULE=""
    _log_file=/dev/null
    _ssh_rescue_start_watchdog
    local dog="$SSH_RESCUE_WATCHDOG_PID" rescue="$SSH_RESCUE_PID" i

    _keeping_bats_traps _ssh_close_rescue_port
    for i in $(seq 1 30); do _alive "$dog" || break; sleep 0.1; done
    _vpssec_refute _alive "$dog"
    _vpssec_refute _alive "$rescue"
}

@test "rescue confirmation: no answer within the window is a no" {
    # confirm_critical reads with a timeout; a silent session must decline.
    # script(1) gives it a real terminal; the pipe keeps that terminal's input
    # open and empty, so the read times out rather than hitting end-of-file.
    command -v script >/dev/null || skip "script(1) not installed"
    cat > "$BATS_TEST_TMPDIR/probe.sh" <<SH
source "$(_vpssec_repo_root)/core/common.sh"
_log_file=/dev/null
VPSSEC_CONFIRM_TIMEOUT=1
confirm_critical XYZ || echo "rc=\$?"
SH
    run bash -c "sleep 5 | script -qec 'bash $BATS_TEST_TMPDIR/probe.sh' /dev/null"
    [[ "$output" == *XYZ* ]]
    [[ "$output" == *error.confirm_timeout* ]]
    [[ "$output" == *rc=1* ]]
}

# A shell with an EXIT trap of its own that opens the rescue over a stand-in
# daemon, closes it when $1 is "close", then exits. Prints what it saw.
_caller_with_exit_trap() {
    printf '#!/usr/bin/env bash\nexec sleep 300\n' > "$BATS_TEST_TMPDIR/fake-sshd"
    chmod +x "$BATS_TEST_TMPDIR/fake-sshd"
    _vpssec_stub sshd
    bash -c 'source "$1/core/common.sh"; source "$1/modules/ssh.sh"
        _log_file=/dev/null; SSH_RESCUE_SSHD="$2"
        _ssh_pick_rescue_port() { echo 2299; }
        _ssh_rescue_is_up() { kill -0 "$SSH_RESCUE_PID" 2>/dev/null; }
        _ssh_rescue_allow_firewall() { :; }
        _ssh_rescue_start_watchdog() { :; }
        trap "echo caller-exit" EXIT
        _ssh_open_rescue_port >/dev/null 2>&1
        echo "rescue=$SSH_RESCUE_PID"
        if [[ "$3" == close ]]; then
            _ssh_close_rescue_port
            _ssh_close_rescue_port
            trap -p EXIT | grep -q caller-exit && echo caller-trap-back
        fi
        exit 0' _ "$(_vpssec_repo_root)" "$BATS_TEST_TMPDIR/fake-sshd" "${1:-}" 2>/dev/null
}

@test "rescue close: the caller's own traps are put back, even after a second close" {
    # trap - cleared them, so a caller's EXIT cleanup never ran.
    run _caller_with_exit_trap close
    [[ "$output" == *caller-trap-back* ]]
    [ "$(grep -c caller-exit <<<"$output")" -eq 1 ]
}

@test "rescue close at exit: the rescue is closed and the caller's EXIT command still runs once" {
    run _caller_with_exit_trap
    [ "$(grep -c caller-exit <<<"$output")" -eq 1 ]
    local rescue
    rescue=$(sed -n 's/^rescue=//p' <<<"$output")
    [ -n "$rescue" ]
    _vpssec_refute _alive "$rescue"
}

@test "rescue open: a daemon confirmed listening gets its watchdog" {
    # Through the real open path, with a stand-in daemon: the watchdog is what
    # bounds the rescue once vpssec itself can no longer run its traps.
    _log_file=/dev/null
    _vpssec_stub sshd
    printf '#!/usr/bin/env bash\nexec sleep 300\n' > "$BATS_TEST_TMPDIR/fake-sshd"
    chmod +x "$BATS_TEST_TMPDIR/fake-sshd"
    SSH_RESCUE_SSHD="$BATS_TEST_TMPDIR/fake-sshd"
    _ssh_pick_rescue_port() { echo 2299; }
    _ssh_rescue_is_up() { kill -0 "$SSH_RESCUE_PID" 2>/dev/null; }
    _ssh_rescue_allow_firewall() { :; }

    _keeping_bats_traps _ssh_open_rescue_port
    local dog="$SSH_RESCUE_WATCHDOG_PID" rescue="$SSH_RESCUE_PID"
    [ -n "$dog" ]
    _alive "$dog"

    _keeping_bats_traps _ssh_close_rescue_port
    _vpssec_refute _alive "$rescue"
}

@test "rescue open: on a recognised cloud, its firewall is named before the confirmation" {
    _log_file=/dev/null
    i18n_load en_US
    VPSSEC_CLOUD_PROVIDER=gcp
    _vpssec_stub sshd
    printf '#!/usr/bin/env bash\nexec sleep 300\n' > "$BATS_TEST_TMPDIR/fake-sshd"
    chmod +x "$BATS_TEST_TMPDIR/fake-sshd"
    SSH_RESCUE_SSHD="$BATS_TEST_TMPDIR/fake-sshd"
    _ssh_pick_rescue_port() { echo 2299; }
    _ssh_rescue_is_up() { kill -0 "$SSH_RESCUE_PID" 2>/dev/null; }
    _ssh_rescue_allow_firewall() { :; }

    _keeping_bats_traps _ssh_open_rescue_port 2>"$BATS_TEST_TMPDIR/said"
    _keeping_bats_traps _ssh_close_rescue_port
    grep -q 'Google Cloud VPC firewall rule allows TCP 2299' "$BATS_TEST_TMPDIR/said"
}
