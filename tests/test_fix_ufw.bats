#!/usr/bin/env bats
# Coverage for the ufw fixes. ufw.enable and ufw.set_default_deny can cut the
# operator's session, so ORDER is the contract — open every sshd port first,
# abort if that fails — and every ordering assertion compares call-log positions.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"

    export TMPDIR="$BATS_TEST_TMPDIR"

    # get_current_ssh_ip reads these first and falls back to `who am i`.
    # Unset plus a silent `who` gives "operator IP unknown" as the default;
    # individual tests opt into a known IP.
    unset SSH_CONNECTION SSH_CLIENT
    _vpssec_stub who

    ufw_rules="$BATS_TEST_TMPDIR/ufw-rules"
    ufw_state="$BATS_TEST_TMPDIR/ufw-state"

    _sshd_ports 22
    _ufw_working
}

# ---- stubs ----------------------------------------------------------

# `sshd -T` reporting the given ports, which is what get_ssh_ports reads.
_sshd_ports() {
    printf 'port %s\n' "$@" > "$BATS_TEST_TMPDIR/sshd-ports"
    _vpssec_stub_script sshd <<SH
[[ "\$*" == *-T* ]] && cat "$BATS_TEST_TMPDIR/sshd-ports"
exit 0
SH
}

# A ufw that remembers: `allow` records a rule and `status` reports the rules
# recorded so far, so _ufw_port_allowed sees what earlier calls did. $1, when
# given, is a port whose `allow` fails; everything else succeeds.
_ufw_working() {
    local failing_port="${1:-}"
    : > "$ufw_rules"
    printf 'inactive\n' > "$ufw_state"
    _vpssec_stub_script ufw <<SH
rules="$ufw_rules"
state="$ufw_state"
fail_port="$failing_port"
case "\$1" in
    allow)
        if [[ "\$2" == from ]]; then
            printf 'Anywhere ALLOW %s\n' "\$3" >> "\$rules"
        else
            [[ -n "\$fail_port" && "\$2" == "\$fail_port"* ]] && exit 1
            printf '%s ALLOW  Anywhere\n' "\$2" >> "\$rules"
        fi
        ;;
    enable)  printf 'active\n' > "\$state" ;;
    status)  printf 'Status: %s\n' "\$(cat "\$state")"; cat "\$rules" ;;
    delete|default) ;;
esac
exit 0
SH
}

# ufw refuses the operation named by $1 (enable / default), everything else
# behaves as _ufw_working.
_ufw_refuses() {
    _ufw_working
    local op="$1"
    _vpssec_stub_script ufw <<SH
rules="$ufw_rules"
state="$ufw_state"
[[ "\$1" == "$op" ]] && exit 1
case "\$1" in
    allow)
        if [[ "\$2" == from ]]; then
            printf 'Anywhere ALLOW %s\n' "\$3" >> "\$rules"
        else
            printf '%s ALLOW  Anywhere\n' "\$2" >> "\$rules"
        fi
        ;;
    enable)  printf 'active\n' > "\$state" ;;
    status)  printf 'Status: %s\n' "\$(cat "\$state")"; cat "\$rules" ;;
esac
exit 0
SH
}

# Pretend the operator is connected from this address.
_operator_at() { export SSH_CONNECTION="$1 54321 10.0.0.1 22"; }

# 1-based position of the first logged call matching the regex; empty when
# it never ran. Comparing two of these is how ordering is asserted.
_call_at() {
    grep -nE "$1" "$VPSSEC_STUB_LOG" 2>/dev/null | head -1 | cut -d: -f1
}

# ==============================================================================
# ufw.enable — the fix that can strand the operator
# ==============================================================================

@test "enable: every sshd port is opened before the firewall comes up" {
    _sshd_ports 22 2222
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]

    local first_port second_port enable_at
    first_port=$(_call_at '^ufw allow 22/tcp')
    second_port=$(_call_at '^ufw allow 2222/tcp')
    enable_at=$(_call_at '^ufw enable')

    # Kept as separate statements: bash exempts every command of an AND-OR
    # list but the last from errexit, so chaining these with && would hide
    # a failure of the first two.
    [ -n "$first_port" ]
    [ -n "$second_port" ]
    [ -n "$enable_at" ]
    [ "$first_port" -lt "$enable_at" ]
    [ "$second_port" -lt "$enable_at" ]
}

@test "enable: a refused SSH rule aborts before the firewall is enabled" {
    # The lockout in one line: enabling with a default-deny policy and no
    # SSH rule. Failing to add the rule must stop the fix, not be shrugged
    # off on the way to `ufw enable`.
    _ufw_working 22
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'enable'
}

@test "enable: the second port failing still aborts before enabling" {
    # The first port succeeding must not be read as "SSH is covered".
    _sshd_ports 22 2222
    _ufw_working 2222
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'enable'
}

@test "enable: declining the confirmation leaves the firewall down" {
    confirm_critical() { return 1; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'enable'
}

@test "enable: declining removes the session rescue rule" {
    # Nothing else changed, and a blanket allow-from-this-IP is the
    # broadest rule the fix adds — it should not outlive a cancelled run.
    _operator_at 203.0.113.9
    confirm_critical() { return 1; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_stub_called ufw 'delete allow from 203\.0\.113\.9'
}

@test "enable: the rescue rule survives a successful enable" {
    # Deliberate. If the detected SSH port does not actually cover the live
    # connection (NAT, a port sshd -T did not report), deleting this rule
    # right after enabling is precisely what locks the operator out.
    _operator_at 203.0.113.9
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow from 203\.0\.113\.9'
    _vpssec_refute _vpssec_stub_called ufw 'delete'
}

@test "enable: no rescue rule is invented when the operator IP is unknown" {
    # A wrong `allow from` source is worse than none — guessing would open
    # the host to whatever address was guessed.
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called ufw 'allow from'
}

@test "enable: a refused enable is reported as failure" {
    _ufw_refuses enable
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
}

# ==============================================================================
# ufw.set_default_deny — the other way to cut the session
# ==============================================================================

@test "default deny: the SSH rule is added before the policy flips" {
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]

    local allow_at deny_at
    allow_at=$(_call_at '^ufw allow 22/tcp')
    deny_at=$(_call_at '^ufw default deny incoming')

    [ -n "$allow_at" ] && [ -n "$deny_at" ]
    [ "$allow_at" -lt "$deny_at" ]
}

@test "default deny: a refused SSH rule aborts before the policy flips" {
    _ufw_working 22

    run _ufw_fix_default_deny
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'default deny'
}

@test "default deny: every sshd port is covered, not just the first" {
    _sshd_ports 22 2222

    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow 22/tcp'
    _vpssec_stub_called ufw 'allow 2222/tcp'
}

@test "default deny: an already-allowed port is not re-added" {
    printf '22/tcp ALLOW  Anywhere\n' > "$ufw_rules"

    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called ufw 'allow 22/tcp'
    _vpssec_stub_called ufw 'default deny incoming'
}

@test "default deny: outgoing traffic is left allowed" {
    # Denying incoming without restoring allow-outgoing would break every
    # outbound connection on the host.
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'default allow outgoing'
}

@test "default deny: a refused policy change is reported as failure" {
    _ufw_refuses default

    run _ufw_fix_default_deny
    [ "$status" -eq 1 ]
}

# ==============================================================================
# ufw.allow_ssh — FIX_SAFE, so it is auto-applied without confirmation
# ==============================================================================

@test "allow ssh: every port is opened, not only the first" {
    _sshd_ports 22 2222 2022

    run _ufw_fix_allow_ssh
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow 22/tcp'
    _vpssec_stub_called ufw 'allow 2222/tcp'
    _vpssec_stub_called ufw 'allow 2022/tcp'
}

@test "allow ssh: one refused port fails the fix even if another succeeded" {
    _sshd_ports 22 2222
    _ufw_working 2222

    run _ufw_fix_allow_ssh
    [ "$status" -eq 1 ]
}

# ==============================================================================
# Install and dispatch
# ==============================================================================

@test "install: a failed package install is propagated" {
    _vpssec_stub apt-get 100

    run _ufw_fix_install
    [ "$status" -eq 1 ]
}

@test "ufw_fix: an unknown fix id fails instead of silently doing nothing" {
    run ufw_fix "ufw.not_a_real_fix"
    [ "$status" -eq 1 ]
}
