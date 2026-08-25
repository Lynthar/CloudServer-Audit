#!/usr/bin/env bats
# execute_fix must not record a success its declared postcondition contradicts.
# FIX_VERIFY maps a fix_id to the audit predicate that sees whether the change is
# in effect; undeclared fixes keep the old behaviour, so the map grows gradually.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    state_init
}

# A fix function the engine will dispatch to, whose outcome the test picks.
# Named for a real module so `${fix_id%%.*}` resolves, and defined here rather
# than sourced so no module's own behaviour leaks into the assertion.
_install_fake_fix() {
    local module="$1" rc="${2:-0}"
    eval "${module}_fix() { return $rc; }"
}

_completed_fixes() {
    jq -r '.completed_fixes[]?.fix_id // .completed_fixes[]? // empty' \
        "$VPSSEC_STATE/ok.json" 2>/dev/null
}

@test "a declared verify that passes lets the fix succeed and be recorded" {
    _install_fake_fix ufw 0
    _fake_verify_pass() { return 0; }
    FIX_VERIFY["ufw.enable"]="_fake_verify_pass"

    run execute_fix ufw.enable true
    [ "$status" -eq 0 ]
    grep -q 'ufw.enable' <<<"$(_completed_fixes)"
}

@test "a declared verify that fails turns the fix into a failure" {
    _install_fake_fix ufw 0
    _fake_verify_fail() { return 1; }
    FIX_VERIFY["ufw.enable"]="_fake_verify_fail"

    run execute_fix ufw.enable true
    [ "$status" -eq 1 ]
}

@test "a failed verify leaves no completion record" {
    _install_fake_fix ufw 0
    _fake_verify_fail() { return 1; }
    FIX_VERIFY["ufw.enable"]="_fake_verify_fail"

    run execute_fix ufw.enable true
    _vpssec_refute grep -q 'ufw.enable' <<<"$(_completed_fixes)"
}

@test "a declared predicate that does not exist fails loudly, not by accident" {
    _install_fake_fix ufw 0
    FIX_VERIFY["ufw.enable"]="_no_such_function_anywhere"

    run execute_fix ufw.enable true
    [ "$status" -eq 1 ]
    # The guarded branch, not bash's "command not found" falling through: the
    # distinction is what keeps the failure attributable in the log.
    [[ "$output" != *"command not found"* ]]
}

@test "an undeclared fix is untouched by the mechanism" {
    _install_fake_fix ufw 0
    _fake_verify_fail() { return 1; }
    FIX_VERIFY["ufw.some_other_fix"]="_fake_verify_fail"

    run execute_fix ufw.enable true
    [ "$status" -eq 0 ]
    grep -q 'ufw.enable' <<<"$(_completed_fixes)"
}

@test "verify does not rescue a fix whose own work failed" {
    _install_fake_fix ufw 1
    _fake_verify_pass() { return 0; }
    FIX_VERIFY["ufw.enable"]="_fake_verify_pass"

    run execute_fix ufw.enable true
    [ "$status" -eq 1 ]
}
