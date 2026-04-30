#!/usr/bin/env bats
#
# Tests for the help dispatcher (core/help.sh).
#
# Help is read-only and runs in pre-init context (no root, no lock,
# no module loading), so we can call vpssec_help_dispatch directly
# after sourcing common + security_levels + engine + help.

load helpers

setup() {
    _vpssec_load core/security_levels.sh core/engine.sh core/help.sh
    # help renders user-facing strings via i18n; load the en_US
    # catalogue so assertions on translated text are stable. Other
    # test files don't need this because they target pure functions.
    i18n_load en_US
}

# ---- _help_collect_fixes: per-module bucketing -----------------------

@test "_help_collect_fixes: ssh module collects expected counts" {
    _help_collect_fixes "ssh"
    # SSH module ships a known mix per security_levels.sh:
    #   5 safe, 1 confirm, 2 risky, 3 alert_only (+ a handful of
    #   passed-state checks that aren't fix_ids — those don't count)
    [ "$(count_lines "${_help_fix_table[safe]}")"        = "5" ]
    [ "$(count_lines "${_help_fix_table[confirm]}")"     = "1" ]
    [ "$(count_lines "${_help_fix_table[risky]}")"       = "2" ]
    [ "$(count_lines "${_help_fix_table[alert_only]}")"  = "3" ]
}

@test "_help_collect_fixes: preflight is audit-only (zero fixes)" {
    _help_collect_fixes "preflight"
    [ "$(count_lines "${_help_fix_table[safe]}")"        = "0" ]
    [ "$(count_lines "${_help_fix_table[confirm]}")"     = "0" ]
    [ "$(count_lines "${_help_fix_table[risky]}")"       = "0" ]
    [ "$(count_lines "${_help_fix_table[alert_only]}")"  = "0" ]
}

@test "_help_collect_fixes: malware module is all alert_only" {
    # CLAUDE.md pins the contract: every malware finding is alert-only.
    # Re-asserting from the help angle catches accidental moves of a
    # malware fix into FIX_SAFE/CONFIRM/RISKY.
    _help_collect_fixes "malware"
    [ "$(count_lines "${_help_fix_table[safe]}")"     = "0" ]
    [ "$(count_lines "${_help_fix_table[confirm]}")"  = "0" ]
    [ "$(count_lines "${_help_fix_table[risky]}")"    = "0" ]
    [ "$(count_lines "${_help_fix_table[alert_only]}")" -gt "0" ]
}

@test "_help_collect_fixes: returns 0 even when last bucket is empty" {
    # Regression: the original implementation ended with a for-loop
    # whose final iteration was `[[ X ]] && y` — when X was false,
    # the function returned 1 and set -e killed the caller mid-render.
    # Pin success-return for any module input.
    _help_collect_fixes "ssh"
    [ "$?" -eq 0 ]
    _help_collect_fixes "nonexistent_module_xyz"
    [ "$?" -eq 0 ]
}

# ---- vpssec_help_dispatch: end-to-end ------------------------------

@test "vpssec_help_dispatch: empty topic prints overview, exits 0" {
    run vpssec_help_dispatch ""
    [ "$status" -eq 0 ]
    # Overview must mention at least one of the categories.
    [[ "$output" == *"$(i18n 'category.access')"* ]]
}

@test "vpssec_help_dispatch: known module prints detail, exits 0" {
    run vpssec_help_dispatch "ssh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"ssh.disable_password_auth"* ]]
    [[ "$output" == *"$(i18n 'help.class_risky')"* ]]
}

@test "vpssec_help_dispatch: unknown module exits non-zero with hint" {
    # Pinning exit code 1 matters for scripts/CI that pipe `vpssec help
    # <maybe-typo>` and want to detect it.
    run vpssec_help_dispatch "totally-not-a-module"
    [ "$status" -ne 0 ]
    [[ "$output" == *"totally-not-a-module"* ]]
    [[ "$output" == *"$(i18n 'help.available_modules')"* ]]
}

@test "vpssec_help_dispatch: every registered module dispatches OK" {
    # Catch the case where a new module is added to VPSSEC_MODULE_ORDER
    # but lacks the minimum i18n keys help expects (title/desc).
    local module
    for module in "${VPSSEC_MODULE_ORDER[@]}"; do
        run vpssec_help_dispatch "$module"
        [ "$status" -eq 0 ] || {
            echo "module $module returned $status; output:"
            echo "$output"
            return 1
        }
    done
}
