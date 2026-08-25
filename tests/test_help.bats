#!/usr/bin/env bats
# Tests for the help dispatcher (core/help.sh). Help is read-only and runs in
# pre-init context — no root, no lock, no module loading — so vpssec_help_dispatch
# can be called directly after sourcing common + security_levels + engine + help.

load helpers

setup() {
    _vpssec_load core/security_levels.sh core/engine.sh core/help.sh
    # help renders user-facing strings via i18n; load the en_US
    # catalogue so assertions on translated text are stable. Other
    # test files don't need this because they target pure functions.
    i18n_load en_US
}

# ---- _help_collect_fixes: per-module bucketing -----------------------

@test "_help_collect_fixes: ssh populates all four buckets" {
    # ssh is the one module shipping fixes in every safety class, so it proves the
    # bucketing. The exact counts are deliberately NOT asserted: they are a
    # snapshot, and deriving them from the maps would re-implement the function.
    _help_collect_fixes "ssh"
    [ "$(count_lines "${_help_fix_table[safe]}")"        -gt 0 ]
    [ "$(count_lines "${_help_fix_table[confirm]}")"     -gt 0 ]
    [ "$(count_lines "${_help_fix_table[risky]}")"       -gt 0 ]
    [ "$(count_lines "${_help_fix_table[alert_only]}")"  -gt 0 ]
}

@test "_help_collect_fixes: every collected id belongs to the module asked for" {
    # What the hardcoded counts were really guarding, stated directly: a
    # bucket must not pick up another module's fix. Independent of how many
    # fixes ssh happens to ship this week.
    _help_collect_fixes "ssh"
    local all ids
    all="${_help_fix_table[safe]}${_help_fix_table[confirm]}"
    all+="${_help_fix_table[risky]}${_help_fix_table[alert_only]}"
    ids=$(grep -c . <<<"$all")
    [ "$ids" -gt 0 ]
    # No line that is not an ssh.* id.
    _vpssec_refute grep -qv '^ssh\.' <<<"$(grep . <<<"$all")"
}

@test "_help_collect_fixes: the module filter is anchored at the dot" {
    # `cloud` and `cloudflared` are a real prefix pair here, so an unanchored
    # `[[ $id == $module* ]]` would print cloudflared's fixes on `help cloud`.
    # No other test notices, because ssh has no prefix sibling to leak from.
    _help_collect_fixes "cloud"
    local all
    all="${_help_fix_table[safe]}${_help_fix_table[confirm]}"
    all+="${_help_fix_table[risky]}${_help_fix_table[alert_only]}"

    _vpssec_refute grep -q 'cloudflared\.' <<<"$all"
    # ...and it must still collect cloud's own, or "no cloudflared" would
    # also pass with the function returning nothing at all.
    grep -q '^cloud\.' <<<"$all"
}

@test "_help_collect_fixes: a bucket only holds ids of its own safety class" {
    # The old counts caught a swapped-bucket bug by accident (5 and 1 would
    # trade places). Assert it on purpose instead.
    _help_collect_fixes "ssh"
    local id
    while read -r id; do
        [[ -n "$id" ]] || continue
        [[ -n "${FIX_SAFE[$id]+set}" ]]
        [[ -z "${FIX_RISKY[$id]+set}" ]]
    done < <(grep . <<<"${_help_fix_table[safe]}")

    while read -r id; do
        [[ -n "$id" ]] || continue
        [[ -n "${FIX_RISKY[$id]+set}" ]]
        [[ -z "${FIX_SAFE[$id]+set}" ]]
    done < <(grep . <<<"${_help_fix_table[risky]}")
}

@test "_help_collect_fixes: preflight is audit-only (zero fixes)" {
    _help_collect_fixes "preflight"
    [ "$(count_lines "${_help_fix_table[safe]}")"        = "0" ]
    [ "$(count_lines "${_help_fix_table[confirm]}")"     = "0" ]
    [ "$(count_lines "${_help_fix_table[risky]}")"       = "0" ]
    [ "$(count_lines "${_help_fix_table[alert_only]}")"  = "0" ]
}

@test "_help_collect_fixes: malware module is all alert_only" {
    # Every malware finding is alert-only. Re-asserting from the help angle
    # catches an accidental move of a malware fix into FIX_SAFE/CONFIRM/RISKY.
    _help_collect_fixes "malware"
    [ "$(count_lines "${_help_fix_table[safe]}")"     = "0" ]
    [ "$(count_lines "${_help_fix_table[confirm]}")"  = "0" ]
    [ "$(count_lines "${_help_fix_table[risky]}")"    = "0" ]
    [ "$(count_lines "${_help_fix_table[alert_only]}")" -gt "0" ]
}

@test "_help_collect_fixes: returns 0 even when last bucket is empty" {
    # A for-loop whose final iteration is `[[ X ]] && y` returns 1 when X is
    # false, and set -e then kills the caller mid-render. Pin success-return.
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
