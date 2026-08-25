#!/usr/bin/env bats
# The UI to plan to executor ID contract: both selectors must emit deduplicated
# fix_ids, generate_plan must yield one entry per unique fix id, and an empty
# plan and a failed plan must both be visible in the exit status.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/engine.sh core/report.sh
    source "$(_vpssec_repo_root)/core/ui_tui.sh"
    source "$(_vpssec_repo_root)/core/ui_text.sh"
    i18n_load en_US

    # Two failed checks that SHARE one fix id, plus one with its own.
    CHECK_A=$(create_check_json "mod.check_a" "mod" "high" "failed" \
        "Title A" "" "" "mod.shared_fix")
    CHECK_B=$(create_check_json "mod.check_b" "mod" "medium" "failed" \
        "Title B" "" "" "mod.shared_fix")
    CHECK_C=$(create_check_json "mod.check_c" "mod" "low" "failed" \
        "Title C" "" "" "mod.other_fix")

    state_init
    state_add_check "$CHECK_A"
    state_add_check "$CHECK_B"
    state_add_check "$CHECK_C"
}

# Selector harness: capture what the checklist is HANDED (its tags are what
# the engine will pass to generate_plan). The stub prints every tag.
_checklist_tags_only() {
    # args: title message tag1 desc1 state1 tag2 desc2 state2 ...
    shift 2
    while [[ $# -gt 0 ]]; do
        printf '%s ' "$1"
        shift 3
    done
}

@test "guide_mode: refusing an unsupported distro exits 4, not 0" {
    # 0 here read as "hardening completed" to anything that checks $?.
    is_debian_based() { return 1; }
    run guide_mode
    [ "$status" -eq 4 ]
}

@test "tui_select_fixes emits fix ids, not check ids, deduplicated" {
    tui_checklist() { _checklist_tags_only "$@"; }

    local -a fixes=("$CHECK_A" "$CHECK_B" "$CHECK_C")
    run tui_select_fixes fixes
    [ "$status" -eq 0 ]
    [[ "$output" == *"mod.shared_fix"* ]]
    [[ "$output" == *"mod.other_fix"* ]]
    _vpssec_refute grep -q "mod.check_a" <<<"$output"
    # shared_fix appears exactly once despite two checks carrying it
    [ "$(grep -o "mod.shared_fix" <<<"$output" | wc -l | tr -d ' ')" -eq 1 ]
}

@test "text_select_fixes emits fix ids, not check ids, deduplicated" {
    text_checklist() { _checklist_tags_only "$@"; }

    local -a fixes=("$CHECK_A" "$CHECK_B" "$CHECK_C")
    run text_select_fixes fixes
    [ "$status" -eq 0 ]
    [[ "$output" == *"mod.shared_fix"* ]]
    _vpssec_refute grep -q "mod.check_b" <<<"$output"
    [ "$(grep -o "mod.shared_fix" <<<"$output" | wc -l | tr -d ' ')" -eq 1 ]
}

@test "generate_plan: one entry per unique fix id, even when selected twice" {
    # Selection repeats shared_fix (the UI can produce this when two rows
    # carried the same fix), and two checks in state match it.
    run generate_plan "mod.shared_fix mod.shared_fix mod.other_fix"
    [ "$status" -eq 0 ]
    local count
    count=$(jq '.fixes | length' <<<"$output")
    [ "$count" -eq 2 ]
    # And the ids are the fix ids we asked for.
    [ "$(jq -r '.fixes[0].fix_id' <<<"$output")" = "mod.shared_fix" ]
    [ "$(jq -r '.fixes[1].fix_id' <<<"$output")" = "mod.other_fix" ]
}

@test "generate_plan: unknown ids resolve to an empty plan (not junk)" {
    run generate_plan "mod.check_a mod.check_c"   # CHECK ids — must not resolve
    [ "$status" -eq 0 ]
    [ "$(jq '.fixes | length' <<<"$output")" -eq 0 ]
}

@test "execute_plan returns non-zero when a fix fails" {
    export VPSSEC_YES=1   # skip the interactive skip/retry/rollback menu
    fake_fix() { return 1; }
    generate_plan "" >/dev/null   # reset plan file
    state_save_plan "$(jq -n '{timestamp: "t", fixes: [
        {id: "fake.check", module: "fake", severity: "low", status: "failed",
         title: "t", desc: "", suggestion: "", fix_id: "fake.broken"}]}')"
    run execute_plan
    [ "$status" -eq 1 ]
}

@test "execute_plan returns zero when every fix succeeds" {
    export VPSSEC_YES=1
    fake_fix() { return 0; }
    state_save_plan "$(jq -n '{timestamp: "t", fixes: [
        {id: "fake.check", module: "fake", severity: "low", status: "failed",
         title: "t", desc: "", suggestion: "", fix_id: "fake.works"}]}')"
    run execute_plan
    [ "$status" -eq 0 ]
}

# ---- module-failure visibility ---------------------------------------------

@test "audit_module records a failed module as an _internal check" {
    VPSSEC_MODULE_LOADED[crashmod]=1
    crashmod_audit() { return 7; }

    audit_module crashmod

    run jq -r '.[] | select(.id == "_internal.module_failed") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]

    # And the flat list drives meta/exit-code downstream.
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" crashmod "* ]]
}

@test "module failure surfaces as meta.complete=false in summary.json" {
    VPSSEC_MODULE_LOADED[crashmod]=1
    crashmod_audit() { return 7; }
    audit_module crashmod

    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.meta.complete' "$VPSSEC_REPORTS/summary.json")" = "false" ]
    run jq -r '.meta.modules_failed[]' "$VPSSEC_REPORTS/summary.json"
    [[ "$output" == *crashmod* ]]
}

@test "clean run reports meta.complete=true and empty modules_failed" {
    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.meta.complete' "$VPSSEC_REPORTS/summary.json")" = "true" ]
    [ "$(jq '.meta.modules_failed | length' "$VPSSEC_REPORTS/summary.json")" -eq 0 ]
}

@test "SARIF executionSuccessful mirrors module completeness" {
    VPSSEC_MODULE_LOADED[crashmod]=1
    crashmod_audit() { return 7; }
    audit_module crashmod

    run report_generate_sarif "$VPSSEC_REPORTS/summary.sarif"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.runs[0].invocations[0].executionSuccessful' "$VPSSEC_REPORTS/summary.sarif")" = "false" ]
    run jq -r '.runs[0].invocations[0].toolExecutionNotifications[0].message.text' \
        "$VPSSEC_REPORTS/summary.sarif"
    [[ "$output" == *crashmod* ]]
}
