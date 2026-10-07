#!/usr/bin/env bats
# The reports' write-and-scope contract: a failed write fails the report
# function, --json-only never replays a stale summary.json, meta describes the
# scope that ran, and the SARIF stays valid (a fix needs artifactChanges).

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh core/report.sh
    i18n_load en_US
    VPSSEC_INCLUDE=""
    VPSSEC_EXCLUDE=""
    state_init

    state_add_check "$(create_check_json \
        "ufw.disabled" "ufw" "medium" "failed" \
        "Firewall disabled" "ufw is installed but inactive" \
        "Enable ufw" "ufw.enable")"
}

# Make write_file_atomic fail for one target basename while every other
# write stays real. Wraps rather than replaces, so the atomic-write logic
# still runs for the files the test is not breaking.
_fail_writes_to() {
    _VPSSEC_FAIL_WRITE="$1"
    eval "_real_$(declare -f write_file_atomic)"
    write_file_atomic() {
        [[ "$1" == *"$_VPSSEC_FAIL_WRITE" ]] && return 1
        _real_write_file_atomic "$@"
    }
}

# ==============================================================================
# Write failures propagate
# ==============================================================================

@test "json report: a failed write is a failed function, not a success" {
    _fail_writes_to summary.json
    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -ne 0 ]
}

@test "markdown report: a failed write is a failed function, not a success" {
    _fail_writes_to summary.md
    run report_generate_markdown "$VPSSEC_REPORTS/summary.md"
    [ "$status" -ne 0 ]
}

@test "sarif report: a failed write is a failed function, not a success" {
    _fail_writes_to summary.sarif
    run report_generate_sarif "$VPSSEC_REPORTS/summary.sarif"
    [ "$status" -ne 0 ]
}

@test "json-only: a failed JSON write refuses to replay the stale file" {
    printf '{"stale":true}' > "$VPSSEC_REPORTS/summary.json"
    _fail_writes_to summary.json
    VPSSEC_JSON_ONLY=1
    run report_generate_all
    [ "$status" -ne 0 ]
    _vpssec_refute grep -q '"stale"' <<<"$output"
    [[ "$output" == *"refusing to emit a stale"* ]]
}

@test "json-only: a failed markdown write fails the run even when the JSON is fresh" {
    # A CI job shipping summary.md must not see exit 0 next to a truncated file.
    _fail_writes_to summary.md
    VPSSEC_JSON_ONLY=1
    run report_generate_all
    [ "$status" -ne 0 ]
}

@test "interactive save: a failed write exits 1, names the file, and claims nothing saved" {
    printf '{"stale":true}' > "$VPSSEC_REPORTS/summary.json"
    _fail_writes_to summary.json
    VPSSEC_YES=1
    run report_generate_all
    [ "$status" -eq 1 ]
    [[ "$output" == *"$(i18n 'report.save_failed' "files=summary.json" "dir=$VPSSEC_REPORTS")"* ]]
    _vpssec_refute grep -qF "$(i18n 'report.report_saved' "path=")" <<<"$output"
    # Named as older, never deleted: the operator saved it once.
    grep -q '"stale"' "$VPSSEC_REPORTS/summary.json"
}

@test "interactive, not saved: an earlier report stays, named with its time, exit 0" {
    printf '{"stale":true}' > "$VPSSEC_REPORTS/summary.json"
    touch -d '2020-01-02 03:04:05' "$VPSSEC_REPORTS/summary.json"
    confirm() { return 1; }
    VPSSEC_QUIET_SCAN=0
    run report_generate_all
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(i18n 'report.not_saved_previous' "dir=$VPSSEC_REPORTS" "time=2020-01-02 03:04:05")"* ]]
    grep -q '"stale"' "$VPSSEC_REPORTS/summary.json"
}

@test "interactive, not saved, nothing earlier: it says so and writes nothing" {
    confirm() { return 1; }
    VPSSEC_QUIET_SCAN=0
    run report_generate_all
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(i18n 'report.not_saved')"* ]]
    [ -z "$(ls -A "$VPSSEC_REPORTS")" ]
}

@test "json and sarif carry a checks array past the 128 KiB argv limit" {
    local long
    long=$(head -c 140000 /dev/zero | tr '\0' a)
    state_add_check "$(create_check_json "malware.big" "malware" "high" "failed" "Big" "$long" "" "")"

    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.checks[] | select(.id == "malware.big") | .desc | length' "$VPSSEC_REPORTS/summary.json")" -eq 140000 ]
    run report_generate_sarif "$VPSSEC_REPORTS/summary.sarif"
    [ "$status" -eq 0 ]
    jq -e '[.runs[0].results[].ruleId] | index("malware.big")' "$VPSSEC_REPORTS/summary.sarif"
}

# ==============================================================================
# meta describes the real scope
# ==============================================================================

@test "meta.modules is all only for an unfiltered run" {
    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.meta.modules' "$VPSSEC_REPORTS/summary.json")" = "all" ]
    [ "$(jq -r '.meta.modules_excluded' "$VPSSEC_REPORTS/summary.json")" = "" ]
}

@test "meta.modules under --include lists what ran, context modules included" {
    source "$(_vpssec_repo_root)/core/engine.sh"
    module_load() { VPSSEC_MODULE_LOADED[$1]=1; return 0; }   # no real sourcing
    VPSSEC_INCLUDE="ssh"
    module_load_all "$VPSSEC_INCLUDE" ""

    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.meta.modules' "$VPSSEC_REPORTS/summary.json")" = "preflight,cloud,timezone,ssh" ]
}

@test "meta.modules under --exclude does not claim all, and the exclude is recorded" {
    source "$(_vpssec_repo_root)/core/engine.sh"
    module_load() { VPSSEC_MODULE_LOADED[$1]=1; return 0; }
    VPSSEC_EXCLUDE="ssh"
    module_load_all "" "$VPSSEC_EXCLUDE"

    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    local mods
    mods=$(jq -r '.meta.modules' "$VPSSEC_REPORTS/summary.json")
    [ "$mods" != "all" ]
    _vpssec_refute grep -qw ssh <<<"$mods"
    [ "$(jq -r '.meta.modules_excluded' "$VPSSEC_REPORTS/summary.json")" = "ssh" ]
}

# ==============================================================================
# SARIF stays schema-valid
# ==============================================================================

@test "sarif: results carry no fix objects, the suggestion rides the property bag" {
    # SARIF 2.1.0 §3.55 requires fix.artifactChanges (non-empty); a text
    # suggestion has no file edit to describe, so it must not be a fix.
    run report_generate_sarif "$VPSSEC_REPORTS/summary.sarif"
    [ "$status" -eq 0 ]
    jq -e '[.runs[0].results[] | has("fixes")] | any | not' "$VPSSEC_REPORTS/summary.sarif"
    jq -e '.runs[0].results[0].properties.suggestion == "Enable ufw"' "$VPSSEC_REPORTS/summary.sarif"
}

@test "sarif: the advertised schema URL is the live OASIS one" {
    # The old github raw URL (oasis-tcs/sarif-spec master branch) is a 404.
    run report_generate_sarif "$VPSSEC_REPORTS/summary.sarif"
    [ "$status" -eq 0 ]
    jq -e '."$schema" | test("docs\\.oasis-open\\.org/sarif")' "$VPSSEC_REPORTS/summary.sarif"
}
