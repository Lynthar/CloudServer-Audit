#!/usr/bin/env bats
#
# Regression: jq 1.7.0 (Debian trixie / Ubuntu 24.04+) added a `module`
# keyword for the new module system. The original create_check_json
# filter used unquoted shorthand keys
#
#     {id: $id, module: $module, severity: $severity, ...}
#
# which under jq 1.7.0 fails to parse with
#
#     unexpected module, expecting IDENT or __loc__
#
# Every state_add_check call therefore failed silently, leaving
# state/checks.json empty and the audit appearing to "hang" at the
# end (the report writer had no data to render).
#
# This test asserts that:
#   1. create_check_json produces well-formed JSON jq itself can re-parse
#   2. All eight expected fields are present with the correct values
#   3. Values containing shell metacharacters survive intact
#   4. The literal string "module" appears as a quoted key in the filter
#      source — guards against a future refactor reverting to shorthand

load helpers.bash

setup() {
    _vpssec_load
}

@test "create_check_json: emits valid JSON parseable by jq" {
    local out
    out=$(create_check_json "x.id" "modname" "high" "failed" \
        "Title" "Desc" "Suggest" "x.fix")
    run bash -c "printf '%s' '$out' | jq empty"
    [ "$status" -eq 0 ]
}

@test "create_check_json: all eight fields are populated correctly" {
    local out
    out=$(create_check_json "x.id" "modname" "medium" "passed" \
        "T" "D" "S" "x.fix")
    [ "$(printf '%s' "$out" | jq -r '.id')"         = "x.id" ]
    [ "$(printf '%s' "$out" | jq -r '.module')"     = "modname" ]
    [ "$(printf '%s' "$out" | jq -r '.severity')"   = "medium" ]
    [ "$(printf '%s' "$out" | jq -r '.status')"     = "passed" ]
    [ "$(printf '%s' "$out" | jq -r '.title')"      = "T" ]
    [ "$(printf '%s' "$out" | jq -r '.desc')"       = "D" ]
    [ "$(printf '%s' "$out" | jq -r '.suggestion')" = "S" ]
    [ "$(printf '%s' "$out" | jq -r '.fix_id')"     = "x.fix" ]
}

@test "create_check_json: shell metacharacters in values survive" {
    local out
    out=$(create_check_json "x.id" "mod" "low" "failed" \
        'Title with "quotes" and $vars' \
        "Desc with newline${IFS}line2" \
        "Suggest with 'single' \"double\"" \
        "x.fix")
    run bash -c "printf '%s' '$out' | jq empty"
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$out" | jq -r '.title')" = 'Title with "quotes" and $vars' ]
}

@test "create_check_json: 'module' is quoted as a string key in the source" {
    # If a future refactor reverts to the shorthand `{module: $module}`
    # form, jq 1.7.0 will reject it again at runtime. This guards the
    # filter source itself.
    local root
    root=$(_vpssec_repo_root)
    run grep -E '"module":\s*\$module' "$root/core/common.sh"
    [ "$status" -eq 0 ]
}

@test "create_check_json: empty optional fields produce empty strings, not null" {
    local out
    out=$(create_check_json "x.id" "mod" "low" "passed" "T")
    [ "$(printf '%s' "$out" | jq -r '.desc')"       = "" ]
    [ "$(printf '%s' "$out" | jq -r '.suggestion')" = "" ]
    [ "$(printf '%s' "$out" | jq -r '.fix_id')"     = "" ]
}
