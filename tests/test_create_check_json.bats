#!/usr/bin/env bats
# create_check_json must not name a jq object key `module` unquoted, nor pass
# `--arg module`: jq 1.7+ made `module` a keyword and rejects both, and every
# state_add_check then fails silently. Apple's jq accepts them, so test on Linux.

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

@test "create_check_json: 'module' key is quoted in the filter source" {
    # If a future refactor reverts to the shorthand `{module: ...}`
    # form, jq 1.7.0 will reject it again at runtime. This guards the
    # filter source itself.
    local root
    root=$(_vpssec_repo_root)
    run grep -E '"module":\s*\$mod' "$root/core/common.sh"
    [ "$status" -eq 0 ]
}

@test "create_check_json: source uses --arg mod, NOT --arg module" {
    # `--arg module` injects a jq variable named $module, which jq 1.7+ rejects
    # as a reserved word; the fix is `--arg mod`. The pattern matches only real
    # jq command lines, so comments naming the old form are exempt.
    local root
    root=$(_vpssec_repo_root)
    run grep -nE -- '--arg +module +"' "$root/core/common.sh"
    [ "$status" -ne 0 ]
    run grep -E -- '--arg +mod +"' "$root/core/common.sh"
    [ "$status" -eq 0 ]
}

@test "create_check_json: SARIF report writer also avoids --arg module" {
    # core/report.sh's SARIF generator hit the same trap independently.
    local root
    root=$(_vpssec_repo_root)
    run grep -nE -- '--arg +module +"' "$root/core/report.sh"
    [ "$status" -ne 0 ]
}

@test "create_check_json: empty optional fields produce empty strings, not null" {
    local out
    out=$(create_check_json "x.id" "mod" "low" "passed" "T")
    [ "$(printf '%s' "$out" | jq -r '.desc')"       = "" ]
    [ "$(printf '%s' "$out" | jq -r '.suggestion')" = "" ]
    [ "$(printf '%s' "$out" | jq -r '.fix_id')"     = "" ]
}
