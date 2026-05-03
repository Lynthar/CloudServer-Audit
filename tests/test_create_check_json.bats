#!/usr/bin/env bats
#
# Regression: jq 1.7.0 (Debian trixie / Ubuntu 24.04+) added a `module`
# keyword for the new module system. This bit create_check_json TWICE:
#
#   (1) The unquoted shorthand object form `{module: $module, ...}` is
#       rejected because `module` can't appear as an unquoted identifier
#       in object-key position.
#   (2) Less obvious: even after quoting the key, `--arg module ...`
#       creates a jq variable named `$module`, and the lexer rejects
#       that on the SAME ground — `module` can't be a variable name.
#
# Both forms produce the same error (note "line 1" points at the FILTER
# string, not the argument list, which made (2) easy to misdiagnose):
#
#     unexpected module, expecting IDENT or __loc__
#
# Every state_add_check call therefore failed silently, leaving
# state/checks.json empty and the audit appearing to "hang" at the
# end (the report writer had no data to render). The macOS / Apple
# build of jq 1.7.1 is more permissive and accepts both forms — that's
# why the bug never surfaced in development.
#
# This test asserts that:
#   1. create_check_json produces well-formed JSON jq itself can re-parse
#   2. All eight expected fields are present with the correct values
#   3. Values containing shell metacharacters survive intact
#   4. The filter source neither uses shorthand keys nor a `$module`
#      jq variable — so a future refactor that re-introduces either
#      form fails at CI rather than in production
#   5. `--arg <reserved-word>` is explicitly rejected by jq 1.7+ — the
#      smoke test that proves the fix shape is necessary

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
    # `--arg module` injects a jq variable named $module, which jq 1.7+
    # rejects because `module` is a reserved word. The fix must be
    # `--arg mod` (or any other non-reserved name).
    #
    # Match only actual jq command lines (which are followed by a
    # quoted "$..." value) — explanatory comments mentioning the old
    # form are exempt.
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
