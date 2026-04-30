#!/usr/bin/env bats
#
# Regression tests for count_lines (core/common.sh).
#
# count_lines exists specifically to replace the `grep -c PAT |
# || echo 0` idiom that emitted "0\n0" on empty input and crashed
# arithmetic under set -e (see comment in common.sh:614). These tests
# pin the behaviour so future refactors can't reintroduce the bug.

load helpers

setup() {
    _vpssec_load
}

@test "empty input returns 0" {
    run count_lines ""
    [ "$status" -eq 0 ]
    [ "$output" = "0" ]
}

@test "single non-empty line returns 1" {
    run count_lines "hello"
    [ "$status" -eq 0 ]
    [ "$output" = "1" ]
}

@test "three lines return 3" {
    run count_lines $'a\nb\nc'
    [ "$output" = "3" ]
}

@test "trailing newline does not double-count" {
    run count_lines $'a\nb\n'
    [ "$output" = "2" ]
}

@test "pattern filter counts only matching lines" {
    run count_lines $'pid|cmd\nother\nmore|stuff' '|'
    [ "$output" = "2" ]
}

@test "pattern not present returns 0" {
    run count_lines "abc" "xyz"
    [ "$output" = "0" ]
}

@test "default pattern '.' counts non-empty lines" {
    # Empty intermediate line should not count
    run count_lines $'a\n\nc'
    [ "$output" = "2" ]
}

@test "output is a single integer (no '0\\n0' regression)" {
    run count_lines ""
    # The whole bug that motivated count_lines was that the legacy
    # `grep -c . || echo 0` produced a literal "0\n0" on empty input.
    # Assert: output is exactly "0" and contains no embedded newline.
    # Uses bash regex rather than `wc -l` because BSD wc -l emits
    # leading whitespace ("       0") that makes a string-equals
    # check brittle across platforms.
    [ "$output" = "0" ]
    [[ "$output" != *$'\n'* ]]
    [[ "$output" =~ ^[0-9]+$ ]]
}
