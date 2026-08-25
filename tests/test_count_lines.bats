#!/usr/bin/env bats
# Regression tests for count_lines (core/common.sh). It replaces the
# `grep -c PAT || echo 0` idiom, which emitted "0\n0" on empty input and crashed
# arithmetic under set -e; these pin the behaviour against a refactor.

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
    # The legacy `grep -c . || echo 0` produced a literal "0\n0" on empty input,
    # so assert the output is exactly "0" with no embedded newline. Bash regex,
    # not `wc -l`: BSD wc pads with leading whitespace.
    [ "$output" = "0" ]
    [[ "$output" != *$'\n'* ]]
    [[ "$output" =~ ^[0-9]+$ ]]
}
