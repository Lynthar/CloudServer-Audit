#!/usr/bin/env bats
#
# Regression tests for _logging_journald_max_size_from_text (M2).
# The original _logging_journald_max_size only read the main
# /etc/systemd/journald.conf, so vpssec writing its own
# 99-vpssec.conf drop-in via _logging_fix_enable_persistent_journal
# became invisible to the next audit — display kept saying "auto".

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/logging.sh"
}

@test "journald: empty merged config → empty result" {
    run _logging_journald_max_size_from_text ""
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}

@test "journald: SystemMaxUse on its own line is read" {
    run _logging_journald_max_size_from_text "[Journal]
SystemMaxUse=500M
Compress=yes"
    [ "$status" -eq 0 ]
    [ "$output" = "500M" ]
}

@test "journald: trailing whitespace on value is stripped" {
    # systemd-analyze cat-config sometimes leaves alignment whitespace.
    run _logging_journald_max_size_from_text 'SystemMaxUse= 1G   '
    [ "$status" -eq 0 ]
    [ "$output" = "1G" ]
}

@test "journald: last definition wins (drop-in semantics)" {
    # Mirrors the merged config semantic: alphabetical drop-in order,
    # last value applied.
    run _logging_journald_max_size_from_text "SystemMaxUse=100M
SystemMaxUse=500M"
    [ "$status" -eq 0 ]
    [ "$output" = "500M" ]
}

@test "journald: SystemMaxUse absent → empty (caller defaults to auto)" {
    run _logging_journald_max_size_from_text "[Journal]
Compress=yes
ForwardToSyslog=no"
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}

@test "journald: similar prefix (SystemMaxUseAlt) does not match" {
    run _logging_journald_max_size_from_text "SystemMaxUseAlt=999M"
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}

@test "journald: commented-out SystemMaxUse is ignored" {
    run _logging_journald_max_size_from_text "#SystemMaxUse=200M
SystemMaxUse=500M"
    [ "$status" -eq 0 ]
    [ "$output" = "500M" ]
}

@test "journald: only commented value → empty" {
    run _logging_journald_max_size_from_text "#SystemMaxUse=200M"
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}
