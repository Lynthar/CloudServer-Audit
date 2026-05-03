#!/usr/bin/env bats
#
# Regression tests for _is_suspicious_username (M8). Original pattern
# list contained `.*\..*` which flagged every dotted username (e.g. the
# firstname.lastname convention universal in LDAP/AD environments) as
# suspicious. The dot pattern was dropped because real malicious accounts
# almost never use dotted names anyway.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/users.sh"
}

@test "suspicious: 'firstname.lastname' is NOT suspicious (regression)" {
    run _is_suspicious_username "alice.smith"
    [ "$status" -ne 0 ]
}

@test "suspicious: 'jane.doe' is NOT suspicious" {
    run _is_suspicious_username "jane.doe"
    [ "$status" -ne 0 ]
}

@test "suspicious: 'a.b.c' is NOT suspicious (multi-dot)" {
    run _is_suspicious_username "a.b.c"
    [ "$status" -ne 0 ]
}

@test "suspicious: 'admin' still flagged" {
    run _is_suspicious_username "admin"
    [ "$status" -eq 0 ]
}

@test "suspicious: 'admin42' still flagged" {
    run _is_suspicious_username "admin42"
    [ "$status" -eq 0 ]
}

@test "suspicious: 'test' still flagged" {
    run _is_suspicious_username "test"
    [ "$status" -eq 0 ]
}

@test "suspicious: 'mysql5' still flagged" {
    run _is_suspicious_username "mysql5"
    [ "$status" -eq 0 ]
}

@test "suspicious: name with whitespace still flagged" {
    run _is_suspicious_username "user name"
    [ "$status" -eq 0 ]
}

@test "suspicious: normal name 'alice' is NOT suspicious" {
    run _is_suspicious_username "alice"
    [ "$status" -ne 0 ]
}
