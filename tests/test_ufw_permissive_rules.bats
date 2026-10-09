#!/usr/bin/env bats
# The permissive-rule audit reads the rule table of `ufw status`, a shape no
# other suite's ufw stub prints. The fixture is real ufw 0.36.2 output
# (Debian 12, LC_ALL=C), trailing spaces and the IPv6 twins included.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"
    i18n_load en_US
    unset LC_ALL
    export VPSSEC_TEST_UFW_STATUS="$(_vpssec_repo_root)/tests/fixtures/ufw-status-debian12.txt"
    # Only the C locale gets the English table: ufw translates ALLOW and
    # Anywhere, and a translated table matches nothing below.
    _vpssec_stub_script ufw <<'SH'
[[ "$1" == status && "${LC_ALL:-}" == C ]] && cat "$VPSSEC_TEST_UFW_STATUS"
exit 0
SH
}

_flagged() { _ufw_find_permissive_rules | sort -u; }

@test "permissive rules: a database port open to anywhere is named" {
    run _flagged
    [[ "$output" == *"3306 (MySQL) open to Anywhere"* ]]
}

@test "permissive rules: a non-standard port open to anywhere is listed for review" {
    run _flagged
    [[ "$output" == *"2222/tcp open to Anywhere (review if needed)"* ]]
}

@test "permissive rules: SSH, one admin address and an outbound rule are not flagged" {
    # The table also holds 22/tcp from anywhere, an allow from 203.0.113.9 and
    # ALLOW OUT for 8080 and 9100; none of them exposes a service to the world.
    run _flagged
    [ "$output" = "2222/tcp open to Anywhere (review if needed)
3306 (MySQL) open to Anywhere" ]
}
