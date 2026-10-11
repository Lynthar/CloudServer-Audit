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
    # sshd on 22 unless a test moves it: SSH's own rules are never "permissive".
    SSH_CONFIG="$BATS_TEST_TMPDIR/sshd_config"
    SSH_DROPIN_DIR="$BATS_TEST_TMPDIR/sshd_config.d"
    : > "$SSH_CONFIG"
    _vpssec_stub_sshd_merging
    # ufw's rule store, where app profiles are resolved to ports; none unless a
    # test gives one.
    UFW_USER_RULES="$BATS_TEST_TMPDIR/absent/user.rules"
    UFW_USER6_RULES="$BATS_TEST_TMPDIR/absent/user6.rules"
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

@test "permissive rules: the port sshd moved to is SSH, not a rule to review" {
    # ufw.enable adds `2222/tcp # SSH (vpssec)` itself; flagging it next audit
    # contradicted the fix that wrote it.
    printf 'Port 2222\n' > "$SSH_CONFIG"
    run _flagged
    [ "$output" = "3306 (MySQL) open to Anywhere" ]
}

@test "permissive rules: a rule and its (v6) twin are one entry" {
    run _ufw_find_permissive_rules
    [ "$(grep -c '2222/tcp' <<<"$output")" -eq 1 ]
}

# Real ufw 0.36.2 output with app profiles, interface rules (one on a VLAN name
# with a dot), an allow-all, destination-address rules and a range (LC_ALL=C),
# and the tuples the same ufw wrote to user.rules for it.
_apps_host() {
    printf 'Port 2222\n' > "$SSH_CONFIG"
    VPSSEC_TEST_UFW_STATUS="$(_vpssec_repo_root)/tests/fixtures/ufw-status-apps-debian12.txt"
    UFW_USER_RULES="$(_vpssec_repo_root)/tests/fixtures/ufw-user-rules-apps-debian12.txt"
}

@test "permissive rules: interface rules are left out; open ports and apps by their ports are listed" {
    _apps_host
    run _ufw_find_permissive_rules
    [ "$output" = "Samba (137,138/udp 139,445/tcp) open to Anywhere (review if needed)
Anywhere open to Anywhere (review if needed)
8443/tcp open to Anywhere (review if needed)
60000:61000/udp open to Anywhere (review if needed)
9443/tcp open to Anywhere (review if needed)" ]
}

@test "permissive rules: an app profile on SSH or web ports is not one to review" {
    # OpenSSH resolves to 22 and Nginx Full to 80,443.
    _apps_host
    run _ufw_find_permissive_rules
    [ "$status" -eq 0 ]
    _vpssec_refute grep -qE 'OpenSSH|Nginx' <<<"$output"
}

@test "permissive rules: an app profile ufw's rule store cannot resolve is listed by name" {
    # No tuples to read: what it opens is unknown, so it is shown, not assumed.
    _apps_host
    UFW_USER_RULES="$BATS_TEST_TMPDIR/absent/user.rules"
    run _ufw_find_permissive_rules
    [[ "$output" == *"OpenSSH open to Anywhere (review if needed)"* ]]
}
