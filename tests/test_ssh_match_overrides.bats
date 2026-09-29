#!/usr/bin/env bats
# The SSH verdicts judge the value an ordinary user gets; a Match block can set
# a different one for some connections. Each judged directive a Match block sets
# is reported in one unscored finding, so the verdicts say where they stop.

load helpers.bash

setup() {
    _vpssec_load core/security_levels.sh core/state.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    etc=$(_vpssec_fake_etc)
    SSH_CONFIG="$etc/ssh/sshd_config"
    mkdir -p "$etc/ssh/sshd_config.d"
}

# The ssh.match_overrides desc, or empty when the finding was not emitted.
_finding() {
    _ssh_audit_match_overrides >/dev/null
    jq -r '.[] | select(.id == "ssh.match_overrides") | .desc' "$VPSSEC_STATE/checks.json"
}

@test "a Match Address block that re-enables root login is reported" {
    printf 'PermitRootLogin no\n\nMatch Address 0.0.0.0/0\n    PermitRootLogin yes\n' > "$SSH_CONFIG"

    run _finding
    [[ "$output" == *"PermitRootLogin (Match Address 0.0.0.0/0)"* ]]
    run jq -r '.[] | select(.id == "ssh.match_overrides") | "\(.status)/\(.severity)"' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed/low" ]
}

@test "a config without Match blocks emits nothing" {
    printf 'PermitRootLogin no\nPasswordAuthentication no\n' > "$SSH_CONFIG"

    run _finding
    [ -z "$output" ]
}

@test "a Match block setting only directives the audit does not judge emits nothing" {
    printf 'Match Group sftp\n    ForceCommand internal-sftp\n    ChrootDirectory /srv/%%u\n' \
        > "$SSH_CONFIG"

    run _finding
    [ -z "$output" ]
}

@test "lines after Match all apply to everyone and are not overrides" {
    printf 'Match User bob\n    X11Forwarding yes\nMatch all\n    PasswordAuthentication no\n' \
        > "$SSH_CONFIG"

    run _finding
    [[ "$output" == *"X11Forwarding (Match User bob)"* ]]
    [[ "$output" != *"PasswordAuthentication"* ]]
}

@test "a Match block in a drop-in named by a relative Include is found" {
    printf 'Include sshd_config.d/*.conf\nPermitRootLogin no\n' > "$SSH_CONFIG"
    printf 'Match User deploy\n    PasswordAuthentication yes\n' \
        > "$etc/ssh/sshd_config.d/50-deploy.conf"

    run _finding
    [[ "$output" == *"PasswordAuthentication (Match User deploy)"* ]]
}

@test "keywords match case-insensitively, in Key=value form, with comments stripped" {
    printf 'match address 10.0.0.0/8  # office\n    permitrootlogin=yes\n    # MaxAuthTries 99\n' \
        > "$SSH_CONFIG"

    run _finding
    [[ "$output" == *"PermitRootLogin (Match address 10.0.0.0/8)"* ]]
    [[ "$output" != *"MaxAuthTries"* ]]
}

@test "the same override seen twice is listed once" {
    printf 'Include %s/ssh/a.conf %s/ssh/a.conf\n' "$etc" "$etc" > "$SSH_CONFIG"
    printf 'Match User bob\n    AllowTcpForwarding yes\n' > "$etc/ssh/a.conf"

    run _ssh_match_overrides
    [ "$(grep -c 'AllowTcpForwarding' <<< "$output")" -eq 1 ]
}

@test "the finding never moves the score" {
    run check_counts_in_score ssh.match_overrides
    [ "$status" -ne 0 ]
}

@test "ssh_audit runs the Match override check" {
    local fn
    for fn in _ssh_audit_password_auth _ssh_audit_root_login _ssh_audit_pubkey \
              _ssh_audit_admin_user _ssh_audit_empty_password _ssh_audit_max_auth_tries \
              _ssh_audit_login_grace_time _ssh_audit_directives _ssh_audit_algorithms \
              _ssh_audit_access_control _ssh_audit_port; do
        eval "$fn() { :; }"
    done
    printf 'Match Address 0.0.0.0/0\n    PermitRootLogin yes\n' > "$SSH_CONFIG"

    ssh_audit >/dev/null
    jq -e '.[] | select(.id == "ssh.match_overrides")' "$VPSSEC_STATE/checks.json" >/dev/null
}
