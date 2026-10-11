#!/usr/bin/env bats
# Regression tests for _logging_journald_max_size_from_text. Reading only
# /etc/systemd/journald.conf makes vpssec's own 99-vpssec.conf drop-in invisible
# to the next audit, which keeps displaying "auto".

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    state_init
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

# ---- what a volatile journal is said to lose ----------------------------

# The volatile-journal finding's desc, on a host whose journal is not kept.
_volatile_desc() {
    local etc
    etc=$(_vpssec_fake_etc)
    JOURNAL_DIR="$etc/log/journal"
    JOURNALD_CONF="$etc/systemd/journald.conf"
    JOURNALD_CONF_D="$etc/systemd/journald.conf.d"
    _logging_audit_journald
    jq -r '.[] | select(.id == "logging.journald_volatile") | .desc' "$VPSSEC_STATE/checks.json"
}

@test "journald: beside a running rsyslog, a volatile journal does not lose the logs" {
    # Stock RHEL: no /var/log/journal, and rsyslog writes /var/log/messages.
    _vpssec_stub_script systemctl <<'SH'
[[ "$*" == "is-active --quiet rsyslog" ]]
SH
    run _volatile_desc
    [ "$status" -eq 0 ]
    [[ "$output" == *rsyslog* ]]
    [ "$output" = "$(i18n 'logging.journald_volatile_syslog_desc' 'daemon=rsyslog')" ]
}

@test "journald: with no syslog daemon running, the logs are said to be lost" {
    _vpssec_stub systemctl 3
    run _volatile_desc
    [ "$status" -eq 0 ]
    [ "$output" = "$(i18n 'logging.journald_volatile_desc')" ]
}
