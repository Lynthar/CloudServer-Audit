#!/usr/bin/env bats
# `vpssec status` reports the last audit, not only the last fix: audits never
# wrote anything it read, so after any number of them it said "never".

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    state_init
    VPSSEC_QUIET_SCAN=0
    _vpssec_latest_release_tag() { :; }   # status's one network call
    module_get_enabled() { :; }
    vpssec_cloud_provider() { :; }
    vpssec_cloud_tier() { :; }
}

@test "status: after an audit pass it shows when the audit ran and its score" {
    _run_audit_pass >/dev/null
    run status_mode
    [ "$status" -eq 0 ]
    grep -qE 'Last audit: [0-9]{4}-[0-9]{2}-[0-9]{2}T.*, score 100/100' <<<"$output"
    _vpssec_refute grep -q 'Last audit: never' <<<"$output"
}

@test "status: an audit with a module that did not finish says so" {
    VPSSEC_MODULES_FAILED=(backup)
    _run_audit_pass >/dev/null
    run status_mode
    grep -q 'some modules did not finish' <<<"$output"
}

@test "status: before any audit it says never, in the operator's language" {
    i18n_load zh_CN
    run status_mode
    grep -q '上次审计: 从未' <<<"$output"
    grep -q '上次应用修复: 从未' <<<"$output"
}

@test "status: the last fix applied is its own line" {
    _run_audit_pass >/dev/null
    state_mark_fix_complete ssh.enable_pubkey
    run status_mode
    grep -qE 'Last fix applied: [0-9]{4}-' <<<"$output"
    grep -q 'Completed fixes: 1' <<<"$output"
}
