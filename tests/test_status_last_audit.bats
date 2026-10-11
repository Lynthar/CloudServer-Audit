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
    # The failure has to happen inside the pass: each pass starts its own record.
    module_get_enabled() { echo backup; }
    VPSSEC_MODULE_LOADED[backup]=1
    backup_audit() { return 1; }
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

# Root reads any directory, so the user who cannot read state/ has to be real:
# as root the test drops to nobody, otherwise it is this user with state/ at 000.
@test "status: a user who cannot read state/ is told why and how, not shown blanks" {
    if [ "$(id -u)" = 0 ]; then
        command -v setpriv >/dev/null || skip "setpriv is needed to drop root"
    fi
    local base root
    root="$(_vpssec_repo_root)"
    base=$(mktemp -d /tmp/vpssec-status-XXXXXX)
    chmod 755 "$base"
    mkdir -m 700 "$base/state" "$base/backups"
    mkdir -m 750 "$base/logs"
    printf '{"last_audit":{"timestamp":"2026-01-01T00:00:00Z","score":90,"complete":true}}\n' \
        > "$base/state/ok.json"
    cat > "$base/status.sh" <<SH
export VPSSEC_LANG=en_US VPSSEC_COLOR=0 VPSSEC_JSON_ONLY=0 VPSSEC_QUIET_SCAN=0
source "$root/core/common.sh"
VPSSEC_STATE="$base/state" VPSSEC_BACKUPS="$base/backups" VPSSEC_LOGS="$base/logs"
_log_file="$base/logs/vpssec.log"
for f in core/state.sh core/security_levels.sh core/engine.sh core/report.sh; do source "$root/\$f"; done
i18n_load en_US
_vpssec_latest_release_tag() { :; }
status_mode
SH
    if [ "$(id -u)" = 0 ]; then
        run setpriv --reuid=65534 --regid=65534 --clear-groups bash "$base/status.sh"
    else
        chmod 000 "$base/state"
        run bash "$base/status.sh"
        chmod 700 "$base/state"
    fi
    rm -rf "$base"

    [ "$status" -eq 0 ]
    [[ "$output" == *"State is not readable as this user (it is root-owned by design). Run: sudo vpssec status"* ]]
    [[ "$output" != *"Last audit"* ]]
}
