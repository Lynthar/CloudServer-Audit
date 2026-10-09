#!/usr/bin/env bats
# What guide offers and how each fix in a plan ends: only failed findings carry
# a fix; a fix the operator answers "no" to is skipped, not failed; and the
# failure menu's rollback is the same rollback `vpssec rollback` performs.

load helpers.bash
bats_require_minimum_version 1.5.0

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    state_init
}

# Write $1 as a script that runs with the engine loaded and output not muted.
_probe() {
    local root
    root=$(_vpssec_repo_root)
    cat > "$BATS_TEST_TMPDIR/probe.sh" <<SH
source "$root/core/common.sh"
VPSSEC_STATE="$VPSSEC_STATE" VPSSEC_BACKUPS="$VPSSEC_BACKUPS" VPSSEC_LOGS="$VPSSEC_LOGS"
_log_file="$VPSSEC_LOGS/vpssec.log"
source "$root/core/state.sh"
source "$root/core/security_levels.sh"
source "$root/core/engine.sh"
i18n_load en_US
VPSSEC_QUIET_SCAN=0
$1
SH
}

# Run $2 on a real terminal that types the lines in $1, then stays open and
# silent. Prints the terminal transcript.
_on_terminal() {
    command -v script >/dev/null || skip "script(1) not installed"
    _probe "$2"
    printf '%s' "$1" > "$BATS_TEST_TMPDIR/typed"
    bash -c "(cat '$BATS_TEST_TMPDIR/typed'; sleep 3) | script -qec 'bash $BATS_TEST_TMPDIR/probe.sh' /dev/null"
}

# Run $1 with no controlling terminal at all, as under cron or a CI job.
_without_terminal() {
    command -v setsid >/dev/null || skip "setsid(1) not installed"
    _probe "$1"
    setsid -w bash "$BATS_TEST_TMPDIR/probe.sh" </dev/null 2>&1
}

# A plan of the named fixes, each hung on a failed check titled after it.
_plan_of() {
    local id fixes=""
    for id in "$@"; do
        fixes+=$(jq -nc --arg f "$id" '{id: ($f + ".check"), module: ($f | split(".")[0]),
            severity: "low", status: "failed", title: ("Title " + $f), desc: "",
            suggestion: "", fix_id: $f}'),
    done
    echo "state_save_plan '{\"timestamp\": \"t\", \"fixes\": [${fixes%,}]}'"
}

# ---- what guide offers --------------------------------------------------------

@test "offer: a passed check carrying a fix id is not offered, a failed one is" {
    state_add_check "$(create_check_json timezone.using_utc timezone low passed \
        'Current timezone: Etc/UTC' '' '' timezone.set_timezone)"
    state_add_check "$(create_check_json timezone.ntp_disabled timezone low failed \
        'NTP disabled' '' '' timezone.enable_ntp)"
    run get_available_fixes
    [ "$status" -eq 0 ]
    [ "$(jq -r '[.[].fix_id] | join(",")' <<<"$output")" = "timezone.enable_ntp" ]
}

@test "offer: a host whose only fix-carrying checks passed ends as complete, exit 0" {
    # Through guide_mode: it used to list the timezone and locale changes on
    # every host, and the "nothing to fix" branch was unreachable.
    is_debian_based() { return 0; }
    _run_audit_pass() {
        state_init
        state_add_check "$(create_check_json timezone.locale_ok timezone low passed \
            'Locale set' '' '' timezone.set_locale)"
    }
    report_generate_all() { :; }
    VPSSEC_QUIET_SCAN=0
    run guide_mode
    [ "$status" -eq 0 ]
    grep -q 'Hardening complete' <<<"$output"
    _vpssec_refute grep -q 'Select fixes' <<<"$output"
}

@test "offer: the timezone audit hangs no fix on a timezone or locale that is set" {
    source "$(_vpssec_repo_root)/modules/timezone.sh"
    _timezone_current() { echo "Etc/UTC|timedatectl"; }
    _timezone_locale_set() { return 0; }
    _timezone_current_locale() { echo "en_US.UTF-8"; }
    _timezone_check_current
    _timezone_check_locale
    [ "$(jq -r '[.[] | select(.fix_id != "")] | length' "$STATE_CHECKS_FILE")" = "0" ]
    jq -r '.[] | select(.id == "timezone.using_utc") | .suggestion' "$STATE_CHECKS_FILE" \
        | grep -q 'timedatectl set-timezone'
    jq -r '.[] | select(.id == "timezone.locale_ok") | .suggestion' "$STATE_CHECKS_FILE" \
        | grep -q 'localectl set-locale'
}

# ---- declining is not failing ---------------------------------------------------

@test "declined: answering no to a fix's confirmation skips it, exit 0, no failure menu" {
    run _on_terminal $'n\n' "
FIX_CONFIRM[fake.ask]='test fixture'
fake_fix() { touch '$BATS_TEST_TMPDIR/applied'; }
$(_plan_of fake.ask)
rc=0; execute_plan || rc=\$?
echo \"rc=\$rc\""
    [[ "$output" == *"rc=0"* ]]
    [[ "$output" == *"Skipped: not confirmed"* ]]
    [[ "$output" == *"No fix applied"* ]]
    [[ "$output" == *"Skipped at confirmation (1): fake.ask"* ]]
    [[ "$output" != *"Failed"* ]]
    [[ "$output" != *"1) Skip"* ]]
    [ ! -e "$BATS_TEST_TMPDIR/applied" ]
}

@test "declined: the rest of the plan still runs and the run reads complete" {
    run _on_terminal $'n\n' "
FIX_SAFE[fake.works]='test fixture'
FIX_CONFIRM[fake.ask]='test fixture'
fake_fix() { [[ \$1 == fake.works ]] && touch '$BATS_TEST_TMPDIR/worked'; return 0; }
$(_plan_of fake.ask fake.works)
rc=0; execute_plan || rc=\$?
echo \"rc=\$rc\""
    [[ "$output" == *"rc=0"* ]]
    [[ "$output" == *"Hardening complete"* ]]
    [[ "$output" == *"Skipped at confirmation (1): fake.ask"* ]]
    [ -e "$BATS_TEST_TMPDIR/worked" ]
}

@test "declined: a fix that asks for itself and is answered no is skipped too" {
    # ufw.enable, the SSH gates and docker's restart prompt confirm inside the
    # fix (FIX_SELF_CONFIRMED); the answer reaches the engine the same way.
    run _on_terminal $'no\n' "
FIX_CONFIRM[fake.self]='test fixture'
FIX_SELF_CONFIRMED[fake.self]=true
fake_fix() { confirm_critical 'really?' || return 1; touch '$BATS_TEST_TMPDIR/applied'; }
$(_plan_of fake.self)
rc=0; execute_plan || rc=\$?
echo \"rc=\$rc\""
    [[ "$output" == *"rc=0"* ]]
    [[ "$output" == *"Skipped at confirmation (1): fake.self"* ]]
    [[ "$output" != *"Failed"* ]]
}

@test "declined: a no does not carry over to the next fix, which still fails" {
    run _on_terminal $'n\n1\n' "
FIX_CONFIRM[fake.ask]='test fixture'
FIX_SAFE[fake.broken]='test fixture'
fake_fix() { [[ \$1 == fake.ask ]]; }
$(_plan_of fake.ask fake.broken)
rc=0; execute_plan || rc=\$?
echo \"rc=\$rc\""
    [[ "$output" == *"rc=1"* ]]
    [[ "$output" == *"Skipped at confirmation (1): fake.ask"* ]]
    [[ "$output" == *"All fixes failed"* ]]
}

@test "declined: no terminal to ask on is a failure, not a skip" {
    # Nobody answered: automation that named this fix must not read success.
    run _without_terminal "
FIX_CONFIRM[fake.ask]='test fixture'
fake_fix() { touch '$BATS_TEST_TMPDIR/applied'; }
$(_plan_of fake.ask)
rc=0; execute_plan || rc=\$?
echo \"rc=\$rc\""
    [[ "$output" == *"rc=1"* ]]
    [[ "$output" == *"could not be read"* ]]
    [[ "$output" != *"Skipped at confirmation"* ]]
    [ ! -e "$BATS_TEST_TMPDIR/applied" ]
}

# ---- the failure menu's rollback ---------------------------------------------------

@test "failure menu: rollback restores the plan's session and reloads the running daemons" {
    # It used to restore files only: sshd kept serving the rolled-back config
    # and the re-audit, which reads the disk, reported the opposite.
    _vpssec_require_gnu_realpath
    local conf="$BATS_TEST_TMPDIR/host/etc/app.conf"
    mkdir -p "${conf%/*}"
    echo original > "$conf"
    _vpssec_stub_script systemctl <<'SH'
case "$*" in *"is-active --quiet ssh") exit 0 ;; *is-active*) exit 3 ;; esac
exit 0
SH
    run _on_terminal $'3\n' "
FIX_SAFE[fake.write]='test fixture'
FIX_SAFE[fake.broken]='test fixture'
fake_fix() {
    [[ \$1 == fake.broken ]] && return 1
    backup_file '$conf' >/dev/null && echo changed > '$conf'
}
$(_plan_of fake.write fake.broken)
rc=0; execute_plan || rc=\$?
echo \"rc=\$rc\""
    [[ "$output" == *"rc=1"* ]]
    [[ "$output" == *"Backup restored"* ]]
    [ "$(cat "$conf")" = "original" ]
    _vpssec_stub_called systemctl 'reload ssh'
}
