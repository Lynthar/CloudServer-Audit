#!/usr/bin/env bats
# A filesystem walk cut short by its time limit, or one that never ran, must not
# read as "nothing found": the walk ends with a cut record, the audit withholds
# its passed checks, names the walks that stopped, and the run exits 3.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh core/engine.sh \
        modules/filesystem.sh modules/webapp.sh
    i18n_load en_US
    state_init
    WALK_OUT="$BATS_TEST_TMPDIR/walk.out"
}

# The records a walk wrote to WALK_OUT, NUL-split into the array `recs`.
_walk_records() {
    mapfile -d '' -t recs < "$WALK_OUT"
}

# Only the walking sub-audits run; the rest read the container's real files.
_only_walks() {
    _fs_audit_sensitive_perms() { :; }
    _fs_audit_tmp_mount() { :; }
    _fs_audit_umask() { :; }
    _fs_audit_cron() { :; }
}

# Every find and getcap stalls past a one-second limit.
_stall_walks() {
    _FS_FIND_TIMEOUT=1
    _vpssec_stub_script find <<<'sleep 5'
    _vpssec_stub_script getcap <<<'sleep 5'
}

# As production calls a module audit: in a condition, so errexit is off.
_audit() {
    if "$1"; then :; fi
}

_has_check() {
    jq -e --arg id "$1" 'any(.[]; .id == $id)' "$STATE_CHECKS_FILE" >/dev/null
}

# ---- _fs_run_find ------------------------------------------------------------

@test "_fs_run_find: a walk killed by the limit ends with the cut record, partial record swallowed" {
    _FS_FIND_TIMEOUT=1
    _fs_run_find t bash -c 'printf "/a\0/partial"; sleep 5' > "$WALK_OUT"
    _walk_records
    [ "${#recs[@]}" -eq 2 ]
    [ "${recs[0]}" = "/a" ]
    [[ "${recs[1]}" == *"$_FS_WALK_CUT" ]]
    grep -q "filesystem scan 't' timed out after 1s" "$_log_file"
}

@test "_fs_run_find: a walk that never ran ends with the cut record" {
    _FS_FIND_TIMEOUT=abc   # timeout(1) rejects it: 125
    _fs_run_find t true > "$WALK_OUT"
    _walk_records
    [ "${recs[*]}" = "$_FS_WALK_CUT" ]

    _FS_FIND_TIMEOUT=60
    _fs_run_find t /nonexistent/walker > "$WALK_OUT"   # 127
    _walk_records
    [ "${recs[*]}" = "$_FS_WALK_CUT" ]
    grep -q "filesystem scan 't' did not run (exit 127)" "$_log_file"
}

@test "_fs_run_find: a finished walk has no cut record, even when find exits 1" {
    # find exits 1 for any unreadable directory on the way; the walk still ran.
    _fs_run_find t bash -c 'printf "/a\0"; exit 1' > "$WALK_OUT"
    _walk_records
    [ "${recs[*]}" = "/a" ]
}

@test "fs_timeout_valid: whole seconds above 0 only" {
    local v
    for v in 1 60 300; do
        _FS_FIND_TIMEOUT=$v
        fs_timeout_valid
    done
    for v in 0 -1 1.5 5m abc ""; do
        _FS_FIND_TIMEOUT=$v
        _vpssec_refute fs_timeout_valid
    done
}

@test "vpssec audit refuses a bad VPSSEC_FS_TIMEOUT before any module runs" {
    [ "$(id -u)" = "0" ] || skip "the root check runs first and exits 1 for non-root"
    run env VPSSEC_FS_TIMEOUT=5min "$(_vpssec_repo_root)/vpssec" audit \
        --lang=en_US --include=filesystem --yes --json-only
    [ "$status" -eq 1 ]
    [[ "$output" == *"$(i18n 'error.bad_fs_timeout' "value=5min")"* ]]
}

# ---- filesystem_audit --------------------------------------------------------

@test "filesystem audit: cut walks emit no passed check, are named, and mark the module incomplete" {
    _only_walks
    _stall_walks
    _audit filesystem_audit

    local ok
    for ok in suid_ok sgid_ok no_world_writable owner_ok caps_ok; do
        _vpssec_refute _has_check "filesystem.$ok"
    done
    run jq -r '.[] | select(.id == "filesystem.scan_incomplete") | "\(.status) \(.severity)"' \
        "$STATE_CHECKS_FILE"
    [ "$output" = "failed info" ]
    [ "${_FS_CUT_WALKS[*]}" = "suid sgid world-writable world-writable-dirs no-owner caps" ]
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" filesystem "* ]]
}

@test "filesystem audit: a cut walk reports what it found before the cut, not the half-written last path" {
    # Killed mid-write, find leaves its last record unterminated; it reaches the
    # loop glued to the cut record and must not count as a finding.
    _only_walks
    _FS_FIND_TIMEOUT=1
    _vpssec_stub_script find <<'SH'
case "$*" in
    *-4000*) printf '/opt/evil/suidshell\0/opt/evil/half'; sleep 5 ;;
esac
SH
    _vpssec_stub getcap 0
    _audit filesystem_audit

    run jq -r '.[] | select(.id == "filesystem.suspicious_suid") | .title + "|" + .desc' "$STATE_CHECKS_FILE"
    [[ "$output" == "$(i18n 'filesystem.suspicious_suid' "count=1")|"* ]]
    [[ "$output" == *"/opt/evil/suidshell"* ]]
    [[ "$output" != *"half"* ]]
    [ "${_FS_CUT_WALKS[*]}" = "suid" ]
    _has_check filesystem.sgid_ok
    _has_check filesystem.scan_incomplete
}

@test "filesystem audit: a full page of findings stops reading before the cut record" {
    # The check fails on the page alone, so the unread rest of the walk is moot.
    _only_walks
    _FS_FIND_TIMEOUT=1
    _vpssec_stub_script find <<'SH'
case "$*" in
    *-4000*) for i in $(seq 1 25); do printf '/opt/evil/s%d\0' "$i"; done; sleep 5 ;;
esac
SH
    _vpssec_stub getcap 0
    _audit filesystem_audit

    run jq -r '.[] | select(.id == "filesystem.suspicious_suid") | .title' "$STATE_CHECKS_FILE"
    [ "$output" = "$(i18n 'filesystem.suspicious_suid' "count=$FS_MAX_REPORT_ITEMS")" ]
    [ "${#_FS_CUT_WALKS[@]}" -eq 0 ]
    _vpssec_refute _has_check filesystem.scan_incomplete
}

@test "filesystem audit: finished walks with nothing found still pass, and nothing is incomplete" {
    _only_walks
    _vpssec_stub find 0
    _vpssec_stub getcap 0
    _audit filesystem_audit

    _has_check filesystem.suid_ok
    _has_check filesystem.caps_ok
    _vpssec_refute _has_check filesystem.scan_incomplete
    [ "${#VPSSEC_MODULES_FAILED[@]}" -eq 0 ]
}

# ---- webapp_audit ------------------------------------------------------------

@test "webapp audit: cut web-root walks withhold sensitive_files_ok and mark the module incomplete" {
    nginx_present() { return 1; }
    _webapp_apache_installed() { return 1; }
    _webapp_php_installed() { return 1; }
    _webapp_ssl_cert_expiry() { :; }
    _webapp_other_webserver() { :; }
    WEB_ROOTS=("$BATS_TEST_TMPDIR/www")
    mkdir -p "$BATS_TEST_TMPDIR/www"
    _stall_walks
    _audit webapp_audit

    _vpssec_refute _has_check webapp.sensitive_files_ok
    _has_check webapp.scan_incomplete
    [ "${_FS_CUT_WALKS[*]}" = "webapp-sensitive webapp-backup" ]
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" webapp "* ]]
}
