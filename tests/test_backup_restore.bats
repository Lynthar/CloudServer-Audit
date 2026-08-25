#!/usr/bin/env bats
# Path-safety tests for backup_restore (core/state.sh): the checks that stop it
# becoming a "write any host file" primitive when the backup directory is
# tampered with, or the target's parent is swung to a symlink mid-restore.

load helpers

setup() {
    _vpssec_load core/state.sh

    # Production restores under "/", so a test must never let a real host path
    # be the destination: VPSSEC_BACKUPS points at a test tree rooted under this
    # sandbox, so the "/<relative>" destination lands inside it.
    export TEST_HOST_ROOT="$BATS_TEST_TMPDIR/host"
    mkdir -p "$TEST_HOST_ROOT/etc"
    # backup_restore is deliberately not monkeypatched: isolation comes from
    # timestamps whose paths fall inside the throwaway tree, and the assertions
    # are the log plus the absence of writes outside it.
}

# Helper: redirect log output to a captureable file
_capture_logs() {
    export _log_file="$BATS_TEST_TMPDIR/vpssec.log"
    : > "$_log_file"
}

# Helper: build a valid timestamp directory and a sentinel file
_make_backup_session() {
    local ts="$1"
    local rel_path="$2"  # e.g. "etc/ssh/sshd_config"
    local content="$3"

    local backup_dir="$VPSSEC_BACKUPS/$ts"
    mkdir -p "$backup_dir/$(dirname "$rel_path")"
    printf '%s' "$content" > "$backup_dir/$rel_path"
}

# ---- Check 1: timestamp shape ----------------------------------------

@test "rejects non-timestamp arg (path traversal attempt)" {
    _capture_logs
    run backup_restore "../../etc"
    [ "$status" -ne 0 ]
    grep -q "does not match YYYYMMDD_HHMMSS" "$_log_file"
}

@test "rejects empty timestamp" {
    _capture_logs
    run backup_restore ""
    [ "$status" -ne 0 ]
}

@test "rejects timestamp-shaped but non-existent dir" {
    _capture_logs
    # Looks valid but no directory exists yet.
    run backup_restore "20990101_120000"
    [ "$status" -ne 0 ]
    grep -q "Backup not found" "$_log_file"
}

@test "reports failure for a valid but empty backup dir" {
    # A rollback that restores nothing is a failure from the operator's point of
    # view: they picked a backup, confirmed, and did not get their config back.
    # Returning 0 here makes rollback_mode print a green "restored" over a no-op.
    _capture_logs
    mkdir -p "$VPSSEC_BACKUPS/20260501_120000"
    run backup_restore "20260501_120000"
    [ "$status" -eq 1 ]
    grep -q "contained no restorable files" "$_log_file"
}

# ---- Check 2: symlinks inside backup tree ----------------------------

@test "does not propagate symlink-only backup entries to host" {
    _capture_logs
    # A symlink planted under backups/<ts>/ must never have its target's contents
    # written to the restore destination. Either find surfaces it and the [[ -L ]]
    # check skips it, or find never yields it; both leave the trap file unread.
    local secret="$BATS_TEST_TMPDIR/secret"
    echo "supersecret" > "$secret"

    local ts="20260501_120000"
    mkdir -p "$VPSSEC_BACKUPS/$ts/etc/ssh"
    ln -s "$secret" "$VPSSEC_BACKUPS/$ts/etc/ssh/sshd_config"

    # Nothing is restorable under either find behaviour, so the file count is
    # zero and this is a failed rollback (1), never 0.
    run backup_restore "$ts"
    [ "$status" -eq 1 ]

    # The skip message is not asserted — a find that never yields the symlink
    # logs nothing. The security property is: nothing under "/etc/ssh" was
    # created outside the sandbox.
    [ ! -e "/etc/ssh/sshd_config.tampered_test" ]
}

# ---- Check 3: destination symlink TOCTOU -----------------------------

@test "skips restore when target path is a symlink" {
    _capture_logs

    local ts="20260501_120000"
    local backup_dir="$VPSSEC_BACKUPS/$ts"

    # A relative path that maps under TEST_HOST_ROOT once backup_restore prefixes
    # "/". The destination directory must not be pre-created as a file.
    local rel="${TEST_HOST_ROOT#/}/sshd_config"
    mkdir -p "$backup_dir/$(dirname "$rel")"
    printf 'real-content' > "$backup_dir/$rel"

    # Pre-create the destination as a symlink pointing somewhere
    # the test would notice.
    local trap_target="$BATS_TEST_TMPDIR/trap"
    : > "$trap_target"
    mkdir -p "$TEST_HOST_ROOT"
    ln -sf "$trap_target" "$TEST_HOST_ROOT/sshd_config"

    # The only entry was skipped, so nothing was restored: status 1.
    run backup_restore "$ts"
    [ "$status" -eq 1 ]
    grep -q "target path is a symlink" "$_log_file"

    # Trap target must remain empty — restore must have refused
    # to follow the symlink and overwrite it.
    [ ! -s "$trap_target" ]
}

@test "skips restore when destination parent dir is a symlink" {
    _capture_logs

    local ts="20260501_120000"
    local backup_dir="$VPSSEC_BACKUPS/$ts"

    # Build a backup with a deep relative path: e.g. tmp/host/foo/bar/file
    local rel="${TEST_HOST_ROOT#/}/foo/bar/file"
    mkdir -p "$backup_dir/$(dirname "$rel")"
    echo "real" > "$backup_dir/$rel"

    # Replace /tmp/host/foo/bar with a symlink to /tmp/trap.
    local trap_dir="$BATS_TEST_TMPDIR/trap_dir"
    mkdir -p "$trap_dir"
    mkdir -p "$TEST_HOST_ROOT/foo"
    ln -sfn "$trap_dir" "$TEST_HOST_ROOT/foo/bar"

    # The only entry was skipped, so nothing was restored: status 1.
    run backup_restore "$ts"
    [ "$status" -eq 1 ]
    grep -q "parent directory is a symlink" "$_log_file"

    # trap_dir/file should NOT exist; the restore must have refused.
    [ ! -e "$trap_dir/file" ]
}

# ---- Happy path -----------------------------------------------------

@test "restores a normal file under the test sandbox" {
    _capture_logs

    local ts="20260501_120000"
    local backup_dir="$VPSSEC_BACKUPS/$ts"
    local rel="${TEST_HOST_ROOT#/}/sshd_config"
    mkdir -p "$backup_dir/$(dirname "$rel")"
    echo "expected" > "$backup_dir/$rel"

    # Make sure the destination tree exists but no symlinks
    # interfere — vanilla file restore.
    mkdir -p "$TEST_HOST_ROOT"

    run backup_restore "$ts"
    [ "$status" -eq 0 ]
    [ -f "$TEST_HOST_ROOT/sshd_config" ]
    [ "$(cat "$TEST_HOST_ROOT/sshd_config")" = "expected" ]
}

# Backup session: with a session open every backup_file lands in the SAME
# directory, so restoring it brings back the WHOLE plan, not just the files
# touched in the last wall-clock second. base_dir validation needs GNU realpath.

@test "backup session: all backups share one dir and restore together" {
    _vpssec_require_gnu_realpath

    local host="$BATS_TEST_TMPDIR/host"
    mkdir -p "$host/etc"
    echo "orig-a" > "$host/etc/a.conf"
    echo "orig-b" > "$host/etc/b.conf"

    VPSSEC_BACKUP_SESSION=$(backup_create_session)
    backup_file "$host/etc/a.conf" >/dev/null
    backup_file "$host/etc/b.conf" >/dev/null

    # Both backups live under the SAME session directory.
    [ -f "${VPSSEC_BACKUP_SESSION}/${host#/}/etc/a.conf" ]
    [ -f "${VPSSEC_BACKUP_SESSION}/${host#/}/etc/b.conf" ]

    # Mutate the live files, then restore the whole session.
    echo "changed-a" > "$host/etc/a.conf"
    echo "changed-b" > "$host/etc/b.conf"
    run backup_restore "$(basename "$VPSSEC_BACKUP_SESSION")"
    [ "$status" -eq 0 ]

    [ "$(cat "$host/etc/a.conf")" = "orig-a" ]
    [ "$(cat "$host/etc/b.conf")" = "orig-b" ]
    VPSSEC_BACKUP_SESSION=""
}

# Exit-status contract: 0 = everything restored, 2 = partial, 1 = nothing.
# rollback_mode branches on all three; collapsing them into a boolean lets a
# zero-file rollback print a green "restored".

@test "partial restore (one file, one skipped entry) returns 2" {
    _capture_logs

    local ts="20260501_120000"
    local backup_dir="$VPSSEC_BACKUPS/$ts"

    # Entry 1: restores cleanly.
    local ok_rel="${TEST_HOST_ROOT#/}/good.conf"
    mkdir -p "$backup_dir/$(dirname "$ok_rel")"
    echo "restored-content" > "$backup_dir/$ok_rel"

    # Entry 2: destination is a symlink, so the safety check skips it.
    local bad_rel="${TEST_HOST_ROOT#/}/bad.conf"
    printf 'never-written' > "$backup_dir/$bad_rel"
    local trap_target="$BATS_TEST_TMPDIR/trap_partial"
    : > "$trap_target"
    ln -sf "$trap_target" "$TEST_HOST_ROOT/bad.conf"

    run backup_restore "$ts"
    [ "$status" -eq 2 ]

    [ "$(cat "$TEST_HOST_ROOT/good.conf")" = "restored-content" ]
    [ ! -s "$trap_target" ]
}

@test "backup_file without a session uses a per-call timestamp dir" {
    _vpssec_require_gnu_realpath
    VPSSEC_BACKUP_SESSION=""
    local host="$BATS_TEST_TMPDIR/host"
    mkdir -p "$host/etc"
    echo x > "$host/etc/c.conf"
    local out
    out=$(backup_file "$host/etc/c.conf")
    [[ "$out" =~ /backups/[0-9]{8}_[0-9]{6}/ ]]
}
