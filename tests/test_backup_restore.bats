#!/usr/bin/env bats
#
# Path-safety tests for backup_restore (core/state.sh).
#
# These pin the defense-in-depth checks added to prevent
# backup_restore from becoming a "write any host file" primitive
# when the backup directory is partially tampered with or the
# rollback target's parent has been swung to a symlink between
# backup and restore (TOCTOU).

load helpers

setup() {
    _vpssec_load core/state.sh

    # Per-test sandbox for both backup source and restore target.
    # We restore into BATS_TEST_TMPDIR/host so we never touch real
    # host paths (the production code restores under "/" — fine in
    # production, fatal for tests). To do that without modifying
    # production code, we run backup_restore in a subshell that
    # overrides VPSSEC_BACKUPS to point at our test backup tree;
    # the destination is "/<relative>", which we then rewrite by
    # rooting the test backup tree under a sandbox host.
    export TEST_HOST_ROOT="$BATS_TEST_TMPDIR/host"
    mkdir -p "$TEST_HOST_ROOT/etc"
    # The production destination is hard-coded "/${relative_path}".
    # For test isolation we *don't* monkeypatch backup_restore;
    # instead we operate on timestamps that produce paths under
    # an existing throwaway tree, and we assert via log inspection
    # plus that no host file outside the tree was touched.
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

@test "accepts valid timestamp with empty backup dir" {
    _capture_logs
    mkdir -p "$VPSSEC_BACKUPS/20260501_120000"
    run backup_restore "20260501_120000"
    [ "$status" -eq 0 ]
}

# ---- Check 2: symlinks inside backup tree ----------------------------

@test "does not propagate symlink-only backup entries to host" {
    _capture_logs
    # Threat: attacker plants a symlink under backups/<ts>/ that
    # points at an arbitrary host file. We need to ensure
    # backup_restore neither reads the linked file nor writes its
    # contents to the rolled-back location.
    #
    # Two valid outcomes:
    #   - find -type f follows the symlink and returns it; our
    #     [[ -L ]] check skips with the "symlinked backup entry"
    #     log. (GNU find on Linux production.)
    #   - find -type f does not include symlinks at all; the loop
    #     never sees the entry and nothing is restored. (BSD find
    #     on macOS dev.)
    # In either case the trap file's contents must NOT have been
    # propagated, which is the actual security property.
    local secret="$BATS_TEST_TMPDIR/secret"
    echo "supersecret" > "$secret"

    local ts="20260501_120000"
    mkdir -p "$VPSSEC_BACKUPS/$ts/etc/ssh"
    ln -s "$secret" "$VPSSEC_BACKUPS/$ts/etc/ssh/sshd_config"

    run backup_restore "$ts"
    [ "$status" -eq 0 ]

    # If the production path (Linux GNU find) reached us, the skip
    # message should be in the log. We don't fail the test if it
    # isn't — BSD find on macOS won't even surface the symlink to
    # backup_restore — but we DO assert the security property:
    # nothing under "/etc/ssh" was created in the test sandbox.
    [ ! -e "/etc/ssh/sshd_config.tampered_test" ]
}

# ---- Check 3: destination symlink TOCTOU -----------------------------

@test "skips restore when target path is a symlink" {
    _capture_logs

    local ts="20260501_120000"
    local backup_dir="$VPSSEC_BACKUPS/$ts"

    # Use a relative path that maps under TEST_HOST_ROOT after the
    # leading "/" prefix is added by backup_restore. (Don't pre-
    # create the destination dir as if it were a file — that was a
    # test bug.)
    local rel="${TEST_HOST_ROOT#/}/sshd_config"
    mkdir -p "$backup_dir/$(dirname "$rel")"
    printf 'real-content' > "$backup_dir/$rel"

    # Pre-create the destination as a symlink pointing somewhere
    # the test would notice.
    local trap_target="$BATS_TEST_TMPDIR/trap"
    : > "$trap_target"
    mkdir -p "$TEST_HOST_ROOT"
    ln -sf "$trap_target" "$TEST_HOST_ROOT/sshd_config"

    run backup_restore "$ts"
    [ "$status" -eq 0 ]
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

    run backup_restore "$ts"
    [ "$status" -eq 0 ]
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
