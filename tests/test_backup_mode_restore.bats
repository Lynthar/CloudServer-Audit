#!/usr/bin/env bats
# The rollback contract for a file's PERMISSIONS. backup_file chmods its own
# copy to 600 and backup_restore uses `cp -p`, so without .vpssec_modes every
# file comes back at 600 — /etc/passwd at 600 breaks non-root name lookups.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    export TMPDIR="$BATS_TEST_TMPDIR"

    etc=$(_vpssec_fake_etc)
    _vpssec_begin_backup_session
    session_ts="$VPSSEC_TEST_BACKUP_SESSION_TS"
    modes_manifest="${VPSSEC_BACKUP_SESSION}/.vpssec_modes"
}

# A file under the scratch tree. backup_restore maps a backup entry back to
# its absolute original path, so a scratch path round-trips correctly.
_make_file() {
    local path="$1" mode="$2"
    mkdir -p "$(dirname "$path")"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$path"
    chmod "$mode" "$path"
}

_mode_of() { stat -c '%a' "$1"; }

# ==============================================================================
# The regression
# ==============================================================================

@test "modes: rollback restores the file's own mode, not the backup copy's 600" {
    local f="$etc/passwd"
    _make_file "$f" 666

    backup_file "$f" >/dev/null
    chmod 644 "$f"

    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$f")" = "666" ]
}

@test "modes: the backup copy itself stays at 600" {
    # The reason the mode has to be recorded separately: this is deliberate,
    # so the fix must not be to stop chmodding the snapshot.
    local f="$etc/shadow"
    _make_file "$f" 640

    backup_file "$f" >/dev/null
    [ "$(_mode_of "${VPSSEC_BACKUP_SESSION}$f")" = "600" ]
}

@test "modes: content is restored as well as the mode" {
    local f="$etc/passwd"
    _make_file "$f" 640
    printf 'original\n' > "$f"
    chmod 640 "$f"

    backup_file "$f" >/dev/null
    printf 'rewritten by a fix\n' > "$f"
    chmod 600 "$f"

    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    grep -qx 'original' "$f"
    [ "$(_mode_of "$f")" = "640" ]
}

# ==============================================================================
# The manifest
# ==============================================================================

@test "modes: the manifest records the pre-plan mode, not an intermediate" {
    # Same first-write-wins rule as the content snapshot. A fix that backs the
    # same file up once per parameter (kernel.sh's sysctl drop-in does) would
    # otherwise record the mode of its own half-finished work.
    local f="$etc/passwd"
    _make_file "$f" 666

    backup_file "$f" >/dev/null
    chmod 600 "$f"
    backup_file "$f" >/dev/null

    [ "$(grep -c . "$modes_manifest")" -eq 1 ]
    grep -qxF "666 $f" "$modes_manifest"
}

@test "modes: recording the same path twice keeps the first mode" {
    # backup_track_mode is called directly, not through backup_file: backup_file
    # returns early for a file it already snapshotted this session, so its dedup
    # hides this guard. This is the only way to exercise the helper's idempotence.
    local f="$etc/passwd"
    _make_file "$f" 666

    backup_track_mode "$f" "$VPSSEC_BACKUP_SESSION"
    chmod 600 "$f"
    backup_track_mode "$f" "$VPSSEC_BACKUP_SESSION"

    [ "$(grep -c . "$modes_manifest")" -eq 1 ]
    grep -qxF "666 $f" "$modes_manifest"
}

@test "modes: the manifest is not itself restored into /" {
    # It lives at the session root, so its path relative to the backup dir is
    # ".vpssec_modes" — which the restore walk would map to /.vpssec_modes.
    # Same trap as .vpssec_created, which is why both are excluded by name.
    local f="$etc/passwd"
    _make_file "$f" 644
    # helpers.bash sets VPSSEC_QUIET_SCAN=1, which silences the count line.
    VPSSEC_QUIET_SCAN=0
    # Self-healing: when this assertion fails it does so by CREATING the file it
    # refutes, which would make every later run fail for an unrelated reason.
    rm -f /.vpssec_modes

    backup_file "$f" >/dev/null
    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    _vpssec_refute test -e /.vpssec_modes
    # Exactly one entry restored: the file, not the file plus a manifest.
    grep -qE '(^|[^0-9])1 file\(s\) restored' <<<"$output"
}

@test "modes: a path containing spaces keeps its mode" {
    # The manifest is "<mode> <path>", parsed on the FIRST space only, because
    # the mode is the one field that can never contain one.
    local f="$etc/a dir/with space.conf"
    _make_file "$f" 664

    backup_file "$f" >/dev/null
    chmod 600 "$f"

    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$f")" = "664" ]
}

@test "modes: a fix-created file gets no mode entry" {
    # It did not exist, so there is no prior mode; rollback DELETES it rather
    # than restoring one. A stray entry here would chmod a path that is about
    # to be removed.
    local f="$etc/created-by-fix.conf"

    backup_file "$f" >/dev/null 2>&1 || true
    grep -qxF "$f" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
    _vpssec_refute test -f "$modes_manifest"
}

# ==============================================================================
# Backward compatibility
# ==============================================================================

@test "modes: a backup taken before the manifest existed still restores" {
    # Rolling back a directory written by an older vpssec must not fail just
    # because it has no .vpssec_modes. Content wins over mode.
    local f="$etc/passwd"
    _make_file "$f" 666

    backup_file "$f" >/dev/null
    rm -f "$modes_manifest"
    printf 'rewritten\n' > "$f"

    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    grep -qx 'root:x:0:0:root:/root:/bin/bash' "$f"
}

@test "modes: an unparseable manifest entry does not abort the restore" {
    local f="$etc/passwd"
    _make_file "$f" 666

    backup_file "$f" >/dev/null
    printf 'not-a-mode /some/other/path\n' >> "$modes_manifest"
    chmod 600 "$f"

    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    [ "$(_mode_of "$f")" = "666" ]
}
