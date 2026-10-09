#!/usr/bin/env bats
# A rollback's preview lists what it restores and what it deletes, and a damaged
# session never rolls back as if whole: a copy that is missing or cut short is
# never reported, or written back, as restored.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/engine.sh
    i18n_load en_US
    export TMPDIR="$BATS_TEST_TMPDIR"
    _vpssec_require_gnu_realpath

    etc=$(_vpssec_fake_etc)
    _vpssec_begin_backup_session
    session_ts="$VPSSEC_TEST_BACKUP_SESSION_TS"
    printf 'original\n' > "$etc/app.conf"
    chmod 640 "$etc/app.conf"
}

# ---- the preview before a rollback ------------------------------------------

@test "preview: lists the file to restore and the file to delete, never the manifests" {
    # It used to list .vpssec_modes / .vpssec_created as files restored to /,
    # and not the drop-in a rollback would delete.
    backup_file "$etc/app.conf" >/dev/null
    backup_file "$etc/new.conf" >/dev/null
    echo created > "$etc/new.conf"
    confirm_critical() { return 1; }   # stop at the question the preview is for

    run rollback_mode "$session_ts"
    [ "$status" -eq 0 ]
    grep -A1 'Files to restore:' <<<"$output" | grep -qx "  - $etc/app.conf"
    grep -A1 'Files to delete' <<<"$output" | grep -qx "  - $etc/new.conf"
    _vpssec_refute grep -q 'vpssec_modes\|vpssec_created' <<<"$output"
}

@test "preview: the session menu counts the changes, not the manifests" {
    backup_file "$etc/app.conf" >/dev/null
    backup_file "$etc/new.conf" >/dev/null
    echo created > "$etc/new.conf"
    run backup_list_contents "$session_ts"
    [ "$status" -eq 0 ]
    [ "$output" = "restore $etc/app.conf
delete $etc/new.conf" ]
}

# ---- a damaged session ------------------------------------------------------------

@test "damaged: a copy deleted from the session is a partial rollback, named" {
    printf 'other\n' > "$etc/other.conf"
    backup_file "$etc/app.conf" >/dev/null
    backup_file "$etc/other.conf" >/dev/null
    rm -f "${VPSSEC_BACKUP_SESSION}${etc}/other.conf"
    echo changed > "$etc/app.conf"

    run backup_restore "$session_ts"
    [ "$status" -eq 2 ]
    [ "$(cat "$etc/app.conf")" = "original" ]
    grep -qF "backup copy missing): $etc/other.conf" "$VPSSEC_LOGS/vpssec.log"
    backup_list_contents "$session_ts" | grep -qx "missing $etc/other.conf"
}

@test "damaged: a backup killed mid-copy leaves nothing a rollback would write back" {
    # cp straight to the final name left the fragment there: the next backup
    # kept it as the original and rollback restored it, rc 0.
    _vpssec_stub_script cp <<SH
head -c 3 "\$2" > "\${@: -1}"
kill -9 \$PPID
SH
    ( backup_file "$etc/app.conf" >/dev/null ) || true
    rm -f "$(_vpssec_stub_dir)/cp"; hash -r
    [ ! -e "${VPSSEC_BACKUP_SESSION}${etc}/app.conf" ]

    backup_file "$etc/app.conf" >/dev/null
    [ "$(backup_list_contents "$session_ts")" = "restore $etc/app.conf" ]
    echo changed > "$etc/app.conf"
    run backup_restore "$session_ts"
    [ "$status" -eq 0 ]
    [ "$(cat "$etc/app.conf")" = "original" ]
}

@test "damaged: a mode that cannot be recorded fails the backup and keeps no copy" {
    # The failed write was swallowed and the file came back 600 on rollback.
    mkdir -p "${VPSSEC_BACKUP_SESSION}/.vpssec_modes"   # an append to it fails
    run backup_file "$etc/app.conf"
    [ "$status" -eq 1 ]
    [ ! -e "${VPSSEC_BACKUP_SESSION}${etc}/app.conf" ]
}
