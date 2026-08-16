#!/usr/bin/env bats
#
# Regression tests for the Docker daemon.json writer and the live-restore
# audit predicate it now asserts as a postcondition.
#
# Two defects motivate this file:
#
#   1. _docker_check_live_restore piped `docker info` straight into
#      `grep -qi '^true$'`, so ANY non-true answer fell through to a
#      daemon.json fallback that was only meant for an unreachable daemon.
#      A running daemon answering "false" was therefore overruled by a
#      daemon.json that merely said true — masking exactly the "the file
#      says X but a systemd ExecStart override won" case the check exists
#      to catch.
#   2. _docker_fix_enable_daemon_setting returned 0 after the operator
#      declined the daemon restart, so the engine recorded live-restore as
#      complete while the daemon was still running without it.
#
# The two settings differ on purpose: live-restore is only observable
# through the running daemon, whereas no-new-privileges has no `docker
# info` field and its audit accepts daemon.json on its own. A blanket
# "declining the restart fails the fix" would be wrong for the latter.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/docker.sh"

    etc=$(_vpssec_fake_etc)
    DOCKER_DAEMON_JSON="$etc/docker/daemon.json"
    mkdir -p "$etc/docker"

    _vpssec_stub systemctl
}

# A running daemon that reports LiveRestoreEnabled=$1 forever.
_daemon_reports() {
    _vpssec_stub_script docker <<SH
case "\$*" in
    *LiveRestoreEnabled*) echo "$1" ;;
    *) echo "" ;;
esac
exit 0
SH
}

# A running daemon that only picks the setting up once something has
# restarted it — the real lifecycle, in one stub.
_daemon_picks_up_on_restart() {
    _vpssec_stub_script systemctl <<SH
[[ "\$*" == *"restart docker"* ]] && touch "$BATS_TEST_TMPDIR/restarted"
exit 0
SH
    _vpssec_stub_script docker <<SH
case "\$*" in
    *LiveRestoreEnabled*)
        if [[ -f "$BATS_TEST_TMPDIR/restarted" ]]; then echo true; else echo false; fi ;;
    *) echo "" ;;
esac
exit 0
SH
}

# ---- the audit predicate --------------------------------------------

@test "live-restore check: a running daemon answering true passes" {
    _daemon_reports true
    run _docker_check_live_restore
    [ "$status" -eq 0 ]
}

@test "live-restore check: a running daemon answering false fails even when daemon.json says true" {
    # The regression. daemon.json is the operator's intent; the daemon's
    # answer is the truth, and it must win.
    _daemon_reports false
    printf '{"live-restore": true}\n' > "$DOCKER_DAEMON_JSON"

    run _docker_check_live_restore
    [ "$status" -ne 0 ]
}

@test "live-restore check: an unreachable daemon falls back to daemon.json" {
    _vpssec_stub docker 1
    printf '{"live-restore": true}\n' > "$DOCKER_DAEMON_JSON"

    run _docker_check_live_restore
    [ "$status" -eq 0 ]
}

@test "live-restore check: an unreachable daemon with no daemon.json fails" {
    _vpssec_stub docker 1
    run _docker_check_live_restore
    [ "$status" -ne 0 ]
}

@test "live-restore check: the daemon's answer is compared case-insensitively" {
    # `docker info` renders a Go bool, so today the answer is always lower
    # case and dropping the ,, would change nothing observable. That is
    # exactly why it needs pinning: the tolerance is deliberate, and without
    # a test the next reader has no way to tell it apart from noise.
    _daemon_reports True
    run _docker_check_live_restore
    [ "$status" -eq 0 ]

    _daemon_reports FALSE
    run _docker_check_live_restore
    [ "$status" -ne 0 ]
}

# ---- the fix's postcondition ----------------------------------------

@test "live-restore fix: declining the restart reports failure, not success" {
    _daemon_reports false
    confirm_critical() { return 1; }

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    [ "$status" -eq 1 ]
}

@test "live-restore fix: the setting is still staged in daemon.json when the restart is declined" {
    # Declining is not an error in the file-writing sense — the operator's
    # choice persists and takes effect on the next restart. Only the
    # completion claim is withheld.
    _daemon_reports false
    confirm_critical() { return 1; }

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON"
}

@test "live-restore fix: accepting the restart succeeds" {
    _daemon_picks_up_on_restart
    confirm_critical() { return 0; }

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    [ "$status" -eq 0 ]
}

@test "no-new-privileges fix: declining the restart is NOT a failure" {
    # Its audit accepts daemon.json alone, so the fix has achieved what the
    # next audit will measure. Failing here would be a false alarm.
    _daemon_reports false
    confirm_critical() { return 1; }

    run _docker_fix_enable_daemon_setting "no-new-privileges" true _docker_check_no_new_privileges
    [ "$status" -eq 0 ]
}

# ---- the writer itself ----------------------------------------------

@test "daemon.json: a malformed existing file is refused, not clobbered" {
    _daemon_reports true
    confirm_critical() { return 0; }
    printf 'this is not json' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    [ "$status" -eq 1 ]
    [ "$(cat "$DOCKER_DAEMON_JSON")" = "this is not json" ]
}

@test "daemon.json: existing keys are merged, not replaced" {
    _daemon_picks_up_on_restart
    confirm_critical() { return 0; }
    printf '{"log-driver": "journald"}\n' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    [ "$status" -eq 0 ]
    jq -e '.["log-driver"] == "journald"' "$DOCKER_DAEMON_JSON"
    jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON"
}

@test "daemon.json: an existing file is backed up before being edited" {
    _daemon_picks_up_on_restart
    confirm_critical() { return 0; }
    printf '{"log-driver": "journald"}\n' > "$DOCKER_DAEMON_JSON"
    _vpssec_begin_backup_session

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    [ "$status" -eq 0 ]
    [ -f "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}" ]
    jq -e '.["log-driver"] == "journald"' "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}"
    jq -e '.["live-restore"] == null' "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}"
}

@test "daemon.json: no leftover .tmp file on the refusal path" {
    _daemon_reports true
    confirm_critical() { return 0; }
    printf 'not json' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore
    [ ! -e "${DOCKER_DAEMON_JSON}.tmp" ]
}

@test "daemon.json: a merge that fails leaves no .tmp file and no half-written file" {
    # The refusal path above never reaches the merge, so it cannot cover the
    # cleanup there. `[]` is the input that separates them: valid JSON, so it
    # passes the refusal guard, but `.["live-restore"] = true` cannot index an
    # array, so the merge itself fails and the cleanup runs.
    _daemon_reports false
    confirm_critical() { return 0; }
    printf '[]\n' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore

    [ "$status" -ne 0 ]
    [ ! -e "${DOCKER_DAEMON_JSON}.tmp" ]
    # The operator's file is exactly as they left it.
    [ "$(cat "$DOCKER_DAEMON_JSON")" = "[]" ]
}

@test "daemon.json: a refused file is not snapshotted into the backup session" {
    # What the refusal guard is FOR, and the only thing that distinguishes it
    # from the merge failing on its own: it sits ahead of backup_file, so a
    # file the fix declines to touch leaves no trace in the rollback session.
    # Remove the guard and the malformed file gets snapshotted, the merge
    # fails anyway, and the session ends up carrying an entry for a file that
    # was never modified — same exit status, same daemon.json, different
    # rollback.
    _daemon_reports false
    confirm_critical() { return 0; }
    printf 'not json' > "$DOCKER_DAEMON_JSON"
    _vpssec_begin_backup_session

    run _docker_fix_enable_daemon_setting "live-restore" true _docker_check_live_restore

    [ "$status" -ne 0 ]
    [ ! -e "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}" ]
}

# ---- the backup contract ---------------------------------------------

@test "daemon.json: a backup that cannot be recorded aborts the fix" {
    # The lever is the created-file manifest, not cp: a stock host ships no
    # daemon.json, so backup_file takes the register-as-created branch. A
    # directory where the manifest file belongs makes that append fail.
    _vpssec_begin_backup_session
    mkdir -p "$VPSSEC_BACKUP_SESSION/$VPSSEC_CREATED_MANIFEST"

    run _docker_fix_enable_daemon_setting "live-restore" true
    [ "$status" -ne 0 ]
    [ ! -f "$DOCKER_DAEMON_JSON" ]
}
