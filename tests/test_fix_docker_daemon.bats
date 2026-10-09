#!/usr/bin/env bats
# The daemon.json writer and the daemon-setting predicates the engine asserts as
# FIX_VERIFY postconditions. The running daemon's answer is final wherever it
# gives one; live-restore is applied by reload, no-new-privileges by restart.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    state_init
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

# A running daemon that only picks the setting up once systemctl has sent it
# $1 (reload or restart) — the real lifecycle, in one stub. It is Engine $2
# (default 29), and lists no-new-privileges in SecurityOptions once loaded.
_daemon_picks_up_on() {
    _vpssec_stub_script systemctl <<SH
[[ "\$*" == "$1 docker" ]] && touch "$BATS_TEST_TMPDIR/loaded"
exit 0
SH
    _vpssec_stub_script docker <<SH
case "\$*" in
    *ServerVersion*) echo "${2:-29.1.3}" ;;
    *LiveRestoreEnabled*)
        if [[ -f "$BATS_TEST_TMPDIR/loaded" ]]; then echo true; else echo false; fi ;;
    *SecurityOptions*)
        if [[ -f "$BATS_TEST_TMPDIR/loaded" ]]; then
            echo '["name=seccomp,profile=builtin","name=no-new-privileges"]'
        else
            echo '["name=seccomp,profile=builtin"]'
        fi ;;
    *) echo "" ;;
esac
exit 0
SH
}

# systemd's view of docker.service: `systemctl show` gives ExecStart's argv as
# $1, EnvironmentFiles as $2; `systemctl cat` gives $3, the raw unit text.
# Through files, so a literal $DOCKER_OPTS reaches the stub unexpanded.
_unit() {
    printf '%s\n' "$1" > "$BATS_TEST_TMPDIR/unit.argv"
    printf '%s' "${2:-}" > "$BATS_TEST_TMPDIR/unit.env"
    printf '%s\n' "${3:-}" > "$BATS_TEST_TMPDIR/unit.cat"
    _vpssec_stub_script systemctl <<SH
case "\$*" in
    "show -p ExecStart --value docker.service")
        printf '{ path=/usr/bin/dockerd ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] }\n' \
            "\$(cat "$BATS_TEST_TMPDIR/unit.argv")" ;;
    "show -p EnvironmentFiles --value docker.service")
        [[ -s "$BATS_TEST_TMPDIR/unit.env" ]] && \
            printf '%s (ignore_errors=yes)\n' "\$(cat "$BATS_TEST_TMPDIR/unit.env")" ;;
    "cat docker.service") cat "$BATS_TEST_TMPDIR/unit.cat" ;;
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
    # `docker info` renders a Go bool, so today the answer is always lower case
    # and dropping the ,, would change nothing observable. That is why it needs
    # pinning: the tolerance is deliberate, not noise.
    _daemon_reports True
    run _docker_check_live_restore
    [ "$status" -eq 0 ]

    _daemon_reports FALSE
    run _docker_check_live_restore
    [ "$status" -ne 0 ]
}

# ---- no-new-privileges and ICC: the daemon first, then the configuration ----

# An Engine $1 daemon whose SecurityOptions are $2 and whose default bridge
# reports enable_icc=$3 (empty: the daemon gives no such option).
_daemon_v() {
    _vpssec_stub_script docker <<SH
case "\$*" in
    *ServerVersion*) echo "$1" ;;
    *SecurityOptions*) echo '$2' ;;
    "network inspect bridge"*) echo "$3" ;;
    *) echo "" ;;
esac
exit 0
SH
}

@test "no-new-privileges check: Engine 24+ is asked, and daemon.json alone is not on" {
    # Written but never loaded: containers created now still lack it.
    _daemon_v 29.1.3 '["name=seccomp,profile=builtin"]' true
    printf '{"no-new-privileges": true}\n' > "$DOCKER_DAEMON_JSON"
    run _docker_check_no_new_privileges
    [ "$status" -ne 0 ]

    _daemon_v 24.0.7 '["name=seccomp,profile=builtin","name=no-new-privileges"]' true
    rm -f "$DOCKER_DAEMON_JSON"
    run _docker_check_no_new_privileges
    [ "$status" -eq 0 ]
}

@test "no-new-privileges check: an older daemon falls back to daemon.json" {
    _daemon_v 20.10.24+dfsg1 '' true
    printf '{"no-new-privileges": true}\n' > "$DOCKER_DAEMON_JSON"
    run _docker_check_no_new_privileges
    [ "$status" -eq 0 ]
}

@test "no-new-privileges check: the flag's value counts, not its presence" {
    _daemon_v 20.10.24+dfsg1 '' true
    _unit "/usr/sbin/dockerd -H fd:// --no-new-privileges=false"
    run _docker_check_no_new_privileges
    [ "$status" -ne 0 ]

    _unit "/usr/sbin/dockerd -H fd:// --no-new-privileges"
    run _docker_check_no_new_privileges
    [ "$status" -eq 0 ]

    # Like dockerd, the last occurrence wins.
    _unit "/usr/sbin/dockerd --no-new-privileges=true --no-new-privileges=0"
    run _docker_check_no_new_privileges
    [ "$status" -ne 0 ]
}

@test "no-new-privileges check: ExecStart as systemd merged it, not the unit's raw text" {
    # A drop-in reset ExecStart: `systemctl cat` still shows the old line with
    # the flag, but dockerd runs without it.
    _daemon_v 20.10.24+dfsg1 '' true
    _unit "/usr/sbin/dockerd -H fd://" "" \
        "ExecStart=/usr/sbin/dockerd -H fd:// --no-new-privileges"
    run _docker_check_no_new_privileges
    [ "$status" -ne 0 ]

    # The flag on a continuation line: systemd joins it, a grep of ExecStart= did not.
    _unit "/usr/sbin/dockerd -H fd:// --no-new-privileges" "" \
        $'ExecStart=/usr/sbin/dockerd -H fd:// \\\n    --no-new-privileges'
    run _docker_check_no_new_privileges
    [ "$status" -eq 0 ]
}

@test "no-new-privileges check: DOCKER_OPTS counts only where the unit expands it" {
    local env="$BATS_TEST_TMPDIR/default-docker"
    printf 'DOCKER_OPTS="--dns 9.9.9.9 --no-new-privileges"\n' > "$env"
    _daemon_v 20.10.24+dfsg1 '' true

    # Debian's docker.io: ExecStart carries $DOCKER_OPTS from /etc/default/docker.
    _unit '/usr/sbin/dockerd -H fd:// $DOCKER_OPTS' "$env"
    run _docker_check_no_new_privileges
    [ "$status" -eq 0 ]

    # docker-ce never reads the file, whatever it says.
    _unit "/usr/bin/dockerd -H fd://" "$env"
    run _docker_check_no_new_privileges
    [ "$status" -ne 0 ]
}

@test "ICC check: the default bridge's enable_icc is final" {
    _daemon_v 29.1.3 '[]' true
    printf '{"icc": false}\n' > "$DOCKER_DAEMON_JSON"
    run _docker_check_icc_disabled
    [ "$status" -ne 0 ]

    _daemon_v 29.1.3 '[]' false
    rm -f "$DOCKER_DAEMON_JSON"
    run _docker_check_icc_disabled
    [ "$status" -eq 0 ]
}

@test "ICC check: a daemon that does not say falls back to the configuration" {
    _vpssec_stub docker 1
    _unit "/usr/bin/dockerd -H fd:// --icc=false"
    run _docker_check_icc_disabled
    [ "$status" -eq 0 ]

    _unit "/usr/bin/dockerd -H fd://"
    printf '{"icc": false}\n' > "$DOCKER_DAEMON_JSON"
    run _docker_check_icc_disabled
    [ "$status" -eq 0 ]

    rm -f "$DOCKER_DAEMON_JSON"
    run _docker_check_icc_disabled
    [ "$status" -ne 0 ]
}

# ---- the fix's postcondition ----------------------------------------

_completed_fixes() {
    jq -r '.completed_fixes[]?.id // empty' \
        "$VPSSEC_STATE/ok.json" 2>/dev/null
}

@test "live-restore fix: applied by a reload, no restart and no restart prompt" {
    # live-restore is reloadable; restarting dockerd to apply it stops every
    # container, because the running daemon does not have live-restore yet.
    _daemon_picks_up_on reload
    confirm() { return 0; }
    confirm_critical() { echo "PROMPTED" >&2; return 1; }

    run execute_fix docker.enable_live_restore
    [ "$status" -eq 0 ]
    grep -q 'docker.enable_live_restore' <<<"$(_completed_fixes)"
    _vpssec_stub_called systemctl 'reload docker$'
    _vpssec_refute _vpssec_stub_called systemctl 'restart'
    [[ "$output" != *PROMPTED* ]]
}

@test "live-restore fix: a reload that fails fails the fix, the setting staged" {
    # The daemon already answering true isolates the fix's own word from the
    # engine's postcondition.
    _vpssec_stub systemctl 1
    _daemon_reports true

    run _docker_fix_enable_daemon_setting live-restore true
    [ "$status" -eq 1 ]
    [[ "$output" == *"$(i18n 'docker.reload_failed')"* ]]
    jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON"
}

@test "live-restore fix: a reload the daemon did not act on fails the fix" {
    # The daemon's answer is the postcondition, not the reload's exit status.
    _vpssec_stub systemctl 0
    _daemon_reports false
    confirm() { return 0; }

    run execute_fix docker.enable_live_restore
    [ "$status" -eq 1 ]
    grep -qF 'Fix verify failed: docker.enable_live_restore' "$VPSSEC_LOGS/vpssec.log"
    _vpssec_refute grep -q 'docker.enable_live_restore' <<<"$(_completed_fixes)"
}

@test "live-restore fix: the engine asks before applying it, as for any CONFIRM fix" {
    # It no longer prompts by itself, so it must not skip the engine's prompt.
    _daemon_picks_up_on reload
    confirm() { return 1; }

    run execute_fix docker.enable_live_restore
    [ "$status" -ne 0 ]
    [ ! -e "$DOCKER_DAEMON_JSON" ]
}

@test "no-new-privileges fix: accepting the restart succeeds once the daemon reports it" {
    _daemon_picks_up_on restart
    confirm_critical() { return 0; }

    run execute_fix docker.enable_no_new_privileges
    [ "$status" -eq 0 ]
    grep -q 'docker.enable_no_new_privileges' <<<"$(_completed_fixes)"
    _vpssec_stub_called systemctl 'restart docker$'
}

@test "no-new-privileges fix: declining the restart is a failure, the setting staged" {
    # Not loaded is not on: the daemon keeps creating containers without it.
    # An answered "no" (the flag set) after daemon.json is written still fails.
    _daemon_picks_up_on restart
    confirm_critical() { _VPSSEC_DECLINED=1; return 1; }

    run execute_fix docker.enable_no_new_privileges
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q 'docker.enable_no_new_privileges' <<<"$(_completed_fixes)"
    jq -e '.["no-new-privileges"] == true' "$DOCKER_DAEMON_JSON"
    _vpssec_refute _vpssec_stub_called systemctl 'restart'
}

@test "no-new-privileges fix: declining is a failure on an old daemon too" {
    # Engine 20.10 cannot report the setting, so the fix's own word decides.
    _daemon_picks_up_on restart 20.10.24+dfsg1
    confirm_critical() { _VPSSEC_DECLINED=1; return 1; }

    run execute_fix docker.enable_no_new_privileges
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q 'docker.enable_no_new_privileges' <<<"$(_completed_fixes)"
}

@test "no-new-privileges fix: the restart prompt says what a restart does here" {
    _daemon_picks_up_on restart
    confirm_critical() { printf 'PROMPT: %s\n' "$1"; return 1; }

    run _docker_fix_enable_daemon_setting no-new-privileges true
    [[ "$output" == *"PROMPT: $(i18n 'docker.confirm_restart')"* ]]
    [[ "$output" == *"every running container is stopped"* ]]

    # live-restore already on: containers keep running through the restart.
    rm -f "$DOCKER_DAEMON_JSON"
    touch "$BATS_TEST_TMPDIR/loaded"
    run _docker_fix_enable_daemon_setting no-new-privileges true
    [[ "$output" == *"PROMPT: $(i18n 'docker.confirm_restart_live')"* ]]
}

@test "daemon fix: a flag already on dockerd's command line is not repeated in daemon.json" {
    # dockerd refuses to start when one setting is both a flag and in
    # daemon.json, so writing it there would take Docker down at the restart.
    _unit "/usr/bin/dockerd -H fd:// --no-new-privileges=false"
    _daemon_reports false
    confirm_critical() { return 0; }

    run _docker_fix_enable_daemon_setting no-new-privileges true
    [ "$status" -eq 1 ]
    [[ "$output" == *"--no-new-privileges is already on dockerd's command line"* ]]
    [ ! -e "$DOCKER_DAEMON_JSON" ]
    _vpssec_refute _vpssec_stub_called systemctl 'restart'
}

@test "FIX_VERIFY: the declared docker predicates exist once the module is loaded" {
    [ "$(get_fix_verify docker.enable_live_restore)" = "_docker_check_live_restore" ]
    [ "$(get_fix_verify docker.enable_no_new_privileges)" = "_docker_check_no_new_privileges" ]
    declare -f _docker_check_live_restore >/dev/null
    declare -f _docker_check_no_new_privileges >/dev/null
}

# ---- the writer itself ----------------------------------------------

@test "daemon.json: a malformed existing file is refused, not clobbered" {
    _daemon_reports true
    confirm_critical() { return 0; }
    printf 'this is not json' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true
    [ "$status" -eq 1 ]
    [ "$(cat "$DOCKER_DAEMON_JSON")" = "this is not json" ]
}

@test "daemon.json: existing keys are merged, not replaced" {
    _daemon_picks_up_on reload
    confirm_critical() { return 0; }
    printf '{"log-driver": "journald"}\n' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true
    [ "$status" -eq 0 ]
    jq -e '.["log-driver"] == "journald"' "$DOCKER_DAEMON_JSON"
    jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON"
}

@test "daemon.json: an existing file is backed up before being edited" {
    _daemon_picks_up_on reload
    confirm_critical() { return 0; }
    printf '{"log-driver": "journald"}\n' > "$DOCKER_DAEMON_JSON"
    _vpssec_begin_backup_session

    run _docker_fix_enable_daemon_setting "live-restore" true
    [ "$status" -eq 0 ]
    [ -f "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}" ]
    jq -e '.["log-driver"] == "journald"' "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}"
    jq -e '.["live-restore"] == null' "${VPSSEC_BACKUP_SESSION}${DOCKER_DAEMON_JSON}"
}

@test "daemon.json: no staging file is left beside it on the refusal path" {
    _daemon_reports true
    confirm_critical() { return 0; }
    printf 'not json' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true
    [ "$(ls -A "$(dirname "$DOCKER_DAEMON_JSON")")" = "daemon.json" ]
}

@test "daemon.json: a merge that fails leaves no staging file and no half-written file" {
    # The refusal path above never reaches the merge, so it cannot cover the
    # cleanup there. `[]` separates them: valid JSON passes the refusal guard,
    # but `.["live-restore"] = true` cannot index an array, so the merge fails.
    _daemon_reports false
    confirm_critical() { return 0; }
    printf '[]\n' > "$DOCKER_DAEMON_JSON"

    run _docker_fix_enable_daemon_setting "live-restore" true

    [ "$status" -ne 0 ]
    [ "$(ls -A "$(dirname "$DOCKER_DAEMON_JSON")")" = "daemon.json" ]
    # The operator's file is exactly as they left it.
    [ "$(cat "$DOCKER_DAEMON_JSON")" = "[]" ]
}

@test "daemon.json: a 0600 file keeps its mode and owner through the merge" {
    # daemon.json can hold registry or proxy credentials; an operator who
    # locked it down must not find it world-readable after a fix.
    _daemon_picks_up_on reload
    confirm_critical() { return 0; }
    printf '{"proxies": {"http-proxy": "http://u:p@proxy.invalid:3128"}}\n' > "$DOCKER_DAEMON_JSON"
    chmod 600 "$DOCKER_DAEMON_JSON"
    local owner
    owner=$(stat -c '%u:%g' "$DOCKER_DAEMON_JSON")
    if (( EUID == 0 )); then
        chown 65534:65534 "$DOCKER_DAEMON_JSON"
        owner="65534:65534"
    fi

    run _docker_fix_enable_daemon_setting "live-restore" true
    [ "$status" -eq 0 ]
    [ "$(stat -c '%a' "$DOCKER_DAEMON_JSON")" = "600" ]
    [ "$(stat -c '%u:%g' "$DOCKER_DAEMON_JSON")" = "$owner" ]
    jq -e '.proxies["http-proxy"] and .["live-restore"] == true' "$DOCKER_DAEMON_JSON"
}

@test "daemon.json: a refused file is not snapshotted into the backup session" {
    # What the refusal guard is FOR: it sits ahead of backup_file, so a file the
    # fix declines to touch leaves no trace in the rollback session. Without it
    # the session carries an entry for a file that was never modified.
    _daemon_reports false
    confirm_critical() { return 0; }
    printf 'not json' > "$DOCKER_DAEMON_JSON"
    _vpssec_begin_backup_session

    run _docker_fix_enable_daemon_setting "live-restore" true

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
