#!/usr/bin/env bash
# Mutation testing harness for vpssec.
#
# For each .case file under tests/mutation/cases/, the driver:
#   1. sources the case to get mutate() / restore() / expectations
#   2. runs mutate() to plant a known defect
#   3. runs `vpssec audit --include=<module> --json-only --yes`
#   4. asserts the expected check_id appears with the expected status
#   5. when the case names FIX_ID, runs `vpssec guide --fix=<id> --yes`
#      through the real CLI, re-audits and asserts EXPECT_FIXED_ID has
#      EXPECT_FIXED_STATUS ("absent" = the id must not appear at all),
#      and that guide itself exited 0 on the host it converged — and, when
#      the case defines postfix(), that it returns 0 (what the service makes
#      of the change, which the audit reads from files). A risky
#      fix asks on /dev/tty and ignores --yes: the case lists what to type
#      in FIX_TTY_ANSWERS, one line per prompt, fed through a pseudo-terminal.
#      The answers are typed ahead, so each yes/no line must meet its own
#      `[yes/NO]` prompt in the transcript — otherwise a fix that never asked
#      would pass. A case with EXPECT_DECLINED=1 answers no: guide must exit 0
#      (a declined fix is a skip), leave no session and no undo command, and
#      EXPECT_FIXED_ID must keep EXPECT_FIXED_STATUS; there is no stage 3
#   6. then runs `vpssec rollback <that session>` (answering its
#      confirmation on a pseudo-terminal), re-audits and asserts
#      EXPECT_ROLLBACK_ID / EXPECT_ROLLBACK_STATUS and the rollback's
#      exit code EXPECT_ROLLBACK_RC — what rollback really undoes is the
#      case's claim, not the driver's assumption — and, when the case
#      defines postrollback(), that it returns 0 (e.g. `nginx -t`: the
#      audit cannot see a config the service would refuse to load).
#      A case with ROLLBACK_BY="undo" names a fix that backs up no file:
#      it must leave no session, and the undo command it logged is run
#      instead of the rollback, with the same assertions on the result
#   7. runs restore() to revert the planted defect, also when mutate() or
#      the audit failed; a restore that fails errors the run, since every
#      later case would start from a dirty host
#
# Every audit must exit 0 with meta.complete true, or 3 with it false; any
# other pairing is the exit-code contract broken, and the case does not pass.
#
# A case whose precheck() is false is skipped (failed under --strict), and
# the condition it stopped at is printed. A case with MANUAL_ONLY="<why>"
# needs what the container cannot provide (a docker daemon): it is listed as
# MANUAL and not run unless --manual is given. A filter that matches no case
# at all, MANUAL ones included, fails the run.
#
# IMPORTANT: run only on a disposable VM or container. Restore is
# best-effort — if a case crashes between mutate and restore, the
# system can be left in a degraded state. Take a VM snapshot first.
#
# Usage:
#   sudo bash tests/mutation/run.sh                 # all cases
#   sudo bash tests/mutation/run.sh ssh             # cases whose filename contains "ssh"
#   sudo bash tests/mutation/run.sh -k filesystem   # synonym for filtering
#   sudo bash tests/mutation/run.sh --manual        # also run the MANUAL_ONLY cases
#   sudo bash tests/mutation/run.sh --strict        # a skipped case fails the run
#   bash tests/mutation/run-in-container.sh         # --strict, inside a throwaway systemd container

set -uo pipefail   # NOT -e: we want to keep going past individual failures

VPSSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VPSSEC_BIN="${VPSSEC_ROOT}/vpssec"
CASES_DIR="${VPSSEC_ROOT}/tests/mutation/cases"
REPORT="${VPSSEC_ROOT}/reports/summary.json"
BACKUPS_DIR="${VPSSEC_ROOT}/backups"
STAGE_LOG="${VPSSEC_ROOT}/logs/mutation-stage.log"

PATTERN=""
STRICT=0
RUN_MANUAL=0
while (( $# > 0 )); do
    case "$1" in
        -k|--filter) shift; PATTERN="${1:-}";;
        --strict) STRICT=1;;
        --manual) RUN_MANUAL=1;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) PATTERN="$1";;
    esac
    shift
done

# ---- preflight ---------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -x "$VPSSEC_BIN" ]] || { echo "vpssec not executable at $VPSSEC_BIN" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not installed" >&2; exit 1; }
mkdir -p "${VPSSEC_ROOT}/logs"

# ---- counters / results ------------------------------------------------------
declare -i total=0 passed=0 failed=0 errored=0 skipped=0 manual=0
declare -a results=()

color() {
    local c="$1"; shift
    case "$c" in
        green)  printf '\033[0;32m%s\033[0m' "$*";;
        red)    printf '\033[0;31m%s\033[0m' "$*";;
        yellow) printf '\033[0;33m%s\033[0m' "$*";;
        dim)    printf '\033[2m%s\033[0m' "$*";;
        *)      printf '%s' "$*";;
    esac
}

# ---- audit + assertion helpers -----------------------------------------------

# Fresh audit of one module into reports/summary.json. Returns 1, with the
# reason in AUDIT_WHY, when no report was written, the exit code disagrees with
# meta.complete, or the module did not complete: none of those is a verdict.
run_audit() {
    local module="$1" rc=0 complete
    AUDIT_WHY=""
    rm -f "$REPORT"
    "$VPSSEC_BIN" audit --include="$module" --json-only --yes --lang=en_US \
        >/dev/null 2>&1 || rc=$?
    if [[ ! -s "$REPORT" ]]; then
        AUDIT_WHY="no summary.json (audit rc=$rc)"
        return 1
    fi
    complete=$(jq -r '.meta.complete' "$REPORT" 2>/dev/null)
    if ! [[ ( $rc -eq 0 && "$complete" == true ) || ( $rc -eq 3 && "$complete" == false ) ]]; then
        AUDIT_WHY="audit exited $rc with meta.complete=$complete"
        return 1
    fi
    if ! jq -e --arg m "$module" '(.meta.modules_failed // []) | index($m) | not' "$REPORT" >/dev/null; then
        AUDIT_WHY="$module did not complete"
        return 1
    fi
}

# Confirmation prompts in the stage transcript against the yes/no lines typed
# for them. Prints the mismatch and returns 1 when they differ.
prompts_match_answers() {
    local answers="$1" what="$2" want got
    want=$(grep -ciE '^(yes|no)$' <<<"$answers")
    got=$(grep -o '\[yes/NO\] >' "$STAGE_LOG" 2>/dev/null | wc -l)
    (( got == want )) && return 0
    echo "  $(color red '[FAIL]') $what showed $got [yes/NO] prompt(s) for $want yes/no answer(s): the answers were typed ahead, not asked for"
    return 1
}

# "id status" as the report shows it, or empty when the id is not there.
report_check() {
    jq -r --arg id "$1" '.checks[] | select(.id == $id) | "\(.status)/\(.severity)"' \
        "$REPORT" 2>/dev/null | head -1
}

# Does the report carry $1 with status $2? "absent" means it must not appear.
report_has() {
    local id="$1" want="$2" got
    got=$(report_check "$id")
    if [[ "$want" == "absent" ]]; then
        [[ -z "$got" ]]
    else
        [[ "${got%%/*}" == "$want" ]]
    fi
}

# ---- helpers for cases that install packages ---------------------------------
# Call host_snapshot <paths it may create> in mutate() before installing, and
# host_restore <units> in restore(): every package installed since is purged,
# or its dependencies stay behind and later cases no longer start from absent.

host_snapshot() {
    local p
    _SNAP_PKGS=$(dpkg-query -W -f '${Package}\n' 2>/dev/null | sort)
    _SNAP_FW_EMPTY=0
    if ! command -v nft >/dev/null 2>&1 || [[ -z "$(nft list ruleset 2>/dev/null)" ]]; then
        _SNAP_FW_EMPTY=1
    fi
    _SNAP_ABSENT=()
    for p in "$@"; do [[ -e "$p" ]] || _SNAP_ABSENT+=("$p"); done
    _SNAP_USERS=$(getent passwd | awk -F: '$3 < 1000 {print $1}' | sort)
    _SNAP_GROUPS=$(getent group | awk -F: '$3 < 1000 {print $1}' | sort)
}

# Undo to the snapshot: stop and disable $@, empty the firewall if it was empty,
# purge every package installed since (and the system accounts they added),
# delete the paths that were absent. Accounts from uid 1000 up are the case's.
host_restore() {
    local u p
    local -a new=()
    [[ -n "${_SNAP_PKGS:-}" ]] || return 1
    for u in "$@"; do systemctl disable --now "$u" >/dev/null 2>&1; done
    # Before the purge, which may take the tool itself away. ufw writes through
    # iptables-nft, so its rules live in the nft ruleset too.
    if (( _SNAP_FW_EMPTY )); then
        if command -v nft >/dev/null 2>&1; then
            nft flush ruleset >/dev/null 2>&1
        else
            for p in iptables ip6tables; do
                command -v "$p" >/dev/null 2>&1 || continue
                for u in filter nat mangle raw; do "$p" -t "$u" -F; "$p" -t "$u" -X; done >/dev/null 2>&1
                for u in INPUT FORWARD OUTPUT; do "$p" -P "$u" ACCEPT; done >/dev/null 2>&1
            done
        fi
    fi
    mapfile -t new < <(comm -13 <(printf '%s\n' "$_SNAP_PKGS") \
                                <(dpkg-query -W -f '${Package}\n' 2>/dev/null | sort))
    if (( ${#new[@]} > 0 )); then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "${new[@]}" >/dev/null 2>&1
    fi
    for p in "${_SNAP_ABSENT[@]}"; do rm -rf -- "$p"; done
    for u in $(comm -13 <(printf '%s\n' "$_SNAP_USERS") \
                        <(getent passwd | awk -F: '$3 < 1000 {print $1}' | sort)); do
        userdel "$u" >/dev/null 2>&1
    done
    for u in $(comm -13 <(printf '%s\n' "$_SNAP_GROUPS") \
                        <(getent group | awk -F: '$3 < 1000 {print $1}' | sort)); do
        groupdel "$u" >/dev/null 2>&1
    done
    systemctl daemon-reload >/dev/null 2>&1
    for u in "$@"; do systemctl reset-failed "$u" >/dev/null 2>&1; done
    return 0
}

# ---- single case runner ------------------------------------------------------
run_case() {
    local case_file="$1"
    local case_name; case_name="$(basename "$case_file" .case)"

    if [[ -n "$PATTERN" && "$case_name" != *"$PATTERN"* ]]; then
        return 0
    fi

    total+=1

    # Reset per-case state — case files set these, but a missing
    # field in case N must not leak from case N-1.
    unset -f mutate restore precheck postfix postrollback 2>/dev/null || true
    unset TEST_DESC EXPECT_ID EXPECT_STATUS EXPECT_SEVERITY EXPECT_DESC_CONTAINS \
          MODULE DESTRUCTIVE FIX_ID EXPECT_FIXED_ID EXPECT_FIXED_STATUS \
          EXPECT_ROLLBACK_ID EXPECT_ROLLBACK_STATUS EXPECT_ROLLBACK_RC \
          FIX_TTY_ANSWERS ROLLBACK_BY EXPECT_DECLINED MANUAL_ONLY \
          _SNAP_PKGS _SNAP_FW_EMPTY _SNAP_ABSENT _SNAP_USERS _SNAP_GROUPS 2>/dev/null || true
    # A command an earlier case ran and then uninstalled stays hashed in this
    # shell, and `command -v` in the next precheck would still find it.
    hash -r

    # shellcheck source=/dev/null
    if ! source "$case_file"; then
        echo "$(color red '[ERROR]') $case_name: source failed"
        results+=("ERROR | $case_name | failed to source")
        errored+=1
        return
    fi

    : "${TEST_DESC:?$case_name missing TEST_DESC}"
    : "${EXPECT_ID:?$case_name missing EXPECT_ID}"
    : "${EXPECT_STATUS:?$case_name missing EXPECT_STATUS}"
    : "${MODULE:?$case_name missing MODULE}"
    if [[ -n "${EXPECT_DECLINED:-}" ]]; then
        : "${FIX_ID:?$case_name has EXPECT_DECLINED but no FIX_ID}"
        : "${FIX_TTY_ANSWERS:?$case_name has EXPECT_DECLINED but no FIX_TTY_ANSWERS}"
        : "${EXPECT_FIXED_ID:?$case_name has EXPECT_DECLINED but no EXPECT_FIXED_ID}"
        : "${EXPECT_FIXED_STATUS:?$case_name has EXPECT_DECLINED but no EXPECT_FIXED_STATUS}"
    elif [[ -n "${FIX_ID:-}" ]]; then
        : "${EXPECT_FIXED_ID:?$case_name has FIX_ID but no EXPECT_FIXED_ID}"
        : "${EXPECT_ROLLBACK_ID:?$case_name has FIX_ID but no EXPECT_ROLLBACK_ID}"
        : "${EXPECT_ROLLBACK_STATUS:?$case_name has FIX_ID but no EXPECT_ROLLBACK_STATUS}"
        EXPECT_FIXED_STATUS="${EXPECT_FIXED_STATUS:-passed}"
        EXPECT_ROLLBACK_RC="${EXPECT_ROLLBACK_RC:-0}"
    fi

    echo ""
    echo "$(color dim '>>>') $case_name — $TEST_DESC"

    if [[ -n "${MANUAL_ONLY:-}" ]] && (( ! RUN_MANUAL )); then
        echo "  $(color yellow '[MANUAL]') $MANUAL_ONLY"
        results+=("MANUAL| $case_name | $MANUAL_ONLY")
        manual+=1
        return
    fi

    # Optional applicability check (e.g. "skip if /etc/shadow- doesn't exist").
    # Under --strict only a MANUAL_ONLY case may skip: the image is pinned, so
    # any other skip means it drifted and the case silently stopped running.
    if declare -f precheck >/dev/null; then
        if ! precheck; then
            local stopped_at
            stopped_at=$( { set -x; precheck; } 2>&1 >/dev/null | grep '^+' | tail -n 2 \
                | sed 's/^+* //' | paste -sd ';' - )
            if (( STRICT )) && [[ -z "${MANUAL_ONLY:-}" ]]; then
                echo "  $(color red '[FAIL]') precheck false under --strict, at: $stopped_at"
                results+=("FAIL  | $case_name | precheck false under --strict: $stopped_at")
                failed+=1
            else
                echo "  $(color yellow '[SKIP]') precheck false, at: $stopped_at"
                results+=("SKIP  | $case_name | precheck false: $stopped_at")
                skipped+=1
            fi
            return
        fi
    fi

    if ! mutate; then
        echo "  $(color red '[ERROR]') mutate() returned non-zero"
        results+=("ERROR | $case_name | mutate failed")
        errored+=1
        restore_case "$case_name"
        return
    fi

    # Run audit. --yes bypasses the "Save report?" prompt; --json-only
    # silences the TUI/text output. We still rely on reports/summary.json
    # being written to disk.
    if ! run_audit "$MODULE"; then
        echo "  $(color red '[ERROR]') audit gave no verdict: $AUDIT_WHY"
        results+=("ERROR | $case_name | $AUDIT_WHY")
        errored+=1
        restore_case "$case_name"
        return
    fi

    local hit_severity
    hit_severity=$(jq -r --arg id "$EXPECT_ID" --arg s "$EXPECT_STATUS" \
        '.checks[] | select(.id == $id and .status == $s) | .severity' \
        "$REPORT" 2>/dev/null | head -1)

    local detected=0 warned=0
    if [[ -n "$hit_severity" ]]; then
        # Optional substring check on desc: an aggregate id such as
        # kernel.kernel_params_weak lumps several values together, so a case
        # would otherwise pass on a value some other setting already failed.
        local desc_ok=1
        if [[ -n "${EXPECT_DESC_CONTAINS:-}" ]]; then
            local hit_desc
            hit_desc=$(jq -r --arg id "$EXPECT_ID" --arg s "$EXPECT_STATUS" \
                '.checks[] | select(.id == $id and .status == $s) | .desc' \
                "$REPORT" 2>/dev/null | head -1)
            if [[ "$hit_desc" != *"$EXPECT_DESC_CONTAINS"* ]]; then
                desc_ok=0
                echo "  $(color red '[FAIL]') desc missing expected substring '$EXPECT_DESC_CONTAINS'"
                echo "         got: ${hit_desc:0:200}"
                results+=("FAIL  | $case_name | desc lacked '$EXPECT_DESC_CONTAINS'")
                failed+=1
            fi
        fi

        if (( desc_ok == 1 )); then
            detected=1
            if [[ -n "${EXPECT_SEVERITY:-}" && "$hit_severity" != "$EXPECT_SEVERITY" ]]; then
                echo "  $(color yellow '[WARN]') detected but severity=$hit_severity (expected $EXPECT_SEVERITY)"
                results+=("WARN  | $case_name | severity drift: got $hit_severity, want $EXPECT_SEVERITY")
                warned=1
            else
                echo "  $(color green '[PASS]') detected $EXPECT_ID @ $hit_severity"
            fi
        fi
    else
        echo "  $(color red '[FAIL]') $EXPECT_ID with status=$EXPECT_STATUS not in summary"
        # Show what DID appear for that check_id, if anything — eases debug
        local actual
        actual=$(report_check "$EXPECT_ID")
        [[ -n "$actual" ]] && echo "         (it appeared as: $actual)"
        results+=("FAIL  | $case_name | $EXPECT_ID expected $EXPECT_STATUS, not found")
        failed+=1
    fi

    # Stages 2 and 3 run only on a detected finding: fixing what the audit
    # did not report would test the fix against the wrong precondition.
    local converged=1
    if (( detected == 1 )) && [[ -n "${FIX_ID:-}" ]]; then
        run_fix_and_rollback "$case_name" || converged=0
    fi

    # Restored before the verdict: a case that leaves the host dirty is an
    # error, not a pass as well.
    local restored=1
    restore_case "$case_name" || restored=0

    # Severity drift is still a detection (the WARN line above stands in for
    # the PASS line); only a failed stage 2 or 3 turns the case red.
    if (( detected == 1 )); then
        if (( converged == 0 )); then
            failed+=1
        elif (( restored == 1 )); then
            local stages="${FIX_ID:+ → $FIX_ID → rollback}"
            [[ -n "${EXPECT_DECLINED:-}" ]] && stages=" → $FIX_ID declined"
            (( warned == 0 )) && results+=("PASS  | $case_name | $EXPECT_ID @ $hit_severity$stages")
            passed+=1
        fi
    fi
}

# The case's restore(); returns 1 when it failed. That is an error, not a warning:
# a half-planted defect left behind changes the verdict of every case after it.
restore_case() {
    restore && return 0
    echo "  $(color red '[ERROR]') restore() failed — later cases run on a dirty host"
    results+=("ERROR | $1 | restore failed (manual cleanup needed)")
    errored+=1
    return 1
}

# Stage 2 (fix → re-audit) and stage 3 (rollback → re-audit); returns 1 on the
# first failed assertion. The audit's verdict decides convergence, and guide's
# exit status must agree with it: a failure on a converged host is a FIX_VERIFY
# predicate stricter than the check it stands in for.
run_fix_and_rollback() {
    local case_name="$1"

    local before_sessions before_log_lines
    before_sessions=$(ls -1 "$BACKUPS_DIR" 2>/dev/null | sort)
    before_log_lines=$(wc -l < "${VPSSEC_ROOT}/logs/vpssec.log" 2>/dev/null || echo 0)

    local guide_rc=0
    local guide_cmd=("$VPSSEC_BIN" guide --include="$MODULE" --fix="$FIX_ID" --yes --json-only --lang=en_US)
    if [[ -n "${FIX_TTY_ANSWERS:-}" ]]; then
        printf '%s\n' "$FIX_TTY_ANSWERS" | script -qefc "${guide_cmd[*]}" /dev/null \
            >"$STAGE_LOG" 2>&1 || guide_rc=$?
    else
        "${guide_cmd[@]}" >"$STAGE_LOG" 2>&1 || guide_rc=$?
    fi

    if [[ -n "${FIX_TTY_ANSWERS:-}" ]] && ! prompts_match_answers "$FIX_TTY_ANSWERS" "guide --fix=$FIX_ID"; then
        results+=("FAIL  | $case_name | guide prompts do not match FIX_TTY_ANSWERS")
        return 1
    fi

    local session
    session=$(comm -13 <(printf '%s\n' "$before_sessions") \
                       <(ls -1 "$BACKUPS_DIR" 2>/dev/null | sort) | tail -1)

    if [[ -n "${EXPECT_DECLINED:-}" ]]; then
        declined_left_nothing "$case_name" "$guide_rc" "$session" "$before_log_lines"
        return
    fi

    if ! run_audit "$MODULE"; then
        echo "  $(color red '[FAIL]') audit gave no verdict after guide --fix=$FIX_ID (guide rc=$guide_rc): $AUDIT_WHY"
        results+=("FAIL  | $case_name | after fix: $AUDIT_WHY")
        return 1
    fi
    if report_has "$EXPECT_FIXED_ID" "$EXPECT_FIXED_STATUS"; then
        echo "  $(color green '[PASS]') after $FIX_ID: $EXPECT_FIXED_ID is $EXPECT_FIXED_STATUS (guide rc=$guide_rc)"
    else
        echo "  $(color red '[FAIL]') after $FIX_ID: $EXPECT_FIXED_ID expected $EXPECT_FIXED_STATUS, got '$(report_check "$EXPECT_FIXED_ID")' (guide rc=$guide_rc)"
        tail -n 15 "$STAGE_LOG" | sed 's/^/         | /'
        results+=("FAIL  | $case_name | $FIX_ID did not converge: $EXPECT_FIXED_ID not $EXPECT_FIXED_STATUS")
        return 1
    fi
    if (( guide_rc != 0 )); then
        echo "  $(color red '[FAIL]') $EXPECT_FIXED_ID converged, but guide --fix=$FIX_ID exited $guide_rc"
        tail -n 15 "$STAGE_LOG" | sed 's/^/         | /'
        results+=("FAIL  | $case_name | converged, yet guide rc $guide_rc")
        return 1
    fi
    if declare -f postfix >/dev/null && ! postfix; then
        echo "  $(color red '[FAIL]') after $FIX_ID: the case's postfix() check failed"
        results+=("FAIL  | $case_name | postfix check failed")
        return 1
    fi

    local rollback_rc=0
    if [[ "${ROLLBACK_BY:-}" == "undo" ]]; then
        if [[ -n "$session" ]]; then
            echo "  $(color red '[FAIL]') a fix that backs up no file left session $session"
            results+=("FAIL  | $case_name | unexpected backup session $session")
            return 1
        fi
        # The command this run's fix logged, never one from an earlier case.
        local undo
        undo=$(tail -n +"$(( before_log_lines + 1 ))" "${VPSSEC_ROOT}/logs/vpssec.log" 2>/dev/null \
            | sed -n "s/.*Undo for ${FIX_ID//./\\.}: //p" | tail -1)
        if [[ -z "$undo" ]]; then
            echo "  $(color red '[FAIL]') $FIX_ID logged no undo command"
            results+=("FAIL  | $case_name | no undo command logged")
            return 1
        fi
        # Written for a person at a terminal (apt asks before removing): answer
        # yes as that person would. Not a pipe, so yes's SIGPIPE is no status.
        DEBIAN_FRONTEND=noninteractive bash -c "$undo" >"$STAGE_LOG" 2>&1 < <(yes) \
            || rollback_rc=$?
        session="undo: $undo"
    else
        if [[ -z "$session" ]]; then
            echo "  $(color red '[FAIL]') guide left no backup session to roll back"
            results+=("FAIL  | $case_name | no backup session after fix")
            return 1
        fi
        # rollback confirms through confirm_critical, which reads /dev/tty and
        # ignores --yes on purpose; a pseudo-terminal answers it the way an
        # operator would, with no menu in between to consume the answer.
        printf 'yes\n' | script -qefc "$VPSSEC_BIN rollback $session --lang=en_US" /dev/null \
            >"$STAGE_LOG" 2>&1 || rollback_rc=$?
        if ! prompts_match_answers yes "rollback $session"; then
            results+=("FAIL  | $case_name | rollback did not ask before restoring")
            return 1
        fi
    fi
    if (( rollback_rc != EXPECT_ROLLBACK_RC )); then
        echo "  $(color red '[FAIL]') rollback ($session) exited $rollback_rc, expected $EXPECT_ROLLBACK_RC"
        tail -n 10 "$STAGE_LOG" | sed 's/^/         | /'
        results+=("FAIL  | $case_name | rollback rc $rollback_rc, want $EXPECT_ROLLBACK_RC")
        return 1
    fi

    if ! run_audit "$MODULE"; then
        echo "  $(color red '[FAIL]') audit gave no verdict after rollback: $AUDIT_WHY"
        results+=("FAIL  | $case_name | after rollback: $AUDIT_WHY")
        return 1
    fi
    if report_has "$EXPECT_ROLLBACK_ID" "$EXPECT_ROLLBACK_STATUS"; then
        echo "  $(color green '[PASS]') after rollback (rc=$rollback_rc): $EXPECT_ROLLBACK_ID is $EXPECT_ROLLBACK_STATUS"
    else
        echo "  $(color red '[FAIL]') after rollback: $EXPECT_ROLLBACK_ID expected $EXPECT_ROLLBACK_STATUS, got '$(report_check "$EXPECT_ROLLBACK_ID")'"
        results+=("FAIL  | $case_name | rollback left $EXPECT_ROLLBACK_ID not $EXPECT_ROLLBACK_STATUS")
        return 1
    fi
    if declare -f postrollback >/dev/null && ! postrollback; then
        echo "  $(color red '[FAIL]') after rollback: the case's postrollback() check failed"
        results+=("FAIL  | $case_name | postrollback check failed")
        return 1
    fi
    return 0
}

# Stage 2 for an EXPECT_DECLINED case: a no at the prompt is a skip (guide 0)
# that changed nothing — no session, no undo command, the finding unchanged.
declined_left_nothing() {
    local case_name="$1" guide_rc="$2" session="$3" before_log_lines="$4" undo
    if (( guide_rc != 0 )); then
        echo "  $(color red '[FAIL]') declined $FIX_ID, yet guide exited $guide_rc (a declined fix is a skip)"
        tail -n 15 "$STAGE_LOG" | sed 's/^/         | /'
        results+=("FAIL  | $case_name | declined, yet guide rc $guide_rc")
        return 1
    fi
    if [[ -n "$session" ]]; then
        echo "  $(color red '[FAIL]') declined $FIX_ID, yet it left backup session $session"
        results+=("FAIL  | $case_name | declined, yet session $session")
        return 1
    fi
    undo=$(tail -n +"$(( before_log_lines + 1 ))" "${VPSSEC_ROOT}/logs/vpssec.log" 2>/dev/null \
        | sed -n "s/.*Undo for ${FIX_ID//./\\.}: //p" | tail -1)
    if [[ -n "$undo" ]]; then
        echo "  $(color red '[FAIL]') declined $FIX_ID, yet it logged an undo command: $undo"
        results+=("FAIL  | $case_name | declined, yet undo logged")
        return 1
    fi
    if ! run_audit "$MODULE"; then
        echo "  $(color red '[FAIL]') audit gave no verdict after declining $FIX_ID: $AUDIT_WHY"
        results+=("FAIL  | $case_name | after decline: $AUDIT_WHY")
        return 1
    fi
    if ! report_has "$EXPECT_FIXED_ID" "$EXPECT_FIXED_STATUS"; then
        echo "  $(color red '[FAIL]') declined $FIX_ID, yet $EXPECT_FIXED_ID is '$(report_check "$EXPECT_FIXED_ID")', not $EXPECT_FIXED_STATUS"
        results+=("FAIL  | $case_name | declined, yet $EXPECT_FIXED_ID not $EXPECT_FIXED_STATUS")
        return 1
    fi
    if declare -f postfix >/dev/null && ! postfix; then
        echo "  $(color red '[FAIL]') after declining $FIX_ID: the case's postfix() check failed"
        results+=("FAIL  | $case_name | postfix check failed")
        return 1
    fi
    echo "  $(color green '[PASS]') declined $FIX_ID: guide rc 0, nothing changed, $EXPECT_FIXED_ID still $EXPECT_FIXED_STATUS"
}

# ---- main --------------------------------------------------------------------
echo "vpssec mutation test harness"
echo "  vpssec:    $VPSSEC_BIN"
echo "  cases:     $CASES_DIR"
echo "  filter:    ${PATTERN:-<all>}"

shopt -s nullglob
for case_file in "$CASES_DIR"/*.case; do
    run_case "$case_file"
done
shopt -u nullglob

echo ""
echo "=== Summary ==="
if (( ${#results[@]} > 0 )); then
    printf '%s\n' "${results[@]}"
fi
echo ""
echo "Total: $total  Passed: $(color green "$passed")  Failed: $(color red "$failed")  Errored: $(color red "$errored")  Skipped: $(color yellow "$skipped")  Manual: $manual"

# A mistyped filter runs nothing; that must not read as a clean run.
if (( total == 0 )); then
    echo "No case matched '${PATTERN:-<all>}' in $CASES_DIR"
    exit 1
fi

# Non-zero exit if anything failed or errored — for CI
(( failed == 0 && errored == 0 ))
