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
#      EXPECT_FIXED_STATUS ("absent" = the id must not appear at all)
#   6. then runs `vpssec rollback <that session>` (answering its
#      confirmation on a pseudo-terminal), re-audits and asserts
#      EXPECT_ROLLBACK_ID / EXPECT_ROLLBACK_STATUS and the rollback's
#      exit code EXPECT_ROLLBACK_RC — what rollback really undoes is the
#      case's claim, not the driver's assumption
#   7. runs restore() to revert the planted defect
#
# IMPORTANT: run only on a disposable VM or container. Restore is
# best-effort — if a case crashes between mutate and restore, the
# system can be left in a degraded state. Take a VM snapshot first.
#
# Usage:
#   sudo bash tests/mutation/run.sh                 # all cases
#   sudo bash tests/mutation/run.sh ssh             # cases whose filename contains "ssh"
#   sudo bash tests/mutation/run.sh -k filesystem   # synonym for filtering
#   bash tests/mutation/run-in-container.sh         # the same, inside a throwaway systemd container

set -uo pipefail   # NOT -e: we want to keep going past individual failures

VPSSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VPSSEC_BIN="${VPSSEC_ROOT}/vpssec"
CASES_DIR="${VPSSEC_ROOT}/tests/mutation/cases"
REPORT="${VPSSEC_ROOT}/reports/summary.json"
BACKUPS_DIR="${VPSSEC_ROOT}/backups"
STAGE_LOG="${VPSSEC_ROOT}/logs/mutation-stage.log"

PATTERN=""
for arg in "$@"; do
    case "$arg" in
        -k|--filter) shift; PATTERN="${1:-}";;
        -h|--help)
            sed -n 's/^# \?//;1,/^$/p' "$0"
            exit 0
            ;;
        *) PATTERN="$arg";;
    esac
done

# ---- preflight ---------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -x "$VPSSEC_BIN" ]] || { echo "vpssec not executable at $VPSSEC_BIN" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not installed" >&2; exit 1; }
mkdir -p "${VPSSEC_ROOT}/logs"

# ---- counters / results ------------------------------------------------------
declare -i total=0 passed=0 failed=0 errored=0 skipped=0
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

# Fresh audit of one module into reports/summary.json. Returns 1 when no report
# was written or the module did not complete: a check that is "absent" from an
# audit that never ran the module is no verdict, so every caller fails on it.
run_audit() {
    local module="$1"
    rm -f "$REPORT"
    "$VPSSEC_BIN" audit --include="$module" --json-only --yes --lang=en_US \
        >/dev/null 2>&1 || true
    [[ -s "$REPORT" ]] || return 1
    jq -e --arg m "$module" '(.meta.modules_failed // []) | index($m) | not' "$REPORT" >/dev/null
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
    unset -f mutate restore precheck 2>/dev/null || true
    unset TEST_DESC EXPECT_ID EXPECT_STATUS EXPECT_SEVERITY EXPECT_DESC_CONTAINS \
          MODULE DESTRUCTIVE FIX_ID EXPECT_FIXED_ID EXPECT_FIXED_STATUS \
          EXPECT_ROLLBACK_ID EXPECT_ROLLBACK_STATUS EXPECT_ROLLBACK_RC 2>/dev/null || true

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
    if [[ -n "${FIX_ID:-}" ]]; then
        : "${EXPECT_FIXED_ID:?$case_name has FIX_ID but no EXPECT_FIXED_ID}"
        : "${EXPECT_ROLLBACK_ID:?$case_name has FIX_ID but no EXPECT_ROLLBACK_ID}"
        : "${EXPECT_ROLLBACK_STATUS:?$case_name has FIX_ID but no EXPECT_ROLLBACK_STATUS}"
        EXPECT_FIXED_STATUS="${EXPECT_FIXED_STATUS:-passed}"
        EXPECT_ROLLBACK_RC="${EXPECT_ROLLBACK_RC:-0}"
    fi

    echo ""
    echo "$(color dim '>>>') $case_name — $TEST_DESC"

    # Optional applicability check (e.g. "skip if /etc/shadow- doesn't exist")
    if declare -f precheck >/dev/null; then
        if ! precheck; then
            echo "  $(color yellow '[SKIP]') precheck reported case is not applicable"
            results+=("SKIP  | $case_name | precheck false")
            skipped+=1
            return
        fi
    fi

    if ! mutate; then
        echo "  $(color red '[ERROR]') mutate() returned non-zero"
        results+=("ERROR | $case_name | mutate failed")
        errored+=1
        return
    fi

    # Run audit. --yes bypasses the "Save report?" prompt; --json-only
    # silences the TUI/text output. We still rely on reports/summary.json
    # being written to disk.
    if ! run_audit "$MODULE"; then
        echo "  $(color red '[ERROR]') audit incomplete: no summary.json or $MODULE did not complete"
        results+=("ERROR | $case_name | audit incomplete")
        errored+=1
        restore >/dev/null 2>&1 || true
        return
    fi

    local hit_severity
    hit_severity=$(jq -r --arg id "$EXPECT_ID" --arg s "$EXPECT_STATUS" \
        '.checks[] | select(.id == $id and .status == $s) | .severity' \
        "$REPORT" 2>/dev/null | head -1)

    local detected=0 warned=0
    if [[ -n "$hit_severity" ]]; then
        # Optional substring check on the matched check's desc field.
        # Critical for aggregate checks like kernel.kernel_params_weak
        # that lump multiple sysctls into one check_id — without this,
        # a case that mutates ldisc_autoload would "pass" simply because
        # sysrq=438 was already in the failure list.
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

    # Severity drift is still a detection (the WARN line above stands in for
    # the PASS line); only a failed stage 2 or 3 turns the case red.
    if (( detected == 1 )); then
        if (( converged == 1 )); then
            (( warned == 0 )) && results+=("PASS  | $case_name | $EXPECT_ID @ $hit_severity${FIX_ID:+ → $FIX_ID → rollback}")
            passed+=1
        else
            failed+=1
        fi
    fi

    if ! restore; then
        echo "  $(color yellow '[WARN]') restore() failed — system may be in dirty state"
        results+=("WARN  | $case_name | restore failed (manual cleanup needed)")
    fi
}

# Stage 2 (fix → re-audit) and stage 3 (rollback → re-audit); returns 1 on the
# first failed assertion. Every assertion reads the audit's verdict, never the
# fix's exit status: a fix that returns 0 while the audit still flags the host is the defect.
run_fix_and_rollback() {
    local case_name="$1"

    local before_sessions
    before_sessions=$(ls -1 "$BACKUPS_DIR" 2>/dev/null | sort)

    local guide_rc=0
    "$VPSSEC_BIN" guide --include="$MODULE" --fix="$FIX_ID" --yes --json-only --lang=en_US \
        >"$STAGE_LOG" 2>&1 || guide_rc=$?

    local session
    session=$(comm -13 <(printf '%s\n' "$before_sessions") \
                       <(ls -1 "$BACKUPS_DIR" 2>/dev/null | sort) | tail -1)

    if ! run_audit "$MODULE"; then
        echo "  $(color red '[FAIL]') audit incomplete after guide --fix=$FIX_ID (guide rc=$guide_rc)"
        results+=("FAIL  | $case_name | audit incomplete after fix")
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

    if [[ -z "$session" ]]; then
        echo "  $(color red '[FAIL]') guide left no backup session to roll back"
        results+=("FAIL  | $case_name | no backup session after fix")
        return 1
    fi

    # rollback confirms through confirm_critical, which reads /dev/tty and
    # ignores --yes on purpose; a pseudo-terminal answers it the way an
    # operator would. --yes still skips the menus, which would eat the answer.
    local rollback_rc=0
    printf 'yes\n' | script -qefc "$VPSSEC_BIN rollback $session --yes --lang=en_US" /dev/null \
        >"$STAGE_LOG" 2>&1 || rollback_rc=$?
    if (( rollback_rc != EXPECT_ROLLBACK_RC )); then
        echo "  $(color red '[FAIL]') rollback $session exited $rollback_rc, expected $EXPECT_ROLLBACK_RC"
        tail -n 10 "$STAGE_LOG" | sed 's/^/         | /'
        results+=("FAIL  | $case_name | rollback rc $rollback_rc, want $EXPECT_ROLLBACK_RC")
        return 1
    fi

    if ! run_audit "$MODULE"; then
        echo "  $(color red '[FAIL]') audit incomplete after rollback"
        results+=("FAIL  | $case_name | audit incomplete after rollback")
        return 1
    fi
    if report_has "$EXPECT_ROLLBACK_ID" "$EXPECT_ROLLBACK_STATUS"; then
        echo "  $(color green '[PASS]') after rollback (rc=$rollback_rc): $EXPECT_ROLLBACK_ID is $EXPECT_ROLLBACK_STATUS"
    else
        echo "  $(color red '[FAIL]') after rollback: $EXPECT_ROLLBACK_ID expected $EXPECT_ROLLBACK_STATUS, got '$(report_check "$EXPECT_ROLLBACK_ID")'"
        results+=("FAIL  | $case_name | rollback left $EXPECT_ROLLBACK_ID not $EXPECT_ROLLBACK_STATUS")
        return 1
    fi
    return 0
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
echo "Total: $total  Passed: $(color green "$passed")  Failed: $(color red "$failed")  Errored: $(color red "$errored")  Skipped: $(color yellow "$skipped")"

# Non-zero exit if anything failed or errored — for CI
(( failed == 0 && errored == 0 ))
