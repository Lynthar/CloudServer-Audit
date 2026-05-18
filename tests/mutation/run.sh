#!/usr/bin/env bash
# Mutation testing harness for vpssec.
#
# For each .case file under tests/mutation/cases/, the driver:
#   1. sources the case to get mutate() / restore() / expectations
#   2. runs mutate() to plant a known defect
#   3. runs `vpssec audit --include=<module> --json-only --yes`
#   4. asserts the expected check_id appears with the expected status
#   5. runs restore() to revert the planted defect
#
# IMPORTANT: run only on a disposable VM or container. Restore is
# best-effort — if a case crashes between mutate and restore, the
# system can be left in a degraded state. Take a VM snapshot first.
#
# Usage:
#   sudo bash tests/mutation/run.sh                 # all cases
#   sudo bash tests/mutation/run.sh ssh             # cases whose filename contains "ssh"
#   sudo bash tests/mutation/run.sh -k filesystem   # synonym for filtering

set -uo pipefail   # NOT -e: we want to keep going past individual failures

VPSSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VPSSEC_BIN="${VPSSEC_ROOT}/vpssec"
CASES_DIR="${VPSSEC_ROOT}/tests/mutation/cases"
REPORT="${VPSSEC_ROOT}/reports/summary.json"

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
          MODULE DESTRUCTIVE 2>/dev/null || true

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
    "$VPSSEC_BIN" audit --include="$MODULE" --json-only --yes --lang=en_US \
        >/dev/null 2>&1 || true

    if [[ ! -s "$REPORT" ]]; then
        echo "  $(color red '[ERROR]') audit produced no summary.json"
        results+=("ERROR | $case_name | no summary.json")
        errored+=1
        restore >/dev/null 2>&1 || true
        return
    fi

    local hit_severity
    hit_severity=$(jq -r --arg id "$EXPECT_ID" --arg s "$EXPECT_STATUS" \
        '.checks[] | select(.id == $id and .status == $s) | .severity' \
        "$REPORT" 2>/dev/null | head -1)

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
            if [[ -n "${EXPECT_SEVERITY:-}" && "$hit_severity" != "$EXPECT_SEVERITY" ]]; then
                echo "  $(color yellow '[WARN]') detected but severity=$hit_severity (expected $EXPECT_SEVERITY)"
                results+=("WARN  | $case_name | severity drift: got $hit_severity, want $EXPECT_SEVERITY")
                passed+=1   # detection still worked; severity miscalibration is a different concern
            else
                echo "  $(color green '[PASS]') detected $EXPECT_ID @ $hit_severity"
                results+=("PASS  | $case_name | $EXPECT_ID @ $hit_severity")
                passed+=1
            fi
        fi
    else
        echo "  $(color red '[FAIL]') $EXPECT_ID with status=$EXPECT_STATUS not in summary"
        # Show what DID appear for that check_id, if anything — eases debug
        local actual
        actual=$(jq -r --arg id "$EXPECT_ID" \
            '.checks[] | select(.id == $id) | "\(.status)/\(.severity)"' \
            "$REPORT" 2>/dev/null | head -1)
        [[ -n "$actual" ]] && echo "         (it appeared as: $actual)"
        results+=("FAIL  | $case_name | $EXPECT_ID expected $EXPECT_STATUS, not found")
        failed+=1
    fi

    if ! restore; then
        echo "  $(color yellow '[WARN]') restore() failed — system may be in dirty state"
        results+=("WARN  | $case_name | restore failed (manual cleanup needed)")
    fi
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
