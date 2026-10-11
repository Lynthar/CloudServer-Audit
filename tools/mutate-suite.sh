#!/usr/bin/env bash
#
# Mutation-test one bats suite against one module: plant a known defect,
# assert the suite goes red, restore, repeat. A SURVIVED line means the
# suite does not actually cover that behaviour.
#
# This is not `tests/mutation/`. That suite plants defects in a real /etc
# on a throwaway host and checks the AUDIT detects them. This one plants
# defects in module source and checks a bats SUITE detects them — it is how
# you find out whether a test you just wrote asserts anything at all.
#
# Usage, from the repo root, inside the verification container:
#
#     bash tools/mutate-suite.sh modules/kernel.sh \
#          tests/test_fix_kernel.bats tools/mutation-cases/kernel.cases
#
# The cases file is a shell fragment of run_case calls, each starting its
# own line (property 5 counts them that way):
#
#     run_case "<id>" <occurrence> "<exact old line>" "<replacement line>"
#
# Exit status is 0 only when every mutation was killed, every anchor
# resolved and every case in the file ran. bad-anchors counts every case
# that produced no verdict: ANCHOR-BAD, NOT-APPLIED, LANDED-WRONG, NOT-RUN.
# An interrupt (Ctrl-C, TERM) puts the module back and ends the run.
#
# ---------------------------------------------------------------------
# Five properties of this runner exist because their absence produced a
# WRONG answer, not merely an inconvenient one. Do not simplify them away:
#
#   1. Anchors match WHOLE LINES and carry an occurrence index. Several
#      lines in these modules appear twice — the audit and the fix share
#      their ip_forward / rp_filter / RA-guard exceptions verbatim, and a
#      4-space-indented line is a substring of the same line at 8 spaces.
#      A first-match replace lands in the wrong function and reports a
#      coverage gap in code the suite never claimed to cover. The index
#      only holds while nobody adds another copy of the line above it, so
#      a case whose anchor is not unique says so on its verdict line and in
#      the file's summary (non-unique-anchors=N): prefer a unique anchor.
#
#   2. Strings reach awk through ENVIRON, never `-v`. awk processes escape
#      sequences in a `-v` assignment, so an anchor containing \*, \s or a
#      trailing backslash arrives mangled, matches nothing, and the
#      UNMUTATED suite passes — which is indistinguishable from a real
#      coverage gap. Two of twelve kernel mutations did exactly this.
#
#   3. The mutation is asserted to have LANDED before the suite runs: the
#      file must differ from the pristine copy, and line N must now equal
#      the replacement. That converts a silent no-op into a loud error.
#
#   4. A mutation counts as killed only when bats names a failing test.
#      bats exiting non-zero with no `not ok` line means the suite died
#      rather than failed -- OOM, a full /tmp, Ctrl-C, a host file an
#      earlier case broke -- and counting that as a kill lets the machine,
#      not the suite, report a clean sweep. Such a case is NOT-RUN.
#
#   5. Every run_case line in the cases file must run. `source` stops at a
#      syntax error, or at a stray `return`, without a word, and the cases
#      before it then report a clean file. The file is checked with bash -n
#      before anything runs, and the cases that ran are counted against its
#      run_case lines afterwards; a mismatch prints no summary and exits 2.
# ---------------------------------------------------------------------
set -u

SRC="${1:-}"
SUITE="${2:-}"
CASES="${3:-}"

if [[ -z "$SRC" || -z "$SUITE" || -z "$CASES" ]]; then
    printf 'usage: %s <module.sh> <suite.bats> <cases-file>\n' "$0" >&2
    exit 2
fi
for f in "$SRC" "$SUITE" "$CASES"; do
    [[ -r "$f" ]] || { printf 'not readable: %s\n' "$f" >&2; exit 2; }
done
command -v bats >/dev/null 2>&1 || { echo 'bats not on PATH' >&2; exit 2; }
bash -n "$CASES" || { printf 'syntax error in %s: no case runs\n' "$CASES" >&2; exit 2; }

PRISTINE=$(mktemp) || exit 2
cp "$SRC" "$PRISTINE" || { rm -f "$PRISTINE"; exit 2; }

# The module goes back on every exit, and an interrupt must end the run: a loop
# that carried on would mutate from the deleted copy and leave the module empty.
trap 'cp "$PRISTINE" "$SRC" && rm -f "$PRISTINE" \
    || printf "could not restore %s; the original is %s\n" "$SRC" "$PRISTINE" >&2' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The suite must be GREEN before anything is mutated: a suite that is already
# red "kills" every mutation and reports a flawless sweep (a macOS checkout,
# lacking GNU realpath, does exactly that).
if ! baseline_out=$(bats "$SUITE" 2>&1); then
    printf 'REFUSING TO RUN: %s already fails before any mutation.\n' "$SUITE" >&2
    printf 'Every mutation would be reported as killed. Failing tests:\n' >&2
    grep '^not ok' <<<"$baseline_out" | sed 's/^/  /' >&2
    exit 2
fi

pass=0
gap=0
bad=0
nonunique=0

run_case() {
    local id="$1" occ="$2" old="$3" new="$4"
    cp "$PRISTINE" "$SRC"

    local n
    n=$(grep -cxF -- "$old" "$SRC")
    if [[ "$n" -lt "$occ" ]]; then
        printf '%-36s ANCHOR-BAD (%s matches, wanted #%s)\n' "$id" "$n" "$occ"
        bad=$((bad + 1))
        return
    fi

    local line dup=""
    line=$(grep -nxF -- "$old" "$SRC" | sed -n "${occ}p" | cut -d: -f1)
    if (( n > 1 )); then
        dup=" [#$occ of $n identical lines]"
        nonunique=$((nonunique + 1))
    fi

    MUT_OLD="$old" MUT_NEW="$new" MUT_OCC="$occ" awk '
        BEGIN { old = ENVIRON["MUT_OLD"]; new = ENVIRON["MUT_NEW"];
                occ = ENVIRON["MUT_OCC"] + 0; seen = 0 }
        { if ($0 == old) { seen++; if (seen == occ) { print new; next } }
          print $0 }
    ' "$PRISTINE" > "$SRC"

    if cmp -s "$PRISTINE" "$SRC"; then
        printf '%-36s NOT-APPLIED (line %s unchanged)%s\n' "$id" "$line" "$dup"
        bad=$((bad + 1))
        return
    fi

    local landed
    landed=$(awk -v l="$line" 'NR == l { print }' "$SRC")
    if [[ "$landed" != "$new" ]]; then
        printf '%-36s LANDED-WRONG at line %s: %s%s\n' "$id" "$line" "$landed" "$dup"
        bad=$((bad + 1))
        return
    fi

    local out failing
    if out=$(bats "$SUITE" 2>&1); then
        printf '%-36s SURVIVED at line %-5s <-- COVERAGE GAP%s\n' "$id" "$line" "$dup"
        gap=$((gap + 1))
        return
    fi
    failing=$(grep -c '^not ok' <<<"$out")
    if (( failing == 0 )); then
        printf '%-36s NOT-RUN at line %-5s (bats failed, but no test did)%s\n' "$id" "$line" "$dup"
        bad=$((bad + 1))
    else
        printf '%-36s killed at line %-5s (%s failing)%s\n' "$id" "$line" "$failing" "$dup"
        pass=$((pass + 1))
    fi
}

# shellcheck source=/dev/null
source "$CASES"

expected=$(grep -c '^run_case ' "$CASES")
if (( pass + gap + bad != expected || expected == 0 )); then
    printf '%s: %d of %d run_case lines ran; the file stopped early or holds none\n' \
        "$(basename "$CASES")" "$((pass + gap + bad))" "$expected" >&2
    exit 2
fi

printf '\n%s: killed=%s  gaps=%s  bad-anchors=%s%s\n' \
    "$(basename "$CASES")" "$pass" "$gap" "$bad" \
    "$( (( nonunique )) && printf '  non-unique-anchors=%s' "$nonunique")"
[[ "$gap" -eq 0 && "$bad" -eq 0 ]]
