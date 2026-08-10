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
# The cases file is a shell fragment of run_case calls:
#
#     run_case "<id>" <occurrence> "<exact old line>" "<replacement line>"
#
# Exit status is 0 only when every mutation was killed and every anchor
# resolved.
#
# ---------------------------------------------------------------------
# Three properties of this runner exist because their absence produced a
# WRONG answer, not merely an inconvenient one. Do not simplify them away:
#
#   1. Anchors match WHOLE LINES and carry an occurrence index. Several
#      lines in these modules appear twice — the audit and the fix share
#      their ip_forward / rp_filter / RA-guard exceptions verbatim, and a
#      4-space-indented line is a substring of the same line at 8 spaces.
#      A first-match replace lands in the wrong function and reports a
#      coverage gap in code the suite never claimed to cover.
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

PRISTINE=$(mktemp) || exit 2
cp "$SRC" "$PRISTINE"

# Always put the module back, including on Ctrl-C — a half-mutated module
# left in the working tree is a nasty thing to debug later.
trap 'cp "$PRISTINE" "$SRC"; rm -f "$PRISTINE"' EXIT INT TERM

# The suite must be GREEN before anything is mutated. A mutation is "killed"
# when the suite goes red, so a suite that is already red kills every mutation
# it is handed and reports a flawless sweep — the loudest possible way to be
# wrong, and silent. It is not hypothetical: on a macOS checkout several
# suites fail for want of GNU realpath, and a sweep run there looks perfect.
# One extra suite run per cases file buys the difference between a result and
# a rumour.
if ! baseline_out=$(bats "$SUITE" 2>&1); then
    printf 'REFUSING TO RUN: %s already fails before any mutation.\n' "$SUITE" >&2
    printf 'Every mutation would be reported as killed. Failing tests:\n' >&2
    grep '^not ok' <<<"$baseline_out" | sed 's/^/  /' >&2
    exit 2
fi

pass=0
gap=0
bad=0

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

    local line
    line=$(grep -nxF -- "$old" "$SRC" | sed -n "${occ}p" | cut -d: -f1)

    MUT_OLD="$old" MUT_NEW="$new" MUT_OCC="$occ" awk '
        BEGIN { old = ENVIRON["MUT_OLD"]; new = ENVIRON["MUT_NEW"];
                occ = ENVIRON["MUT_OCC"] + 0; seen = 0 }
        { if ($0 == old) { seen++; if (seen == occ) { print new; next } }
          print $0 }
    ' "$PRISTINE" > "$SRC"

    if cmp -s "$PRISTINE" "$SRC"; then
        printf '%-36s NOT-APPLIED (line %s unchanged)\n' "$id" "$line"
        bad=$((bad + 1))
        return
    fi

    local landed
    landed=$(awk -v l="$line" 'NR == l { print }' "$SRC")
    if [[ "$landed" != "$new" ]]; then
        printf '%-36s LANDED-WRONG at line %s: %s\n' "$id" "$line" "$landed"
        bad=$((bad + 1))
        return
    fi

    local out
    if out=$(bats "$SUITE" 2>&1); then
        printf '%-36s SURVIVED at line %-5s <-- COVERAGE GAP\n' "$id" "$line"
        gap=$((gap + 1))
    else
        printf '%-36s killed at line %-5s (%s failing)\n' \
            "$id" "$line" "$(grep -c '^not ok' <<<"$out")"
        pass=$((pass + 1))
    fi
}

# shellcheck source=/dev/null
source "$CASES"

printf '\n%s: killed=%s  gaps=%s  bad-anchors=%s\n' \
    "$(basename "$CASES")" "$pass" "$gap" "$bad"
[[ "$gap" -eq 0 && "$bad" -eq 0 ]]
