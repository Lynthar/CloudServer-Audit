#!/usr/bin/env bash
#
# Run every mutation-cases file against the suite it belongs to, and report
# one total. This exists because "all the mutation cases are killed" was
# written into the project's records for two releases without anyone ever
# having run them all at once — each cases file was run once, by whoever
# wrote it, and never again. The first sweep that actually did it found five
# surviving mutations and two anchors that had stopped resolving months
# earlier, one of them an equivalent mutant nobody could ever have killed.
#
# Usage, from the repo root:
#
#     bash tools/mutate-all.sh                 # every cases file
#     bash tools/mutate-all.sh docker fail2ban # only those, by file stem
#
# Exit status is 0 only when every case was killed, every anchor resolved,
# and every cases file declared a pairing. Expect this to take a while: each
# mutation runs its whole suite, and there are several hundred of them.
#
# ---------------------------------------------------------------------
# The pairing is DECLARED, not guessed. Every cases file carries
#
#     # mutate-suite: <module-or-script> <suite.bats>
#
# and a file without one is an error rather than a skip. The alternative --
# parsing the `bash tools/mutate-suite.sh ...` invocation out of the header
# prose -- was tried and is how this script's first draft paired docker.cases
# with the wrong suite and reported four coverage gaps that did not exist.
# Three cases files had never named their suite at all, writing the literal
# placeholder <suite.bats>, so there was nothing to parse in the first place.
# A mis-paired run is worse than no run: it accuses code that the suite never
# claimed to cover.
# ---------------------------------------------------------------------
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
command -v bats >/dev/null 2>&1 || { echo 'bats not on PATH' >&2; exit 2; }

files=()
if (( $# > 0 )); then
    for stem in "$@"; do
        f="tools/mutation-cases/${stem}.cases"
        [[ -r "$f" ]] || { printf 'no such cases file: %s\n' "$f" >&2; exit 2; }
        files+=("$f")
    done
else
    while IFS= read -r f; do files+=("$f"); done \
        < <(find tools/mutation-cases -name '*.cases' | sort)
fi

(( ${#files[@]} )) || { echo 'no cases files found' >&2; exit 2; }

total_killed=0 total_gaps=0 total_bad=0 not_run=0 ran=0

for f in "${files[@]}"; do
    pairing=$(sed -n 's/^# *mutate-suite: *//p' "$f" | head -1)
    read -r module suite _ <<< "$pairing"

    if [[ -z "${module:-}" || -z "${suite:-}" ]]; then
        printf '%-34s NO PAIRING DECLARED (add "# mutate-suite: <module> <suite>")\n' "${f##*/}"
        not_run=$((not_run + 1))
        continue
    fi
    if [[ ! -r "$module" || ! -r "$suite" ]]; then
        printf '%-34s PAIRING DOES NOT RESOLVE: %s + %s\n' "${f##*/}" "$module" "$suite"
        not_run=$((not_run + 1))
        continue
    fi

    out=$(bash tools/mutate-suite.sh "$module" "$suite" "$f" 2>&1)
    summary=$(tail -1 <<< "$out")

    # A refusal (the suite was already red) prints no summary line. Without
    # this branch it parses as killed=0 gaps=0 and reads as a clean file.
    if [[ "$summary" != *killed=* ]]; then
        printf '%-34s DID NOT RUN:\n' "${f##*/}"
        sed 's/^/    /' <<< "$out"
        not_run=$((not_run + 1))
        continue
    fi
    printf '%-34s %s\n' "${f##*/}" "${summary#*: }"

    k=$(sed -n 's/.*killed=\([0-9]*\).*/\1/p' <<< "$summary")
    g=$(sed -n 's/.*gaps=\([0-9]*\).*/\1/p' <<< "$summary")
    b=$(sed -n 's/.*bad-anchors=\([0-9]*\).*/\1/p' <<< "$summary")
    total_killed=$((total_killed + ${k:-0}))
    total_gaps=$((total_gaps + ${g:-0}))
    total_bad=$((total_bad + ${b:-0}))
    ran=$((ran + 1))
done

printf '\n%s\n' '--------------------------------------------------------------'
printf 'files=%d  killed=%d  gaps=%d  bad-anchors=%d  not-run=%d\n' \
    "$ran" "$total_killed" "$total_gaps" "$total_bad" "$not_run"

if (( total_gaps || total_bad || not_run )); then
    printf '\nA gap means the suite does not assert the behaviour the mutation\n'
    printf 'broke. Before writing a test to chase it, check the other two\n'
    printf 'possibilities: the assertion may be asking the wrong question, or\n'
    printf 'the mutated code may be inert -- an equivalent mutant no test can\n'
    printf 'kill, which should be deleted rather than chased.\n'
    exit 1
fi
