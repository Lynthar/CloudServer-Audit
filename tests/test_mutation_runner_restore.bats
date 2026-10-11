#!/usr/bin/env bats
# tests/mutation/run.sh's verdict: what a case planted is undone even when mutate()
# failed half way, a restore() that fails turns the run red (later cases would start
# from a dirty host), and a filter that matches no case is a failure, not a pass.

load helpers.bash

setup() {
    [ "$(id -u)" = 0 ] || skip "the runner refuses to start unless root"
    ROOT="$BATS_TEST_TMPDIR/tree"
    mkdir -p "$ROOT/tests/mutation/cases"
    cp "$(_vpssec_repo_root)/tests/mutation/run.sh" "$ROOT/tests/mutation/"
    # An audit that completes and reports the one check every case expects.
    printf '%s\n' '#!/usr/bin/env bash' 'mkdir -p "$(dirname "$0")/reports"' \
        "echo '{\"meta\":{\"complete\":true},\"checks\":[{\"id\":\"fx.planted\",\"status\":\"failed\",\"severity\":\"low\",\"desc\":\"\"}]}' > \"\$(dirname \"\$0\")/reports/summary.json\"" \
        > "$ROOT/vpssec"
    chmod +x "$ROOT/vpssec"
    PLANTED="$BATS_TEST_TMPDIR/planted"
    UNDONE="$BATS_TEST_TMPDIR/undone"
}

# A case named $1 whose mutate() and restore() bodies are $2 and $3.
_case() {
    printf '%s\n' "TEST_DESC=\"$1\"" 'EXPECT_ID="fx.planted"' 'EXPECT_STATUS="failed"' \
        'MODULE="fx"' "mutate() { $2; }" "restore() { $3; }" \
        > "$ROOT/tests/mutation/cases/$1.case"
}

@test "runner: a mutate() that fails half way is restored, and the run fails" {
    _case 010-half "touch $PLANTED; return 1" "rm -f $PLANTED; touch $UNDONE"
    run bash "$ROOT/tests/mutation/run.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"ERROR | 010-half | mutate failed"* ]]
    [ -e "$UNDONE" ]
    [ ! -e "$PLANTED" ]
}

@test "runner: a restore() that fails is an error, not a warning" {
    _case 010-dirty "touch $PLANTED" "return 1"
    run bash "$ROOT/tests/mutation/run.sh"
    [ "$status" -eq 1 ]
    # The detection passed; the restore is what failed the run.
    [[ "$output" == *"PASS  | 010-dirty | fx.planted @ low"* ]]
    [[ "$output" == *"ERROR | 010-dirty | restore failed"* ]]
}

@test "runner: a case that plants and restores cleanly passes the run" {
    _case 010-clean "touch $PLANTED" "rm -f $PLANTED"
    run bash "$ROOT/tests/mutation/run.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"PASS  | 010-clean | fx.planted @ low"* ]]
    [ ! -e "$PLANTED" ]
}

@test "runner: a filter that matches no case fails the run and says so" {
    _case 010-clean "touch $PLANTED" "rm -f $PLANTED"
    run bash "$ROOT/tests/mutation/run.sh" 011-typo
    [ "$status" -eq 1 ]
    [[ "$output" == *"Total: 0 "* ]]
    [[ "$output" == *"No case matched '011-typo'"* ]]
    [ ! -e "$PLANTED" ]
}

@test "runner: a filter that matches only a MANUAL case is listed, not a failure" {
    _case 080-by-hand "touch $PLANTED" "rm -f $PLANTED"
    printf '%s\n' 'MANUAL_ONLY="needs what the container lacks"' \
        >> "$ROOT/tests/mutation/cases/080-by-hand.case"
    run bash "$ROOT/tests/mutation/run.sh" 080
    [ "$status" -eq 0 ]
    [[ "$output" == *"MANUAL| 080-by-hand | needs what the container lacks"* ]]
    [[ "$output" == *"Total: 1 "*"Manual: 1"* ]]
    [[ "$output" != *"No case matched"* ]]
}
