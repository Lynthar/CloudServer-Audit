#!/usr/bin/env bats
# A mutation counts as killed only when the suite names a failing test: bats
# dying for some other reason after the baseline must not read as a clean sweep.
# No .cases file pairs these tools: a sweep would rewrite a script that is running.

load helpers.bash

setup() {
    REPO="$BATS_TEST_TMPDIR/repo"
    mkdir -p "$REPO/tools/mutation-cases" "$REPO/src" "$REPO/tests"
    cp "$(_vpssec_repo_root)/tools/mutate-suite.sh" "$(_vpssec_repo_root)/tools/mutate-all.sh" \
        "$REPO/tools/"

    printf 'fx_answer() { echo 42; }\n' > "$REPO/src/fx.sh"
    cat > "$REPO/tests/fx.bats" <<'EOF'
@test "the answer" {
    source "$BATS_TEST_DIRNAME/../src/fx.sh"
    [ "$(fx_answer)" = 42 ]
}
@test "something else" { true; }
EOF
    cat > "$REPO/tools/mutation-cases/fx.cases" <<'EOF'
# mutate-suite: src/fx.sh tests/fx.bats
run_case "fx/wrong-answer" 1 'fx_answer() { echo 42; }' 'fx_answer() { echo 41; }'
EOF
}

# Puts a bats first on PATH that runs the real one once (the baseline), then
# dies by SIGKILL without a word: what an OOM kill looks like from outside.
_bats_dies_after_baseline() {
    local real
    real=$(command -v bats)
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat > "$BATS_TEST_TMPDIR/bin/bats" <<EOF
#!/usr/bin/env bash
n=\$(( \$(cat "$BATS_TEST_TMPDIR/calls" 2>/dev/null || echo 0) + 1 ))
echo "\$n" > "$BATS_TEST_TMPDIR/calls"
(( n == 1 )) && exec "$real" "\$@"
kill -9 \$\$
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/bats"
    PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

# Like the above, but every call after the baseline first leaves a marker and
# waits two seconds, so a test can act while a mutation is in flight.
_bats_pauses_after_baseline() {
    local real
    real=$(command -v bats)
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat > "$BATS_TEST_TMPDIR/bin/bats" <<EOF
#!/usr/bin/env bash
n=\$(( \$(cat "$BATS_TEST_TMPDIR/calls" 2>/dev/null || echo 0) + 1 ))
echo "\$n" > "$BATS_TEST_TMPDIR/calls"
(( n > 1 )) && { touch "$BATS_TEST_TMPDIR/in-flight"; sleep 2; }
exec "$real" "\$@"
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/bats"
    PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

_wait_in_flight() {
    local i
    for i in $(seq 1 100); do
        [ -e "$BATS_TEST_TMPDIR/in-flight" ] && return 0
        sleep 0.1
    done
    return 1
}

@test "mutate-suite: a mutation the suite catches is killed, with its failing count" {
    cd "$REPO"
    run bash tools/mutate-suite.sh src/fx.sh tests/fx.bats tools/mutation-cases/fx.cases
    [ "$status" -eq 0 ]
    [[ "$output" == *"fx/wrong-answer"*"killed at line 1"*"(1 failing)"* ]]
    [[ "$output" == *"killed=1  gaps=0  bad-anchors=0"* ]]
}

@test "mutate-suite: bats dying after the baseline is NOT-RUN, not killed, and fails the run" {
    _bats_dies_after_baseline
    cd "$REPO"
    run bash tools/mutate-suite.sh src/fx.sh tests/fx.bats tools/mutation-cases/fx.cases
    [ "$status" -ne 0 ]
    [[ "$output" == *"fx/wrong-answer"*"NOT-RUN at line 1"* ]]
    [[ "$output" != *"killed at line"* ]]
    [[ "$output" == *"killed=0  gaps=0  bad-anchors=1"* ]]
    [ "$(cat src/fx.sh)" = 'fx_answer() { echo 42; }' ]
}

@test "mutate-all: a case that did not run is named and the sweep exits non-zero" {
    _bats_dies_after_baseline
    run bash "$REPO/tools/mutate-all.sh" fx
    [ "$status" -ne 0 ]
    [[ "$output" == *"fx.cases"*"killed=0  gaps=0  bad-anchors=1"* ]]
    [[ "$output" == *"    fx/wrong-answer"*"NOT-RUN"* ]]
    [[ "$output" == *"files=1  killed=0  gaps=0  bad-anchors=1"* ]]
}

@test "mutate-suite: a TERM mid-run puts the module back and ends the run" {
    _bats_pauses_after_baseline
    cd "$REPO"
    printf '%s\n' "run_case \"fx/second\" 1 'fx_answer() { echo 42; }' 'fx_answer() { echo 40; }'" \
        >> tools/mutation-cases/fx.cases
    bash tools/mutate-suite.sh src/fx.sh tests/fx.bats tools/mutation-cases/fx.cases \
        > "$BATS_TEST_TMPDIR/out" 2>&1 3>&- &
    local pid=$! rc=0
    _wait_in_flight
    kill -TERM "$pid"
    wait "$pid" || rc=$?
    [ "$rc" -eq 143 ]
    [ "$(cat src/fx.sh)" = 'fx_answer() { echo 42; }' ]
    # The baseline and the first case: the second never started.
    [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 2 ]
}

@test "mutate-suite: a syntax error in the cases file stops it before any case runs" {
    cd "$REPO"
    printf '%s\n' 'if then fi' \
        "run_case \"fx/second\" 1 'fx_answer() { echo 42; }' 'fx_answer() { echo 40; }'" \
        >> tools/mutation-cases/fx.cases
    run bash tools/mutate-suite.sh src/fx.sh tests/fx.bats tools/mutation-cases/fx.cases
    [ "$status" -eq 2 ]
    [[ "$output" == *"syntax error in tools/mutation-cases/fx.cases: no case runs"* ]]
    [[ "$output" != *"killed at line"* ]]
}

@test "mutate-suite: a cases file that stops early prints no summary and fails" {
    cd "$REPO"
    printf '%s\n' 'return 0' \
        "run_case \"fx/second\" 1 'fx_answer() { echo 42; }' 'fx_answer() { echo 40; }'" \
        >> tools/mutation-cases/fx.cases
    run bash tools/mutate-suite.sh src/fx.sh tests/fx.bats tools/mutation-cases/fx.cases
    [ "$status" -eq 2 ]
    [[ "$output" == *"fx/wrong-answer"*"killed at line 1"* ]]
    [[ "$output" == *"fx.cases: 1 of 2 run_case lines ran"* ]]
    [[ "$output" != *"killed=1"* ]]
}

@test "mutate-all: a cases file holding no case did not run" {
    printf '# mutate-suite: src/fx.sh tests/fx.bats\n' > "$REPO/tools/mutation-cases/fx.cases"
    run bash "$REPO/tools/mutate-all.sh" fx
    [ "$status" -eq 1 ]
    [[ "$output" == *"fx.cases"*"DID NOT RUN:"*"0 of 0 run_case lines ran"* ]]
    [[ "$output" == *"files=0  killed=0  gaps=0  bad-anchors=0  not-run=1"* ]]
}

@test "mutate-suite: an anchor that is not unique says so, per case and per file" {
    cd "$REPO"
    printf '%s\n' 'fx_answer() { echo 42; }' ':' ':' > src/fx.sh
    printf '%s\n' "run_case \"fx/dup\" 2 ':' 'fx_answer() { echo 41; }'" \
        >> tools/mutation-cases/fx.cases
    run bash tools/mutate-suite.sh src/fx.sh tests/fx.bats tools/mutation-cases/fx.cases
    [ "$status" -eq 0 ]
    [[ "$output" == *"fx/dup"*"killed at line 3"*"(1 failing) [#2 of 2 identical lines]"* ]]
    [ "$(grep -c 'identical lines' <<<"$output")" -eq 1 ]
    [[ "$output" == *"killed=2  gaps=0  bad-anchors=0  non-unique-anchors=1"* ]]
}

@test "mutate-all: a file is named before its run finishes" {
    _bats_pauses_after_baseline
    bash "$REPO/tools/mutate-all.sh" fx > "$BATS_TEST_TMPDIR/out" 2>&1 3>&- &
    local pid=$! rc=0 early
    _wait_in_flight
    early=$(cat "$BATS_TEST_TMPDIR/out")
    wait "$pid" || rc=$?
    [ "$rc" -eq 0 ]
    [[ "$early" == "fx.cases"* ]]
    [[ "$(cat "$BATS_TEST_TMPDIR/out")" == "fx.cases"*"killed=1  gaps=0  bad-anchors=0"* ]]
}
