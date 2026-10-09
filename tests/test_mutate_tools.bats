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
