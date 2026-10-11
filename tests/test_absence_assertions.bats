#!/usr/bin/env bats
# `run` swallows the exit status, so a test that runs something and then asserts
# only absences passes when the thing died before doing anything. Such a test
# must assert $status as well.

load helpers.bash

# "file:line: @test ..." for each test that calls run, never reads $status, and
# after its first run asserts only absences (!=, -z "$output", _vpssec_refute).
_absence_only_tests() {
    awk '
        function flush() {
            if (name != "" && hasrun && !hasstatus && npos == 0 && nneg > 0)
                print FILENAME ":" start ": " name
            name = ""; hasrun = hasstatus = npos = nneg = afterrun = 0
        }
        FNR == 1 { flush() }
        /^@test / { flush(); name = $0; start = FNR; next }
        /^}/ { flush(); next }
        name != "" {
            if ($0 ~ /^[[:space:]]*run[[:space:]]/) { hasrun = afterrun = 1; next }
            if ($0 ~ /\$status/) hasstatus = 1
            if (!afterrun || $0 ~ /^[[:space:]]*(#|$)/) next
            if ($0 ~ /!=|_vpssec_refute|-z "\$[{]?output|! *grep|grep -v/) nneg++
            else if ($0 ~ /^[[:space:]]*(\[|\[\[|grep|_vpssec_stub_called|jq)/) npos++
        }
        END { flush() }
    ' "$@"
}

@test "no test that runs something asserts only absences without its \$status" {
    run _absence_only_tests "$(_vpssec_repo_root)"/tests/*.bats
    [ "$status" -eq 0 ]
    [ -z "$output" ] || { echo "assert \$status too, or a run that died passes:"; echo "$output"; false; }
}

@test "lint: absences alone are flagged; \$status or a presence clears the test" {
    local f="$BATS_TEST_TMPDIR/fx.bats"
    printf '%s\n' '@test "a" {' '    run f' '    [ -z "$output" ]' '}' \
        '@test "b" {' '    run f' '    [ "$status" -eq 0 ]' '    [ -z "$output" ]' '}' \
        '@test "c" {' '    run f' '    [[ "$output" == *x* ]]' '    [[ "$output" != *y* ]]' '}' \
        '@test "d" {' '    run f' '    _vpssec_refute grep -q x <<<"$output"' '}' > "$f"
    run _absence_only_tests "$f"
    [ "$status" -eq 0 ]
    [ "$output" = "$(printf '%s\n' "$f:1: @test \"a\" {" "$f:15: @test \"d\" {")" ]
}
