#!/usr/bin/env bats
# Under `set -euo pipefail` the idiom n=$(cmd | grep -c PAT || echo 0) breaks
# on zero matches: grep -c prints "0" AND exits 1, so the fallback also fires
# and stdout becomes "0\n0", which then kills the audit in an arithmetic test.

load helpers.bash

setup() {
    _vpssec_load
}

# Direct repro of the broken pattern. If this test ever passes — i.e. the bug is
# back — the check below would print "0\n0".

@test "anti-pattern: grep -c with no matches under pipefail produces double output" {
    set -o pipefail
    local n
    # Empty input → grep -c prints "0" exits 1 → || echo 0 fires
    n=$(printf '' | grep -c "anything" || echo 0)
    # Verify the buggy result IS what we think it is, so the fix
    # below can be contrasted meaningfully.
    [ "$n" = "0
0" ]
}

@test "fix: grep -c with no matches under pipefail + || true is a single 0" {
    set -o pipefail
    local n
    n=$(printf '' | grep -c "anything" || true)
    [ "$n" = "0" ]
    # And it's safe in arithmetic
    [ "${n:-0}" -eq 0 ]
}
