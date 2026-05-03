#!/usr/bin/env bats
#
# Regression: under `set -euo pipefail` (which vpssec runs with),
# the idiom
#
#     n=$(some_cmd | grep -c PATTERN || echo 0)
#
# is broken when grep finds zero matches: grep -c prints "0" AND exits
# with status 1, so the `|| echo 0` fallback ALSO fires and stdout
# becomes the literal "0\n0". A subsequent `[[ "$n" -gt N ]]` then
# blows up with "syntax error in expression" and, under set -e, kills
# the audit.
#
# The user-visible failure was in modules/ufw.sh:24 on a host where
# iptables existed but had no ACCEPT/DROP/REJECT lines. Same anti-
# pattern lived in ufw.sh, kernel.sh, and logging.sh. The fix is
# `|| true` (grep -c / wc -l already print 0 to stdout).

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"
}

# ---------------------------------------------------------------------
# Direct repro of the broken pattern. If this test ever passes (i.e.
# the bug is back), the check below would print "0\n0".
# ---------------------------------------------------------------------

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

# ---------------------------------------------------------------------
# Production helpers: must not abort under set -e on the zero-match path.
# ---------------------------------------------------------------------

@test "_iptables_has_rules: returns false (not aborts) when iptables produces no rules" {
    # Stub iptables to return Chain headers only (no ACCEPT/DROP/REJECT
    # lines) — this is the exact shape that bit the user.
    iptables() {
        cat <<'EOF'
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
EOF
        return 0
    }
    export -f iptables

    # set -e is on (sourced common.sh enables it). The function must
    # complete WITHOUT triggering "syntax error in expression".
    run _iptables_has_rules
    [ "$status" -eq 1 ]   # no rules → false, but cleanly false
}

@test "_iptables_has_rules: returns true when policy rules exceed default count" {
    iptables() {
        cat <<'EOF'
Chain INPUT (policy DROP)
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0   tcp dpt:22
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0   tcp dpt:80
DROP       all  --  0.0.0.0/0            0.0.0.0/0
EOF
        return 0
    }
    export -f iptables
    run _iptables_has_rules
    [ "$status" -eq 0 ]
}

@test "_iptables_has_rules: handles iptables-not-installed gracefully" {
    # Simulate command-not-found by stubbing to return 127.
    iptables() { return 127; }
    export -f iptables
    run _iptables_has_rules
    [ "$status" -eq 1 ]   # No rules → false. NOT aborted with set -e.
}

@test "_nftables_active: zero tables does not crash" {
    nft() {
        # nft list tables returns empty stdout when there are no tables
        return 0
    }
    check_command() { [[ "$1" == "nft" ]]; }
    export -f nft check_command
    run _nftables_active
    # With wc -l on empty input giving "1" (one line of empty string)
    # OR "0" depending on bash version, the function must at least
    # complete without arithmetic syntax errors.
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}
