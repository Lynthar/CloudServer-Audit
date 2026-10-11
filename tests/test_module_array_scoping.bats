#!/usr/bin/env bats
# Production sources every module from inside core/engine.sh's `module_load`, and
# bash makes a top-level `declare -a NAME=(...)` function-local, so a sibling
# function sees it unset — and `set -u` does not error on an empty array loop.

load helpers.bash

setup() {
    _vpssec_load
}

# Source modules from inside a function (mirrors engine.sh module_load),
# return, then assert visibility from the test scope (which is a sibling
# function, mirroring audit_all → audit_module → <module>_audit).
_simulate_module_load_all() {
    local root
    root=$(_vpssec_repo_root)
    # shellcheck disable=SC1090
    source "$root/modules/users.sh"
    # shellcheck disable=SC1090
    source "$root/modules/filesystem.sh"
    # shellcheck disable=SC1090
    source "$root/modules/cloud.sh"
    # shellcheck disable=SC1090
    source "$root/modules/malware.sh"
    # shellcheck disable=SC1090
    source "$root/modules/webapp.sh"
    # shellcheck disable=SC1090
    source "$root/modules/kernel.sh"
}

@test "scoping: users.sh top-level arrays are visible after sibling-call source" {
    _simulate_module_load_all
    [ "${#ALLOWED_SHELL_USERS[@]}" -gt 0 ]
    [ "${#SYSTEM_ACCOUNTS[@]}" -gt 0 ]
    [ "${#SUSPICIOUS_USERNAMES[@]}" -gt 0 ]
}

@test "scoping: filesystem.sh top-level arrays are visible" {
    _simulate_module_load_all
    [ "${#FS_SUID_WHITELIST[@]}" -gt 0 ]
    [ "${#FS_SENSITIVE_FILES[@]}" -gt 0 ]
    [ "${#FS_CAPS_WHITELIST[@]}" -gt 0 ]
    [ "${#FS_DANGEROUS_CAPS[@]}" -gt 0 ]
}

@test "scoping: cloud.sh top-level arrays are visible" {
    _simulate_module_load_all
    [ "${#KNOWN_CLOUD_AGENTS[@]}" -gt 0 ]
    [ "${#SUSPICIOUS_AGENT_PATTERNS[@]}" -gt 0 ]
    [ "${#SAFE_SYSTEM_PROCESSES[@]}" -gt 0 ]
}

@test "scoping: malware.sh top-level arrays are visible" {
    _simulate_module_load_all
    [ "${#CRYPTO_PROCESS_PATTERNS[@]}" -gt 0 ]
    [ "${#CRYPTO_POOL_PORTS[@]}" -gt 0 ]
    [ "${#WEB_DIRECTORIES[@]}" -gt 0 ]
    [ "${#WEBSHELL_PATTERNS[@]}" -gt 0 ]
    [ "${#SUSPICIOUS_OUTBOUND_PORTS[@]}" -gt 0 ]
    [ "${#C2_PORTS[@]}" -gt 0 ]
}

@test "scoping: webapp.sh + kernel.sh top-level arrays are visible" {
    _simulate_module_load_all
    [ "${#NGINX_SECURITY_HEADERS[@]}" -gt 0 ]
    [ "${#KERNEL_SECURITY_PARAMS[@]}" -gt 0 ]
}

@test "scoping: end-to-end — _is_suspicious_username actually fires after sibling-source" {
    # The user-visible symptom: previously this returned "no match"
    # for every input because SUSPICIOUS_USERNAMES was out of scope
    # and the for-loop iterated zero patterns.
    _simulate_module_load_all
    run _is_suspicious_username "admin"
    [ "$status" -eq 0 ]
}

# "file:line" for each top-level declare / typeset / local in modules/*.sh under
# $1 that is not -g. Only these three make a local; readonly and export do not.
_module_local_declares() {
    awk '
        /^(declare|typeset|local)([ \t]|$)/ {
            n = split($0, w, /[ \t]+/); g = 0
            for (i = 2; i <= n && w[i] ~ /^-/; i++) if (w[i] ~ /g/) g = 1
            if (!g || w[1] == "local") print FILENAME ":" FNR
        }
    ' "$1"/modules/*.sh | sed "s|^$1/||"
}

@test "every top-level declare in modules/ is global, not just the six above" {
    run _module_local_declares "$(_vpssec_repo_root)"
    [ "$status" -eq 0 ]
    [ -z "$output" ] || { echo "local to module_load (add -g):"; echo "$output"; false; }
}

@test "lint: a declare without -g is flagged at top level, not inside a function" {
    local root="$BATS_TEST_TMPDIR/tree"
    mkdir -p "$root/modules"
    printf '%s\n' 'declare -ga A=(x)' 'declare -A B=()' 'declare -gA C=()' 'typeset -a D' \
        'local E=1' 'f() {' '    declare -a inner=()' '}' 'declare F=1' 'readonly G=1' \
        > "$root/modules/m.sh"
    run _module_local_declares "$root"
    [ "$status" -eq 0 ]
    [ "$output" = "$(printf 'modules/m.sh:%s\n' 2 4 5 9)" ]
}
