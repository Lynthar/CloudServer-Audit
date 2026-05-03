#!/usr/bin/env bats
#
# Latent-bug regression: production sources every module from inside
# core/engine.sh's `module_load` function. bash makes `declare -a NAME=(...)`
# function-local even though it is at the script's top level, so any
# audit code that ran later (called from a sibling function `audit_all`)
# saw the array as unset. Under `set -u` the for-loop expansion of an
# empty/unset array is special-cased to NOT error, so the check silently
# iterated zero entries and reported "all OK".
#
# This test simulates that flow: source modules from inside a function,
# return, then assert each module-level array is still readable. It
# fails (under set -u) if any module reverts to the bare `declare -a`
# without -g.

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
    [ "${#PASSWORD_POLICY[@]}" -gt 0 ]
    [ "${#PWQUALITY_POLICY[@]}" -gt 0 ]
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
    [ "${#CRYPTO_POOL_PATTERNS[@]}" -gt 0 ]
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
