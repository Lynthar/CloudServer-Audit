#!/usr/bin/env bats
# A run that cannot start says why, on stderr, with the documented exit code:
# a missing jq, a misspelt --include module, a second run while one holds the
# lock. Each used to exit silently, with the wrong code, or without the PID.

load helpers.bash
bats_require_minimum_version 1.5.0

setup() {
    _vpssec_load core/distro.sh core/state.sh core/engine.sh
    i18n_load en_US
}

# errexit as vpssec runs (bats' `run` turns it off).
_errexit() { set -euo pipefail; "$@"; }

# main and parse_args from the entry script, run in this shell so that
# check_command can be masked: jq cannot be hidden by PATH alone, since vpssec
# appends the sbin directories and Arch links those to /usr/bin.
_load_entry() {
    local src
    src="$(_vpssec_repo_root)/vpssec"
    eval "$(awk '/^parse_args\(\)/,/^}/' "$src")"
    eval "$(awk '/^main\(\)/,/^}/' "$src")"
}

# ---- no jq ------------------------------------------------------------------

@test "without jq, --help and status say jq is missing on stderr and exit 1" {
    _load_entry
    _vpssec_absent_command jq
    local args
    for args in --help status; do
        run --separate-stderr _errexit main $args
        [ "$status" -eq 1 ]
        [ -z "$output" ]
        [[ "$stderr" == *"jq is required"* ]]
    done
}

# ---- --json-only keeps stdout for the JSON document ---------------------------

@test "under --json-only a missing dependency and its install hint both reach stderr" {
    _load_entry
    check_root() { return 0; }
    check_required_deps() { echo ss; return 1; }
    run --separate-stderr _errexit main audit --json-only --yes --lang=en_US
    [ "$status" -eq 1 ]
    [ -z "$output" ]
    [[ "$stderr" == *"$(i18n 'preflight.dep_missing' "dep=ss")"* ]]
    [[ "$stderr" == *"Install with"* ]]
}

@test "under --json-only a run without root and its sudo hint both reach stderr" {
    _load_entry
    check_root() { return 1; }
    run --separate-stderr _errexit main audit --json-only --lang=en_US
    [ "$status" -eq 1 ]
    [ -z "$output" ]
    [[ "$stderr" == *"$(i18n 'error.run_with_sudo' "cmd=audit")"* ]]
}

# ---- an unknown --include module --------------------------------------------

@test "--include naming an unknown module exits 1, the bad-arguments code, on stderr" {
    module_load() { VPSSEC_MODULE_LOADED[$1]=1; return 0; }
    run --separate-stderr _errexit module_load_all "ssh,ssg" ""
    [ "$status" -eq 1 ]
    [ -z "$output" ]
    [[ "$stderr" == *"ssg"* ]]
    [[ "$stderr" == *"$(i18n 'error.available_modules' "list=")"* ]]
}

# ---- a second run while one holds the lock ----------------------------------

# Hold the run lock on fd 201 as a live run would, its PID 4242 on record. The
# competitor is `run`'s subshell, which opens the file again: flock refuses it.
_hold_run_lock() {
    command -v flock >/dev/null || skip "flock(1) not installed"
    run_lock="$VPSSEC_STATE/.run.lock"
    exec 201>>"$run_lock"
    flock -n 201
    echo 4242 > "$run_lock"
}

teardown() {
    exec 201>&- 2>/dev/null || true
}

@test "a second run names the holder's PID, and the PID stays on record" {
    _hold_run_lock
    VPSSEC_MODE=audit
    run vpssec_init
    [ "$status" -eq 1 ]
    [[ "$output" == *"PID 4242"* ]]
    [[ "$output" == *"kill 4242"* ]]
    [ "$(cat "$run_lock")" = 4242 ]
}

@test "under --json-only the refusal and its hint both reach stderr" {
    _hold_run_lock
    VPSSEC_MODE=audit VPSSEC_JSON_ONLY=1
    run --separate-stderr vpssec_init
    [ "$status" -eq 1 ]
    [ -z "$output" ]
    [[ "$stderr" == *"PID 4242"* ]]
    [[ "$stderr" == *"kill 4242"* ]]
}

@test "the run that takes the lock records its own PID" {
    command -v flock >/dev/null || skip "flock(1) not installed"
    VPSSEC_MODE=audit
    vpssec_init
    [ "$(cat "$VPSSEC_STATE/.run.lock")" = "$$" ]
}
