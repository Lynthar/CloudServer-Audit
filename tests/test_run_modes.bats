#!/usr/bin/env bats
# run.sh deletes its whole tree on exit, and a fix's backups land in that tree.
# So guide and rollback must be refused here — running them would change /etc
# and destroy the only means of undoing it in the same command.

load helpers.bash

setup() {
    _vpssec_load

    local src
    src="$(_vpssec_repo_root)/run.sh"
    eval "$(awk '/^_refuse_stateful_mode\(\)/,/^}/' "$src")"

    print_error() { echo "[ERROR] $*"; }
    VPSSEC_REPO="Lynthar/CloudServer-Audit"
}

@test "guide is refused, and not with the code that means a wrong host" {
    run _refuse_stateful_mode guide
    # 4 is "this HOST cannot be hardened"; automation must not read one as the
    # other, and 0 would read as "hardening completed".
    [ "$status" -eq 2 ]
    [[ "$output" == *"not available through the one-line runner"* ]]
}

@test "rollback is refused too: a fresh tree has no backups to restore from" {
    run _refuse_stateful_mode rollback
    [ "$status" -eq 2 ]
}

@test "the refusal names the way forward, not just the refusal" {
    run _refuse_stateful_mode guide
    [[ "$output" == *"install.sh"* ]]
    [[ "$output" == *"sudo vpssec guide"* ]]
}

@test "audit and status are untouched" {
    for m in audit status ""; do
        run _refuse_stateful_mode "$m"
        [ "$status" -eq 0 ]
        [ -z "$output" ]
    done
}

@test "the refusal happens before anything is downloaded" {
    # Refusing after the download would still be correct, but it would fetch a
    # release only to decline to use it — and on a slow link that reads as a
    # hang rather than a refusal.
    local src refuse_line download_line
    src="$(_vpssec_repo_root)/run.sh"
    refuse_line=$(grep -n '^ *_refuse_stateful_mode "\$mode"$' "$src" | head -1 | cut -d: -f1)
    download_line=$(grep -n '^ *download_and_verify$' "$src" | head -1 | cut -d: -f1)

    [ -n "$refuse_line" ] && [ -n "$download_line" ]
    [ "$refuse_line" -lt "$download_line" ]
}
