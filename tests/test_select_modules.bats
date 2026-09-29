#!/usr/bin/env bats
# The module menu belongs to audit and guide. rollback and status must skip it
# even on a terminal, or it reads the answer typed for rollback's own prompt.

load helpers.bash

# setsid: no controlling terminal, so a menu that is reached reads EOF from
# /dev/tty and falls through instead of waiting on whoever runs the suite.
_select_modules_as() {
    setsid -w bash -c '
        source "$1/core/common.sh"
        _tty_readable() { return 0; }
        unset VPSSEC_INCLUDE VPSSEC_YES VPSSEC_JSON_ONLY
        VPSSEC_MODE="$2" VPSSEC_LANG=en_US select_modules
    ' _ "$(_vpssec_repo_root)" "$1"
}

@test "rollback and status skip the module menu on a terminal" {
    for m in rollback status; do
        run _select_modules_as "$m"
        [ "$status" -eq 0 ]
        [ -z "$output" ]
    done
}

@test "audit and guide still show it" {
    for m in audit guide; do
        run _select_modules_as "$m"
        [ "$status" -eq 0 ]
        [[ "$output" == *"Select modules to check:"* ]]
    done
}
