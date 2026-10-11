#!/usr/bin/env bats
# Which start-up menus a terminal gets. The module menu belongs to audit and
# guide: rollback and status skip it, or it reads the answer typed for rollback's
# own prompt. The language menu is skipped once VPSSEC_LANG names a language.

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

# The language menu with VPSSEC_LANG=$1 exported by the operator (none when $1 is
# empty); prints the language it settles on. setsid as above.
_select_language_with() {
    setsid -w env -u VPSSEC_LANG -u VPSSEC_LANG_SET ${1:+VPSSEC_LANG=$1} bash -c '
        source "$1/core/common.sh"
        _tty_readable() { return 0; }
        unset VPSSEC_YES VPSSEC_JSON_ONLY
        select_language
        echo "lang=$VPSSEC_LANG"
    ' _ "$(_vpssec_repo_root)"
}

@test "language menu: VPSSEC_LANG in the environment answers it, as --lang does" {
    run _select_language_with en_US
    [ "$status" -eq 0 ]
    [ "$output" = "lang=en_US" ]
}

@test "language menu: without VPSSEC_LANG a terminal still gets it" {
    run _select_language_with ""
    [ "$status" -eq 0 ]
    [[ "$output" == *"Select language"* ]]
}
