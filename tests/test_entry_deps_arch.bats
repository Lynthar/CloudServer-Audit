#!/usr/bin/env bats
# On Arch the entry scripts install nothing: there installing means a full -Syu
# (-Sy alone is the partial upgrade Arch does not support), and an audit or an
# installer must not upgrade the whole host unasked. They print the command instead.

load helpers.bash

setup() {
    _vpssec_load
    print_warn() { :; }; print_info() { :; }; print_ok() { :; }
    print_error() { echo "$*" >&2; }
    PACMAN_LOG="$BATS_TEST_TMPDIR/pacman.log"
    # An Arch host without curl: pacman is the only package manager there is.
    command() {
        if [[ "$1" == -v ]]; then
            case "$2" in
                curl|apt-get|dnf|yum) return 1 ;;
                pacman) return 0 ;;
            esac
        fi
        builtin command "$@"
    }
    pacman() { echo "pacman $*" >> "$PACMAN_LOG"; }
    id() { echo 0; }
}

@test "run.sh: a missing tool is named with the pacman command, and nothing is upgraded" {
    eval "$(awk '/^check_requirements\(\)/,/^}/' "$(_vpssec_repo_root)/run.sh")"
    VPSSEC_NO_VERIFY=1
    run check_requirements
    [ "$status" -eq 1 ]
    [[ "$output" == *"pacman -Syu --needed curl"* ]]
    [ ! -e "$PACMAN_LOG" ]
}

@test "install.sh: a missing tool is named with the pacman command, and nothing is upgraded" {
    eval "$(awk '/^check_system\(\)/,/^}/' "$(_vpssec_repo_root)/install.sh")"
    run check_system
    [ "$status" -eq 1 ]
    [[ "$output" == *"pacman -Syu --needed curl"* ]]
    [ ! -e "$PACMAN_LOG" ]
}
