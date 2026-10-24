#!/usr/bin/env bats
# On Arch the entry scripts install a missing tool with a full -Syu: -Sy syncs
# the database and installs against it without upgrading the rest, the partial
# upgrade Arch does not support.

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

@test "run.sh: a missing tool is installed with pacman -Syu" {
    eval "$(awk '/^check_requirements\(\)/,/^}/' "$(_vpssec_repo_root)/run.sh")"
    VPSSEC_NO_VERIFY=1
    check_requirements
    [ "$(cat "$PACMAN_LOG")" = "pacman -Syu --noconfirm --needed curl" ]
}

@test "install.sh: a missing tool is installed with pacman -Syu" {
    eval "$(awk '/^check_system\(\)/,/^}/' "$(_vpssec_repo_root)/install.sh")"
    check_system
    [ "$(cat "$PACMAN_LOG")" = "pacman -Syu --noconfirm --needed curl" ]
}
