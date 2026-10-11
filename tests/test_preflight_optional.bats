#!/usr/bin/env bats
# A missing optional tool is a check in the report, not a print: preflight
# only runs during the scan, when prints are silenced, so the old line only
# ever reached the log. Each capability needs any one of its tools.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    source "$(_vpssec_repo_root)/modules/preflight.sh"
    i18n_load en_US
    state_init
    VPSSEC_DISTRO_FAMILY=debian VPSSEC_PKG_MGR=apt
}

_optional_check() {
    jq -c '.[] | select(.id == "preflight.optional_missing")' "$STATE_CHECKS_FILE"
}

@test "optional: no menu tool and no lsof are one unscored check naming both" {
    _vpssec_stub curl 0
    _vpssec_absent_command whiptail
    _vpssec_absent_command dialog
    _vpssec_absent_command lsof
    _preflight_check_deps
    local c
    c=$(_optional_check)
    [ "$(jq -r '.status' <<<"$c")" = "failed" ]
    jq -r '.desc' <<<"$c" | grep -q 'menus (whiptail or dialog)'
    jq -r '.desc' <<<"$c" | grep -q 'package-lock check fallback (lsof)'
    _vpssec_refute grep -q 'curl or wget' <<<"$(jq -r '.desc' <<<"$c")"
    [ "$(jq -r '.suggestion' <<<"$c")" = "apt install dialog lsof" ]
    [ "${CHECK_SCORE_CATEGORY[preflight.optional_missing]}" = "info" ]
}

@test "optional: one tool of a pair is enough, and all present emits nothing" {
    # The old line listed dialog as missing next to a working whiptail.
    _vpssec_stub whiptail 0
    _vpssec_stub wget 0
    _vpssec_stub lsof 0
    _vpssec_absent_command dialog
    _vpssec_absent_command curl
    _preflight_check_deps
    [ -z "$(_optional_check)" ]
}

@test "optional: through the preflight audit, with prints silenced as in a scan" {
    _preflight_check_os() { :; }
    _preflight_check_network() { :; }
    _preflight_check_ports() { :; }
    _vpssec_absent_command curl
    _vpssec_absent_command wget
    _vpssec_stub whiptail 0
    _vpssec_stub lsof 0
    VPSSEC_QUIET_SCAN=1
    preflight_audit
    _optional_check | jq -r '.desc' | grep -q 'network reachability check (curl or wget)'
}

# ---- the package-lock check's tool follows the package manager ----------------
# pkg_manager_locked asks /proc/locks then lsof on apt, pgrep on dnf, and only a
# file test on pacman: telling a dnf host to install lsof fixes nothing.

@test "optional: a dnf host missing pgrep is told pgrep, in the package that ships it" {
    VPSSEC_DISTRO_FAMILY=rhel VPSSEC_PKG_MGR=dnf
    _vpssec_stub whiptail 0
    _vpssec_stub curl 0
    _vpssec_absent_command pgrep
    _vpssec_absent_command lsof
    _preflight_check_deps
    local c
    c=$(_optional_check)
    jq -r '.desc' <<<"$c" | grep -qF 'package-lock check (pgrep)'
    _vpssec_refute grep -q lsof <<<"$(jq -r '.desc' <<<"$c")"
    [ "$(jq -r '.suggestion' <<<"$c")" = "dnf install procps-ng" ]
}

@test "optional: a pacman host needs neither lsof nor pgrep" {
    VPSSEC_DISTRO_FAMILY=arch VPSSEC_PKG_MGR=pacman
    _vpssec_stub whiptail 0
    _vpssec_stub curl 0
    _vpssec_absent_command pgrep
    _vpssec_absent_command lsof
    _preflight_check_deps
    [ -z "$(_optional_check)" ]
}
