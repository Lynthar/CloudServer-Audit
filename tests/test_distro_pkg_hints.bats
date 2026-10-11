#!/usr/bin/env bats
# The audit must not hand an operator a command that cannot run on their host:
# package names are not command names, and the manager comes from the distro.
# The hints are advice, never executed, so what is pinned is the wording.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh
    i18n_load en_US
}

# distro.sh reads its answers from globals rather than from the host, so a
# test can put itself on any distribution by assigning them.
_as_distro() {
    VPSSEC_DISTRO_FAMILY="$1"
    VPSSEC_PKG_MGR="$2"
}

# ==============================================================================
# The install / remove hints
# ==============================================================================

@test "install hint: each package manager gets its own verb" {
    _as_distro debian apt   && [ "$(pkg_install_hint aide)" = "apt install aide" ]
    _as_distro rhel   dnf   && [ "$(pkg_install_hint aide)" = "dnf install aide" ]
    _as_distro arch   pacman && [ "$(pkg_install_hint aide)" = "pacman -S aide" ]
    _as_distro suse   zypper && [ "$(pkg_install_hint aide)" = "zypper install aide" ]
}

@test "remove hint: apt purges, the others remove" {
    # purge, not remove: a disabled service whose config survives comes back
    # configured on the next reinstall.
    _as_distro debian apt    && [ "$(pkg_remove_hint telnetd)" = "apt purge telnetd" ]
    _as_distro rhel   dnf    && [ "$(pkg_remove_hint telnet-server)" = "dnf remove telnet-server" ]
    _as_distro arch   pacman && [ "$(pkg_remove_hint rsh)" = "pacman -Rns rsh" ]
}

@test "refresh hint: each manager's own command, and never pacman -Sy alone" {
    _as_distro debian apt    && [ "$(pkg_refresh_hint)" = "apt-get update" ]
    _as_distro rhel   dnf    && [ "$(pkg_refresh_hint)" = "dnf makecache" ]
    # Arch does not support partial upgrades: refresh and upgrade together.
    _as_distro arch   pacman && [ "$(pkg_refresh_hint)" = "pacman -Syu" ]
    _as_distro unknown unknown
    run pkg_refresh_hint
    [ "$status" -ne 0 ]
    [ -z "$output" ]
}

@test "hints: several packages arrive as one command" {
    _as_distro debian apt
    [ "$(pkg_install_hint jq iproute2)" = "apt install jq iproute2" ]
}

@test "hints: an unknown package manager refuses rather than guessing" {
    # The whole point. A default branch that fell back to apt would put this
    # right back where it started.
    _as_distro unknown unknown
    run pkg_install_hint aide
    [ "$status" -ne 0 ]
    [ -z "$output" ]

    run pkg_remove_hint telnetd
    [ "$status" -ne 0 ]
    [ -z "$output" ]
}

@test "hints: no packages is not a command" {
    _as_distro debian apt
    run pkg_install_hint
    [ "$status" -ne 0 ]
    [ -z "$output" ]
}

# ==============================================================================
# Command name -> package name
# ==============================================================================

@test "packages: ss is iproute on RHEL and iproute2 elsewhere" {
    # The one required command whose package differs across families, and the
    # reason this mapping exists at all.
    _as_distro rhel   dnf    && [ "$(distro_packages_for_commands ss)" = "iproute" ]
    _as_distro debian apt    && [ "$(distro_packages_for_commands ss)" = "iproute2" ]
    _as_distro arch   pacman && [ "$(distro_packages_for_commands ss)" = "iproute2" ]
}

@test "packages: systemctl and awk are not package names anywhere" {
    _as_distro debian apt
    [ "$(distro_packages_for_commands systemctl)" = "systemd" ]
    [ "$(distro_packages_for_commands awk)" = "gawk" ]
}

@test "packages: commands whose package shares their name pass through" {
    _as_distro debian apt
    [ "$(distro_packages_for_commands jq sed tar grep)" = "jq sed tar grep" ]
}

@test "packages: ps and pgrep are procps on Debian, procps-ng on RHEL and Arch" {
    _as_distro debian apt    && [ "$(distro_packages_for_commands ps pgrep)" = "procps procps" ]
    _as_distro rhel   dnf    && [ "$(distro_packages_for_commands ps pgrep)" = "procps-ng procps-ng" ]
    _as_distro arch   pacman && [ "$(distro_packages_for_commands pgrep)" = "procps-ng" ]
}

@test "packages: the mapping composes into one install command" {
    # End to end, on the exact dependency list the entry point checks.
    _as_distro rhel dnf
    local pkgs
    pkgs=$(distro_packages_for_commands jq ss systemctl sed awk tar grep)
    # shellcheck disable=SC2086
    [ "$(pkg_install_hint $pkgs)" = "dnf install jq iproute systemd sed gawk tar grep" ]
}

# ==============================================================================
# The package a distribution does not ship
# ==============================================================================

@test "integrity: AIDE is named where it is packaged and nowhere else" {
    # Arch keeps aide in the AUR, so `pacman -S aide` would have been one
    # unrunnable command swapped for another.
    _as_distro debian apt    && [ "$(distro_integrity_package)" = "aide" ]
    _as_distro rhel   dnf    && [ "$(distro_integrity_package)" = "aide" ]
    _as_distro arch   pacman && [ -z "$(distro_integrity_package)" ]
    _as_distro unknown unknown && [ -z "$(distro_integrity_package)" ]
}

# ==============================================================================
# What the operator actually reads
# ==============================================================================

_integrity_suggestion() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/baseline.sh"
    _vpssec_stub systemctl 1
    # On PATH, yet absent to check_command: the answer must come from the seam
    # a test controls, not from what this host happens to lack.
    local t
    for t in aide aide.wrapper tripwire samhain afick integrit; do
        _vpssec_stub "$t"
        _vpssec_absent_command "$t"
    done
    run _baseline_audit_integrity
    jq -r '.[] | select(.id == "baseline.integrity_missing") | .suggestion' \
        "$VPSSEC_STATE/checks.json"
}

@test "baseline: the integrity suggestion follows the distribution" {
    _as_distro rhel dnf
    [ "$(_integrity_suggestion)" = "Install a file integrity tool: dnf install aide" ]
}

@test "baseline: with no packaged tool the suggestion names no command" {
    _as_distro arch pacman

    local suggestion
    suggestion=$(_integrity_suggestion)
    [ "$suggestion" = "Install a file integrity tool (AIDE, Tripwire or Samhain)" ]
    # Stated as the operator would check it: no package manager is named.
    _vpssec_refute grep -qE 'apt|dnf|pacman|zypper' <<< "$suggestion"
}

# ==============================================================================
# Which package manager the hints are for
# ==============================================================================

# A directory of stand-ins for exactly the named tools: only their presence
# is ever asked about.
_tools_dir() {
    local d t
    d=$(mktemp -d "$BATS_TEST_TMPDIR/pm.XXXXXX")
    for t in "$@"; do
        : > "$d/$t"
        chmod +x "$d/$t"
    done
    echo "$d"
}

# _distro_pkg_mgr for family $1 on a PATH of just the tools named after it.
_pm_on() {
    local family="$1" d
    shift
    d=$(_tools_dir "$@")
    PATH="$d" _distro_pkg_mgr "$family"
}

@test "package manager: Arch with apt and dnf from its own repositories is still pacman" {
    # Arch's [extra] ships both; presence alone audited such a host as Debian.
    [ "$(_pm_on arch apt-get dnf pacman)" = pacman ]
}

@test "package manager: each known family takes its own tool when it is there" {
    [ "$(_pm_on rhel apt-get dnf)" = dnf ]
    [ "$(_pm_on rhel apt-get yum)" = dnf ]
    [ "$(_pm_on suse apt-get zypper)" = zypper ]
    [ "$(_pm_on debian dnf pacman apt-get)" = apt ]
}

@test "package manager: an unknown family, or a family missing its tool, goes by presence" {
    [ "$(_pm_on unknown pacman)" = pacman ]
    [ "$(_pm_on unknown zypper dnf)" = dnf ]
    [ "$(_pm_on arch apt-get)" = apt ]
    [ "$(_pm_on unknown)" = unknown ]
}

@test "package manager: detection hands the host's family to the choice" {
    _distro_osrelease_field() { [[ "$1" == ID ]] && echo arch || true; }
    VPSSEC_DISTRO_FAMILY=""
    local d
    d=$(_tools_dir apt-get pacman)
    PATH="$d" distro_detect
    [ "$VPSSEC_DISTRO_FAMILY" = arch ]
    [ "$VPSSEC_PKG_MGR" = pacman ]
}

@test "log paths: RHEL names no log whose own tool rotates it" {
    # dnf rotates dnf.rpm.log itself (log_size, log_rotate) and logrotate.d/dnf
    # names only hawkey.log, so listing it reports a stock RHEL host as unrotated.
    _as_distro rhel dnf
    [ "$(distro_log_paths)" = "messages secure" ]
}
