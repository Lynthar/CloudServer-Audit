#!/usr/bin/env bats
# "No firewall" is one fact and gets one finding, carried by the id whose fix
# resolves it: ufw.disabled when UFW is installed, ufw.not_installed on
# Debian/Ubuntu, ufw.no_firewall elsewhere (no UFW fix offered there).

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"
    fw_backend() { echo none; }
}

_findings() { jq -r '[.[] | "\(.id) \(.severity) \(if (.fix_id // "") == "" then "-" else .fix_id end)"] | join(",")' "$VPSSEC_STATE/checks.json"; }

@test "no firewall, Debian, no UFW: one finding, the install" {
    VPSSEC_DISTRO_FAMILY=debian
    _vpssec_absent_command ufw
    ufw_audit
    [ "$(_findings)" = "ufw.not_installed medium ufw.install" ]
}

@test "no firewall, RHEL, no UFW: one finding and no UFW fix" {
    VPSSEC_DISTRO_FAMILY=rhel
    _vpssec_absent_command ufw
    ufw_audit
    [ "$(_findings)" = "ufw.no_firewall medium -" ]
}

@test "no firewall, Arch, UFW installed but off: only that it is disabled" {
    VPSSEC_DISTRO_FAMILY=arch
    _vpssec_stub ufw 0 "Status: inactive"
    ufw_audit
    [ "$(_findings)" = "ufw.disabled medium ufw.enable" ]
}
