#!/usr/bin/env bats
# The OS line names the release as os-release does: a distribution without a
# VERSION_CODENAME (RHEL, Arch) gets no "(unknown)" after it.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    source "$(_vpssec_repo_root)/modules/preflight.sh"
    i18n_load en_US
    state_init
    is_supported_os() { return 0; }
}

_os_desc() {
    jq -r '.[] | select(.id == "preflight.os_supported") | .desc' "$STATE_CHECKS_FILE"
}

@test "os: a release without a codename is named without one" {
    detect_os() { echo almalinux; }
    detect_os_version() { echo 9.8; }
    detect_os_codename() { echo unknown; }
    _preflight_check_os >/dev/null
    [ "$(_os_desc)" = "almalinux 9.8" ]
}

@test "os: a release with a codename keeps it" {
    detect_os() { echo ubuntu; }
    detect_os_version() { echo 22.04; }
    detect_os_codename() { echo jammy; }
    _preflight_check_os >/dev/null
    [ "$(_os_desc)" = "ubuntu 22.04 (jammy)" ]
}
