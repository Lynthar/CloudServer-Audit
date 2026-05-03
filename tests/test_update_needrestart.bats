#!/usr/bin/env bats
#
# Regression tests for _update_needrestart_kernel_pending (M16).
# /var/run/reboot-required is created by the update-notifier-common
# package — installed by default on Ubuntu, NOT installed on stock
# Debian. needrestart (default-installed on Debian 12+) is the
# distro-agnostic kernel-reboot signal; this helper parses its
# batch-mode output.
#
# NEEDRESTART-KSTA values per liske/needrestart docs:
#   0 = detection failure
#   1 = no upgrade pending (kernel current)
#   2 = ABI-compat upgrade pending (reboot to run new version)
#   3 = full version upgrade pending (reboot mandatory)

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/update.sh"
}

@test "needrestart: KSTA=1 (current) → no reboot pending" {
    local out="NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.1.0-13-amd64
NEEDRESTART-KEXP: 6.1.0-13-amd64
NEEDRESTART-KSTA: 1"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -ne 0 ]
}

@test "needrestart: KSTA=2 (ABI-compat upgrade) → reboot pending" {
    local out="NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.1.0-12-amd64
NEEDRESTART-KEXP: 6.1.0-13-amd64
NEEDRESTART-KSTA: 2"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -eq 0 ]
}

@test "needrestart: KSTA=3 (version upgrade) → reboot pending (regression)" {
    # The case M16 fixes: pure Debian box, kernel updated, no
    # /var/run/reboot-required because update-notifier-common isn't
    # installed. needrestart sees the version delta and reports KSTA=3.
    local out="NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.1.0-13-amd64
NEEDRESTART-KEXP: 6.1.0-15-amd64
NEEDRESTART-KSTA: 3"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -eq 0 ]
}

@test "needrestart: KSTA=0 (detection failed) → not pending (conservative)" {
    local out="NEEDRESTART-VER: 3.6
NEEDRESTART-KSTA: 0"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -ne 0 ]
}

@test "needrestart: KSTA missing → not pending" {
    local out="NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.1.0-13-amd64"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -ne 0 ]
}

@test "needrestart: only first KSTA line is consulted" {
    # Defensive against duplicated batch output.
    local out="NEEDRESTART-KSTA: 3
NEEDRESTART-KSTA: 1"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -eq 0 ]
}

@test "needrestart: non-numeric KSTA (corrupt output) → not pending" {
    local out="NEEDRESTART-KSTA: unknown"
    run _update_needrestart_kernel_pending "$out"
    [ "$status" -ne 0 ]
}
