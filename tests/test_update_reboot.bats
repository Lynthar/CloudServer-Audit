#!/usr/bin/env bats
# Does the host need a reboot: pkg_reboot_required in core/distro.sh and the
# check update.sh emits from it. Three answers, because a container with no
# kernel package of its own cannot say "no reboot needed" any more than "yes".

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    export TMPDIR="$BATS_TEST_TMPDIR"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/update.sh"

    DISTRO_REBOOT_FLAG="$BATS_TEST_TMPDIR/reboot-required"
    DISTRO_MODULES_DIR="$BATS_TEST_TMPDIR/modules"
}

# ---- needrestart's batch output (NEEDRESTART-KSTA) ---------------------
# 0 = detection failed, 1 = kernel current, 2 = ABI-compatible upgrade
# pending, 3 = version upgrade pending (liske/needrestart).

@test "needrestart: KSTA=1 (current) → no reboot" {
    run _distro_needrestart_kernel_pending "NEEDRESTART-KCUR: 6.1.0-13-amd64
NEEDRESTART-KEXP: 6.1.0-13-amd64
NEEDRESTART-KSTA: 1"
    [ "$status" -eq 1 ]
}

@test "needrestart: KSTA=2 (ABI-compatible upgrade) → reboot pending" {
    # An ABI-compatible kernel still has to be booted to run.
    run _distro_needrestart_kernel_pending "NEEDRESTART-KSTA: 2"
    [ "$status" -eq 0 ]
}

@test "needrestart: KSTA=3 (version upgrade) → reboot pending" {
    run _distro_needrestart_kernel_pending "NEEDRESTART-KCUR: 6.1.0-13-amd64
NEEDRESTART-KEXP: 6.1.0-15-amd64
NEEDRESTART-KSTA: 3"
    [ "$status" -eq 0 ]
}

@test "needrestart: KSTA=0, missing or not a number → no answer" {
    run _distro_needrestart_kernel_pending "NEEDRESTART-KSTA: 0"
    [ "$status" -eq 2 ]
    run _distro_needrestart_kernel_pending "NEEDRESTART-VER: 3.6"
    [ "$status" -eq 2 ]
    run _distro_needrestart_kernel_pending "NEEDRESTART-KSTA: unknown"
    [ "$status" -eq 2 ]
}

@test "needrestart: only the first KSTA line is consulted" {
    run _distro_needrestart_kernel_pending "NEEDRESTART-KSTA: 3
NEEDRESTART-KSTA: 1"
    [ "$status" -eq 0 ]
}

# ---- the installed kernel on rpm hosts ---------------------------------

@test "rpm: no kernel package is no version, not the word in rpm's message" {
    # rpm prints "package kernel is not installed" on STDOUT and exits 1, so
    # discarding stderr is not enough: the first word came out as the version.
    VPSSEC_PKG_MGR=dnf
    _vpssec_stub rpm 1 'package kernel is not installed'
    run pkg_installed_kernel
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "rpm: the newest kernel package is given as uname -r would" {
    VPSSEC_PKG_MGR=dnf
    _vpssec_stub rpm 0 'kernel-5.14.0-503.el9.x86_64       Mon 01 Sep 2026 10:00:00 AM UTC'
    run pkg_installed_kernel
    [ "$output" = "5.14.0-503.el9.x86_64" ]
}

# ---- RHEL family: dnf needs-restarting ---------------------------------

# dnf answering needs-restarting with RC and STDOUT; any other subcommand fails.
_dnf_needs_restarting() {
    local rc="$1" out="$2"
    _vpssec_stub_script dnf <<SH
[[ " \$* " == *" needs-restarting -r "* ]] || exit 1
printf '%s\n' "$out"
exit $rc
SH
}

_rhel_host() {
    VPSSEC_DISTRO_FAMILY=rhel
    VPSSEC_PKG_MGR=dnf
    _vpssec_stub uname 0 '5.14.0-503.el9.x86_64'
}

@test "rhel: needs-restarting asking for a reboot is a reboot, with what changed" {
    # Recorded from Rocky 9 after a glibc update: rc 1 and this text.
    _rhel_host
    _dnf_needs_restarting 1 'Core libraries or services have been updated since boot-up:
  * glibc
  * dbus-daemon

Reboot is required to fully utilize these updates.
More information: https://access.redhat.com/solutions/27943'
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ "$output" = "glibc
dbus-daemon" ]
}

@test "rhel: needs-restarting saying none is believed" {
    # It covers the kernel too, so an rpm list that disagrees does not win.
    _rhel_host
    _dnf_needs_restarting 0 'No core libraries or services have been updated since boot-up.
Reboot should not be necessary.'
    _vpssec_stub rpm 0 'kernel-5.14.0-570.el9.x86_64       Mon 01 Sep 2026 10:00:00 AM UTC'
    run pkg_reboot_required
    [ "$status" -eq 1 ]
}

@test "rhel: needs-restarting is asked cache-only, its logs kept out of /var/log" {
    _rhel_host
    _dnf_needs_restarting 0 'Reboot should not be necessary.'
    run pkg_reboot_required
    _vpssec_stub_called dnf '-C --setopt=logdir=[^ ]+ needs-restarting -r'
}

@test "rhel: a dnf without the plugin falls back to the kernel, by its text not its rc" {
    # dnf exits 1 for "No such command" as for "reboot required".
    _rhel_host
    _vpssec_stub_script dnf <<'SH'
echo "No such command: needs-restarting. Please use /usr/bin/dnf --help" >&2
exit 1
SH
    _vpssec_stub rpm 0 'kernel-5.14.0-503.el9.x86_64       Mon 01 Sep 2026 10:00:00 AM UTC'
    run pkg_reboot_required
    [ "$status" -eq 1 ]

    _vpssec_stub rpm 0 'kernel-5.14.0-570.el9.x86_64       Mon 01 Sep 2026 10:00:00 AM UTC'
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ "$output" = "kernel: 5.14.0-503.el9.x86_64 → 5.14.0-570.el9.x86_64" ]
}

@test "rhel: no plugin and no kernel package is no answer" {
    # A container, or an LXC/OpenVZ VPS: the kernel is the host's.
    _rhel_host
    _vpssec_stub dnf 1
    _vpssec_stub rpm 1 'package kernel is not installed'
    run pkg_reboot_required
    [ "$status" -eq 2 ]
}

# ---- Debian family ------------------------------------------------------

_debian_host() {
    VPSSEC_DISTRO_FAMILY=debian
    VPSSEC_PKG_MGR=apt
    _vpssec_stub uname 0 '6.1.0-13-amd64'
    # needrestart present but answering nothing, unless a test says otherwise.
    _vpssec_stub needrestart 1
}

# dpkg-query listing installed kernel images.
_kernel_images() {
    local out="" k
    for k in "$@"; do out+="install ok installed	linux-image-$k"$'\n'; done
    _vpssec_stub dpkg-query 0 "${out%$'\n'}"
}

@test "debian: Ubuntu's reboot flag is a reboot, with its package list" {
    _debian_host
    : > "$DISTRO_REBOOT_FLAG"
    printf 'linux-image-6.8.0-45-generic\nlibc6\n' > "$DISTRO_REBOOT_FLAG.pkgs"
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ "$output" = "linux-image-6.8.0-45-generic
libc6" ]
}

@test "debian: the flag without its package list is still a reboot" {
    _debian_host
    : > "$DISTRO_REBOOT_FLAG"
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "debian: needrestart's pending kernel is a reboot, naming both kernels" {
    _debian_host
    _vpssec_stub needrestart 0 'NEEDRESTART-KCUR: 6.1.0-13-amd64
NEEDRESTART-KEXP: 6.1.0-15-amd64
NEEDRESTART-KSTA: 3'
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ "$output" = "kernel: 6.1.0-13-amd64 → 6.1.0-15-amd64" ]
}

@test "debian: needrestart's current kernel is believed over the package list" {
    _debian_host
    _vpssec_stub needrestart 0 'NEEDRESTART-KSTA: 1'
    _kernel_images 6.1.0-13-amd64 6.1.0-15-cloud-amd64
    run pkg_reboot_required
    [ "$status" -eq 1 ]
}

@test "debian: without needrestart, a newer kernel image is a reboot" {
    _debian_host
    _kernel_images 6.1.0-13-amd64 6.1.0-15-amd64
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ "$output" = "kernel: 6.1.0-13-amd64 → 6.1.0-15-amd64" ]

    _kernel_images 6.1.0-13-amd64
    run pkg_reboot_required
    [ "$status" -eq 1 ]
}

@test "debian: no flag, no needrestart answer and no kernel image is no answer" {
    # Every Debian container. This used to pass as "No reboot required".
    _debian_host
    _vpssec_stub dpkg-query 1
    run pkg_reboot_required
    [ "$status" -eq 2 ]
}

# ---- Arch and the rest ----------------------------------------------------

@test "arch: the newest modules directory against the running kernel" {
    VPSSEC_DISTRO_FAMILY=arch
    VPSSEC_PKG_MGR=pacman
    _vpssec_stub uname 0 '6.18.30-1-lts'
    mkdir -p "$DISTRO_MODULES_DIR/6.18.31-1-lts"
    run pkg_reboot_required
    [ "$status" -eq 0 ]
    [ "$output" = "kernel: 6.18.30-1-lts → 6.18.31-1-lts" ]

    rm -rf "$DISTRO_MODULES_DIR"
    run pkg_reboot_required
    [ "$status" -eq 2 ]
}

@test "an unknown family is no answer, not 'no reboot'" {
    VPSSEC_DISTRO_FAMILY=suse
    run pkg_reboot_required
    [ "$status" -eq 2 ]
}

# ---- what the audit emits --------------------------------------------------

_emitted() {
    jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
}

_desc() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

@test "audit: no answer is an unscored unknown, not 'no reboot required'" {
    pkg_reboot_required() { return 2; }
    _update_audit_reboot
    [ "$(_emitted)" = "update.reboot_state_unknown failed" ]
    [ "${CHECK_SCORE_CATEGORY[update.reboot_state_unknown]}" = "info" ]
}

@test "audit: a reboot lists what asked for it, without a trailing comma" {
    pkg_reboot_required() { printf 'glibc\ndbus-daemon\n'; }
    _update_audit_reboot
    [ "$(_emitted)" = "update.reboot_required failed" ]
    [ "$(_desc update.reboot_required)" = "Packages requiring reboot: glibc, dbus-daemon" ]
}

@test "audit: at most five are listed" {
    pkg_reboot_required() { printf '%s\n' a b c d e f g; }
    _update_audit_reboot
    [ "$(_desc update.reboot_required)" = "Packages requiring reboot: a, b, c, d, e" ]
}

@test "audit: a reboot with nothing to list says nothing about packages" {
    pkg_reboot_required() { return 0; }
    _update_audit_reboot
    [ "$(_emitted)" = "update.reboot_required failed" ]
    [ -z "$(_desc update.reboot_required)" ]
}

@test "audit: no reboot needed passes" {
    pkg_reboot_required() { return 1; }
    _update_audit_reboot
    [ "$(_emitted)" = "update.no_reboot passed" ]
}
