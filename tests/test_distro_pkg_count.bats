#!/usr/bin/env bats
# The update-count primitives in core/distro.sh, against package managers that
# behave like the real ones: apt keeps back an upgrade needing a new package
# unless asked not to, and an apt or dnf query writes to /var unless told not to.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh
    export TMPDIR="$BATS_TEST_TMPDIR"
    written="$BATS_TEST_TMPDIR/written"
    mkdir -p "$written"
}

# apt-get as apt behaves on a Debian 12 host whose kernel security update is an
# ABI bump: the metapackage needs a new linux-image package, so a plain upgrade
# keeps it back. Recorded: a bookworm container, 2026-10-07. Every simulation
# rebuilds stale binary caches and overwrites eipp.log.xz unless told not to.
_apt_kernel_abi_bump() {
    VPSSEC_PKG_MGR=apt
    _vpssec_stub_script apt-get <<SH
args=" \$* "
[[ "\$args" == *" Dir::Cache::pkgcache= "* ]] || touch "$written/pkgcache.bin"
[[ "\$args" == *" Dir::Log::Planner=/dev/null "* ]] || touch "$written/eipp.log.xz"
echo "Inst tzdata [2026b-0+deb12u1] (2026c-0+deb12u1 Debian-Security:12/oldstable-security [all])"
echo "Inst base-files [12.4+deb12u14] (12.4+deb12u15 Debian:12.15/oldstable [arm64])"
if [[ "\$args" == *" --with-new-pkgs "* ]]; then
    echo "Inst apparmor (3.0.8-3 Debian:12.15/oldstable [arm64])"
    echo "Inst linux-image-6.1.0-53-arm64 (6.1.187-1 Debian-Security:12/oldstable-security [arm64])"
    echo "Inst linux-image-arm64 [6.1.176-1] (6.1.187-1 Debian-Security:12/oldstable-security [arm64])"
else
    echo "The following packages have been kept back:"
    echo "  linux-image-arm64"
fi
echo "Conf tzdata (2026c-0+deb12u1 Debian-Security:12/oldstable-security [all])"
exit 0
SH
}

@test "apt: an upgrade kept back for a new dependency is still pending" {
    # The kernel security update is the one a plain `apt-get -s upgrade` hid.
    _apt_kernel_abi_bump
    run pkg_update_count
    [ "$status" -eq 0 ]
    [ "$output" = "3" ]
    run pkg_security_update_count
    [ "$output" = "2" ]
}

@test "apt: the new packages an upgrade pulls in are not counted as updates" {
    # apparmor (a Recommends) and the new ABI's image are installs, not
    # upgrades: counting them reported 5 pending where apt lists 3.
    _apt_kernel_abi_bump
    run pkg_update_count
    [ "$output" = "3" ]
}

@test "apt: the query writes neither binary caches nor the planner log" {
    _apt_kernel_abi_bump
    pkg_update_count >/dev/null
    pkg_security_update_count >/dev/null
    [ -z "$(ls -A "$written")" ]
}

@test "apt: a query that fails is a failure, not zero" {
    VPSSEC_PKG_MGR=apt
    _vpssec_stub apt-get 100
    run pkg_update_count
    [ "$status" -ne 0 ]
    [ -z "$output" ]
    run pkg_security_update_count
    [ "$status" -ne 0 ]
    [ -z "$output" ]
}

# dnf as it behaves on RHEL 8-10: every query appends to dnf.log and friends in
# its logdir, /var/log unless --setopt=logdir moves it.
_dnf_logging() {
    VPSSEC_PKG_MGR=dnf
    _vpssec_stub_script dnf <<SH
logdir="$written/var-log"
for a in "\$@"; do [[ "\$a" == --setopt=logdir=* ]] && logdir="\${a#--setopt=logdir=}"; done
mkdir -p "\$logdir" && echo query >> "\$logdir/dnf.log"
echo "\$logdir" >> "$BATS_TEST_TMPDIR/logdirs"
case " \$* " in
    *" check-update --security "*)
        printf '%s\n' "openssl.x86_64  1:3.0.7-28.el9  baseos"; exit 100 ;;
    *" check-update "*)
        printf '%s\n' "openssl.x86_64  1:3.0.7-28.el9  baseos" "vim-data.noarch  2:9.1-9.el9  baseos"
        exit 100 ;;
esac
exit 1
SH
}

@test "dnf: queries leave no log behind, in /var/log or anywhere else" {
    _dnf_logging
    run pkg_update_count
    [ "$output" = "2" ]
    run pkg_security_update_count
    [ "$output" = "1" ]

    [ ! -e "$written/var-log" ]
    local d
    while read -r d; do [ ! -e "$d" ]; done < "$BATS_TEST_TMPDIR/logdirs"
}

@test "dnf: the security count is the installed packages with a security update" {
    # Not updateinfo's list, which names every package in an applicable
    # advisory: on Rocky 9 that was 155 against 45 packages to update.
    _dnf_logging
    run pkg_security_update_count
    [ "$status" -eq 0 ]
    [ "$output" = "1" ]
    _vpssec_stub_called dnf 'check-update --security'
    _vpssec_refute _vpssec_stub_called dnf 'updateinfo'
}

@test "dnf: a security query that fails is a failure, not zero" {
    VPSSEC_PKG_MGR=dnf
    _vpssec_stub dnf 1
    run pkg_security_update_count
    [ "$status" -ne 0 ]
    [ -z "$output" ]
}

# ---- how old the apt index is -------------------------------------------

_apt_index() {
    VPSSEC_PKG_MGR=apt
    DISTRO_APT_LISTS="$BATS_TEST_TMPDIR/lists"
    DISTRO_APT_STAMP="$BATS_TEST_TMPDIR/periodic/update-success-stamp"
    mkdir -p "$DISTRO_APT_LISTS" "${DISTRO_APT_STAMP%/*}"
}

@test "index age: a manual apt-get update counts, not only apt-daily's stamp" {
    # The stamp is written by apt-daily alone. Preferring it whenever it
    # existed aged a host whose operator runs `apt-get update` by hand.
    _apt_index
    touch -d '100 days ago' "$DISTRO_APT_STAMP"
    touch -d '2 days ago' "$DISTRO_APT_LISTS/deb.debian.org_debian_dists_bookworm_InRelease"
    run pkg_index_age_days
    [ "$output" = "2" ]
}

@test "index age: apt-daily's stamp counts when it is the newest" {
    _apt_index
    touch -d '40 days ago' "$DISTRO_APT_LISTS/deb.debian.org_debian_dists_bookworm_InRelease"
    touch -d '1 day ago' "$DISTRO_APT_STAMP"
    run pkg_index_age_days
    [ "$output" = "1" ]
}

@test "index age: an index never refreshed has no age at all" {
    _apt_index
    touch "$DISTRO_APT_LISTS/lock"
    run pkg_index_age_days
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}
