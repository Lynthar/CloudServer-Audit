#!/usr/bin/env bats
# Regression tests for the apt-config dump readers in core/distro.sh, shared by
# the audit and the unattended-upgrades fix. Checking 20auto-upgrades alone
# misses a drop-in that clears Allowed-Origins: u-u runs and updates nothing.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/distro.sh"
}

# ---------- periodic flag (APT::Periodic::Unattended-Upgrade) ----------

@test "periodic: flag set to 1 → enabled" {
    run _auto_update_apt_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "1";'
    [ "$status" -eq 0 ]
}

@test "periodic: flag set to 0 → disabled" {
    run _auto_update_apt_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "0";'
    [ "$status" -ne 0 ]
}

@test "periodic: flag absent → disabled" {
    run _auto_update_apt_periodic_from_dump 'APT::Periodic::Update-Package-Lists "1";'
    [ "$status" -ne 0 ]
}

@test "periodic: drop-in re-set to 0 wins (last-write semantics in dump)" {
    # apt-config dump emits one final line per scalar key after merging all
    # drop-ins, and the awk takes the first match, so simulate the merged result.
    local dump='APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::AutocleanInterval "7";'
    run _auto_update_apt_periodic_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "periodic: a repeated key is read as its first occurrence" {
    # apt-config dump emits one merged line per scalar key, so this input is
    # artificial — but it is what pins the awk's "first match wins" exit: dropping
    # it makes awk print "1\n0", which compares unequal and flips the answer.
    local dump='APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Unattended-Upgrade "0";'
    run _auto_update_apt_periodic_from_dump "$dump"
    [ "$status" -eq 0 ]
}

@test "periodic: ignores APT::Periodic::Update-Package-Lists" {
    local dump='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "0";'
    run _auto_update_apt_periodic_from_dump "$dump"
    [ "$status" -ne 0 ]
}

# ---------- origins (Origins-Pattern / Allowed-Origins) ----------

@test "origins: stock Debian Origins-Pattern → effective" {
    # Three lines active in the shipped 50unattended-upgrades.Debian.
    local dump='Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm,label=Debian";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm,label=Debian-Security";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm-security,label=Debian-Security";'
    run _auto_update_apt_origins_from_dump "$dump"
    [ "$status" -eq 0 ]
}

@test "origins: stock Ubuntu Allowed-Origins → effective" {
    local dump='Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESMApps:${distro_codename}-apps-security";'
    run _auto_update_apt_origins_from_dump "$dump"
    [ "$status" -eq 0 ]
}

@test "origins: only the empty anchor present → not effective (regression)" {
    # u-u config reduced to an empty list (every entry commented, or a drop-in
    # cleared it): apt-config dump still emits the anchor line but no `::`
    # element, and that must be reported as ineffective.
    local dump='Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Package-Blacklist "";'
    run _auto_update_apt_origins_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "origins: completely absent → not effective" {
    local dump='APT::Architecture "amd64";
APT::Build-Essential "build-essential";'
    run _auto_update_apt_origins_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "origins: anchor with whitespace-only quoted value → not effective" {
    # Defensive: the regex requires non-empty in the quoted value of a
    # list element. A list element with empty string should NOT count.
    local dump='Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "";'
    run _auto_update_apt_origins_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "origins: only Allowed-Origins set, no Origins-Pattern → effective" {
    # Older configs use Allowed-Origins; either one is sufficient.
    local dump='Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";'
    run _auto_update_apt_origins_from_dump "$dump"
    [ "$status" -eq 0 ]
}
