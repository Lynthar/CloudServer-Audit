#!/usr/bin/env bats
#
# Regression tests for _update_unattended_periodic_from_dump and
# _update_unattended_origins_from_dump. Original audit only verified
# `APT::Periodic::Unattended-Upgrade "1"` in /etc/apt/apt.conf.d/20auto-upgrades,
# missing the case where 50unattended-upgrades or a drop-in clears the
# Allowed-Origins/Origins-Pattern list — u-u then runs but updates nothing.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/update.sh"
}

# ---------- periodic flag (APT::Periodic::Unattended-Upgrade) ----------

@test "periodic: flag set to 1 → enabled" {
    run _update_unattended_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "1";'
    [ "$status" -eq 0 ]
}

@test "periodic: flag set to 0 → disabled" {
    run _update_unattended_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "0";'
    [ "$status" -ne 0 ]
}

@test "periodic: flag absent → disabled" {
    run _update_unattended_periodic_from_dump 'APT::Periodic::Update-Package-Lists "1";'
    [ "$status" -ne 0 ]
}

@test "periodic: drop-in re-set to 0 wins (last-write semantics in dump)" {
    # apt-config dump emits one final line per scalar key after merging
    # all drop-ins; if 20auto-upgrades sets 1 and 99-local sets 0, only
    # the latter appears. Our awk takes the first match, so simulate the
    # merged result directly.
    local dump='APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::AutocleanInterval "7";'
    run _update_unattended_periodic_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "periodic: ignores APT::Periodic::Update-Package-Lists" {
    local dump='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "0";'
    run _update_unattended_periodic_from_dump "$dump"
    [ "$status" -ne 0 ]
}

# ---------- origins (Origins-Pattern / Allowed-Origins) ----------

@test "origins: stock Debian Origins-Pattern → effective" {
    # Three lines active in the shipped 50unattended-upgrades.Debian.
    local dump='Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm,label=Debian";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm,label=Debian-Security";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm-security,label=Debian-Security";'
    run _update_unattended_origins_from_dump "$dump"
    [ "$status" -eq 0 ]
}

@test "origins: stock Ubuntu Allowed-Origins → effective" {
    local dump='Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESMApps:${distro_codename}-apps-security";'
    run _update_unattended_origins_from_dump "$dump"
    [ "$status" -eq 0 ]
}

@test "origins: only the empty anchor present → not effective (regression)" {
    # The exact case the H4 fix exists to catch: u-u config reduced to
    # an empty list (user commented every entry, or a drop-in cleared
    # it). apt-config dump still emits the anchor line but no `::`
    # element — should be reported as ineffective.
    local dump='Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Package-Blacklist "";'
    run _update_unattended_origins_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "origins: completely absent → not effective" {
    local dump='APT::Architecture "amd64";
APT::Build-Essential "build-essential";'
    run _update_unattended_origins_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "origins: anchor with whitespace-only quoted value → not effective" {
    # Defensive: the regex requires non-empty in the quoted value of a
    # list element. A list element with empty string should NOT count.
    local dump='Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "";'
    run _update_unattended_origins_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "origins: only Allowed-Origins set, no Origins-Pattern → effective" {
    # Older configs use Allowed-Origins; either one is sufficient.
    local dump='Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";'
    run _update_unattended_origins_from_dump "$dump"
    [ "$status" -eq 0 ]
}
