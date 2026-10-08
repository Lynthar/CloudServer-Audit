#!/usr/bin/env bats
# auto_update_status in core/distro.sh, shared by the audit and the unattended-
# upgrades fix: its apt-config dump and automatic.conf readers, and the timers it
# asks. Each mechanism has more than one way to say "on", and a way to look on.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/distro.sh"
}

# ---------- intervals, as apt.systemd.daily reads them ----------

@test "interval: every value apt.systemd.daily runs on is on" {
    # A number is days unless suffixed s/m/h/d; "always" runs every time, and
    # so do "00" and "0d" — only the literal "0" short-circuits.
    local v
    for v in 1 7 always 12h 30m 3600s 1d 00 0d; do
        _auto_update_apt_interval_on "$v" || { echo "read as off: $v"; return 1; }
    done
}

@test "interval: a bare 0, no value, or a word the script dies on is off" {
    # dash aborts apt.systemd.daily on `$((yes*86400))`, so nothing runs.
    local v
    for v in 0 "" yes true; do
        _vpssec_refute _auto_update_apt_interval_on "$v" || { echo "read as on: $v"; return 1; }
    done
}

# ---------- the install half (APT::Periodic::Unattended-Upgrade) ----------

@test "periodic: flag set to 1 → enabled" {
    run _auto_update_apt_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "1";'
    [ "$status" -eq 0 ]
}

@test "periodic: a weekly interval or \"always\" is enabled too" {
    run _auto_update_apt_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "7";'
    [ "$status" -eq 0 ]
    run _auto_update_apt_periodic_from_dump 'APT::Periodic::Unattended-Upgrade "always";'
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

@test "periodic: a repeated key is read as its first occurrence" {
    # apt-config dump emits one merged line per scalar key, so this input is
    # artificial — but it is what pins the reader's "first match wins" exit:
    # without it the value comes out as "1\n0", which is not a valid interval.
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

@test "periodic: a key that only starts with the name is a different key" {
    local dump='APT::Periodic::Unattended-Upgrade-Foo "1";'
    run _auto_update_apt_periodic_from_dump "$dump"
    [ "$status" -ne 0 ]
}

@test "periodic: APT::Periodic::Enable at numeric 0 switches everything off" {
    # apt.systemd.daily exits on `[ $AutoAptEnable -eq 0 ]`; a word fails that
    # test and the script carries on.
    local on='APT::Periodic::Unattended-Upgrade "1";'
    run _auto_update_apt_periodic_from_dump "APT::Periodic::Enable \"0\";
$on"
    [ "$status" -ne 0 ]
    run _auto_update_apt_periodic_from_dump "APT::Periodic::Enable \"00\";
$on"
    [ "$status" -ne 0 ]
    run _auto_update_apt_periodic_from_dump "APT::Periodic::Enable \"1\";
$on"
    [ "$status" -eq 0 ]
    run _auto_update_apt_periodic_from_dump "APT::Periodic::Enable \"false\";
$on"
    [ "$status" -eq 0 ]
}

# ---------- the refresh half (APT::Periodic::Update-Package-Lists) ----------

@test "refresh: the index refresh interval is read on its own" {
    run _auto_update_apt_refresh_from_dump 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "0";'
    [ "$status" -eq 0 ]
    run _auto_update_apt_refresh_from_dump 'APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "1";'
    [ "$status" -ne 0 ]
    run _auto_update_apt_refresh_from_dump 'APT::Periodic::Unattended-Upgrade "1";'
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

# ---------- dnf-automatic's apply_updates ----------

@test "dnf: apply_updates is true in every spelling libdnf accepts" {
    local v
    for v in yes Yes YES true True 1 on ON; do
        _auto_update_dnf_applies "[commands]
apply_updates = $v" || { echo "read as off: $v"; return 1; }
    done
}

@test "dnf: apply_updates off, absent, or commented out is download-only" {
    local conf
    for conf in "apply_updates = no" "apply_updates = False" "apply_updates = 0" \
                "download_updates = yes" "# apply_updates = yes"; do
        _vpssec_refute _auto_update_dnf_applies "[commands]
$conf" || { echo "read as on: $conf"; return 1; }
    done
}

@test "dnf: the last apply_updates line is the one that counts" {
    run _auto_update_dnf_applies "apply_updates = no
apply_updates = yes"
    [ "$status" -eq 0 ]
}

# ---------- auto_update_status: which timers it asks ----------

# systemctl answering is-enabled from a list of enabled units.
_timers_enabled() {
    _vpssec_stub_script systemctl <<SH
[[ "\$1" == "is-enabled" ]] || exit 0
for u in $*; do [[ "\$2" == "\$u" ]] && { echo enabled; exit 0; }; done
echo disabled; exit 1
SH
}

_apt_config_dump() {
    _vpssec_stub_script apt-config <<SH
cat <<'DUMP'
$1
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=\${distro_codename}-security,label=Debian-Security";
DUMP
SH
}

@test "status: apt with both timers and both intervals on is ok" {
    VPSSEC_PKG_MGR=apt
    _timers_enabled apt-daily.timer apt-daily-upgrade.timer
    _apt_config_dump 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
    run auto_update_status
    [ "$status" -eq 0 ]
    [ "$output" = "ok" ]
}

@test "status: apt with the index refresh timer off is not ok" {
    # apt-daily-upgrade only installs; without apt-daily the index never moves,
    # so unattended-upgrade keeps finding nothing new to install.
    VPSSEC_PKG_MGR=apt
    _timers_enabled apt-daily-upgrade.timer
    _apt_config_dump 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
    run auto_update_status
    [ "$status" -ne 0 ]
    [ "$output" = "refresh_disabled" ]
}

@test "status: apt with the refresh interval at 0 is not ok" {
    VPSSEC_PKG_MGR=apt
    _timers_enabled apt-daily.timer apt-daily-upgrade.timer
    _apt_config_dump 'APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "1";'
    run auto_update_status
    [ "$output" = "refresh_disabled" ]
}

@test "status: apt with the install timer off is still reported as such" {
    VPSSEC_PKG_MGR=apt
    _timers_enabled apt-daily.timer
    _apt_config_dump 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
    run auto_update_status
    [ "$output" = "service_disabled" ]
}

@test "status: dnf with the -install timer is ok whatever apply_updates says" {
    # It runs dnf-automatic --installupdates, which overrides the config file.
    VPSSEC_PKG_MGR=dnf
    DISTRO_DNF_AUTOMATIC_CONF="$BATS_TEST_TMPDIR/automatic.conf"
    printf '[commands]\napply_updates = no\n' > "$DISTRO_DNF_AUTOMATIC_CONF"
    _timers_enabled dnf-automatic-install.timer
    run auto_update_status
    [ "$status" -eq 0 ]
    [ "$output" = "ok" ]
}

@test "status: dnf with the plain timer follows apply_updates" {
    VPSSEC_PKG_MGR=dnf
    DISTRO_DNF_AUTOMATIC_CONF="$BATS_TEST_TMPDIR/automatic.conf"
    _timers_enabled dnf-automatic.timer
    printf '[commands]\napply_updates = True\n' > "$DISTRO_DNF_AUTOMATIC_CONF"
    run auto_update_status
    [ "$output" = "ok" ]
    printf '[commands]\napply_updates = no\n' > "$DISTRO_DNF_AUTOMATIC_CONF"
    run auto_update_status
    [ "$output" = "periodic_off" ]
}

@test "status: dnf timers that never install are not ok" {
    VPSSEC_PKG_MGR=dnf
    DISTRO_DNF_AUTOMATIC_CONF="$BATS_TEST_TMPDIR/automatic.conf"
    printf '[commands]\napply_updates = yes\n' > "$DISTRO_DNF_AUTOMATIC_CONF"
    _timers_enabled dnf-automatic-download.timer dnf-automatic-notifyonly.timer
    run auto_update_status
    [ "$status" -ne 0 ]
    [ "$output" = "service_disabled" ]
}
