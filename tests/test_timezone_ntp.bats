#!/usr/bin/env bats
# The NTP check names the daemon that actually runs, and a systemctl that
# cannot answer is not "NTP disabled". timedated's NTP property is true when
# any unit in ntp-units.d runs, chrony's included, so it never names one.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/timezone.sh"
}

# systemctl on which the units named in $1 (space-separated) are active and
# every other `is-active` exits $2 (3: inactive; 1: no systemd to ask).
_units_active() {
    printf '%s\n' $1 > "$BATS_TEST_TMPDIR/active-units"
    _vpssec_stub_script systemctl <<SH
if [[ "\$1" == is-active ]]; then
    unit="\${@: -1}"
    grep -qx "\$unit" "$BATS_TEST_TMPDIR/active-units" && exit 0
    exit ${2:-3}
fi
exit 0
SH
}

# timedatectl as timedated answers when $1 runs: NTP=yes, NTPSynchronized=$2.
_timedated() {
    _vpssec_stub_script timedatectl <<SH
case "\$*" in
    *"property=NTPSynchronized"*) echo "$2" ;;
    *"property=NTP "*|*"property=NTP --"*) echo yes ;;
esac
exit 0
SH
}

_emitted() {
    jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
}

_field() {
    jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f] // ""' \
        "$VPSSEC_STATE/checks.json"
}

@test "chrony running: the check names chrony, not systemd-timesyncd" {
    # Debian/Ubuntu's chrony ships 50-chrony.list, so timedated says NTP=yes.
    _units_active "chrony"
    _timedated chrony no
    _vpssec_stub chronyc 0 "Leap status     : Normal"

    _timezone_check_ntp >/dev/null
    [ "$(_emitted)" = "timezone.ntp_synced passed" ]
    [ "$(_field timezone.ntp_synced title)" = "$(i18n 'timezone.ntp_synced' 'service=chrony')" ]
}

@test "RHEL's chronyd, not yet synchronised: named chrony, not systemd-timesyncd" {
    _units_active "chronyd"
    _timedated chronyd no
    _vpssec_stub chronyc 0 "Leap status     : Not synchronised"

    _timezone_check_ntp >/dev/null
    [ "$(_emitted)" = "timezone.ntp_not_synced failed" ]
    [[ "$(_field timezone.ntp_not_synced desc)" != *timesyncd* ]]
    [ "$(_field timezone.ntp_not_synced desc)" = "$(i18n 'timezone.ntp_not_synced_desc' 'service=chrony')" ]
}

@test "timesyncd running where timedated is unreachable is not NTP disabled" {
    # No D-Bus: timedatectl fails, but systemctl still sees the unit.
    _units_active "systemd-timesyncd"
    _vpssec_stub timedatectl 1

    _timezone_check_ntp >/dev/null
    [ "$(_emitted)" = "timezone.ntp_synced passed" ]
    [ "$(_field timezone.ntp_synced title)" = "$(i18n 'timezone.ntp_synced' 'service=systemd-timesyncd')" ]
}

@test "timesyncd running and not synchronised says so, naming it" {
    _units_active "systemd-timesyncd"
    _timedated systemd-timesyncd no

    _timezone_check_ntp >/dev/null
    [ "$(_emitted)" = "timezone.ntp_not_synced failed" ]
    [ "$(_field timezone.ntp_not_synced desc)" = "$(i18n 'timezone.ntp_not_synced_desc' 'service=systemd-timesyncd')" ]
}

@test "a systemctl that cannot answer is unknown and unscored, with no fix" {
    # Without it the SAFE enable_ntp was offered, and installing chrony
    # removes timesyncd (both Conflict: time-daemon).
    _units_active "" 1
    _vpssec_stub timedatectl 1

    _timezone_check_ntp >/dev/null
    [ "$(_emitted)" = "timezone.ntp_state_unknown failed" ]
    [ "${CHECK_SCORE_CATEGORY[timezone.ntp_state_unknown]}" = "info" ]
    [ -z "$(_field timezone.ntp_state_unknown fix_id)" ]
}

@test "no NTP unit running is NTP disabled, with the fix" {
    _units_active ""
    _vpssec_stub timedatectl 0 "no"

    _timezone_check_ntp >/dev/null
    [ "$(_emitted)" = "timezone.ntp_disabled failed" ]
    [ "$(_field timezone.ntp_disabled fix_id)" = "timezone.enable_ntp" ]
}
