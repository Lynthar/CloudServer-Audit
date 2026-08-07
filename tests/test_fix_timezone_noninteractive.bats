#!/usr/bin/env bats
#
# Regression tests for _timezone_current and the non-interactive guard in
# _timezone_fix_set_timezone.
#
# timezone.set_timezone is offered on the PASSING checks too (using_utc /
# configured) so a guide user can change the timezone on purpose. While it
# was classified FIX_SAFE that made a select-all run reach an interactive
# menu on a host whose timezone was already correct, and under --yes /
# --json-only / no readable /dev/tty the menu could never be answered, so
# the fix returned 1 and the engine recorded a failure for something the
# operator never requested.
#
# The interactive branch itself is out of scope here — it needs a real tty.
# What these tests pin down is that a non-interactive run never reaches it.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/timezone.sh"

    etc=$(_vpssec_fake_etc)
    TZ_CONF="$etc/timezone"
    TZ_LOCALTIME="$etc/localtime"
    TZ_ZONEINFO="$etc/zoneinfo"
    mkdir -p "$TZ_ZONEINFO/Asia"
    : > "$TZ_ZONEINFO/Asia/Shanghai"

    unset TZ
}

# ---- the shared getter ----------------------------------------------

@test "timezone getter: timedatectl wins when it answers" {
    _vpssec_stub timedatectl 0 'Asia/Shanghai'
    printf 'Europe/Berlin\n' > "$TZ_CONF"

    run _timezone_current
    [ "$output" = "Asia/Shanghai|timedatectl" ]
}

@test "timezone getter: falls back to the timezone file" {
    _vpssec_stub timedatectl 0 ''
    printf 'Europe/Berlin\n' > "$TZ_CONF"

    run _timezone_current
    [ "$output" = "Europe/Berlin|$TZ_CONF" ]
}

@test "timezone getter: falls back to the localtime symlink" {
    _vpssec_stub timedatectl 0 ''
    ln -sf "$TZ_ZONEINFO/Asia/Shanghai" "$TZ_LOCALTIME"

    run _timezone_current
    [ "$output" = "Asia/Shanghai|$TZ_LOCALTIME" ]
}

@test "timezone getter: reports empty when nothing is configured" {
    _vpssec_stub timedatectl 0 ''

    run _timezone_current
    [ "${output%%|*}" = "" ]
}

# ---- the non-interactive guard --------------------------------------

@test "set_timezone: --yes on a configured host succeeds without changing anything" {
    _vpssec_stub timedatectl 0 'Asia/Shanghai'
    printf 'Asia/Shanghai\n' > "$TZ_CONF"
    export VPSSEC_YES=1

    run _timezone_fix_set_timezone
    [ "$status" -eq 0 ]
    [ "$(cat "$TZ_CONF")" = "Asia/Shanghai" ]
    ! _vpssec_stub_called timedatectl 'set-timezone'
}

@test "set_timezone: --yes on a host with no timezone reports failure" {
    # Nothing to preserve and no way to ask — the honest answer is "this
    # one needs a human", not a silent success.
    _vpssec_stub timedatectl 0 ''
    export VPSSEC_YES=1

    run _timezone_fix_set_timezone
    [ "$status" -eq 1 ]
}

@test "set_timezone: --json-only is treated as non-interactive too" {
    _vpssec_stub timedatectl 0 'Asia/Shanghai'
    export VPSSEC_JSON_ONLY=1

    run _timezone_fix_set_timezone
    [ "$status" -eq 0 ]
    ! _vpssec_stub_called timedatectl 'set-timezone'
}

@test "set_timezone: no interactive menu is printed on a non-interactive run" {
    # The old behaviour parked on a 1-9 menu. Nothing resembling it may
    # reach stdout when the operator cannot answer.
    _vpssec_stub timedatectl 0 'Asia/Shanghai'
    export VPSSEC_YES=1

    run _timezone_fix_set_timezone
    ! grep -q 'Asia/Tokyo' <<<"$output"
    ! grep -qE '^\s+[0-9]\) ' <<<"$output"
}
