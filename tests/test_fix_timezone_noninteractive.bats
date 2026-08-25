#!/usr/bin/env bats
# Regression tests for _timezone_current and the non-interactive guard in
# _timezone_fix_set_timezone. Under --yes / --json-only / no readable /dev/tty
# the fix must never reach its interactive menu; the menu itself needs a real tty.

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
    _vpssec_refute _vpssec_stub_called timedatectl 'set-timezone'
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
    _vpssec_refute _vpssec_stub_called timedatectl 'set-timezone'
}

@test "set_timezone: no interactive menu is printed on a non-interactive run" {
    # The old behaviour parked on a 1-9 menu. Nothing resembling it may
    # reach stdout when the operator cannot answer.
    _vpssec_stub timedatectl 0 'Asia/Shanghai'
    export VPSSEC_YES=1

    run _timezone_fix_set_timezone
    _vpssec_refute grep -q 'Asia/Tokyo' <<<"$output"
    _vpssec_refute grep -qE '^\s+[0-9]\) ' <<<"$output"
}

# STATED GAP: _timezone_fix_set_timezone's two backup calls sit after a
# `read </dev/tty`, so no non-interactive test can reach them. The locale fix
# below covers the module's other two.

@test "locale: a backup that cannot be taken aborts the fix" {
    _vpssec_begin_backup_session
    TZ_LOCALE_GEN="$etc/locale.gen"
    printf '# en_US.UTF-8 UTF-8\n' > "$TZ_LOCALE_GEN"
    LANG=C
    _vpssec_stub localectl 0 ''
    _vpssec_stub cp 1

    run _timezone_fix_set_locale
    [ "$status" -ne 0 ]
    grep -q '^# en_US.UTF-8' "$TZ_LOCALE_GEN"
}

@test "locale: a locale.gen that already has the target is not rewritten" {
    # The other side of the guard: without it the fix rewrites a file it has
    # no reason to touch and re-runs locale-gen on every call.
    TZ_LOCALE_GEN="$etc/locale.gen"
    printf 'en_US.UTF-8 UTF-8\n' > "$TZ_LOCALE_GEN"
    LANG=C
    _vpssec_stub localectl 0 ''
    _vpssec_stub locale-gen

    run _timezone_fix_set_locale
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called locale-gen
}
