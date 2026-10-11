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
    # The locale getter falls back to these files, and the fix writes them.
    TZ_LOCALE_GEN="$etc/locale.gen"
    TZ_DEFAULT_LOCALE="$etc/default/locale"
    TZ_LOCALE_CONF="$etc/locale.conf"
    mkdir -p "$etc/default"

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
    [ "$status" -eq 0 ]
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
    _vpssec_stub locale 0 'en_US.utf8'

    run _timezone_fix_set_locale
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called locale-gen
}

# ---- the locale the audit reads and the fix writes ------------------

@test "locale getter: localectl's (unset) is no locale, not 'System' or the caller's" {
    # Current systemd right-aligns the labels, and this is the widest one.
    _vpssec_stub localectl 0 $'System Locale: (unset)\n    VC Keymap: (unset)'
    LANG=en_US.UTF-8
    run _timezone_current_locale
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    run _timezone_locale_set
    [ "$status" -ne 0 ]

    # Older systemd indents it.
    _vpssec_stub localectl 0 $'   System Locale: LANG=de_DE.UTF-8\n                  LANGUAGE=de_DE:de'
    run _timezone_current_locale
    [ "$output" = "de_DE.UTF-8" ]
}

@test "locale getter: without localectl the locale file decides, never the caller's LANG" {
    # sudo and ssh pass the operator's LANG through to this process.
    _vpssec_absent_command localectl
    LANG=en_US.UTF-8
    run _timezone_current_locale
    [ -z "$output" ]

    printf '# set by the installer\nLANG="de_DE.UTF-8"\n' > "$TZ_DEFAULT_LOCALE"
    run _timezone_current_locale
    [ "$output" = "de_DE.UTF-8" ]
    # locale.conf is read first, as localed reads it.
    printf 'LANG=fr_FR.UTF-8\n' > "$TZ_LOCALE_CONF"
    run _timezone_current_locale
    [ "$output" = "fr_FR.UTF-8" ]
}

@test "locale: a locale the host has not compiled is not written" {
    # Written anyway, every login warns it cannot set it, and the audit,
    # which only reads the setting, passes.
    i18n_load en_US
    _vpssec_absent_command localectl
    printf 'LANG=C\n' > "$TZ_DEFAULT_LOCALE"
    _vpssec_stub locale 0 $'C\nC.utf8\nPOSIX'

    run _timezone_fix_set_locale
    [ "$status" -eq 1 ]
    [ "$(cat "$TZ_DEFAULT_LOCALE")" = "LANG=C" ]
    [[ "$output" == *"$(i18n 'timezone.locale_not_installed' 'locale=en_US.UTF-8')"* ]]
}

@test "locale: a compiled locale is found whichever way its codeset is spelled" {
    _vpssec_absent_command localectl
    printf 'LANG=C\n' > "$TZ_DEFAULT_LOCALE"
    _vpssec_stub locale 0 $'C.utf8\nen_US.utf8'

    run _timezone_fix_set_locale
    [ "$status" -eq 0 ]
    [ "$(cat "$TZ_DEFAULT_LOCALE")" = "LANG=en_US.UTF-8" ]
}

# ---- enable_ntp's chrony fallback -------------------------------------

@test "enable_ntp: chrony comes from a refreshed index, and a failed refresh does not stop it" {
    _vpssec_stub timedatectl 1
    _vpssec_stub systemctl 0
    _vpssec_stub_script apt-get <<'SH'
case "$*" in
    *update*) exit 100 ;;
esac
exit 0
SH

    run _timezone_fix_enable_ntp
    [ "$status" -eq 0 ]
    _vpssec_stub_called apt-get 'update'
    _vpssec_stub_called apt-get 'install .*chrony'
}
