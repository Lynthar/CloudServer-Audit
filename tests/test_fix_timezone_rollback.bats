#!/usr/bin/env bats
# What a rollback can undo after the timezone fixes. timedatectl and localectl
# write /etc files themselves, so the fix backs them up first; a re-pointed
# /etc/localtime symlink is not a file, so its undo command is logged instead.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/timezone.sh"
    _vpssec_require_gnu_realpath

    etc=$(_vpssec_fake_etc)
    TZ_CONF="$etc/timezone"
    TZ_LOCALTIME="$etc/localtime"
    TZ_ZONEINFO="$etc/zoneinfo"
    TZ_ADJTIME="$etc/adjtime"
    TZ_DEFAULT_LOCALE="$etc/default/locale"
    TZ_LOCALE_CONF="$etc/locale.conf"
    TZ_LOCALE_GEN="$etc/locale.gen"
    mkdir -p "$TZ_ZONEINFO/Asia" "$TZ_ZONEINFO/Europe" "$etc/default"
    : > "$TZ_ZONEINFO/Asia/Tokyo"
    : > "$TZ_ZONEINFO/Europe/Berlin"
    export VPSSEC_PKG_MGR=apt
    _vpssec_begin_backup_session

    # timedatectl and localectl as the real ones behave: each rewrites the file
    # it owns. The fix's backup has to have happened before that.
    export TZ_ADJTIME TZ_DEFAULT_LOCALE
    _vpssec_stub_script timedatectl <<'SH'
case "$*" in
    "show --property=NTP --value") echo no ;;
    "set-local-rtc 0") printf '0.0 0 0\n0\nUTC\n' > "$TZ_ADJTIME" ;;
esac
exit 0
SH
    _vpssec_stub_script localectl <<'SH'
case "$1" in
    status) echo "   System Locale: LANG=C" ;;
    set-locale) printf '%s\n' "$2" > "$TZ_DEFAULT_LOCALE" ;;
esac
exit 0
SH
    # The fix sets only a locale the host has compiled.
    _vpssec_stub locale 0 'en_US.utf8'
}

_snapshot_of() {
    cat "$VPSSEC_BACKUP_SESSION/${1#/}"
}

@test "set_timezone: the previous zone is logged as the undo command" {
    run _timezone_apply Asia/Tokyo Europe/Berlin
    [ "$status" -eq 0 ]
    _vpssec_stub_called timedatectl 'set-timezone Asia/Tokyo'
    grep -q 'Undo for timezone.set_timezone: timedatectl set-timezone Europe/Berlin' \
        "$VPSSEC_LOGS/vpssec.log"
}

@test "set_timezone: /etc/timezone is kept in step and backed up first" {
    printf 'Europe/Berlin\n' > "$TZ_CONF"

    run _timezone_apply Asia/Tokyo Europe/Berlin
    [ "$status" -eq 0 ]
    [ "$(cat "$TZ_CONF")" = "Asia/Tokyo" ]
    [ "$(_snapshot_of "$TZ_CONF")" = "Europe/Berlin" ]
}

@test "set_timezone without timedatectl: the old link target is the undo command" {
    _vpssec_absent_command timedatectl
    ln -s "$TZ_ZONEINFO/Europe/Berlin" "$TZ_LOCALTIME"

    run _timezone_apply Asia/Tokyo Europe/Berlin
    [ "$status" -eq 0 ]
    [ "$(readlink "$TZ_LOCALTIME")" = "$TZ_ZONEINFO/Asia/Tokyo" ]
    grep -q "Undo for timezone.set_timezone: ln -sf $TZ_ZONEINFO/Europe/Berlin $TZ_LOCALTIME" \
        "$VPSSEC_LOGS/vpssec.log"
}

@test "set_rtc_utc: /etc/adjtime is snapshotted before timedatectl rewrites it" {
    printf '0.0 0 0\n0\nLOCAL\n' > "$TZ_ADJTIME"

    run _timezone_fix_rtc_utc
    [ "$status" -eq 0 ]
    grep -q 'UTC' "$TZ_ADJTIME"
    _snapshot_of "$TZ_ADJTIME" | grep -q 'LOCAL'
}

@test "set_rtc_utc: an absent /etc/adjtime is recorded as created" {
    run _timezone_fix_rtc_utc
    [ "$status" -eq 0 ]
    grep -qxF "$TZ_ADJTIME" "$VPSSEC_BACKUP_SESSION/.vpssec_created"
}

@test "set_locale: the file localectl writes is snapshotted first" {
    printf 'LANG=C\n' > "$TZ_DEFAULT_LOCALE"

    run _timezone_fix_set_locale
    [ "$status" -eq 0 ]
    [ "$(cat "$TZ_DEFAULT_LOCALE")" = "LANG=en_US.UTF-8" ]
    [ "$(_snapshot_of "$TZ_DEFAULT_LOCALE")" = "LANG=C" ]
}

@test "set_locale: a locale file that is a symlink stays one, its target backed up" {
    # Debian 13: /etc/default/locale -> ../locale.conf. Writing through the
    # link used to replace it with a regular file, restored later as mode 777.
    _vpssec_absent_command localectl
    printf 'LANG=C\n' > "$TZ_LOCALE_CONF"
    chmod 644 "$TZ_LOCALE_CONF"
    rm -f "$TZ_DEFAULT_LOCALE"
    ln -s ../locale.conf "$TZ_DEFAULT_LOCALE"

    run _timezone_fix_set_locale
    [ "$status" -eq 0 ]
    [ -L "$TZ_DEFAULT_LOCALE" ]
    [ "$(cat "$TZ_LOCALE_CONF")" = "LANG=en_US.UTF-8" ]

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    [ -L "$TZ_DEFAULT_LOCALE" ]
    [ "$(cat "$TZ_LOCALE_CONF")" = "LANG=C" ]
    [ "$(stat -c '%a' "$TZ_LOCALE_CONF")" = "644" ]
}

@test "enable_ntp: switching NTP on logs the command that switches it off" {
    run _timezone_fix_enable_ntp
    [ "$status" -eq 0 ]
    grep -q 'Undo for timezone.enable_ntp: timedatectl set-ntp false' "$VPSSEC_LOGS/vpssec.log"
}
