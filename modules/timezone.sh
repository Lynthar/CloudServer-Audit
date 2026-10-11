#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Timezone module - timezone and time synchronization checks
# Copyright (c) 2024

# Named rather than inlined: this is the seam that lets a test point the
# module at a scratch tree instead of the host's real /etc.
TZ_CONF="/etc/timezone"
TZ_LOCALTIME="/etc/localtime"
TZ_ZONEINFO="/usr/share/zoneinfo"
TZ_LOCALE_GEN="/etc/locale.gen"
TZ_DEFAULT_LOCALE="/etc/default/locale"
TZ_LOCALE_CONF="/etc/locale.conf"
TZ_ADJTIME="/etc/adjtime"

# --- Timezone Audit ---

timezone_audit() {
    local module="timezone"

    # Check current timezone
    print_item "$(i18n 'timezone.checking_timezone')"
    _timezone_check_current

    # Check NTP synchronization
    print_item "$(i18n 'timezone.checking_ntp')"
    _timezone_check_ntp

    # Check time drift
    print_item "$(i18n 'timezone.checking_drift')"
    _timezone_check_drift

    # Check locale settings
    print_item "$(i18n 'timezone.checking_locale')"
    _timezone_check_locale
}

# Effective system timezone as "<tz>|<source>"; <tz> empty when unconfigured.
# Shared by the audit and the fix on purpose: a second copy of this fallback
# chain is how a fix and its audit drift apart.
_timezone_current() {
    local tz=""
    local src=""

    # Try to get timezone from timedatectl
    if command -v timedatectl &>/dev/null; then
        tz=$(timedatectl show --property=Timezone --value 2>/dev/null)
        src="timedatectl"
    fi

    # Fallback to /etc/timezone
    if [[ -z "$tz" ]] && [[ -f "$TZ_CONF" ]]; then
        tz=$(tr -d '[:space:]' < "$TZ_CONF" 2>/dev/null)
        src="$TZ_CONF"
    fi

    # Fallback to TZ environment or localtime symlink
    if [[ -z "$tz" ]]; then
        if [[ -L "$TZ_LOCALTIME" ]]; then
            tz=$(readlink "$TZ_LOCALTIME" | sed 's|.*/zoneinfo/||')
            src="$TZ_LOCALTIME"
        elif [[ -n "${TZ:-}" ]]; then
            tz="${TZ:-}"
            src="TZ env"
        fi
    fi

    printf '%s|%s\n' "$tz" "$src"
}

# Pass condition of the timezone check: some timezone is configured.
_timezone_configured() {
    local tz
    IFS='|' read -r tz _ <<< "$(_timezone_current)"
    [[ -n "$tz" ]]
}

# Check current timezone setting
_timezone_check_current() {
    local current_tz=""
    local tz_source=""
    IFS='|' read -r current_tz tz_source <<< "$(_timezone_current)"

    if [[ -z "$current_tz" ]]; then
        check_emit "timezone.not_configured" low failed \
            desc="$(i18n 'timezone.not_configured_desc')" \
            suggestion="$(i18n 'timezone.fix_set_timezone')" \
            fix="timezone.set_timezone"
        print_warn "$(i18n 'timezone.not_configured')"
        return
    fi

    # Passed checks carry no fix: guide lists findings only. Changing a set
    # timezone is the operator's call, so the command is given instead.
    if [[ "$current_tz" == "UTC" || "$current_tz" == "Etc/UTC" ]]; then
        check_emit "timezone.using_utc" low passed \
            title="$(i18n 'timezone.current_timezone' "tz=$current_tz")" \
            desc="$(i18n 'timezone.utc_note')" \
            suggestion="$(i18n 'timezone.change_timezone_cmd')"
        print_ok "$(i18n 'timezone.current_timezone' "tz=$current_tz")"
    else
        check_emit "timezone.configured" low passed \
            title="$(i18n 'timezone.current_timezone' "tz=$current_tz")" \
            suggestion="$(i18n 'timezone.change_timezone_cmd')"
        print_ok "$(i18n 'timezone.current_timezone' "tz=$current_tz")"
    fi

    log_info "Timezone: $current_tz (source: $tz_source)"
}

# Is unit $1 running: 0 yes, 1 no (is-active exits 3, or 4 for no such unit),
# 2 systemctl could not answer (no systemd, or no systemctl at all).
_timezone_unit_active() {
    local rc=0
    systemctl is-active --quiet "$1" 2>/dev/null || rc=$?
    case "$rc" in
        0) return 0 ;;
        3|4) return 1 ;;
        *) return 2 ;;
    esac
}

# Echoes "<status> <service>". status: synced, active (running, sync not
# asked: openntpd, or timesyncd without timedated), active_not_synced, none
# when no NTP daemon runs, or unqueryable when systemctl could not say.
_timezone_ntp_state() {
    # The daemon is whichever unit runs. timedated's NTP=yes means "some unit
    # in ntp-units.d runs", chrony's included, so it never names the daemon.
    local unit rc service="" failed=0
    for unit in systemd-timesyncd chrony chronyd ntpsec ntp ntpd openntpd; do
        rc=0
        _timezone_unit_active "$unit" || rc=$?
        if (( rc == 0 )); then
            service="$unit"
            break
        fi
        (( rc == 2 )) && failed=1
    done
    if [[ -z "$service" ]]; then
        if (( failed )); then echo "unqueryable"; else echo "none"; fi
        return 0
    fi

    local synced tracking
    case "$service" in
        systemd-timesyncd)
            synced=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null) || synced=""
            case "$synced" in
                yes) echo "synced $service" ;;
                no)  echo "active_not_synced $service" ;;
                *)   echo "active $service" ;;
            esac ;;
        chrony|chronyd)
            # Unit active but chronyc unqueryable: the daemon IS running, so
            # never read that as disabled.
            tracking=$(chronyc tracking 2>/dev/null) || tracking=""
            if grep -qiE 'Leap status[[:space:]]*:[[:space:]]*Normal' <<<"$tracking"; then
                echo "synced chrony"
            else
                echo "active_not_synced chrony"
            fi ;;
        ntpsec|ntp|ntpd)
            if ntpq -p &>/dev/null; then echo "synced ntpd"; else echo "active_not_synced ntpd"; fi ;;
        openntpd)
            echo "active openntpd" ;;
    esac
}

# Pass condition of timezone.enable_ntp: some NTP daemon is on. Synced is
# NOT required — sync takes minutes, so a re-check right after would fail.
_timezone_ntp_enabled() {
    local ntp_status
    read -r ntp_status _ <<<"$(_timezone_ntp_state)"
    [[ "$ntp_status" != "none" && "$ntp_status" != "unqueryable" ]]
}

# Check NTP synchronization
_timezone_check_ntp() {
    local ntp_status ntp_service
    read -r ntp_status ntp_service <<<"$(_timezone_ntp_state)"

    if [[ "$ntp_status" == "synced" || "$ntp_status" == "active" ]]; then
        check_emit "timezone.ntp_synced" low passed \
            title="$(i18n 'timezone.ntp_synced' "service=$ntp_service")"
        print_ok "$(i18n 'timezone.ntp_synced' "service=$ntp_service")"
    elif [[ "$ntp_status" == "active_not_synced" ]]; then
        check_emit "timezone.ntp_not_synced" low failed \
            desc="$(i18n 'timezone.ntp_not_synced_desc' "service=$ntp_service")" \
            suggestion="$(i18n 'timezone.fix_check_ntp')"
        print_warn "$(i18n 'timezone.ntp_not_synced')"
    elif [[ "$ntp_status" == "unqueryable" ]]; then
        # Not a "no": nothing could be asked, so no score and no fix.
        check_emit "timezone.ntp_state_unknown" low failed \
            desc="$(i18n 'timezone.ntp_state_unknown_desc')"
        print_warn "$(i18n 'timezone.ntp_state_unknown')"
    else
        check_emit "timezone.ntp_disabled" low failed \
            desc="$(i18n 'timezone.ntp_disabled_desc')" \
            suggestion="$(i18n 'timezone.fix_enable_ntp')" \
            fix="timezone.enable_ntp"
        print_warn "$(i18n 'timezone.ntp_disabled')"
    fi

    log_info "NTP status: $ntp_status (service: $ntp_service)"
}

# Pass condition of the RTC check. Without timedatectl there is nothing to
# ask and the audit reports nothing, so that passes too.
_timezone_rtc_utc() {
    command -v timedatectl &>/dev/null || return 0
    [[ "$(timedatectl show --property=LocalRTC --value 2>/dev/null)" != "yes" ]]
}

# Check that the hardware clock is kept in UTC. Clock correctness itself is
# covered locally by _timezone_check_ntp — do not add a network time probe;
# a read-only audit should not phone a third-party endpoint.
_timezone_check_drift() {
    if ! _timezone_rtc_utc; then
        # RTC in local time is generally not recommended for servers.
        check_emit "timezone.rtc_local" low failed \
            desc="$(i18n 'timezone.rtc_local_desc')" \
            suggestion="$(i18n 'timezone.fix_rtc_utc')" \
            fix="timezone.set_rtc_utc"
        print_warn "$(i18n 'timezone.rtc_local')"
    fi
}

# The system LANG, empty when none is set: localectl's answer when it gives
# one, else the first locale file that exists. Never this process's LANG,
# which sudo and ssh carry over from the operator's own terminal.
_timezone_current_locale() {
    local out f
    if check_command localectl && out=$(localectl status 2>/dev/null) \
       && grep -q 'System Locale:' <<<"$out"; then
        # "(unset)" or "n/a" has no LANG= and yields nothing.
        sed -n '/System Locale:/s/.*LANG=\([^ ,]*\).*/\1/p' <<<"$out"
        return 0
    fi
    for f in "$TZ_LOCALE_CONF" "$TZ_DEFAULT_LOCALE"; do
        [[ -e "$f" ]] || continue
        sed -n 's/^[[:space:]]*LANG=//p' "$f" 2>/dev/null | tail -n 1 | tr -d "\"'"
        return 0
    done
}

# Is locale $1 compiled on this host? `locale -a` spells the codeset
# normalised (UTF-8 as utf8), so both sides are compared in that form.
_timezone_locale_installed() {
    locale -a 2>/dev/null | awk -v want="$1" '
        function norm(s,   i, c) {
            i = index(s, ".")
            if (i == 0) return s
            c = tolower(substr(s, i + 1))
            gsub(/[^a-z0-9@]/, "", c)
            return substr(s, 1, i) c
        }
        norm($0) == norm(want) { found = 1 }
        END { exit !found }'
}

# Pass condition of the locale check: anything but C / POSIX / empty.
_timezone_locale_set() {
    local current_locale
    current_locale=$(_timezone_current_locale)
    [[ "$current_locale" != "C" && "$current_locale" != "POSIX" && -n "$current_locale" ]]
}

# Check locale settings
_timezone_check_locale() {
    local current_locale
    current_locale=$(_timezone_current_locale)

    if ! _timezone_locale_set; then
        check_emit "timezone.locale_not_set" low failed \
            desc="$(i18n 'timezone.locale_not_set_desc')" \
            suggestion="$(i18n 'timezone.fix_set_locale')" \
            fix="timezone.set_locale"
        print_warn "$(i18n 'timezone.locale_not_set')"
    else
        check_emit "timezone.locale_ok" low passed \
            title="$(i18n 'timezone.locale_ok' "locale=$current_locale")" \
            suggestion="$(i18n 'timezone.change_locale_cmd')"
        print_ok "$(i18n 'timezone.locale_ok' "locale=$current_locale")"
    fi

    log_info "System locale: $current_locale"
}

# --- Timezone Fix ---

timezone_fix() {
    local fix_id="$1"

    case "$fix_id" in
        timezone.set_timezone)
            _timezone_fix_set_timezone
            ;;
        timezone.enable_ntp)
            _timezone_fix_enable_ntp
            ;;
        timezone.set_rtc_utc)
            _timezone_fix_rtc_utc
            ;;
        timezone.set_locale)
            _timezone_fix_set_locale
            ;;
        *)
            log_error "Unknown fix: $fix_id"
            return 1
            ;;
    esac
}

# Fix: Set timezone interactively
_timezone_fix_set_timezone() {
    print_info "$(i18n 'timezone.setting_timezone')"

    # The menu cannot be answered non-interactively, so a host that has a
    # timezone by now is left alone and reported as success.
    local current_tz=""
    IFS='|' read -r current_tz _ <<< "$(_timezone_current)"
    if _noninteractive || ! _tty_readable; then
        if [[ -n "$current_tz" ]]; then
            print_ok "$(i18n 'timezone.already_configured' "tz=$current_tz")"
            return 0
        fi
        print_warn "$(i18n 'timezone.needs_interactive')"
        return 1
    fi

    # Common timezones for quick selection
    local common_timezones=(
        "Asia/Shanghai"
        "Asia/Tokyo"
        "Asia/Singapore"
        "America/New_York"
        "America/Los_Angeles"
        "Europe/London"
        "Europe/Paris"
        "UTC"
    )

    tty_say ""
    tty_say "$(i18n 'timezone.select_timezone'):"
    tty_say ""

    local i=1
    for tz in "${common_timezones[@]}"; do
        tty_say "  $i) $tz"
        ((i++))
    done
    tty_say "  $i) $(i18n 'timezone.enter_custom')"

    tty_say ""
    tty_say -n "$(i18n 'common.enter_choice') [1-$i]: "
    local choice
    read -r choice 2>/dev/null </dev/tty || choice=""

    local selected_tz=""
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if ((choice >= 1 && choice < i)); then
            selected_tz="${common_timezones[$((choice-1))]}"
        elif ((choice == i)); then
            tty_say -n "$(i18n 'timezone.enter_timezone'): "
            read -r selected_tz 2>/dev/null </dev/tty || selected_tz=""
        fi
    fi

    if [[ -z "$selected_tz" ]]; then
        print_warn "$(i18n 'common.cancel')"
        return 1
    fi

    # Validate timezone
    if [[ ! -f "${TZ_ZONEINFO}/$selected_tz" ]]; then
        print_error "$(i18n 'timezone.invalid_timezone' "tz=$selected_tz")"
        return 1
    fi

    _timezone_apply "$selected_tz" "$current_tz"
}

# Switch the system timezone from $2 (may be empty) to $1. /etc/localtime is a
# symlink that gets re-pointed, which rollback cannot restore: the previous
# zone is handed back as an undo command instead.
_timezone_apply() {
    local selected_tz="$1" current_tz="$2" undo=""
    # stdout is discarded: it carries the snapshot path.
    backup_file "$TZ_CONF" >/dev/null || return 1
    if check_command timedatectl; then
        [[ -n "$current_tz" ]] && undo="timedatectl set-timezone $current_tz"
        if timedatectl set-timezone "$selected_tz"; then
            # timedated leaves the legacy /etc/timezone alone (Debian 12), so
            # the two would disagree.
            if [[ -f "$TZ_CONF" ]]; then
                write_file_atomic "$TZ_CONF" "$selected_tz"$'\n' \
                    || log_warn "Could not update $TZ_CONF"
            fi
            print_ok "$(i18n 'timezone.timezone_set' "tz=$selected_tz")"
            record_undo timezone.set_timezone "$undo"
            return 0
        fi
    else
        [[ -n "$current_tz" ]] && undo="ln -sf ${TZ_ZONEINFO}/$current_tz $TZ_LOCALTIME"
        if ln -sf "${TZ_ZONEINFO}/$selected_tz" "$TZ_LOCALTIME" \
            && write_file_atomic "$TZ_CONF" "$selected_tz"$'\n'; then
            print_ok "$(i18n 'timezone.timezone_set' "tz=$selected_tz")"
            record_undo timezone.set_timezone "$undo"
            return 0
        fi
    fi

    print_error "$(i18n 'timezone.set_failed')"
    return 1
}

# Fix: Enable NTP synchronization
_timezone_fix_enable_ntp() {
    print_info "$(i18n 'timezone.enabling_ntp')"

    # Check if systemd-timesyncd is available
    if command -v timedatectl &>/dev/null; then
        local was_on
        was_on=$(timedatectl show --property=NTP --value 2>/dev/null)
        if timedatectl set-ntp true; then
            print_ok "$(i18n 'timezone.ntp_enabled')"
            [[ "$was_on" == "yes" ]] || record_undo timezone.enable_ntp "timedatectl set-ntp false"
            return 0
        fi
    fi

    # Try to install and enable chrony as alternative
    local -a missing=()
    mapfile -t missing < <(pkg_missing chrony)
    apt_refresh_index
    if DEBIAN_FRONTEND=noninteractive apt-get install -y chrony &>/dev/null; then
        systemctl enable chrony &>/dev/null
        systemctl start chrony &>/dev/null
        print_ok "$(i18n 'timezone.chrony_installed')"
        (( ${#missing[@]} )) && record_undo timezone.enable_ntp "$(pkg_remove_hint "${missing[@]}")"
        return 0
    fi

    print_error "$(i18n 'timezone.ntp_enable_failed')"
    return 1
}

# No sync_time fix: a fix_id no check emits is unreachable through the engine
# while still being advertised by `vpssec help`. The actionable case is
# handled by timezone.enable_ntp, whose check does emit its fix_id.

# Fix: Set RTC to UTC
_timezone_fix_rtc_utc() {
    print_info "$(i18n 'timezone.setting_rtc_utc')"

    if command -v timedatectl &>/dev/null; then
        # timedated rewrites or deletes /etc/adjtime: back it up (or record it
        # as created) first, so rollback can put the old RTC mode back.
        backup_file "$TZ_ADJTIME" >/dev/null || return 1
        if timedatectl set-local-rtc 0; then
            print_ok "$(i18n 'timezone.rtc_utc_set')"
            return 0
        fi
    fi

    print_error "$(i18n 'timezone.rtc_set_failed')"
    return 1
}

# Fix: Set locale
_timezone_fix_set_locale() {
    print_info "$(i18n 'timezone.setting_locale')"

    # NEVER override an already-valid locale: this fix is FIX_SAFE, and forcing
    # en_US.UTF-8 would silently change the operator's language. Only a
    # genuinely unset locale is set.
    if _timezone_locale_set; then
        print_ok "$(i18n 'timezone.locale_already_set' "locale=$(_timezone_current_locale)")"
        return 0
    fi

    local target_locale="en_US.UTF-8"

    # Generate locale if needed. Build the edited file in memory and write it
    # atomically rather than `sed -i` in place: an interrupted in-place edit
    # could truncate /etc/locale.gen.
    if [[ -f "$TZ_LOCALE_GEN" ]]; then
        if ! grep -q "^${target_locale}" "$TZ_LOCALE_GEN"; then
            backup_file "$TZ_LOCALE_GEN" >/dev/null || return 1
            local gen_content
            gen_content=$(sed "s/^# *${target_locale}/${target_locale}/" "$TZ_LOCALE_GEN")
            if write_file_atomic "$TZ_LOCALE_GEN" "$gen_content"; then
                locale-gen &>/dev/null
            fi
        fi
    fi

    # Both branches below would record a locale that cannot be set: localectl
    # refuses it, and the file written by hand makes every login warn.
    if ! _timezone_locale_installed "$target_locale"; then
        print_error "$(i18n 'timezone.locale_not_installed' "locale=$target_locale")"
        return 1
    fi

    # localed writes whichever of these the distro uses (Debian 13 links one
    # to the other); both are backed up or recorded as created beforehand.
    if check_command localectl; then
        backup_file "$TZ_DEFAULT_LOCALE" >/dev/null || return 1
        backup_file "$TZ_LOCALE_CONF" >/dev/null || return 1
        if localectl set-locale LANG="$target_locale"; then
            print_ok "$(i18n 'timezone.locale_set' "locale=$target_locale")"
            return 0
        fi
    fi

    # Manual method (atomic write instead of a bare redirect).
    if [[ -f "$TZ_DEFAULT_LOCALE" ]]; then
        backup_file "$TZ_DEFAULT_LOCALE" >/dev/null || return 1
        if write_file_atomic "$TZ_DEFAULT_LOCALE" "LANG=$target_locale"; then
            print_ok "$(i18n 'timezone.locale_set' "locale=$target_locale")"
            return 0
        fi
    fi

    print_error "$(i18n 'timezone.locale_set_failed')"
    return 1
}
