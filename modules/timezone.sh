#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Timezone module - timezone and time synchronization checks
# Copyright (c) 2024

# ==============================================================================
# Timezone Audit
# ==============================================================================

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

# Check current timezone setting
_timezone_check_current() {
    local current_tz=""
    local tz_source=""

    # Try to get timezone from timedatectl
    if command -v timedatectl &>/dev/null; then
        current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null)
        tz_source="timedatectl"
    fi

    # Fallback to /etc/timezone
    if [[ -z "$current_tz" ]] && [[ -f /etc/timezone ]]; then
        current_tz=$(cat /etc/timezone 2>/dev/null | tr -d '[:space:]')
        tz_source="/etc/timezone"
    fi

    # Fallback to TZ environment or localtime symlink
    if [[ -z "$current_tz" ]]; then
        if [[ -L /etc/localtime ]]; then
            current_tz=$(readlink /etc/localtime | sed 's|.*/zoneinfo/||')
            tz_source="/etc/localtime"
        elif [[ -n "$TZ" ]]; then
            current_tz="$TZ"
            tz_source="TZ env"
        fi
    fi

    if [[ -z "$current_tz" ]]; then
        local check=$(create_check_json \
            "timezone.not_configured" \
            "timezone" \
            "low" \
            "failed" \
            "$(i18n 'timezone.not_configured')" \
            "$(i18n 'timezone.not_configured_desc')" \
            "$(i18n 'timezone.fix_set_timezone')" \
            "timezone.set_timezone")
        state_add_check "$check"
        print_warn "$(i18n 'timezone.not_configured')"
        return
    fi

    # Check if using UTC (common for cloud VPS but may not be desired)
    # Always provide fix_id to allow user to change timezone in guide mode
    if [[ "$current_tz" == "UTC" || "$current_tz" == "Etc/UTC" ]]; then
        local check=$(create_check_json \
            "timezone.using_utc" \
            "timezone" \
            "low" \
            "passed" \
            "$(i18n 'timezone.current_timezone' "tz=$current_tz")" \
            "$(i18n 'timezone.utc_note'). $(i18n 'timezone.change_available' 2>/dev/null || echo 'Change available in guide mode')" \
            "$(i18n 'timezone.fix_set_timezone')" \
            "timezone.set_timezone")
        state_add_check "$check"
        print_ok "$(i18n 'timezone.current_timezone' "tz=$current_tz")"
    else
        local check=$(create_check_json \
            "timezone.configured" \
            "timezone" \
            "low" \
            "passed" \
            "$(i18n 'timezone.current_timezone' "tz=$current_tz")" \
            "$(i18n 'timezone.change_available' 2>/dev/null || echo 'Change available in guide mode')" \
            "$(i18n 'timezone.fix_set_timezone')" \
            "timezone.set_timezone")
        state_add_check "$check"
        print_ok "$(i18n 'timezone.current_timezone' "tz=$current_tz")"
    fi

    log_info "Timezone: $current_tz (source: $tz_source)"
}

# Check NTP synchronization
_timezone_check_ntp() {
    local ntp_status="unknown"
    local ntp_service=""
    local is_synced=0

    # Check timedatectl for systemd-timesyncd
    if command -v timedatectl &>/dev/null; then
        local ntp_active=$(timedatectl show --property=NTP --value 2>/dev/null)
        local ntp_synced=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null)

        if [[ "$ntp_active" == "yes" ]]; then
            ntp_service="systemd-timesyncd"
            if [[ "$ntp_synced" == "yes" ]]; then
                is_synced=1
                ntp_status="synced"
            else
                ntp_status="active_not_synced"
            fi
        fi
    fi

    # Check for chrony / chronyd. Debian/Ubuntu name the unit
    # `chrony.service`; RHEL/Fedora and some derivatives use
    # `chronyd.service`. Probing only `chronyd` silently misclassified
    # synced Debian hosts as "NTP disabled" — every Debian/Ubuntu
    # install with chrony fell through to the openntpd branch and
    # then the no-NTP-found case.
    if [[ "$ntp_status" == "unknown" ]] && \
        ( systemctl is-active chrony &>/dev/null || \
          systemctl is-active chronyd &>/dev/null ); then
        ntp_service="chrony"
        if chronyc tracking &>/dev/null; then
            local leap=$(chronyc tracking 2>/dev/null | grep -i "Leap status" | grep -i "Normal")
            if [[ -n "$leap" ]]; then
                is_synced=1
                ntp_status="synced"
            else
                ntp_status="active_not_synced"
            fi
        fi
    fi

    # Check for ntpd / ntpsec. Debian 12+ replaced the legacy `ntp`
    # package with `ntpsec` (unit: `ntpsec.service`); the original
    # `ntp.service` form only exists on older Debian / non-Debian
    # distros. `ntpd.service` is a systemd alias on some images.
    if [[ "$ntp_status" == "unknown" ]] && \
        ( systemctl is-active ntpsec &>/dev/null || \
          systemctl is-active ntp &>/dev/null || \
          systemctl is-active ntpd &>/dev/null ); then
        ntp_service="ntpd"
        if ntpq -p &>/dev/null 2>&1; then
            is_synced=1
            ntp_status="synced"
        else
            ntp_status="active_not_synced"
        fi
    fi

    # Check for openntpd
    if [[ "$ntp_status" == "unknown" ]] && systemctl is-active openntpd &>/dev/null; then
        ntp_service="openntpd"
        is_synced=1  # OpenNTPD doesn't have easy sync check
        ntp_status="active"
    fi

    if [[ "$is_synced" == "1" ]]; then
        local check=$(create_check_json \
            "timezone.ntp_synced" \
            "timezone" \
            "low" \
            "passed" \
            "$(i18n 'timezone.ntp_synced' "service=$ntp_service")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'timezone.ntp_synced' "service=$ntp_service")"
    elif [[ "$ntp_status" == "active_not_synced" ]]; then
        local check=$(create_check_json \
            "timezone.ntp_not_synced" \
            "timezone" \
            "low" \
            "failed" \
            "$(i18n 'timezone.ntp_not_synced')" \
            "$(i18n 'timezone.ntp_not_synced_desc' "service=$ntp_service")" \
            "$(i18n 'timezone.fix_check_ntp')" \
            "")
        state_add_check "$check"
        print_warn "$(i18n 'timezone.ntp_not_synced')"
    else
        local check=$(create_check_json \
            "timezone.ntp_disabled" \
            "timezone" \
            "low" \
            "failed" \
            "$(i18n 'timezone.ntp_disabled')" \
            "$(i18n 'timezone.ntp_disabled_desc')" \
            "$(i18n 'timezone.fix_enable_ntp')" \
            "timezone.enable_ntp")
        state_add_check "$check"
        print_warn "$(i18n 'timezone.ntp_disabled')"
    fi

    log_info "NTP status: $ntp_status (service: $ntp_service)"
}

# Check that the hardware clock is kept in UTC.
#
# The former network time-drift probe (curl to worldtimeapi.org) was
# removed: that service is defunct, the call went over plaintext HTTP,
# it stalled every audit up to 5s, and on failure it silently always
# reported "time accurate". Clock correctness is already covered locally
# and authoritatively by the NTP-sync check above (_timezone_check_ntp);
# a read-only security audit should not phone a third-party endpoint.
_timezone_check_drift() {
    command -v timedatectl &>/dev/null || return 0

    local rtc_in_local
    rtc_in_local=$(timedatectl show --property=LocalRTC --value 2>/dev/null)
    if [[ "$rtc_in_local" == "yes" ]]; then
        # RTC in local time is generally not recommended for servers.
        local check=$(create_check_json \
            "timezone.rtc_local" \
            "timezone" \
            "low" \
            "failed" \
            "$(i18n 'timezone.rtc_local')" \
            "$(i18n 'timezone.rtc_local_desc')" \
            "$(i18n 'timezone.fix_rtc_utc')" \
            "timezone.set_rtc_utc")
        state_add_check "$check"
        print_warn "$(i18n 'timezone.rtc_local')"
    fi
}

# Check locale settings
_timezone_check_locale() {
    local current_locale=""
    local locale_ok=1

    # Get current locale
    if command -v localectl &>/dev/null; then
        current_locale=$(localectl status 2>/dev/null | grep "System Locale" | sed 's/.*LANG=//' | cut -d' ' -f1)
    fi

    if [[ -z "$current_locale" ]]; then
        current_locale="${LANG:-C}"
    fi

    # Check if locale is set to something reasonable
    if [[ "$current_locale" == "C" || "$current_locale" == "POSIX" || -z "$current_locale" ]]; then
        local check=$(create_check_json \
            "timezone.locale_not_set" \
            "timezone" \
            "low" \
            "failed" \
            "$(i18n 'timezone.locale_not_set')" \
            "$(i18n 'timezone.locale_not_set_desc')" \
            "$(i18n 'timezone.fix_set_locale')" \
            "timezone.set_locale")
        state_add_check "$check"
        print_warn "$(i18n 'timezone.locale_not_set')"
    else
        # Provide fix_id to allow user to change locale in guide mode
        local check=$(create_check_json \
            "timezone.locale_ok" \
            "timezone" \
            "low" \
            "passed" \
            "$(i18n 'timezone.locale_ok' "locale=$current_locale")" \
            "$(i18n 'timezone.change_available' 2>/dev/null || echo 'Change available in guide mode')" \
            "$(i18n 'timezone.fix_set_locale')" \
            "timezone.set_locale")
        state_add_check "$check"
        print_ok "$(i18n 'timezone.locale_ok' "locale=$current_locale")"
    fi

    log_info "System locale: $current_locale"
}

# ==============================================================================
# Timezone Fix
# ==============================================================================

timezone_fix() {
    local fix_id="$1"

    case "$fix_id" in
        timezone.set_timezone)
            _timezone_fix_set_timezone
            ;;
        timezone.enable_ntp)
            _timezone_fix_enable_ntp
            ;;
        timezone.sync_time)
            _timezone_fix_sync_time
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

    print_msg ""
    print_msg "$(i18n 'timezone.select_timezone'):"
    print_msg ""

    local i=1
    for tz in "${common_timezones[@]}"; do
        echo "  $i) $tz"
        ((i++))
    done
    echo "  $i) $(i18n 'timezone.enter_custom')"

    print_msg ""
    echo -n "$(i18n 'common.enter_choice') [1-$i]: "
    local choice
    read -r choice </dev/tty 2>/dev/null || choice=""

    local selected_tz=""
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if ((choice >= 1 && choice < i)); then
            selected_tz="${common_timezones[$((choice-1))]}"
        elif ((choice == i)); then
            echo -n "$(i18n 'timezone.enter_timezone'): "
            read -r selected_tz </dev/tty 2>/dev/null || selected_tz=""
        fi
    fi

    if [[ -z "$selected_tz" ]]; then
        print_warn "$(i18n 'common.cancel')"
        return 1
    fi

    # Validate timezone
    if [[ ! -f "/usr/share/zoneinfo/$selected_tz" ]]; then
        print_error "$(i18n 'timezone.invalid_timezone' "tz=$selected_tz")"
        return 1
    fi

    # Create backup
    backup_file "/etc/timezone"
    backup_file "/etc/localtime"

    # Set timezone
    if command -v timedatectl &>/dev/null; then
        if timedatectl set-timezone "$selected_tz"; then
            print_ok "$(i18n 'timezone.timezone_set' "tz=$selected_tz")"
            return 0
        fi
    else
        # Manual method
        ln -sf "/usr/share/zoneinfo/$selected_tz" /etc/localtime
        echo "$selected_tz" > /etc/timezone
        print_ok "$(i18n 'timezone.timezone_set' "tz=$selected_tz")"
        return 0
    fi

    print_error "$(i18n 'timezone.set_failed')"
    return 1
}

# Fix: Enable NTP synchronization
_timezone_fix_enable_ntp() {
    print_info "$(i18n 'timezone.enabling_ntp')"

    # Check if systemd-timesyncd is available
    if command -v timedatectl &>/dev/null; then
        if timedatectl set-ntp true; then
            # Wait a moment for sync
            sleep 2

            local synced=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null)
            if [[ "$synced" == "yes" ]]; then
                print_ok "$(i18n 'timezone.ntp_enabled')"
                return 0
            else
                print_ok "$(i18n 'timezone.ntp_enabled_waiting')"
                return 0
            fi
        fi
    fi

    # Try to install and enable chrony as alternative
    if apt-get install -y chrony &>/dev/null; then
        systemctl enable chrony &>/dev/null
        systemctl start chrony &>/dev/null
        print_ok "$(i18n 'timezone.chrony_installed')"
        return 0
    fi

    print_error "$(i18n 'timezone.ntp_enable_failed')"
    return 1
}

# Fix: Force time sync
_timezone_fix_sync_time() {
    print_info "$(i18n 'timezone.syncing_time')"

    # Try chrony / chronyd (see _timezone_check_ntp for the unit-name
    # rationale: Debian uses chrony.service, RHEL uses chronyd.service).
    if command -v chronyc &>/dev/null && \
        ( systemctl is-active chrony &>/dev/null || \
          systemctl is-active chronyd &>/dev/null ); then
        chronyc makestep &>/dev/null
        print_ok "$(i18n 'timezone.time_synced')"
        return 0
    fi

    # Try systemd-timesyncd restart
    if systemctl restart systemd-timesyncd &>/dev/null; then
        sleep 2
        print_ok "$(i18n 'timezone.time_synced')"
        return 0
    fi

    # Try ntpdate as last resort
    if command -v ntpdate &>/dev/null; then
        ntpdate -u pool.ntp.org &>/dev/null
        print_ok "$(i18n 'timezone.time_synced')"
        return 0
    fi

    print_error "$(i18n 'timezone.sync_failed')"
    return 1
}

# Fix: Set RTC to UTC
_timezone_fix_rtc_utc() {
    print_info "$(i18n 'timezone.setting_rtc_utc')"

    if command -v timedatectl &>/dev/null; then
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

    local target_locale="en_US.UTF-8"

    # Generate locale if needed
    if [[ -f /etc/locale.gen ]]; then
        if ! grep -q "^${target_locale}" /etc/locale.gen; then
            backup_file "/etc/locale.gen"
            sed -i "s/^# *${target_locale}/${target_locale}/" /etc/locale.gen
            locale-gen &>/dev/null
        fi
    fi

    # Set locale
    if command -v localectl &>/dev/null; then
        if localectl set-locale LANG="$target_locale"; then
            print_ok "$(i18n 'timezone.locale_set' "locale=$target_locale")"
            return 0
        fi
    fi

    # Manual method
    if [[ -f /etc/default/locale ]]; then
        backup_file "/etc/default/locale"
        echo "LANG=$target_locale" > /etc/default/locale
        print_ok "$(i18n 'timezone.locale_set' "locale=$target_locale")"
        return 0
    fi

    print_error "$(i18n 'timezone.locale_set_failed')"
    return 1
}
