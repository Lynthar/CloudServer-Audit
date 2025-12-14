#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Baseline hardening module
# Copyright (c) 2024

# ==============================================================================
# Baseline Helper Functions
# ==============================================================================

_baseline_apparmor_enabled() {
    if check_command aa-status; then
        aa-status --enabled 2>/dev/null
        return $?
    fi
    return 1
}

_baseline_get_unused_services() {
    local unused=()
    local check_services=(
        "cups"           # Printing
        "avahi-daemon"   # mDNS
        "bluetooth"      # Bluetooth
        "ModemManager"   # Modem
        "whoopsie"       # Error reporting
        "apport"         # Crash reporting
    )

    for service in "${check_services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            unused+=("$service")
        fi
    done

    echo "${unused[*]}"
}

# ==============================================================================
# Baseline Audit
# ==============================================================================

baseline_audit() {
    local module="baseline"

    # Check AppArmor
    print_item "$(i18n 'baseline.check_apparmor')"
    _baseline_audit_apparmor

    # Check unused services
    print_item "$(i18n 'baseline.check_unused_services')"
    _baseline_audit_unused_services
}

_baseline_audit_apparmor() {
    if _baseline_apparmor_enabled; then
        local check=$(create_check_json \
            "baseline.apparmor_enabled" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.apparmor_enabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.apparmor_enabled')"
    else
        local check=$(create_check_json \
            "baseline.apparmor_disabled" \
            "baseline" \
            "medium" \
            "failed" \
            "$(i18n 'baseline.apparmor_disabled')" \
            "AppArmor is not enabled" \
            "Enable AppArmor for additional security" \
            "baseline.enable_apparmor")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'baseline.apparmor_disabled')"
    fi
}

_baseline_audit_unused_services() {
    local unused=$(_baseline_get_unused_services)
    local count=$(echo "$unused" | wc -w)

    if ((count > 0)); then
        local check=$(create_check_json \
            "baseline.unused_services" \
            "baseline" \
            "low" \
            "failed" \
            "$(i18n 'baseline.unused_services' "count=$count")" \
            "Services: $unused" \
            "Disable unused services" \
            "baseline.disable_unused")
        state_add_check "$check"
        print_severity "low" "$(i18n 'baseline.unused_services' "count=$count"): $unused"
    else
        local check=$(create_check_json \
            "baseline.no_unused_services" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.no_unused_services')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.no_unused_services')"
    fi
}

# ==============================================================================
# Baseline Fix Functions
# ==============================================================================

baseline_fix() {
    local fix_id="$1"

    case "$fix_id" in
        baseline.enable_apparmor)
            _baseline_fix_enable_apparmor
            ;;
        baseline.disable_unused)
            _baseline_fix_disable_unused
            ;;
        *)
            log_error "Unknown baseline fix: $fix_id"
            return 1
            ;;
    esac
}

_baseline_fix_enable_apparmor() {
    print_info "$(i18n 'baseline.enabling_apparmor')"

    # Install if needed
    if ! check_command aa-status; then
        apt-get install -y apparmor apparmor-utils 2>/dev/null
    fi

    # Enable and start
    systemctl enable apparmor
    systemctl start apparmor

    if _baseline_apparmor_enabled; then
        print_ok "$(i18n 'baseline.apparmor_enabled_success')"
        return 0
    else
        print_error "$(i18n 'baseline.apparmor_enable_failed')"
        return 1
    fi
}

_baseline_fix_disable_unused() {
    local unused=$(_baseline_get_unused_services)
    local failed=0

    for service in $unused; do
        print_info "$(i18n 'baseline.disabling_service' "service=$service")"
        if systemctl disable "$service" 2>/dev/null && systemctl stop "$service" 2>/dev/null; then
            print_ok "$(i18n 'baseline.service_disabled' "service=$service")"
        else
            print_warn "$(i18n 'baseline.service_disable_failed' "service=$service")"
            ((failed++)) || true
        fi
    done

    return $failed
}
