#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Baseline hardening module (Enhanced with SELinux support)
# Copyright (c) 2024

# ==============================================================================
# Baseline Helper Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# AppArmor Functions
# ------------------------------------------------------------------------------

_baseline_apparmor_enabled() {
    if check_command aa-status; then
        aa-status --enabled 2>/dev/null
        return $?
    fi
    return 1
}

_baseline_apparmor_installed() {
    check_command aa-status || check_command apparmor_status
}

_baseline_apparmor_get_status() {
    if ! _baseline_apparmor_installed; then
        echo "not_installed"
        return
    fi

    if _baseline_apparmor_enabled; then
        # Get profile stats
        local enforced=$(aa-status 2>/dev/null | grep -E "^\s*[0-9]+ profiles are in enforce mode" | grep -oE "[0-9]+" | head -1)
        local complain=$(aa-status 2>/dev/null | grep -E "^\s*[0-9]+ profiles are in complain mode" | grep -oE "[0-9]+" | head -1)
        echo "enabled:${enforced:-0}:${complain:-0}"
    else
        echo "disabled"
    fi
}

# ------------------------------------------------------------------------------
# SELinux Functions
# ------------------------------------------------------------------------------

_baseline_selinux_installed() {
    check_command getenforce || check_command sestatus
}

_baseline_selinux_get_status() {
    if ! _baseline_selinux_installed; then
        echo "not_installed"
        return
    fi

    local mode=""
    if check_command getenforce; then
        mode=$(getenforce 2>/dev/null)
    elif check_command sestatus; then
        mode=$(sestatus 2>/dev/null | grep "Current mode" | awk '{print $3}')
    fi

    case "$mode" in
        Enforcing|enforcing)   echo "enforcing" ;;
        Permissive|permissive) echo "permissive" ;;
        Disabled|disabled)     echo "disabled" ;;
        *)                     echo "unknown" ;;
    esac
}

_baseline_selinux_get_config() {
    # Get configured mode from config file
    if [[ -f /etc/selinux/config ]]; then
        grep -E "^SELINUX=" /etc/selinux/config 2>/dev/null | cut -d= -f2 | tr -d '"'
    else
        echo "not_configured"
    fi
}

_baseline_selinux_get_policy() {
    if check_command sestatus; then
        sestatus 2>/dev/null | grep "Loaded policy name" | awk '{print $4}'
    elif [[ -f /etc/selinux/config ]]; then
        grep -E "^SELINUXTYPE=" /etc/selinux/config 2>/dev/null | cut -d= -f2 | tr -d '"'
    fi
}

_baseline_selinux_denials_count() {
    # Count recent SELinux denials (last 24h)
    if check_command ausearch; then
        ausearch -m avc -ts today 2>/dev/null | grep -c "type=AVC" || echo "0"
    elif [[ -f /var/log/audit/audit.log ]]; then
        grep -c "type=AVC.*denied" /var/log/audit/audit.log 2>/dev/null || echo "0"
    else
        echo "unknown"
    fi
}

# ------------------------------------------------------------------------------
# MAC System Detection (Mandatory Access Control)
# ------------------------------------------------------------------------------

_baseline_detect_mac_system() {
    # Detect which MAC system is in use
    # Priority: SELinux > AppArmor (some systems have both installed)

    local selinux_status=$(_baseline_selinux_get_status)
    local apparmor_status=$(_baseline_apparmor_get_status)

    # Check if SELinux is actively in use
    if [[ "$selinux_status" == "enforcing" || "$selinux_status" == "permissive" ]]; then
        echo "selinux"
        return
    fi

    # Check if AppArmor is enabled
    if [[ "$apparmor_status" =~ ^enabled ]]; then
        echo "apparmor"
        return
    fi

    # Neither is active, check what's installed
    if _baseline_selinux_installed && [[ "$selinux_status" != "not_installed" ]]; then
        echo "selinux_disabled"
        return
    fi

    if _baseline_apparmor_installed; then
        echo "apparmor_disabled"
        return
    fi

    echo "none"
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

    # Check Mandatory Access Control (SELinux/AppArmor)
    print_item "$(i18n 'baseline.check_mac')"
    _baseline_audit_mac

    # Check unused services
    print_item "$(i18n 'baseline.check_unused_services')"
    _baseline_audit_unused_services
}

# Combined MAC (Mandatory Access Control) audit - SELinux + AppArmor
_baseline_audit_mac() {
    local mac_system=$(_baseline_detect_mac_system)

    case "$mac_system" in
        selinux)
            _baseline_audit_selinux
            ;;
        apparmor)
            _baseline_audit_apparmor
            ;;
        selinux_disabled)
            _baseline_audit_selinux_disabled
            ;;
        apparmor_disabled)
            _baseline_audit_apparmor_disabled
            ;;
        none)
            _baseline_audit_no_mac
            ;;
    esac
}

# ------------------------------------------------------------------------------
# SELinux Audit
# ------------------------------------------------------------------------------

_baseline_audit_selinux() {
    local status=$(_baseline_selinux_get_status)
    local config=$(_baseline_selinux_get_config)
    local policy=$(_baseline_selinux_get_policy)
    local denials=$(_baseline_selinux_denials_count)

    if [[ "$status" == "enforcing" ]]; then
        local check=$(create_check_json \
            "baseline.selinux_enforcing" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.selinux_enforcing')" \
            "SELinux enforcing, policy: ${policy:-targeted}, denials today: ${denials}" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.selinux_enforcing') (policy: ${policy:-targeted})"

        # Check for excessive denials
        if [[ "$denials" != "unknown" ]] && [[ "$denials" -gt 50 ]]; then
            local check=$(create_check_json \
                "baseline.selinux_many_denials" \
                "baseline" \
                "low" \
                "failed" \
                "$(i18n 'baseline.selinux_many_denials' "count=$denials")" \
                "High number of SELinux denials may indicate misconfiguration" \
                "Review denials: ausearch -m avc -ts today" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'baseline.selinux_many_denials' "count=$denials")"
        fi

    elif [[ "$status" == "permissive" ]]; then
        local check=$(create_check_json \
            "baseline.selinux_permissive" \
            "baseline" \
            "medium" \
            "failed" \
            "$(i18n 'baseline.selinux_permissive')" \
            "SELinux is in permissive mode - violations are logged but not enforced" \
            "Set SELinux to enforcing: setenforce 1" \
            "baseline.selinux_set_enforcing")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'baseline.selinux_permissive')"

        # Check if configured as disabled (will be disabled on reboot)
        if [[ "$config" == "disabled" ]]; then
            print_warn "SELinux is configured as disabled in /etc/selinux/config"
        fi
    fi
}

_baseline_audit_selinux_disabled() {
    local config=$(_baseline_selinux_get_config)

    local check=$(create_check_json \
        "baseline.selinux_disabled" \
        "baseline" \
        "medium" \
        "failed" \
        "$(i18n 'baseline.selinux_disabled')" \
        "SELinux is installed but disabled (config: ${config})" \
        "Enable SELinux in /etc/selinux/config and reboot" \
        "baseline.selinux_enable")
    state_add_check "$check"
    print_severity "medium" "$(i18n 'baseline.selinux_disabled')"
}

# ------------------------------------------------------------------------------
# AppArmor Audit
# ------------------------------------------------------------------------------

_baseline_audit_apparmor() {
    local status=$(_baseline_apparmor_get_status)

    if [[ "$status" =~ ^enabled ]]; then
        # Parse enforced:complain counts
        local enforced=$(echo "$status" | cut -d: -f2)
        local complain=$(echo "$status" | cut -d: -f3)

        local check=$(create_check_json \
            "baseline.apparmor_enabled" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.apparmor_enabled')" \
            "AppArmor enabled: ${enforced} profiles enforcing, ${complain} in complain mode" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.apparmor_enabled') (enforcing: ${enforced}, complain: ${complain})"

        # Check if too many profiles in complain mode
        if [[ "$complain" -gt "$enforced" ]] && [[ "$complain" -gt 5 ]]; then
            local check=$(create_check_json \
                "baseline.apparmor_many_complain" \
                "baseline" \
                "low" \
                "failed" \
                "$(i18n 'baseline.apparmor_many_complain' "count=$complain")" \
                "Many AppArmor profiles in complain mode (not enforcing)" \
                "Review and set profiles to enforce mode" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'baseline.apparmor_many_complain' "count=$complain")"
        fi
    fi
}

_baseline_audit_apparmor_disabled() {
    local check=$(create_check_json \
        "baseline.apparmor_disabled" \
        "baseline" \
        "medium" \
        "failed" \
        "$(i18n 'baseline.apparmor_disabled')" \
        "AppArmor is installed but not enabled" \
        "Enable AppArmor for additional security" \
        "baseline.enable_apparmor")
    state_add_check "$check"
    print_severity "medium" "$(i18n 'baseline.apparmor_disabled')"
}

_baseline_audit_no_mac() {
    local check=$(create_check_json \
        "baseline.no_mac_system" \
        "baseline" \
        "medium" \
        "failed" \
        "$(i18n 'baseline.no_mac_system')" \
        "No Mandatory Access Control system (SELinux/AppArmor) detected" \
        "Install and enable AppArmor or SELinux" \
        "baseline.enable_apparmor")
    state_add_check "$check"
    print_severity "medium" "$(i18n 'baseline.no_mac_system')"
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
        baseline.selinux_set_enforcing)
            _baseline_fix_selinux_enforcing
            ;;
        baseline.selinux_enable)
            _baseline_fix_selinux_enable
            ;;
        *)
            log_error "Unknown baseline fix: $fix_id"
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# SELinux Fix Functions
# ------------------------------------------------------------------------------

_baseline_fix_selinux_enforcing() {
    print_info "$(i18n 'baseline.setting_selinux_enforcing')"

    # Set enforcing mode immediately
    if check_command setenforce; then
        setenforce 1 2>/dev/null
        if [[ "$(_baseline_selinux_get_status)" == "enforcing" ]]; then
            print_ok "$(i18n 'baseline.selinux_enforcing_set')"

            # Update config file for persistence
            if [[ -f /etc/selinux/config ]]; then
                backup_file /etc/selinux/config
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                print_ok "$(i18n 'baseline.selinux_config_updated')"
            fi
            return 0
        else
            print_error "$(i18n 'baseline.selinux_enforcing_failed')"
            return 1
        fi
    else
        print_error "setenforce command not found"
        return 1
    fi
}

_baseline_fix_selinux_enable() {
    print_warn "$(i18n 'baseline.selinux_enable_manual')"
    echo ""
    echo "$(i18n 'baseline.selinux_enable_steps'):"
    echo "  1. Edit /etc/selinux/config"
    echo "  2. Set SELINUX=enforcing (or permissive for testing)"
    echo "  3. Set SELINUXTYPE=targeted"
    echo "  4. Reboot the system"
    echo ""
    echo "$(i18n 'common.warning'): Enabling SELinux requires a system reboot"
    echo "$(i18n 'baseline.selinux_relabel_warning')"
    return 1  # Manual intervention required
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
