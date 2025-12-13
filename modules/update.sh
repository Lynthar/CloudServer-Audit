#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# System update module
# Copyright (c) 2024

# ==============================================================================
# Update Helper Functions
# ==============================================================================

# Check if APT is locked
_update_apt_locked() {
    lsof /var/lib/dpkg/lock-frontend &>/dev/null || \
    lsof /var/lib/apt/lists/lock &>/dev/null || \
    lsof /var/cache/apt/archives/lock &>/dev/null
}

# Get count of available updates
_update_get_count() {
    apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || echo "0"
}

# Get count of security updates
_update_get_security_count() {
    apt-get -s upgrade 2>/dev/null | grep -c "security" || echo "0"
}

# Check if unattended-upgrades is installed
_update_unattended_installed() {
    dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"
}

# Check if unattended-upgrades is enabled
_update_unattended_enabled() {
    # Check if the service is enabled
    systemctl is-enabled unattended-upgrades &>/dev/null && \
    # Check if auto-upgrade is configured
    [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && \
    grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
}

# ==============================================================================
# Update Audit
# ==============================================================================

update_audit() {
    local module="update"

    # Check APT lock
    print_item "$(i18n 'update.check_apt_lock')"
    _update_audit_apt_lock

    # Check available updates
    print_item "$(i18n 'update.check_updates')"
    _update_audit_available

    # Check unattended-upgrades
    print_item "$(i18n 'update.check_unattended')"
    _update_audit_unattended
}

_update_audit_apt_lock() {
    if _update_apt_locked; then
        local check=$(create_check_json \
            "update.apt_locked" \
            "update" \
            "medium" \
            "failed" \
            "$(i18n 'update.apt_locked')" \
            "APT is locked by another process" \
            "Wait for other process to finish or remove lock" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'update.apt_locked')"
    else
        local check=$(create_check_json \
            "update.apt_available" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.apt_available')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.apt_available')"
    fi
}

_update_audit_available() {
    # Update package lists (silently)
    apt-get update -qq 2>/dev/null

    local update_count=$(_update_get_count)
    local security_count=$(_update_get_security_count)

    if ((update_count == 0)); then
        local check=$(create_check_json \
            "update.no_updates" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.no_updates')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.no_updates')"
    else
        local severity="low"
        local fix_id=""

        if ((security_count > 0)); then
            severity="high"
            fix_id="update.apply_security"
        fi

        local check=$(create_check_json \
            "update.updates_available" \
            "update" \
            "$severity" \
            "failed" \
            "$(i18n 'update.updates_available' "count=$update_count")" \
            "Security updates: $security_count" \
            "Run: apt upgrade" \
            "$fix_id")
        state_add_check "$check"

        if ((security_count > 0)); then
            print_severity "high" "$(i18n 'update.security_updates' "count=$security_count")"
        else
            print_severity "low" "$(i18n 'update.updates_available' "count=$update_count")"
        fi
    fi
}

_update_audit_unattended() {
    if ! _update_unattended_installed; then
        local check=$(create_check_json \
            "update.unattended_not_installed" \
            "update" \
            "medium" \
            "failed" \
            "$(i18n 'update.unattended_disabled')" \
            "unattended-upgrades package not installed" \
            "$(i18n 'update.fix_install_unattended')" \
            "update.install_unattended")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'update.unattended_disabled')"
        return
    fi

    if _update_unattended_enabled; then
        local check=$(create_check_json \
            "update.unattended_enabled" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.unattended_enabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.unattended_enabled')"
    else
        local check=$(create_check_json \
            "update.unattended_disabled" \
            "update" \
            "medium" \
            "failed" \
            "$(i18n 'update.unattended_disabled')" \
            "unattended-upgrades installed but not enabled" \
            "$(i18n 'update.fix_install_unattended')" \
            "update.enable_unattended")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'update.unattended_disabled')"
    fi
}

# ==============================================================================
# Update Fix Functions
# ==============================================================================

update_fix() {
    local fix_id="$1"

    case "$fix_id" in
        update.apply_security)
            _update_fix_apply_security
            ;;
        update.install_unattended)
            _update_fix_install_unattended
            ;;
        update.enable_unattended)
            _update_fix_enable_unattended
            ;;
        *)
            log_error "Unknown update fix: $fix_id"
            return 1
            ;;
    esac
}

_update_fix_apply_security() {
    print_info "Applying security updates..."

    # Use unattended-upgrade if available for safer updates
    if _update_unattended_installed; then
        if unattended-upgrade -d 2>/dev/null; then
            print_ok "Security updates applied"
            return 0
        fi
    fi

    # Fallback to apt upgrade
    export DEBIAN_FRONTEND=noninteractive
    if apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"; then
        print_ok "Updates applied"
        return 0
    else
        print_error "Failed to apply updates"
        return 1
    fi
}

_update_fix_install_unattended() {
    print_info "Installing unattended-upgrades..."

    export DEBIAN_FRONTEND=noninteractive

    if apt-get install -y unattended-upgrades apt-listchanges; then
        # Configure auto-upgrades
        _update_fix_enable_unattended
        return $?
    else
        print_error "Failed to install unattended-upgrades"
        return 1
    fi
}

_update_fix_enable_unattended() {
    print_info "Configuring unattended-upgrades..."

    # Create auto-upgrades config
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    # Configure unattended-upgrades for security only
    local uu_config="/etc/apt/apt.conf.d/50unattended-upgrades"

    if [[ -f "$uu_config" ]]; then
        backup_file "$uu_config"
    fi

    # Get OS info for proper origin pattern
    local os=$(detect_os)
    local codename=$(detect_os_codename)

    cat > "$uu_config" <<EOF
// vpssec unattended-upgrades configuration
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot if required (disabled by default for safety)
Unattended-Upgrade::Automatic-Reboot "false";

// Mail report (optional)
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "on-change";

// Logging
Unattended-Upgrade::SyslogEnable "true";
EOF

    # Enable and start service
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades

    if _update_unattended_enabled; then
        print_ok "$(i18n 'update.unattended_configured')"
        return 0
    else
        print_error "Failed to enable unattended-upgrades"
        return 1
    fi
}
