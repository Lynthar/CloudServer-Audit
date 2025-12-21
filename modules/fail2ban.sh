#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Fail2ban / intrusion prevention module
# Copyright (c) 2024

# ==============================================================================
# Fail2ban Configuration
# ==============================================================================

F2B_CONFIG="/etc/fail2ban/fail2ban.conf"
F2B_JAIL_LOCAL="/etc/fail2ban/jail.local"
F2B_JAIL_D="/etc/fail2ban/jail.d"

# ==============================================================================
# Fail2ban Helper Functions
# ==============================================================================

_f2b_installed() {
    check_command fail2ban-client
}

_f2b_service_active() {
    systemctl is-active --quiet fail2ban 2>/dev/null
}

_f2b_service_enabled() {
    systemctl is-enabled --quiet fail2ban 2>/dev/null
}

# Detect the correct SSH auth log path
# Returns: log path suitable for fail2ban
_f2b_detect_ssh_logpath() {
    # Check for systemd journal (modern systems)
    # fail2ban can use systemd backend directly
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        # Check if rsyslog/syslog-ng is also writing to files
        if [[ -f /var/log/auth.log ]] && [[ -s /var/log/auth.log ]]; then
            echo "/var/log/auth.log"
            return
        fi
        if [[ -f /var/log/secure ]] && [[ -s /var/log/secure ]]; then
            echo "/var/log/secure"
            return
        fi
        # Use systemd journal backend
        echo "%(sshd_log)s"
        return
    fi

    # Traditional log files
    # Debian/Ubuntu use /var/log/auth.log
    if [[ -f /var/log/auth.log ]]; then
        echo "/var/log/auth.log"
        return
    fi

    # RHEL/CentOS use /var/log/secure
    if [[ -f /var/log/secure ]]; then
        echo "/var/log/secure"
        return
    fi

    # Fallback - let fail2ban figure it out
    echo "%(sshd_log)s"
}

# Detect the correct fail2ban backend
_f2b_detect_backend() {
    # Check if systemd journal is available and working
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        # Check if journalctl works
        if journalctl -n 1 &>/dev/null; then
            echo "systemd"
            return
        fi
    fi

    # Check for pyinotify (more efficient than polling)
    if python3 -c "import pyinotify" 2>/dev/null; then
        echo "pyinotify"
        return
    fi

    # Default to auto
    echo "auto"
}

# Check if SSH jail is enabled
_f2b_ssh_jail_enabled() {
    if ! _f2b_installed || ! _f2b_service_active; then
        return 1
    fi

    # Check if sshd jail is active
    fail2ban-client status sshd &>/dev/null || \
    fail2ban-client status ssh &>/dev/null
}

# Get SSH jail configuration
_f2b_get_ssh_jail_config() {
    local jail_name=""

    # Determine which jail name is used
    if fail2ban-client status sshd &>/dev/null; then
        jail_name="sshd"
    elif fail2ban-client status ssh &>/dev/null; then
        jail_name="ssh"
    else
        return 1
    fi

    # Get jail status
    fail2ban-client status "$jail_name" 2>/dev/null
}

# Get ban statistics
_f2b_get_ban_count() {
    local jail_name=""

    if fail2ban-client status sshd &>/dev/null; then
        jail_name="sshd"
    elif fail2ban-client status ssh &>/dev/null; then
        jail_name="ssh"
    else
        echo "0"
        return
    fi

    fail2ban-client status "$jail_name" 2>/dev/null | \
        grep "Currently banned" | \
        awk '{print $NF}'
}

# Get total banned count
_f2b_get_total_banned() {
    local jail_name=""

    if fail2ban-client status sshd &>/dev/null; then
        jail_name="sshd"
    elif fail2ban-client status ssh &>/dev/null; then
        jail_name="ssh"
    else
        echo "0"
        return
    fi

    fail2ban-client status "$jail_name" 2>/dev/null | \
        grep "Total banned" | \
        awk '{print $NF}'
}

# Check jail.local exists with reasonable settings
_f2b_has_custom_config() {
    [[ -f "$F2B_JAIL_LOCAL" ]] || \
    [[ -d "$F2B_JAIL_D" && -n "$(ls -A "$F2B_JAIL_D"/*.conf 2>/dev/null)" ]]
}

# Get maxretry setting for SSH jail
_f2b_get_maxretry() {
    local maxretry=""

    # Check jail.local first
    if [[ -f "$F2B_JAIL_LOCAL" ]]; then
        maxretry=$(grep -E "^\s*maxretry\s*=" "$F2B_JAIL_LOCAL" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    fi

    # Check jail.d directory
    if [[ -z "$maxretry" && -d "$F2B_JAIL_D" ]]; then
        maxretry=$(grep -rh "^\s*maxretry\s*=" "$F2B_JAIL_D"/*.conf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    fi

    # Default value
    echo "${maxretry:-5}"
}

# Get bantime setting
_f2b_get_bantime() {
    local bantime=""

    if [[ -f "$F2B_JAIL_LOCAL" ]]; then
        bantime=$(grep -E "^\s*bantime\s*=" "$F2B_JAIL_LOCAL" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    fi

    if [[ -z "$bantime" && -d "$F2B_JAIL_D" ]]; then
        bantime=$(grep -rh "^\s*bantime\s*=" "$F2B_JAIL_D"/*.conf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    fi

    echo "${bantime:-10m}"
}

# ==============================================================================
# Fail2ban Audit
# ==============================================================================

fail2ban_audit() {
    local module="fail2ban"

    # Check if fail2ban is installed
    print_item "$(i18n 'fail2ban.check_installed')"
    if ! _f2b_installed; then
        local check=$(create_check_json \
            "fail2ban.not_installed" \
            "fail2ban" \
            "medium" \
            "failed" \
            "$(i18n 'fail2ban.not_installed')" \
            "fail2ban is not installed" \
            "$(i18n 'fail2ban.fix_install')" \
            "fail2ban.install")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'fail2ban.not_installed')"
        return
    fi
    print_ok "$(i18n 'fail2ban.installed')"

    # Check service status
    print_item "$(i18n 'fail2ban.check_service')"
    _f2b_audit_service

    # Check SSH jail
    print_item "$(i18n 'fail2ban.check_ssh_jail')"
    _f2b_audit_ssh_jail

    # Check configuration
    print_item "$(i18n 'fail2ban.check_config')"
    _f2b_audit_config
}

_f2b_audit_service() {
    if _f2b_service_active; then
        if _f2b_service_enabled; then
            local check=$(create_check_json \
                "fail2ban.service_active" \
                "fail2ban" \
                "low" \
                "passed" \
                "$(i18n 'fail2ban.service_active')" \
                "Service is running and enabled" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'fail2ban.service_active')"
        else
            local check=$(create_check_json \
                "fail2ban.service_not_enabled" \
                "fail2ban" \
                "low" \
                "failed" \
                "$(i18n 'fail2ban.service_not_enabled')" \
                "Service is running but not enabled at boot" \
                "Enable fail2ban service" \
                "fail2ban.enable_service")
            state_add_check "$check"
            print_severity "low" "$(i18n 'fail2ban.service_not_enabled')"
        fi
    else
        local check=$(create_check_json \
            "fail2ban.service_inactive" \
            "fail2ban" \
            "medium" \
            "failed" \
            "$(i18n 'fail2ban.service_inactive')" \
            "fail2ban service is not running" \
            "$(i18n 'fail2ban.fix_enable')" \
            "fail2ban.enable_service")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'fail2ban.service_inactive')"
    fi
}

_f2b_audit_ssh_jail() {
    if ! _f2b_service_active; then
        return  # Skip if service not running
    fi

    if _f2b_ssh_jail_enabled; then
        local current_banned=$(_f2b_get_ban_count)
        local total_banned=$(_f2b_get_total_banned)
        local maxretry=$(_f2b_get_maxretry)
        local bantime=$(_f2b_get_bantime)

        local check=$(create_check_json \
            "fail2ban.ssh_jail_enabled" \
            "fail2ban" \
            "low" \
            "passed" \
            "$(i18n 'fail2ban.ssh_jail_enabled')" \
            "Currently banned: $current_banned, Total: $total_banned, maxretry: $maxretry, bantime: $bantime" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'fail2ban.ssh_jail_enabled') (banned: $current_banned, total: $total_banned)"

        # Check if maxretry is too high
        if [[ "$maxretry" -gt 5 ]]; then
            local check=$(create_check_json \
                "fail2ban.maxretry_high" \
                "fail2ban" \
                "low" \
                "failed" \
                "$(i18n 'fail2ban.maxretry_high')" \
                "maxretry=$maxretry (recommended: 3-5)" \
                "Lower maxretry value" \
                "fail2ban.configure_ssh_jail")
            state_add_check "$check"
            print_severity "low" "$(i18n 'fail2ban.maxretry_high'): $maxretry"
        fi
    else
        local check=$(create_check_json \
            "fail2ban.ssh_jail_disabled" \
            "fail2ban" \
            "medium" \
            "failed" \
            "$(i18n 'fail2ban.ssh_jail_disabled')" \
            "SSH jail is not enabled" \
            "$(i18n 'fail2ban.fix_enable_ssh_jail')" \
            "fail2ban.enable_ssh_jail")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'fail2ban.ssh_jail_disabled')"
    fi
}

_f2b_audit_config() {
    if ! _f2b_service_active; then
        return
    fi

    if _f2b_has_custom_config; then
        local check=$(create_check_json \
            "fail2ban.custom_config" \
            "fail2ban" \
            "low" \
            "passed" \
            "$(i18n 'fail2ban.custom_config')" \
            "Custom configuration found" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'fail2ban.custom_config')"
    else
        local check=$(create_check_json \
            "fail2ban.default_config" \
            "fail2ban" \
            "low" \
            "failed" \
            "$(i18n 'fail2ban.default_config')" \
            "Using default configuration only" \
            "Create custom jail.local" \
            "fail2ban.configure_ssh_jail")
        state_add_check "$check"
        print_severity "low" "$(i18n 'fail2ban.default_config')"
    fi
}

# ==============================================================================
# Fail2ban Fix Functions
# ==============================================================================

fail2ban_fix() {
    local fix_id="$1"

    case "$fix_id" in
        fail2ban.install)
            _f2b_fix_install
            ;;
        fail2ban.enable_service)
            _f2b_fix_enable_service
            ;;
        fail2ban.enable_ssh_jail)
            _f2b_fix_enable_ssh_jail
            ;;
        fail2ban.configure_ssh_jail)
            _f2b_fix_configure_ssh_jail
            ;;
        *)
            log_error "Unknown fail2ban fix: $fix_id"
            return 1
            ;;
    esac
}

_f2b_fix_install() {
    print_info "$(i18n 'fail2ban.installing')"

    export DEBIAN_FRONTEND=noninteractive

    if apt-get update -qq && apt-get install -y fail2ban; then
        print_ok "$(i18n 'fail2ban.install_success')"

        # Enable and configure
        _f2b_fix_enable_service
        _f2b_fix_configure_ssh_jail

        return 0
    else
        print_error "$(i18n 'fail2ban.install_failed')"
        return 1
    fi
}

_f2b_fix_enable_service() {
    print_info "$(i18n 'fail2ban.enabling_service')"

    systemctl enable fail2ban 2>/dev/null
    systemctl start fail2ban 2>/dev/null

    if _f2b_service_active; then
        print_ok "$(i18n 'fail2ban.service_started')"
        return 0
    else
        print_error "$(i18n 'fail2ban.service_start_failed')"
        return 1
    fi
}

_f2b_fix_enable_ssh_jail() {
    _f2b_fix_configure_ssh_jail
}

_f2b_fix_configure_ssh_jail() {
    print_info "$(i18n 'fail2ban.configuring_ssh_jail')"

    # Backup existing config
    if [[ -f "$F2B_JAIL_LOCAL" ]]; then
        backup_file "$F2B_JAIL_LOCAL"
    fi

    # Get SSH port and detect log path/backend
    local ssh_port=$(get_ssh_port)
    local ssh_logpath=$(_f2b_detect_ssh_logpath)
    local f2b_backend=$(_f2b_detect_backend)

    print_info "Detected log path: $ssh_logpath"
    print_info "Detected backend: $f2b_backend"

    # Create jail.local with SSH configuration
    cat > "$F2B_JAIL_LOCAL" <<EOF
# vpssec fail2ban configuration
# Generated: $(date -Iseconds)
# Detected logpath: $ssh_logpath
# Detected backend: $f2b_backend

[DEFAULT]
# Ban duration (default: 10 minutes, increase for production)
bantime = 1h

# Time window for counting failures
findtime = 10m

# Max failures before ban
maxretry = 3

# Backend for log monitoring
backend = $f2b_backend

# Action: ban IP using iptables/nftables
banaction = iptables-multiport
banaction_allports = iptables-allports

# Email notifications (optional)
# destemail = admin@example.com
# sender = fail2ban@example.com
# action = %(action_mwl)s

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = $ssh_logpath
backend = $f2b_backend
maxretry = 3
bantime = 1h
findtime = 10m

# Aggressive mode for repeated offenders (optional)
# [sshd-aggressive]
# enabled = true
# port = $ssh_port
# filter = sshd[mode=aggressive]
# logpath = $ssh_logpath
# maxretry = 1
# bantime = 1w
EOF

    chmod 644 "$F2B_JAIL_LOCAL"

    # Reload fail2ban
    if _f2b_service_active; then
        fail2ban-client reload 2>/dev/null
    else
        systemctl start fail2ban 2>/dev/null
    fi

    # Verify SSH jail is now enabled
    sleep 2  # Give fail2ban time to start
    if _f2b_ssh_jail_enabled; then
        print_ok "$(i18n 'fail2ban.ssh_jail_configured')"
        return 0
    else
        print_error "$(i18n 'fail2ban.ssh_jail_config_failed')"
        return 1
    fi
}

# ==============================================================================
# Fail2ban Utility Functions
# ==============================================================================

# Unban an IP address (utility for other scripts)
f2b_unban_ip() {
    local ip="$1"
    local jail="${2:-sshd}"

    if _f2b_service_active; then
        fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null
    fi
}

# Get list of currently banned IPs
f2b_get_banned_ips() {
    local jail="${1:-sshd}"

    if _f2b_service_active; then
        fail2ban-client status "$jail" 2>/dev/null | \
            grep "Banned IP list" | \
            cut -d: -f2 | \
            tr -d '\t'
    fi
}
