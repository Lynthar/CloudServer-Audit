#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Logging and audit module
# Copyright (c) 2024

# ==============================================================================
# Logging Configuration
# ==============================================================================

JOURNALD_CONF="/etc/systemd/journald.conf"
JOURNALD_CONF_D="/etc/systemd/journald.conf.d"
LOGROTATE_CONF="/etc/logrotate.conf"
LOGROTATE_D="/etc/logrotate.d"
RSYSLOG_CONF="/etc/rsyslog.conf"
AUDIT_RULES_D="/etc/audit/rules.d"

# ==============================================================================
# Logging Helper Functions
# ==============================================================================

_logging_journald_persistent() {
    # Check if journal is configured for persistent storage
    if [[ -d "/var/log/journal" ]]; then
        return 0
    fi

    if grep -qE "^Storage=persistent" "$JOURNALD_CONF" 2>/dev/null; then
        return 0
    fi

    if [[ -d "$JOURNALD_CONF_D" ]]; then
        if grep -rqE "^Storage=persistent" "$JOURNALD_CONF_D" 2>/dev/null; then
            return 0
        fi
    fi

    return 1
}

_logging_journald_max_size() {
    local size=$(grep -E "^SystemMaxUse=" "$JOURNALD_CONF" 2>/dev/null | cut -d= -f2)
    echo "${size:-auto}"
}

_logging_check_logrotate() {
    # Check if logrotate is installed and configured
    check_command logrotate && [[ -f "$LOGROTATE_CONF" ]]
}

_logging_check_syslog_remote() {
    # Check if remote syslog is configured
    if [[ -f "$RSYSLOG_CONF" ]]; then
        grep -qE "^[^#]*@@?" "$RSYSLOG_CONF" 2>/dev/null
    else
        return 1
    fi
}

_logging_check_audit_installed() {
    check_command auditd && check_command auditctl
}

_logging_check_audit_rules() {
    if [[ -d "$AUDIT_RULES_D" ]]; then
        local rule_count=$(find "$AUDIT_RULES_D" -name "*.rules" -type f 2>/dev/null | wc -l)
        [[ "$rule_count" -gt 0 ]]
    else
        return 1
    fi
}

_logging_get_failed_logins() {
    # Get recent failed login attempts
    # Note: grep -c outputs "0" AND exits with code 1 when no matches
    # Using || true prevents double output from || echo "0"
    local count
    count=$(journalctl _SYSTEMD_UNIT=sshd.service --since "24 hours ago" 2>/dev/null | \
        grep -c "Failed password\|authentication failure" 2>/dev/null) || true
    echo "${count:-0}"
}

_logging_get_sudo_events() {
    # Get recent sudo events
    journalctl _COMM=sudo --since "24 hours ago" 2>/dev/null | wc -l || echo "0"
}

# ==============================================================================
# Logging Audit
# ==============================================================================

logging_audit() {
    local module="logging"

    # Check journald persistence
    print_item "Checking journald persistence..."
    _logging_audit_journald

    # Check logrotate
    print_item "Checking logrotate configuration..."
    _logging_audit_logrotate

    # Check audit system
    print_item "Checking audit system..."
    _logging_audit_auditd

    # Check SSH logs
    print_item "Checking SSH authentication logs..."
    _logging_audit_ssh_logs

    # Check sudo logging
    print_item "Checking sudo logging..."
    _logging_audit_sudo_logs
}

_logging_audit_journald() {
    if _logging_journald_persistent; then
        local max_size=$(_logging_journald_max_size)
        local check=$(create_check_json \
            "logging.journald_persistent" \
            "logging" \
            "low" \
            "passed" \
            "Journald persistent storage enabled" \
            "Max size: $max_size" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Journald persistent storage enabled (max: $max_size)"
    else
        local check=$(create_check_json \
            "logging.journald_volatile" \
            "logging" \
            "medium" \
            "failed" \
            "Journald using volatile storage" \
            "Logs are lost on reboot" \
            "Enable persistent storage" \
            "logging.enable_persistent_journal")
        state_add_check "$check"
        print_severity "medium" "Journald using volatile storage (logs lost on reboot)"
    fi
}

_logging_audit_logrotate() {
    if _logging_check_logrotate; then
        # Check if critical log files have rotation configured
        local missing=()

        for log in syslog auth.log dpkg.log; do
            if [[ -f "/var/log/$log" ]] && ! grep -rq "$log" "$LOGROTATE_D" 2>/dev/null; then
                missing+=("$log")
            fi
        done

        if [[ ${#missing[@]} -eq 0 ]]; then
            local check=$(create_check_json \
                "logging.logrotate_ok" \
                "logging" \
                "low" \
                "passed" \
                "Logrotate properly configured" \
                "" \
                "" \
                "")
            state_add_check "$check"
            print_ok "Logrotate properly configured"
        else
            local check=$(create_check_json \
                "logging.logrotate_missing" \
                "logging" \
                "low" \
                "failed" \
                "Some logs missing rotation config" \
                "Missing: ${missing[*]}" \
                "Add logrotate configuration" \
                "")
            state_add_check "$check"
            print_severity "low" "Some logs missing rotation: ${missing[*]}"
        fi
    else
        local check=$(create_check_json \
            "logging.logrotate_not_configured" \
            "logging" \
            "medium" \
            "failed" \
            "Logrotate not configured" \
            "Log rotation is not set up" \
            "Install and configure logrotate" \
            "logging.setup_logrotate")
        state_add_check "$check"
        print_severity "medium" "Logrotate not configured"
    fi
}

_logging_audit_auditd() {
    if _logging_check_audit_installed; then
        if systemctl is-active --quiet auditd; then
            if _logging_check_audit_rules; then
                local check=$(create_check_json \
                    "logging.auditd_configured" \
                    "logging" \
                    "low" \
                    "passed" \
                    "Audit daemon running with rules" \
                    "" \
                    "" \
                    "")
                state_add_check "$check"
                print_ok "Audit daemon running with rules configured"
            else
                local check=$(create_check_json \
                    "logging.auditd_no_rules" \
                    "logging" \
                    "medium" \
                    "failed" \
                    "Audit daemon running but no rules" \
                    "No audit rules configured" \
                    "Add audit rules" \
                    "logging.setup_audit_rules")
                state_add_check "$check"
                print_severity "medium" "Audit daemon running but no rules configured"
            fi
        else
            local check=$(create_check_json \
                "logging.auditd_inactive" \
                "logging" \
                "medium" \
                "failed" \
                "Audit daemon not running" \
                "auditd is installed but not active" \
                "Start and enable auditd" \
                "logging.enable_auditd")
            state_add_check "$check"
            print_severity "medium" "Audit daemon not running"
        fi
    else
        local check=$(create_check_json \
            "logging.auditd_not_installed" \
            "logging" \
            "low" \
            "failed" \
            "Audit daemon not installed" \
            "auditd provides detailed system auditing" \
            "Install auditd for enhanced auditing" \
            "logging.install_auditd")
        state_add_check "$check"
        print_severity "low" "Audit daemon not installed (optional but recommended)"
    fi
}

_logging_audit_ssh_logs() {
    local failed_logins=$(_logging_get_failed_logins)

    if ((failed_logins > 100)); then
        local check=$(create_check_json \
            "logging.ssh_many_failures" \
            "logging" \
            "high" \
            "failed" \
            "High number of SSH login failures" \
            "$failed_logins failed attempts in last 24h" \
            "Consider fail2ban or stricter firewall rules" \
            "")
        state_add_check "$check"
        print_severity "high" "$failed_logins SSH login failures in last 24h (possible brute force)"
    elif ((failed_logins > 20)); then
        local check=$(create_check_json \
            "logging.ssh_some_failures" \
            "logging" \
            "medium" \
            "failed" \
            "Moderate SSH login failures" \
            "$failed_logins failed attempts in last 24h" \
            "Monitor for brute force attempts" \
            "")
        state_add_check "$check"
        print_severity "medium" "$failed_logins SSH login failures in last 24h"
    else
        local check=$(create_check_json \
            "logging.ssh_logs_ok" \
            "logging" \
            "low" \
            "passed" \
            "SSH authentication logs normal" \
            "$failed_logins failed attempts in last 24h" \
            "" \
            "")
        state_add_check "$check"
        print_ok "SSH logs normal ($failed_logins failures in 24h)"
    fi
}

_logging_audit_sudo_logs() {
    local sudo_events=$(_logging_get_sudo_events)

    # Just informational - sudo logging should be working
    if ((sudo_events > 0)); then
        local check=$(create_check_json \
            "logging.sudo_logging_ok" \
            "logging" \
            "low" \
            "passed" \
            "Sudo events being logged" \
            "$sudo_events events in last 24h" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Sudo logging active ($sudo_events events in 24h)"
    else
        local check=$(create_check_json \
            "logging.sudo_no_events" \
            "logging" \
            "low" \
            "passed" \
            "No sudo events in last 24h" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "No sudo events in last 24h"
    fi
}

# ==============================================================================
# Logging Fix Functions
# ==============================================================================

logging_fix() {
    local fix_id="$1"

    case "$fix_id" in
        logging.enable_persistent_journal)
            _logging_fix_enable_persistent_journal
            ;;
        logging.setup_logrotate)
            _logging_fix_setup_logrotate
            ;;
        logging.install_auditd)
            _logging_fix_install_auditd
            ;;
        logging.enable_auditd)
            _logging_fix_enable_auditd
            ;;
        logging.setup_audit_rules)
            _logging_fix_setup_audit_rules
            ;;
        *)
            log_warn "Logging fix not implemented: $fix_id"
            return 1
            ;;
    esac
}

_logging_fix_enable_persistent_journal() {
    print_info "Enabling persistent journal storage..."

    # Create journal directory
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal

    # Create drop-in configuration
    mkdir -p "$JOURNALD_CONF_D"
    cat > "${JOURNALD_CONF_D}/99-vpssec.conf" <<'EOF'
# vpssec journald configuration
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=1month
EOF

    # Restart journald
    systemctl restart systemd-journald

    if _logging_journald_persistent; then
        print_ok "Persistent journal storage enabled"
        return 0
    else
        print_error "Failed to enable persistent storage"
        return 1
    fi
}

_logging_fix_setup_logrotate() {
    print_info "Setting up logrotate..."

    apt-get install -y logrotate 2>/dev/null

    # Ensure default config exists
    if [[ ! -f "$LOGROTATE_CONF" ]]; then
        cat > "$LOGROTATE_CONF" <<'EOF'
# vpssec logrotate configuration
weekly
rotate 4
create
dateext
compress
delaycompress
include /etc/logrotate.d
EOF
    fi

    print_ok "Logrotate configured"
    return 0
}

_logging_fix_install_auditd() {
    print_info "Installing auditd..."

    if apt-get install -y auditd audispd-plugins 2>/dev/null; then
        print_ok "Auditd installed"
        _logging_fix_enable_auditd
        _logging_fix_setup_audit_rules
        return 0
    else
        print_error "Failed to install auditd"
        return 1
    fi
}

_logging_fix_enable_auditd() {
    print_info "Enabling auditd service..."

    systemctl enable auditd
    systemctl start auditd

    if systemctl is-active --quiet auditd; then
        print_ok "Auditd service enabled and started"
        return 0
    else
        print_error "Failed to start auditd"
        return 1
    fi
}

_logging_fix_setup_audit_rules() {
    print_info "Setting up audit rules..."

    mkdir -p "$AUDIT_RULES_D"

    # Create security-focused audit rules
    cat > "${AUDIT_RULES_D}/99-vpssec.rules" <<'EOF'
# vpssec audit rules for security monitoring

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor login files
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Make configuration immutable (uncomment for production)
# -e 2
EOF

    # Load rules
    augenrules --load 2>/dev/null || auditctl -R "${AUDIT_RULES_D}/99-vpssec.rules" 2>/dev/null

    if _logging_check_audit_rules; then
        print_ok "Audit rules configured"
        return 0
    else
        print_error "Failed to configure audit rules"
        return 1
    fi
}
