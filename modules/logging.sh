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
    print_item "$(i18n 'logging.check_journald')"
    _logging_audit_journald

    # Check logrotate
    print_item "$(i18n 'logging.check_logrotate')"
    _logging_audit_logrotate

    # Check audit system
    print_item "$(i18n 'logging.check_auditd')"
    _logging_audit_auditd

    # Check SSH logs
    print_item "$(i18n 'logging.check_ssh_logs')"
    _logging_audit_ssh_logs

    # Check sudo logging
    print_item "$(i18n 'logging.check_sudo_logs')"
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
            "$(i18n 'logging.journald_persistent')" \
            "$(i18n 'logging.journald_max_size' "size=$max_size")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'logging.journald_persistent') ($(i18n 'logging.journald_max_size' "size=$max_size"))"
    else
        local check=$(create_check_json \
            "logging.journald_volatile" \
            "logging" \
            "medium" \
            "failed" \
            "$(i18n 'logging.journald_volatile')" \
            "$(i18n 'logging.journald_volatile_desc')" \
            "$(i18n 'logging.fix_enable_persistent')" \
            "logging.enable_persistent_journal")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'logging.journald_volatile')"
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
                "$(i18n 'logging.logrotate_ok')" \
                "" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'logging.logrotate_ok')"
        else
            local check=$(create_check_json \
                "logging.logrotate_missing" \
                "logging" \
                "low" \
                "failed" \
                "$(i18n 'logging.logrotate_some_missing' "logs=${missing[*]}")" \
                "$(i18n 'logging.logrotate_missing_desc')" \
                "$(i18n 'logging.fix_configure_logrotate')" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'logging.logrotate_some_missing' "logs=${missing[*]}")"
        fi
    else
        local check=$(create_check_json \
            "logging.logrotate_not_configured" \
            "logging" \
            "medium" \
            "failed" \
            "$(i18n 'logging.logrotate_missing')" \
            "$(i18n 'logging.logrotate_missing_desc')" \
            "$(i18n 'logging.fix_configure_logrotate')" \
            "logging.setup_logrotate")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'logging.logrotate_missing')"
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
                    "$(i18n 'logging.auditd_running')" \
                    "" \
                    "" \
                    "")
                state_add_check "$check"
                print_ok "$(i18n 'logging.auditd_running')"
            else
                local check=$(create_check_json \
                    "logging.auditd_no_rules" \
                    "logging" \
                    "medium" \
                    "failed" \
                    "$(i18n 'logging.auditd_no_rules')" \
                    "$(i18n 'logging.auditd_no_rules_desc')" \
                    "$(i18n 'logging.fix_configure_auditd')" \
                    "logging.setup_audit_rules")
                state_add_check "$check"
                print_severity "medium" "$(i18n 'logging.auditd_no_rules')"
            fi
        else
            local check=$(create_check_json \
                "logging.auditd_inactive" \
                "logging" \
                "medium" \
                "failed" \
                "$(i18n 'logging.auditd_not_running')" \
                "$(i18n 'logging.auditd_not_running_desc')" \
                "$(i18n 'logging.fix_enable_auditd')" \
                "logging.enable_auditd")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'logging.auditd_not_running')"
        fi
    else
        local check=$(create_check_json \
            "logging.auditd_not_installed" \
            "logging" \
            "low" \
            "failed" \
            "$(i18n 'logging.auditd_not_installed')" \
            "$(i18n 'logging.auditd_not_running_desc')" \
            "$(i18n 'logging.fix_install_auditd')" \
            "logging.install_auditd")
        state_add_check "$check"
        print_severity "low" "$(i18n 'logging.auditd_not_installed')"
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
            "$(i18n 'logging.ssh_logs_warning')" \
            "$(i18n 'logging.ssh_logs_warning_desc' "count=$failed_logins")" \
            "" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'logging.ssh_logs_high' "count=$failed_logins")"
    elif ((failed_logins > 20)); then
        local check=$(create_check_json \
            "logging.ssh_some_failures" \
            "logging" \
            "medium" \
            "failed" \
            "$(i18n 'logging.ssh_logs_moderate' "count=$failed_logins")" \
            "$(i18n 'logging.ssh_logs_warning_desc' "count=$failed_logins")" \
            "" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'logging.ssh_logs_moderate' "count=$failed_logins")"
    else
        local check=$(create_check_json \
            "logging.ssh_logs_ok" \
            "logging" \
            "low" \
            "passed" \
            "$(i18n 'logging.ssh_logs_normal' "count=$failed_logins")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'logging.ssh_logs_normal' "count=$failed_logins")"
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
            "$(i18n 'logging.sudo_logs_active' "count=$sudo_events")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'logging.sudo_logs_active' "count=$sudo_events")"
    else
        local check=$(create_check_json \
            "logging.sudo_no_events" \
            "logging" \
            "low" \
            "passed" \
            "$(i18n 'logging.sudo_no_events')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'logging.sudo_no_events')"
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
    print_info "$(i18n 'logging.enabling_persistent')"

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
        print_ok "$(i18n 'logging.persistent_enabled')"
        return 0
    else
        print_error "$(i18n 'logging.persistent_failed')"
        return 1
    fi
}

_logging_fix_setup_logrotate() {
    print_info "$(i18n 'logging.configuring_logrotate')"

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

    print_ok "$(i18n 'logging.logrotate_configured')"
    return 0
}

_logging_fix_install_auditd() {
    print_info "$(i18n 'logging.installing_auditd')"

    if apt-get install -y auditd audispd-plugins 2>/dev/null; then
        print_ok "$(i18n 'logging.auditd_installed')"
        _logging_fix_enable_auditd
        _logging_fix_setup_audit_rules
        return 0
    else
        print_error "$(i18n 'logging.auditd_install_failed')"
        return 1
    fi
}

_logging_fix_enable_auditd() {
    print_info "$(i18n 'logging.enabling_auditd')"

    systemctl enable auditd
    systemctl start auditd

    if systemctl is-active --quiet auditd; then
        print_ok "$(i18n 'logging.auditd_service_enabled')"
        return 0
    else
        print_error "$(i18n 'logging.auditd_start_failed')"
        return 1
    fi
}

_logging_fix_setup_audit_rules() {
    print_info "$(i18n 'logging.configuring_audit_rules')"

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
        print_ok "$(i18n 'logging.audit_rules_configured')"
        return 0
    else
        print_error "$(i18n 'logging.audit_rules_failed')"
        return 1
    fi
}
