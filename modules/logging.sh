#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Logging and audit module
# Copyright (c) 2024

# --- Logging Configuration ---

JOURNALD_CONF="/etc/systemd/journald.conf"
JOURNALD_CONF_D="/etc/systemd/journald.conf.d"
JOURNALD_DROPIN="${JOURNALD_CONF_D}/99-vpssec.conf"
# The directory whose mere existence makes journald persist. A module
# variable rather than a literal so the audit predicate and the fix cannot
# be pointed at different places, and so both are reachable from a test.
JOURNAL_DIR="/var/log/journal"
LOGROTATE_CONF="/etc/logrotate.conf"
LOGROTATE_D="/etc/logrotate.d"
RSYSLOG_CONF="/etc/rsyslog.conf"
AUDIT_RULES_D="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_D}/99-vpssec.rules"

# --- Logging Helper Functions ---

_logging_journald_persistent() {
    # Check if journal is configured for persistent storage
    if [[ -d "$JOURNAL_DIR" ]]; then
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

# Pure-data variant for tests. Argument is the merged journald config
# text. Echoes the last SystemMaxUse= value found, or empty.
_logging_journald_max_size_from_text() {
    awk -F= '
        /^SystemMaxUse=/ {
            gsub(/[[:space:]]/, "", $2)
            v = $2
        }
        END { if (v != "") print v }
    ' <<<"$1"
}

# Last definition wins across the main file and drop-ins, matching systemd.
# Reading only the main file makes vpssec's own drop-in invisible here.
_logging_journald_max_size() {
    local size=""
    if command -v systemd-analyze >/dev/null 2>&1; then
        local merged
        merged=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null)
        size=$(_logging_journald_max_size_from_text "$merged")
    fi
    if [[ -z "$size" ]]; then
        # Fallback: manually read main + drop-ins (alphabetical, last wins).
        local f text=""
        for f in "$JOURNALD_CONF" "$JOURNALD_CONF_D"/*.conf; do
            [[ -f "$f" ]] || continue
            text="${text}$(cat "$f" 2>/dev/null)
"
        done
        size=$(_logging_journald_max_size_from_text "$text")
    fi
    echo "${size:-auto}"
}

_logging_check_logrotate() {
    # Check if logrotate is installed and configured
    check_command logrotate && [[ -f "$LOGROTATE_CONF" ]]
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
    # Filters on _COMM (the unit is ssh.service on Debian) and matches BOTH
    # sshd and sshd-session, since OpenSSH 9.8+ logs auth failures from the
    # latter. Non-zero with no output = query failed, which is not zero.
    local out count
    out=$(journalctl _COMM=sshd _COMM=sshd-session --since "24 hours ago" 2>/dev/null) || return 1
    # Note: grep -c outputs "0" AND exits 1 when no matches; `|| count=0`
    # (not `|| echo 0`) avoids the historical "0\n0" double-output bug.
    count=$(grep -c "Failed password\|authentication failure" <<<"$out" 2>/dev/null) || count=0
    echo "${count:-0}"
}

_logging_get_sudo_events() {
    # Same contract as _logging_get_failed_logins: non-zero when journalctl
    # itself failed, a real count otherwise.
    local out count
    out=$(journalctl _COMM=sudo --since "24 hours ago" 2>/dev/null) || return 1
    count=$(wc -l <<<"$out") || count=0
    # wc -l counts the herestring's trailing newline even when empty.
    [[ -z "$out" ]] && count=0
    echo "${count:-0}"
}

# --- Logging Audit ---

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
            "low" \
            "failed" \
            "$(i18n 'logging.journald_volatile')" \
            "$(i18n 'logging.journald_volatile_desc')" \
            "$(i18n 'logging.fix_enable_persistent')" \
            "logging.enable_persistent_journal")
        state_add_check "$check"
        print_severity "low" "$(i18n 'logging.journald_volatile')"
    fi
}

_logging_audit_logrotate() {
    if _logging_check_logrotate; then
        # Check if critical log files have rotation configured
        local missing=()

        # Per-distro critical logs from distro.sh; this is the Debian
        # fallback. RHEL uses messages/secure/dnf.rpm.log, Arch pacman.log.
        local logs="syslog auth.log dpkg.log"
        if declare -f distro_log_paths >/dev/null 2>&1; then
            local dl; dl=$(distro_log_paths)
            if [[ -n "$dl" ]]; then logs="$dl"; fi
        fi

        for log in $logs; do
            # BOTH logrotate.conf and logrotate.d: many distros configure
            # core logs directly in the former.
            if [[ -f "/var/log/$log" ]] && ! grep -rq "$log" "$LOGROTATE_CONF" "$LOGROTATE_D" 2>/dev/null; then
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
            "low" \
            "failed" \
            "$(i18n 'logging.logrotate_missing')" \
            "$(i18n 'logging.logrotate_missing_desc')" \
            "$(i18n 'logging.fix_configure_logrotate')" \
            "logging.setup_logrotate")
        state_add_check "$check"
        print_severity "low" "$(i18n 'logging.logrotate_missing')"
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
                    "low" \
                    "failed" \
                    "$(i18n 'logging.auditd_no_rules')" \
                    "$(i18n 'logging.auditd_no_rules_desc')" \
                    "$(i18n 'logging.fix_configure_auditd')" \
                    "logging.setup_audit_rules")
                state_add_check "$check"
                print_severity "low" "$(i18n 'logging.auditd_no_rules')"
            fi
        else
            local check=$(create_check_json \
                "logging.auditd_inactive" \
                "logging" \
                "low" \
                "failed" \
                "$(i18n 'logging.auditd_not_running')" \
                "$(i18n 'logging.auditd_not_running_desc')" \
                "$(i18n 'logging.fix_enable_auditd')" \
                "logging.enable_auditd")
            state_add_check "$check"
            print_severity "low" "$(i18n 'logging.auditd_not_running')"
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
    # Query failure is its own outcome: "0 failed logins" claims the journal
    # was read and found quiet. Emitted failed + info, like update.check_failed.
    local failed_logins
    if ! failed_logins=$(_logging_get_failed_logins); then
        local check=$(create_check_json \
            "logging.journal_unreadable" \
            "logging" \
            "low" \
            "failed" \
            "$(i18n 'logging.journal_unreadable')" \
            "$(i18n 'logging.journal_unreadable_desc')" \
            "$(i18n 'logging.journal_unreadable_fix')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'logging.journal_unreadable')"
        return 0
    fi

    if ((failed_logins > 100)); then
        local check=$(create_check_json \
            "logging.ssh_many_failures" \
            "logging" \
            "low" \
            "failed" \
            "$(i18n 'logging.ssh_logs_warning')" \
            "$(i18n 'logging.ssh_logs_warning_desc' "count=$failed_logins")" \
            "" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'logging.ssh_logs_high' "count=$failed_logins")"
    elif ((failed_logins > 20)); then
        local check=$(create_check_json \
            "logging.ssh_some_failures" \
            "logging" \
            "low" \
            "failed" \
            "$(i18n 'logging.ssh_logs_moderate' "count=$failed_logins")" \
            "$(i18n 'logging.ssh_logs_warning_desc' "count=$failed_logins")" \
            "" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'logging.ssh_logs_moderate' "count=$failed_logins")"
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
    # Unreadable journal: the ssh-logs check right above this already
    # reported it (logging.journal_unreadable); repeating the finding per
    # consumer would be noise. Just skip the sudo claim we cannot make.
    local sudo_events
    if ! sudo_events=$(_logging_get_sudo_events); then
        return 0
    fi

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

# --- Logging Fix Functions ---

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
    mkdir -p "$JOURNAL_DIR"
    systemd-tmpfiles --create --prefix "$JOURNAL_DIR"

    # backup_file is UNCONDITIONAL: it also records an absent path as
    # fix-created, which is the only thing that lets a rollback delete this
    # drop-in. Never guard it on the file already existing.
    mkdir -p "$JOURNALD_CONF_D"
    backup_file "$JOURNALD_DROPIN" >/dev/null || return 1
    write_file_atomic "$JOURNALD_DROPIN" '# vpssec journald configuration
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=1month'

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

    # The install status must propagate: returning 0 regardless records a
    # completion the next audit contradicts.
    if ! check_command logrotate; then
        # Refresh first, or an empty apt cache gives "Unable to locate
        # package". NOT gated on update's status: one broken third-party repo
        # makes it non-zero while the package is still installable.
        DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y logrotate 2>/dev/null; then
            print_error "$(i18n 'logging.logrotate_install_failed')"
            return 1
        fi
    fi

    # Only reached when the install could not supply the conffile. Goes
    # through backup_file + write_file_atomic like every other /etc write:
    # a bare `cat >` truncates on interrupt and leaves no rollback entry.
    if [[ ! -f "$LOGROTATE_CONF" ]]; then
        backup_file "$LOGROTATE_CONF" >/dev/null || return 1
        if ! write_file_atomic "$LOGROTATE_CONF" '# vpssec logrotate configuration
weekly
rotate 4
create
dateext
compress
delaycompress
include /etc/logrotate.d'; then
            print_error "$(i18n 'logging.logrotate_failed')"
            return 1
        fi
    fi

    print_ok "$(i18n 'logging.logrotate_configured')"
    return 0
}

_logging_fix_install_auditd() {
    print_info "$(i18n 'logging.installing_auditd')"

    if DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins 2>/dev/null; then
        print_ok "$(i18n 'logging.auditd_installed')"

        # The follow-ups are a convenience and deliberately do NOT decide this
        # fix: it answers logging.auditd_not_installed, which measures the
        # install. The service and rules have their own checks and fix_ids.
        _logging_fix_enable_auditd || true
        _logging_fix_setup_audit_rules || true
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

    # Built then written atomically: a truncated 99-vpssec.rules is rejected
    # by auditd on the next load.
    local rules_content
    rules_content=$(cat <<'EOF'
# vpssec audit rules for security monitoring

# NOTE: intentionally NO `-D` here. augenrules concatenates rules.d/*.rules in
# lexical order, and this file sorts LAST (99-). A `-D` (delete-all) at the top
# of the last file wipes every rule loaded from earlier files — including a
# hand-written 10-*/20-* ruleset and the base audit.rules. The base audit.rules
# already carries the single `-D` that resets the set at the start of the load,
# so vpssec's rules are purely additive.

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

# Lock the audit configuration (RECOMMENDED for production / compliance).
# With -e 2 the rules cannot be modified until the next reboot, which
# prevents an attacker with root from running `auditctl -D` to erase
# the forensic trail before tampering. Trade-off: editing /etc/audit
# rules will also require a reboot. Uncomment this line if your
# environment can accept that operational cost.
# -e 2
EOF
)

    # Unconditional: an existing file must be restorable, and an absent one
    # must be recorded as fix-created so a rollback deletes it.
    backup_file "$AUDIT_RULES_FILE" >/dev/null || return 1

    if ! write_file_atomic "$AUDIT_RULES_FILE" "$rules_content"; then
        print_error "$(i18n 'logging.audit_rules_failed')"
        return 1
    fi

    # Report whether the KERNEL took the rules (auditctl -l), not whether the
    # file exists: augenrules can fail while the file looks fine on disk.
    augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true

    if auditctl -l 2>/dev/null | grep -q '.'; then
        print_ok "$(i18n 'logging.audit_rules_configured')"
        print_info "$(i18n 'logging.audit_immutable_hint')"
        return 0
    elif _logging_check_audit_rules; then
        # File correctly persisted but not live yet (e.g. auditd not running in
        # this environment); it applies at next auditd start / reboot.
        print_warn "$(i18n 'logging.audit_rules_pending')"
        return 0
    else
        print_error "$(i18n 'logging.audit_rules_failed')"
        return 1
    fi
}
