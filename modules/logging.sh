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
AUDIT_RULES_D="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_D}/99-vpssec.rules"
# What augenrules --load regenerates from rules.d.
AUDIT_RULES_COMPILED="/etc/audit/audit.rules"

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

# The syslog daemon writing /var/log, if one runs: with it, a volatile
# journal loses only the journal across a reboot, not the system logs.
_logging_syslog_daemon() {
    local unit
    for unit in rsyslog syslog-ng; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            echo "$unit"
            return 0
        fi
    done
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

_logging_auditd_active() {
    systemctl is-active --quiet auditd
}

_logging_check_audit_rules() {
    if [[ -d "$AUDIT_RULES_D" ]]; then
        local rule_count=$(find "$AUDIT_RULES_D" -name "*.rules" -type f 2>/dev/null | wc -l)
        [[ "$rule_count" -gt 0 ]]
    else
        return 1
    fi
}

# journalctl's output for the matches in "$@" over the last 24 hours (count
# lines matching a pattern, not lines). Fails when journalctl failed or found
# no journal at all: that only says "No journal files were found.", exit 0.
_logging_journal_24h() {
    local out
    out=$(journalctl "$@" --since "24 hours ago" 2>&1) || return 1
    grep -q '^No journal files were found' <<<"$out" && return 1
    printf '%s\n' "$out"
}

_logging_get_failed_logins() {
    # Filters on _COMM (the unit is ssh.service on Debian) and matches BOTH
    # sshd and sshd-session, since OpenSSH 9.8+ logs auth failures from the
    # latter. A query that failed is not zero.
    local out count
    out=$(_logging_journal_24h _COMM=sshd _COMM=sshd-session) || return 1
    # Note: grep -c outputs "0" AND exits 1 when no matches; `|| count=0`
    # (not `|| echo 0`) avoids the historical "0\n0" double-output bug.
    count=$(grep -c "Failed password\|authentication failure" <<<"$out" 2>/dev/null) || count=0
    echo "${count:-0}"
}

_logging_get_sudo_events() {
    # One event per command sudo ran: its session opened/closed lines are not.
    local out count
    out=$(_logging_journal_24h _COMM=sudo) || return 1
    count=$(grep -c 'COMMAND=' <<<"$out" 2>/dev/null) || count=0
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
        check_emit "logging.journald_persistent" low passed \
            desc="$(i18n 'logging.journald_max_size' "size=$max_size")"
        print_ok "$(i18n 'logging.journald_persistent') ($(i18n 'logging.journald_max_size' "size=$max_size"))"
    else
        local desc daemon
        if daemon=$(_logging_syslog_daemon); then
            desc=$(i18n 'logging.journald_volatile_syslog_desc' "daemon=$daemon")
        else
            desc=$(i18n 'logging.journald_volatile_desc')
        fi
        check_emit "logging.journald_volatile" low failed \
            desc="$desc" \
            suggestion="$(i18n 'logging.fix_enable_persistent')" \
            fix="logging.enable_persistent_journal"
        print_severity "low" "$(i18n 'logging.journald_volatile')"
    fi
}

_logging_audit_logrotate() {
    if _logging_check_logrotate; then
        # Check if critical log files have rotation configured
        local missing=()

        # Per-distro critical logs from distro.sh; a family it has no list
        # for gets the Debian names.
        local logs dl
        dl=$(distro_log_paths)
        logs="${dl:-syslog auth.log dpkg.log}"

        for log in $logs; do
            # BOTH logrotate.conf and logrotate.d: many distros configure
            # core logs directly in the former.
            if [[ -f "/var/log/$log" ]] && ! grep -rq "$log" "$LOGROTATE_CONF" "$LOGROTATE_D" 2>/dev/null; then
                missing+=("$log")
            fi
        done

        if [[ ${#missing[@]} -eq 0 ]]; then
            check_emit "logging.logrotate_ok" low passed
            print_ok "$(i18n 'logging.logrotate_ok')"
        else
            check_emit "logging.logrotate_missing" low failed \
                title="$(i18n 'logging.logrotate_some_missing' "logs=${missing[*]}")" \
                desc="$(i18n 'logging.logrotate_missing_desc')" \
                suggestion="$(i18n 'logging.fix_configure_logrotate')"
            print_severity "low" "$(i18n 'logging.logrotate_some_missing' "logs=${missing[*]}")"
        fi
    else
        check_emit "logging.logrotate_not_configured" low failed \
            title="$(i18n 'logging.logrotate_missing')" \
            desc="$(i18n 'logging.logrotate_missing_desc')" \
            suggestion="$(i18n 'logging.fix_configure_logrotate')" \
            fix="logging.setup_logrotate"
        print_severity "low" "$(i18n 'logging.logrotate_missing')"
    fi
}

_logging_audit_auditd() {
    if _logging_check_audit_installed; then
        if _logging_auditd_active; then
            if _logging_check_audit_rules; then
                check_emit "logging.auditd_configured" low passed \
                    title="$(i18n 'logging.auditd_running')"
                print_ok "$(i18n 'logging.auditd_running')"
            else
                check_emit "logging.auditd_no_rules" low failed \
                    desc="$(i18n 'logging.auditd_no_rules_desc')" \
                    suggestion="$(i18n 'logging.fix_configure_auditd')" \
                    fix="logging.setup_audit_rules"
                print_severity "low" "$(i18n 'logging.auditd_no_rules')"
            fi
        else
            check_emit "logging.auditd_inactive" low failed \
                title="$(i18n 'logging.auditd_not_running')" \
                desc="$(i18n 'logging.auditd_not_running_desc')" \
                suggestion="$(i18n 'logging.fix_enable_auditd')" \
                fix="logging.enable_auditd"
            print_severity "low" "$(i18n 'logging.auditd_not_running')"
        fi
    else
        check_emit "logging.auditd_not_installed" low failed \
            desc="$(i18n 'logging.auditd_not_running_desc')" \
            suggestion="$(i18n 'logging.fix_install_auditd')" \
            fix="logging.install_auditd"
        print_severity "low" "$(i18n 'logging.auditd_not_installed')"
    fi
}

_logging_audit_ssh_logs() {
    # Query failure is its own outcome: "0 failed logins" claims the journal
    # was read and found quiet. Emitted failed + info, like update.check_failed.
    local failed_logins
    if ! failed_logins=$(_logging_get_failed_logins); then
        check_emit "logging.journal_unreadable" low failed \
            desc="$(i18n 'logging.journal_unreadable_desc')" \
            suggestion="$(i18n 'logging.journal_unreadable_fix')"
        print_severity "low" "$(i18n 'logging.journal_unreadable')"
        return 0
    fi

    if ((failed_logins > 100)); then
        check_emit "logging.ssh_many_failures" low failed \
            title="$(i18n 'logging.ssh_logs_warning')" \
            desc="$(i18n 'logging.ssh_logs_warning_desc' "count=$failed_logins")"
        print_severity "low" "$(i18n 'logging.ssh_logs_high' "count=$failed_logins")"
    elif ((failed_logins > 20)); then
        check_emit "logging.ssh_some_failures" low failed \
            title="$(i18n 'logging.ssh_logs_moderate' "count=$failed_logins")" \
            desc="$(i18n 'logging.ssh_logs_warning_desc' "count=$failed_logins")"
        print_severity "low" "$(i18n 'logging.ssh_logs_moderate' "count=$failed_logins")"
    else
        check_emit "logging.ssh_logs_ok" low passed \
            title="$(i18n 'logging.ssh_logs_normal' "count=$failed_logins")"
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
        check_emit "logging.sudo_logging_ok" low passed \
            title="$(i18n 'logging.sudo_logs_active' "count=$sudo_events")"
        print_ok "$(i18n 'logging.sudo_logs_active' "count=$sudo_events")"
    else
        check_emit "logging.sudo_no_events" low passed
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

    # Under the default Storage=auto, this directory alone makes the journal
    # persistent; the drop-in pins it for hosts that set something else.
    local made_dir=0
    [[ -d "$JOURNAL_DIR" ]] || made_dir=1
    if ! mkdir -p "$JOURNAL_DIR"; then
        print_error "$(i18n 'logging.persistent_failed')"
        return 1
    fi
    systemd-tmpfiles --create --prefix "$JOURNAL_DIR"

    # backup_file is UNCONDITIONAL: it also records an absent path as
    # fix-created, which is the only thing that lets a rollback delete this
    # drop-in. Never guard it on the file already existing.
    backup_mkdir "$JOURNALD_CONF_D" || return 1
    backup_file "$JOURNALD_DROPIN" >/dev/null || return 1
    if ! write_file_atomic "$JOURNALD_DROPIN" '# vpssec journald configuration
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=1month'; then
        print_error "$(i18n 'logging.persistent_failed')"
        return 1
    fi

    # Flush, never restart: a FIX_SAFE fix may not restart a service. The
    # drop-in itself is read at journald's next start.
    if journalctl --flush 2>/dev/null; then
        print_ok "$(i18n 'logging.persistent_enabled')"
    else
        print_warn "$(i18n 'logging.journald_flush_failed')"
    fi
    print_info "$(i18n 'logging.journald_limits_next_start' "file=$JOURNALD_DROPIN")"
    # Rollback deletes the drop-in, not this directory, which alone keeps
    # Storage=auto persistent; removing it deletes the logs stored since.
    (( made_dir )) && record_undo logging.enable_persistent_journal \
        "journalctl --relinquish-var && rm -rf $JOURNAL_DIR"
    return 0
}

_logging_fix_setup_logrotate() {
    print_info "$(i18n 'logging.configuring_logrotate')"

    # The install status must propagate: returning 0 regardless records a
    # completion the next audit contradicts.
    local -a missing=()
    if ! check_command logrotate; then
        mapfile -t missing < <(pkg_missing logrotate)
        apt_refresh_index
        if ! apt_install logrotate; then
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
    (( ${#missing[@]} )) && record_undo logging.setup_logrotate "$(pkg_remove_hint "${missing[@]}")"
    return 0
}

_logging_fix_install_auditd() {
    print_info "$(i18n 'logging.installing_auditd')"

    local -a missing=()
    mapfile -t missing < <(pkg_missing auditd audispd-plugins)
    apt_refresh_index
    if apt_install auditd audispd-plugins; then
        print_ok "$(i18n 'logging.auditd_installed')"
        (( ${#missing[@]} )) && record_undo logging.install_auditd "$(pkg_remove_hint "${missing[@]}")"

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

    local undo
    undo=$(service_undo_cmd auditd)
    if systemctl enable auditd --quiet && systemctl start auditd; then
        print_ok "$(i18n 'logging.auditd_service_enabled')"
        record_undo logging.enable_auditd "$undo"
        return 0
    fi
    print_error "$(i18n 'logging.auditd_start_failed')"
    return 1
}

_logging_fix_setup_audit_rules() {
    print_info "$(i18n 'logging.configuring_audit_rules')"

    backup_mkdir "$AUDIT_RULES_D" || return 1

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

    # augenrules rewrites the compiled audit.rules from rules.d.
    backup_file "$AUDIT_RULES_COMPILED" >/dev/null || return 1

    # Report whether the KERNEL took the rules, not whether the file exists:
    # augenrules can fail while the file looks fine on disk, and auditctl -l
    # prints "No rules" for an empty set, so look for one of these rules.
    augenrules --load >/dev/null 2>&1 || auditctl -R "$AUDIT_RULES_FILE" >/dev/null 2>&1 || true

    local loaded
    loaded=$(auditctl -l 2>/dev/null) || loaded=""
    if grep -qF -- '-w /etc/passwd -p wa -k identity' <<<"$loaded"; then
        print_ok "$(i18n 'logging.audit_rules_configured')"
        print_info "$(i18n 'logging.audit_immutable_hint')"
        # Rollback restores the rule files; the kernel keeps these until reloaded.
        record_undo logging.setup_audit_rules "vpssec rollback && augenrules --load"
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
