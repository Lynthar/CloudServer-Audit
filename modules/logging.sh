#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Logging and audit module
# Copyright (c) 2024

# ==============================================================================
# Logging Configuration
# ==============================================================================

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

# ==============================================================================
# Logging Helper Functions
# ==============================================================================

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

# Last definition wins across main + drop-in files (matches systemd
# semantics). Original implementation read only the main file, so
# vpssec writing its own drop-in via _logging_fix_enable_persistent_journal
# became invisible to the next audit — self-inconsistent display.
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
    # Get recent failed login attempts.
    #
    # Filter by `_COMM=sshd` (the binary name as recorded by the
    # kernel), not `_SYSTEMD_UNIT=sshd.service`. The latter is the
    # canonical RHEL/CentOS unit name; on Debian/Ubuntu — every OS
    # this project targets — the unit is `ssh.service` and
    # `sshd.service` is only a systemd alias that may not match
    # journal-recorded metadata. With the wrong filter this query
    # silently returned zero on every Debian/Ubuntu host, hiding
    # active brute-force activity.
    #
    # Match BOTH _COMM=sshd and _COMM=sshd-session. OpenSSH >= 9.8 (Debian 13,
    # Ubuntu 24.10+) split per-session work — including the authentication
    # failure log lines — into a separate `sshd-session` process, so filtering
    # on `_COMM=sshd` alone returns zero even during an active brute-force (this
    # is the same change fail2ban had to make). journalctl ORs repeated matches
    # of the same field, so listing both COMM values is the correct union.
    #
    # Capture journalctl's output FIRST so its own exit status is visible:
    # "the journal says zero failures" and "the journal could not be read"
    # are different answers, and folding the second into a 0 told the
    # operator of an unreadable-journal host that nobody is attacking them.
    # Returns non-zero (printing nothing) when journalctl itself failed;
    # callers report that as an unknown, not a zero.
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

        # Critical log files to check, per distro (from distro.sh). Defaults to
        # the Debian set; on Debian/Ubuntu distro_log_paths returns exactly this,
        # so behaviour is unchanged. RHEL→messages/secure/dnf.rpm.log,
        # Arch→pacman.log (everything else is journald-only there).
        local logs="syslog auth.log dpkg.log"
        if declare -f distro_log_paths >/dev/null 2>&1; then
            local dl; dl=$(distro_log_paths)
            if [[ -n "$dl" ]]; then logs="$dl"; fi
        fi

        for log in $logs; do
            # Search BOTH /etc/logrotate.conf and /etc/logrotate.d: many
            # distros configure core logs (wtmp/btmp, and on some setups
            # syslog) directly in logrotate.conf, so searching only the .d
            # directory falsely reported rotation as missing.
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
    # was read and found quiet — on a host where journalctl cannot answer,
    # that claim is exactly what a brute-forced operator must not be told.
    # failed + info-category, same pattern as update.check_failed.
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
    mkdir -p "$JOURNAL_DIR"
    systemd-tmpfiles --create --prefix "$JOURNAL_DIR"

    # Create drop-in configuration atomically; back up any prior drop-in so a
    # bad restart can be rolled back. A partial file here could degrade
    # journald on the restart below.
    #
    # Call backup_file unconditionally. Guarding it on the file already
    # existing is what left the FIRST run with no manifest entry: backup_file
    # records an absent path as fix-created (.vpssec_created), which is the
    # only thing that lets a rollback delete the drop-in. Without it the
    # operator could undo the plan and still be left with journald
    # reconfigured. The logrotate fix below already writes it this way.
    mkdir -p "$JOURNALD_CONF_D"
    backup_file "$JOURNALD_DROPIN" >/dev/null 2>&1 || true
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

    # Propagate the install failure. The previous version discarded apt's exit
    # status and then returned 0 unconditionally, so on a host with no network
    # (or a held apt lock) the fix printed "configured", the engine recorded it
    # via state_mark_fix_complete, and the next audit re-flagged logrotate as
    # missing — a fix that permanently disagrees with its own audit.
    if ! check_command logrotate; then
        # Refresh the index first (fail2ban/ufw's install fixes already do
        # this): without it, a host whose /var/lib/apt/lists is empty or stale
        # gets "Unable to locate package" and the install can never succeed.
        # Unlike those two we do NOT gate the install on update's exit status —
        # one broken third-party repo makes `apt-get update` non-zero, and
        # logrotate is very likely still installable from the rest of the index.
        # The install's own status is what decides.
        DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y logrotate 2>/dev/null; then
            print_error "$(i18n 'logging.logrotate_install_failed')"
            return 1
        fi
    fi

    # The logrotate package ships /etc/logrotate.conf as a conffile, so this
    # branch only runs when the install above could not supply one. Go through
    # backup_file + write_file_atomic like every other /etc write in this
    # project: the bare `cat >` it replaces could truncate the file if
    # interrupted, and left no backup entry — so backup_file's session manifest
    # (.vpssec_created) never learned about the new file and a rollback could
    # not delete it.
    if [[ ! -f "$LOGROTATE_CONF" ]]; then
        backup_file "$LOGROTATE_CONF" >/dev/null 2>&1 || true
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

        # The two follow-ups are a convenience, and their status deliberately
        # does NOT decide this one. This fix_id answers the check
        # logging.auditd_not_installed, and the install is what that check
        # measures; the service and the rules have their own checks and their
        # own fix_ids, so a failure there is reported by them on the next run
        # rather than being recast as "the install failed". Each prints its own
        # error, so nothing is swallowed silently.
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

    # Build the rules content, then write atomically (tempfile + rename). The
    # bare `cat >` could leave a truncated 99-vpssec.rules on an interrupted
    # write — which auditd would then reject on the next load — and its write
    # failure went unchecked.
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

    # Back up before writing, unconditionally: an existing 99-vpssec.rules is
    # about to be replaced and must be restorable, and an absent one has to be
    # recorded as fix-created so a rollback deletes it. This write had no
    # backup call at all, so rolling back a plan that configured auditd left
    # the rules loading on every boot.
    backup_file "$AUDIT_RULES_FILE" >/dev/null 2>&1 || true

    if ! write_file_atomic "$AUDIT_RULES_FILE" "$rules_content"; then
        print_error "$(i18n 'logging.audit_rules_failed')"
        return 1
    fi

    # Load the rules, then report honestly whether the KERNEL actually took
    # them (auditctl -l) rather than declaring success merely because the file
    # exists. augenrules/auditctl can fail (auditd inactive, syntax error,
    # already immutable via -e 2) while the file sits on disk looking fine.
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
