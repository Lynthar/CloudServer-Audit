#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Fail2ban / intrusion prevention module
# Copyright (c) 2024

# --- Fail2ban Configuration ---

F2B_CONFIG="/etc/fail2ban/fail2ban.conf"
F2B_JAIL_LOCAL="/etc/fail2ban/jail.local"
F2B_JAIL_D="/etc/fail2ban/jail.d"

# This tool's own jail config as a drop-in; jail.local is the operator's.
# Precedence: jail.d beats jail.local, and the *.local tier beats *.conf —
# that, not the 99- prefix, is what outranks the distro's defaults.
F2B_DROPIN="/etc/fail2ban/jail.d/99-vpssec-sshd.local"

# Seconds to wait for fail2ban to load the new jail before asking whether the
# SSH jail came up. A variable so tests can drop it to 0; a fix that sleeps 2s
# per invocation makes a suite unusable.
F2B_RELOAD_SETTLE="${F2B_RELOAD_SETTLE:-2}"

# --- Fail2ban Helper Functions ---

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
    # `backend = systemd` needs python3-systemd, which Debian only Recommends
    # and a running journald says NOTHING about. Get it wrong and fail2ban
    # drops the jail entirely, taking the distro's own sshd jail with it.
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        if journalctl -n 1 &>/dev/null && \
           python3 -c "import systemd.journal" 2>/dev/null; then
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

# The banaction must match the host's ACTIVE firewall. A hardcoded
# iptables-multiport silently no-ops on nftables: the jail loads and reports
# active while every ban fails against a filter that is not in use.
_f2b_detect_banaction() {
    # Prefer ufw when it manages the firewall. LC_ALL=C is load-bearing: a
    # translated "Status: active" makes this pick nftables and write bans
    # into a table that bypasses the live ufw rules.
    if command -v ufw &>/dev/null && LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "ufw"
        return
    fi

    # Native nftables (no UFW wrapper) has its own multiport action.
    if command -v nft &>/dev/null && [[ -n "$(nft list tables 2>/dev/null)" ]]; then
        echo "nftables-multiport"
        return
    fi

    # Fall back to the legacy iptables action.
    echo "iptables-multiport"
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

# Currently-active jails, whitespace-separated. Empty means the service is up
# with no jails loaded — installed but effectively disabled.
_f2b_list_active_jails() {
    fail2ban-client status 2>/dev/null \
        | awk -F: '/Jail list/{print $2}' \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$'
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

# Operator tuning beyond the package default: jail.local with a real line, OR
# a jail.d file other than the shipped defaults-debian.conf. The glob MUST
# cover *.local too, or the audit cannot see this tool's own drop-in.
_f2b_has_custom_config() {
    if [[ -f "$F2B_JAIL_LOCAL" ]]; then
        # Skip files that are entirely whitespace/comments.
        if grep -qE '^[[:space:]]*[^#[:space:]]' "$F2B_JAIL_LOCAL" 2>/dev/null; then
            return 0
        fi
    fi

    if [[ -d "$F2B_JAIL_D" ]]; then
        local f
        for f in "$F2B_JAIL_D"/*.conf "$F2B_JAIL_D"/*.local; do
            [[ -f "$f" ]] || continue
            # Ignore the Debian/Ubuntu shipped default; it is part of
            # the package, not operator configuration.
            [[ "$(basename "$f")" == "defaults-debian.conf" ]] && continue
            return 0
        done
    fi

    return 1
}

# maxretry for the SSH jail. Prefer fail2ban-client, which returns the actual
# runtime value: a tail across the file ignores INI section semantics, so a
# [DEFAULT] after [sshd] reads as effective when it is not.
_f2b_get_maxretry() {
    local maxretry=""

    if systemctl is-active --quiet fail2ban 2>/dev/null && command -v fail2ban-client &>/dev/null; then
        maxretry=$(fail2ban-client get sshd maxretry 2>/dev/null)
    fi

    if [[ -z "$maxretry" ]]; then
        if [[ -f "$F2B_JAIL_LOCAL" ]]; then
            maxretry=$(grep -E "^\s*maxretry\s*=" "$F2B_JAIL_LOCAL" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        fi
        # *.local as well as *.conf: fail2ban reads both from jail.d/, and this
        # tool's own drop-in is a .local. See _f2b_has_custom_config.
        if [[ -z "$maxretry" && -d "$F2B_JAIL_D" ]]; then
            maxretry=$(grep -rh "^\s*maxretry\s*=" "$F2B_JAIL_D"/*.conf "$F2B_JAIL_D"/*.local 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        fi
    fi

    echo "${maxretry:-5}"
}

# Get bantime setting. See _f2b_get_maxretry for the rationale.
_f2b_get_bantime() {
    local bantime=""

    if systemctl is-active --quiet fail2ban 2>/dev/null && command -v fail2ban-client &>/dev/null; then
        bantime=$(fail2ban-client get sshd bantime 2>/dev/null)
    fi

    if [[ -z "$bantime" ]]; then
        if [[ -f "$F2B_JAIL_LOCAL" ]]; then
            bantime=$(grep -E "^\s*bantime\s*=" "$F2B_JAIL_LOCAL" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        fi
        if [[ -z "$bantime" && -d "$F2B_JAIL_D" ]]; then
            bantime=$(grep -rh "^\s*bantime\s*=" "$F2B_JAIL_D"/*.conf "$F2B_JAIL_D"/*.local 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        fi
    fi

    echo "${bantime:-10m}"
}

# --- Fail2ban Audit ---

fail2ban_audit() {
    local module="fail2ban"

    # Check if fail2ban is installed
    print_item "$(i18n 'fail2ban.check_installed')"
    if ! _f2b_installed; then
        local check=$(create_check_json \
            "fail2ban.not_installed" \
            "fail2ban" \
            "low" \
            "failed" \
            "$(i18n 'fail2ban.not_installed')" \
            "$(i18n 'fail2ban.not_installed_desc')" \
            "$(i18n 'fail2ban.fix_install')" \
            "fail2ban.install")
        state_add_check "$check"
        print_severity "low" "$(i18n 'fail2ban.not_installed')"
        return
    fi
    print_ok "$(i18n 'fail2ban.installed')"

    # Check service status
    print_item "$(i18n 'fail2ban.check_service')"
    _f2b_audit_service

    # Distinct from service_active: fail2ban can be running with every jail
    # disabled, which that check alone reports as healthy.
    print_item "$(i18n 'fail2ban.check_any_jail')"
    _f2b_audit_any_jail

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
                "$(i18n 'fail2ban.service_active_desc')" \
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
                "$(i18n 'fail2ban.service_not_enabled_desc')" \
                "$(i18n 'fail2ban.fix_enable')" \
                "fail2ban.enable_service")
            state_add_check "$check"
            print_severity "low" "$(i18n 'fail2ban.service_not_enabled')"
        fi
    else
        local check=$(create_check_json \
            "fail2ban.service_inactive" \
            "fail2ban" \
            "low" \
            "failed" \
            "$(i18n 'fail2ban.service_inactive')" \
            "$(i18n 'fail2ban.service_inactive_desc')" \
            "$(i18n 'fail2ban.fix_enable')" \
            "fail2ban.enable_service")
        state_add_check "$check"
        print_severity "low" "$(i18n 'fail2ban.service_inactive')"
    fi
}

_f2b_audit_any_jail() {
    if ! _f2b_service_active; then
        return  # Service-down already surfaced by _f2b_audit_service
    fi

    local jails
    jails=$(_f2b_list_active_jails)

    if [[ -z "$jails" ]]; then
        local check=$(create_check_json \
            "fail2ban.no_jails_active" \
            "fail2ban" \
            "low" \
            "failed" \
            "$(i18n 'fail2ban.no_jails_active' 2>/dev/null || echo 'fail2ban running but no jails active')" \
            "$(i18n 'fail2ban.no_jails_active_desc')" \
            "$(i18n 'fail2ban.fix_enable_jail')" \
            "fail2ban.enable_ssh_jail")
        state_add_check "$check"
        print_severity "low" "$(i18n 'fail2ban.no_jails_active' 2>/dev/null || echo 'No active jails')"
    else
        local jail_count jail_list
        jail_count=$(echo "$jails" | wc -l)
        jail_list=$(echo "$jails" | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')
        local check=$(create_check_json \
            "fail2ban.jails_active" \
            "fail2ban" \
            "low" \
            "passed" \
            "$(i18n 'fail2ban.jails_active' 2>/dev/null || echo "Active jails"): $jail_count" \
            "$(i18n 'fail2ban.jails_active_desc' "jails=$jail_list")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'fail2ban.jails_active' 2>/dev/null || echo "Active jails"): $jail_list"
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
            "$(i18n 'fail2ban.ssh_jail_enabled_desc' "current=$current_banned" "total=$total_banned" "maxretry=$maxretry" "bantime=$bantime")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'fail2ban.ssh_jail_enabled') (banned: $current_banned, total: $total_banned)"

        # Guarded numerically first: a non-numeric token in `[[ -gt ]]` is
        # read as a variable name and aborts the audit under set -u.
        if [[ "$maxretry" =~ ^[0-9]+$ ]] && [[ "$maxretry" -gt 5 ]]; then
            local check=$(create_check_json \
                "fail2ban.maxretry_high" \
                "fail2ban" \
                "low" \
                "failed" \
                "$(i18n 'fail2ban.maxretry_high')" \
                "$(i18n 'fail2ban.maxretry_high_desc' "value=$maxretry")" \
                "$(i18n 'fail2ban.maxretry_high_suggestion')" \
                "fail2ban.configure_ssh_jail")
            state_add_check "$check"
            print_severity "low" "$(i18n 'fail2ban.maxretry_high'): $maxretry"
        fi
    else
        local check=$(create_check_json \
            "fail2ban.ssh_jail_disabled" \
            "fail2ban" \
            "low" \
            "failed" \
            "$(i18n 'fail2ban.ssh_jail_disabled')" \
            "$(i18n 'fail2ban.ssh_jail_disabled_desc')" \
            "$(i18n 'fail2ban.fix_enable_ssh_jail')" \
            "fail2ban.enable_ssh_jail")
        state_add_check "$check"
        print_severity "low" "$(i18n 'fail2ban.ssh_jail_disabled')"
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
            "$(i18n 'fail2ban.custom_config_desc')" \
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
            "$(i18n 'fail2ban.default_config_desc')" \
            "$(i18n 'fail2ban.default_config_suggestion')" \
            "fail2ban.configure_ssh_jail")
        state_add_check "$check"
        print_severity "low" "$(i18n 'fail2ban.default_config')"
    fi
}

# --- Fail2ban Fix Functions ---

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

        # Failures must propagate: a successful apt install is not success if
        # the service then fails to start. errexit is off here, so capture.
        local rc=0
        _f2b_fix_enable_service || rc=1
        # Only where the operator has tuned nothing: `install` is FIX_SAFE
        # while configure_ssh_jail is CONFIRM-class, so calling it
        # transitively would bypass that gate.
        if _f2b_has_custom_config; then
            print_warn "$(i18n 'fail2ban.custom_config_preserved')"
        else
            _f2b_fix_configure_ssh_jail || rc=1
        fi
        return $rc
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

# Undo a drop-in write that failed to validate. Two cases, and collapsing
# them costs a file: restore from the backup, or remove a file we created.
# A pre-existing file with no backup is LEFT ALONE.
_f2b_restore_dropin() {
    local bak="$1" had_dropin="$2"

    if [[ -n "$bak" && -f "$bak" ]]; then
        cp -p "$bak" "$F2B_DROPIN"
    elif [[ "$had_dropin" != "true" ]]; then
        rm -f "$F2B_DROPIN"
    fi
}

_f2b_fix_configure_ssh_jail() {
    print_info "$(i18n 'fail2ban.configuring_ssh_jail')"

    # Recorded before the backup, so the validation-failure path knows whether
    # removing the file is safe. NOT a guard around backup_file.
    local f2b_had_dropin="false"
    [[ -f "$F2B_DROPIN" ]] && f2b_had_dropin="true"

    # UNCONDITIONAL: backup_file also records an ABSENT path, the only thing
    # that lets a rollback delete what this fix creates — and the drop-in is
    # absent on every host that needs it.
    local f2b_bak=""
    f2b_bak=$(backup_file "$F2B_DROPIN") || return 1

    # Get SSH port and detect log path/backend/banaction
    local ssh_port=$(get_ssh_port)
    local ssh_logpath=$(_f2b_detect_ssh_logpath)
    local f2b_backend=$(_f2b_detect_backend)
    local f2b_banaction=$(_f2b_detect_banaction)
    # The "-allports" variant for banaction_allports uses the same base
    # name except for `ufw` which has a single action handling both.
    local f2b_banaction_allports
    case "$f2b_banaction" in
        ufw) f2b_banaction_allports="ufw" ;;
        nftables-multiport) f2b_banaction_allports="nftables-allports" ;;
        *) f2b_banaction_allports="iptables-allports" ;;
    esac

    # NEVER ban the operator's own address: loopback always, plus the current
    # SSH source when it can be determined. Without it, three fat-fingered
    # passwords lock the admin out for an hour via this tool's own jail.
    local f2b_ignoreip="127.0.0.1/8 ::1"
    local f2b_current_ip
    f2b_current_ip=$(get_current_ssh_ip)
    [[ -n "$f2b_current_ip" ]] && f2b_ignoreip+=" $f2b_current_ip"

    print_info "$(i18n 'fail2ban.detected_logpath' "path=$ssh_logpath")"
    print_info "$(i18n 'fail2ban.detected_backend' "backend=$f2b_backend")"
    print_info "$(i18n 'fail2ban.detected_banaction' "banaction=$f2b_banaction")"

    # Built first, then written atomically: a truncated drop-in breaks
    # fail2ban on the next reload.
    local jail_content
    jail_content=$(cat <<EOF
# vpssec fail2ban configuration
# Generated: $(date -Iseconds)
# Detected logpath: $ssh_logpath
# Detected backend: $f2b_backend

[DEFAULT]
# Never ban these addresses (operator loopback + current SSH source).
ignoreip = $f2b_ignoreip

# Ban duration (default: 10 minutes, increase for production)
bantime = 1h

# Time window for counting failures
findtime = 10m

# Max failures before ban
maxretry = 3

# Backend for log monitoring
backend = $f2b_backend

# Action: ban IP using the host's active firewall (selected at runtime)
banaction = $f2b_banaction
banaction_allports = $f2b_banaction_allports

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
)

    # No restore call here, deliberately: write_file_atomic stages into a temp
    # file, so all of its failure paths leave the target untouched. A cleanup
    # here would make this branch look like it handles a case it never sees.
    if ! write_file_atomic "$F2B_DROPIN" "$jail_content"; then
        print_error "$(i18n 'fail2ban.dropin_write_failed')"
        return 1
    fi

    # A legacy jail.local is now shadowed and can be removed, but it is not
    # ours to delete unasked — an operator may have edited it since. Say so,
    # rather than leaving two configs where only one is in effect.
    if [[ -f "$F2B_JAIL_LOCAL" ]] && \
       grep -q '^# vpssec fail2ban configuration' "$F2B_JAIL_LOCAL" 2>/dev/null; then
        print_warn "$(i18n 'fail2ban.legacy_jail_local' "path=$F2B_JAIL_LOCAL")"
        log_info "Superseded by $F2B_DROPIN; remove with: rm $F2B_JAIL_LOCAL"
    fi

    # Validate the merged config before (re)loading. A broken drop-in would make
    # fail2ban fail to start on the next boot; restore the previous file (or
    # remove the one we just wrote) and abort instead of leaving it live.
    if command -v fail2ban-client >/dev/null 2>&1 && ! fail2ban-client -t >/dev/null 2>&1; then
        print_error "$(i18n 'fail2ban.config_test_failed')"
        _f2b_restore_dropin "$f2b_bak" "$f2b_had_dropin"
        return 1
    fi

    # Reload fail2ban
    if _f2b_service_active; then
        fail2ban-client reload 2>/dev/null
    else
        systemctl start fail2ban 2>/dev/null
    fi

    # Verify SSH jail is now enabled
    if [[ "$F2B_RELOAD_SETTLE" -gt 0 ]]; then
        sleep "$F2B_RELOAD_SETTLE"   # give fail2ban time to load the jail
    fi
    if _f2b_ssh_jail_enabled; then
        print_ok "$(i18n 'fail2ban.ssh_jail_configured')"
        return 0
    fi

    # The jail did not come up, so the drop-in is withdrawn: a file that
    # passes `-t` can still fail at runtime, leaving NO sshd jail. Only when
    # the service is up — a stopped fail2ban says nothing about our file.
    if _f2b_service_active; then
        print_warn "$(i18n 'fail2ban.dropin_rolled_back')"
        _f2b_restore_dropin "$f2b_bak" "$f2b_had_dropin"
        fail2ban-client reload 2>/dev/null
    fi
    print_error "$(i18n 'fail2ban.ssh_jail_config_failed')"
    return 1
}

# --- Fail2ban Utility Functions ---

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
