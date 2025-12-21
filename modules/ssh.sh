#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# SSH hardening module
# Copyright (c) 2024

# ==============================================================================
# SSH Configuration Paths
# ==============================================================================

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSH_HARDENING_DROPIN="${SSH_DROPIN_DIR}/99-vpssec-hardening.conf"
SSH_RESCUE_PORT=2222

# ==============================================================================
# SSH Helper Functions
# ==============================================================================

# Get effective SSH config value using sshd -T (most accurate method)
# Falls back to file parsing if sshd -T is not available
_ssh_get_config() {
    local key="$1"
    local default="$2"
    local value=""

    # Method 1: Use sshd -T for accurate effective configuration
    # This handles Match blocks, Include directives, and all override rules correctly
    if command -v sshd &>/dev/null; then
        # sshd -T outputs all effective settings in lowercase
        local key_lower="${key,,}"
        value=$(sshd -T 2>/dev/null | grep -i "^${key_lower} " | head -1 | awk '{print $2}')
        if [[ -n "$value" ]]; then
            echo "$value"
            return
        fi
    fi

    # Method 2: Fallback to file parsing (less accurate but works without root)
    # Check drop-ins first (higher priority, sorted by name)
    if [[ -d "$SSH_DROPIN_DIR" ]]; then
        value=$(grep -h "^${key}[[:space:]]" "$SSH_DROPIN_DIR"/*.conf 2>/dev/null | tail -1 | awk '{print $2}')
        if [[ -n "$value" ]]; then
            echo "$value"
            return
        fi
    fi

    # Check main config
    value=$(grep "^${key}[[:space:]]" "$SSH_CONFIG" 2>/dev/null | tail -1 | awk '{print $2}')
    if [[ -n "$value" ]]; then
        echo "$value"
        return
    fi

    # Return default
    echo "$default"
}

# Get SSH listening port (handles multiple ports)
_ssh_get_port() {
    local port=""

    # Try sshd -T first
    if command -v sshd &>/dev/null; then
        port=$(sshd -T 2>/dev/null | grep -i "^port " | head -1 | awk '{print $2}')
    fi

    # Fallback to file parsing
    if [[ -z "$port" ]]; then
        port=$(grep "^Port[[:space:]]" "$SSH_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    fi

    echo "${port:-22}"
}

# Check if password auth is enabled
_ssh_password_auth_enabled() {
    local value=$(_ssh_get_config "PasswordAuthentication" "yes")
    [[ "${value,,}" == "yes" ]]
}

# Check if root login is enabled
_ssh_root_login_enabled() {
    local value=$(_ssh_get_config "PermitRootLogin" "prohibit-password")
    [[ "${value,,}" == "yes" ]]
}

# Check if pubkey auth is enabled
_ssh_pubkey_enabled() {
    local value=$(_ssh_get_config "PubkeyAuthentication" "yes")
    [[ "${value,,}" == "yes" ]]
}

# Check if empty passwords are allowed
_ssh_empty_password_allowed() {
    local value=$(_ssh_get_config "PermitEmptyPasswords" "no")
    [[ "${value,,}" == "yes" ]]
}

# Check for non-root sudo users
_ssh_get_admin_users() {
    # Get users who can sudo (excluding root)
    local admin_users=()

    # Check sudo group members
    if getent group sudo &>/dev/null; then
        while IFS=: read -r _ _ _ members; do
            for user in ${members//,/ }; do
                if [[ "$user" != "root" ]]; then
                    admin_users+=("$user")
                fi
            done
        done < <(getent group sudo)
    fi

    # Check wheel group members (some systems)
    if getent group wheel &>/dev/null; then
        while IFS=: read -r _ _ _ members; do
            for user in ${members//,/ }; do
                if [[ "$user" != "root" ]]; then
                    admin_users+=("$user")
                fi
            done
        done < <(getent group wheel)
    fi

    # Remove duplicates
    printf '%s\n' "${admin_users[@]}" | sort -u
}

# Check if user has authorized_keys
_ssh_user_has_key() {
    local user="$1"
    local home_dir
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    local auth_keys="${home_dir}/.ssh/authorized_keys"

    [[ -f "$auth_keys" ]] && [[ -s "$auth_keys" ]]
}

# Check if SSH access control is configured (AllowUsers/DenyUsers/AllowGroups/DenyGroups)
_ssh_has_access_control() {
    local has_control=false

    # Check for AllowUsers
    local allow_users=$(_ssh_get_config "AllowUsers" "")
    if [[ -n "$allow_users" ]]; then
        has_control=true
    fi

    # Check for AllowGroups
    local allow_groups=$(_ssh_get_config "AllowGroups" "")
    if [[ -n "$allow_groups" ]]; then
        has_control=true
    fi

    # Check for DenyUsers
    local deny_users=$(_ssh_get_config "DenyUsers" "")
    if [[ -n "$deny_users" ]]; then
        has_control=true
    fi

    # Check for DenyGroups
    local deny_groups=$(_ssh_get_config "DenyGroups" "")
    if [[ -n "$deny_groups" ]]; then
        has_control=true
    fi

    $has_control
}

# Get SSH access control details
_ssh_get_access_control_info() {
    local info=()

    local allow_users=$(_ssh_get_config "AllowUsers" "")
    [[ -n "$allow_users" ]] && info+=("AllowUsers: $allow_users")

    local allow_groups=$(_ssh_get_config "AllowGroups" "")
    [[ -n "$allow_groups" ]] && info+=("AllowGroups: $allow_groups")

    local deny_users=$(_ssh_get_config "DenyUsers" "")
    [[ -n "$deny_users" ]] && info+=("DenyUsers: $deny_users")

    local deny_groups=$(_ssh_get_config "DenyGroups" "")
    [[ -n "$deny_groups" ]] && info+=("DenyGroups: $deny_groups")

    printf '%s; ' "${info[@]}"
}

# Check authorized_keys file permissions (security check)
_ssh_check_authkeys_permissions() {
    local user="$1"
    local home_dir
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    local ssh_dir="${home_dir}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"
    local issues=()

    if [[ ! -d "$ssh_dir" ]]; then
        return 0  # No .ssh dir, nothing to check
    fi

    # Check .ssh directory permissions (should be 700 or 755)
    local ssh_perms
    ssh_perms=$(stat -c "%a" "$ssh_dir" 2>/dev/null)
    if [[ -n "$ssh_perms" ]] && [[ "$ssh_perms" != "700" ]] && [[ "$ssh_perms" != "755" ]]; then
        issues+=("$ssh_dir has permissions $ssh_perms (should be 700)")
    fi

    # Check authorized_keys permissions (should be 600 or 644)
    if [[ -f "$auth_keys" ]]; then
        local ak_perms
        ak_perms=$(stat -c "%a" "$auth_keys" 2>/dev/null)
        if [[ -n "$ak_perms" ]] && [[ "$ak_perms" != "600" ]] && [[ "$ak_perms" != "644" ]]; then
            issues+=("$auth_keys has permissions $ak_perms (should be 600)")
        fi

        # Check ownership
        local ak_owner
        ak_owner=$(stat -c "%U" "$auth_keys" 2>/dev/null)
        if [[ -n "$ak_owner" ]] && [[ "$ak_owner" != "$user" ]] && [[ "$ak_owner" != "root" ]]; then
            issues+=("$auth_keys owned by $ak_owner (should be $user)")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        printf '%s\n' "${issues[@]}"
        return 1
    fi
    return 0
}

# ==============================================================================
# SSH Audit
# ==============================================================================

ssh_audit() {
    local module="ssh"

    # Check password authentication
    print_item "$(i18n 'ssh.check_password_auth')"
    _ssh_audit_password_auth

    # Check root login
    print_item "$(i18n 'ssh.check_root_login')"
    _ssh_audit_root_login

    # Check pubkey authentication
    print_item "$(i18n 'ssh.check_pubkey_auth')"
    _ssh_audit_pubkey

    # Check for admin user
    print_item "$(i18n 'ssh.check_admin_user')"
    _ssh_audit_admin_user

    # Check empty passwords
    print_item "$(i18n 'ssh.check_empty_password')"
    _ssh_audit_empty_password

    # Check MaxAuthTries
    print_item "$(i18n 'ssh.check_max_auth_tries')"
    _ssh_audit_max_auth_tries

    # Check LoginGraceTime
    print_item "$(i18n 'ssh.check_login_grace_time')"
    _ssh_audit_login_grace_time

    # Check X11Forwarding
    print_item "$(i18n 'ssh.check_x11_forwarding')"
    _ssh_audit_x11_forwarding

    # Check SSH protocol and algorithms
    print_item "$(i18n 'ssh.check_algorithms')"
    _ssh_audit_algorithms

    # Check SSH access control (AllowUsers/DenyUsers)
    print_item "$(i18n 'ssh.check_access_control')"
    _ssh_audit_access_control
}

_ssh_audit_password_auth() {
    if _ssh_password_auth_enabled; then
        local check=$(create_check_json \
            "ssh.password_auth_enabled" \
            "ssh" \
            "high" \
            "failed" \
            "$(i18n 'ssh.password_auth_enabled')" \
            "PasswordAuthentication is yes or not explicitly set" \
            "$(i18n 'ssh.fix_disable_password')" \
            "ssh.disable_password_auth")
        state_add_check "$check"
        print_severity "high" "$(i18n 'ssh.password_auth_enabled')"
    else
        local check=$(create_check_json \
            "ssh.password_auth_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.password_auth_disabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.password_auth_disabled')"
    fi
}

_ssh_audit_root_login() {
    if _ssh_root_login_enabled; then
        local check=$(create_check_json \
            "ssh.root_login_enabled" \
            "ssh" \
            "high" \
            "failed" \
            "$(i18n 'ssh.root_login_enabled')" \
            "PermitRootLogin is set to yes" \
            "$(i18n 'ssh.fix_disable_root')" \
            "ssh.disable_root_login")
        state_add_check "$check"
        print_severity "high" "$(i18n 'ssh.root_login_enabled')"
    else
        local check=$(create_check_json \
            "ssh.root_login_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.root_login_disabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.root_login_disabled')"
    fi
}

_ssh_audit_pubkey() {
    if _ssh_pubkey_enabled; then
        local check=$(create_check_json \
            "ssh.pubkey_enabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.pubkey_enabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.pubkey_enabled')"
    else
        local check=$(create_check_json \
            "ssh.pubkey_disabled" \
            "ssh" \
            "high" \
            "failed" \
            "$(i18n 'ssh.pubkey_disabled')" \
            "PubkeyAuthentication is disabled" \
            "$(i18n 'ssh.fix_enable_pubkey')" \
            "ssh.enable_pubkey")
        state_add_check "$check"
        print_severity "high" "$(i18n 'ssh.pubkey_disabled')"
    fi
}

_ssh_audit_admin_user() {
    local admin_users
    admin_users=$(_ssh_get_admin_users)

    if [[ -n "$admin_users" ]]; then
        local first_admin
        first_admin=$(echo "$admin_users" | head -1)
        local check
        check=$(create_check_json \
            "ssh.admin_user_exists" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.admin_user_exists' "user=$first_admin")" \
            "Admin users: $admin_users" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.admin_user_exists' "user=$first_admin")"

        # Check if admin has SSH key
        if ! _ssh_user_has_key "$first_admin"; then
            check=$(create_check_json \
                "ssh.admin_no_key" \
                "ssh" \
                "medium" \
                "failed" \
                "Admin user $first_admin has no SSH key" \
                "No authorized_keys file found" \
                "Add SSH public key for $first_admin" \
                "")
            state_add_check "$check"
            print_severity "medium" "Admin user $first_admin has no SSH key"
        else
            # Check authorized_keys permissions if key exists
            local perm_issues
            perm_issues=$(_ssh_check_authkeys_permissions "$first_admin")
            if [[ -n "$perm_issues" ]]; then
                check=$(create_check_json \
                    "ssh.authkeys_permissions" \
                    "ssh" \
                    "medium" \
                    "failed" \
                    "SSH key files have insecure permissions" \
                    "$perm_issues" \
                    "Fix permissions: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys" \
                    "")
                state_add_check "$check"
                print_severity "medium" "SSH key files have insecure permissions"
            fi
        fi
    else
        local check
        check=$(create_check_json \
            "ssh.no_admin_user" \
            "ssh" \
            "high" \
            "failed" \
            "$(i18n 'ssh.no_admin_user')" \
            "No non-root user with sudo privileges found" \
            "Create a non-root admin user before disabling root login" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'ssh.no_admin_user')"
    fi
}

_ssh_audit_empty_password() {
    if _ssh_empty_password_allowed; then
        local check=$(create_check_json \
            "ssh.empty_password_allowed" \
            "ssh" \
            "high" \
            "failed" \
            "Empty password login allowed" \
            "PermitEmptyPasswords is yes" \
            "Disable empty password login" \
            "ssh.disable_empty_password")
        state_add_check "$check"
        print_severity "high" "Empty password login allowed"
    else
        local check=$(create_check_json \
            "ssh.empty_password_denied" \
            "ssh" \
            "low" \
            "passed" \
            "Empty password login denied" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Empty password login denied"
    fi
}

_ssh_audit_max_auth_tries() {
    local max_auth=$(_ssh_get_config "MaxAuthTries" "6")

    if [[ "$max_auth" -le 4 ]]; then
        local check=$(create_check_json \
            "ssh.max_auth_tries_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.max_auth_tries_ok')" \
            "MaxAuthTries=$max_auth" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.max_auth_tries_ok') ($max_auth)"
    else
        local check=$(create_check_json \
            "ssh.max_auth_tries_high" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.max_auth_tries_high')" \
            "MaxAuthTries=$max_auth (recommended: 3-4)" \
            "Set MaxAuthTries to 4 or less" \
            "ssh.set_max_auth_tries")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.max_auth_tries_high') ($max_auth)"
    fi
}

_ssh_audit_login_grace_time() {
    local grace_time=$(_ssh_get_config "LoginGraceTime" "120")

    # Handle time suffixes (s, m, h)
    local seconds="$grace_time"
    if [[ "$grace_time" =~ ^[0-9]+m$ ]]; then
        seconds=$((${grace_time%m} * 60))
    elif [[ "$grace_time" =~ ^[0-9]+h$ ]]; then
        seconds=$((${grace_time%h} * 3600))
    elif [[ "$grace_time" =~ ^[0-9]+s$ ]]; then
        seconds="${grace_time%s}"
    fi

    if [[ "$seconds" -le 60 ]]; then
        local check=$(create_check_json \
            "ssh.login_grace_time_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.login_grace_time_ok')" \
            "LoginGraceTime=$grace_time" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.login_grace_time_ok') ($grace_time)"
    else
        local check=$(create_check_json \
            "ssh.login_grace_time_long" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.login_grace_time_long')" \
            "LoginGraceTime=$grace_time (recommended: 60s or less)" \
            "Set LoginGraceTime to 60" \
            "ssh.set_login_grace_time")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.login_grace_time_long') ($grace_time)"
    fi
}

_ssh_audit_x11_forwarding() {
    local x11=$(_ssh_get_config "X11Forwarding" "no")

    if [[ "${x11,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.x11_forwarding_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.x11_forwarding_disabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.x11_forwarding_disabled')"
    else
        local check=$(create_check_json \
            "ssh.x11_forwarding_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.x11_forwarding_enabled')" \
            "X11Forwarding is enabled" \
            "Disable X11 forwarding unless needed" \
            "ssh.disable_x11_forwarding")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.x11_forwarding_enabled')"
    fi
}

_ssh_audit_algorithms() {
    local issues=()

    # Check for weak ciphers using sshd -T
    if command -v sshd &>/dev/null; then
        local ciphers
        ciphers=$(sshd -T 2>/dev/null | grep "^ciphers " | cut -d' ' -f2-)

        # Check for known weak ciphers
        local weak_ciphers=("3des-cbc" "arcfour" "arcfour128" "arcfour256" "blowfish-cbc" "cast128-cbc")
        for weak in "${weak_ciphers[@]}"; do
            if [[ "$ciphers" == *"$weak"* ]]; then
                issues+=("cipher:$weak")
            fi
        done

        # Check for weak MACs
        local macs
        macs=$(sshd -T 2>/dev/null | grep "^macs " | cut -d' ' -f2-)
        local weak_macs=("hmac-md5" "hmac-md5-96" "hmac-sha1-96")
        for weak in "${weak_macs[@]}"; do
            if [[ "$macs" == *"$weak"* ]]; then
                issues+=("mac:$weak")
            fi
        done

        # Check for weak KEX algorithms
        local kex
        kex=$(sshd -T 2>/dev/null | grep "^kexalgorithms " | cut -d' ' -f2-)
        local weak_kex=("diffie-hellman-group1-sha1" "diffie-hellman-group-exchange-sha1")
        for weak in "${weak_kex[@]}"; do
            if [[ "$kex" == *"$weak"* ]]; then
                issues+=("kex:$weak")
            fi
        done
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s ' "${issues[@]}")
        local check=$(create_check_json \
            "ssh.weak_algorithms" \
            "ssh" \
            "medium" \
            "failed" \
            "$(i18n 'ssh.weak_algorithms')" \
            "Weak algorithms: $issue_list" \
            "$(i18n 'ssh.fix_algorithms')" \
            "ssh.harden_algorithms")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ssh.weak_algorithms'): ${#issues[@]} found"
    else
        local check=$(create_check_json \
            "ssh.algorithms_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.algorithms_ok')" \
            "No weak algorithms detected" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.algorithms_ok')"
    fi
}

_ssh_audit_access_control() {
    if _ssh_has_access_control; then
        local control_info=$(_ssh_get_access_control_info)
        local check=$(create_check_json \
            "ssh.access_control_configured" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.access_control_configured')" \
            "$control_info" \
            "" \
            "")
        state_add_check "$check"
        print_ok "SSH access control configured"
    else
        # This is a recommendation, not critical
        local check=$(create_check_json \
            "ssh.no_access_control" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.no_access_control')" \
            "No AllowUsers/DenyUsers/AllowGroups/DenyGroups configured" \
            "Consider adding AllowUsers or AllowGroups to restrict SSH access" \
            "ssh.configure_access_control")
        state_add_check "$check"
        print_severity "low" "No SSH access control configured (AllowUsers/DenyUsers)"
    fi
}

# ==============================================================================
# SSH Fix Functions
# ==============================================================================

ssh_fix() {
    local fix_id="$1"

    case "$fix_id" in
        ssh.disable_password_auth)
            _ssh_fix_disable_password_auth
            ;;
        ssh.disable_root_login)
            _ssh_fix_disable_root_login
            ;;
        ssh.enable_pubkey)
            _ssh_fix_enable_pubkey
            ;;
        ssh.disable_empty_password)
            _ssh_fix_disable_empty_password
            ;;
        ssh.set_max_auth_tries)
            _ssh_fix_set_max_auth_tries
            ;;
        ssh.set_login_grace_time)
            _ssh_fix_set_login_grace_time
            ;;
        ssh.disable_x11_forwarding)
            _ssh_fix_disable_x11_forwarding
            ;;
        ssh.harden_algorithms)
            _ssh_fix_harden_algorithms
            ;;
        *)
            log_error "Unknown SSH fix: $fix_id"
            return 1
            ;;
    esac
}

# Open rescue port for safety
_ssh_open_rescue_port() {
    print_info "$(i18n 'ssh.rescue_port_notice' "port=$SSH_RESCUE_PORT")"

    # Create temporary sshd config with secure permissions
    local rescue_config
    rescue_config=$(mktemp -t vpssec-sshd-rescue.XXXXXX) || {
        print_error "Failed to create temp file for rescue config"
        return 1
    }
    chmod 600 "$rescue_config"
    SSH_RESCUE_CONFIG="$rescue_config"  # Store for cleanup

    cat > "$rescue_config" <<EOF
Port $SSH_RESCUE_PORT
Include /etc/ssh/sshd_config
EOF

    # Start rescue sshd
    /usr/sbin/sshd -f "$rescue_config" 2>/dev/null

    if check_port_open "$SSH_RESCUE_PORT"; then
        print_ok "$(i18n 'ssh.rescue_port_opened' "port=$SSH_RESCUE_PORT")"
        print_warn "$(i18n 'ssh.rescue_port_test' "port=$SSH_RESCUE_PORT")"
        return 0
    else
        print_error "Failed to open rescue port"
        rm -f "$rescue_config"
        return 1
    fi
}

# Close rescue port
_ssh_close_rescue_port() {
    # Kill sshd listening on rescue port
    local pid
    pid=$(ss -tlnp | grep ":${SSH_RESCUE_PORT}" | grep -oP 'pid=\K\d+' | head -1) || true
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        log_info "Closed rescue port $SSH_RESCUE_PORT (pid: $pid)"
    fi
    # Clean up temp config file if it exists
    if [[ -n "${SSH_RESCUE_CONFIG:-}" ]] && [[ -f "$SSH_RESCUE_CONFIG" ]]; then
        rm -f "$SSH_RESCUE_CONFIG"
    fi
}

# Write SSH hardening config
_ssh_write_hardening_config() {
    local content="$1"
    local temp_file

    mkdir -p "$SSH_DROPIN_DIR"

    # Backup existing
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        backup_file "$SSH_HARDENING_DROPIN"
    fi

    # Write to temp file first with secure permissions
    temp_file=$(mktemp -t vpssec-sshd.XXXXXX) || {
        print_error "Failed to create temp file"
        return 1
    }
    chmod 600 "$temp_file"

    {
        echo "# vpssec SSH hardening - $(date -Iseconds)"
        echo "$content"
    } > "$temp_file"

    # Validate config by testing with the actual sshd_config
    if sshd -t -f /dev/null -o "Include=$temp_file" 2>/dev/null; then
        chmod 644 "$temp_file"
        if mv "$temp_file" "$SSH_HARDENING_DROPIN"; then
            print_ok "$(i18n 'ssh.dropin_created' "path=$SSH_HARDENING_DROPIN")"
            return 0
        else
            rm -f "$temp_file"
            print_error "Failed to move config file"
            return 1
        fi
    else
        rm -f "$temp_file"
        print_error "$(i18n 'ssh.sshd_test_fail')"
        return 1
    fi
}

# Reload SSH service safely
_ssh_reload_safe() {
    # Test config first
    if sshd -t 2>/dev/null; then
        print_ok "$(i18n 'ssh.sshd_test_ok')"

        if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
            print_ok "$(i18n 'ssh.sshd_reloaded')"
            return 0
        else
            print_error "Failed to reload SSH"
            return 1
        fi
    else
        print_error "$(i18n 'ssh.sshd_test_fail')"
        return 1
    fi
}

_ssh_fix_disable_password_auth() {
    # Safety check - ensure user has SSH key access
    local current_ip=$(get_current_ssh_ip)
    if [[ -n "$current_ip" ]]; then
        print_info "Current connection from: $current_ip"
    fi

    # Check for admin with SSH key
    local admin_users=$(_ssh_get_admin_users)
    local has_key_user=""

    for user in $admin_users; do
        if _ssh_user_has_key "$user"; then
            has_key_user="$user"
            break
        fi
    done

    if [[ -z "$has_key_user" ]] && ! _ssh_user_has_key "root"; then
        print_error "No user with SSH key found. Cannot safely disable password auth."
        print_warn "Please add an SSH key first: ssh-copy-id user@host"
        return 1
    fi

    # Critical confirmation
    if ! confirm_critical "$(i18n 'ssh.confirm_ssh_change')"; then
        return 1
    fi

    # Open rescue port - MANDATORY for SSH changes
    if ! _ssh_open_rescue_port; then
        print_error "Cannot open rescue port - aborting SSH changes for safety"
        print_warn "Please check if port $SSH_RESCUE_PORT is available"
        return 1
    fi

    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^PasswordAuthentication") || true
    fi

    # Write config
    local content="PasswordAuthentication no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
        local result=$?
        _ssh_close_rescue_port
        return $result
    else
        _ssh_close_rescue_port
        return 1
    fi
}

_ssh_fix_disable_root_login() {
    # Safety check - ensure non-root admin exists
    local admin_users=$(_ssh_get_admin_users)
    if [[ -z "$admin_users" ]]; then
        print_error "No non-root admin user found. Cannot safely disable root login."
        print_warn "Create a sudo user first: adduser newuser && usermod -aG sudo newuser"
        return 1
    fi

    # Critical confirmation
    if ! confirm_critical "$(i18n 'ssh.confirm_ssh_change')"; then
        return 1
    fi

    # Open rescue port - MANDATORY for SSH changes
    if ! _ssh_open_rescue_port; then
        print_error "Cannot open rescue port - aborting SSH changes for safety"
        print_warn "Please check if port $SSH_RESCUE_PORT is available"
        return 1
    fi

    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^PermitRootLogin") || true
    fi

    # Write config
    local content="PermitRootLogin no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
        local result=$?
        _ssh_close_rescue_port
        return $result
    else
        _ssh_close_rescue_port
        return 1
    fi
}

_ssh_fix_enable_pubkey() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^PubkeyAuthentication") || true
    fi

    # Write config
    local content="PubkeyAuthentication yes"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
    else
        return 1
    fi
}

_ssh_fix_disable_empty_password() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^PermitEmptyPasswords") || true
    fi

    # Write config
    local content="PermitEmptyPasswords no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
    else
        return 1
    fi
}

_ssh_fix_set_max_auth_tries() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^MaxAuthTries") || true
    fi

    # Write config
    local content="MaxAuthTries 4"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
    else
        return 1
    fi
}

_ssh_fix_set_login_grace_time() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^LoginGraceTime") || true
    fi

    # Write config
    local content="LoginGraceTime 60"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
    else
        return 1
    fi
}

_ssh_fix_disable_x11_forwarding() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -v "^X11Forwarding") || true
    fi

    # Write config
    local content="X11Forwarding no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
    else
        return 1
    fi
}

_ssh_fix_harden_algorithms() {
    print_info "$(i18n 'ssh.hardening_algorithms')"

    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | \
            grep -v "^Ciphers" | \
            grep -v "^MACs" | \
            grep -v "^KexAlgorithms") || true
    fi

    # Recommended secure algorithms (modern OpenSSH)
    local secure_ciphers="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    local secure_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    local secure_kex="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"

    # Write config
    local content="Ciphers $secure_ciphers
MACs $secure_macs
KexAlgorithms $secure_kex"

    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe
        return $?
    else
        return 1
    fi
}
