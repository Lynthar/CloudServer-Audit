#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# SSH hardening module
# Copyright (c) 2024

# --- SSH Configuration Paths ---

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
# The `00-` prefix is load-bearing: sshd takes the FIRST value and reads
# Include globs in lexical order, so a 99- drop-in loses to cloud-init's.
# Opposite of sysctl.d. Precedence is still asserted by _ssh_verify_effective.
SSH_HARDENING_DROPIN="${SSH_DROPIN_DIR}/00-vpssec-hardening.conf"
# Older vpssec releases wrote the losing `99-` file; migrate it to the new name
# on first fix so prior settings carry over and the stale (ignored) file goes.
SSH_HARDENING_DROPIN_LEGACY="${SSH_DROPIN_DIR}/99-vpssec-hardening.conf"
SSH_RESCUE_PORT=2222     # preferred rescue port; replaced with a free port at open time
SSH_RESCUE_PID=""        # pid of the rescue sshd we launched (the only kill target)
SSH_RESCUE_CONFIG=""     # temp rescue config path
SSH_RESCUE_PIDFILE=""    # temp rescue pidfile path
SSH_RESCUE_FW_RULE=""    # firewall rule added for the rescue port, for exact teardown

# --- SSH Helper Functions ---

# Get effective SSH config value using sshd -T (most accurate method)
# Falls back to file parsing if sshd -T is not available
_ssh_get_config() {
    local key="$1"
    local default="$2"
    local value=""

    # sshd -T resolves Match, Include and every override rule. The -C spec
    # is critical: without it Match is evaluated against the CURRENT user,
    # so a `Match User root` override becomes the reported base value.
    if command -v sshd &>/dev/null; then
        local key_lower="${key,,}"
        value=$(sshd -T -C user=doesnotexist,host=none,addr=none 2>/dev/null \
            | grep -i "^${key_lower} " | head -1 | awk '{sub(/^[^ ]+ /, ""); print}')
        # Some hardened or chrooted sshd builds reject -C. Retry without it
        # before falling through to file parsing.
        if [[ -z "$value" ]]; then
            value=$(sshd -T 2>/dev/null | grep -i "^${key_lower} " | head -1 | awk '{sub(/^[^ ]+ /, ""); print}')
        fi
        if [[ -n "$value" ]]; then
            echo "$value"
            return
        fi
    fi

    # Method 2: Fallback to file parsing (less accurate but works without root)
    # Check drop-ins first (higher priority, sorted by name)
    if [[ -d "$SSH_DROPIN_DIR" ]]; then
        value=$(grep -h "^${key}[[:space:]]" "$SSH_DROPIN_DIR"/*.conf 2>/dev/null | tail -1 | awk '{sub(/^[^[:space:]]+[[:space:]]+/, ""); print}')
        if [[ -n "$value" ]]; then
            echo "$value"
            return
        fi
    fi

    # Check main config
    value=$(grep "^${key}[[:space:]]" "$SSH_CONFIG" 2>/dev/null | tail -1 | awk '{sub(/^[^[:space:]]+[[:space:]]+/, ""); print}')
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

# Non-root sudo users. Feeds the safety gate in disable_root_login, where an
# empty result blocks the fix — so it must cover file-based grants in
# /etc/sudoers and sudoers.d, not just the sudo/wheel groups.
_ssh_get_admin_users() {
    local admin_users=()

    # Group-based grants: members of `sudo` and `wheel`.
    local grp
    for grp in sudo wheel; do
        if getent group "$grp" &>/dev/null; then
            while IFS=: read -r _ _ _ members; do
                for user in ${members//,/ }; do
                    [[ -n "$user" && "$user" != "root" ]] && admin_users+=("$user")
                done
            done < <(getent group "$grp")
        fi
    done

    # Direct `user ALL=...` entries only. %group entries are deliberately
    # skipped: the two common groups are covered by the scan above, and
    # resolving arbitrary group membership is out of scope here.
    local sudoers_files=("/etc/sudoers")
    local f
    if [[ -d /etc/sudoers.d ]]; then
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] && sudoers_files+=("$f")
        done
    fi
    for f in "${sudoers_files[@]}"; do
        [[ -r "$f" ]] || continue
        # Match lines like `alice ALL=(ALL) NOPASSWD: ALL` — username
        # at column 0, whitespace, then ALL=. Skip #includes and
        # comments.
        while IFS= read -r user; do
            [[ -n "$user" && "$user" != "root" ]] && admin_users+=("$user")
        done < <(grep -E '^[a-zA-Z_][a-zA-Z0-9_-]*[[:space:]]+ALL=' "$f" 2>/dev/null | awk '{print $1}')
    done

    # Remove duplicates
    printf '%s\n' "${admin_users[@]}" | sort -u
}

# The EFFECTIVE AuthorizedKeysFile paths for a user, with sshd's token
# expansion and relative paths resolved under home. One absolute path per
# line; empty means no static key file applies.
_ssh_effective_authorizedkeysfiles() {
    local user="$1"
    local home_dir
    home_dir=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    [[ -z "$home_dir" ]] && return 0

    # Captured first, THEN awk over a herestring: piping into an awk that
    # exits early gives sshd SIGPIPE, and under pipefail that aborts this
    # function before it prints anything.
    local akf sshd_dump
    sshd_dump=$(sshd -T 2>/dev/null || true)
    akf=$(awk 'tolower($1)=="authorizedkeysfile"{$1=""; sub(/^[[:space:]]+/,""); print; exit}' <<<"$sshd_dump")
    # sshd's built-in default when unset.
    [[ -z "$akf" ]] && akf=".ssh/authorized_keys .ssh/authorized_keys2"
    [[ "${akf,,}" == "none" ]] && return 0

    local tok path
    for tok in $akf; do
        path="${tok//%%/$'\x01'}"   # protect literal %% before %h/%u
        path="${path//%h/$home_dir}"
        path="${path//%u/$user}"
        path="${path//$'\x01'/%}"
        [[ "$path" != /* ]] && path="$home_dir/$path"
        echo "$path"
    done
}

# Does this user have a usable key in the file(s) sshd will actually read?
# Delegates to count_authorized_keys, which never counts a commented-out key —
# reading a rotated-out key as "has key" is a lockout.
_ssh_user_has_key() {
    local user="$1"
    local total=0 path n
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        n=$(count_authorized_keys "$path")
        total=$(( total + n ))
    done < <(_ssh_effective_authorizedkeysfiles "$user")
    [[ "$total" -gt 0 ]]
}

# True unless there is POSITIVE evidence the account cannot log in: a
# nologin shell or a past expiry date. Anything unreadable counts as "can
# log in". A locked password is NOT evidence — it does not block key auth.
_ssh_account_can_login() {
    local user="$1"
    local shell
    shell=$(getent passwd "$user" 2>/dev/null | cut -d: -f7)
    case "$shell" in
        */nologin|*/false) return 1 ;;
    esac

    # Shadow field 8: account-expiry in days since epoch; empty = never.
    local expire
    expire=$(getent shadow "$user" 2>/dev/null | cut -d: -f8)
    if [[ "$expire" =~ ^[0-9]+$ ]]; then
        local today=$(( $(date +%s) / 86400 ))
        (( expire <= today )) && return 1
    fi
    return 0
}

# Can $user log in by key under the CURRENT effective config? For root this
# also requires PermitRootLogin to permit key auth: under "no" root's key is
# useless and must NOT count toward the disable-password safety gate.
_ssh_can_login_with_key() {
    local user="$1"
    if [[ "$user" == "root" ]]; then
        local prl
        prl=$(_ssh_get_config "PermitRootLogin" "prohibit-password")
        [[ "${prl,,}" == "no" ]] && return 1
    fi
    _ssh_user_has_key "$user"
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

# --- SSH Audit ---

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

    # Additional hardening options surfaced by Lynis SSH-7408 that the
    # original module didn't cover. All are advisory (low severity,
    # info-category) — operator preferences, not security baseline.
    print_item "$(i18n 'ssh.check_allow_tcp_forwarding')"
    _ssh_audit_allow_tcp_forwarding

    print_item "$(i18n 'ssh.check_client_alive')"
    _ssh_audit_client_alive_count_max

    print_item "$(i18n 'ssh.check_log_level')"
    _ssh_audit_log_level

    print_item "$(i18n 'ssh.check_max_sessions')"
    _ssh_audit_max_sessions

    print_item "$(i18n 'ssh.check_tcp_keepalive')"
    _ssh_audit_tcp_keepalive

    print_item "$(i18n 'ssh.check_agent_forwarding')"
    _ssh_audit_agent_forwarding

    # These alter the security boundary rather than hygiene, so they matter
    # more than the options above — still low severity, to match the
    # existing SSH-option category.
    print_item "$(i18n 'ssh.check_ignore_rhosts')"
    _ssh_audit_ignore_rhosts

    print_item "$(i18n 'ssh.check_strict_modes')"
    _ssh_audit_strict_modes

    print_item "$(i18n 'ssh.check_permit_user_env')"
    _ssh_audit_permit_user_environment

    print_item "$(i18n 'ssh.check_permit_tunnel')"
    _ssh_audit_permit_tunnel

    print_item "$(i18n 'ssh.check_gateway_ports')"
    _ssh_audit_gateway_ports

    # Check SSH protocol and algorithms
    print_item "$(i18n 'ssh.check_algorithms')"
    _ssh_audit_algorithms

    # Check SSH access control (AllowUsers/DenyUsers)
    print_item "$(i18n 'ssh.check_access_control')"
    _ssh_audit_access_control

    # Check SSH port (recommend non-default)
    print_item "$(i18n 'ssh.check_port')"
    _ssh_audit_port
}

_ssh_audit_password_auth() {
    if _ssh_password_auth_enabled; then
        local check=$(create_check_json \
            "ssh.password_auth_enabled" \
            "ssh" \
            "high" \
            "failed" \
            "$(i18n 'ssh.password_auth_enabled')" \
            "$(i18n 'ssh.password_auth_enabled_desc')" \
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
        # With password auth off, PermitRootLogin=yes exposes root only by
        # key. Still flagged, but at medium, so the score tracks real
        # exposure rather than a checkbox.
        local sev="high"
        local title_key="ssh.root_login_enabled"
        local info="PermitRootLogin=yes (allows root via password and key)"
        if ! _ssh_password_auth_enabled; then
            sev="medium"
            title_key="ssh.root_login_keyonly"
            info="PermitRootLogin=yes; effectively key-only because PasswordAuthentication=no globally"
        fi
        local check=$(create_check_json \
            "ssh.root_login_enabled" \
            "ssh" \
            "$sev" \
            "failed" \
            "$(i18n "$title_key")" \
            "$info" \
            "$(i18n 'ssh.fix_disable_root')" \
            "ssh.disable_root_login")
        state_add_check "$check"
        print_severity "$sev" "$(i18n "$title_key")"
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
            "medium" \
            "failed" \
            "$(i18n 'ssh.pubkey_disabled')" \
            "$(i18n 'ssh.pubkey_disabled_desc')" \
            "$(i18n 'ssh.fix_enable_pubkey')" \
            "ssh.enable_pubkey")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ssh.pubkey_disabled')"
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
            "$(i18n 'ssh.admin_user_exists_desc' "admin_users=$admin_users")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.admin_user_exists' "user=$first_admin")"

        # Check if admin has SSH key
        if ! _ssh_user_has_key "$first_admin"; then
            check=$(create_check_json \
                "ssh.admin_no_key" \
                "ssh" \
                "low" \
                "failed" \
                "Admin user $first_admin has no SSH key" \
                "$(i18n 'ssh.admin_no_key_desc')" \
                "Add SSH public key for $first_admin" \
                "")
            state_add_check "$check"
            print_severity "low" "Admin user $first_admin has no SSH key"
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
            "low" \
            "failed" \
            "$(i18n 'ssh.no_admin_user')" \
            "$(i18n 'ssh.no_admin_user_desc')" \
            "Create a non-root admin user before disabling root login" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.no_admin_user')"
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
            "$(i18n 'ssh.empty_password_allowed_desc')" \
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
            "$(i18n 'ssh.empty_password_disabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.empty_password_disabled')"
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
            "$(i18n 'ssh.max_auth_tries_high_desc' "max_auth=$max_auth")" \
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

    # 0 means UNLIMITED, which is a weakness, not a pass. The safe range is
    # 1..60; everything else falls through to the too-long branch. The regex
    # guard also stops a non-numeric value aborting the audit under set -u.
    if [[ "$seconds" =~ ^[0-9]+$ ]] && (( seconds >= 1 && seconds <= 60 )); then
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
            "$(i18n 'ssh.login_grace_time_long_desc' "grace_time=$grace_time")" \
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
            "$(i18n 'ssh.x11_forwarding_enabled_desc')" \
            "Disable X11 forwarding unless needed" \
            "ssh.disable_x11_forwarding")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.x11_forwarding_enabled')"
    fi
}

_ssh_audit_allow_tcp_forwarding() {
    local val=$(_ssh_get_config "AllowTcpForwarding" "yes")
    if [[ "${val,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.allow_tcp_forwarding_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.allow_tcp_forwarding_disabled')" \
            "AllowTcpForwarding=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.allow_tcp_forwarding_disabled')"
    else
        local check=$(create_check_json \
            "ssh.allow_tcp_forwarding_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.allow_tcp_forwarding_enabled')" \
            "$(i18n 'ssh.allow_tcp_forwarding_enabled_desc' "val=$val")" \
            "Set AllowTcpForwarding to no in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.allow_tcp_forwarding_enabled')"
    fi
}

_ssh_audit_client_alive_count_max() {
    local val=$(_ssh_get_config "ClientAliveCountMax" "3")
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val <= 2 )); then
        local check=$(create_check_json \
            "ssh.client_alive_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.client_alive_ok')" \
            "ClientAliveCountMax=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.client_alive_ok') ($val)"
    else
        local check=$(create_check_json \
            "ssh.client_alive_high" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.client_alive_high')" \
            "$(i18n 'ssh.client_alive_high_desc' "val=$val")" \
            "Set ClientAliveCountMax to 2 in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.client_alive_high') ($val)"
    fi
}

_ssh_audit_log_level() {
    local val=$(_ssh_get_config "LogLevel" "INFO")
    if [[ "${val^^}" == "VERBOSE" ]]; then
        local check=$(create_check_json \
            "ssh.log_level_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.log_level_ok')" \
            "LogLevel=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.log_level_ok')"
    else
        local check=$(create_check_json \
            "ssh.log_level_low" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.log_level_low')" \
            "$(i18n 'ssh.log_level_low_desc' "val=$val")" \
            "Set LogLevel to VERBOSE in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.log_level_low') ($val)"
    fi
}

_ssh_audit_max_sessions() {
    local val=$(_ssh_get_config "MaxSessions" "10")
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val <= 4 )); then
        local check=$(create_check_json \
            "ssh.max_sessions_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.max_sessions_ok')" \
            "MaxSessions=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.max_sessions_ok') ($val)"
    else
        local check=$(create_check_json \
            "ssh.max_sessions_high" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.max_sessions_high')" \
            "$(i18n 'ssh.max_sessions_high_desc' "val=$val")" \
            "Set MaxSessions to 4 in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.max_sessions_high') ($val)"
    fi
}

_ssh_audit_tcp_keepalive() {
    local val=$(_ssh_get_config "TCPKeepAlive" "yes")
    if [[ "${val,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.tcp_keepalive_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.tcp_keepalive_disabled')" \
            "TCPKeepAlive=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.tcp_keepalive_disabled')"
    else
        local check=$(create_check_json \
            "ssh.tcp_keepalive_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.tcp_keepalive_enabled')" \
            "$(i18n 'ssh.tcp_keepalive_enabled_desc' "val=$val")" \
            "Set TCPKeepAlive to no and rely on ClientAliveInterval instead" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.tcp_keepalive_enabled')"
    fi
}

_ssh_audit_agent_forwarding() {
    local val=$(_ssh_get_config "AllowAgentForwarding" "yes")
    if [[ "${val,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.agent_forwarding_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.agent_forwarding_disabled')" \
            "AllowAgentForwarding=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.agent_forwarding_disabled')"
    else
        local check=$(create_check_json \
            "ssh.agent_forwarding_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.agent_forwarding_enabled')" \
            "$(i18n 'ssh.agent_forwarding_enabled_desc' "val=$val")" \
            "Set AllowAgentForwarding to no in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.agent_forwarding_enabled')"
    fi
}

_ssh_audit_ignore_rhosts() {
    local val=$(_ssh_get_config "IgnoreRhosts" "yes")
    if [[ "${val,,}" == "yes" ]]; then
        local check=$(create_check_json \
            "ssh.ignore_rhosts_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.ignore_rhosts_ok')" \
            "IgnoreRhosts=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.ignore_rhosts_ok')"
    else
        local check=$(create_check_json \
            "ssh.ignore_rhosts_disabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.ignore_rhosts_disabled')" \
            "$(i18n 'ssh.ignore_rhosts_disabled_desc' "val=$val")" \
            "Set IgnoreRhosts to yes in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.ignore_rhosts_disabled')"
    fi
}

_ssh_audit_strict_modes() {
    local val=$(_ssh_get_config "StrictModes" "yes")
    if [[ "${val,,}" == "yes" ]]; then
        local check=$(create_check_json \
            "ssh.strict_modes_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.strict_modes_ok')" \
            "StrictModes=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.strict_modes_ok')"
    else
        local check=$(create_check_json \
            "ssh.strict_modes_disabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.strict_modes_disabled')" \
            "$(i18n 'ssh.strict_modes_disabled_desc' "val=$val")" \
            "Set StrictModes to yes in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.strict_modes_disabled')"
    fi
}

_ssh_audit_permit_user_environment() {
    local val=$(_ssh_get_config "PermitUserEnvironment" "no")
    if [[ "${val,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.permit_user_env_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.permit_user_env_disabled')" \
            "PermitUserEnvironment=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.permit_user_env_disabled')"
    else
        local check=$(create_check_json \
            "ssh.permit_user_env_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.permit_user_env_enabled')" \
            "$(i18n 'ssh.permit_user_env_enabled_desc' "val=$val")" \
            "Set PermitUserEnvironment to no in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.permit_user_env_enabled')"
    fi
}

_ssh_audit_permit_tunnel() {
    local val=$(_ssh_get_config "PermitTunnel" "no")
    if [[ "${val,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.permit_tunnel_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.permit_tunnel_disabled')" \
            "PermitTunnel=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.permit_tunnel_disabled')"
    else
        local check=$(create_check_json \
            "ssh.permit_tunnel_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.permit_tunnel_enabled')" \
            "$(i18n 'ssh.permit_tunnel_enabled_desc' "val=$val")" \
            "Set PermitTunnel to no in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.permit_tunnel_enabled')"
    fi
}

_ssh_audit_gateway_ports() {
    local val=$(_ssh_get_config "GatewayPorts" "no")
    if [[ "${val,,}" == "no" ]]; then
        local check=$(create_check_json \
            "ssh.gateway_ports_disabled" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.gateway_ports_disabled')" \
            "GatewayPorts=$val" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.gateway_ports_disabled')"
    else
        local check=$(create_check_json \
            "ssh.gateway_ports_enabled" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.gateway_ports_enabled')" \
            "$(i18n 'ssh.gateway_ports_enabled_desc' "val=$val")" \
            "Set GatewayPorts to no in /etc/ssh/sshd_config.d/" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.gateway_ports_enabled')"
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
        # Substring match, so "hmac-md5" also catches hmac-md5-96 and
        # "hmac-sha1" catches hmac-sha1-96 / hmac-sha1-etm@openssh.com — every
        # SHA-1/MD5 MAC is deprecated. (Previously hmac-sha1 itself was missed.)
        local weak_macs=("hmac-md5" "hmac-sha1")
        for weak in "${weak_macs[@]}"; do
            if [[ "$macs" == *"$weak"* ]]; then
                issues+=("mac:$weak")
            fi
        done

        # Check for weak KEX algorithms
        local kex
        kex=$(sshd -T 2>/dev/null | grep "^kexalgorithms " | cut -d' ' -f2-)
        # group14-sha1 was missing: SHA-1 KEX is deprecated (RFC 8732 / OpenSSH
        # 8.8 disabled it by default). group14-sha256 is NOT a substring match
        # of "...-sha1", so the strong variant is not falsely flagged.
        local weak_kex=("diffie-hellman-group1-sha1" "diffie-hellman-group-exchange-sha1" "diffie-hellman-group14-sha1")
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
            "low" \
            "failed" \
            "$(i18n 'ssh.weak_algorithms')" \
            "$(i18n 'ssh.weak_algorithms_desc' "list=$issue_list")" \
            "$(i18n 'ssh.fix_algorithms')" \
            "ssh.harden_algorithms")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.weak_algorithms'): ${#issues[@]} found"
    else
        local check=$(create_check_json \
            "ssh.algorithms_ok" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.algorithms_ok')" \
            "$(i18n 'ssh.algorithms_ok_desc')" \
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
        print_ok "$(i18n 'ssh.access_control_configured')"
    else
        # This is a recommendation, not critical
        local check=$(create_check_json \
            "ssh.no_access_control" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.no_access_control')" \
            "$(i18n 'ssh.no_access_control_desc')" \
            "$(i18n 'ssh.fix_access_control')" \
            "ssh.configure_access_control")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ssh.no_access_control')"
    fi
}

_ssh_audit_port() {
    local ssh_port=$(_ssh_get_port)

    if [[ "$ssh_port" == "22" ]]; then
        # Default port - recommend changing for security through obscurity
        local check=$(create_check_json \
            "ssh.default_port" \
            "ssh" \
            "low" \
            "failed" \
            "$(i18n 'ssh.default_port')" \
            "$(i18n 'ssh.default_port_desc')" \
            "Consider changing to a non-standard port (e.g., 2222, 22222)" \
            "")
        state_add_check "$check"
        print_severity "low" "SSH using default port 22 (consider changing)"
    else
        local check=$(create_check_json \
            "ssh.custom_port" \
            "ssh" \
            "low" \
            "passed" \
            "$(i18n 'ssh.custom_port')" \
            "$(i18n 'ssh.custom_port_desc' "ssh_port=$ssh_port")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ssh.custom_port') ($ssh_port)"
    fi
}

# --- SSH Fix Functions ---

ssh_fix() {
    local fix_id="$1"

    # Migrate any legacy `99-` drop-in to the new `00-` name before a fix reads
    # or writes it, so prior settings are preserved and the losing file is gone.
    _ssh_migrate_legacy_dropin

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

# Rescue SSH daemon: a second sshd on a temporary port, started BEFORE any
# change that can cut SSH access. Four invariants bound it, each of which has
# already prevented a lockout — do not loosen any (see the design notes).

# Pick a free TCP port for the rescue daemon: never the live SSH port, never an
# already-listening port. Prefer 2222, then scan small high-port ranges.
_ssh_pick_rescue_port() {
    local live_port listening candidate
    live_port=$(get_ssh_port 2>/dev/null || echo 22)
    listening=$(get_listening_ports 2>/dev/null || echo "")
    for candidate in 2222 $(seq 2200 2299) $(seq 22000 22099); do
        [[ "$candidate" == "$live_port" ]] && continue
        grep -qx "$candidate" <<<"$listening" && continue
        echo "$candidate"
        return 0
    done
    return 1
}

# True when the rescue daemon we launched is alive AND owns the listening
# socket on the rescue port (verified by pid, so a coincidental listener on
# that port cannot read as success).
_ssh_rescue_is_up() {
    [[ -n "${SSH_RESCUE_PID:-}" ]] || return 1
    kill -0 "$SSH_RESCUE_PID" 2>/dev/null || return 1
    ss -tlnp 2>/dev/null \
        | grep -E "LISTEN.*:${SSH_RESCUE_PORT}[[:space:]]" \
        | grep -q "pid=${SSH_RESCUE_PID}\b"
}

# Open the rescue port, scoped to the operator's client IP when known, and
# record what was added so teardown removes exactly that. Only ufw is
# auto-managed; other backends warn and lean on the reachability check.
_ssh_rescue_allow_firewall() {
    local backend ip
    backend=$(fw_backend 2>/dev/null || echo none)
    ip=$(get_current_ssh_ip)

    case "$backend" in
        ufw)
            # No detectable source IP: ASK, never fall back to world-open.
            # Empty answer or unreadable tty adds NO rule — the mandatory
            # reachability confirmation catches an unreachable rescue.
            if [[ -z "$ip" ]]; then
                print_warn "$(i18n 'ssh.rescue_fw_no_source')"
                echo -n "$(i18n 'ssh.rescue_fw_ask_cidr' "port=$SSH_RESCUE_PORT") > "
                local answer=""
                read -r answer 2>/dev/null </dev/tty || answer=""
                if [[ "$answer" == "any" ]]; then
                    ip=""  # explicit world-open, handled below
                elif [[ -n "$answer" ]] && _ssh_valid_cidr "$answer"; then
                    ip="$answer"
                elif [[ -n "$answer" ]]; then
                    print_warn "$(i18n 'ssh.rescue_fw_bad_cidr' "value=$answer")"
                    print_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
                    return 0
                else
                    print_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
                    return 0
                fi
                # world-open only via the explicit "any" answer above
                if [[ -z "$ip" ]]; then
                    if ufw allow "$SSH_RESCUE_PORT/tcp" comment "vpssec rescue" >/dev/null 2>&1; then
                        SSH_RESCUE_FW_RULE="ufw::${SSH_RESCUE_PORT}"
                    fi
                fi
            fi
            if [[ -n "$ip" && -z "$SSH_RESCUE_FW_RULE" ]]; then
                if ufw allow from "$ip" to any port "$SSH_RESCUE_PORT" proto tcp comment "vpssec rescue" >/dev/null 2>&1; then
                    SSH_RESCUE_FW_RULE="ufw:${ip}:${SSH_RESCUE_PORT}"
                fi
            fi
            if [[ -n "$SSH_RESCUE_FW_RULE" ]]; then
                print_ok "$(i18n 'ssh.rescue_fw_allowed' "port=$SSH_RESCUE_PORT")"
            else
                print_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
            fi
            ;;
        none)
            : # no active firewall: the rescue port is reachable, nothing to do
            ;;
        *)
            # firewalld / nftables / iptables: don't manipulate rules blind.
            print_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
            ;;
    esac
}

# Accept "addr" or "addr/prefix" as a ufw source. Both address families;
# prefix bounds checked per family (v4 ≤ 32, v6 ≤ 128).
_ssh_valid_cidr() {
    local value="$1" addr prefix
    addr="${value%%/*}"
    validate_ip "$addr" || return 1
    [[ "$value" == */* ]] || return 0
    prefix="${value#*/}"
    [[ "$prefix" =~ ^[0-9]{1,3}$ ]] || return 1
    if [[ "$addr" == *:* ]]; then
        (( prefix <= 128 ))
    else
        (( prefix <= 32 ))
    fi
}

# Remove exactly the firewall rule added by _ssh_rescue_allow_firewall.
_ssh_rescue_remove_firewall() {
    [[ -n "${SSH_RESCUE_FW_RULE:-}" ]] || return 0
    local kind rest ip port
    # First field is the kind, LAST is the port, everything between is the
    # source. A three-way IFS=':' read truncates any IPv6 source, so teardown
    # deletes a rule that never existed and leaves the real one behind.
    kind="${SSH_RESCUE_FW_RULE%%:*}"
    rest="${SSH_RESCUE_FW_RULE#*:}"
    port="${rest##*:}"
    ip="${rest%:*}"
    [[ "$ip" == "$port" ]] && ip=""   # "ufw::2222" leaves rest=":2222"
    case "$kind" in
        ufw)
            if [[ -n "$ip" ]]; then
                ufw delete allow from "$ip" to any port "$port" proto tcp >/dev/null 2>&1 || true
            else
                ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            fi
            ;;
    esac
    SSH_RESCUE_FW_RULE=""
}

# Open the rescue daemon (see header). Returns 0 only when our daemon is
# verified listening; on any failure it tears down whatever it created.
_ssh_open_rescue_port() {
    local port
    if ! port=$(_ssh_pick_rescue_port); then
        print_error "$(i18n 'ssh.rescue_no_free_port')"
        return 1
    fi
    SSH_RESCUE_PORT="$port"
    print_info "$(i18n 'ssh.rescue_port_notice' "port=$SSH_RESCUE_PORT")"

    SSH_RESCUE_CONFIG=$(mktemp -t vpssec-sshd-rescue.XXXXXX) || {
        print_error "$(i18n 'error.temp_file_failed')"
        return 1
    }
    SSH_RESCUE_PIDFILE=$(mktemp -t vpssec-sshd-rescue-pid.XXXXXX) || {
        print_error "$(i18n 'error.temp_file_failed')"
        rm -f "$SSH_RESCUE_CONFIG"; SSH_RESCUE_CONFIG=""
        return 1
    }
    chmod 600 "$SSH_RESCUE_CONFIG"

    # Standalone, never Include-ing the live sshd_config: that re-imports its
    # Port and any in-flux directive that could block the rescue. Auth is
    # permissive on purpose; MaxAuthTries and LoginGraceTime bound it.
    cat > "$SSH_RESCUE_CONFIG" <<EOF
Port $SSH_RESCUE_PORT
PidFile $SSH_RESCUE_PIDFILE
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
UsePAM yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
EOF

    # Validate the rescue config in isolation before launching.
    if ! sshd -t -f "$SSH_RESCUE_CONFIG" 2>/dev/null; then
        print_error "$(i18n 'ssh.rescue_port_failed')"
        _ssh_close_rescue_port
        return 1
    fi

    # Launch in the foreground (-D) and background it, so $! is the master sshd
    # pid (a daemonising sshd double-forks and loses the pid). Output is dropped:
    # the config was validated above and the bind is verified below.
    /usr/sbin/sshd -D -f "$SSH_RESCUE_CONFIG" >/dev/null 2>&1 &
    SSH_RESCUE_PID=$!

    # Wait (up to ~3s) for OUR daemon to bind the rescue port.
    local _i
    for ((_i=0; _i<30; _i++)); do
        if _ssh_rescue_is_up; then
            print_ok "$(i18n 'ssh.rescue_port_opened' "port=$SSH_RESCUE_PORT")"
            # Armed the moment the daemon is confirmed listening: without it
            # a killed vpssec leaves a root-and-password sshd running forever,
            # since sshd re-execs on HUP rather than exiting.
            trap '_ssh_close_rescue_port' EXIT
            trap '_ssh_close_rescue_port; exit 130' INT TERM HUP
            _ssh_rescue_allow_firewall
            return 0
        fi
        # If our daemon already exited, stop waiting.
        kill -0 "$SSH_RESCUE_PID" 2>/dev/null || break
        sleep 0.1
    done

    print_error "$(i18n 'ssh.rescue_port_failed')"
    _ssh_close_rescue_port
    return 1
}

# Tear down the rescue daemon: kill ONLY our tracked pid, remove our firewall
# rule, clean temps. Safe to call multiple times / after a failed open.
_ssh_close_rescue_port() {
    _ssh_rescue_remove_firewall

    if [[ -n "${SSH_RESCUE_PID:-}" ]] && kill -0 "$SSH_RESCUE_PID" 2>/dev/null; then
        kill "$SSH_RESCUE_PID" 2>/dev/null || true
        log_info "Closed rescue sshd on port ${SSH_RESCUE_PORT} (pid: $SSH_RESCUE_PID)"
    fi
    SSH_RESCUE_PID=""

    [[ -n "${SSH_RESCUE_CONFIG:-}" && -f "$SSH_RESCUE_CONFIG" ]] && rm -f "$SSH_RESCUE_CONFIG"
    [[ -n "${SSH_RESCUE_PIDFILE:-}" && -f "$SSH_RESCUE_PIDFILE" ]] && rm -f "$SSH_RESCUE_PIDFILE"
    SSH_RESCUE_CONFIG=""
    SSH_RESCUE_PIDFILE=""

    # Disarm the safety-net traps set when the rescue came up. Idempotent:
    # clearing unset traps is a no-op, and when the EXIT trap itself invoked
    # us, clearing here prevents a second run.
    trap - EXIT INT TERM HUP
}

# Backup path of the drop-in overwritten by the most recent write, so
# _ssh_reload_safe can roll back. "NEW" = no prior drop-in existed, so
# rollback deletes the file; empty = no call has run yet.
SSH_LAST_DROPIN_BACKUP=""

# Migrate the legacy 99- drop-in, which loses to 50-cloud-init, to the 00-
# name. Acts only when the legacy file exists and the new one does not.
# Best effort: a failure leaves the legacy file, which 00- outranks anyway.
_ssh_migrate_legacy_dropin() {
    [[ -f "$SSH_HARDENING_DROPIN_LEGACY" ]] || return 0
    [[ -e "$SSH_HARDENING_DROPIN" ]] && return 0
    if mv "$SSH_HARDENING_DROPIN_LEGACY" "$SSH_HARDENING_DROPIN" 2>/dev/null; then
        log_info "Migrated legacy SSH hardening drop-in to $SSH_HARDENING_DROPIN"
    fi
}

# Assert sshd's EFFECTIVE value via the fully-merged `sshd -T` — the real
# guard against the precedence trap, where a wrong file order or a Match
# override would otherwise read as success. Compared case-insensitively.
_ssh_verify_effective() {
    local key="${1,,}"
    local expected="${2,,}"
    # Capture then awk-over-herestring, not `sshd -T | awk ...exit`: the early
    # awk exit SIGPIPEs sshd and, under pipefail+set -e in a subshell, would
    # abort before returning (same trap as _ssh_effective_authorizedkeysfiles).
    local sshd_dump effective
    sshd_dump=$(sshd -T 2>/dev/null || true)
    effective=$(awk -v k="$key" 'tolower($1)==k{print tolower($2); exit}' <<<"$sshd_dump")
    [[ "$effective" == "$expected" ]]
}

# Write SSH hardening config
_ssh_write_hardening_config() {
    local content="$1"
    local temp_file

    mkdir -p "$SSH_DROPIN_DIR"

    # Backed up so the full-context sshd -t failure path can restore it: a
    # broken drop-in left on disk blocks sshd at the next restart.
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        SSH_LAST_DROPIN_BACKUP=$(backup_file "$SSH_HARDENING_DROPIN") || return 1
    else
        # "NEW" drives this module's own reload-failure rollback. backup_file
        # is called as well so the plan-level rollback also deletes it —
        # without both, the drop-in survives "rollback".
        backup_file "$SSH_HARDENING_DROPIN" >/dev/null || return 1
        SSH_LAST_DROPIN_BACKUP="NEW"
    fi

    # Write to temp file first with secure permissions
    temp_file=$(mktemp -t vpssec-sshd.XXXXXX) || {
        print_error "$(i18n 'error.temp_file_failed')"
        return 1
    }
    chmod 600 "$temp_file"

    {
        echo "# vpssec SSH hardening - $(date -Iseconds)"
        echo "$content"
    } > "$temp_file"

    # Standalone parse: catches syntax errors without the real sshd_config on
    # disk. Full-context validation happens in _ssh_reload_safe.
    if sshd -t -f "$temp_file" 2>/dev/null; then
        chmod 644 "$temp_file"
        if mv "$temp_file" "$SSH_HARDENING_DROPIN"; then
            print_ok "$(i18n 'ssh.dropin_created' "path=$SSH_HARDENING_DROPIN")"
            return 0
        else
            rm -f "$temp_file"
            print_error "$(i18n 'ssh.move_file_failed')"
            return 1
        fi
    else
        rm -f "$temp_file"
        print_error "$(i18n 'ssh.sshd_test_fail')"
        return 1
    fi
}

# Restore the drop-in to its state before the most recent write. Used when
# full-context validation fails on a file that parses fine in isolation.
_ssh_rollback_dropin() {
    local backup="${SSH_LAST_DROPIN_BACKUP:-}"

    if [[ "$backup" == "NEW" ]]; then
        # No prior drop-in: delete the new one we just wrote.
        if [[ -f "$SSH_HARDENING_DROPIN" ]] && rm -f "$SSH_HARDENING_DROPIN"; then
            print_warn "$(i18n 'ssh.dropin_rolled_back_deleted' 2>/dev/null || echo 'Removed newly written SSH drop-in after validation failed')"
        fi
    elif [[ -n "$backup" && -f "$backup" ]]; then
        # Restore prior content. Use cp -p to preserve mode/ownership
        # (backup_file already chmodded the backup 600, but the live
        # drop-in is 644; let chmod --reference restore that).
        if cp -p "$backup" "$SSH_HARDENING_DROPIN" 2>/dev/null; then
            chmod 644 "$SSH_HARDENING_DROPIN" 2>/dev/null || true
            print_warn "$(i18n 'ssh.dropin_rolled_back_restored' 2>/dev/null || echo 'Restored previous SSH drop-in from backup after validation failed')"
        else
            print_error "$(i18n 'ssh.dropin_rollback_failed' 2>/dev/null || echo 'Failed to restore previous SSH drop-in; manual review required')"
        fi
    else
        # Backup path unset or backup file missing (very unusual).
        print_error "$(i18n 'ssh.dropin_rollback_missing' 2>/dev/null || echo 'No SSH drop-in backup available for rollback')"
    fi

    # Reset so a later reload cannot "rollback" stale state.
    SSH_LAST_DROPIN_BACKUP=""
}

# Reload sshd safely. The full-context `sshd -t` can fail on a drop-in that
# parses alone, and that failure MUST roll back. Optional trailing
# (key expected) pairs are asserted with sshd -T after the reload.
_ssh_reload_safe() {
    # Test config first
    if sshd -t 2>/dev/null; then
        print_ok "$(i18n 'ssh.sshd_test_ok')"

        if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
            print_ok "$(i18n 'ssh.sshd_reloaded')"

            # Verify effective values actually changed. Skipped only when sshd
            # is unavailable to answer (verify returns non-zero → treated as
            # mismatch), which correctly surfaces "could not confirm".
            local _k _v
            while [[ $# -ge 2 ]]; do
                _k="$1"; _v="$2"; shift 2
                if ! _ssh_verify_effective "$_k" "$_v"; then
                    print_error "$(i18n 'ssh.effective_mismatch' "key=$_k" "value=$_v")"
                    _ssh_rollback_dropin
                    return 1
                fi
            done
            return 0
        else
            print_error "$(i18n 'ssh.reload_failed')"
            # Roll back here too: the config parses, so leaving it would not
            # break the next boot — it would apply the change unverified at
            # whatever later restart, with no rescue port open.
            _ssh_rollback_dropin
            return 1
        fi
    else
        print_error "$(i18n 'ssh.sshd_test_fail')"
        _ssh_rollback_dropin
        return 1
    fi
}

_ssh_fix_disable_password_auth() {
    # Safety check - ensure user has SSH key access
    local current_ip=$(get_current_ssh_ip)
    if [[ -n "$current_ip" ]]; then
        print_info "$(i18n 'ssh.current_connection' "ip=$current_ip")"
    fi

    # Safety gate: at least one account that can ACTUALLY log in by key must
    # survive. A non-root admin with a key is safest. Root's key counts ONLY
    # when PermitRootLogin still permits key auth.
    local admin_users=$(_ssh_get_admin_users)
    local has_key_user=""

    # A key alone is not a way back in if the account itself cannot log in:
    # a nologin-shell or expired "admin" satisfied this gate and the change
    # then locked out everyone with a working shell.
    for user in $admin_users; do
        if _ssh_user_has_key "$user" && _ssh_account_can_login "$user"; then
            has_key_user="$user"
            break
        fi
    done

    if [[ -z "$has_key_user" ]]; then
        if _ssh_can_login_with_key "root"; then
            # Root's key is the only way back in — legitimate on a fresh
            # image, but fragile. Warn that disabling root login too would
            # remove this last path.
            print_warn "$(i18n 'ssh.only_root_key_warning')"
        else
            print_error "$(i18n 'ssh.no_key_user')"
            print_warn "$(i18n 'ssh.add_key_first')"
            return 1
        fi
    fi

    # Open the rescue daemon BEFORE confirming, so the operator can actually
    # test it during the confirmation below. MANDATORY for SSH access changes.
    if ! _ssh_open_rescue_port; then
        print_warn "$(i18n 'ssh.rescue_port_check' "port=$SSH_RESCUE_PORT")"
        return 1
    fi

    # Critical confirmation = verify the rescue path works before we touch the
    # live config. confirm_critical ignores --yes and needs a typed "yes" on a
    # tty; declining tears the rescue down and changes nothing.
    if ! confirm_critical "$(i18n 'ssh.rescue_port_verify' "port=$SSH_RESCUE_PORT")"; then
        _ssh_close_rescue_port
        return 1
    fi

    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^PasswordAuthentication") || true
    fi

    # Write config
    local content="PasswordAuthentication no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe PasswordAuthentication no
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
        print_error "$(i18n 'ssh.no_admin_for_root')"
        print_warn "$(i18n 'ssh.create_admin_first')"
        return 1
    fi

    # Joint-lockout guard: with password auth already off, removing root login
    # leaves only the non-root admins' keys, so one must actually exist. This
    # makes disable_password + disable_root safe in either apply order.
    if ! _ssh_password_auth_enabled; then
        local root_key_admin=""
        for user in $admin_users; do
            if _ssh_user_has_key "$user" && _ssh_account_can_login "$user"; then
                root_key_admin="$user"
                break
            fi
        done
        if [[ -z "$root_key_admin" ]]; then
            print_error "$(i18n 'ssh.no_admin_key_pw_off')"
            print_warn "$(i18n 'ssh.add_key_first')"
            return 1
        fi
    fi

    # Open the rescue daemon BEFORE confirming, so the operator can actually
    # test it during the confirmation below. MANDATORY for SSH access changes.
    if ! _ssh_open_rescue_port; then
        print_warn "$(i18n 'ssh.rescue_port_check' "port=$SSH_RESCUE_PORT")"
        return 1
    fi

    # Critical confirmation = verify the rescue path works before we touch the
    # live config. confirm_critical ignores --yes and needs a typed "yes" on a
    # tty; declining tears the rescue down and changes nothing.
    if ! confirm_critical "$(i18n 'ssh.rescue_port_verify' "port=$SSH_RESCUE_PORT")"; then
        _ssh_close_rescue_port
        return 1
    fi

    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^PermitRootLogin") || true
    fi

    # Write config
    local content="PermitRootLogin no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe PermitRootLogin no
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
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^PubkeyAuthentication") || true
    fi

    # Write config
    local content="PubkeyAuthentication yes"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe PubkeyAuthentication yes
    else
        return 1
    fi
}

_ssh_fix_disable_empty_password() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^PermitEmptyPasswords") || true
    fi

    # Write config
    local content="PermitEmptyPasswords no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe PermitEmptyPasswords no
    else
        return 1
    fi
}

_ssh_fix_set_max_auth_tries() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^MaxAuthTries") || true
    fi

    # Write config
    local content="MaxAuthTries 4"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe MaxAuthTries 4
    else
        return 1
    fi
}

_ssh_fix_set_login_grace_time() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^LoginGraceTime") || true
    fi

    # Write config
    local content="LoginGraceTime 60"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe LoginGraceTime 60
    else
        return 1
    fi
}

_ssh_fix_disable_x11_forwarding() {
    # Read existing hardening config
    local existing=""
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        existing=$(grep -v "^#" "$SSH_HARDENING_DROPIN" | grep -iv "^X11Forwarding") || true
    fi

    # Write config
    local content="X11Forwarding no"
    if [[ -n "$existing" ]]; then
        content="$existing
$content"
    fi

    if _ssh_write_hardening_config "$content"; then
        _ssh_reload_safe X11Forwarding no
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
            grep -iv "^Ciphers" | \
            grep -iv "^MACs" | \
            grep -iv "^KexAlgorithms") || true
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
