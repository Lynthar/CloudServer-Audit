#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# User security audit module
# Copyright (c) 2024
#
# IMPORTANT: This module is AUDIT ONLY
# - NO automatic modifications to users
# - NO automatic deletions
# - NO automatic password changes
# - All findings are ALERT ONLY
#
# This module detects:
# - UID 0 accounts (besides root)
# - Empty password accounts
# - Users with interactive shells
# - Sudoers and privileged users
# - Recently created users
# - SSH authorized_keys analysis
# - Suspicious user configurations

# ==============================================================================
# Configuration
# ==============================================================================

# System users that should have shells (whitelist)
declare -a ALLOWED_SHELL_USERS=(
    "root"
    "sync"  # Has /bin/sync as shell
)

# Known system accounts (should not have login shells)
declare -a SYSTEM_ACCOUNTS=(
    "daemon" "bin" "sys" "games" "man" "lp" "mail" "news" "uucp"
    "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody"
    "systemd-network" "systemd-resolve" "systemd-timesync"
    "messagebus" "syslog" "sshd" "mysql" "postgres" "redis"
    "mongodb" "nginx" "apache" "httpd" "ftp" "postfix" "dovecot"
    "_apt" "uuidd" "tcpdump" "landscape" "pollinate" "ubuntu"
    "lxd" "usbmux" "dnsmasq" "libvirt-qemu" "libvirt-dnsmasq"
    "colord" "geoclue" "pulse" "rtkit" "saned" "avahi" "cups"
)

# Suspicious username patterns
declare -a SUSPICIOUS_USERNAMES=(
    "^admin[0-9]*$"
    "^test[0-9]*$"
    "^guest[0-9]*$"
    "^user[0-9]*$"
    "^temp[0-9]*$"
    "^tmp[0-9]*$"
    "^backup[0-9]+$"
    "^ftp[0-9]+$"
    "^mysql[0-9]+$"
    "^postgres[0-9]+$"
    "^oracle[0-9]*$"
    "^support[0-9]*$"
    "^service[0-9]*$"
    "^daemon[0-9]+$"
    ".*\\..*"  # Contains dots
    ".*[[:space:]].*"  # Contains spaces
)

# Days to consider a user "recently created"
RECENT_USER_DAYS=7

# Password policy settings (recommended values)
declare -A PASSWORD_POLICY=(
    ["PASS_MAX_DAYS"]="90"      # Maximum days before password expires
    ["PASS_MIN_DAYS"]="1"       # Minimum days between password changes
    ["PASS_MIN_LEN"]="8"        # Minimum password length
    ["PASS_WARN_AGE"]="7"       # Days before expiry to warn user
)

# pwquality recommended settings
declare -A PWQUALITY_POLICY=(
    ["minlen"]="12"
    ["dcredit"]="-1"
    ["ucredit"]="-1"
    ["lcredit"]="-1"
    ["ocredit"]="-1"
    ["minclass"]="3"
)

# ==============================================================================
# Detection Functions
# ==============================================================================

# Check if user has a login shell
_has_login_shell() {
    local shell="$1"
    case "$shell" in
        */nologin|*/false|""|/bin/sync)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

# Check if username is in system accounts list
_is_system_account() {
    local user="$1"
    for sys_user in "${SYSTEM_ACCOUNTS[@]}"; do
        [[ "$user" == "$sys_user" ]] && return 0
    done
    return 1
}

# Check if username matches suspicious patterns
_is_suspicious_username() {
    local user="$1"
    for pattern in "${SUSPICIOUS_USERNAMES[@]}"; do
        if [[ "$user" =~ $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Get all users with UID 0 (except root)
_find_uid0_users() {
    awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd 2>/dev/null
}

# Get users with empty passwords that can login
_find_empty_password_users() {
    local users=()

    # Check /etc/shadow for empty password field
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r user pass rest; do
            # Empty password or single character (! or * means locked)
            if [[ -z "$pass" || "$pass" == "" ]]; then
                # Check if user has a login shell
                local shell=$(getent passwd "$user" 2>/dev/null | cut -d: -f7)
                if _has_login_shell "$shell"; then
                    users+=("$user")
                fi
            fi
        done < /etc/shadow
    fi

    printf '%s\n' "${users[@]}"
}

# Get system users with interactive shells
_find_system_users_with_shells() {
    local suspicious=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        # Skip non-system users (UID >= 1000) and root
        [[ "$uid" -ge 1000 || "$user" == "root" ]] && continue

        # Skip allowed shell users
        local allowed=false
        for allowed_user in "${ALLOWED_SHELL_USERS[@]}"; do
            [[ "$user" == "$allowed_user" ]] && allowed=true && break
        done
        [[ "$allowed" == "true" ]] && continue

        # Check if has login shell
        if _has_login_shell "$shell"; then
            suspicious+=("$user|$uid|$shell")
        fi
    done < /etc/passwd

    printf '%s\n' "${suspicious[@]}"
}

# Get all users in sudo/wheel groups
_find_sudo_users() {
    local sudo_users=()

    # Check sudo group
    if getent group sudo &>/dev/null; then
        local members=$(getent group sudo | cut -d: -f4)
        IFS=',' read -ra sudo_users <<< "$members"
    fi

    # Check wheel group
    if getent group wheel &>/dev/null; then
        local wheel_members=$(getent group wheel | cut -d: -f4)
        IFS=',' read -ra wheel_arr <<< "$wheel_members"
        sudo_users+=("${wheel_arr[@]}")
    fi

    # Check /etc/sudoers.d/ for additional users
    if [[ -d /etc/sudoers.d ]]; then
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            local sudoer_users=$(grep -oP '^\s*\K[a-zA-Z_][a-zA-Z0-9_-]*(?=\s+ALL)' "$f" 2>/dev/null)
            while read -r u; do
                [[ -n "$u" ]] && sudo_users+=("$u")
            done <<< "$sudoer_users"
        done
    fi

    # Deduplicate
    printf '%s\n' "${sudo_users[@]}" | sort -u
}

# Find NOPASSWD sudo entries - HIGH RISK
_find_nopasswd_sudo() {
    local findings=()

    # Check /etc/sudoers
    if [[ -r /etc/sudoers ]]; then
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue

            # Check for NOPASSWD
            if [[ "$line" =~ NOPASSWD ]]; then
                # Extract user/group
                local entry=$(echo "$line" | sed 's/[[:space:]]*#.*//')
                findings+=("/etc/sudoers: $entry")
            fi
        done < /etc/sudoers
    fi

    # Check /etc/sudoers.d/
    if [[ -d /etc/sudoers.d ]]; then
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            [[ -r "$f" ]] || continue

            # Skip backup files
            [[ "$f" =~ ~$ ]] && continue
            [[ "$f" =~ \.bak$ ]] && continue

            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "$line" ]] && continue

                if [[ "$line" =~ NOPASSWD ]]; then
                    local entry=$(echo "$line" | sed 's/[[:space:]]*#.*//')
                    findings+=("$f: $entry")
                fi
            done < "$f"
        done
    fi

    printf '%s\n' "${findings[@]}"
}

# Get recently created users
_find_recent_users() {
    local recent=()
    local cutoff_date=$(date -d "$RECENT_USER_DAYS days ago" +%s 2>/dev/null || date -v-${RECENT_USER_DAYS}d +%s 2>/dev/null)

    while IFS=: read -r user pass uid gid gecos home shell; do
        # Skip system users
        [[ "$uid" -lt 1000 ]] && continue

        # Check home directory creation time or passwd modification
        local created=""
        if [[ -d "$home" ]]; then
            local home_stat=$(stat -c %Y "$home" 2>/dev/null || stat -f %m "$home" 2>/dev/null)
            if [[ -n "$home_stat" && "$home_stat" -gt "$cutoff_date" ]]; then
                created=$(date -d "@$home_stat" "+%Y-%m-%d" 2>/dev/null || date -r "$home_stat" "+%Y-%m-%d" 2>/dev/null)
                recent+=("$user|$uid|$created|$home")
            fi
        fi
    done < /etc/passwd

    printf '%s\n' "${recent[@]}"
}

# Analyze SSH authorized_keys
_analyze_ssh_keys() {
    local findings=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        # Skip system users without login shells
        [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
        ! _has_login_shell "$shell" && continue

        local authkeys="$home/.ssh/authorized_keys"
        [[ -f "$authkeys" ]] || continue

        # Count keys
        local key_count=$(grep -c '^ssh-' "$authkeys" 2>/dev/null || echo 0)
        [[ "$key_count" -eq 0 ]] && continue

        # Check permissions
        local key_perms=$(stat -c %a "$authkeys" 2>/dev/null || stat -f %Lp "$authkeys" 2>/dev/null)
        local perms_ok="yes"
        if [[ "$key_perms" != "600" && "$key_perms" != "400" ]]; then
            perms_ok="no"
        fi

        # Check for suspicious key comments
        local suspicious_keys=0
        while read -r line; do
            [[ "$line" =~ ^ssh- ]] || continue
            local comment=$(echo "$line" | awk '{print $NF}')
            # Check for suspicious patterns in comments
            if [[ "$comment" =~ (test|temp|backup|admin@|root@unknown) ]]; then
                ((suspicious_keys++))
            fi
        done < "$authkeys"

        findings+=("$user|$key_count|$key_perms|$perms_ok|$suspicious_keys|$authkeys")
    done < /etc/passwd

    printf '%s\n' "${findings[@]}"
}

# Find users with suspicious usernames
_find_suspicious_users() {
    local suspicious=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        # Only check regular users
        [[ "$uid" -lt 1000 ]] && continue

        if _is_suspicious_username "$user"; then
            local has_shell="no"
            _has_login_shell "$shell" && has_shell="yes"
            suspicious+=("$user|$uid|$shell|$has_shell")
        fi
    done < /etc/passwd

    printf '%s\n' "${suspicious[@]}"
}

# Find users with home directories in unusual locations
_find_unusual_home() {
    local unusual=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        # Skip system users
        [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue

        # Normal locations
        case "$home" in
            /root|/home/*|/var/lib/*|/nonexistent|/var/empty)
                continue
                ;;
            *)
                if [[ -d "$home" ]]; then
                    unusual+=("$user|$uid|$home")
                fi
                ;;
        esac
    done < /etc/passwd

    printf '%s\n' "${unusual[@]}"
}

# Check password policy in /etc/login.defs
_check_password_policy() {
    local issues=()
    local login_defs="/etc/login.defs"

    if [[ ! -f "$login_defs" ]]; then
        echo "login.defs_missing"
        return
    fi

    # Check PASS_MAX_DAYS
    local pass_max=$(grep -E "^PASS_MAX_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -z "$pass_max" ]]; then
        issues+=("PASS_MAX_DAYS not set")
    elif [[ "$pass_max" == "99999" || "$pass_max" -gt 365 ]]; then
        issues+=("PASS_MAX_DAYS=$pass_max (no expiry or too long)")
    fi

    # Check PASS_MIN_DAYS
    local pass_min=$(grep -E "^PASS_MIN_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -z "$pass_min" || "$pass_min" == "0" ]]; then
        issues+=("PASS_MIN_DAYS=$pass_min (allows immediate changes)")
    fi

    # Check PASS_MIN_LEN (may be deprecated in favor of pam)
    local pass_len=$(grep -E "^PASS_MIN_LEN" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -n "$pass_len" && "$pass_len" -lt 8 ]]; then
        issues+=("PASS_MIN_LEN=$pass_len (too short)")
    fi

    # Check PASS_WARN_AGE
    local pass_warn=$(grep -E "^PASS_WARN_AGE" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -z "$pass_warn" || "$pass_warn" -lt 7 ]]; then
        issues+=("PASS_WARN_AGE=$pass_warn (should be at least 7)")
    fi

    printf '%s\n' "${issues[@]}"
}

# Check password quality settings (pwquality.conf or pam_pwquality)
_check_pwquality() {
    local issues=()
    local pwquality_conf="/etc/security/pwquality.conf"

    # Check if pwquality is used in PAM
    local pam_uses_pwquality=false
    if grep -rq "pam_pwquality" /etc/pam.d/ 2>/dev/null; then
        pam_uses_pwquality=true
    fi

    if [[ "$pam_uses_pwquality" == false ]]; then
        # Check for pam_cracklib as alternative
        if ! grep -rq "pam_cracklib" /etc/pam.d/ 2>/dev/null; then
            issues+=("No password quality module (pwquality/cracklib) in PAM")
        fi
    fi

    # If pwquality.conf exists, check settings
    if [[ -f "$pwquality_conf" ]]; then
        local minlen=$(grep -E "^minlen" "$pwquality_conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')
        if [[ -z "$minlen" || "$minlen" -lt 8 ]]; then
            issues+=("minlen=$minlen (should be at least 12)")
        fi

        # Check for complexity requirements
        local dcredit=$(grep -E "^dcredit" "$pwquality_conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')
        local ucredit=$(grep -E "^ucredit" "$pwquality_conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')
        local lcredit=$(grep -E "^lcredit" "$pwquality_conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')
        local ocredit=$(grep -E "^ocredit" "$pwquality_conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')

        # Negative values mean required, 0 or positive means not enforced
        if [[ -z "$dcredit" || "$dcredit" -ge 0 ]]; then
            issues+=("dcredit not enforcing digit requirement")
        fi
        if [[ -z "$ucredit" || "$ucredit" -ge 0 ]]; then
            issues+=("ucredit not enforcing uppercase requirement")
        fi
    fi

    printf '%s\n' "${issues[@]}"
}

# ==============================================================================
# Audit Functions
# ==============================================================================

users_audit() {
    log_info "Running user security audit"

    local check_json

    # 1. Check for UID 0 users (besides root) - CRITICAL
    local uid0_users=$(_find_uid0_users)
    local uid0_count=$(echo "$uid0_users" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$uid0_users" && "$uid0_count" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "users.uid0_found",
    "check_id": "users.uid0_found",
    "module": "users",
    "title": "$(i18n 'users.uid0_found' 2>/dev/null || echo 'UID 0 Users Found (Besides root)'): $uid0_count",
    "desc": "$(echo "$uid0_users" | tr '\n' ', ' | sed 's/,$//')",
    "status": "failed",
    "severity": "high",
    "suggestion": "$(i18n 'users.uid0_review' 2>/dev/null || echo 'Review these accounts - may be backdoors')",
    "fix_id": "users.uid0_found"
}
EOF
)
    else
        check_json=$(cat <<EOF
{
    "id": "users.uid0_ok",
    "check_id": "users.uid0_ok",
    "module": "users",
    "title": "$(i18n 'users.uid0_ok' 2>/dev/null || echo 'No Extra UID 0 Users')",
    "desc": "$(i18n 'users.uid0_ok_desc' 2>/dev/null || echo 'Only root has UID 0')",
    "status": "passed",
    "severity": "info"
}
EOF
)
    fi
    state_add_check "$check_json"

    # 2. Check for empty password users - CRITICAL
    local empty_pass=$(_find_empty_password_users)
    local empty_count=$(echo "$empty_pass" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$empty_pass" && "$empty_count" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "users.empty_password",
    "check_id": "users.empty_password",
    "module": "users",
    "title": "$(i18n 'users.empty_password' 2>/dev/null || echo 'Empty Password Users'): $empty_count",
    "desc": "$(echo "$empty_pass" | tr '\n' ', ' | sed 's/,$//')",
    "status": "failed",
    "severity": "high",
    "suggestion": "$(i18n 'users.set_password' 2>/dev/null || echo 'Set passwords or lock these accounts')",
    "fix_id": "users.empty_password"
}
EOF
)
    else
        check_json=$(cat <<EOF
{
    "id": "users.no_empty_password",
    "check_id": "users.no_empty_password",
    "module": "users",
    "title": "$(i18n 'users.no_empty_password' 2>/dev/null || echo 'No Empty Password Users')",
    "desc": "$(i18n 'users.no_empty_password_desc' 2>/dev/null || echo 'All users with shells have passwords')",
    "status": "passed",
    "severity": "info"
}
EOF
)
    fi
    state_add_check "$check_json"

    # 3. Check system users with shells - MEDIUM
    local sys_shells=$(_find_system_users_with_shells)
    local sys_shell_count=$(echo "$sys_shells" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$sys_shells" && "$sys_shell_count" -gt 0 ]]; then
        local user_list=""
        while IFS='|' read -r user uid shell; do
            [[ -z "$user" ]] && continue
            user_list+="$user ($shell), "
        done <<< "$sys_shells"
        user_list="${user_list%, }"

        check_json=$(cat <<EOF
{
    "id": "users.system_with_shell",
    "check_id": "users.system_with_shell",
    "module": "users",
    "title": "$(i18n 'users.system_with_shell' 2>/dev/null || echo 'System Users with Login Shells'): $sys_shell_count",
    "desc": "$user_list",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'users.change_shell' 2>/dev/null || echo 'Change shell to /usr/sbin/nologin if not needed')",
    "fix_id": "users.system_with_shell"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 4. List sudo/privileged users - INFO
    local sudo_users=$(_find_sudo_users)
    local sudo_count=$(echo "$sudo_users" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$sudo_users" && "$sudo_count" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "users.sudo_users",
    "check_id": "users.sudo_users",
    "module": "users",
    "title": "$(i18n 'users.sudo_users' 2>/dev/null || echo 'Privileged Users'): $sudo_count",
    "desc": "$(echo "$sudo_users" | tr '\n' ', ' | sed 's/,$//')",
    "status": "passed",
    "severity": "info",
    "suggestion": "$(i18n 'users.review_sudo' 2>/dev/null || echo 'Review if all these users need sudo access')"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 4.5 Check for NOPASSWD sudo - HIGH RISK
    local nopasswd=$(_find_nopasswd_sudo)
    local nopasswd_count=$(echo "$nopasswd" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$nopasswd" && "$nopasswd_count" -gt 0 ]]; then
        local nopasswd_list=""
        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            nopasswd_list+="$entry; "
        done <<< "$nopasswd"
        nopasswd_list="${nopasswd_list%; }"

        check_json=$(cat <<EOF
{
    "id": "users.nopasswd_sudo",
    "check_id": "users.nopasswd_sudo",
    "module": "users",
    "title": "$(i18n 'users.nopasswd_sudo' 2>/dev/null || echo 'NOPASSWD Sudo Entries Found'): $nopasswd_count",
    "desc": "$nopasswd_list",
    "status": "failed",
    "severity": "high",
    "suggestion": "$(i18n 'users.review_nopasswd' 2>/dev/null || echo 'NOPASSWD allows privilege escalation without password - review if necessary')",
    "fix_id": "users.nopasswd_sudo"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 5. Check recently created users - INFO/LOW
    local recent=$(_find_recent_users)
    local recent_count=$(echo "$recent" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$recent" && "$recent_count" -gt 0 ]]; then
        local recent_list=""
        while IFS='|' read -r user uid created home; do
            [[ -z "$user" ]] && continue
            recent_list+="$user ($created), "
        done <<< "$recent"
        recent_list="${recent_list%, }"

        check_json=$(cat <<EOF
{
    "id": "users.recent_users",
    "check_id": "users.recent_users",
    "module": "users",
    "title": "$(i18n 'users.recent_users' 2>/dev/null || echo 'Recently Created Users'): $recent_count",
    "desc": "$recent_list",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'users.verify_recent' 2>/dev/null || echo 'Verify these users were intentionally created')",
    "fix_id": "users.recent_users"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 6. Analyze SSH authorized_keys - MEDIUM
    local ssh_keys=$(_analyze_ssh_keys)
    local bad_perms=0
    local suspicious_keys=0
    local users_with_keys=0

    while IFS='|' read -r user key_count perms perms_ok sus_count path; do
        [[ -z "$user" ]] && continue
        ((users_with_keys++))
        [[ "$perms_ok" == "no" ]] && ((bad_perms++))
        ((suspicious_keys += sus_count))
    done <<< "$ssh_keys"

    if [[ "$bad_perms" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "users.ssh_keys_perms",
    "check_id": "users.ssh_keys_perms",
    "module": "users",
    "title": "$(i18n 'users.ssh_keys_perms' 2>/dev/null || echo 'SSH authorized_keys Permission Issues'): $bad_perms",
    "desc": "$(i18n 'users.ssh_keys_perms_desc' 2>/dev/null || echo 'Some authorized_keys files have weak permissions')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'users.fix_key_perms' 2>/dev/null || echo 'Set permissions to 600: chmod 600 ~/.ssh/authorized_keys')",
    "fix_id": "users.ssh_keys_perms"
}
EOF
)
        state_add_check "$check_json"
    fi

    if [[ "$users_with_keys" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "users.ssh_keys_info",
    "check_id": "users.ssh_keys_info",
    "module": "users",
    "title": "$(i18n 'users.ssh_keys_info' 2>/dev/null || echo 'Users with SSH Keys'): $users_with_keys",
    "desc": "$(i18n 'users.ssh_keys_info_desc' 2>/dev/null || echo 'Users configured with SSH public key authentication')",
    "status": "passed",
    "severity": "info"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 7. Check for suspicious usernames - LOW (strict only)
    local suspicious=$(_find_suspicious_users)
    local sus_count=$(echo "$suspicious" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$suspicious" && "$sus_count" -gt 0 ]]; then
        local sus_list=""
        while IFS='|' read -r user uid shell has_shell; do
            [[ -z "$user" ]] && continue
            sus_list+="$user, "
        done <<< "$suspicious"
        sus_list="${sus_list%, }"

        check_json=$(cat <<EOF
{
    "id": "users.suspicious_names",
    "check_id": "users.suspicious_names",
    "module": "users",
    "title": "$(i18n 'users.suspicious_names' 2>/dev/null || echo 'Suspicious Usernames'): $sus_count",
    "desc": "$sus_list",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'users.review_names' 2>/dev/null || echo 'Review these usernames - may be test accounts')",
    "fix_id": "users.suspicious_names"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 8. Check for unusual home directories - LOW (strict only)
    local unusual=$(_find_unusual_home)
    local unusual_count=$(echo "$unusual" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$unusual" && "$unusual_count" -gt 0 ]]; then
        local unusual_list=""
        while IFS='|' read -r user uid home; do
            [[ -z "$user" ]] && continue
            unusual_list+="$user:$home, "
        done <<< "$unusual"
        unusual_list="${unusual_list%, }"

        check_json=$(cat <<EOF
{
    "id": "users.unusual_home",
    "check_id": "users.unusual_home",
    "module": "users",
    "title": "$(i18n 'users.unusual_home' 2>/dev/null || echo 'Unusual Home Directories'): $unusual_count",
    "desc": "$unusual_list",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'users.review_home' 2>/dev/null || echo 'Review these home directory locations')",
    "fix_id": "users.unusual_home"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 9. Check password policy in login.defs - MEDIUM
    local policy_issues=$(_check_password_policy)
    local policy_count=$(echo "$policy_issues" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$policy_issues" && "$policy_count" -gt 0 ]]; then
        local policy_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            policy_list+="$issue; "
        done <<< "$policy_issues"
        policy_list="${policy_list%; }"

        check_json=$(cat <<EOF
{
    "id": "users.password_policy_weak",
    "check_id": "users.password_policy_weak",
    "module": "users",
    "title": "$(i18n 'users.password_policy_weak' 2>/dev/null || echo 'Weak Password Policy'): $policy_count issues",
    "desc": "$policy_list",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'users.fix_password_policy' 2>/dev/null || echo 'Configure password aging in /etc/login.defs')",
    "fix_id": "users.password_policy"
}
EOF
)
        state_add_check "$check_json"
    else
        check_json=$(cat <<EOF
{
    "id": "users.password_policy_ok",
    "check_id": "users.password_policy_ok",
    "module": "users",
    "title": "$(i18n 'users.password_policy_ok' 2>/dev/null || echo 'Password Policy Configured')",
    "desc": "$(i18n 'users.password_policy_ok_desc' 2>/dev/null || echo 'Password aging and length policies are set')",
    "status": "passed",
    "severity": "info"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 10. Check password quality settings - LOW
    local pwquality_issues=$(_check_pwquality)
    local pwquality_count=$(echo "$pwquality_issues" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$pwquality_issues" && "$pwquality_count" -gt 0 ]]; then
        local pwq_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            pwq_list+="$issue; "
        done <<< "$pwquality_issues"
        pwq_list="${pwq_list%; }"

        check_json=$(cat <<EOF
{
    "id": "users.pwquality_weak",
    "check_id": "users.pwquality_weak",
    "module": "users",
    "title": "$(i18n 'users.pwquality_weak' 2>/dev/null || echo 'Password Quality Not Enforced'): $pwquality_count issues",
    "desc": "$pwq_list",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'users.fix_pwquality' 2>/dev/null || echo 'Configure pam_pwquality or pam_cracklib for password complexity')",
    "fix_id": "users.pwquality"
}
EOF
)
        state_add_check "$check_json"
    fi

    return 0
}

# ==============================================================================
# Fix Functions (ALL ALERT ONLY - NO AUTO MODIFICATIONS)
# ==============================================================================

users_fix() {
    local fix_id="$1"

    # IMPORTANT: This module NEVER modifies users automatically
    # All fixes are alert-only with manual instructions

    case "$fix_id" in
        users.uid0_found)
            print_warn "⚠️  $(i18n 'users.critical_alert' 2>/dev/null || echo 'CRITICAL SECURITY ALERT')"
            echo ""
            echo "$(i18n 'users.uid0_warning' 2>/dev/null || echo 'Found non-root users with UID 0 (root privileges)'):"
            echo ""

            local uid0_users=$(_find_uid0_users)
            while read -r user; do
                [[ -z "$user" ]] && continue
                echo "  • $user"
                echo "    $(i18n 'users.check_cmd' 2>/dev/null || echo 'Check'): grep \"^$user:\" /etc/passwd"
                echo "    $(i18n 'users.lock_cmd' 2>/dev/null || echo 'Lock'): usermod -L $user"
                echo ""
            done <<< "$uid0_users"

            print_warn "$(i18n 'users.manual_action' 2>/dev/null || echo 'Manual action required - DO NOT delete without investigation')"
            return 1
            ;;

        users.empty_password)
            print_warn "⚠️  $(i18n 'users.critical_alert' 2>/dev/null || echo 'CRITICAL SECURITY ALERT')"
            echo ""
            echo "$(i18n 'users.empty_pass_warning' 2>/dev/null || echo 'Found users with empty passwords'):"
            echo ""

            local empty_pass=$(_find_empty_password_users)
            while read -r user; do
                [[ -z "$user" ]] && continue
                echo "  • $user"
                echo "    $(i18n 'users.set_pass_cmd' 2>/dev/null || echo 'Set password'): passwd $user"
                echo "    $(i18n 'users.lock_cmd' 2>/dev/null || echo 'Lock account'): usermod -L $user"
                echo ""
            done <<< "$empty_pass"

            print_warn "$(i18n 'users.manual_action' 2>/dev/null || echo 'Manual action required')"
            return 1
            ;;

        users.system_with_shell)
            print_info "$(i18n 'users.review_needed' 2>/dev/null || echo 'Review Needed')"
            echo ""
            echo "$(i18n 'users.sys_shell_info' 2>/dev/null || echo 'System users with login shells'):"
            echo ""

            local sys_shells=$(_find_system_users_with_shells)
            while IFS='|' read -r user uid shell; do
                [[ -z "$user" ]] && continue
                echo "  • $user (UID: $uid, Shell: $shell)"
                echo "    $(i18n 'users.change_shell_cmd' 2>/dev/null || echo 'Change shell'): usermod -s /usr/sbin/nologin $user"
                echo ""
            done <<< "$sys_shells"

            print_info "$(i18n 'users.verify_before_change' 2>/dev/null || echo 'Verify the user does not need shell access before changing')"
            return 1
            ;;

        users.nopasswd_sudo)
            print_warn "⚠️  $(i18n 'users.high_risk_alert' 2>/dev/null || echo 'HIGH RISK SECURITY ISSUE')"
            echo ""
            echo "$(i18n 'users.nopasswd_warning' 2>/dev/null || echo 'NOPASSWD sudo entries allow privilege escalation without password verification'):"
            echo ""

            local nopasswd=$(_find_nopasswd_sudo)
            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                echo "  ⚠️  $entry"
            done <<< "$nopasswd"

            echo ""
            echo "$(i18n 'users.nopasswd_risks' 2>/dev/null || echo 'Risks'):"
            echo "  • $(i18n 'users.nopasswd_risk1' 2>/dev/null || echo 'Compromised user account = full root access')"
            echo "  • $(i18n 'users.nopasswd_risk2' 2>/dev/null || echo 'Malware can escalate privileges without interaction')"
            echo "  • $(i18n 'users.nopasswd_risk3' 2>/dev/null || echo 'No audit trail for privilege escalation')"
            echo ""
            echo "$(i18n 'users.nopasswd_action' 2>/dev/null || echo 'Recommended actions'):"
            echo "  1. $(i18n 'users.nopasswd_action1' 2>/dev/null || echo 'Review if NOPASSWD is absolutely necessary')"
            echo "  2. $(i18n 'users.nopasswd_action2' 2>/dev/null || echo 'Limit NOPASSWD to specific commands only')"
            echo "  3. $(i18n 'users.nopasswd_action3' 2>/dev/null || echo 'Remove NOPASSWD and use password authentication')"
            echo ""
            echo "$(i18n 'users.edit_sudoers' 2>/dev/null || echo 'To edit safely'): sudo visudo"
            echo ""
            print_warn "$(i18n 'users.manual_action' 2>/dev/null || echo 'Manual action required - DO NOT auto-modify sudoers')"
            return 1
            ;;

        users.recent_users)
            print_info "$(i18n 'users.info_only' 2>/dev/null || echo 'Information Only')"
            echo ""
            echo "$(i18n 'users.recent_info' 2>/dev/null || echo 'Recently created users'):"
            echo ""

            local recent=$(_find_recent_users)
            while IFS='|' read -r user uid created home; do
                [[ -z "$user" ]] && continue
                echo "  • $user"
                echo "    UID: $uid"
                echo "    $(i18n 'users.created' 2>/dev/null || echo 'Created'): $created"
                echo "    Home: $home"
                echo "    $(i18n 'users.check_cmd' 2>/dev/null || echo 'Check'): id $user && chage -l $user"
                echo ""
            done <<< "$recent"

            return 1
            ;;

        users.ssh_keys_perms)
            print_info "$(i18n 'users.review_needed' 2>/dev/null || echo 'Review Needed')"
            echo ""
            echo "$(i18n 'users.ssh_perms_info' 2>/dev/null || echo 'SSH authorized_keys with incorrect permissions'):"
            echo ""

            local ssh_keys=$(_analyze_ssh_keys)
            while IFS='|' read -r user key_count perms perms_ok sus_count path; do
                [[ -z "$user" || "$perms_ok" == "yes" ]] && continue
                echo "  • $user: $path"
                echo "    $(i18n 'users.current_perms' 2>/dev/null || echo 'Current'): $perms (should be 600)"
                echo "    $(i18n 'users.fix_cmd' 2>/dev/null || echo 'Fix'): chmod 600 $path"
                echo ""
            done <<< "$ssh_keys"

            return 1
            ;;

        users.suspicious_names|users.unusual_home)
            print_info "$(i18n 'users.info_only' 2>/dev/null || echo 'Information Only')"
            echo ""
            echo "$(i18n 'users.review_accounts' 2>/dev/null || echo 'Please review these accounts manually')"
            echo ""
            return 1
            ;;

        users.password_policy)
            print_info "$(i18n 'users.password_policy_info' 2>/dev/null || echo 'Password Policy Configuration')"
            echo ""
            echo "$(i18n 'users.login_defs_location' 2>/dev/null || echo 'Configuration file'): /etc/login.defs"
            echo ""
            echo "$(i18n 'users.recommended_settings' 2>/dev/null || echo 'Recommended settings'):"
            echo "  PASS_MAX_DAYS   90    # Password expires after 90 days"
            echo "  PASS_MIN_DAYS   1     # Minimum 1 day between changes"
            echo "  PASS_MIN_LEN    8     # Minimum 8 characters (use pam for better)"
            echo "  PASS_WARN_AGE   7     # Warn 7 days before expiry"
            echo ""
            echo "$(i18n 'users.apply_to_existing' 2>/dev/null || echo 'To apply to existing users'):"
            echo "  chage -M 90 -m 1 -W 7 <username>"
            echo ""
            return 1
            ;;

        users.pwquality)
            print_info "$(i18n 'users.pwquality_info' 2>/dev/null || echo 'Password Quality Configuration')"
            echo ""
            echo "$(i18n 'users.pwquality_location' 2>/dev/null || echo 'Configuration file'): /etc/security/pwquality.conf"
            echo ""
            echo "$(i18n 'users.install_pwquality' 2>/dev/null || echo 'Install'): apt install libpam-pwquality"
            echo ""
            echo "$(i18n 'users.recommended_settings' 2>/dev/null || echo 'Recommended settings'):"
            echo "  minlen = 12       # Minimum password length"
            echo "  dcredit = -1      # Require at least 1 digit"
            echo "  ucredit = -1      # Require at least 1 uppercase"
            echo "  lcredit = -1      # Require at least 1 lowercase"
            echo "  ocredit = -1      # Require at least 1 special char"
            echo "  minclass = 3      # Require 3 character classes"
            echo ""
            return 1
            ;;

        *)
            log_warn "Unknown fix_id: $fix_id"
            return 1
            ;;
    esac
}
