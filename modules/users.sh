#!/usr/bin/env bash
# User security audit. AUDIT ONLY: this module never modifies, deletes or
# resets an account — every finding is alert-only.

# --- Configuration ---

# Named, not inlined: this is the seam that lets a test point every reader
# in this module at a fixture instead of the host's real /etc/shadow.
USERS_SHADOW_FILE="/etc/shadow"

# System users that should have shells (whitelist)
declare -ga ALLOWED_SHELL_USERS=(
    "root"
    "sync"  # Has /bin/sync as shell
)

# Known system accounts (should not have login shells)
declare -ga SYSTEM_ACCOUNTS=(
    "daemon" "bin" "sys" "games" "man" "lp" "mail" "news" "uucp"
    "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody"
    "systemd-network" "systemd-resolve" "systemd-timesync"
    "messagebus" "syslog" "sshd" "mysql" "postgres" "redis"
    "mongodb" "nginx" "apache" "httpd" "ftp" "postfix" "dovecot"
    "_apt" "uuidd" "tcpdump" "landscape" "pollinate" "ubuntu"
    "lxd" "usbmux" "dnsmasq" "libvirt-qemu" "libvirt-dnsmasq"
    "colord" "geoclue" "pulse" "rtkit" "saned" "avahi" "cups"
)

# Suspicious username patterns. Dotted names are deliberately absent:
# firstname.lastname is the standard LDAP/AD convention. Spaces stay,
# since shell-metacharacter usernames are genuinely unusual.
declare -ga SUSPICIOUS_USERNAMES=(
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
    ".*[[:space:]].*"  # Contains whitespace
)

# Days to consider a user "recently created"
RECENT_USER_DAYS=7

# Password policy settings (recommended values)
declare -gA PASSWORD_POLICY=(
    ["PASS_MAX_DAYS"]="90"      # Maximum days before password expires
    ["PASS_MIN_DAYS"]="1"       # Minimum days between password changes
    ["PASS_MIN_LEN"]="8"        # Minimum password length
    ["PASS_WARN_AGE"]="7"       # Days before expiry to warn user
)

# pwquality recommended settings
declare -gA PWQUALITY_POLICY=(
    ["minlen"]="12"
    ["dcredit"]="-1"
    ["ucredit"]="-1"
    ["lcredit"]="-1"
    ["ocredit"]="-1"
    ["minclass"]="3"
)

# --- Detection Functions ---

# Does this user have a login shell? An EMPTY 7th passwd field is NOT
# "no login": login(1) and sshd fall back to /bin/sh, so an empty-password,
# empty-shell account is fully login-capable.
_has_login_shell() {
    local shell="$1"
    case "$shell" in
        */nologin|*/false|/bin/sync)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

# True for a sudoers.d drop-in that sudo IGNORES: @includedir skips any name
# containing '.' or ending in '~'. Auditing those yields false findings, so
# every sudoers.d scanner here must skip them.
_sudoers_dropin_ignored() {
    local base="${1##*/}"
    [[ "$base" == *.* || "$base" == *'~' ]]
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

# All non-root UID 0 accounts. Uses getent, never /etc/passwd directly: a
# UID-0 entry from an LDAP/AD backend never appears in that file, which is
# exactly the backdoor this check exists for.
_find_uid0_users() {
    getent passwd 2>/dev/null | awk -F: '$3 == 0 && $1 != "root" { print $1 }'
}

# Get users with empty passwords that can login
_find_empty_password_users() {
    local users=()

    # Check /etc/shadow for empty password field
    if [[ -r "$USERS_SHADOW_FILE" ]]; then
        while IFS=: read -r user pass rest; do
            # Only truly empty hashes. `!` / `!!` / `*` mean a locked
            # account, which cannot log in and is safe.
            if [[ -z "$pass" ]]; then
                local shell=$(getent passwd "$user" 2>/dev/null | cut -d: -f7)
                if _has_login_shell "$shell"; then
                    users+=("$user")
                fi
            fi
        done < "$USERS_SHADOW_FILE"
    fi

    # Inline empty passwords too: an empty second passwd field means the
    # account needs no password, and such an entry NEVER appears in
    # /etc/shadow, so the scan above misses this backdoor form entirely.
    while IFS=: read -r user pass _ _ _ _ shell; do
        [[ -z "$pass" ]] || continue
        if _has_login_shell "$shell"; then
            users+=("$user")
        fi
    done < <(getent passwd 2>/dev/null)

    # Dedup: an account could surface from both scans.
    printf '%s\n' "${users[@]}" | grep -v '^$' | sort -u
}

# Get system users with interactive shells
_find_system_users_with_shells() {
    local suspicious=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        # Skip malformed lines (non-numeric UID would abort under set -u).
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
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
    done < <(getent passwd 2>/dev/null)

    printf '%s\n' "${suspicious[@]}"
}

# Pure-data variant of _group_all_members, for tests.
# $1: a getent-group line (`name:x:gid:m1,m2`); $2: getent-passwd content.
# Privileged access has four sources: sudo, wheel, user entries, %group.
_group_all_members_from_streams() {
    local group_line="$1"
    local passwd_text="$2"

    local name pwd gid secondary
    IFS=: read -r name pwd gid secondary <<<"$group_line"

    if [[ -n "$secondary" ]]; then
        echo "$secondary" | tr ',' '\n'
    fi
    if [[ -n "$gid" ]]; then
        awk -F: -v g="$gid" '$4 == g {print $1}' <<<"$passwd_text"
    fi
}

# All users in a group: the 4th-field secondary members PLUS everyone whose
# primary GID matches. Omitting the latter loses `useradd -g sudo bob`.
_group_all_members() {
    local group="$1"
    local group_line passwd
    group_line=$(getent group "$group" 2>/dev/null) || return 0
    passwd=$(getent passwd 2>/dev/null)
    _group_all_members_from_streams "$group_line" "$passwd"
}

_find_sudo_users() {
    local sudo_users=()

    # Check sudo and wheel groups (Debian/Ubuntu vs RHEL/CentOS).
    local g
    for g in sudo wheel; do
        local arr=()
        mapfile -t arr < <(_group_all_members "$g")
        sudo_users+=("${arr[@]}")
    done

    # Scan sudoers files for direct user rules AND %group rules.
    local sudoers_files=()
    [[ -r /etc/sudoers ]] && sudoers_files+=(/etc/sudoers)
    if [[ -d /etc/sudoers.d ]]; then
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" && -r "$f" ]] || continue
            _sudoers_dropin_ignored "$f" && continue
            sudoers_files+=("$f")
        done
    fi

    local f
    for f in "${sudoers_files[@]}"; do
        while IFS= read -r line; do
            # Skip comments, blank lines, and sudoers keyword directives
            # (we only want rule lines).
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ "$line" =~ ^[[:space:]]*$ ]] && continue
            [[ "$line" =~ ^[[:space:]]*(Defaults|Cmnd_Alias|Host_Alias|User_Alias|Runas_Alias) ]] && continue

            # Leading token of a rule line. The class MUST include `.` and
            # `\` for LDAP/AD names, or those admins go uncounted and the
            # "no non-root admin" gate clears wrongly.
            if [[ "$line" =~ ^[[:space:]]*(%?[a-zA-Z_][a-zA-Z0-9._\\-]*)[[:space:]]+[^=]+= ]]; then
                local token="${BASH_REMATCH[1]}"
                if [[ "$token" == %* ]]; then
                    local group_name="${token#%}"
                    local -a members_arr=()
                    mapfile -t members_arr < <(_group_all_members "$group_name")
                    sudo_users+=("${members_arr[@]}")
                else
                    sudo_users+=("$token")
                fi
            fi
        done < "$f"
    done

    # Deduplicate and drop empty entries.
    printf '%s\n' "${sudo_users[@]}" | grep -v '^$' | sort -u
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
            if [[ "$line" =~ NOPASSWD: ]]; then
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

            # Skip drop-ins sudo itself ignores (see _sudoers_dropin_ignored)
            _sudoers_dropin_ignored "$f" && continue

            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "$line" ]] && continue

                if [[ "$line" =~ NOPASSWD: ]]; then
                    local entry=$(echo "$line" | sed 's/[[:space:]]*#.*//')
                    findings+=("$f: $entry")
                fi
            done < "$f"
        done
    fi

    printf '%s\n' "${findings[@]}"
}

# Regex of cloud-init default usernames FOR THE DETECTED PROVIDER; the union
# when the provider is unknown. This is why an --include that reaches this
# module must also load cloud.sh.
_cloudinit_default_users_for_provider() {
    case "$(vpssec_cloud_provider)" in
        aws)
            echo "^(ec2-user|ubuntu|debian|admin|fedora|al2023-user|amzn-user|centos|rocky|almalinux|opensuse|root)$" ;;
        azure)
            echo "^(azureuser|ubuntu|debian|admin|root)$" ;;
        gcp)
            echo "^(ubuntu|debian|root)$" ;;
        alibaba)
            echo "^(root|ecs-user|aliyun)$" ;;
        tencent)
            echo "^(ubuntu|root|lighthouse)$" ;;
        huawei)
            echo "^(root|admin|ubuntu|debian)$" ;;
        oracle)
            echo "^(opc|oracle|ubuntu|root)$" ;;
        digitalocean|vultr|linode|hetzner|ovh|scaleway)
            # Mid-tier managed VPS: image defaults are usually root or
            # the distro's stock user (debian/ubuntu).
            echo "^(root|debian|ubuntu)$" ;;
        *)
            # Independent / unrecognized VPS — keep the union list so
            # NOPASSWD-classification behavior is unchanged from before
            # cloud-awareness was added.
            echo "^(debian|ubuntu|ec2-user|centos|rocky|almalinux|fedora|opensuse|admin|azureuser|cloud-user|cloud_user|clouduser|root|opc|arch|linaro|gardenlinux|core)$" ;;
    esac
}

# True only when every NOPASSWD line has exactly one principal, that
# principal is a cloud-init default user, and it is the SAME one throughout.
# Anything else — groups, aliases, wildcards, two default users — is high.
_nopasswd_is_cloudinit_only() {
    local findings="$1"
    local cloudinit_users
    cloudinit_users=$(_cloudinit_default_users_for_provider)
    local seen_user=""

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue

        # Strip "/path/to/sudoers: " prefix to get the raw rule.
        local rule="${entry#*: }"

        # Trim leading whitespace.
        rule="${rule#"${rule%%[![:space:]]*}"}"

        # First token is the principal. If it starts with `%`, it's
        # a group — we don't want to special-case groups even if the
        # group looks safe.
        local principal="${rule%%[[:space:]]*}"
        [[ -z "$principal" ]] && return 1
        [[ "$principal" == %* ]] && return 1

        # Comma in principal means multiple users on one line.
        [[ "$principal" == *,* ]] && return 1

        # Alias and Defaults lines are not grants themselves, but NOPASSWD
        # in one affects everyone that later references it.
        case "$principal" in
            Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias|Defaults*) return 1 ;;
        esac

        if ! [[ "$principal" =~ $cloudinit_users ]]; then
            return 1
        fi

        if [[ -z "$seen_user" ]]; then
            seen_user="$principal"
        elif [[ "$seen_user" != "$principal" ]]; then
            # Multiple cloud-init users with NOPASSWD in the same
            # sudoers tree is unusual; surface as high.
            return 1
        fi
    done <<< "$findings"

    [[ -n "$seen_user" ]]
}

# Emits "user|uid|date|home|evidence" for recently created accounts. POSIX
# records no creation time, so every signal is a proxy and the one that fired
# is reported. password-set is for homeless accounts only (design notes).
_find_recent_users() {
    local recent=()
    local cutoff_date
    cutoff_date=$(date -d "$RECENT_USER_DAYS days ago" +%s 2>/dev/null || date -v-"${RECENT_USER_DAYS}"d +%s 2>/dev/null)
    [[ "$cutoff_date" =~ ^[0-9]+$ ]] || return 0

    # One pass over shadow instead of a grep per account.
    local -A shadow_lstchg=()
    if [[ -r "$USERS_SHADOW_FILE" ]]; then
        local s_user s_lstchg
        while IFS=: read -r s_user _ s_lstchg _; do
            # 0 means "must change at next login", not a date.
            [[ "$s_lstchg" =~ ^[0-9]+$ ]] && (( s_lstchg > 0 )) && \
                shadow_lstchg["$s_user"]="$s_lstchg"
        done < "$USERS_SHADOW_FILE"
    fi

    while IFS=: read -r user pass uid gid gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        # Skip system users
        [[ "$uid" -lt 1000 ]] && continue
        # "UID >= 1000" alone is not enough once the shadow fallback exists:
        # `nobody` is 65534, has no home, and carries a shadow entry stamped
        # at image build, so it reads as a new account on every cloud image.
        (( uid >= 65534 )) && continue
        _is_system_account "$user" && continue

        local epoch="" evidence=""
        if [[ -d "$home" ]]; then
            local btime
            btime=$(stat -c %W "$home" 2>/dev/null) || btime=""
            if [[ "$btime" =~ ^[0-9]+$ ]] && (( btime > 0 )); then
                epoch="$btime"
                evidence="home-created"
            else
                local mtime
                mtime=$(stat -c %Y "$home" 2>/dev/null || stat -f %m "$home" 2>/dev/null) || mtime=""
                if [[ "$mtime" =~ ^[0-9]+$ ]]; then
                    epoch="$mtime"
                    evidence="home-modified"
                fi
            fi
        elif [[ -n "${shadow_lstchg[$user]:-}" ]]; then
            epoch=$(( shadow_lstchg[$user] * 86400 ))
            evidence="password-set"
        fi

        [[ -n "$epoch" ]] || continue
        (( epoch > cutoff_date )) || continue

        local created
        created=$(date -d "@$epoch" "+%Y-%m-%d" 2>/dev/null || date -r "$epoch" "+%Y-%m-%d" 2>/dev/null)
        recent+=("$user|$uid|$created|$home|$evidence")
    done < <(getent passwd 2>/dev/null)

    printf '%s\n' "${recent[@]}"
}

# Analyze SSH authorized_keys
_analyze_ssh_keys() {
    local findings=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        # Skip system users without login shells
        [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
        ! _has_login_shell "$shell" && continue

        local authkeys="$home/.ssh/authorized_keys"
        [[ -f "$authkeys" ]] || continue

        # Counted via the shared helper, which recognises ECDSA and FIDO keys
        # and options-prefixed lines that a `^ssh-` match would miss.
        local key_count
        key_count=$(count_authorized_keys "$authkeys")
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
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ "$line" =~ (^|[[:space:]])(ssh-|ecdsa-|sk-) ]] || continue
            local comment=$(echo "$line" | awk '{print $NF}')
            # Check for suspicious patterns in comments
            if [[ "$comment" =~ (test|temp|backup|admin@|root@unknown) ]]; then
                ((suspicious_keys++)) || true
            fi
        done < "$authkeys"

        findings+=("$user|$key_count|$key_perms|$perms_ok|$suspicious_keys|$authkeys")
    done < <(getent passwd 2>/dev/null)

    printf '%s\n' "${findings[@]}"
}

# Find users with suspicious usernames
_find_suspicious_users() {
    local suspicious=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        # Only check regular users
        [[ "$uid" -lt 1000 ]] && continue

        if _is_suspicious_username "$user"; then
            local has_shell="no"
            _has_login_shell "$shell" && has_shell="yes"
            suspicious+=("$user|$uid|$shell|$has_shell")
        fi
    done < <(getent passwd 2>/dev/null)

    printf '%s\n' "${suspicious[@]}"
}

# Find users with home directories in unusual locations
_find_unusual_home() {
    local unusual=()

    while IFS=: read -r user pass uid gid gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
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
    done < <(getent passwd 2>/dev/null)

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
    elif [[ "$pass_max" == "99999" ]] || { [[ "$pass_max" =~ ^[0-9]+$ ]] && (( pass_max > 365 )); }; then
        # Guard the arithmetic: a non-numeric admin-edited value (e.g.
        # "PASS_MAX_DAYS unlimited") in `[[ x -gt N ]]` is treated as a
        # variable name and, if unbound, aborts the WHOLE audit under set -u.
        issues+=("PASS_MAX_DAYS=$pass_max (no expiry or too long)")
    fi

    # Check PASS_MIN_DAYS
    local pass_min=$(grep -E "^PASS_MIN_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -z "$pass_min" || "$pass_min" == "0" ]]; then
        issues+=("PASS_MIN_DAYS=$pass_min (allows immediate changes)")
    fi

    # Check PASS_MIN_LEN (may be deprecated in favor of pam)
    local pass_len=$(grep -E "^PASS_MIN_LEN" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ "$pass_len" =~ ^[0-9]+$ ]] && (( pass_len < 8 )); then
        issues+=("PASS_MIN_LEN=$pass_len (too short)")
    fi

    # Check PASS_WARN_AGE (guard the arithmetic against non-numeric values)
    local pass_warn=$(grep -E "^PASS_WARN_AGE" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -z "$pass_warn" ]] || { [[ "$pass_warn" =~ ^[0-9]+$ ]] && (( pass_warn < 7 )); }; then
        issues+=("PASS_WARN_AGE=$pass_warn (should be at least 7)")
    fi

    printf '%s\n' "${issues[@]}"
}

# Effective value of a pwquality directive across the supplied files, with
# libpwquality's ASCII-order last-write-wins semantics. Pure-data variant;
# the production wrapper enumerates the real paths.
_pwquality_get_directive_from_files() {
    local key="$1"
    shift
    [[ $# -eq 0 ]] && return 0

    awk -v k="$key" '
        { sub(/[[:space:]]*#.*$/, "") }
        $0 ~ ("^[[:space:]]*" k "[[:space:]]*=") {
            split($0, a, "=")
            v = a[2]
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
            val = v
        }
        END { if (val != "") print val }
    ' "$@"
}

_pwquality_get_directive() {
    local key="$1"
    local -a files=()
    [[ -f /etc/security/pwquality.conf ]] && files+=(/etc/security/pwquality.conf)
    if [[ -d /etc/security/pwquality.conf.d ]]; then
        local f
        for f in /etc/security/pwquality.conf.d/*.conf; do
            [[ -f "$f" ]] && files+=("$f")
        done
    fi
    [[ ${#files[@]} -eq 0 ]] && return 0
    _pwquality_get_directive_from_files "$key" "${files[@]}"
}

# Check password quality settings (pwquality.conf or pam_pwquality)
_check_pwquality() {
    local issues=()

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

    # Reads pwquality.conf plus pwquality.conf.d/*.conf, last-write-wins, so
    # drop-in policies are honoured.
    if [[ -f /etc/security/pwquality.conf || -d /etc/security/pwquality.conf.d ]]; then
        # Every comparison guards with a numeric regex first: a non-numeric
        # value would be read as a variable name and abort under set -u.
        # dcredit/ucredit are legitimately negative, so they allow a '-'.
        local minlen
        minlen=$(_pwquality_get_directive minlen)
        if [[ -z "$minlen" ]] || { [[ "$minlen" =~ ^[0-9]+$ ]] && (( minlen < 8 )); }; then
            issues+=("minlen=$minlen (should be at least 12)")
        fi

        local dcredit ucredit
        dcredit=$(_pwquality_get_directive dcredit)
        ucredit=$(_pwquality_get_directive ucredit)

        # Negative values mean required, 0 or positive means not enforced
        if [[ -z "$dcredit" ]] || { [[ "$dcredit" =~ ^-?[0-9]+$ ]] && (( dcredit >= 0 )); }; then
            issues+=("dcredit not enforcing digit requirement")
        fi
        if [[ -z "$ucredit" ]] || { [[ "$ucredit" =~ ^-?[0-9]+$ ]] && (( ucredit >= 0 )); }; then
            issues+=("ucredit not enforcing uppercase requirement")
        fi
    fi

    printf '%s\n' "${issues[@]}"
}

# Check bash history security settings
_check_history_security() {
    local issues=()

    # Check global profile for HISTSIZE and HISTFILESIZE
    local histsize=""
    local histfilesize=""

    # Check /etc/profile and /etc/bash.bashrc
    for config in /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh; do
        [[ -f "$config" ]] || continue
        if [[ -z "$histsize" ]]; then
            histsize=$(grep -h "^HISTSIZE=" "$config" 2>/dev/null | tail -1 | cut -d= -f2)
        fi
        if [[ -z "$histfilesize" ]]; then
            histfilesize=$(grep -h "^HISTFILESIZE=" "$config" 2>/dev/null | tail -1 | cut -d= -f2)
        fi
    done

    # Check for HISTCONTROL (should include ignorespace or ignoreboth)
    local histcontrol=""
    for config in /etc/profile /etc/bash.bashrc; do
        [[ -f "$config" ]] || continue
        histcontrol=$(grep -h "^HISTCONTROL=" "$config" 2>/dev/null | tail -1 | cut -d= -f2)
        [[ -n "$histcontrol" ]] && break
    done

    # Check for timestamp in history
    local histtimeformat=""
    for config in /etc/profile /etc/bash.bashrc; do
        [[ -f "$config" ]] || continue
        histtimeformat=$(grep -h "^HISTTIMEFORMAT=" "$config" 2>/dev/null | tail -1)
        [[ -n "$histtimeformat" ]] && break
    done

    # Report issues
    if [[ -z "$histtimeformat" ]]; then
        issues+=("HISTTIMEFORMAT not set (no timestamps in history)")
    fi

    if [[ -z "$histcontrol" ]] || [[ ! "$histcontrol" =~ ignore ]]; then
        issues+=("HISTCONTROL not set to ignore duplicates/spaces")
    fi

    printf '%s\n' "${issues[@]}"
}

# Non-root accounts sharing a UID: either accidental aliasing or a
# deliberate backdoor. Output: "UID:user1,user2".
_find_duplicate_uids() {
    # Read via getent, not /etc/passwd directly, so a duplicate UID injected
    # through an NSS backend (LDAP/SSSD) — the same backdoor vector
    # _find_uid0_users deliberately uses getent for — is visible too.
    getent passwd 2>/dev/null | awk -F: '$3 != "" {
        if (uids[$3]) uids[$3] = uids[$3] "," $1
        else          uids[$3] = $1
        count[$3]++
    }
    END {
        for (u in count) if (count[u] > 1) print u ":" uids[u]
    }'
}

# Weak password hash methods, from two sources: the live hashes in
# /etc/shadow, and the configured method for NEW passwords (pam_unix,
# falling back to ENCRYPT_METHOD in login.defs).
_check_hash_method() {
    local issues=()

    if [[ -r "$USERS_SHADOW_FILE" ]]; then
        local weak="" user hash _rest
        while IFS=: read -r user hash _rest; do
            case "$hash" in
                '$y$'*|'$6$'*|'$2'*|'$5$'*) ;;   # yescrypt / sha512 / bcrypt / sha256: OK
                '$1$'*) weak+="${user}(md5) " ;;
                '!'*|'*'|'') ;;                   # locked / unset
                *)
                    # Bare 13-char crypt = traditional DES. Anything
                    # else that doesn't start with $ is treated as
                    # non-hash (NIS hint, blank, etc.) and skipped.
                    if [[ "$hash" =~ ^[A-Za-z0-9./]{13}$ ]]; then
                        weak+="${user}(des) "
                    fi
                    ;;
            esac
        done < "$USERS_SHADOW_FILE"
        [[ -n "$weak" ]] && issues+=("Weak hashes in /etc/shadow: ${weak% }")
    fi

    local pam_method="" f
    for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -f "$f" ]] || continue
        pam_method=$(grep -E '^password[[:space:]]+(\[[^]]*\]|\S+)[[:space:]]+pam_unix\.so' "$f" 2>/dev/null \
            | grep -oiE '\b(yescrypt|sha512|sha256|md5|blowfish|bigcrypt|des)\b' \
            | head -1 | tr '[:upper:]' '[:lower:]')
        [[ -n "$pam_method" ]] && break
    done

    case "$pam_method" in
        yescrypt|sha512) ;;
        sha256) issues+=("pam_unix configured for sha256 (sha512/yescrypt preferred)") ;;
        md5|blowfish|bigcrypt|des) issues+=("pam_unix configured for $pam_method (weak)") ;;
        "")
            local enc
            enc=$(grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print tolower($2)}')
            case "$enc" in
                yescrypt|sha512|"") ;;
                sha256) issues+=("ENCRYPT_METHOD=sha256 in login.defs (sha512 preferred)") ;;
                md5|blowfish|bigcrypt|des) issues+=("ENCRYPT_METHOD=$enc in login.defs (weak)") ;;
            esac
            ;;
    esac

    printf '%s\n' "${issues[@]}"
}

# Hash rounds. ONLY relevant for SHA-256/SHA-512: yescrypt, bcrypt, md5 and
# des never consult SHA_CRYPT_*_ROUNDS, so flagging them fires on every
# stock Debian 12+ host. glibc defaults to the 5000 minimum when unset.
_check_hash_rounds() {
    local pam_method="" f
    for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -f "$f" ]] || continue
        pam_method=$(grep -E '^password[[:space:]]+(\[[^]]*\]|\S+)[[:space:]]+pam_unix\.so' "$f" 2>/dev/null \
            | grep -oiE '\b(yescrypt|sha512|sha256|md5|blowfish|bigcrypt|des)\b' \
            | head -1 | tr '[:upper:]' '[:lower:]')
        [[ -n "$pam_method" ]] && break
    done
    # Fall back to login.defs ENCRYPT_METHOD when PAM doesn't name a method
    if [[ -z "$pam_method" ]]; then
        pam_method=$(grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null \
            | awk '{print tolower($2)}')
    fi

    case "$pam_method" in
        sha512|sha256) ;;   # rounds parameter is relevant
        *) return 0 ;;       # yescrypt/bcrypt/md5/des/unset — skip
    esac

    local rmin
    rmin=$(grep -E '^SHA_CRYPT_MIN_ROUNDS' /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ -z "$rmin" ]]; then
        echo "SHA_CRYPT_MIN_ROUNDS not set (glibc default 5000; >= 10000 recommended for SHA-512)"
    elif [[ "$rmin" =~ ^[0-9]+$ ]] && (( rmin < 10000 )); then
        # Numeric guard before (( )): a non-numeric value in login.defs would
        # otherwise be treated as an arithmetic variable name and abort the
        # users audit under `set -u` (skipping the later sudoers-syntax check).
        echo "SHA_CRYPT_MIN_ROUNDS=$rmin (>= 10000 recommended)"
    fi
}

# Failed-login logging in login.defs. Both FAILLOG_ENAB and LOG_UNKFAIL_ENAB
# should be yes; the latter surfaces brute-force against fake usernames.
_check_faillog_logging() {
    local issues=() enab unk
    enab=$(grep -E '^FAILLOG_ENAB'     /etc/login.defs 2>/dev/null | awk '{print $2}')
    unk=$(grep -E  '^LOG_UNKFAIL_ENAB' /etc/login.defs 2>/dev/null | awk '{print $2}')
    [[ -n "$enab" && "$enab" != "yes" ]] && issues+=("FAILLOG_ENAB=$enab (should be yes)")
    [[ -n "$unk"  && "$unk"  != "yes" ]] && issues+=("LOG_UNKFAIL_ENAB=$unk (should be yes)")
    printf '%s\n' "${issues[@]}"
}

# sudoers integrity via visudo -c. A syntax error either locks operators out
# entirely or, in parser corner cases, widens privileges.
_check_sudoers_syntax() {
    command -v visudo >/dev/null 2>&1 || return 0
    local issues=() drop

    if ! visudo -c -f /etc/sudoers >/dev/null 2>&1; then
        issues+=("/etc/sudoers syntax invalid")
    fi
    for drop in /etc/sudoers.d/*; do
        [[ -f "$drop" ]] || continue
        _sudoers_dropin_ignored "$drop" && continue
        if ! visudo -c -f "$drop" >/dev/null 2>&1; then
            issues+=("$drop syntax invalid")
        fi
    done
    printf '%s\n' "${issues[@]}"
}

# --- Audit Functions ---

users_audit() {
    log_info "Running user security audit"

    # 1. Check for UID 0 users (besides root) - CRITICAL
    local uid0_users=$(_find_uid0_users)
    local uid0_count=$(count_lines "$uid0_users")

    if [[ -n "$uid0_users" && "$uid0_count" -gt 0 ]]; then
        check_emit "users.uid0_found" high failed \
            title="$(i18n 'users.uid0_found'): $uid0_count" \
            desc="$(echo "$uid0_users" | tr '\n' ', ' | sed 's/,$//')" \
            suggestion="$(i18n 'users.uid0_review')"
    else
        check_emit "users.uid0_ok" info passed \
            desc="$(i18n 'users.uid0_ok_desc')"
    fi

    # 2. Check for empty password users - CRITICAL
    local empty_pass=$(_find_empty_password_users)
    local empty_count=$(count_lines "$empty_pass")

    if [[ -n "$empty_pass" && "$empty_count" -gt 0 ]]; then
        check_emit "users.empty_password" high failed \
            title="$(i18n 'users.empty_password'): $empty_count" \
            desc="$(echo "$empty_pass" | tr '\n' ', ' | sed 's/,$//')" \
            suggestion="$(i18n 'users.set_password')"
    else
        check_emit "users.no_empty_password" info passed \
            desc="$(i18n 'users.no_empty_password_desc')"
    fi

    # 3. Check system users with shells - MEDIUM
    local sys_shells=$(_find_system_users_with_shells)
    local sys_shell_count=$(count_lines "$sys_shells" '|')

    if [[ -n "$sys_shells" && "$sys_shell_count" -gt 0 ]]; then
        local user_list=""
        while IFS='|' read -r user uid shell; do
            [[ -z "$user" ]] && continue
            user_list+="$user ($shell), "
        done <<< "$sys_shells"
        user_list="${user_list%, }"

        check_emit "users.system_with_shell" low failed \
            title="$(i18n 'users.system_with_shell'): $sys_shell_count" \
            desc="$user_list" \
            suggestion="$(i18n 'users.change_shell')"
    fi

    # sudo_count includes root, so it is never zero. The title must carry the
    # NON-ROOT count: "Privileged Users: 1" reads as "safe to disable root
    # login" when that 1 is root itself.
    local sudo_users=$(_find_sudo_users)
    local sudo_count=$(count_lines "$sudo_users")
    local non_root_count=$(echo "$sudo_users" | grep -vx 'root' | grep -c .)

    if [[ -n "$sudo_users" && "$sudo_count" -gt 0 ]]; then
        local label="$(i18n 'users.sudo_users')"
        local title
        # The qualifier used to be an English literal appended to a
        # translated label, producing "✓ 特权用户: 1 (root only — no
        # non-root admin)" in Chinese output.
        if [[ "$non_root_count" -eq 0 ]]; then
            title="${label}: ${sudo_count} ($(i18n 'users.sudo_root_only'))"
        else
            title="${label}: ${sudo_count} ($(i18n 'users.sudo_non_root' "count=${non_root_count}"))"
        fi
        check_emit "users.sudo_users" info passed \
            title="$title" \
            desc="$(echo "$sudo_users" | tr '\n' ', ' | sed 's/,$//')" \
            suggestion="$(i18n 'users.review_sudo')"
    fi

    # Cloud images ship NOPASSWD for their cloud-init user, so calling every
    # fresh VM high risk destroys the signal. Entries scoped to a single
    # cloud-init default user are medium; everything else is high.
    local nopasswd=$(_find_nopasswd_sudo)
    local nopasswd_count=$(count_lines "$nopasswd")

    if [[ -n "$nopasswd" && "$nopasswd_count" -gt 0 ]]; then
        local nopasswd_list=""
        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            nopasswd_list+="$entry; "
        done <<< "$nopasswd"
        nopasswd_list="${nopasswd_list%; }"

        local sev="medium"
        local title_key="users.nopasswd_sudo"
        if _nopasswd_is_cloudinit_only "$nopasswd"; then
            sev="low"
            title_key="users.nopasswd_sudo_cloudinit"
        fi

        check_emit "users.nopasswd_sudo" "$sev" failed \
            title="$(i18n "$title_key"): $nopasswd_count" \
            desc="$nopasswd_list" \
            suggestion="$(i18n 'users.review_nopasswd')"
    fi

    # 5. Check recently created users - INFO/LOW
    local recent=$(_find_recent_users)
    local recent_count=$(count_lines "$recent" '|')

    if [[ -n "$recent" && "$recent_count" -gt 0 ]]; then
        local recent_list=""
        while IFS='|' read -r user uid created home evidence; do
            [[ -z "$user" ]] && continue
            # Carry the evidence token: "home-modified" on a busy box is far
            # weaker than "home-created", and an operator triaging the list
            # needs to know which one fired.
            recent_list+="$user ($created, $evidence), "
        done <<< "$recent"
        recent_list="${recent_list%, }"

        check_emit "users.recent_users" low failed \
            title="$(i18n 'users.recent_users'): $recent_count" \
            desc="$recent_list" \
            suggestion="$(i18n 'users.verify_recent')"
    fi

    # 6. Analyze SSH authorized_keys - MEDIUM
    local ssh_keys=$(_analyze_ssh_keys)
    local bad_perms=0
    local suspicious_keys=0
    local users_with_keys=0

    while IFS='|' read -r user key_count perms perms_ok sus_count path; do
        [[ -z "$user" ]] && continue
        ((users_with_keys++)) || true
        [[ "$perms_ok" == "no" ]] && { ((bad_perms++)) || true; }
        ((suspicious_keys += sus_count)) || true
    done <<< "$ssh_keys"

    if [[ "$bad_perms" -gt 0 ]]; then
        check_emit "users.ssh_keys_perms" medium failed \
            title="$(i18n 'users.ssh_keys_perms'): $bad_perms" \
            desc="$(i18n 'users.ssh_keys_perms_desc')" \
            suggestion="$(i18n 'users.fix_key_perms')"
    fi

    if [[ "$users_with_keys" -gt 0 ]]; then
        check_emit "users.ssh_keys_info" info passed \
            title="$(i18n 'users.ssh_keys_info'): $users_with_keys" \
            desc="$(i18n 'users.ssh_keys_info_desc')"
    fi

    # 7. Check for suspicious usernames - LOW (strict only)
    local suspicious=$(_find_suspicious_users)
    local sus_count=$(count_lines "$suspicious" '|')

    if [[ -n "$suspicious" && "$sus_count" -gt 0 ]]; then
        local sus_list=""
        while IFS='|' read -r user uid shell has_shell; do
            [[ -z "$user" ]] && continue
            sus_list+="$user, "
        done <<< "$suspicious"
        sus_list="${sus_list%, }"

        check_emit "users.suspicious_names" low failed \
            title="$(i18n 'users.suspicious_names'): $sus_count" \
            desc="$sus_list" \
            suggestion="$(i18n 'users.review_names')"
    fi

    # 8. Check for unusual home directories - LOW (strict only)
    local unusual=$(_find_unusual_home)
    local unusual_count=$(count_lines "$unusual" '|')

    if [[ -n "$unusual" && "$unusual_count" -gt 0 ]]; then
        local unusual_list=""
        while IFS='|' read -r user uid home; do
            [[ -z "$user" ]] && continue
            unusual_list+="$user:$home, "
        done <<< "$unusual"
        unusual_list="${unusual_list%, }"

        check_emit "users.unusual_home" low failed \
            title="$(i18n 'users.unusual_home'): $unusual_count" \
            desc="$unusual_list" \
            suggestion="$(i18n 'users.review_home')"
    fi

    # 9. Check password policy in login.defs - MEDIUM
    local policy_issues=$(_check_password_policy)
    local policy_count=$(count_lines "$policy_issues")

    if [[ -n "$policy_issues" && "$policy_count" -gt 0 ]]; then
        local policy_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            policy_list+="$issue; "
        done <<< "$policy_issues"
        policy_list="${policy_list%; }"

        check_emit "users.password_policy_weak" low failed \
            title="$(i18n 'users.password_policy_weak'): $policy_count issues" \
            desc="$policy_list" \
            suggestion="$(i18n 'users.fix_password_policy')"
    else
        check_emit "users.password_policy_ok" info passed \
            desc="$(i18n 'users.password_policy_ok_desc')"
    fi

    # 10. Check password quality settings - LOW
    local pwquality_issues=$(_check_pwquality)
    local pwquality_count=$(count_lines "$pwquality_issues")

    if [[ -n "$pwquality_issues" && "$pwquality_count" -gt 0 ]]; then
        local pwq_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            pwq_list+="$issue; "
        done <<< "$pwquality_issues"
        pwq_list="${pwq_list%; }"

        check_emit "users.pwquality_weak" low failed \
            title="$(i18n 'users.pwquality_weak'): $pwquality_count issues" \
            desc="$pwq_list" \
            suggestion="$(i18n 'users.fix_pwquality')"
    fi

    # 11. Check bash history security - LOW
    local history_issues=$(_check_history_security)
    local history_count=$(count_lines "$history_issues")

    if [[ -n "$history_issues" && "$history_count" -gt 0 ]]; then
        local hist_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            hist_list+="$issue; "
        done <<< "$history_issues"
        hist_list="${hist_list%; }"

        check_emit "users.history_insecure" low failed \
            title="$(i18n 'users.history_insecure'): $history_count issues" \
            desc="$hist_list" \
            suggestion="$(i18n 'users.fix_history')"
    fi

    # Medium, not high: a duplicate UID 0 — the actual backdoor pattern — is
    # reported separately and at high by users.uid0_found. A collision among
    # regular UIDs is ambiguous file ownership.
    local dup_uids
    dup_uids=$(_find_duplicate_uids)
    if [[ -n "$dup_uids" ]]; then
        local dup_list=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            dup_list+="UID=$line; "
        done <<< "$dup_uids"
        dup_list="${dup_list%; }"
        check_emit "users.duplicate_uids" medium failed \
            desc="$dup_list" \
            suggestion="$(i18n 'users.review_duplicate_uids')"
    fi

    # 13. Weak password hash method (Lynis AUTH-9229) - MEDIUM
    local hash_issues
    hash_issues=$(_check_hash_method)
    if [[ -n "$hash_issues" ]]; then
        local hash_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            hash_list+="$issue; "
        done <<< "$hash_issues"
        hash_list="${hash_list%; }"
        check_emit "users.weak_hash_method" low failed \
            desc="$hash_list" \
            suggestion="$(i18n 'users.fix_hash_method')"
    fi

    # 14. SHA crypt rounds (Lynis AUTH-9230) - LOW / defense in depth
    local rounds_issue
    rounds_issue=$(_check_hash_rounds)
    if [[ -n "$rounds_issue" ]]; then
        check_emit "users.hash_rounds_low" low failed \
            desc="$rounds_issue" \
            suggestion="$(i18n 'users.fix_hash_rounds')"
    fi

    # 15. Failed-login logging (Lynis AUTH-9408) - LOW
    local faillog_issues
    faillog_issues=$(_check_faillog_logging)
    if [[ -n "$faillog_issues" ]]; then
        local fl_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            fl_list+="$issue; "
        done <<< "$faillog_issues"
        fl_list="${fl_list%; }"
        check_emit "users.faillog_disabled" low failed \
            desc="$fl_list" \
            suggestion="$(i18n 'users.fix_faillog')"
    fi

    # Medium: sudo logs and skips a malformed drop-in rather than failing
    # open, so this is configuration integrity, not an exploitable hole.
    local sudoers_issues
    sudoers_issues=$(_check_sudoers_syntax)
    if [[ -n "$sudoers_issues" ]]; then
        local su_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            su_list+="$issue; "
        done <<< "$sudoers_issues"
        su_list="${su_list%; }"
        check_emit "users.sudoers_syntax_invalid" medium failed \
            desc="$su_list" \
            suggestion="$(i18n 'users.fix_sudoers_syntax')"
    fi

    return 0
}

# --- Fix Function ---

# vpssec never creates, deletes or edits an account: nothing here is
# auto-fixable. The entry point stays because the engine dispatches
# <module>_fix by name, and a missing one reads as a fix that did nothing.
users_fix() {
    log_warn "users has no automatic fix; every finding needs human review: ${1:-}"
    return 1
}
