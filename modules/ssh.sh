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
SSH_RESCUE_SSHD="/usr/sbin/sshd"  # absolute: sshd re-executes itself by its own path
SSH_RESCUE_PID=""        # pid of the rescue sshd we launched (the only kill target)
SSH_RESCUE_CONFIG=""     # temp rescue config path
SSH_RESCUE_PIDFILE=""    # temp rescue pidfile path
SSH_RESCUE_FW_RULE=""    # firewall rule added for the rescue port, for exact teardown
SSH_RESCUE_WATCHDOG_PID="" # pid of the watchdog that bounds the rescue's lifetime
# Seconds the rescue may outlive the confirmation window (applying, reloading
# and verifying the change) before the watchdog tears it down regardless.
SSH_RESCUE_GRACE=120

# --- SSH Helper Functions ---

# The effective value of $1 for user $3 (default: an ordinary user), or $2 when
# sshd prints none (it omits unset list keywords such as AllowUsers). When sshd
# cannot report its configuration, prints $2 and returns 1: no file is read instead.
_ssh_get_config() {
    local key="${1,,}" default="$2" dump value
    if ! dump=$(sshd_effective_config "${3:-}"); then
        printf '%s\n' "$default"
        return 1
    fi
    value=$(awk -v k="$key" '$1 == k { sub(/^[^ ]+ /, ""); print; exit }' <<<"$dump")
    printf '%s\n' "${value:-$default}"
}

# Check if password auth is enabled: PasswordAuthentication, or a password
# typed into keyboard-interactive (see the next function).
_ssh_password_auth_enabled() {
    local value=$(_ssh_get_config "PasswordAuthentication" "yes")
    [[ "${value,,}" == "yes" ]] || _ssh_kbdint_password_path
}

# keyboard-interactive through PAM asks pam_unix for the password whatever
# PasswordAuthentication says. It stays a password login unless every
# AuthenticationMethods list also needs something besides a password.
_ssh_kbdint_password_path() {
    local value list m only
    local -a ms=()
    value=$(_ssh_get_config "KbdInteractiveAuthentication" "yes")
    [[ "${value,,}" == "yes" ]] || return 1
    value=$(_ssh_get_config "UsePAM" "no")
    [[ "${value,,}" == "yes" ]] || return 1
    value=$(_ssh_get_config "AuthenticationMethods" "any")
    [[ "${value,,}" == "any" ]] && return 0
    for list in $value; do
        IFS=, read -ra ms <<<"$list"
        only=1
        for m in "${ms[@]}"; do
            [[ "${m%%:*}" == keyboard-interactive || "$m" == password ]] || only=0
        done
        [[ "$only" == 1 && ",$list" == *",keyboard-interactive"* ]] && return 0
    done
    return 1
}

# Check if root login is enabled
_ssh_root_login_enabled() {
    local value=$(_ssh_get_config "PermitRootLogin" "prohibit-password")
    [[ "${value,,}" == "yes" ]]
}

# Is pubkey auth on, for user $1 (default: an ordinary user)?
_ssh_pubkey_enabled() {
    local value=$(_ssh_get_config "PubkeyAuthentication" "yes" "${1:-}")
    [[ "${value,,}" == "yes" ]]
}

# Check if empty passwords are allowed
_ssh_empty_password_allowed() {
    local value=$(_ssh_get_config "PermitEmptyPasswords" "no")
    [[ "${value,,}" == "yes" ]]
}

_ssh_empty_password_denied() {
    ! _ssh_empty_password_allowed
}

_ssh_password_auth_disabled() {
    ! _ssh_password_auth_enabled
}

_ssh_root_login_disabled() {
    ! _ssh_root_login_enabled
}

# Pass conditions of the MaxAuthTries (<= 4) and LoginGraceTime (1..60 s; 0 is
# unlimited) checks. $1 is the value already read; omitted, sshd is asked.
_ssh_max_auth_tries_ok() {
    local v="${1-$(_ssh_get_config "MaxAuthTries" "6")}"
    [[ "$v" =~ ^[0-9]+$ ]] && (( v <= 4 ))
}

_ssh_login_grace_time_ok() {
    local v="${1-$(_ssh_get_config "LoginGraceTime" "120")}"
    local seconds="$v"
    if [[ "$v" =~ ^[0-9]+m$ ]]; then
        seconds=$((${v%m} * 60))
    elif [[ "$v" =~ ^[0-9]+h$ ]]; then
        seconds=$((${v%h} * 3600))
    elif [[ "$v" =~ ^[0-9]+s$ ]]; then
        seconds="${v%s}"
    fi
    # The regex guard also stops a non-numeric value aborting under set -u.
    [[ "$seconds" =~ ^[0-9]+$ ]] && (( seconds >= 1 && seconds <= 60 ))
}

# Non-root accounts that can become root through sudo (core's one answer).
_ssh_get_admin_users() {
    sudo_admin_users | grep -vx 'root'
    return 0
}

# Does this user have a usable key in the file(s) sshd will actually read? A
# commented-out key, or one in a file StrictModes refuses, reads as no key:
# counting either toward the password-off gate is a lockout.
_ssh_user_has_key() {
    local user="$1" strict total=0 path n
    strict=$(_ssh_get_config "StrictModes" "yes")
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        if [[ "${strict,,}" != no ]] && strictmodes_refused_path "$user" "$path" >/dev/null; then
            continue
        fi
        n=$(count_authorized_keys "$path") || continue
        total=$(( total + n ))
    done < <(sshd_authorized_keys_files "$user")
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

# Can $user log in by key under the CURRENT config, its Match User blocks applied?
# Needs PubkeyAuthentication on; for root also a PermitRootLogin that permits keys —
# under "no" root's key is useless and must NOT count toward the gate.
_ssh_can_login_with_key() {
    local user="$1"
    _ssh_pubkey_enabled "$user" || return 1
    if [[ "$user" == "root" ]]; then
        local prl
        prl=$(_ssh_get_config "PermitRootLogin" "prohibit-password" "$user")
        [[ "${prl,,}" == "no" ]] && return 1
    fi
    _ssh_user_has_key "$user"
}

# True when $1 has a password hash login and sudo will accept. Empty, `*` and
# `!`-prefixed (locked) hashes do not; an unreadable shadow counts as none,
# so the gates fail closed.
_ssh_password_usable() {
    local hash
    hash=$(getent shadow "$1" 2>/dev/null | cut -d: -f2)
    [[ -n "$hash" && "$hash" != [\!\*]* ]]
}

# Can admin $1 still log in and become root once the change lands, with
# password authentication then $2 (yes|no)? Needs a login-capable account, an
# auth method sshd still offers, and a usable password or NOPASSWD for sudo.
_ssh_admin_survives() {
    local user="$1" pw_after="$2" pw_ok=0
    _ssh_account_can_login "$user" || return 1
    _ssh_password_usable "$user" && pw_ok=1
    if ! [[ "$pw_after" == yes && "$pw_ok" == 1 ]]; then
        _ssh_can_login_with_key "$user" || return 1
    fi
    [[ "$pw_ok" == 1 ]] || sudo_nopasswd_admin "$user"
}

# First admin from _ssh_get_admin_users that survives the change ($1 as in
# _ssh_admin_survives); fails when none does.
_ssh_surviving_admin() {
    local user
    for user in $(_ssh_get_admin_users); do
        if _ssh_admin_survives "$user" "$1"; then
            echo "$user"
            return 0
        fi
    done
    return 1
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

# One line per key file of the admins $@ whose path StrictModes would refuse,
# over every effective AuthorizedKeysFile. Judged whatever StrictModes says: a
# path others can write lets them add a key.
_ssh_check_authkeys_permissions() {
    local user path bad mode owner
    for user in "$@"; do
        while IFS= read -r path; do
            [[ -f "$path" ]] || continue
            bad=$(strictmodes_refused_path "$user" "$path") || continue
            IFS=$'\t' read -r bad mode owner <<<"$bad"
            i18n 'ssh.authkeys_refused' "path=$bad" "mode=$mode" "owner=$owner" "file=$path"
        done < <(sshd_authorized_keys_files "$user")
    done | awk '!seen[$0]++'
}

# --- SSH Audit ---

ssh_audit() {
    local module="ssh"

    # Without sshd every verdict below would grade a daemon that does not exist.
    if ! check_command sshd; then
        check_emit "ssh.not_installed" low passed \
            desc="$(i18n 'ssh.not_installed_desc')"
        print_ok "$(i18n 'ssh.not_installed') - $(i18n 'common.skipping')"
        return 0
    fi
    # sshd that cannot print its effective config leaves every verdict unjudged:
    # one finding, and the audit is marked incomplete rather than graded on defaults.
    if ! _ssh_get_config "Port" "22" >/dev/null; then
        local why
        why=$(sshd -T 2>&1 >/dev/null) || true
        why="${why%%$'\n'*}"   # sshd ends its stderr lines with \r\n
        check_emit "ssh.config_unreadable" info failed \
            desc="$(i18n 'ssh.config_unreadable_desc' "error=${why%$'\r'}")" \
            suggestion="$(i18n 'ssh.config_unreadable_fix')"
        print_warn "$(i18n 'ssh.config_unreadable')"
        _module_record_failure ssh query
        return 0
    fi

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

    _ssh_audit_directives
    _ssh_audit_match_overrides

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
    # No fix for the keyboard-interactive path: turning it off can break a
    # second factor, so that choice stays with the operator.
    if _ssh_kbdint_password_path; then
        check_emit "ssh.password_auth_enabled" high failed \
            desc="$(i18n 'ssh.password_auth_kbdint_desc')" \
            suggestion="$(i18n 'ssh.fix_kbdint_password')"
        print_severity "high" "$(i18n 'ssh.password_auth_enabled')"
    elif _ssh_password_auth_enabled; then
        check_emit "ssh.password_auth_enabled" high failed \
            desc="$(i18n 'ssh.password_auth_enabled_desc')" \
            suggestion="$(i18n 'ssh.fix_disable_password')" \
            fix="ssh.disable_password_auth"
        print_severity "high" "$(i18n 'ssh.password_auth_enabled')"
    else
        check_emit "ssh.password_auth_disabled" low passed
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
        local info="PermitRootLogin=yes $(i18n 'ssh.root_login_any_desc')"
        if ! _ssh_password_auth_enabled; then
            sev="medium"
            title_key="ssh.root_login_keyonly"
            info="PermitRootLogin=yes; $(i18n 'ssh.root_login_keyonly_desc')"
        fi
        check_emit "ssh.root_login_enabled" "$sev" failed \
            title="$(i18n "$title_key")" \
            desc="$info" \
            suggestion="$(i18n 'ssh.fix_disable_root')" \
            fix="ssh.disable_root_login"
        print_severity "$sev" "$(i18n "$title_key")"
    else
        check_emit "ssh.root_login_disabled" low passed
        print_ok "$(i18n 'ssh.root_login_disabled')"
    fi
}

_ssh_audit_pubkey() {
    if _ssh_pubkey_enabled; then
        check_emit "ssh.pubkey_enabled" low passed
        print_ok "$(i18n 'ssh.pubkey_enabled')"
    else
        check_emit "ssh.pubkey_disabled" medium failed \
            desc="$(i18n 'ssh.pubkey_disabled_desc')" \
            suggestion="$(i18n 'ssh.fix_enable_pubkey')" \
            fix="ssh.enable_pubkey"
        print_severity "medium" "$(i18n 'ssh.pubkey_disabled')"
    fi
}

_ssh_audit_admin_user() {
    local admin_users
    admin_users=$(_ssh_get_admin_users)

    if [[ -n "$admin_users" ]]; then
        local first_admin
        first_admin=$(echo "$admin_users" | head -1)
        check_emit "ssh.admin_user_exists" low passed \
            title="$(i18n 'ssh.admin_user_exists' "user=$first_admin")" \
            desc="$(i18n 'ssh.admin_user_exists_desc' "admin_users=$admin_users")"
        print_ok "$(i18n 'ssh.admin_user_exists' "user=$first_admin")"

        # Every admin, so the verdict does not hang on which one sudoers names first.
        local admins=() keyless=() admin
        mapfile -t admins <<<"$admin_users"
        for admin in "${admins[@]}"; do
            _ssh_user_has_key "$admin" || keyless+=("$admin")
        done
        if (( ${#keyless[@]} )); then
            local who
            who=$(printf '%s, ' "${keyless[@]}")
            who="${who%, }"
            check_emit "ssh.admin_no_key" low failed \
                title="$(i18n 'ssh.admin_no_key' "user=$who")" \
                desc="$(i18n 'ssh.admin_no_key_desc')" \
                suggestion="$(i18n 'ssh.admin_no_key_suggestion' "user=$who")"
            print_severity "low" "$(i18n 'ssh.admin_no_key' "user=$who")"
        fi

        # Every admin, whatever the verdict above: a refused key file is also
        # why an admin reads as keyless.
        local perm_issues
        perm_issues=$(_ssh_check_authkeys_permissions "${admins[@]}")
        if [[ -n "$perm_issues" ]]; then
            check_emit "ssh.authkeys_permissions" medium failed \
                desc="${perm_issues//$'\n'/; }" \
                suggestion="$(i18n 'ssh.authkeys_permissions_suggestion')"
            print_severity "medium" "$(i18n 'ssh.authkeys_permissions')"
        fi
    else
        check_emit "ssh.no_admin_user" low failed \
            desc="$(i18n 'ssh.no_admin_user_desc')" \
            suggestion="$(i18n 'ssh.no_admin_user_suggestion')"
        print_severity "low" "$(i18n 'ssh.no_admin_user')"
    fi
}

_ssh_audit_empty_password() {
    if _ssh_empty_password_allowed; then
        check_emit "ssh.empty_password_allowed" high failed \
            desc="$(i18n 'ssh.empty_password_allowed_desc')" \
            suggestion="$(i18n 'ssh.fix_disable_empty_password')" \
            fix="ssh.disable_empty_password"
        print_severity "high" "$(i18n 'ssh.empty_password_allowed')"
    else
        check_emit "ssh.empty_password_denied" low passed \
            title="$(i18n 'ssh.empty_password_disabled')"
        print_ok "$(i18n 'ssh.empty_password_disabled')"
    fi
}

_ssh_audit_max_auth_tries() {
    local max_auth=$(_ssh_get_config "MaxAuthTries" "6")

    if _ssh_max_auth_tries_ok "$max_auth"; then
        check_emit "ssh.max_auth_tries_ok" low passed \
            desc="MaxAuthTries=$max_auth"
        print_ok "$(i18n 'ssh.max_auth_tries_ok') ($max_auth)"
    else
        check_emit "ssh.max_auth_tries_high" low failed \
            desc="$(i18n 'ssh.max_auth_tries_high_desc' "max_auth=$max_auth")" \
            suggestion="$(i18n 'ssh.max_auth_tries_high_suggestion')" \
            fix="ssh.set_max_auth_tries"
        print_severity "low" "$(i18n 'ssh.max_auth_tries_high') ($max_auth)"
    fi
}

_ssh_audit_login_grace_time() {
    local grace_time=$(_ssh_get_config "LoginGraceTime" "120")

    if _ssh_login_grace_time_ok "$grace_time"; then
        check_emit "ssh.login_grace_time_ok" low passed \
            desc="LoginGraceTime=$grace_time"
        print_ok "$(i18n 'ssh.login_grace_time_ok') ($grace_time)"
    else
        check_emit "ssh.login_grace_time_long" low failed \
            desc="$(i18n 'ssh.login_grace_time_long_desc' "grace_time=$grace_time")" \
            suggestion="$(i18n 'ssh.login_grace_time_long_suggestion')" \
            fix="ssh.set_login_grace_time"
        print_severity "low" "$(i18n 'ssh.login_grace_time_long') ($grace_time)"
    fi
}

# stem|directive|default|test|expect|pass_id|fail_id|suggestion_key|fix_id
# test: = compares case-insensitively, <= numerically (a non-number fails).
# Ids are contract names and stay literal; "-" means the shared suggestion / no fix.
declare -ga SSH_DIRECTIVE_CHECKS=(
    "x11_forwarding|X11Forwarding|no|=|no|ssh.x11_forwarding_disabled|ssh.x11_forwarding_enabled|ssh.x11_forwarding_enabled_suggestion|ssh.disable_x11_forwarding"
    "allow_tcp_forwarding|AllowTcpForwarding|yes|=|no|ssh.allow_tcp_forwarding_disabled|ssh.allow_tcp_forwarding_enabled|-|-"
    "client_alive|ClientAliveCountMax|3|<=|2|ssh.client_alive_ok|ssh.client_alive_high|-|-"
    "log_level|LogLevel|INFO|=|VERBOSE|ssh.log_level_ok|ssh.log_level_low|-|-"
    "max_sessions|MaxSessions|10|<=|4|ssh.max_sessions_ok|ssh.max_sessions_high|-|-"
    "tcp_keepalive|TCPKeepAlive|yes|=|no|ssh.tcp_keepalive_disabled|ssh.tcp_keepalive_enabled|ssh.tcp_keepalive_enabled_suggestion|-"
    "agent_forwarding|AllowAgentForwarding|yes|=|no|ssh.agent_forwarding_disabled|ssh.agent_forwarding_enabled|-|-"
    "ignore_rhosts|IgnoreRhosts|yes|=|yes|ssh.ignore_rhosts_ok|ssh.ignore_rhosts_disabled|-|-"
    "strict_modes|StrictModes|yes|=|yes|ssh.strict_modes_ok|ssh.strict_modes_disabled|-|-"
    "permit_user_env|PermitUserEnvironment|no|=|no|ssh.permit_user_env_disabled|ssh.permit_user_env_enabled|-|-"
    "permit_tunnel|PermitTunnel|no|=|no|ssh.permit_tunnel_disabled|ssh.permit_tunnel_enabled|-|-"
    "gateway_ports|GatewayPorts|no|=|no|ssh.gateway_ports_disabled|ssh.gateway_ports_enabled|-|-"
)

# A row's test on value $3: '=' compares with $2 case-insensitively, '<='
# numerically (a non-number fails).
_ssh_directive_test() {
    local test="$1" expect="$2" val="$3"
    case "$test" in
        '=')  [[ "${val,,}" == "${expect,,}" ]] ;;
        '<=') [[ "$val" =~ ^[0-9]+$ ]] && (( val <= expect )) ;;
        *)    return 1 ;;
    esac
}

# Pass condition of the row named $1, asking sshd for the value.
_ssh_directive_ok() {
    local row stem directive default test expect
    for row in "${SSH_DIRECTIVE_CHECKS[@]}"; do
        IFS='|' read -r stem directive default test expect _ <<< "$row"
        [[ "$stem" == "$1" ]] || continue
        _ssh_directive_test "$test" "$expect" "$(_ssh_get_config "$directive" "$default")"
        return
    done
    return 1
}

_ssh_x11_forwarding_disabled() {
    _ssh_directive_ok x11_forwarding
}

# One pass over SSH_DIRECTIVE_CHECKS: the terminal shows the value only for
# the numeric checks, where the number is the finding.
_ssh_audit_directives() {
    local row stem directive default test expect pass_id fail_id sugg fix val ok shown
    for row in "${SSH_DIRECTIVE_CHECKS[@]}"; do
        IFS='|' read -r stem directive default test expect pass_id fail_id sugg fix <<< "$row"
        print_item "$(i18n "ssh.check_${stem}")"
        val=$(_ssh_get_config "$directive" "$default")
        ok=0; shown=""
        [[ "$test" == '<=' ]] && shown=" ($val)"
        _ssh_directive_test "$test" "$expect" "$val" && ok=1
        if (( ok )); then
            check_emit "$pass_id" low passed desc="${directive}=${val}"
            print_ok "$(i18n "$pass_id")$shown"
        else
            if [[ "$sugg" == - ]]; then
                sugg=$(i18n 'ssh.suggest_set_directive' "directive=$directive" "value=$expect")
            else
                sugg=$(i18n "$sugg")
            fi
            check_emit "$fail_id" low failed \
                desc="$(i18n "${fail_id}_desc" "val=$val")" \
                suggestion="$sugg" \
                fix="${fix/#-/}"
            print_severity "low" "$(i18n "$fail_id")$shown"
        fi
    done
}

# The patterns the Include lines of file $1 name, one per line, unexpanded.
# Relative patterns resolve under the main config's directory, as sshd's do.
_ssh_include_patterns() {
    local base line pat
    base=$(dirname "$SSH_CONFIG")
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee]([[:space:]]+|[[:space:]]*=[[:space:]]*)(.+)$ ]] || continue
        # read -a splits the patterns without globbing them against the cwd.
        local pats=()
        read -ra pats <<< "${BASH_REMATCH[2]%%#*}"
        for pat in "${pats[@]}"; do
            [[ "$pat" == /* ]] || pat="$base/$pat"
            printf '%s\n' "$pat"
        done
    done < "$1"
}

# Every file sshd reads for its config: $1 (default SSH_CONFIG) and, recursively,
# what its Include lines name.
_ssh_config_files() {
    local file="${1:-$SSH_CONFIG}" depth="${2:-0}" pat f
    [[ -r "$file" ]] && (( depth <= 8 )) || return 0
    echo "$file"
    while IFS= read -r pat; do
        for f in $pat; do
            [[ -f "$f" ]] && _ssh_config_files "$f" $((depth + 1))
        done
    done < <(_ssh_include_patterns "$file")
}

# True when an Include somewhere in sshd's config names a pattern that matches
# SSH_HARDENING_DROPIN, i.e. sshd reads what the fixes write.
_ssh_dropin_included() {
    local f pat
    while IFS= read -r f; do
        while IFS= read -r pat; do
            # shellcheck disable=SC2053  # the pattern is a glob on purpose
            [[ "$SSH_HARDENING_DROPIN" == $pat ]] && return 0
        done < <(_ssh_include_patterns "$f")
    done < <(_ssh_config_files)
    return 1
}

# "Directive<TAB>criteria" for each directive this audit judges that a Match
# block sets. The audit reads the value an ordinary user gets (_ssh_get_config),
# so these are the connections whose value it did not see.
_ssh_match_overrides() {
    local judged="PasswordAuthentication PermitRootLogin PubkeyAuthentication PermitEmptyPasswords MaxAuthTries AllowUsers AllowGroups DenyUsers DenyGroups"
    local row directive
    for row in "${SSH_DIRECTIVE_CHECKS[@]}"; do
        IFS='|' read -r _ directive _ <<< "$row"
        judged+=" $directive"
    done
    local f
    while IFS= read -r f; do
        JUDGED="$judged" awk '
            BEGIN { n = split(ENVIRON["JUDGED"], a, " "); for (i = 1; i <= n; i++) want[tolower(a[i])] = a[i] }
            { line = $0; sub(/#.*/, "", line) }
            match(line, /^[[:space:]]*[A-Za-z0-9]+/) {
                kw = tolower(substr(line, RSTART, RLENGTH)); gsub(/[[:space:]]/, "", kw)
                if (kw == "match") {
                    crit = line
                    sub(/^[[:space:]]*[A-Za-z]+[[:space:]=]*/, "", crit); sub(/[[:space:]]+$/, "", crit)
                    inmatch = (tolower(crit) != "all")
                    next
                }
                if (inmatch && (kw in want)) print want[kw] "\t" crit
            }' "$f"
    done < <(_ssh_config_files) | awk '!seen[$0]++'
}

# One finding for every Match override of a judged directive. Not scored: the
# pass/fail verdicts above stand for ordinary users, and this says where they stop.
_ssh_audit_match_overrides() {
    local overrides list
    overrides=$(_ssh_match_overrides)
    [[ -n "$overrides" ]] || return 0
    list=$(awk -F'\t' '{ printf "%s%s (Match %s)", (NR > 1 ? "; " : ""), $1, $2 }' <<< "$overrides")
    check_emit "ssh.match_overrides" low failed \
        desc="$(i18n 'ssh.match_overrides_desc' "list=$list")" \
        suggestion="$(i18n 'ssh.match_overrides_suggestion')"
    print_severity "low" "$(i18n 'ssh.match_overrides'): $list"
}

# Space-separated "cipher:x" / "mac:x" / "kex:x" for each weak algorithm sshd
# offers; empty is the pass condition of the algorithms check. Returns 1 when
# sshd cannot report what it offers.
_ssh_weak_algorithms() {
    local issues=() list weak

    # Substrings: "hmac-md5" also catches hmac-md5-96, "hmac-sha1" catches
    # hmac-sha1-96 and -etm; "...-sha1" never matches group14-sha256.
    list=$(_ssh_get_config "Ciphers" "") || return 1
    for weak in 3des-cbc arcfour arcfour128 arcfour256 blowfish-cbc cast128-cbc; do
        [[ "$list" == *"$weak"* ]] && issues+=("cipher:$weak")
    done
    list=$(_ssh_get_config "MACs" "") || return 1
    for weak in hmac-md5 hmac-sha1; do
        [[ "$list" == *"$weak"* ]] && issues+=("mac:$weak")
    done
    list=$(_ssh_get_config "KexAlgorithms" "") || return 1
    for weak in diffie-hellman-group1-sha1 diffie-hellman-group-exchange-sha1 diffie-hellman-group14-sha1; do
        [[ "$list" == *"$weak"* ]] && issues+=("kex:$weak")
    done

    echo "${issues[*]}"
}

# FIX_VERIFY's predicate: fails closed when sshd cannot answer.
_ssh_algorithms_ok() {
    local weak
    weak=$(_ssh_weak_algorithms) || return 1
    [[ -z "$weak" ]]
}

_ssh_audit_algorithms() {
    local issues=()
    read -ra issues <<< "$(_ssh_weak_algorithms)"

    if [[ ${#issues[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s ' "${issues[@]}")
        check_emit "ssh.weak_algorithms" low failed \
            desc="$(i18n 'ssh.weak_algorithms_desc' "list=$issue_list")" \
            suggestion="$(i18n 'ssh.fix_algorithms')" \
            fix="ssh.harden_algorithms"
        print_severity "low" "$(i18n 'ssh.weak_algorithms'): $(i18n 'common.n_found' "n=${#issues[@]}")"
    else
        check_emit "ssh.algorithms_ok" low passed \
            desc="$(i18n 'ssh.algorithms_ok_desc')"
        print_ok "$(i18n 'ssh.algorithms_ok')"
    fi
}

_ssh_audit_access_control() {
    if _ssh_has_access_control; then
        local control_info=$(_ssh_get_access_control_info)
        check_emit "ssh.access_control_configured" low passed \
            desc="$control_info"
        print_ok "$(i18n 'ssh.access_control_configured')"
    else
        # This is a recommendation, not critical
        check_emit "ssh.no_access_control" low failed \
            desc="$(i18n 'ssh.no_access_control_desc')" \
            suggestion="$(i18n 'ssh.fix_access_control')"
        print_severity "low" "$(i18n 'ssh.no_access_control')"
    fi
}

_ssh_audit_port() {
    local ports ssh_port
    ports=$(get_ssh_ports)
    ssh_port=$(paste -sd, - <<<"$ports")

    if grep -qx '22' <<<"$ports"; then
        # Default port - recommend changing for security through obscurity
        check_emit "ssh.default_port" low failed \
            desc="$(i18n 'ssh.default_port_desc')" \
            suggestion="$(i18n 'ssh.default_port_suggestion')"
        print_severity "low" "$(i18n 'ssh.default_port')"
    else
        check_emit "ssh.custom_port" low passed \
            desc="$(i18n 'ssh.custom_port_desc' "ssh_port=$ssh_port")"
        print_ok "$(i18n 'ssh.custom_port') ($ssh_port)"
    fi
}

# --- SSH Fix Functions ---

ssh_fix() {
    local fix_id="$1"

    # Every fix writes the drop-in; when sshd never reads it, each one could
    # only fail its post-reload check, so stop before anything is touched.
    if ! _ssh_dropin_included; then
        print_error "$(i18n 'ssh.dropin_not_included' "config=$SSH_CONFIG" "dir=$SSH_DROPIN_DIR")"
        return 1
    fi

    # Migrate before the lockout gates: they read sshd -T, and the 00- name
    # makes the legacy settings win. A fix that writes nothing moves it back.
    SSH_DROPIN_MIGRATED="" SSH_DROPIN_WRITTEN=""
    _ssh_migrate_legacy_dropin || return 1

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
            false
            ;;
    esac
    local rc=$?
    if [[ -n "$SSH_DROPIN_MIGRATED" && -z "$SSH_DROPIN_WRITTEN" ]]; then
        _ssh_unmigrate_legacy_dropin
    fi
    return "$rc"
}

# Rescue sshd: a second daemon on a temporary port, up BEFORE any change that
# can cut SSH access. Each rule stopped a lockout: a free port, never the live
# one; up once OUR pid listens; let through ufw; teardown undoes only its own.

# Pick a free TCP port for the rescue daemon: never the live SSH port, never an
# already-listening port. Prefer 2222, then scan small high-port ranges.
_ssh_pick_rescue_port() {
    local live_port listening candidate
    live_port=$(get_ssh_ports 2>/dev/null || echo 22)
    listening=$(get_listening_ports 2>/dev/null || echo "")
    for candidate in 2222 $(seq 2200 2299) $(seq 22000 22099); do
        grep -qx "$candidate" <<<"$live_port" && continue
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
    backend=$(fw_backend 2>/dev/null) || backend="unknown"
    ip=$(get_current_ssh_ip)

    case "$backend" in
        ufw)
            # No detectable source IP: ASK, never fall back to world-open.
            # Empty answer or unreadable tty adds NO rule — the mandatory
            # reachability confirmation catches an unreachable rescue.
            if [[ -z "$ip" ]]; then
                tty_warn "$(i18n 'ssh.rescue_fw_no_source')"
                tty_say -n "$(i18n 'ssh.rescue_fw_ask_cidr' "port=$SSH_RESCUE_PORT") > "
                local answer=""
                read -r -t "$VPSSEC_CONFIRM_TIMEOUT" answer 2>/dev/null </dev/tty || answer=""
                if [[ "$answer" == "any" ]]; then
                    ip=""  # explicit world-open, handled below
                elif [[ -n "$answer" ]] && _ssh_valid_cidr "$answer"; then
                    ip="$answer"
                elif [[ -n "$answer" ]]; then
                    tty_warn "$(i18n 'ssh.rescue_fw_bad_cidr' "value=$answer")"
                    tty_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
                    return 0
                else
                    tty_say ""
                    tty_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
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
                tty_say "${GREEN}${SYM_OK}${NC} $(i18n 'ssh.rescue_fw_allowed' "port=$SSH_RESCUE_PORT")"
            else
                tty_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
            fi
            ;;
        none)
            : # no active firewall: the rescue port is reachable, nothing to do
            ;;
        unknown)
            # The firewall query failed: no rule is added, and the operator is
            # told why the reachability check below is the one that matters.
            tty_warn "$(i18n 'ssh.rescue_fw_unknown' "port=$SSH_RESCUE_PORT")"
            ;;
        *)
            # firewalld / nftables / iptables: don't manipulate rules blind.
            tty_warn "$(i18n 'ssh.rescue_fw_warn' "port=$SSH_RESCUE_PORT")"
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
    # ufw answers 0 for a rule already gone, so a failure here is a rule left
    # open: name the command that removes it.
    local -a rule=(allow "$port/tcp")
    [[ -n "$ip" ]] && rule=(allow from "$ip" to any port "$port" proto tcp)
    case "$kind" in
        ufw)
            if ! ufw delete "${rule[@]}" >/dev/null 2>&1; then
                tty_warn "$(i18n 'ssh.rescue_rule_remove_failed' "cmd=ufw delete ${rule[*]}")"
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
    tty_say "${BLUE}${SYM_INFO}${NC} $(i18n 'ssh.rescue_port_notice' "port=$SSH_RESCUE_PORT")"

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
    "$SSH_RESCUE_SSHD" -D -f "$SSH_RESCUE_CONFIG" >/dev/null 2>&1 &
    SSH_RESCUE_PID=$!

    # Wait (up to ~3s) for OUR daemon to bind the rescue port.
    local _i
    for ((_i=0; _i<30; _i++)); do
        if _ssh_rescue_is_up; then
            tty_say "${GREEN}${SYM_OK}${NC} $(i18n 'ssh.rescue_port_opened' "port=$SSH_RESCUE_PORT")"
            # Armed the moment the daemon is confirmed listening: without it
            # a killed vpssec leaves a root-and-password sshd running forever,
            # since sshd re-execs on HUP rather than exiting.
            _ssh_rescue_arm_traps
            _ssh_rescue_allow_firewall
            # After the firewall rule exists, so the watchdog knows to remove it.
            _ssh_rescue_start_watchdog
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

# True while pid $1 runs. Not kill -0: it also answers for a zombie, and a killed
# vpssec stays one until its parent reaps it (never, under a PID 1 that does not).
_ssh_rescue_pid_running() {
    local stat
    read -r stat 2>/dev/null < "/proc/$1/stat" || return 1
    stat=${stat##*') '}
    [[ "${stat%% *}" != [ZX] ]]
}

# Tears the rescue down when vpssec dies without its traps (SIGKILL, OOM) or
# outstays the confirmation window plus SSH_RESCUE_GRACE. Ignores INT/HUP, left
# to the parent's trap, and must not hold the run lock (fd 200).
_ssh_rescue_start_watchdog() {
    local parent=$$
    local limit=$(( VPSSEC_CONFIRM_TIMEOUT + SSH_RESCUE_GRACE ))
    (
        exec 200>&- </dev/null >/dev/null 2>&1
        trap '' INT HUP
        local waited=0
        while _ssh_rescue_pid_running "$parent" && (( waited < limit )); do
            sleep 1
            waited=$(( waited + 1 ))
        done
        _ssh_rescue_teardown
    ) &
    SSH_RESCUE_WATCHDOG_PID=$!
}

# Kill ONLY our tracked daemon, remove our firewall rule, clean temps. Shared
# by the parent's close and the watchdog, so either one alone is enough.
_ssh_rescue_teardown() {
    _ssh_rescue_remove_firewall

    if [[ -n "${SSH_RESCUE_PID:-}" ]] && kill -0 "$SSH_RESCUE_PID" 2>/dev/null; then
        kill "$SSH_RESCUE_PID" 2>/dev/null || true
        log_info "Closed rescue sshd on port ${SSH_RESCUE_PORT} (pid: $SSH_RESCUE_PID)"
    fi

    [[ -n "${SSH_RESCUE_CONFIG:-}" && -f "$SSH_RESCUE_CONFIG" ]] && rm -f "$SSH_RESCUE_CONFIG"
    [[ -n "${SSH_RESCUE_PIDFILE:-}" && -f "$SSH_RESCUE_PIDFILE" ]] && rm -f "$SSH_RESCUE_PIDFILE"
    return 0
}

# Tear down the rescue daemon and its watchdog. Safe to call multiple times /
# after a failed open.
_ssh_close_rescue_port() {
    if [[ -n "${SSH_RESCUE_WATCHDOG_PID:-}" ]]; then
        kill "$SSH_RESCUE_WATCHDOG_PID" 2>/dev/null || true
        SSH_RESCUE_WATCHDOG_PID=""
    fi
    _ssh_rescue_teardown
    SSH_RESCUE_PID=""
    SSH_RESCUE_CONFIG=""
    SSH_RESCUE_PIDFILE=""

    # Put back the traps the rescue replaced, once: a second close must not
    # clear the caller's. When the EXIT trap invoked us this prevents a rerun.
    if (( SSH_RESCUE_TRAPS_ARMED )); then
        trap - EXIT INT TERM HUP
        eval "$SSH_RESCUE_PRIOR_TRAPS"
        SSH_RESCUE_PRIOR_TRAPS=""
        SSH_RESCUE_TRAPS_ARMED=0
    fi
}

# The caller's EXIT/INT/TERM/HUP traps, as `trap -p` prints them, while the
# rescue's own are armed.
SSH_RESCUE_PRIOR_TRAPS=""
SSH_RESCUE_TRAPS_ARMED=0

# Close the rescue on exit or a signal. The caller's EXIT command is chained
# after the close: run from the EXIT trap, the close puts it back too late.
_ssh_rescue_arm_traps() {
    local -a prior_exit=()
    SSH_RESCUE_PRIOR_TRAPS=$(trap -p EXIT INT TERM HUP)
    eval "prior_exit=($(trap -p EXIT))"
    trap "_ssh_close_rescue_port${prior_exit[2]:+; ${prior_exit[2]}}" EXIT
    trap '_ssh_close_rescue_port; exit 130' INT TERM HUP
    SSH_RESCUE_TRAPS_ARMED=1
}

# What the most recent write replaced, for _ssh_reload_safe's rollback: "NEW"
# (no prior drop-in, so delete); "PREV" (the old content is in
# SSH_LAST_DROPIN_PREV); empty = no call has run yet.
SSH_LAST_DROPIN_BACKUP=""
SSH_LAST_DROPIN_PREV=""
# Set by this ssh_fix call: the legacy file was moved / the drop-in was written.
SSH_DROPIN_MIGRATED=""
SSH_DROPIN_WRITTEN=""

# Migrate the legacy 99- drop-in, which loses to 50-cloud-init, to the 00-
# name, both recorded so a rollback brings 99- back and deletes 00-. A failed
# mv leaves the legacy file, which a written 00- outranks anyway.
_ssh_migrate_legacy_dropin() {
    [[ -f "$SSH_HARDENING_DROPIN_LEGACY" ]] || return 0
    [[ -e "$SSH_HARDENING_DROPIN" ]] && return 0
    backup_file "$SSH_HARDENING_DROPIN_LEGACY" >/dev/null || return 1
    backup_file "$SSH_HARDENING_DROPIN" >/dev/null || return 1
    if mv "$SSH_HARDENING_DROPIN_LEGACY" "$SSH_HARDENING_DROPIN" 2>/dev/null; then
        SSH_DROPIN_MIGRATED=1
        log_info "Migrated legacy SSH hardening drop-in to $SSH_HARDENING_DROPIN"
    fi
}

# Undo the migration of a fix that wrote nothing: left in place, the 00- name
# would apply the legacy settings at the next sshd restart, unverified.
_ssh_unmigrate_legacy_dropin() {
    if mv "$SSH_HARDENING_DROPIN" "$SSH_HARDENING_DROPIN_LEGACY" 2>/dev/null; then
        log_info "Moved the SSH hardening drop-in back to $SSH_HARDENING_DROPIN_LEGACY"
    else
        log_warn "Could not move $SSH_HARDENING_DROPIN back to $SSH_HARDENING_DROPIN_LEGACY"
    fi
}

# Assert the value the audit will read, through its own getter — the guard
# against the precedence trap, where a wrong file order or a Match override
# would otherwise read as success. Compared case-insensitively.
_ssh_verify_effective() {
    local effective
    effective=$(_ssh_get_config "$1" "") || return 1
    [[ "${effective,,}" == "${2,,}" ]]
}

# The global value of $1 with no Match block applied (plain `sshd -T` applies
# none). Only tells a Match override apart from a lost merge.
_ssh_global_value() {
    local dump
    dump=$(sshd -T 2>/dev/null) || return 1
    awk -v k="${1,,}" 'tolower($1)==k{sub(/^[^ ]+ /, ""); print; exit}' <<<"$dump"
}

# Write SSH hardening config
_ssh_write_hardening_config() {
    local content="$1"
    local temp_file

    backup_mkdir "$SSH_DROPIN_DIR" || return 1

    # backup_file serves the plan-level rollback; this write's own undo keeps the
    # content it replaces, since the session copy predates the plan.
    backup_file "$SSH_HARDENING_DROPIN" >/dev/null || return 1
    if [[ -f "$SSH_HARDENING_DROPIN" ]]; then
        SSH_LAST_DROPIN_PREV=$(cat "$SSH_HARDENING_DROPIN") || return 1
        SSH_LAST_DROPIN_BACKUP="PREV"
    else
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
            SSH_DROPIN_WRITTEN=1
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

# Restore the drop-in to its state before the most recent write: the write
# failed the full-context sshd -t, the reload, or the post-reload check.
_ssh_rollback_dropin() {
    local backup="${SSH_LAST_DROPIN_BACKUP:-}"

    if [[ "$backup" == "NEW" ]]; then
        # No prior drop-in: delete the new one we just wrote.
        if [[ -f "$SSH_HARDENING_DROPIN" ]] && rm -f "$SSH_HARDENING_DROPIN"; then
            print_warn "$(i18n 'ssh.dropin_rolled_back_deleted')"
        fi
    elif [[ "$backup" == "PREV" ]]; then
        if printf '%s\n' "$SSH_LAST_DROPIN_PREV" > "$SSH_HARDENING_DROPIN"; then
            print_warn "$(i18n 'ssh.dropin_rolled_back_restored')"
        else
            print_error "$(i18n 'ssh.dropin_rollback_failed')"
        fi
    else
        # No write recorded since the last rollback.
        print_error "$(i18n 'ssh.dropin_rollback_missing')"
    fi

    # Reset so a later reload cannot "rollback" stale state.
    SSH_LAST_DROPIN_BACKUP=""
}

_ssh_reload_service() {
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
}

# Reload sshd safely. The full-context `sshd -t` can fail on a drop-in that
# parses alone, and that failure MUST roll back. Optional trailing
# (key expected) pairs are asserted with sshd -T after the reload.
_ssh_reload_safe() {
    # Test config first
    if sshd -t 2>/dev/null; then
        print_ok "$(i18n 'ssh.sshd_test_ok')"

        if _ssh_reload_service; then
            print_ok "$(i18n 'ssh.sshd_reloaded')"

            # Verify effective values actually changed. Skipped only when sshd
            # is unavailable to answer (verify returns non-zero → treated as
            # mismatch), which correctly surfaces "could not confirm".
            local _k _v
            while [[ $# -ge 2 ]]; do
                _k="$1"; _v="$2"; shift 2
                if ! _ssh_verify_effective "$_k" "$_v"; then
                    local _global
                    _global=$(_ssh_global_value "$_k") || _global=""
                    if [[ "${_global,,}" == "${_v,,}" ]]; then
                        print_error "$(i18n 'ssh.effective_match_override' "key=$_k" "value=$_v")"
                    else
                        print_error "$(i18n 'ssh.effective_mismatch' "key=$_k" "value=$_v")"
                    fi
                    _ssh_rollback_dropin
                    # sshd is already running the rejected change.
                    _ssh_reload_service || print_error "$(i18n 'ssh.reload_after_rollback_failed')"
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
    # Passwords would still log in through keyboard-interactive (PAM) after
    # this fix; whether to turn that off is the operator's call.
    if _ssh_kbdint_password_path; then
        print_error "$(i18n 'ssh.kbdint_fix_refused')"
        return 1
    fi

    # Safety check - ensure user has SSH key access
    local current_ip=$(get_current_ssh_ip)
    if [[ -n "$current_ip" ]]; then
        print_info "$(i18n 'ssh.current_connection' "ip=$current_ip")"
    fi

    # Safety gate: once passwords are off, someone must still get in by key
    # AND reach root. A non-root admin is safest; root's own key counts only
    # while PermitRootLogin permits key auth.
    local survivor=""
    if ! survivor=$(_ssh_surviving_admin no); then
        if _ssh_can_login_with_key "root"; then
            # Root's key is the only way back in — legitimate on a fresh
            # image, but fragile. Warn that disabling root login too would
            # remove this last path.
            print_warn "$(i18n 'ssh.only_root_key_warning')"
            survivor="root"
        elif ! _ssh_pubkey_enabled; then
            print_error "$(i18n 'ssh.pubkey_off_no_password_off')"
            return 1
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
        (( result == 0 )) && _ssh_tell_verify_login "$survivor"
        return $result
    else
        _ssh_close_rescue_port
        return 1
    fi
}

# The rescue check above tested the rescue daemon, not the changed main one.
# Name the account the gate relied on and how to undo from this session.
_ssh_tell_verify_login() {
    local ports
    ports=$(get_ssh_ports | paste -sd, -)
    tty_warn "$(i18n 'ssh.verify_main_login' "user=$1" "port=$ports")"
}

_ssh_fix_disable_root_login() {
    # Safety gate: with root login gone, an admin must still get in by what
    # stays enabled and reach root through sudo. Asking with the CURRENT
    # password setting keeps either order of the two SSH fixes safe.
    local pw_after="no" survivor=""
    _ssh_password_auth_enabled && pw_after="yes"
    if ! survivor=$(_ssh_surviving_admin "$pw_after"); then
        if [[ "$pw_after" == yes ]]; then
            print_error "$(i18n 'ssh.no_admin_for_root')"
            print_warn "$(i18n 'ssh.create_admin_first')"
        else
            print_error "$(i18n 'ssh.no_admin_key_pw_off')"
            print_warn "$(i18n 'ssh.add_key_first')"
        fi
        return 1
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
        (( result == 0 )) && _ssh_tell_verify_login "$survivor"
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

    # Removed from the defaults rather than a fixed list: the distro's own
    # set, its post-quantum hybrid KEX included, stays (OpenSSH 7.5+ syntax).
    local content="Ciphers -3des-cbc,arcfour*,blowfish-cbc,cast128-cbc
MACs -hmac-md5*,hmac-sha1*
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"

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
