#!/usr/bin/env bats
# FIX_SAFE fixes judged by their FIX_VERIFY predicate: each case is a host where
# the fix's own work succeeds while the audit would still flag it, or the reverse
# — the two answers must agree, because the engine records what the fix reports.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    state_init
    etc=$(_vpssec_fake_etc)
}

_recorded() {
    jq -e --arg id "$1" 'any(.completed_fixes[]; .id == $id)' \
        "$VPSSEC_STATE/ok.json" >/dev/null 2>&1
}

# ---- fail2ban.enable_service -------------------------------------------

# fail2ban starts, and `systemctl enable` succeeds or not per $1.
_f2b_starts_enabled() {
    _vpssec_stub_script systemctl <<SH
case "\$*" in
    *"start fail2ban"*) touch "$BATS_TEST_TMPDIR/f2b-up" ;;
    *is-active*)        [[ -f "$BATS_TEST_TMPDIR/f2b-up" ]] || exit 3 ;;
    *is-enabled*)       exit $1 ;;
esac
exit 0
SH
}

@test "fail2ban.enable_service: running but not enabled at boot is not recorded" {
    # The audit wants active AND enabled; the fix only checks active.
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"
    _f2b_starts_enabled 1

    run execute_fix fail2ban.enable_service true
    [ "$status" -eq 1 ]
    _vpssec_refute _recorded fail2ban.enable_service
}

@test "fail2ban.enable_service: running and enabled is recorded" {
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"
    _f2b_starts_enabled 0

    run execute_fix fail2ban.enable_service true
    [ "$status" -eq 0 ]
    _recorded fail2ban.enable_service
}

# ---- timezone.enable_ntp -----------------------------------------------

@test "timezone.enable_ntp: enabled but not yet synchronised counts as done" {
    # Sync takes minutes; the re-check runs at once. The audit reports this
    # host as ntp_not_synced, which has no fix, not ntp_disabled.
    source "$(_vpssec_repo_root)/modules/timezone.sh"
    _vpssec_stub_script timedatectl <<SH
case "\$*" in
    *"set-ntp true"*)  touch "$BATS_TEST_TMPDIR/ntp-on" ;;
    *"property=NTP "*|*"property=NTP --"*)
        if [[ -f "$BATS_TEST_TMPDIR/ntp-on" ]]; then echo yes; else echo no; fi ;;
    *NTPSynchronized*) echo no ;;
esac
exit 0
SH
    _vpssec_stub systemctl 3

    run execute_fix timezone.enable_ntp true
    [ "$status" -eq 0 ]
    _recorded timezone.enable_ntp

    _timezone_check_ntp
    run jq -r '[.[] | .id] | join(",")' "$VPSSEC_STATE/checks.json"
    [ "$output" = "timezone.ntp_not_synced" ]
}

# ---- ufw.allow_ssh -------------------------------------------------------

@test "ufw: an installed but inactive UFW reports only that it is disabled" {
    # An inactive `ufw status` lists no rules, so no_ssh_rule would be flagged
    # on every such host and ufw.allow_ssh could never be seen to work.
    source "$(_vpssec_repo_root)/core/distro.sh"
    source "$(_vpssec_repo_root)/modules/ufw.sh"
    _vpssec_stub ufw 0 "Status: inactive"
    _vpssec_stub systemctl 3
    _vpssec_stub nft 0
    _vpssec_stub iptables 0 "Chain INPUT (policy ACCEPT)"

    run ufw_audit
    [ "$status" -eq 0 ]
    run jq -r '[.[] | .id] | join(",")' "$VPSSEC_STATE/checks.json"
    [ "$output" = "ufw.disabled" ]
}

# ---- webapp.nginx_server_tokens ------------------------------------------

@test "webapp.nginx_server_tokens: a vhost still saying 'on' is not recorded" {
    # nginx.conf already has `server_tokens off`, so the fix has nothing to
    # write; the audit reads the whole `nginx -T` dump and still sees the vhost.
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    NGINX_CONF="$etc/nginx/nginx.conf"
    mkdir -p "$etc/nginx"
    printf 'http {\n    server_tokens off;\n}\n' > "$NGINX_CONF"
    _vpssec_stub_script nginx <<'SH'
[[ "$*" == *-T* ]] && printf 'http {\n    server_tokens off;\n}\nserver {\n    server_tokens on;\n}\n'
exit 0
SH

    run execute_fix webapp.nginx_server_tokens true
    [ "$status" -eq 1 ]
    _vpssec_refute _recorded webapp.nginx_server_tokens
}

# ---- ssh.set_max_auth_tries / ssh.set_login_grace_time ------------------

@test "ssh: MaxAuthTries passes at 4 or below, and a non-number fails" {
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    local v
    for v in 0 3 4; do _ssh_max_auth_tries_ok "$v" || { echo "$v"; false; }; done
    for v in 5 6 abc ""; do _vpssec_refute _ssh_max_auth_tries_ok "$v"; done
}

@test "ssh: LoginGraceTime passes from 1 to 60 seconds in any unit" {
    # 0 is unlimited, not instant: it is the weakest value, not the strongest.
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    local v
    for v in 1 60 30s 1m; do _ssh_login_grace_time_ok "$v" || { echo "$v"; false; }; done
    for v in 0 61 2m 1h 120 abc 1d; do _vpssec_refute _ssh_login_grace_time_ok "$v"; done
}

@test "ssh: with no value given the predicates ask sshd, as FIX_VERIFY calls them" {
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    _ssh_get_config() {
        case "$1" in MaxAuthTries) echo 3 ;; LoginGraceTime) echo 90 ;; esac
    }
    _ssh_max_auth_tries_ok
    _vpssec_refute _ssh_login_grace_time_ok
}

# ---- filesystem.fix_sensitive_perms --------------------------------------

@test "filesystem: every wrong file is listed in its bucket, not only the first" {
    # _fs_check_sensitive_file returns 1 for each bad file; under errexit a
    # lister that let that through would stop at the first and hide the rest.
    source "$(_vpssec_repo_root)/modules/filesystem.sh"
    FS_SENSITIVE_FILES=(["$etc/passwd"]="644" ["$etc/group"]="644")
    FS_SUDOERS_D="$etc/sudoers.d"
    FS_SSHD_CONFIG_D="$etc/sshd_config.d"
    mkdir -p "$FS_SUDOERS_D" "$FS_SSHD_CONFIG_D"
    local f
    for f in "$etc/passwd" "$etc/group" "$FS_SUDOERS_D/ops" "$FS_SSHD_CONFIG_D/10.conf"; do
        printf 'x\n' > "$f"
        chmod 666 "$f"
    done

    run bash -ec "$(declare -f _fs_sensitive_perm_issues _fs_sensitive_perm_issue \
        _fs_check_sensitive_file _fs_is_critical_perm_path)
        $(declare -p FS_SENSITIVE_FILES FS_SUDOERS_D FS_SSHD_CONFIG_D)
        _fs_sensitive_perm_issues"
    [ "$status" -eq 0 ]
    [ "$(grep -c '^med' <<<"$output")" -eq 3 ]
    grep -q "^high	$FS_SUDOERS_D/ops:" <<<"$output"
    _vpssec_refute _fs_sensitive_perms_ok

    chmod 644 "$etc/passwd" "$etc/group" "$FS_SSHD_CONFIG_D/10.conf"
    chmod 440 "$FS_SUDOERS_D/ops"
    _fs_sensitive_perms_ok
}

# ---- kernel.harden_ipv6 ----------------------------------------------------

@test "kernel: accept_ra=1 is an IPv6 issue only on a host that does not use RA" {
    # harden_ipv6 never touches accept_ra on an RA/SLAAC host (it would drop
    # the default route), so the audit must not flag it there either.
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _kernel_ipv6_enabled() { return 0; }
    _kernel_ip_forward_needed() { return 1; }
    _kernel_get_sysctl() {
        case "$1" in
            net.ipv6.conf.all.accept_ra) echo 1 ;;
            net.ipv6.conf.all.use_tempaddr) echo 2 ;;
            *) echo 0 ;;
        esac
    }

    _kernel_ipv6_uses_ra() { return 0; }
    [ -z "$(_kernel_ipv6_check_security)" ]
    _kernel_ipv6_in_use() { return 0; }
    _kernel_ipv6_secure

    _kernel_ipv6_uses_ra() { return 1; }
    [ "$(_kernel_ipv6_check_security)" = "accept_ra_enabled" ]
    _vpssec_refute _kernel_ipv6_secure
}

@test "kernel: an idle IPv6 stack tolerates two issues, one in use none" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _kernel_ipv6_issues_ok yes 0
    _vpssec_refute _kernel_ipv6_issues_ok yes 1
    _kernel_ipv6_issues_ok no 2
    _vpssec_refute _kernel_ipv6_issues_ok no 3
    _kernel_ipv6_enabled() { return 1; }
    _kernel_ipv6_secure
}

# ---- kernel.harden_network / harden_kernel ----------------------------------

# /proc/sys as a table the test fills: unset names read as unavailable.
_sysctl_table() {
    declare -gA SYSCTL=()
    _kernel_get_sysctl() { printf '%s' "${SYSCTL[$1]-}"; }
    _kernel_ip_forward_needed() { return 1; }
    _kernel_ipv6_uses_ra() { return 1; }
}

@test "kernel: network params pass only with nothing wrong and something read" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _sysctl_table

    # Nothing readable is network_params_unreadable, not a pass.
    _vpssec_refute _kernel_network_params_ok

    SYSCTL[net.ipv4.tcp_syncookies]=1
    _kernel_network_params_ok

    SYSCTL[net.ipv4.conf.all.send_redirects]=1
    _vpssec_refute _kernel_network_params_ok
}

@test "kernel: the fix sets exactly what the audit flags, then the predicate passes" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _sysctl_table
    SYSCTL[net.ipv4.tcp_syncookies]=0
    SYSCTL[net.ipv4.conf.all.rp_filter]=0
    SYSCTL[net.ipv6.conf.all.accept_ra]=1
    _kernel_ipv6_uses_ra() { return 0; }     # accept_ra stays: RA host
    _kernel_write_sysctl() { SYSCTL[$1]="$2"; }
    _kernel_reload_sysctl_dropin() { :; }
    sysctl() { return 0; }

    _kernel_fix_network_params
    [ "${SYSCTL[net.ipv4.tcp_syncookies]}" = "1" ]
    [ "${SYSCTL[net.ipv4.conf.all.rp_filter]}" = "1" ]
    [ "${SYSCTL[net.ipv6.conf.all.accept_ra]}" = "1" ]
    _kernel_network_params_ok
}

@test "kernel: kernel params pass with nothing wrong, unreadable ones aside" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _sysctl_table
    _kernel_kernel_params_ok

    SYSCTL[kernel.kptr_restrict]=0
    _vpssec_refute _kernel_kernel_params_ok
}

# ---- fail2ban.configure_ssh_jail ---------------------------------------------

@test "fail2ban.configure_ssh_jail: every check that offers it has to pass" {
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"
    _f2b_ssh_jail_enabled() { return 0; }
    _f2b_has_custom_config() { return 0; }
    _f2b_get_maxretry() { echo 3; }
    _f2b_ssh_jail_configured

    _f2b_get_maxretry() { echo 10; }
    _vpssec_refute _f2b_ssh_jail_configured

    _f2b_get_maxretry() { echo 3; }
    _f2b_has_custom_config() { return 1; }
    _vpssec_refute _f2b_ssh_jail_configured
}

# ---- ssh.harden_algorithms ---------------------------------------------------

@test "ssh: the algorithms predicate fails on any weak cipher, MAC or kex" {
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    _vpssec_stub_script sshd <<'SH'
printf 'ciphers aes256-gcm@openssh.com,3des-cbc\nmacs hmac-sha2-256\nkexalgorithms curve25519-sha256\n'
SH
    [ "$(_ssh_weak_algorithms)" = "cipher:3des-cbc" ]
    _vpssec_refute _ssh_algorithms_ok

    _vpssec_stub_script sshd <<'SH'
printf 'ciphers aes256-gcm@openssh.com\nmacs hmac-sha2-256\nkexalgorithms curve25519-sha256\n'
SH
    _ssh_algorithms_ok
}

# ---- ufw.set_default_deny / timezone.set_timezone ----------------------------

@test "ufw: only a deny or reject incoming policy passes" {
    source "$(_vpssec_repo_root)/modules/ufw.sh"
    _ufw_default_deny deny
    _ufw_default_deny REJECT
    _vpssec_refute _ufw_default_deny allow
    _vpssec_refute _ufw_default_deny ""
}

@test "timezone: set_timezone is done once any timezone is configured" {
    source "$(_vpssec_repo_root)/modules/timezone.sh"
    _timezone_current() { echo "|"; }
    _vpssec_refute _timezone_configured
    _timezone_current() { echo "Asia/Shanghai|timedatectl"; }
    _timezone_configured
}
