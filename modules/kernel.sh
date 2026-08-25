#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Kernel and network security parameters module
# Copyright (c) 2024

# --- Kernel Security Configuration ---

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_D="/etc/sysctl.d"
VPSSEC_SYSCTL_CONF="${SYSCTL_D}/99-vpssec-hardening.conf"

# Variables, not literals, so the audit predicate and the fix read the SAME
# locations, and so the fix is reachable from a test.
KERNEL_LIMITS_CONF="/etc/security/limits.conf"
KERNEL_COREDUMP_CONF="/etc/systemd/coredump.conf"
KERNEL_COREDUMP_D="/etc/systemd/coredump.conf.d"
KERNEL_COREDUMP_DROPIN="${KERNEL_COREDUMP_D}/99-vpssec.conf"

# Recommended sysctl settings with descriptions
# Format: parameter:recommended_value:severity:description
declare -ga KERNEL_SECURITY_PARAMS=(
    # Network security - IPv4
    "net.ipv4.ip_forward:0:medium:IP forwarding (should be disabled unless routing)"
    "net.ipv4.conf.all.send_redirects:0:medium:ICMP redirects sending"
    "net.ipv4.conf.default.send_redirects:0:medium:ICMP redirects sending (default)"
    "net.ipv4.conf.all.accept_redirects:0:medium:ICMP redirects acceptance"
    "net.ipv4.conf.default.accept_redirects:0:medium:ICMP redirects acceptance (default)"
    "net.ipv4.conf.all.secure_redirects:0:low:Secure ICMP redirects"
    "net.ipv4.conf.default.secure_redirects:0:low:Secure ICMP redirects (default)"
    "net.ipv4.conf.all.accept_source_route:0:medium:Source routing acceptance"
    "net.ipv4.conf.default.accept_source_route:0:medium:Source routing acceptance (default)"
    "net.ipv4.conf.all.log_martians:1:low:Log suspicious packets"
    "net.ipv4.conf.default.log_martians:1:low:Log suspicious packets (default)"
    "net.ipv4.conf.all.rp_filter:1:medium:Reverse path filtering"
    "net.ipv4.conf.default.rp_filter:1:medium:Reverse path filtering (default)"
    "net.ipv4.icmp_echo_ignore_broadcasts:1:low:Ignore ICMP broadcast"
    "net.ipv4.icmp_ignore_bogus_error_responses:1:low:Ignore bogus ICMP errors"
    "net.ipv4.tcp_syncookies:1:high:SYN flood protection"
    "net.ipv4.tcp_timestamps:1:low:TCP timestamps"
    # Niche-but-default-off IPv4 features (Lynis KRNL-6000 cross-check)
    "net.ipv4.conf.all.bootp_relay:0:low:BOOTP relay (default off; enable = relay agent role)"
    "net.ipv4.conf.all.mc_forwarding:0:low:Multicast forwarding (default off; enable = mrouted role)"
    "net.ipv4.conf.all.proxy_arp:0:low:Proxy ARP (default off; enable = bridge/router role)"

    # Network security - IPv6 (Enhanced)
    "net.ipv6.conf.all.accept_redirects:0:medium:IPv6 ICMP redirects"
    "net.ipv6.conf.default.accept_redirects:0:medium:IPv6 ICMP redirects (default)"
    # IPv6 symmetry with the IPv4 send_redirects checks above (Lynis
    # cross-check; the original list audited IPv4 only).
    "net.ipv6.conf.all.send_redirects:0:medium:IPv6 ICMP redirects sending"
    "net.ipv6.conf.default.send_redirects:0:medium:IPv6 ICMP redirects sending (default)"
    "net.ipv6.conf.all.accept_source_route:0:medium:IPv6 source routing"
    "net.ipv6.conf.default.accept_source_route:0:medium:IPv6 source routing (default)"
    "net.ipv6.conf.all.accept_ra:0:medium:IPv6 Router Advertisements (can be MITM vector)"
    "net.ipv6.conf.default.accept_ra:0:medium:IPv6 Router Advertisements (default)"
    "net.ipv6.conf.all.use_tempaddr:2:low:IPv6 privacy extensions (use temp addresses)"
    "net.ipv6.conf.default.use_tempaddr:2:low:IPv6 privacy extensions (default)"
    "net.ipv6.conf.all.max_addresses:1:low:Limit IPv6 addresses per interface"
    "net.ipv6.conf.all.accept_ra_defrtr:0:low:Accept RA default router"
    "net.ipv6.conf.all.accept_ra_pinfo:0:low:Accept RA prefix info"
    "net.ipv6.conf.all.accept_ra_rtr_pref:0:low:Accept RA router preference"
    "net.ipv6.conf.all.autoconf:0:low:IPv6 stateless autoconfiguration"
    "net.ipv6.conf.all.dad_transmits:0:low:Duplicate address detection transmits"

    # ASLR is deliberately absent: it has its own check, and listing it here
    # too double-counts ASLR-off in the score.
    "kernel.dmesg_restrict:1:medium:Restrict dmesg access"
    "kernel.kptr_restrict:2:medium:Restrict kernel pointer exposure"
    "kernel.yama.ptrace_scope:1:medium:Restrict ptrace"
    "fs.suid_dumpable:0:medium:Disable SUID core dumps"
    "fs.protected_hardlinks:1:medium:Hardlink protection"
    "fs.protected_symlinks:1:medium:Symlink protection"
    "kernel.core_uses_pid:1:low:Core dump filename includes PID"

    # unprivileged_userns_clone stays MEDIUM: disabling it breaks rootless
    # containers, snap and browser sandboxes, and Debian ships =1 by default.
    # A real mitigation, but not one worth driving users into that loop.
    "kernel.unprivileged_userns_clone:0:medium:Disable unprivileged user namespaces (defence-in-depth; breaks Docker rootless / podman / snap / Chrome sandbox if enabled)"
    # Worth doing on hardened hosts but not a default-broken
    # kernel — keep at medium.
    "kernel.unprivileged_bpf_disabled:1:medium:Disable unprivileged BPF (exploit prevention)"
    "net.core.bpf_jit_harden:2:medium:BPF JIT hardening"
    "kernel.sysrq:0|176:medium:Disable Magic SysRq key (0, or 176 for the safe subset)"
    "kernel.perf_event_paranoid:3:medium:Restrict perf events"
    "fs.protected_fifos:2:low:FIFO protection"
    "fs.protected_regular:2:low:Regular file protection"
    # Console/console-equivalent attack surface (Lynis KRNL-6000 cross-check)
    "kernel.core_setuid_ok:0:low:SUID core dumps disabled (defence-in-depth)"
    "kernel.ctrl-alt-del:0:low:Console Ctrl-Alt-Del bypass disabled"
    # TTY line discipline autoload — CVE-2019-13272 / CVE-2020-14381
    # exploit primitive lives here. Mainline default is 0 since 5.x;
    # flag anything else.
    "dev.tty.ldisc_autoload:0:low:TTY line discipline autoload restricted"
)

# --- Kernel Helper Functions ---

# Detect if running in a container (OpenVZ, LXC, Docker)
# Many kernel parameters cannot be modified in containers
_kernel_is_container() {
    # Check for OpenVZ
    if [[ -f /proc/vz/veinfo ]] || [[ -d /proc/vz ]]; then
        echo "openvz"
        return 0
    fi

    # Check for LXC
    if grep -qa "lxc" /proc/1/cgroup 2>/dev/null; then
        echo "lxc"
        return 0
    fi

    # Check for Docker
    if [[ -f /.dockerenv ]] || grep -qa "docker" /proc/1/cgroup 2>/dev/null; then
        echo "docker"
        return 0
    fi

    # Check for systemd-nspawn
    if grep -qa "machine.slice" /proc/1/cgroup 2>/dev/null; then
        echo "nspawn"
        return 0
    fi

    # Check /proc/1/environ for container hints
    if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -q "container="; then
        echo "container"
        return 0
    fi

    # Not a container
    return 1
}

# Check if a kernel parameter is modifiable (not read-only in container)
_kernel_param_modifiable() {
    local param="$1"

    # Try to read the current value
    if ! sysctl -n "$param" &>/dev/null; then
        return 1  # Parameter doesn't exist
    fi

    # In containers, some params are read-only
    # Try a dry-run write (this won't actually change anything)
    local current
    current=$(sysctl -n "$param" 2>/dev/null)

    # Check if the sysctl file is writable
    local sysctl_file="/proc/sys/${param//\.//}"
    if [[ -f "$sysctl_file" ]] && [[ ! -w "$sysctl_file" ]]; then
        return 1  # Read-only
    fi

    return 0
}

# Get current sysctl value
_kernel_get_sysctl() {
    local param="$1"
    sysctl -n "$param" 2>/dev/null
}

# Check if parameter matches expected value
_kernel_check_param() {
    local param="$1"
    local expected="$2"

    local actual
    actual=$(_kernel_get_sysctl "$param")

    if [[ -z "$actual" ]]; then
        echo "unavailable"
        return 2  # Parameter not available
    fi

    # `expected` may be a |-separated set of acceptable values, e.g. sysrq
    # "0|176" where both the disabled and the safe-subset value are fine.
    # A single value splits into one token, so other params are unaffected.
    local exp
    local IFS='|'
    for exp in $expected; do
        [[ "$actual" == "$exp" ]] && return 0  # Correct
    done

    echo "$actual"
    return 1  # Incorrect
}

# Check ASLR status
_kernel_check_aslr() {
    local value
    value=$(_kernel_get_sysctl "kernel.randomize_va_space")

    case "$value" in
        2) echo "full" ;;      # Full randomization
        1) echo "partial" ;;   # Partial randomization
        0) echo "disabled" ;;  # Disabled
        *) echo "unknown" ;;
    esac
}

# True when something here legitimately needs IP forwarding: container
# runtimes, VM hosts, mesh-VPN subnet routers, Kubernetes nodes. Mesh VPNs
# matter — they are the most common ip_forward=1 source on a cloud VPS.
_kernel_ip_forward_needed() {
    # Container / VM runtimes
    systemctl is-active --quiet docker 2>/dev/null && return 0
    systemctl is-active --quiet podman 2>/dev/null && return 0
    systemctl is-active --quiet lxc 2>/dev/null && return 0
    systemctl is-active --quiet lxd 2>/dev/null && return 0
    systemctl is-active --quiet incus 2>/dev/null && return 0
    systemctl is-active --quiet libvirtd 2>/dev/null && return 0

    # VPN / mesh-network daemons. tailscaled and openvpn(.service)
    # match directly; wg-quick@<iface>.service and openvpn-{client,
    # server}@<name>.service are template units and need a listing scan.
    systemctl is-active --quiet tailscaled 2>/dev/null && return 0
    systemctl is-active --quiet openvpn 2>/dev/null && return 0
    if systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
        | awk '{print $1}' \
        | grep -qE '^(wg-quick@|openvpn-(client|server)@)'; then
        return 0
    fi

    # Kubernetes node
    systemctl is-active --quiet k3s 2>/dev/null && return 0
    systemctl is-active --quiet kubelet 2>/dev/null && return 0

    # Wireguard via manual `ip link add` (no systemd unit). Cheaper
    # than `wg show` and works without the wireguard-tools package.
    if command -v ip >/dev/null 2>&1; then
        ip -br link show type wireguard 2>/dev/null | grep -q . && return 0
    fi

    return 1
}

# --- IPv6 Detection Functions ---

# Check if IPv6 is enabled system-wide
_kernel_ipv6_enabled() {
    # Check kernel module
    if [[ -d /proc/sys/net/ipv6 ]]; then
        # Check if disabled via sysctl
        local disabled=$(_kernel_get_sysctl "net.ipv6.conf.all.disable_ipv6")
        [[ "$disabled" != "1" ]]
        return $?
    fi
    return 1
}

# Check if IPv6 is actively used (has global addresses)
_kernel_ipv6_in_use() {
    # Check for global IPv6 addresses (not link-local fe80::)
    ip -6 addr show scope global 2>/dev/null | grep -q "inet6" 2>/dev/null
}

# Get IPv6 statistics
_kernel_ipv6_get_stats() {
    local stats=""

    # `|| true`, never `|| echo 0`: grep -c already prints 0 on no matches,
    # so the fallback appends a second one and breaks the arithmetic.

    # Count interfaces with IPv6
    local iface_count
    iface_count=$(ip -6 addr show 2>/dev/null | grep -c "inet6" || true)
    iface_count="${iface_count:-0}"
    stats+="interfaces:$iface_count;"

    # Count global addresses
    local global_count
    global_count=$(ip -6 addr show scope global 2>/dev/null | grep -c "inet6" || true)
    global_count="${global_count:-0}"
    stats+="global:$global_count;"

    # Check if IPv6 forwarding is enabled
    local forward=$(_kernel_get_sysctl "net.ipv6.conf.all.forwarding")
    stats+="forwarding:${forward:-0};"

    # Check for IPv6 default route
    if ip -6 route show default 2>/dev/null | grep -q "default"; then
        stats+="default_route:yes"
    else
        stats+="default_route:no"
    fi

    echo "$stats"
}

# Check for IPv6-specific security issues
_kernel_ipv6_check_security() {
    local issues=()

    # 1. Check if IPv6 is enabled but not secured
    if _kernel_ipv6_enabled; then
        # Check Router Advertisements (MITM vector)
        local accept_ra=$(_kernel_get_sysctl "net.ipv6.conf.all.accept_ra")
        if [[ "$accept_ra" == "1" ]]; then
            issues+=("accept_ra_enabled")
        fi

        # Check if forwarding is unexpectedly enabled
        local forward=$(_kernel_get_sysctl "net.ipv6.conf.all.forwarding")
        if [[ "$forward" == "1" ]] && ! _kernel_ip_forward_needed; then
            issues+=("forwarding_enabled")
        fi

        # Check privacy extensions
        local tempaddr=$(_kernel_get_sysctl "net.ipv6.conf.all.use_tempaddr")
        if [[ "$tempaddr" != "2" ]]; then
            issues+=("privacy_extensions_weak")
        fi

        # Check accept_redirects
        local redirects=$(_kernel_get_sysctl "net.ipv6.conf.all.accept_redirects")
        if [[ "$redirects" == "1" ]]; then
            issues+=("accept_redirects_enabled")
        fi
    fi

    echo "${issues[*]}"
}

# Check for dual-stack firewall consistency
_kernel_ipv6_firewall_check() {
    local result="unknown"

    # Only when ufw is ACTIVE: a stock inactive ufw already has IPV6=yes and
    # filters nothing. Inactive falls through to the raw probes below.
    if check_command ufw && LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
        if grep -q "IPV6=yes" /etc/default/ufw 2>/dev/null; then
            result="ufw_ipv6_enabled"
        else
            result="ufw_ipv6_disabled"
        fi
    # Check if ip6tables has rules
    elif check_command ip6tables; then
        local rule_count
        # grep -c already emits a single integer, so the previous
        # `| head -1` was dead; kept the defensive regex strip below
        # for robustness.
        rule_count=$(ip6tables -L -n 2>/dev/null | grep -cv "^Chain\|^target\|^$" || true)
        rule_count="${rule_count//[^0-9]/}"
        [[ -z "$rule_count" ]] && rule_count=0
        if [[ "$rule_count" -gt 0 ]]; then
            result="ip6tables_configured"
        else
            result="ip6tables_empty"
        fi
    # Check nftables
    elif check_command nft; then
        if nft list tables 2>/dev/null | grep -q "ip6\|inet"; then
            result="nftables_ipv6_configured"
        else
            result="nftables_ipv6_missing"
        fi
    fi

    echo "$result"
}

# Check core dump settings
_kernel_check_core_dump() {
    local issues=()

    # Check fs.suid_dumpable
    local suid_dump
    suid_dump=$(_kernel_get_sysctl "fs.suid_dumpable")
    if [[ "$suid_dump" != "0" ]]; then
        issues+=("suid_dumpable=$suid_dump")
    fi

    # Check limits.conf for core limits
    if [[ -f "$KERNEL_LIMITS_CONF" ]]; then
        if ! grep -qE "^\*\s+(soft|hard)\s+core\s+0" "$KERNEL_LIMITS_CONF" 2>/dev/null; then
            issues+=("no_core_limit")
        fi
    fi

    # Storage=none may live in the main coredump.conf OR a drop-in, which is
    # where the fix writes it and how systemd merges. Read BOTH, or the audit
    # keeps flagging a host the fix already handled.
    if [[ -f "$KERNEL_COREDUMP_CONF" || -d "$KERNEL_COREDUMP_D" ]]; then
        if ! grep -rqsE "^[[:space:]]*Storage=none" \
                "$KERNEL_COREDUMP_CONF" "$KERNEL_COREDUMP_D/" 2>/dev/null; then
            issues+=("systemd_coredump")
        fi
    fi

    echo "${issues[*]}"
}

# --- Kernel Audit ---

kernel_audit() {
    local module="kernel"

    # Check if running in a container first
    local container_type
    container_type=$(_kernel_is_container)
    if [[ -n "$container_type" ]]; then
        print_item "$(i18n 'kernel.check_container')"
        local check=$(create_check_json \
            "kernel.container_detected" \
            "kernel" \
            "low" \
            "info" \
            "$(i18n 'kernel.container_detected' "type=$container_type")" \
            "$(i18n 'kernel.container_limitations')" \
            "" \
            "")
        state_add_check "$check"
        print_info "$(i18n 'kernel.container_detected' "type=$container_type")"
        print_info "$(i18n 'kernel.container_limitations')"
    fi

    # Check ASLR
    print_item "$(i18n 'kernel.check_aslr')"
    _kernel_audit_aslr

    # Check network security parameters
    print_item "$(i18n 'kernel.check_network_params')"
    _kernel_audit_network_params

    # Check IPv6 security (dedicated section)
    print_item "$(i18n 'kernel.check_ipv6')"
    _kernel_audit_ipv6

    # Check kernel security parameters
    print_item "$(i18n 'kernel.check_kernel_params')"
    _kernel_audit_kernel_params

    # Check core dump settings
    print_item "$(i18n 'kernel.check_core_dump')"
    _kernel_audit_core_dump

    # Check rarely-used network protocol modules (Lynis NETW-3200)
    print_item "$(i18n 'kernel.check_unused_protocols')"
    _kernel_audit_unused_protocols
}

# Are the rarely-used protocol modules blacklisted? dccp/sctp/rds/tipc ship
# enabled but are almost never needed on a server.
_kernel_audit_unused_protocols() {
    local protocols=("dccp" "sctp" "rds" "tipc")
    local unblocked=()
    local search_paths=(/etc/modprobe.d /usr/lib/modprobe.d /run/modprobe.d /lib/modprobe.d)
    local existing=()
    local p
    for p in "${search_paths[@]}"; do
        [[ -d "$p" ]] && existing+=("$p")
    done

    local proto
    for proto in "${protocols[@]}"; do
        local blocked=0
        if (( ${#existing[@]} > 0 )); then
            # Match: `install <proto> /bin/(true|false)` or `blacklist <proto>`
            if grep -rqsE "^[[:space:]]*(install[[:space:]]+${proto}[[:space:]]+/bin/(true|false)|blacklist[[:space:]]+${proto})([[:space:]]|$)" "${existing[@]}"; then
                blocked=1
            fi
        fi
        (( blocked == 0 )) && unblocked+=("$proto")
    done

    if (( ${#unblocked[@]} > 0 )); then
        local list="${unblocked[*]}"
        local check=$(create_check_json \
            "kernel.unused_protocols_unblocked" \
            "kernel" \
            "low" \
            "failed" \
            "$(i18n 'kernel.unused_protocols_unblocked' "count=${#unblocked[@]}")" \
            "$(i18n 'kernel.unused_protocols_unblocked_desc' "list=$list")" \
            "$(i18n 'kernel.unused_protocols_unblocked_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'kernel.unused_protocols_unblocked' "count=${#unblocked[@]}")"
    else
        local check=$(create_check_json \
            "kernel.unused_protocols_blocked" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.unused_protocols_blocked')" \
            "$(i18n 'kernel.unused_protocols_blocked_desc' "protocols=${protocols[*]}")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'kernel.unused_protocols_blocked')"
    fi
}

# --- IPv6 Audit Function ---

_kernel_audit_ipv6() {
    # Check if IPv6 is enabled
    if ! _kernel_ipv6_enabled; then
        local check=$(create_check_json \
            "kernel.ipv6_disabled" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.ipv6_disabled')" \
            "$(i18n 'kernel.ipv6_disabled_desc')" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'kernel.ipv6_disabled')"
        return
    fi

    # IPv6 is enabled - check if it's actively used
    local ipv6_stats=$(_kernel_ipv6_get_stats)
    local ipv6_in_use=$(_kernel_ipv6_in_use && echo "yes" || echo "no")
    local ipv6_issues=$(_kernel_ipv6_check_security)
    local ipv6_fw=$(_kernel_ipv6_firewall_check)

    # Report IPv6 status
    if [[ "$ipv6_in_use" == "yes" ]]; then
        # IPv6 is actively used
        local issue_count=$(echo "$ipv6_issues" | wc -w)

        if [[ "$issue_count" -gt 0 ]]; then
            local check=$(create_check_json \
                "kernel.ipv6_insecure" \
                "kernel" \
                "low" \
                "failed" \
                "$(i18n 'kernel.ipv6_insecure' "count=$issue_count")" \
                "$(i18n 'kernel.ipv6_insecure_desc' "ipv6_issues=$ipv6_issues")" \
                "$(i18n 'kernel.fix_ipv6')" \
                "kernel.harden_ipv6")
            state_add_check "$check"
            print_severity "low" "$(i18n 'kernel.ipv6_insecure' "count=$issue_count")"
        else
            local check=$(create_check_json \
                "kernel.ipv6_secure" \
                "kernel" \
                "low" \
                "passed" \
                "$(i18n 'kernel.ipv6_secure')" \
                "$(i18n 'kernel.ipv6_secure_desc')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'kernel.ipv6_secure')"
        fi
    else
        # IPv6 enabled but not actively used
        local issue_count=$(echo "$ipv6_issues" | wc -w)

        if [[ "$issue_count" -gt 2 ]]; then
            local check=$(create_check_json \
                "kernel.ipv6_unused_insecure" \
                "kernel" \
                "low" \
                "failed" \
                "$(i18n 'kernel.ipv6_unused_insecure')" \
                "$(i18n 'kernel.ipv6_unused_insecure_desc')" \
                "$(i18n 'kernel.ipv6_unused_insecure_suggestion')" \
                "kernel.harden_ipv6")
            state_add_check "$check"
            print_severity "low" "$(i18n 'kernel.ipv6_unused_insecure')"
        else
            local check=$(create_check_json \
                "kernel.ipv6_enabled_unused" \
                "kernel" \
                "low" \
                "passed" \
                "$(i18n 'kernel.ipv6_enabled_unused')" \
                "$(i18n 'kernel.ipv6_enabled_unused_desc')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'kernel.ipv6_enabled_unused')"
        fi
    fi

    # Check IPv6 firewall consistency (only if IPv6 is in use)
    if [[ "$ipv6_in_use" == "yes" ]]; then
        case "$ipv6_fw" in
            ufw_ipv6_disabled|ip6tables_empty|nftables_ipv6_missing)
                local check=$(create_check_json \
                    "kernel.ipv6_firewall_missing" \
                    "kernel" \
                    "medium" \
                    "failed" \
                    "$(i18n 'kernel.ipv6_firewall_missing')" \
                    "$(i18n 'kernel.ipv6_firewall_missing_desc')" \
                    "$(i18n 'kernel.ipv6_firewall_missing_suggestion')" \
                    "")
                state_add_check "$check"
                print_severity "medium" "$(i18n 'kernel.ipv6_firewall_missing')"
                ;;
            ufw_ipv6_enabled|ip6tables_configured|nftables_ipv6_configured)
                local check=$(create_check_json \
                    "kernel.ipv6_firewall_ok" \
                    "kernel" \
                    "low" \
                    "passed" \
                    "$(i18n 'kernel.ipv6_firewall_ok')" \
                    "$(i18n 'kernel.ipv6_firewall_ok_desc')" \
                    "" \
                    "")
                state_add_check "$check"
                print_ok "$(i18n 'kernel.ipv6_firewall_ok')"
                ;;
        esac
    fi
}

_kernel_audit_aslr() {
    local aslr_status
    aslr_status=$(_kernel_check_aslr)

    case "$aslr_status" in
        full)
            local check=$(create_check_json \
                "kernel.aslr_full" \
                "kernel" \
                "low" \
                "passed" \
                "$(i18n 'kernel.aslr_enabled')" \
                "$(i18n 'kernel.aslr_full_desc')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'kernel.aslr_enabled') (full)"
            ;;
        partial)
            local check=$(create_check_json \
                "kernel.aslr_partial" \
                "kernel" \
                "low" \
                "failed" \
                "$(i18n 'kernel.aslr_partial')" \
                "$(i18n 'kernel.aslr_partial_desc')" \
                "$(i18n 'kernel.fix_aslr')" \
                "kernel.enable_aslr")
            state_add_check "$check"
            print_severity "low" "$(i18n 'kernel.aslr_partial')"
            ;;
        disabled)
            local check=$(create_check_json \
                "kernel.aslr_disabled" \
                "kernel" \
                "medium" \
                "failed" \
                "$(i18n 'kernel.aslr_disabled')" \
                "$(i18n 'kernel.aslr_disabled_desc')" \
                "$(i18n 'kernel.fix_aslr')" \
                "kernel.enable_aslr")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'kernel.aslr_disabled')"
            ;;
        *)
            local check=$(create_check_json \
                "kernel.aslr_unknown" \
                "kernel" \
                "low" \
                "failed" \
                "$(i18n 'kernel.aslr_unknown')" \
                "" \
                "" \
                "")
            state_add_check "$check"
            print_severity "low" "Cannot determine ASLR status"
            ;;
    esac
}

_kernel_audit_network_params() {
    local issues_high=()
    local issues_medium=()
    local issues_low=()
    local passed=0

    # On a SLAAC host accept_ra=1 / autoconf=1 are the CORRECT values, so
    # skip them rather than raise a finding the fix must never act on.
    local host_uses_ra=false
    _kernel_ipv6_uses_ra && host_uses_ra=true

    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        local param="${entry%%:*}"
        local rest="${entry#*:}"
        local expected="${rest%%:*}"
        rest="${rest#*:}"
        local severity="${rest%%:*}"
        local desc="${rest#*:}"

        # Skip non-network params here
        if [[ ! "$param" =~ ^net\. ]]; then
            continue
        fi

        # Special handling for ip_forward
        if [[ "$param" == "net.ipv4.ip_forward" ]] && _kernel_ip_forward_needed; then
            # IP forwarding is needed for Docker/LXC/Tailscale/WG/k3s/...
            continue
        fi

        # On a forwarding host rp_filter=2 (loose) is correct — strict mode
        # drops the asymmetric-return packets those workloads produce.
        # rp_filter=0 is still flagged: it permits spoofed source addresses.
        if [[ "$param" =~ ^net\.ipv4\.conf\.(all|default)\.rp_filter$ ]] \
           && _kernel_ip_forward_needed; then
            local rp_val
            rp_val=$(_kernel_get_sysctl "$param" 2>/dev/null)
            [[ "$rp_val" == "2" ]] && continue
        fi

        # On RA/SLAAC hosts the RA-dependent params are correct as-is.
        if [[ "$host_uses_ra" == "true" ]] && _kernel_param_is_ra_dependent "$param"; then
            continue
        fi

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        local result=$?

        if [[ $result -eq 0 ]]; then
            ((passed++))
        elif [[ $result -eq 1 ]]; then
            case "$severity" in
                high)   issues_high+=("$param=$actual (expected $expected)") ;;
                medium) issues_medium+=("$param=$actual") ;;
                low)    issues_low+=("$param=$actual") ;;
            esac
        fi
        # result=2 means parameter unavailable, skip
    done

    local total_issues=$((${#issues_high[@]} + ${#issues_medium[@]} + ${#issues_low[@]}))

    # Severity is capped ONE tier below the parameter's weight, so the
    # *_high / *_medium check_ids name the source group, not the severity.
    # `desc` MUST list EVERY offending parameter, never a truncated head.
    if [[ ${#issues_high[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_high[@]}" | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.network_params_high" \
            "kernel" \
            "medium" \
            "failed" \
            "$(i18n 'kernel.network_params_insecure' "count=${#issues_high[@]}")" \
            "$(i18n 'kernel.network_params_high_desc' "list=$issue_list")" \
            "$(i18n 'kernel.fix_network_params')" \
            "kernel.harden_network")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'kernel.network_params_insecure' "count=${#issues_high[@]}")"
    fi

    # Medium and low report together, because the fix applies every net.*
    # param regardless of tier. A tier with no emit branch still counts
    # toward total_issues and suppresses the OK branch.
    local issues_weak=("${issues_medium[@]}" "${issues_low[@]}")
    if [[ ${#issues_weak[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_weak[@]}" | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.network_params_medium" \
            "kernel" \
            "low" \
            "failed" \
            "$(i18n 'kernel.network_params_weak' "count=${#issues_weak[@]}")" \
            "$(i18n 'kernel.network_params_medium_desc' "list=$issue_list")" \
            "$(i18n 'kernel.fix_network_params')" \
            "kernel.harden_network")
        state_add_check "$check"
        print_severity "low" "$(i18n 'kernel.network_params_weak' "count=${#issues_weak[@]}")"
    fi

    if [[ $total_issues -eq 0 ]]; then
        # Zero issues from reading ZERO parameters is not a pass — it is a
        # /proc/sys we could not ask. failed + info, unscored, same pattern
        # as update.check_failed.
        if (( passed == 0 )); then
            local check=$(create_check_json \
                "kernel.network_params_unreadable" \
                "kernel" \
                "low" \
                "failed" \
                "$(i18n 'kernel.network_params_unreadable')" \
                "$(i18n 'kernel.network_params_unreadable_desc')" \
                "" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'kernel.network_params_unreadable')"
            return 0
        fi
        local check=$(create_check_json \
            "kernel.network_params_ok" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.network_params_ok')" \
            "$(i18n 'kernel.network_params_ok_desc' "passed=$passed")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'kernel.network_params_ok')"
    fi
}

_kernel_audit_kernel_params() {
    local issues_high=()
    local issues_medium=()
    local issues_low=()
    local unavailable=()
    local passed=0

    # Check if we're in a container
    local in_container=false
    if _kernel_is_container &>/dev/null; then
        in_container=true
    fi

    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        local param="${entry%%:*}"
        local rest="${entry#*:}"
        local expected="${rest%%:*}"
        rest="${rest#*:}"
        local severity="${rest%%:*}"
        local desc="${rest#*:}"

        # kernel.* / fs.* / dev.* only. dev.* must stay in this list: the
        # fix side routes on the same prefixes, and a mismatch means the
        # param is audited but never fixed.
        if [[ ! "$param" =~ ^(kernel\.|fs\.|dev\.) ]]; then
            continue
        fi

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        local result=$?

        if [[ $result -eq 0 ]]; then
            ((passed++))
        elif [[ $result -eq 2 ]]; then
            # Parameter unavailable (common in containers)
            unavailable+=("$param")
        elif [[ $result -eq 1 ]]; then
            case "$severity" in
                high)   issues_high+=("$param=$actual (expected $expected)") ;;
                medium) issues_medium+=("$param=$actual") ;;
                low)    issues_low+=("$param=$actual") ;;
            esac
        fi
    done

    local total_issues=$((${#issues_high[@]} + ${#issues_medium[@]} + ${#issues_low[@]}))

    # Report any high-severity kernel params separately. (Currently none in
    # KERNEL_SECURITY_PARAMS are tagged high — ASLR has its own check — so
    # this branch is dormant; kept for forward-compat if a high param is added.)
    if [[ ${#issues_high[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_high[@]}" | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.kernel_params_high" \
            "kernel" \
            "medium" \
            "failed" \
            "$(i18n 'kernel.kernel_params_critical' "count=${#issues_high[@]}")" \
            "$(i18n 'kernel.kernel_params_high_desc' "list=$issue_list")" \
            "$(i18n 'kernel.fix_kernel_params')" \
            "kernel.harden_kernel")
        state_add_check "$check"
        print_severity "medium" "Critical kernel hardening issues: ${#issues_high[@]}"
    fi

    # Report medium AND low tiers together (see _kernel_audit_network_params for
    # the rationale): the low tier had no emit branch yet counted toward
    # total_issues, so low-only deviations went completely silent.
    local issues_weak=("${issues_medium[@]}" "${issues_low[@]}")
    if [[ ${#issues_weak[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_weak[@]}" | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.kernel_params_weak" \
            "kernel" \
            "low" \
            "failed" \
            "$(i18n 'kernel.kernel_params_weak' "count=${#issues_weak[@]}")" \
            "$(i18n 'kernel.kernel_params_weak_desc' "list=$issue_list")" \
            "$(i18n 'kernel.fix_kernel_params')" \
            "kernel.harden_kernel")
        state_add_check "$check"
        print_severity "low" "$(i18n 'kernel.kernel_params_weak' "count=${#issues_weak[@]}")"
    fi

    # Report unavailable parameters (info only, not penalized)
    if [[ ${#unavailable[@]} -gt 0 ]] && [[ "$in_container" == true ]]; then
        local unavail_list=$(printf '%s ' "${unavailable[@]}")
        log_debug "Unavailable kernel params (container): $unavail_list"
    fi

    if [[ $total_issues -eq 0 ]]; then
        local check=$(create_check_json \
            "kernel.kernel_params_ok" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.kernel_params_ok')" \
            "$(i18n 'kernel.kernel_params_ok_desc' "passed=$passed")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'kernel.kernel_params_ok')"
    fi
}

_kernel_audit_core_dump() {
    local issues
    issues=$(_kernel_check_core_dump)

    if [[ -z "$issues" ]]; then
        local check=$(create_check_json \
            "kernel.core_dump_ok" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.core_dump_disabled')" \
            "$(i18n 'kernel.core_dump_ok_desc')" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'kernel.core_dump_disabled')"
    else
        local check=$(create_check_json \
            "kernel.core_dump_enabled" \
            "kernel" \
            "low" \
            "failed" \
            "$(i18n 'kernel.core_dump_enabled')" \
            "$(i18n 'kernel.core_dump_enabled_desc' "issues=$issues")" \
            "$(i18n 'kernel.fix_core_dump')" \
            "kernel.disable_core_dump")
        state_add_check "$check"
        print_severity "low" "$(i18n 'kernel.core_dump_enabled')"
    fi
}

# --- Kernel Fix Functions ---

kernel_fix() {
    local fix_id="$1"

    case "$fix_id" in
        kernel.enable_aslr)
            _kernel_fix_aslr
            ;;
        kernel.harden_network)
            _kernel_fix_network_params
            ;;
        kernel.harden_kernel)
            _kernel_fix_kernel_params
            ;;
        kernel.harden_ipv6)
            _kernel_fix_ipv6
            ;;
        kernel.disable_core_dump)
            _kernel_fix_core_dump
            ;;
        kernel.harden_all)
            _kernel_fix_all
            ;;
        *)
            log_error "Unknown kernel fix: $fix_id"
            return 1
            ;;
    esac
}

# --- IPv6 Fix Function ---

# True when the IPv6 default route comes from Router Advertisements, OR when
# that cannot be determined. Fail-safe: an unprobeable host is assumed to be
# on RA, so the caller SKIPS accept_ra rather than cutting IPv6.
_kernel_ipv6_uses_ra() {
    command -v ip >/dev/null 2>&1 || return 0

    # "The probe failed" and "the probe says no RA route" MUST stay apart:
    # piping straight into grep collapses them, and an `ip` that cannot answer
    # then reads as a statically configured host.
    local routes
    routes=$(ip -6 route show default 2>/dev/null) || return 0

    grep -q 'proto ra' <<<"$routes"
}

# The IPv6 params that would tear down a SLAAC default route if disabled.
# EVERY path that writes accept_ra must consult this — one unguarded path is
# enough to re-introduce the lockout.
_kernel_param_is_ra_dependent() {
    case "$1" in
        net.ipv6.conf.*.accept_ra|\
        net.ipv6.conf.*.accept_ra_defrtr|\
        net.ipv6.conf.*.accept_ra_pinfo|\
        net.ipv6.conf.*.accept_ra_rtr_pref|\
        net.ipv6.conf.*.autoconf|\
        net.ipv6.conf.*.max_addresses|\
        net.ipv6.conf.*.dad_transmits)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

_kernel_fix_ipv6() {
    print_info "$(i18n 'kernel.hardening_ipv6')"

    # Always-safe params: these harden IPv6 without changing how the host
    # obtains its address or default route.
    local ipv6_params=(
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_source_route=0"
        "net.ipv6.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.use_tempaddr=2"
        "net.ipv6.conf.default.use_tempaddr=2"
    )

    # RA-disabling params remove the SLAAC default route and global address,
    # so apply them ONLY on a host that does not rely on RA.
    if _kernel_ipv6_uses_ra; then
        print_warn "$(i18n 'kernel.ipv6_ra_skipped')"
        log_warn "kernel.harden_ipv6: host uses RA/SLAAC for its IPv6 default route; skipping accept_ra=0 to preserve connectivity"
    else
        ipv6_params+=(
            "net.ipv6.conf.all.accept_ra=0"
            "net.ipv6.conf.default.accept_ra=0"
            "net.ipv6.conf.all.accept_ra_defrtr=0"
            "net.ipv6.conf.all.accept_ra_pinfo=0"
            "net.ipv6.conf.all.accept_ra_rtr_pref=0"
        )
    fi

    local fixed=0
    local persist_failed=0

    for setting in "${ipv6_params[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        # A parameter counts as fixed only when runtime AND persistence
        # both landed — a runtime-only success evaporates on reboot.
        if sysctl -w "$param=$value" 2>/dev/null; then
            if _kernel_write_sysctl "$param" "$value"; then
                ((fixed++)) || true
            else
                ((persist_failed++)) || true
            fi
        fi
    done

    # Reload once after the batch; _kernel_write_sysctl no longer reloads
    # per-call (previously: N params = N reloads).
    ((fixed > 0)) && _kernel_reload_sysctl_dropin

    if (( persist_failed > 0 )); then
        print_error "$(i18n 'kernel.persist_failed' "count=$persist_failed")"
        return 1
    fi
    if [[ "$fixed" -gt 0 ]]; then
        print_ok "$(i18n 'kernel.ipv6_hardened' "count=$fixed")"
        return 0
    else
        print_warn "$(i18n 'kernel.ipv6_harden_failed')"
        return 1
    fi
}

_kernel_fix_aslr() {
    print_info "$(i18n 'kernel.enabling_aslr')"

    # Apply immediately (the audit-predicate postcondition below verifies
    # the runtime value, so the write itself may be fire-and-forget).
    sysctl -w kernel.randomize_va_space=2 2>/dev/null || true

    # A failed persist is a failed fix: a runtime-only success reverts to
    # weak ASLR on reboot with a "completed" entry in ok.json.
    if ! _kernel_write_sysctl "kernel.randomize_va_space" "2"; then
        print_error "$(i18n 'kernel.persist_failed' "count=1")"
        return 1
    fi
    _kernel_reload_sysctl_dropin

    if [[ "$(_kernel_check_aslr)" == "full" ]]; then
        print_ok "$(i18n 'kernel.aslr_enabled')"
        return 0
    else
        print_error "$(i18n 'kernel.aslr_enable_failed')"
        return 1
    fi
}

_kernel_fix_network_params() {
    print_info "$(i18n 'kernel.hardening_network')"

    local params_to_set=()

    # Same RA guard as _kernel_fix_ipv6: disabling accept_ra or autoconf on
    # a SLAAC host drops IPv6 connectivity.
    local host_uses_ra=false
    _kernel_ipv6_uses_ra && host_uses_ra=true
    local ra_skipped=false

    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        local param="${entry%%:*}"
        local rest="${entry#*:}"
        local expected="${rest%%:*}"

        # Only network params
        if [[ ! "$param" =~ ^net\. ]]; then
            continue
        fi

        # Special handling for ip_forward
        if [[ "$param" == "net.ipv4.ip_forward" ]] && _kernel_ip_forward_needed; then
            continue
        fi

        # Mirrors the audit's rp_filter exception. Without it, harden_network
        # triggered for some other parameter breaks exactly the config the
        # audit deliberately accepted.
        if [[ "$param" =~ ^net\.ipv4\.conf\.(all|default)\.rp_filter$ ]] \
           && _kernel_ip_forward_needed; then
            local rp_val
            rp_val=$(_kernel_get_sysctl "$param" 2>/dev/null)
            [[ "$rp_val" == "2" ]] && continue
        fi

        # Skip RA-dependent params on SLAAC hosts (see top of function).
        if [[ "$host_uses_ra" == "true" ]] && _kernel_param_is_ra_dependent "$param"; then
            ra_skipped=true
            continue
        fi

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        # `expected` may be a |-set (e.g. sysrq 0|176); set the canonical
        # (first) value, never the literal "0|176".
        if [[ $? -eq 1 ]]; then
            params_to_set+=("$param=${expected%%|*}")
        fi
    done

    [[ "$ra_skipped" == "true" ]] && print_warn "$(i18n 'kernel.ipv6_ra_skipped')"

    if [[ ${#params_to_set[@]} -eq 0 ]]; then
        print_ok "$(i18n 'kernel.network_already_hardened')"
        return 0
    fi

    # Count what actually landed. Fix bodies run with errexit off, so bare
    # failing writes fall through and the summary below would report
    # "hardened N" for writes that all bounced.
    local applied=0 apply_failed=0
    for setting in "${params_to_set[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        if sysctl -w "$param=$value" 2>/dev/null && \
           _kernel_write_sysctl "$param" "$value"; then
            ((applied++)) || true
        else
            ((apply_failed++)) || true
        fi
    done

    ((applied > 0)) && _kernel_reload_sysctl_dropin

    if (( apply_failed > 0 )); then
        print_error "$(i18n 'kernel.persist_failed' "count=$apply_failed")"
        return 1
    fi
    print_ok "$(i18n 'kernel.network_hardened' "count=$applied")"
    return 0
}

_kernel_fix_kernel_params() {
    print_info "$(i18n 'kernel.hardening_kernel')"

    local params_to_set=()

    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        local param="${entry%%:*}"
        local rest="${entry#*:}"
        local expected="${rest%%:*}"

        # Must match the audit scope in _kernel_audit_kernel_params exactly,
        # or a param is audited but silently skipped by the fix.
        if [[ ! "$param" =~ ^(kernel\.|fs\.|dev\.) ]]; then
            continue
        fi

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        # Set the canonical (first) value of a |-set (e.g. sysrq 0|176 → 0).
        if [[ $? -eq 1 ]]; then
            params_to_set+=("$param=${expected%%|*}")
        fi
    done

    if [[ ${#params_to_set[@]} -eq 0 ]]; then
        print_ok "$(i18n 'kernel.kernel_already_hardened')"
        return 0
    fi

    # Apply and persist — same counted pattern (and rationale) as
    # _kernel_fix_network_params above.
    local applied=0 apply_failed=0
    for setting in "${params_to_set[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        if sysctl -w "$param=$value" 2>/dev/null && \
           _kernel_write_sysctl "$param" "$value"; then
            ((applied++)) || true
        else
            ((apply_failed++)) || true
        fi
    done

    ((applied > 0)) && _kernel_reload_sysctl_dropin

    if (( apply_failed > 0 )); then
        print_error "$(i18n 'kernel.persist_failed' "count=$apply_failed")"
        return 1
    fi
    print_ok "$(i18n 'kernel.kernel_hardened' "count=$applied")"
    return 0
}

_kernel_fix_core_dump() {
    print_info "$(i18n 'kernel.disabling_core_dump')"

    # Disable via sysctl. The persist status is checked because the
    # postcondition below reads the RUNTIME value, which `sysctl -w` just set:
    # a drop-in that never got written would pass it and revert at reboot.
    sysctl -w fs.suid_dumpable=0 2>/dev/null
    _kernel_write_sysctl "fs.suid_dumpable" "0" || return 1
    _kernel_reload_sysctl_dropin

    # PAM reads limits.conf on every login, so append through the atomic
    # writer: a partial line is a config error on every later login.
    if [[ -f "$KERNEL_LIMITS_CONF" ]]; then
        if ! grep -qE "^\*\s+hard\s+core\s+0" "$KERNEL_LIMITS_CONF"; then
            backup_file "$KERNEL_LIMITS_CONF" >/dev/null || return 1
            local limits_content
            limits_content=$(cat "$KERNEL_LIMITS_CONF")
            write_file_atomic "$KERNEL_LIMITS_CONF" \
                "${limits_content}"$'\n'"* hard core 0"$'\n'
        fi
    fi

    # The condition MUST mirror the audit's exactly: requiring the drop-in
    # directory while the audit accepts either path means the fix writes
    # nothing on a stock Debian host and claims success anyway.
    if [[ -f "$KERNEL_COREDUMP_CONF" || -d "$KERNEL_COREDUMP_D" ]]; then
        mkdir -p "$KERNEL_COREDUMP_D"
        backup_file "$KERNEL_COREDUMP_DROPIN" >/dev/null || return 1
        write_file_atomic "$KERNEL_COREDUMP_DROPIN" '[Coredump]
Storage=none
ProcessSizeMax=0'
    fi

    # Postcondition is the audit's own predicate, so this reports what was
    # achieved rather than what was attempted.
    local remaining
    remaining=$(_kernel_check_core_dump)
    if [[ -z "$remaining" ]]; then
        print_ok "$(i18n 'kernel.core_dump_disabled')"
        return 0
    fi

    print_warn "$(i18n 'kernel.core_dump_partial' "issues=$remaining")"
    log_warn "kernel.disable_core_dump: still unrestricted after fix: $remaining"
    return 1
}

# Run every hardening step and fail if ANY failed — returning only the last
# step's status records a failed pass as complete. Each step still runs after
# an earlier failure; they are independent.
_kernel_fix_all() {
    local rc=0

    _kernel_fix_aslr || rc=1
    _kernel_fix_network_params || rc=1
    _kernel_fix_kernel_params || rc=1
    _kernel_fix_core_dump || rc=1

    return "$rc"
}

# Persist one sysctl. Each call rewrites the whole drop-in so the header
# appears once and an existing entry is replaced rather than duplicated.
# Does NOT reload — loop callers reload once after the loop.
_kernel_write_sysctl() {
    local param="$1"
    local value="$2"

    mkdir -p "$SYSCTL_D"

    # Strip previous header/blank lines AND any existing entry for this
    # param, leaving only clean `key = value` lines to replay.
    local existing=""
    if [[ -f "$VPSSEC_SYSCTL_CONF" ]]; then
        local param_re="${param//./\\.}"
        existing=$(grep -vE '^[[:space:]]*(#|$)' "$VPSSEC_SYSCTL_CONF" 2>/dev/null \
                   | grep -vE "^${param_re}[[:space:]]*=" || true)
    fi
    # UNCONDITIONAL: backup_file also records an absent path as fix-created,
    # which is the only thing that lets a rollback DELETE this drop-in.
    backup_file "$VPSSEC_SYSCTL_CONF" >/dev/null || return 1

    # Build the full drop-in and write it atomically — never a partial file:
    # this is persisted hardening replayed on every boot. write_file_atomic
    # sets 0644 for a new file and preserves the mode of an existing one.
    local content
    content="# vpssec kernel hardening configuration"$'\n'
    content+="# Generated: $(date -Iseconds)"$'\n'
    content+=$'\n'
    if [[ -n "$existing" ]]; then
        content+="$existing"$'\n'
    fi
    content+="$param = $value"

    write_file_atomic "$VPSSEC_SYSCTL_CONF" "$content"
}

# Reload the drop-in so persisted values take effect now, at the priority
# they will have after reboot. Silently a no-op where /proc/sys is read-only.
_kernel_reload_sysctl_dropin() {
    sysctl -p "$VPSSEC_SYSCTL_CONF" >/dev/null 2>&1 || true
}
