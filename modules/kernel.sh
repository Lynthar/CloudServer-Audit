#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Kernel and network security parameters module
# Copyright (c) 2024

# ==============================================================================
# Kernel Security Configuration
# ==============================================================================

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_D="/etc/sysctl.d"
VPSSEC_SYSCTL_CONF="${SYSCTL_D}/99-vpssec-hardening.conf"

# Recommended sysctl settings with descriptions
# Format: parameter:recommended_value:severity:description
declare -a KERNEL_SECURITY_PARAMS=(
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

    # Network security - IPv6 (Enhanced)
    "net.ipv6.conf.all.accept_redirects:0:medium:IPv6 ICMP redirects"
    "net.ipv6.conf.default.accept_redirects:0:medium:IPv6 ICMP redirects (default)"
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

    # Kernel security
    "kernel.randomize_va_space:2:high:ASLR (Address Space Layout Randomization)"
    "kernel.dmesg_restrict:1:medium:Restrict dmesg access"
    "kernel.kptr_restrict:2:medium:Restrict kernel pointer exposure"
    "kernel.yama.ptrace_scope:1:medium:Restrict ptrace"
    "fs.suid_dumpable:0:medium:Disable SUID core dumps"
    "fs.protected_hardlinks:1:medium:Hardlink protection"
    "fs.protected_symlinks:1:medium:Symlink protection"
    "kernel.core_uses_pid:1:low:Core dump filename includes PID"

    # Additional kernel hardening (may not be available on all systems)
    "kernel.unprivileged_userns_clone:0:high:Disable unprivileged user namespaces (container escape prevention)"
    "kernel.unprivileged_bpf_disabled:1:high:Disable unprivileged BPF (exploit prevention)"
    "net.core.bpf_jit_harden:2:medium:BPF JIT hardening"
    "kernel.sysrq:0:medium:Disable Magic SysRq key (or use 176 for safe subset)"
    "kernel.perf_event_paranoid:3:medium:Restrict perf events"
    "fs.protected_fifos:2:low:FIFO protection"
    "fs.protected_regular:2:low:Regular file protection"
)

# ==============================================================================
# Kernel Helper Functions
# ==============================================================================

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

    if [[ "$actual" == "$expected" ]]; then
        return 0  # Correct
    else
        echo "$actual"
        return 1  # Incorrect
    fi
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

# Check if IP forwarding is needed (Docker, LXC, etc.)
_kernel_ip_forward_needed() {
    # Check if Docker is running (needs IP forwarding)
    if systemctl is-active --quiet docker 2>/dev/null; then
        return 0
    fi

    # Check if LXC/LXD is running
    if systemctl is-active --quiet lxc 2>/dev/null || \
       systemctl is-active --quiet lxd 2>/dev/null; then
        return 0
    fi

    # Check if libvirt is running
    if systemctl is-active --quiet libvirtd 2>/dev/null; then
        return 0
    fi

    return 1
}

# ==============================================================================
# IPv6 Detection Functions
# ==============================================================================

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

    # Count interfaces with IPv6
    local iface_count=$(ip -6 addr show 2>/dev/null | grep -c "inet6" || echo "0")
    stats+="interfaces:$iface_count;"

    # Count global addresses
    local global_count=$(ip -6 addr show scope global 2>/dev/null | grep -c "inet6" || echo "0")
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

    # Check if UFW is managing IPv6
    if check_command ufw; then
        if grep -q "IPV6=yes" /etc/default/ufw 2>/dev/null; then
            result="ufw_ipv6_enabled"
        else
            result="ufw_ipv6_disabled"
        fi
    # Check if ip6tables has rules
    elif check_command ip6tables; then
        local rule_count=$(ip6tables -L -n 2>/dev/null | grep -cv "^Chain\|^target\|^$" || echo "0")
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

    # Check /etc/security/limits.conf for core limits
    if [[ -f /etc/security/limits.conf ]]; then
        if ! grep -qE "^\*\s+(soft|hard)\s+core\s+0" /etc/security/limits.conf 2>/dev/null; then
            issues+=("no_core_limit")
        fi
    fi

    # Check systemd coredump
    if [[ -f /etc/systemd/coredump.conf ]]; then
        if ! grep -qE "^Storage=none" /etc/systemd/coredump.conf 2>/dev/null; then
            issues+=("systemd_coredump")
        fi
    fi

    echo "${issues[*]}"
}

# ==============================================================================
# Kernel Audit
# ==============================================================================

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

    # Check auditd status (only if not in container)
    if [[ -z "$container_type" ]]; then
        print_item "$(i18n 'kernel.check_auditd')"
        _kernel_audit_auditd
    fi
}

# ==============================================================================
# IPv6 Audit Function
# ==============================================================================

_kernel_audit_ipv6() {
    # Check if IPv6 is enabled
    if ! _kernel_ipv6_enabled; then
        local check=$(create_check_json \
            "kernel.ipv6_disabled" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.ipv6_disabled')" \
            "IPv6 is disabled system-wide (reduced attack surface)" \
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
                "medium" \
                "failed" \
                "$(i18n 'kernel.ipv6_insecure' "count=$issue_count")" \
                "IPv6 in use with security issues: $ipv6_issues" \
                "$(i18n 'kernel.fix_ipv6')" \
                "kernel.harden_ipv6")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'kernel.ipv6_insecure' "count=$issue_count")"
        else
            local check=$(create_check_json \
                "kernel.ipv6_secure" \
                "kernel" \
                "low" \
                "passed" \
                "$(i18n 'kernel.ipv6_secure')" \
                "IPv6 enabled and properly secured" \
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
                "IPv6 enabled but not used, with weak settings" \
                "Consider disabling IPv6 or hardening settings" \
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
                "IPv6 enabled but not actively used" \
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
                    "high" \
                    "failed" \
                    "$(i18n 'kernel.ipv6_firewall_missing')" \
                    "IPv6 is in use but firewall not configured for IPv6" \
                    "Enable IPv6 in firewall configuration" \
                    "")
                state_add_check "$check"
                print_severity "high" "$(i18n 'kernel.ipv6_firewall_missing')"
                ;;
            ufw_ipv6_enabled|ip6tables_configured|nftables_ipv6_configured)
                local check=$(create_check_json \
                    "kernel.ipv6_firewall_ok" \
                    "kernel" \
                    "low" \
                    "passed" \
                    "$(i18n 'kernel.ipv6_firewall_ok')" \
                    "IPv6 firewall is configured" \
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
                "ASLR is fully enabled (randomize_va_space=2)" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'kernel.aslr_enabled') (full)"
            ;;
        partial)
            local check=$(create_check_json \
                "kernel.aslr_partial" \
                "kernel" \
                "medium" \
                "failed" \
                "$(i18n 'kernel.aslr_partial')" \
                "ASLR is only partially enabled (randomize_va_space=1)" \
                "$(i18n 'kernel.fix_aslr')" \
                "kernel.enable_aslr")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'kernel.aslr_partial')"
            ;;
        disabled)
            local check=$(create_check_json \
                "kernel.aslr_disabled" \
                "kernel" \
                "high" \
                "failed" \
                "$(i18n 'kernel.aslr_disabled')" \
                "ASLR is disabled (randomize_va_space=0)" \
                "$(i18n 'kernel.fix_aslr')" \
                "kernel.enable_aslr")
            state_add_check "$check"
            print_severity "high" "$(i18n 'kernel.aslr_disabled')"
            ;;
        *)
            local check=$(create_check_json \
                "kernel.aslr_unknown" \
                "kernel" \
                "low" \
                "failed" \
                "Cannot determine ASLR status" \
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
            # IP forwarding is needed for Docker/LXC
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

    if [[ ${#issues_high[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_high[@]}" | head -3 | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.network_params_high" \
            "kernel" \
            "high" \
            "failed" \
            "$(i18n 'kernel.network_params_insecure' "count=${#issues_high[@]}")" \
            "Critical: $issue_list" \
            "$(i18n 'kernel.fix_network_params')" \
            "kernel.harden_network")
        state_add_check "$check"
        print_severity "high" "$(i18n 'kernel.network_params_insecure' "count=${#issues_high[@]}")"
    fi

    if [[ ${#issues_medium[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_medium[@]}" | head -3 | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.network_params_medium" \
            "kernel" \
            "medium" \
            "failed" \
            "$(i18n 'kernel.network_params_weak' "count=${#issues_medium[@]}")" \
            "Issues: $issue_list" \
            "$(i18n 'kernel.fix_network_params')" \
            "kernel.harden_network")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'kernel.network_params_weak' "count=${#issues_medium[@]}")"
    fi

    if [[ $total_issues -eq 0 ]]; then
        local check=$(create_check_json \
            "kernel.network_params_ok" \
            "kernel" \
            "low" \
            "passed" \
            "$(i18n 'kernel.network_params_ok')" \
            "$passed parameters checked" \
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

        # Only check kernel.* and fs.* params here
        if [[ ! "$param" =~ ^(kernel\.|fs\.) ]]; then
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

    # Report high-severity kernel issues separately (userns, bpf)
    if [[ ${#issues_high[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_high[@]}" | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.kernel_params_high" \
            "kernel" \
            "high" \
            "failed" \
            "$(i18n 'kernel.kernel_params_critical' "count=${#issues_high[@]}")" \
            "Critical: $issue_list" \
            "$(i18n 'kernel.fix_kernel_params')" \
            "kernel.harden_kernel")
        state_add_check "$check"
        print_severity "high" "Critical kernel hardening issues: ${#issues_high[@]}"
    fi

    # Report medium-severity issues
    if [[ ${#issues_medium[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_medium[@]}" | head -5 | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.kernel_params_weak" \
            "kernel" \
            "medium" \
            "failed" \
            "$(i18n 'kernel.kernel_params_weak' "count=${#issues_medium[@]}")" \
            "Issues: $issue_list" \
            "$(i18n 'kernel.fix_kernel_params')" \
            "kernel.harden_kernel")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'kernel.kernel_params_weak' "count=${#issues_medium[@]}")"
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
            "$passed parameters checked" \
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
            "Core dumps are properly restricted" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'kernel.core_dump_disabled')"
    else
        local check=$(create_check_json \
            "kernel.core_dump_enabled" \
            "kernel" \
            "medium" \
            "failed" \
            "$(i18n 'kernel.core_dump_enabled')" \
            "Issues: $issues" \
            "$(i18n 'kernel.fix_core_dump')" \
            "kernel.disable_core_dump")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'kernel.core_dump_enabled')"
    fi
}

_kernel_audit_auditd() {
    # Check if auditd is installed
    if ! command -v auditd &>/dev/null && ! command -v auditctl &>/dev/null; then
        local check=$(create_check_json \
            "kernel.auditd_not_installed" \
            "kernel" \
            "low" \
            "failed" \
            "$(i18n 'kernel.auditd_not_installed')" \
            "Linux Audit daemon not installed" \
            "Install auditd for security event logging: apt install auditd" \
            "")
        state_add_check "$check"
        print_severity "low" "auditd not installed"
        return
    fi

    # Check if auditd service is running
    if systemctl is-active --quiet auditd 2>/dev/null; then
        # Check if rules are loaded
        local rule_count=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo 0)

        if ((rule_count > 5)); then
            local check=$(create_check_json \
                "kernel.auditd_active" \
                "kernel" \
                "low" \
                "passed" \
                "$(i18n 'kernel.auditd_active')" \
                "auditd running with $rule_count rules" \
                "" \
                "")
            state_add_check "$check"
            print_ok "auditd active with $rule_count rules"
        else
            local check=$(create_check_json \
                "kernel.auditd_few_rules" \
                "kernel" \
                "low" \
                "failed" \
                "$(i18n 'kernel.auditd_few_rules')" \
                "auditd running but only $rule_count rules configured" \
                "Consider adding audit rules for security monitoring" \
                "")
            state_add_check "$check"
            print_severity "low" "auditd has few rules configured"
        fi
    else
        local check=$(create_check_json \
            "kernel.auditd_not_running" \
            "kernel" \
            "low" \
            "failed" \
            "$(i18n 'kernel.auditd_not_running')" \
            "auditd installed but not running" \
            "Enable auditd: systemctl enable --now auditd" \
            "")
        state_add_check "$check"
        print_severity "low" "auditd not running"
    fi
}

# ==============================================================================
# Kernel Fix Functions
# ==============================================================================

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

# ==============================================================================
# IPv6 Fix Function
# ==============================================================================

_kernel_fix_ipv6() {
    print_info "$(i18n 'kernel.hardening_ipv6')"

    local ipv6_params=(
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_source_route=0"
        "net.ipv6.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.accept_ra=0"
        "net.ipv6.conf.default.accept_ra=0"
        "net.ipv6.conf.all.use_tempaddr=2"
        "net.ipv6.conf.default.use_tempaddr=2"
        "net.ipv6.conf.all.accept_ra_defrtr=0"
        "net.ipv6.conf.all.accept_ra_pinfo=0"
        "net.ipv6.conf.all.accept_ra_rtr_pref=0"
    )

    local fixed=0

    for setting in "${ipv6_params[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        # Apply immediately
        if sysctl -w "$param=$value" 2>/dev/null; then
            _kernel_write_sysctl "$param" "$value"
            ((fixed++)) || true
        fi
    done

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

    # Apply immediately
    sysctl -w kernel.randomize_va_space=2 2>/dev/null

    # Make persistent
    _kernel_write_sysctl "kernel.randomize_va_space" "2"

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

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        if [[ $? -eq 1 ]]; then
            params_to_set+=("$param=$expected")
        fi
    done

    if [[ ${#params_to_set[@]} -eq 0 ]]; then
        print_ok "$(i18n 'kernel.network_already_hardened')"
        return 0
    fi

    # Apply and persist
    for setting in "${params_to_set[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        sysctl -w "$param=$value" 2>/dev/null
        _kernel_write_sysctl "$param" "$value"
    done

    print_ok "$(i18n 'kernel.network_hardened' "count=${#params_to_set[@]}")"
    return 0
}

_kernel_fix_kernel_params() {
    print_info "$(i18n 'kernel.hardening_kernel')"

    local params_to_set=()

    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        local param="${entry%%:*}"
        local rest="${entry#*:}"
        local expected="${rest%%:*}"

        # Only kernel.* and fs.* params
        if [[ ! "$param" =~ ^(kernel\.|fs\.) ]]; then
            continue
        fi

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        if [[ $? -eq 1 ]]; then
            params_to_set+=("$param=$expected")
        fi
    done

    if [[ ${#params_to_set[@]} -eq 0 ]]; then
        print_ok "$(i18n 'kernel.kernel_already_hardened')"
        return 0
    fi

    # Apply and persist
    for setting in "${params_to_set[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        sysctl -w "$param=$value" 2>/dev/null
        _kernel_write_sysctl "$param" "$value"
    done

    print_ok "$(i18n 'kernel.kernel_hardened' "count=${#params_to_set[@]}")"
    return 0
}

_kernel_fix_core_dump() {
    print_info "$(i18n 'kernel.disabling_core_dump')"

    # Disable via sysctl
    sysctl -w fs.suid_dumpable=0 2>/dev/null
    _kernel_write_sysctl "fs.suid_dumpable" "0"

    # Add limits.conf entry
    if [[ -f /etc/security/limits.conf ]]; then
        if ! grep -qE "^\*\s+hard\s+core\s+0" /etc/security/limits.conf; then
            backup_file /etc/security/limits.conf
            echo "* hard core 0" >> /etc/security/limits.conf
        fi
    fi

    # Configure systemd-coredump if present
    if [[ -d /etc/systemd/coredump.conf.d ]]; then
        mkdir -p /etc/systemd/coredump.conf.d
        cat > /etc/systemd/coredump.conf.d/99-vpssec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    fi

    print_ok "$(i18n 'kernel.core_dump_disabled')"
    return 0
}

_kernel_fix_all() {
    _kernel_fix_aslr
    _kernel_fix_network_params
    _kernel_fix_kernel_params
    _kernel_fix_core_dump
}

# Helper: Write sysctl setting to persistent config
_kernel_write_sysctl() {
    local param="$1"
    local value="$2"

    mkdir -p "$SYSCTL_D"

    # Read existing config or create new
    local existing=""
    if [[ -f "$VPSSEC_SYSCTL_CONF" ]]; then
        existing=$(grep -v "^$param\s*=" "$VPSSEC_SYSCTL_CONF" 2>/dev/null || true)
    fi

    # Write config
    {
        echo "# vpssec kernel hardening configuration"
        echo "# Generated: $(date -Iseconds)"
        echo ""
        if [[ -n "$existing" ]]; then
            echo "$existing"
        fi
        echo "$param = $value"
    } > "$VPSSEC_SYSCTL_CONF"

    chmod 644 "$VPSSEC_SYSCTL_CONF"
}
