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

    # Network security - IPv6
    "net.ipv6.conf.all.accept_redirects:0:low:IPv6 ICMP redirects"
    "net.ipv6.conf.default.accept_redirects:0:low:IPv6 ICMP redirects (default)"
    "net.ipv6.conf.all.accept_source_route:0:low:IPv6 source routing"
    "net.ipv6.conf.default.accept_source_route:0:low:IPv6 source routing (default)"

    # Kernel security
    "kernel.randomize_va_space:2:high:ASLR (Address Space Layout Randomization)"
    "kernel.dmesg_restrict:1:medium:Restrict dmesg access"
    "kernel.kptr_restrict:2:medium:Restrict kernel pointer exposure"
    "kernel.yama.ptrace_scope:1:medium:Restrict ptrace"
    "fs.suid_dumpable:0:medium:Disable SUID core dumps"
    "fs.protected_hardlinks:1:medium:Hardlink protection"
    "fs.protected_symlinks:1:medium:Symlink protection"
    "kernel.core_uses_pid:1:low:Core dump filename includes PID"
)

# ==============================================================================
# Kernel Helper Functions
# ==============================================================================

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

    # Check ASLR
    print_item "$(i18n 'kernel.check_aslr')"
    _kernel_audit_aslr

    # Check network security parameters
    print_item "$(i18n 'kernel.check_network_params')"
    _kernel_audit_network_params

    # Check kernel security parameters
    print_item "$(i18n 'kernel.check_kernel_params')"
    _kernel_audit_kernel_params

    # Check core dump settings
    print_item "$(i18n 'kernel.check_core_dump')"
    _kernel_audit_core_dump
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
    local issues=()
    local passed=0

    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        local param="${entry%%:*}"
        local rest="${entry#*:}"
        local expected="${rest%%:*}"
        rest="${rest#*:}"
        local severity="${rest%%:*}"

        # Only check kernel.* and fs.* params here
        if [[ ! "$param" =~ ^(kernel\.|fs\.) ]]; then
            continue
        fi

        local actual
        actual=$(_kernel_check_param "$param" "$expected")
        local result=$?

        if [[ $result -eq 0 ]]; then
            ((passed++))
        elif [[ $result -eq 1 ]]; then
            issues+=("$param=$actual")
        fi
    done

    if [[ ${#issues[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues[@]}" | head -5 | tr '\n' '; ')
        local check=$(create_check_json \
            "kernel.kernel_params_weak" \
            "kernel" \
            "medium" \
            "failed" \
            "$(i18n 'kernel.kernel_params_weak' "count=${#issues[@]}")" \
            "Issues: $issue_list" \
            "$(i18n 'kernel.fix_kernel_params')" \
            "kernel.harden_kernel")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'kernel.kernel_params_weak' "count=${#issues[@]}")"
    else
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
