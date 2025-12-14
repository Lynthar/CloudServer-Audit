#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Preflight module - environment detection and prerequisite checks
# Copyright (c) 2024

# ==============================================================================
# Preflight Audit
# ==============================================================================

preflight_audit() {
    local module="preflight"

    # Check OS
    print_item "$(i18n 'preflight.checking_os')"
    _preflight_check_os

    # Check virtualization
    print_item "$(i18n 'preflight.virtualization' "type=$(detect_virtualization)")"

    # Check network
    print_item "$(i18n 'preflight.checking_network')"
    _preflight_check_network

    # Check dependencies
    print_item "$(i18n 'preflight.checking_deps')"
    _preflight_check_deps

    # Scan listening ports
    print_item "$(i18n 'preflight.checking_ports')"
    _preflight_check_ports
}

# Check if OS is supported
_preflight_check_os() {
    local os=$(detect_os)
    local version=$(detect_os_version)
    local codename=$(detect_os_codename)

    if is_supported_os; then
        local check=$(create_check_json \
            "preflight.os_supported" \
            "preflight" \
            "low" \
            "passed" \
            "$(i18n 'preflight.os_supported')" \
            "${os} ${version} (${codename})" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'preflight.os_supported'): ${os} ${version}"
    else
        local check=$(create_check_json \
            "preflight.os_unsupported" \
            "preflight" \
            "medium" \
            "failed" \
            "$(i18n 'preflight.os_unsupported')" \
            "${os} ${version} - $(i18n 'preflight.os_unsupported')" \
            "Use Debian 12/13 or Ubuntu 22.04/24.04" \
            "")
        state_add_check "$check"
        print_warn "$(i18n 'preflight.os_unsupported'): ${os} ${version}"
    fi
}

# Check network connectivity
_preflight_check_network() {
    local network_ok=1

    # Check if we can reach common endpoints
    if command -v curl &>/dev/null; then
        if ! curl -s --max-time 5 https://www.google.com > /dev/null 2>&1; then
            if ! curl -s --max-time 5 https://www.baidu.com > /dev/null 2>&1; then
                network_ok=0
            fi
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=5 -O /dev/null https://www.google.com 2>&1; then
            if ! wget -q --timeout=5 -O /dev/null https://www.baidu.com 2>&1; then
                network_ok=0
            fi
        fi
    fi

    if [[ "$network_ok" == "1" ]]; then
        local check=$(create_check_json \
            "preflight.network_ok" \
            "preflight" \
            "low" \
            "passed" \
            "$(i18n 'preflight.network_ok')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'preflight.network_ok')"
    else
        local check=$(create_check_json \
            "preflight.network_fail" \
            "preflight" \
            "medium" \
            "failed" \
            "$(i18n 'preflight.network_fail')" \
            "Cannot reach external network" \
            "Check network configuration and DNS" \
            "")
        state_add_check "$check"
        print_warn "$(i18n 'preflight.network_fail')"
    fi
}

# Check required and optional dependencies
_preflight_check_deps() {
    # Required dependencies
    local required_deps=(jq ss systemctl sed awk tar grep)
    local missing_required=()

    for dep in "${required_deps[@]}"; do
        if ! check_command "$dep"; then
            missing_required+=("$dep")
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        local check=$(create_check_json \
            "preflight.deps_missing" \
            "preflight" \
            "high" \
            "failed" \
            "$(i18n 'preflight.dep_missing' "dep=${missing_required[*]}")" \
            "Required: ${missing_required[*]}" \
            "apt install ${missing_required[*]}" \
            "")
        state_add_check "$check"
        print_error "$(i18n 'preflight.dep_missing' "dep=${missing_required[*]}")"
    else
        local check=$(create_check_json \
            "preflight.deps_ok" \
            "preflight" \
            "low" \
            "passed" \
            "$(i18n 'common.required_deps')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'common.required_deps')"
    fi

    # Optional dependencies
    local optional_deps=(whiptail dialog curl wget)
    local missing_optional=()

    for dep in "${optional_deps[@]}"; do
        if ! check_command "$dep"; then
            missing_optional+=("$dep")
        fi
    done

    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log_info "Optional dependencies missing: ${missing_optional[*]}"
        print_item "${DIM}$(i18n 'preflight.dep_optional' "dep=${missing_optional[*]}")${NC}"
    fi
}

# Check listening ports
_preflight_check_ports() {
    local ports=$(get_listening_ports)
    local port_count=$(echo "$ports" | wc -w)

    # Common dangerous ports to flag
    local dangerous_ports=(21 23 25 110 143 3306 5432 6379 27017)
    local exposed_dangerous=()

    for port in $ports; do
        for dport in "${dangerous_ports[@]}"; do
            if [[ "$port" == "$dport" ]]; then
                exposed_dangerous+=("$port")
            fi
        done
    done

    if [[ ${#exposed_dangerous[@]} -gt 0 ]]; then
        local check=$(create_check_json \
            "preflight.dangerous_ports" \
            "preflight" \
            "medium" \
            "failed" \
            "$(i18n 'preflight.dangerous_ports' "ports=${exposed_dangerous[*]}")" \
            "" \
            "$(i18n 'ufw.fix_allow_ssh')" \
            "ufw.add_rules")
        state_add_check "$check"
        print_warn "$(i18n 'preflight.listening_ports' "count=$port_count") - Dangerous: ${exposed_dangerous[*]}"
    else
        local check=$(create_check_json \
            "preflight.ports_ok" \
            "preflight" \
            "low" \
            "passed" \
            "$(i18n 'preflight.listening_ports' "count=$port_count")" \
            "No commonly dangerous ports exposed" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'preflight.listening_ports' "count=$port_count")"
    fi

    # Log all ports for reference
    log_info "Listening ports: $ports"
}

# ==============================================================================
# Preflight Fix (N/A - preflight is audit only)
# ==============================================================================

preflight_fix() {
    local fix_id="$1"
    log_warn "Preflight module has no fixes"
    return 1
}
