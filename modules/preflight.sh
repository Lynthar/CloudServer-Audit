#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Preflight module - environment detection and prerequisite checks
# Copyright (c) 2024

# --- Preflight Audit ---

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
        check_emit "preflight.os_supported" low passed \
            desc="${os} ${version} (${codename})"
        print_ok "$(i18n 'preflight.os_supported'): ${os} ${version}"
    else
        check_emit "preflight.os_unsupported" low failed \
            desc="${os} ${version} - $(i18n 'preflight.os_unsupported')" \
            suggestion="$(i18n 'preflight.os_unsupported_suggestion')"
        print_warn "$(i18n 'preflight.os_unsupported'): ${os} ${version}"
    fi
}

# Check network connectivity
_preflight_check_network() {
    # If neither curl nor wget exists we genuinely cannot test reachability —
    # don't emit a "network OK" check (which would be a false, untested
    # success). Skip silently; this is an info-only context check.
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        log_debug "preflight: no curl/wget available; skipping network reachability check"
        return 0
    fi

    local network_ok=1

    # Check if we can reach common endpoints
    if command -v curl &>/dev/null; then
        if ! curl -s --max-time 5 https://www.google.com > /dev/null 2>&1; then
            if ! curl -s --max-time 5 https://www.baidu.com > /dev/null 2>&1; then
                network_ok=0
            fi
        fi
    elif command -v wget &>/dev/null; then
        # --tries=1: without it wget retries a black-holed host up to 20 times,
        # so the 5s timeout could stall the audit for minutes.
        if ! wget -q --tries=1 --timeout=5 -O /dev/null https://www.google.com 2>&1; then
            if ! wget -q --tries=1 --timeout=5 -O /dev/null https://www.baidu.com 2>&1; then
                network_ok=0
            fi
        fi
    fi

    if [[ "$network_ok" == "1" ]]; then
        check_emit "preflight.network_ok" low passed
        print_ok "$(i18n 'preflight.network_ok')"
    else
        check_emit "preflight.network_fail" low failed \
            desc="$(i18n 'preflight.network_fail_desc')" \
            suggestion="$(i18n 'preflight.network_fail_suggestion')"
        print_warn "$(i18n 'preflight.network_fail')"
    fi
}

# Check required and optional dependencies
_preflight_check_deps() {
    # The entry point exits before any mode runs when a required command is
    # missing (check_required_deps), so here they are all present.
    check_emit "preflight.deps_ok" low passed \
        title="$(i18n 'common.required_deps')"
    print_ok "$(i18n 'common.required_deps')"

    # One check for what is missing, not a print: prints are silenced during
    # the scan. Any member of a group provides it.
    local -a lacking=() lacking_cmds=()
    if ! check_command whiptail && ! check_command dialog; then
        # dialog: one package name on every family (whiptail is newt on RHEL).
        lacking+=("$(i18n 'preflight.cap_tui')"); lacking_cmds+=(dialog)
    fi
    if ! check_command curl && ! check_command wget; then
        lacking+=("$(i18n 'preflight.cap_network')"); lacking_cmds+=(curl)
    fi
    # The package-lock check's own tool, as pkg_manager_locked uses it: lsof
    # backs up /proc/locks for apt, dnf's check is pgrep, pacman's is a file test.
    local lock_tool="" lock_cap=""
    case "${VPSSEC_PKG_MGR:-}" in
        apt) lock_tool=lsof  lock_cap=preflight.cap_lsof ;;
        dnf) lock_tool=pgrep lock_cap=preflight.cap_pgrep ;;
    esac
    if [[ -n "$lock_tool" ]] && ! check_command "$lock_tool"; then
        lacking+=("$(i18n "$lock_cap")"); lacking_cmds+=("$lock_tool")
    fi

    if (( ${#lacking[@]} > 0 )); then
        local caps opt_hint opt_pkgs
        caps=$(printf '%s; ' "${lacking[@]}")
        caps="${caps%; }"
        opt_pkgs=$(distro_packages_for_commands "${lacking_cmds[@]}")
        # shellcheck disable=SC2086  # deliberate split: one package per word
        if ! opt_hint=$(pkg_install_hint $opt_pkgs); then
            opt_hint=$(i18n 'preflight.install_deps' "deps=$opt_pkgs")
        fi
        log_info "Optional capabilities missing: $caps"
        check_emit "preflight.optional_missing" low failed \
            desc="$(i18n 'preflight.optional_missing_desc' "caps=$caps")" \
            suggestion="$opt_hint"
        print_warn "$(i18n 'preflight.optional_missing')"
    fi
}

# Check listening ports
_preflight_check_ports() {
    local ports=$(get_listening_ports)
    local port_count=$(echo "$ports" | wc -w)

    # Context only. Dangerous-port exposure is audited authoritatively by
    # networking.exposed_dangerous_ports, which is wildcard-aware.
    check_emit "preflight.ports_ok" low passed \
        title="$(i18n 'preflight.listening_ports' "count=$port_count")"
    print_ok "$(i18n 'preflight.listening_ports' "count=$port_count")"

    # Log all ports for reference
    log_info "Listening ports: $ports"
}

# --- Preflight Fix (N/A - preflight is audit only) ---

preflight_fix() {
    local fix_id="$1"
    log_warn "Preflight module has no fixes"
    return 1
}
