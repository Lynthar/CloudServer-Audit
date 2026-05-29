#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Baseline hardening module (Enhanced with SELinux support)
# Copyright (c) 2024

# ==============================================================================
# Baseline Helper Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# AppArmor Functions
# ------------------------------------------------------------------------------

_baseline_apparmor_enabled() {
    if check_command aa-status; then
        aa-status --enabled 2>/dev/null
        return $?
    fi
    return 1
}

_baseline_apparmor_installed() {
    check_command aa-status || check_command apparmor_status
}

# Echoes "<enforced>:<complain>" — empty fields default to 0 in caller.
# Tries machine-readable `aa-status --json` first (available on Debian 12+),
# then falls back to the human-readable form under LC_ALL=C so the regex
# doesn't fail on hosts running zh_CN.UTF-8 / de_DE.UTF-8 / etc.
_baseline_apparmor_count_profiles() {
    local enforced complain json

    if json=$(aa-status --json 2>/dev/null) && [[ -n "$json" ]]; then
        enforced=$(echo "$json" | jq -r '[.profiles[]? | select(. == "enforce")] | length' 2>/dev/null)
        complain=$(echo "$json" | jq -r '[.profiles[]? | select(. == "complain")] | length' 2>/dev/null)
        if [[ "$enforced" =~ ^[0-9]+$ && "$complain" =~ ^[0-9]+$ ]]; then
            echo "${enforced}:${complain}"
            return 0
        fi
    fi

    local text
    text=$(LC_ALL=C aa-status 2>/dev/null) || return 1
    enforced=$(echo "$text" | grep -E "^\s*[0-9]+ profiles are in enforce mode" | grep -oE "[0-9]+" | head -1)
    complain=$(echo "$text" | grep -E "^\s*[0-9]+ profiles are in complain mode" | grep -oE "[0-9]+" | head -1)
    echo "${enforced:-0}:${complain:-0}"
}

_baseline_apparmor_get_status() {
    if ! _baseline_apparmor_installed; then
        echo "not_installed"
        return
    fi

    if _baseline_apparmor_enabled; then
        echo "enabled:$(_baseline_apparmor_count_profiles)"
    else
        echo "disabled"
    fi
}

# ------------------------------------------------------------------------------
# SELinux Functions
# ------------------------------------------------------------------------------

_baseline_selinux_installed() {
    # Gate on the kernel-level LSM, not just userspace tooling.
    #
    # On Debian/Ubuntu, installing the `selinux-utils` package (which
    # an unrelated user or another module's dependency can pull in)
    # puts `getenforce` and `sestatus` on PATH while the running
    # kernel has no SELinux support. The original `command -v` check
    # then reported "SELinux installed but disabled" and offered a
    # fix that told the user to edit /etc/selinux/config — a file
    # that doesn't exist on Debian. Active misdirection.
    #
    # /sys/fs/selinux/enforce only exists when the kernel was built
    # with CONFIG_SECURITY_SELINUX=y AND the LSM is loaded; that is
    # the canonical "SELinux is real on this host" signal.
    [[ -e /sys/fs/selinux/enforce ]] || return 1
    check_command getenforce || check_command sestatus
}

_baseline_selinux_get_status() {
    if ! _baseline_selinux_installed; then
        echo "not_installed"
        return
    fi

    local mode=""
    if check_command getenforce; then
        mode=$(getenforce 2>/dev/null)
    elif check_command sestatus; then
        mode=$(sestatus 2>/dev/null | grep "Current mode" | awk '{print $3}')
    fi

    case "$mode" in
        Enforcing|enforcing)   echo "enforcing" ;;
        Permissive|permissive) echo "permissive" ;;
        Disabled|disabled)     echo "disabled" ;;
        *)                     echo "unknown" ;;
    esac
}

_baseline_selinux_get_config() {
    # Get configured mode from config file
    if [[ -f /etc/selinux/config ]]; then
        grep -E "^SELINUX=" /etc/selinux/config 2>/dev/null | cut -d= -f2 | tr -d '"'
    else
        echo "not_configured"
    fi
}

_baseline_selinux_get_policy() {
    if check_command sestatus; then
        sestatus 2>/dev/null | grep "Loaded policy name" | awk '{print $4}'
    elif [[ -f /etc/selinux/config ]]; then
        grep -E "^SELINUXTYPE=" /etc/selinux/config 2>/dev/null | cut -d= -f2 | tr -d '"'
    fi
}

_baseline_selinux_denials_count() {
    # Count recent SELinux denials (last 24h). awk replaces the legacy
    # `grep -c PAT FILE 2>/dev/null || echo "0"` idiom: when grep finds
    # zero matches it prints "0" and exits 1, so the `|| echo "0"`
    # fallback ran too and emitted a literal "0\n0" — caller arithmetic
    # then died under set -e. awk's `c+0` always yields one integer.
    if check_command ausearch; then
        ausearch -m avc -ts today 2>/dev/null | awk '/type=AVC/ {c++} END {print c+0}'
    elif [[ -f /var/log/audit/audit.log ]]; then
        awk '/type=AVC.*denied/ {c++} END {print c+0}' /var/log/audit/audit.log 2>/dev/null
    else
        echo "unknown"
    fi
}

# ------------------------------------------------------------------------------
# MAC System Detection (Mandatory Access Control)
# ------------------------------------------------------------------------------

_baseline_detect_mac_system() {
    # Detect which MAC system is in use
    # Priority: SELinux > AppArmor (some systems have both installed)

    local selinux_status=$(_baseline_selinux_get_status)
    local apparmor_status=$(_baseline_apparmor_get_status)

    # Check if SELinux is actively in use
    if [[ "$selinux_status" == "enforcing" || "$selinux_status" == "permissive" ]]; then
        echo "selinux"
        return
    fi

    # Check if AppArmor is enabled
    if [[ "$apparmor_status" =~ ^enabled ]]; then
        echo "apparmor"
        return
    fi

    # Neither is active, check what's installed
    if _baseline_selinux_installed && [[ "$selinux_status" != "not_installed" ]]; then
        echo "selinux_disabled"
        return
    fi

    if _baseline_apparmor_installed; then
        echo "apparmor_disabled"
        return
    fi

    echo "none"
}

_baseline_get_unused_services() {
    local unused=()
    local check_services=(
        "cups"           # Printing
        "avahi-daemon"   # mDNS
        "bluetooth"      # Bluetooth
        "ModemManager"   # Modem
        "whoopsie"       # Error reporting
        "apport"         # Crash reporting
    )

    for service in "${check_services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            unused+=("$service")
        fi
    done

    echo "${unused[*]}"
}

# ==============================================================================
# Baseline Audit
# ==============================================================================

baseline_audit() {
    local module="baseline"

    # Check Mandatory Access Control (SELinux/AppArmor)
    print_item "$(i18n 'baseline.check_mac')"
    _baseline_audit_mac

    # Check unused services
    print_item "$(i18n 'baseline.check_unused_services')"
    _baseline_audit_unused_services

    # Check file integrity tool (Lynis FINT-4350)
    print_item "$(i18n 'baseline.check_integrity')"
    _baseline_audit_integrity

    # Check for known-insecure legacy services (Lynis INSE-* family)
    print_item "$(i18n 'baseline.check_insecure_services' 2>/dev/null || echo 'Checking for insecure legacy services')"
    _baseline_audit_insecure_services
}

# Scan for telnet/rsh/finger/inetd/xinetd/NIS/tftp etc. — protocols
# that should never be on a modern cloud VPS. Lynis dedicates a whole
# tests_insecure_services file (INSE-* IDs); we condense to one check
# because the action is the same regardless of which one is found:
# stop the service and remove the package.
_baseline_audit_insecure_services() {
    local found=()
    local svc

    # Active services / sockets. Includes both service units and the
    # .socket form of activated daemons (telnet.socket etc).
    for svc in \
        telnet telnet.socket telnetd telnetd.socket \
        rsh rsh.socket rlogin rlogin.socket rexec rexec.socket \
        rsh-server rlogin-server rexec-server \
        finger fingerd \
        inetd openbsd-inetd xinetd \
        ypbind ypserv ypxfrd \
        tftpd tftpd-hpa tftp.socket \
        talk talkd ntalk \
        rwhod rwho \
    ; do
        if systemctl is-active --quiet "$svc" 2>/dev/null \
           || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            found+=("$svc(service)")
        fi
    done

    # Packages installed but maybe not active — still a finding because
    # a package may be enabled later, and shipped configs may include
    # weak defaults.
    # Installed-but-maybe-inactive insecure packages. Both the package names and
    # the query tool are distro-specific (distro.sh): Debian dpkg / RHEL rpm /
    # Arch pacman. The debian list is the same names as before, so Debian/Ubuntu
    # is unchanged; if distro.sh isn't loaded this scan is skipped (the active-
    # service scan above still ran).
    if declare -f distro_insecure_packages >/dev/null 2>&1; then
        local pkg
        for pkg in $(distro_insecure_packages); do
            if pkg_is_installed "$pkg"; then
                found+=("$pkg(pkg)")
            fi
        done
    fi

    if (( ${#found[@]} > 0 )); then
        local list; list=$(printf '%s ' "${found[@]}")
        local check=$(create_check_json \
            "baseline.insecure_services_active" \
            "baseline" \
            "high" \
            "failed" \
            "$(i18n 'baseline.insecure_services_active' "count=${#found[@]}" 2>/dev/null || echo "${#found[@]} insecure legacy service(s)/package(s) present")" \
            "Found: ${list% }" \
            "Disable the service (systemctl disable --now <name>) and remove the package (apt purge <name>)" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'baseline.insecure_services_active' "count=${#found[@]}" 2>/dev/null || echo "Insecure legacy services present")"
    else
        local check=$(create_check_json \
            "baseline.insecure_services_clean" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.insecure_services_clean' 2>/dev/null || echo 'No insecure legacy services found')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.insecure_services_clean' 2>/dev/null || echo 'No insecure legacy services found')"
    fi
}

# Detect a host-based file integrity monitoring tool. Mirrors Lynis
# FINT-4350; treated as a defence-in-depth control (low severity), not
# a baseline requirement.
_baseline_audit_integrity() {
    local found=""
    local t
    for t in aide aide.wrapper tripwire samhain afick integrit; do
        if command -v "$t" &>/dev/null; then
            found="$t"
            break
        fi
    done
    if [[ -z "$found" ]] && declare -f pkg_is_installed >/dev/null 2>&1; then
        # Integrity-tool package names are the same across distros; only the
        # query tool differs, so pkg_is_installed (dpkg/rpm/pacman) handles it.
        for t in aide tripwire samhain afick integrit ossec-hids-server ossec-hids-agent; do
            if pkg_is_installed "$t"; then
                found="$t"
                break
            fi
        done
    fi

    if [[ -n "$found" ]]; then
        local check=$(create_check_json \
            "baseline.integrity_installed" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.integrity_installed' "tool=$found")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.integrity_installed' "tool=$found")"
    else
        local check=$(create_check_json \
            "baseline.integrity_missing" \
            "baseline" \
            "low" \
            "failed" \
            "$(i18n 'baseline.integrity_missing')" \
            "No file integrity monitor (AIDE/Tripwire/Samhain) installed" \
            "Install a file integrity tool: apt install aide" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'baseline.integrity_missing')"
    fi
}

# Combined MAC (Mandatory Access Control) audit - SELinux + AppArmor
_baseline_audit_mac() {
    local mac_system=$(_baseline_detect_mac_system)

    case "$mac_system" in
        selinux)
            _baseline_audit_selinux
            ;;
        apparmor)
            _baseline_audit_apparmor
            ;;
        selinux_disabled)
            _baseline_audit_selinux_disabled
            ;;
        apparmor_disabled)
            _baseline_audit_apparmor_disabled
            ;;
        none)
            _baseline_audit_no_mac
            ;;
    esac
}

# ------------------------------------------------------------------------------
# SELinux Audit
# ------------------------------------------------------------------------------

_baseline_audit_selinux() {
    local status=$(_baseline_selinux_get_status)
    local config=$(_baseline_selinux_get_config)
    local policy=$(_baseline_selinux_get_policy)
    local denials=$(_baseline_selinux_denials_count)

    if [[ "$status" == "enforcing" ]]; then
        local check=$(create_check_json \
            "baseline.selinux_enforcing" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.selinux_enforcing')" \
            "SELinux enforcing, policy: ${policy:-targeted}, denials today: ${denials}" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.selinux_enforcing') (policy: ${policy:-targeted})"

        # Check for excessive denials
        if [[ "$denials" != "unknown" ]] && [[ "$denials" -gt 50 ]]; then
            local check=$(create_check_json \
                "baseline.selinux_many_denials" \
                "baseline" \
                "low" \
                "failed" \
                "$(i18n 'baseline.selinux_many_denials' "count=$denials")" \
                "High number of SELinux denials may indicate misconfiguration" \
                "Review denials: ausearch -m avc -ts today" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'baseline.selinux_many_denials' "count=$denials")"
        fi

    elif [[ "$status" == "permissive" ]]; then
        local check=$(create_check_json \
            "baseline.selinux_permissive" \
            "baseline" \
            "low" \
            "failed" \
            "$(i18n 'baseline.selinux_permissive')" \
            "SELinux is in permissive mode - violations are logged but not enforced" \
            "Set SELinux to enforcing: setenforce 1" \
            "baseline.selinux_set_enforcing")
        state_add_check "$check"
        print_severity "low" "$(i18n 'baseline.selinux_permissive')"

        # Check if configured as disabled (will be disabled on reboot)
        if [[ "$config" == "disabled" ]]; then
            print_warn "SELinux is configured as disabled in /etc/selinux/config"
        fi
    fi
}

_baseline_audit_selinux_disabled() {
    local config=$(_baseline_selinux_get_config)

    local check=$(create_check_json \
        "baseline.selinux_disabled" \
        "baseline" \
        "low" \
        "failed" \
        "$(i18n 'baseline.selinux_disabled')" \
        "SELinux is installed but disabled (config: ${config})" \
        "Enable SELinux in /etc/selinux/config and reboot" \
        "baseline.selinux_enable")
    state_add_check "$check"
    print_severity "low" "$(i18n 'baseline.selinux_disabled')"
}

# ------------------------------------------------------------------------------
# AppArmor Audit
# ------------------------------------------------------------------------------

_baseline_audit_apparmor() {
    local status=$(_baseline_apparmor_get_status)

    if [[ "$status" =~ ^enabled ]]; then
        # Parse enforced:complain counts
        local enforced=$(echo "$status" | cut -d: -f2)
        local complain=$(echo "$status" | cut -d: -f3)

        local check=$(create_check_json \
            "baseline.apparmor_enabled" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.apparmor_enabled')" \
            "AppArmor enabled: ${enforced} profiles enforcing, ${complain} in complain mode" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.apparmor_enabled') (enforcing: ${enforced}, complain: ${complain})"

        # Check if too many profiles in complain mode
        if [[ "$complain" -gt "$enforced" ]] && [[ "$complain" -gt 5 ]]; then
            local check=$(create_check_json \
                "baseline.apparmor_many_complain" \
                "baseline" \
                "low" \
                "failed" \
                "$(i18n 'baseline.apparmor_many_complain' "count=$complain")" \
                "Many AppArmor profiles in complain mode (not enforcing)" \
                "Review and set profiles to enforce mode" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'baseline.apparmor_many_complain' "count=$complain")"
        fi
    fi
}

_baseline_audit_apparmor_disabled() {
    local check=$(create_check_json \
        "baseline.apparmor_disabled" \
        "baseline" \
        "low" \
        "failed" \
        "$(i18n 'baseline.apparmor_disabled')" \
        "AppArmor is installed but not enabled" \
        "Enable AppArmor for additional security" \
        "baseline.enable_apparmor")
    state_add_check "$check"
    print_severity "low" "$(i18n 'baseline.apparmor_disabled')"
}

_baseline_audit_no_mac() {
    local check=$(create_check_json \
        "baseline.no_mac_system" \
        "baseline" \
        "low" \
        "failed" \
        "$(i18n 'baseline.no_mac_system')" \
        "No Mandatory Access Control system (SELinux/AppArmor) detected" \
        "Install and enable AppArmor or SELinux" \
        "baseline.enable_apparmor")
    state_add_check "$check"
    print_severity "low" "$(i18n 'baseline.no_mac_system')"
}

_baseline_audit_unused_services() {
    local unused=$(_baseline_get_unused_services)
    local count=$(echo "$unused" | wc -w)

    if ((count > 0)); then
        local check=$(create_check_json \
            "baseline.unused_services" \
            "baseline" \
            "low" \
            "failed" \
            "$(i18n 'baseline.unused_services' "count=$count")" \
            "$(i18n 'baseline.unused_services_desc' "services=$unused")" \
            "$(i18n 'baseline.review_unused_services')" \
            "baseline.disable_unused")
        state_add_check "$check"
        print_severity "low" "$(i18n 'baseline.unused_services' "count=$count"): $unused"
    else
        local check=$(create_check_json \
            "baseline.no_unused_services" \
            "baseline" \
            "low" \
            "passed" \
            "$(i18n 'baseline.no_unused_services')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'baseline.no_unused_services')"
    fi
}

# ==============================================================================
# Baseline Fix Functions
# ==============================================================================

baseline_fix() {
    local fix_id="$1"

    case "$fix_id" in
        baseline.enable_apparmor)
            _baseline_fix_enable_apparmor
            ;;
        baseline.disable_unused)
            _baseline_fix_disable_unused
            ;;
        baseline.selinux_set_enforcing)
            _baseline_fix_selinux_enforcing
            ;;
        baseline.selinux_enable)
            _baseline_fix_selinux_enable
            ;;
        *)
            log_error "Unknown baseline fix: $fix_id"
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# SELinux Fix Functions
# ------------------------------------------------------------------------------

_baseline_fix_selinux_enforcing() {
    print_info "$(i18n 'baseline.setting_selinux_enforcing')"

    # Set enforcing mode immediately
    if check_command setenforce; then
        setenforce 1 2>/dev/null
        if [[ "$(_baseline_selinux_get_status)" == "enforcing" ]]; then
            print_ok "$(i18n 'baseline.selinux_enforcing_set')"

            # Update config file for persistence. Verify the edit produced the
            # intended SELINUX=enforcing line; if it did not (e.g. an unexpected
            # config layout with no SELINUX= line), restore the backup so we
            # never leave a half-edited /etc/selinux/config that could
            # mis-initialise SELinux on the next boot.
            if [[ -f /etc/selinux/config ]]; then
                local sel_bak
                sel_bak=$(backup_file /etc/selinux/config)
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                if grep -qE '^SELINUX=enforcing[[:space:]]*$' /etc/selinux/config; then
                    print_ok "$(i18n 'baseline.selinux_config_updated')"
                else
                    print_error "$(i18n 'baseline.selinux_config_restore' 2>/dev/null || echo 'Unexpected /etc/selinux/config layout; restored from backup - set SELINUX=enforcing manually')"
                    [[ -n "$sel_bak" && -f "$sel_bak" ]] && cp -p "$sel_bak" /etc/selinux/config
                fi
            fi
            return 0
        else
            print_error "$(i18n 'baseline.selinux_enforcing_failed')"
            return 1
        fi
    else
        print_error "setenforce command not found"
        return 1
    fi
}

_baseline_fix_selinux_enable() {
    print_warn "$(i18n 'baseline.selinux_enable_manual')"
    echo ""
    echo "$(i18n 'baseline.selinux_enable_steps'):"
    echo "  1. Edit /etc/selinux/config"
    echo "  2. Set SELINUX=enforcing (or permissive for testing)"
    echo "  3. Set SELINUXTYPE=targeted"
    echo "  4. Reboot the system"
    echo ""
    echo "$(i18n 'common.warning'): Enabling SELinux requires a system reboot"
    echo "$(i18n 'baseline.selinux_relabel_warning')"
    return 1  # Manual intervention required
}

_baseline_fix_enable_apparmor() {
    print_info "$(i18n 'baseline.enabling_apparmor')"

    # Install if needed
    if ! check_command aa-status; then
        apt-get install -y apparmor apparmor-utils 2>/dev/null
    fi

    # Enable and start
    systemctl enable apparmor
    systemctl start apparmor

    if _baseline_apparmor_enabled; then
        print_ok "$(i18n 'baseline.apparmor_enabled_success')"
        return 0
    else
        print_error "$(i18n 'baseline.apparmor_enable_failed')"
        return 1
    fi
}

_baseline_fix_disable_unused() {
    local unused=$(_baseline_get_unused_services)
    local failed=0

    for service in $unused; do
        print_info "$(i18n 'baseline.disabling_service' "service=$service")"
        if systemctl disable "$service" 2>/dev/null && systemctl stop "$service" 2>/dev/null; then
            print_ok "$(i18n 'baseline.service_disabled' "service=$service")"
        else
            print_warn "$(i18n 'baseline.service_disable_failed' "service=$service")"
            ((failed++)) || true
        fi
    done

    return $failed
}
