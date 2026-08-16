#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Baseline hardening module (Enhanced with SELinux support)
# Copyright (c) 2024

# --- Baseline Configuration ---

# Variables, not literals, so the audit predicate and the fix cannot point at
# different places and the fixes stay reachable from a test.
BASELINE_SELINUX_CONFIG="/etc/selinux/config"
# The kernel-level "SELinux is real on this host" signal; see
# _baseline_selinux_installed for why userspace tooling is not enough.
BASELINE_SELINUX_FS_ENFORCE="/sys/fs/selinux/enforce"
BASELINE_AUDIT_LOG="/var/log/audit/audit.log"
# Profiles the operator switched off. A symlink here removes the profile from
# AppArmor's view entirely, so it counts as neither enforced nor complaining —
# without reading it, a disabled profile is indistinguishable from an absent one.
BASELINE_APPARMOR_DISABLE_DIR="/etc/apparmor.d/disable"

# --- Baseline Helper Functions ---

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

# Echoes "<enforced>:<complain>". Prefers `aa-status --json`, falling back to
# the human-readable form under LC_ALL=C so the regex survives a translated
# locale.
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

# Names of the profiles under BASELINE_APPARMOR_DISABLE_DIR, one per line.
# Echoes nothing when the directory is absent or empty, which is the stock
# state on every distro that ships AppArmor.
_baseline_apparmor_disabled_profiles() {
    [[ -d "$BASELINE_APPARMOR_DISABLE_DIR" ]] || return 0
    # -maxdepth 1 because AppArmor does not recurse here, and `! -name '.*'`
    # so editor leftovers are not reported. sed rather than -printf '%f',
    # which is a GNU extension this suite cannot assume.
    find "$BASELINE_APPARMOR_DISABLE_DIR" -maxdepth 1 -mindepth 1 \
         ! -name '.*' 2>/dev/null | sed 's|.*/||' | sort
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
    # Gate on the KERNEL LSM, never userspace tooling: selinux-utils puts
    # getenforce on PATH while the kernel has no SELinux at all. This path
    # exists only when the LSM is really loaded.
    [[ -e "$BASELINE_SELINUX_FS_ENFORCE" ]] || return 1
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
    if [[ -f "$BASELINE_SELINUX_CONFIG" ]]; then
        grep -E "^SELINUX=" "$BASELINE_SELINUX_CONFIG" 2>/dev/null | cut -d= -f2 | tr -d '"'
    else
        echo "not_configured"
    fi
}

_baseline_selinux_get_policy() {
    if check_command sestatus; then
        sestatus 2>/dev/null | grep "Loaded policy name" | awk '{print $4}'
    elif [[ -f "$BASELINE_SELINUX_CONFIG" ]]; then
        grep -E "^SELINUXTYPE=" "$BASELINE_SELINUX_CONFIG" 2>/dev/null | cut -d= -f2 | tr -d '"'
    fi
}

_baseline_selinux_denials_count() {
    # awk, never `grep -c ... || echo 0`: grep already prints 0 on no matches
    # and exits 1, so the fallback appends a second one and the caller's
    # arithmetic dies. awk's `c+0` always yields one integer.
    if check_command ausearch; then
        ausearch -m avc -ts today 2>/dev/null | awk '/type=AVC/ {c++} END {print c+0}'
    elif [[ -f "$BASELINE_AUDIT_LOG" ]]; then
        awk '/type=AVC.*denied/ {c++} END {print c+0}' "$BASELINE_AUDIT_LOG" 2>/dev/null
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

    local service state
    for service in "${check_services[@]}"; do
        # Match the state WORD, never the exit status: is-enabled also exits
        # 0 for static and alias units, which `disable` cannot act on. tail -n1
        # drops the sysv notice; `|| state=""` survives an absent unit.
        state=$(systemctl is-enabled "$service" 2>/dev/null | tail -n1) || state=""
        case "$state" in
            enabled|enabled-runtime) unused+=("$service") ;;
        esac
    done

    echo "${unused[*]}"
}

# --- Baseline Audit ---

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

# Scan for legacy plaintext protocols that should not be on a cloud VPS.
# One check rather than many, because the action is the same whichever is
# found: stop the service and remove the package.
_baseline_audit_insecure_services() {
    local found=()
    local svc

    # Both service units and the .socket form of activated daemons. The
    # generic super-servers are deliberately absent: a supervisor is not
    # itself insecure, only the protocols it serves, which are listed here.
    for svc in \
        telnet telnet.socket telnetd telnetd.socket \
        rsh rsh.socket rlogin rlogin.socket rexec rexec.socket \
        rsh-server rlogin-server rexec-server \
        finger fingerd \
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

    # Installed but possibly inactive packages are still a finding: one can be
    # enabled later, and shipped configs carry weak defaults. Names and query
    # tool both come from distro.sh; the scan is skipped when it is absent.
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
            "Disable the service (systemctl disable --now <name>) and remove the package ($(pkg_remove_hint '<name>' || echo 'with your package manager'))" \
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
        # Name a command only where one exists. AIDE is not in Arch's own
        # repositories, so the old `apt install aide` had no honest
        # replacement there — the tools are named instead.
        local integrity_pkg integrity_cmd integrity_hint
        integrity_pkg=$(distro_integrity_package)
        if [[ -n "$integrity_pkg" ]] && integrity_cmd=$(pkg_install_hint "$integrity_pkg"); then
            integrity_hint="Install a file integrity tool: $integrity_cmd"
        else
            integrity_hint="Install a file integrity tool (AIDE, Tripwire or Samhain)"
        fi
        local check=$(create_check_json \
            "baseline.integrity_missing" \
            "baseline" \
            "low" \
            "failed" \
            "$(i18n 'baseline.integrity_missing')" \
            "No file integrity monitor (AIDE/Tripwire/Samhain) installed" \
            "$integrity_hint" \
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

    _baseline_audit_apparmor_disabled_profiles
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
            print_warn "SELinux is configured as disabled in $BASELINE_SELINUX_CONFIG"
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

# Explicitly disabled profiles. Deliberately NOT part of the apparmor audit,
# which runs on only one branch of the MAC dispatch: this is worth reporting
# whether AppArmor is off entirely or SELinux won the dispatch.
_baseline_audit_apparmor_disabled_profiles() {
    _baseline_apparmor_installed || return 0

    local disabled disabled_count
    disabled=$(_baseline_apparmor_disabled_profiles)
    disabled_count=$(count_lines "$disabled")
    (( disabled_count > 0 )) || return 0

    local list
    list=$(echo "$disabled" | tr '\n' ' ' | sed 's/ $//')
    local check
    check=$(create_check_json \
        "baseline.apparmor_profiles_disabled" \
        "baseline" \
        "low" \
        "failed" \
        "$(i18n 'baseline.apparmor_profiles_disabled' "count=$disabled_count")" \
        "$(i18n 'baseline.apparmor_profiles_disabled_desc' "list=$list")" \
        "$(i18n 'baseline.apparmor_profiles_disabled_fix' "dir=$BASELINE_APPARMOR_DISABLE_DIR")" \
        "")
    state_add_check "$check"
    print_severity "low" "$(i18n 'baseline.apparmor_profiles_disabled' "count=$disabled_count")"
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

# --- Baseline Fix Functions ---

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

    if ! check_command setenforce; then
        print_error "setenforce command not found"
        return 1
    fi

    # Set enforcing mode immediately
    setenforce 1 2>/dev/null || true
    if [[ "$(_baseline_selinux_get_status)" != "enforcing" ]]; then
        print_error "$(i18n 'baseline.selinux_enforcing_failed')"
        return 1
    fi
    print_ok "$(i18n 'baseline.selinux_enforcing_set')"

    # setenforce does not survive a reboot — only SELINUX= in the config does.
    # Both branches return 1: the runtime change happened, but returning 0
    # records a host as fixed that comes back permissive at the next boot.
    if [[ ! -f "$BASELINE_SELINUX_CONFIG" ]]; then
        print_warn "$(i18n 'baseline.selinux_runtime_only' "file=$BASELINE_SELINUX_CONFIG")"
        return 1
    fi

    backup_file "$BASELINE_SELINUX_CONFIG" >/dev/null || return 1

    # Validate the staged content BEFORE it nears the file that decides how
    # SELinux initialises at boot: an unexpected layout must be discovered
    # before the live file is rewritten, not after.
    local staged
    staged=$(sed 's/^SELINUX=.*/SELINUX=enforcing/' "$BASELINE_SELINUX_CONFIG") || staged=""
    if ! grep -qE '^SELINUX=enforcing[[:space:]]*$' <<<"$staged"; then
        print_error "$(i18n 'baseline.selinux_config_restore' "file=$BASELINE_SELINUX_CONFIG")"
        return 1
    fi

    if ! write_file_atomic "$BASELINE_SELINUX_CONFIG" "$staged"; then
        print_error "$(i18n 'baseline.selinux_config_write_failed' "file=$BASELINE_SELINUX_CONFIG")"
        return 1
    fi

    print_ok "$(i18n 'baseline.selinux_config_updated')"
    return 0
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

    # A swallowed install failure makes the operator read "Failed to enable
    # AppArmor", pointing at the service rather than the apt transaction.
    if ! check_command aa-status; then
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils 2>/dev/null; then
            print_error "$(i18n 'baseline.apparmor_install_failed')"
            return 1
        fi
    fi

    # Neither status is decisive alone: a unit can be enabled and still refuse
    # to start. The postcondition below is what the return value rests on.
    systemctl enable apparmor || log_warn "systemctl enable apparmor failed"
    systemctl start apparmor || log_warn "systemctl start apparmor failed"

    if _baseline_apparmor_enabled; then
        print_ok "$(i18n 'baseline.apparmor_enabled_success')"
        return 0
    else
        print_error "$(i18n 'baseline.apparmor_enable_failed')"
        return 1
    fi
}

_baseline_fix_disable_unused() {
    local unused
    unused=$(_baseline_get_unused_services)
    local failed=0
    local service
    local disabled=()

    for service in $unused; do
        print_info "$(i18n 'baseline.disabling_service' "service=$service")"

        # Run independently, never chained with &&: a failed disable would
        # skip the stop, and a failed stop would hide a disable that landed.
        local ok=1
        if ! systemctl disable "$service" 2>/dev/null; then
            log_warn "systemctl disable $service failed"
            ok=0
        fi
        if ! systemctl stop "$service" 2>/dev/null; then
            log_warn "systemctl stop $service failed"
            ok=0
        fi

        if (( ok )); then
            print_ok "$(i18n 'baseline.service_disabled' "service=$service")"
            disabled+=("$service")
        else
            print_warn "$(i18n 'baseline.service_disable_failed' "service=$service")"
            failed=$((failed + 1))
        fi
    done

    # rollback restores FILES, so a disabled unit is invisible to it. Print
    # AND log the undo command: a printed line scrolls away, and this one may
    # be needed days later.
    if (( ${#disabled[@]} > 0 )); then
        local revert="systemctl enable --now ${disabled[*]}"
        print_info "$(i18n 'baseline.services_revert_hint' "cmd=$revert")"
        log_info "baseline.disable_unused revert command: $revert"
    fi

    (( failed == 0 ))
}
