#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# System update module
# Copyright (c) 2024

# ==============================================================================
# Update Helper Functions
# ==============================================================================

# Check if APT is locked
_update_apt_locked() {
    lsof /var/lib/dpkg/lock-frontend &>/dev/null || \
    lsof /var/lib/apt/lists/lock &>/dev/null || \
    lsof /var/cache/apt/archives/lock &>/dev/null
}

# Get count of available updates
_update_get_count() {
    local count
    count=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst ") || true
    echo "${count:-0}"
}

# Get count of security updates
_update_get_security_count() {
    local count
    count=$(apt-get -s upgrade 2>/dev/null | grep -c "security") || true
    echo "${count:-0}"
}

# Check if unattended-upgrades is installed
_update_unattended_installed() {
    dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"
}

# Read from merged apt-config dump (not 20auto-upgrades directly) so drop-in overrides are caught.
_update_unattended_periodic_from_dump() {
    local val
    val=$(awk -F'"' '/^APT::Periodic::Unattended-Upgrade /{print $2; exit}' <<<"$1")
    [[ "$val" == "1" ]]
}

# Match list elements (`Key:: "value";`) only; skip the empty-list anchor (`Key "";`).
_update_unattended_origins_from_dump() {
    grep -qE '^Unattended-Upgrade::(Origins-Pattern|Allowed-Origins):: "[^"]+";' <<<"$1"
}

# Echoes ok|service_disabled|periodic_off|no_origins|unknown; returns 0 iff ok.
_update_unattended_status() {
    if ! systemctl is-enabled unattended-upgrades &>/dev/null; then
        echo "service_disabled"
        return 1
    fi
    if ! command -v apt-config >/dev/null 2>&1; then
        echo "unknown"
        return 1
    fi
    local dump
    dump=$(apt-config dump 2>/dev/null) || { echo "unknown"; return 1; }

    if ! _update_unattended_periodic_from_dump "$dump"; then
        echo "periodic_off"
        return 1
    fi
    if ! _update_unattended_origins_from_dump "$dump"; then
        echo "no_origins"
        return 1
    fi

    echo "ok"
    return 0
}

_update_unattended_enabled() {
    [[ "$(_update_unattended_status)" == "ok" ]]
}

# Pure-data variant for tests. Returns 0 when needrestart batch output
# reports a kernel reboot is pending: NEEDRESTART-KSTA in {2,3} per
# liske/needrestart docs (1=current, 2=ABI-compat upgrade, 3=full
# version upgrade, 0=detection failure). 2 is included on purpose —
# operationally an ABI-compat kernel still calls for a reboot to run
# the new version.
_update_needrestart_kernel_pending() {
    local ksta
    ksta=$(awk -F': ' '/^NEEDRESTART-KSTA:/ {print $2; exit}' <<<"$1")
    [[ "$ksta" =~ ^[0-9]+$ ]] && (( ksta >= 2 ))
}

# Latest installed linux-image package version (e.g. 6.12.88+deb13-amd64).
# Empty string if dpkg unavailable or no kernel package installed.
_update_latest_installed_kernel() {
    command -v dpkg-query >/dev/null 2>&1 || return 0
    dpkg-query -W -f='${Status}\t${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
        | awk -F'\t' '$1 == "install ok installed" {sub(/^linux-image-/, "", $2); print $2}' \
        | sort -V | tail -1
}

# True when the running kernel version differs from the latest installed
# linux-image package.
_update_running_kernel_outdated() {
    local running latest
    running="$(uname -r)"
    latest="$(_update_latest_installed_kernel)"
    [[ -n "$running" && -n "$latest" && "$running" != "$latest" ]]
}

# Check if system reboot is required.
# /var/run/reboot-required is created by the `update-notifier-common`
# package (Ubuntu default; not installed on stock Debian), so on a
# Debian box without it the file may never exist even after kernel /
# glibc updates. needrestart (default-installed on Debian 12+) is the
# preferred distro-agnostic signal. As a final fallback we compare the
# running kernel against the latest installed linux-image package —
# catches stock Debian hosts that have neither update-notifier-common
# nor needrestart available (real case surfaced by Lynis cross-check
# against KRNL-5830).
_update_reboot_required() {
    [[ -f /var/run/reboot-required ]] && return 0
    if command -v needrestart >/dev/null 2>&1; then
        local out
        if out=$(needrestart -k -b 2>/dev/null); then
            _update_needrestart_kernel_pending "$out" && return 0
        fi
    fi
    _update_running_kernel_outdated
}

# Get reboot required packages
_update_reboot_packages() {
    if [[ -f /var/run/reboot-required.pkgs ]]; then
        cat /var/run/reboot-required.pkgs 2>/dev/null
        return
    fi
    # needrestart fallback: surface the kernel-version delta as
    # informational context (no per-package list available).
    if command -v needrestart >/dev/null 2>&1; then
        local nr_out kcur kexp
        if nr_out=$(needrestart -k -b 2>/dev/null); then
            kcur=$(awk -F': ' '/^NEEDRESTART-KCUR:/ {print $2; exit}' <<<"$nr_out")
            kexp=$(awk -F': ' '/^NEEDRESTART-KEXP:/ {print $2; exit}' <<<"$nr_out")
            if [[ -n "$kcur" && -n "$kexp" && "$kcur" != "$kexp" ]]; then
                echo "kernel: ${kcur} → ${kexp}"
                return
            fi
        fi
    fi
    # Direct dpkg fallback when no other source is available.
    if _update_running_kernel_outdated; then
        echo "kernel: $(uname -r) → $(_update_latest_installed_kernel)"
    fi
}

# Check time synchronization status
_update_check_timesync() {
    local issues=()

    # Check if timesyncd is active
    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        # Check if time is synchronized
        if timedatectl show 2>/dev/null | grep -q "NTPSynchronized=yes"; then
            echo "synced:timesyncd"
            return 0
        else
            issues+=("timesyncd active but not synchronized")
        fi
    # Check if ntpd is running
    elif systemctl is-active --quiet ntp 2>/dev/null || \
         systemctl is-active --quiet ntpd 2>/dev/null; then
        echo "synced:ntpd"
        return 0
    # Check if chronyd is running
    elif systemctl is-active --quiet chronyd 2>/dev/null; then
        if chronyc tracking 2>/dev/null | grep -q "Leap status.*Normal"; then
            echo "synced:chronyd"
            return 0
        else
            issues+=("chronyd active but not synchronized")
        fi
    else
        issues+=("No NTP service running")
    fi

    printf '%s\n' "${issues[@]}"
    return 1
}

# ==============================================================================
# Update Audit
# ==============================================================================

update_audit() {
    local module="update"

    # Check APT lock
    print_item "$(i18n 'update.check_apt_lock')"
    _update_audit_apt_lock

    # Check available updates
    print_item "$(i18n 'update.check_updates')"
    _update_audit_available

    # Check unattended-upgrades
    print_item "$(i18n 'update.check_unattended')"
    _update_audit_unattended

    # Check if reboot is required
    print_item "$(i18n 'update.check_reboot')"
    _update_audit_reboot

    # Check time synchronization
    print_item "$(i18n 'update.check_timesync')"
    _update_audit_timesync
}

_update_audit_apt_lock() {
    if pkg_manager_locked; then
        local check=$(create_check_json \
            "update.apt_locked" \
            "update" \
            "low" \
            "failed" \
            "$(i18n 'update.apt_locked')" \
            "APT is locked by another process" \
            "Wait for other process to finish or remove lock" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'update.apt_locked')"
    else
        local check=$(create_check_json \
            "update.apt_available" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.apt_available')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.apt_available')"
    fi
}

_update_audit_available() {
    # Read-only: do NOT refresh the package index here. Auditing must not mutate
    # state or hit the network, and refreshing would defeat the index-age signal
    # below. Counts come from the existing metadata cache via distro.sh.
    local update_count security_count sec_shown
    update_count=$(pkg_update_count)
    security_count=$(pkg_security_update_count)

    if ((update_count == 0)); then
        local check=$(create_check_json \
            "update.no_updates" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.no_updates')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.no_updates')"
    else
        # Severity model:
        #   no security updates                     → low (routine pending pkgs)
        #   security updates pending                → medium
        #   security updates AND index stale (>30d) → high (operator hasn't even
        #                                             pulled the index in a month
        #                                             — the lag is the finding)
        # security_count < 0 means the distro has no security-update channel
        # (Arch, rolling) → don't escalate. It's an upper bound on dnf, so the
        # displayed figure is clamped to the total update count.
        local severity="low"
        local fix_id=""
        local sec_desc=""

        if ((security_count > 0)); then
            severity="medium"
            fix_id="update.apply_security"

            sec_shown=$security_count
            if ((sec_shown > update_count)); then sec_shown=$update_count; fi
            sec_desc="Security updates: $sec_shown"

            local stale_days
            stale_days=$(pkg_index_age_days)
            if [[ -n "$stale_days" ]] && (( stale_days > 30 )); then
                severity="high"
            fi
        fi

        local check=$(create_check_json \
            "update.updates_available" \
            "update" \
            "$severity" \
            "failed" \
            "$(i18n 'update.updates_available' "count=$update_count")" \
            "$sec_desc" \
            "Apply pending updates with the system package manager" \
            "$fix_id")
        state_add_check "$check"

        if ((security_count > 0)); then
            print_severity "$severity" "$(i18n 'update.security_updates' "count=$sec_shown")"
        else
            print_severity "low" "$(i18n 'update.updates_available' "count=$update_count")"
        fi
    fi
}

# Return how many days ago `apt update` last ran, or empty if we can't
# tell. Used as a "is the operator paying attention" signal — a host
# that has security updates pending *and* hasn't pulled the index in
# weeks is qualitatively worse than one that's a day behind.
_update_apt_list_age_days() {
    local marker=""
    if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
        marker=/var/lib/apt/periodic/update-success-stamp
    elif [[ -d /var/lib/apt/lists ]]; then
        # Fall back to the newest mtime in the lists dir; -t sorts by mtime.
        marker=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Packages*' 2>/dev/null | head -1)
    fi
    [[ -z "$marker" ]] && return 0
    [[ ! -e "$marker" ]] && return 0

    local mtime now age_seconds
    mtime=$(stat -c %Y "$marker" 2>/dev/null || stat -f %m "$marker" 2>/dev/null)
    [[ -z "$mtime" ]] && return 0
    now=$(date +%s)
    age_seconds=$(( now - mtime ))
    (( age_seconds < 0 )) && age_seconds=0
    echo $(( age_seconds / 86400 ))
}

_update_audit_unattended() {
    local status
    status=$(auto_update_status) || true

    # Arch (rolling) has no native auto-update mechanism — that's normal, not a
    # finding. Mark passed so it doesn't penalise the score.
    if [[ "$status" == "unsupported" ]]; then
        local check=$(create_check_json \
            "update.unattended_unsupported" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.unattended_unsupported' 2>/dev/null || echo 'No native auto-update mechanism (distro default)')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.unattended_unsupported' 2>/dev/null || echo 'No native auto-update mechanism (distro default)')"
        return
    fi

    if ! auto_update_installed; then
        local check=$(create_check_json \
            "update.unattended_not_installed" \
            "update" \
            "low" \
            "failed" \
            "$(i18n 'update.unattended_disabled')" \
            "no automatic-update mechanism installed (unattended-upgrades / dnf-automatic)" \
            "$(i18n 'update.fix_install_unattended')" \
            "update.install_unattended")
        state_add_check "$check"
        print_severity "low" "$(i18n 'update.unattended_disabled')"
        return
    fi

    if [[ "$status" == "ok" ]]; then
        local check=$(create_check_json \
            "update.unattended_enabled" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.unattended_enabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.unattended_enabled')"
    else
        local reason_desc
        case "$status" in
            service_disabled)
                reason_desc="auto-update service/timer is not enabled" ;;
            periodic_off)
                reason_desc="auto-update is installed but not set to apply updates" ;;
            no_origins)
                reason_desc="unattended-upgrades has no Origins-Pattern/Allowed-Origins configured" ;;
            *)
                reason_desc="auto-update mechanism installed but not effective" ;;
        esac

        local check=$(create_check_json \
            "update.unattended_disabled" \
            "update" \
            "low" \
            "failed" \
            "$(i18n 'update.unattended_disabled')" \
            "$reason_desc" \
            "$(i18n 'update.fix_install_unattended')" \
            "update.enable_unattended")
        state_add_check "$check"
        print_severity "low" "$(i18n 'update.unattended_disabled')"
    fi
}

_update_audit_reboot() {
    if pkg_reboot_required; then
        local packages=$(_update_reboot_packages)
        local pkg_list=""
        if [[ -n "$packages" ]]; then
            pkg_list=$(echo "$packages" | head -5 | tr '\n' ', ')
            pkg_list="${pkg_list%, }"
        fi

        local check=$(create_check_json \
            "update.reboot_required" \
            "update" \
            "medium" \
            "failed" \
            "$(i18n 'update.reboot_required')" \
            "Packages requiring reboot: $pkg_list" \
            "Schedule a system reboot to apply kernel/security updates" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'update.reboot_required')"
    else
        local check=$(create_check_json \
            "update.no_reboot" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.no_reboot')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.no_reboot')"
    fi
}

_update_audit_timesync() {
    local sync_status
    sync_status=$(_update_check_timesync)
    local result=$?

    if [[ $result -eq 0 ]]; then
        local service="${sync_status#*:}"
        local check=$(create_check_json \
            "update.timesync_ok" \
            "update" \
            "low" \
            "passed" \
            "$(i18n 'update.timesync_ok')" \
            "Time synchronized via $service" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'update.timesync_ok') ($service)"
    else
        local check=$(create_check_json \
            "update.timesync_failed" \
            "update" \
            "low" \
            "failed" \
            "$(i18n 'update.timesync_failed')" \
            "$sync_status" \
            "Enable time synchronization: timedatectl set-ntp true" \
            "update.enable_timesync")
        state_add_check "$check"
        print_severity "low" "$(i18n 'update.timesync_failed')"
    fi
}

# ==============================================================================
# Update Fix Functions
# ==============================================================================

update_fix() {
    local fix_id="$1"

    case "$fix_id" in
        update.apply_security)
            _update_fix_apply_security
            ;;
        update.install_unattended)
            _update_fix_install_unattended
            ;;
        update.enable_unattended)
            _update_fix_enable_unattended
            ;;
        *)
            log_error "Unknown update fix: $fix_id"
            return 1
            ;;
    esac
}

_update_fix_apply_security() {
    print_info "$(i18n 'update.applying_updates')"

    # Honor the function name. Previous fallback was `apt-get upgrade -y`
    # which upgrades EVERY package (database, web server, language
    # runtimes, etc.) — not what an "apply security updates" function
    # should ever do. If unattended-upgrades is missing we install it
    # and use it; if it then fails, we surface the error rather than
    # silently doing something different.
    if ! _update_unattended_installed; then
        print_info "$(i18n 'update.installing_unattended_for_security')"
        export DEBIAN_FRONTEND=noninteractive
        if ! apt-get install -y unattended-upgrades; then
            print_error "$(i18n 'update.unattended_install_failed')"
            print_info "$(i18n 'update.security_aborted_install_uu_first')"
            return 1
        fi
    fi

    if unattended-upgrade -d 2>/dev/null; then
        print_ok "$(i18n 'update.updates_applied')"
        return 0
    fi

    print_error "$(i18n 'update.updates_failed')"
    print_info "$(i18n 'update.check_uu_log')"
    return 1
}

_update_fix_install_unattended() {
    print_info "$(i18n 'update.installing_unattended')"

    export DEBIAN_FRONTEND=noninteractive

    if apt-get install -y unattended-upgrades apt-listchanges; then
        # Configure auto-upgrades
        _update_fix_enable_unattended
        return $?
    else
        print_error "$(i18n 'update.unattended_install_failed')"
        return 1
    fi
}

_update_fix_enable_unattended() {
    print_info "$(i18n 'update.configuring_unattended')"

    # Create auto-upgrades config
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    # Configure unattended-upgrades for security only
    local uu_config="/etc/apt/apt.conf.d/50unattended-upgrades"

    if [[ -f "$uu_config" ]]; then
        backup_file "$uu_config"
    fi

    # Get OS info for proper origin pattern
    local os=$(detect_os)
    local codename=$(detect_os_codename)

    cat > "$uu_config" <<EOF
// vpssec unattended-upgrades configuration
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot if required (disabled by default for safety)
Unattended-Upgrade::Automatic-Reboot "false";

// Mail report (optional)
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "on-change";

// Logging
Unattended-Upgrade::SyslogEnable "true";
EOF

    # Enable and start service
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades

    if _update_unattended_enabled; then
        print_ok "$(i18n 'update.unattended_configured')"
        return 0
    else
        print_error "$(i18n 'update.unattended_enable_failed')"
        return 1
    fi
}
