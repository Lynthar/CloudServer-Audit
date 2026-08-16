#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# System update module
# Copyright (c) 2024

# --- Update Configuration ---

# The two files the unattended-upgrades fix writes. The audit deliberately
# reads the MERGED apt-config dump instead, since a drop-in can override
# either, so these belong to the fix alone.
UPDATE_AUTO_UPGRADES_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
UPDATE_UU_DROPIN="/etc/apt/apt.conf.d/52vpssec-unattended-security"

# --- Update Helper Functions ---

# There is deliberately no local lock / count / index-age predicate here:
# they were apt-only copies of distro.sh primitives with zero callers.
# Ask distro.sh — a second copy only grows a second version of the truth.

# (Same rule as above: no local duplicates of the distro.sh count primitives.)

# Whether automatic updates are installed / effective. Both delegate to
# core/distro.sh, which is what the AUDIT asks, so the fix's success gate and
# the finding it clears cannot disagree. Never keep a second copy.
_update_unattended_installed() {
    auto_update_installed
}

_update_unattended_enabled() {
    [[ "$(auto_update_status)" == "ok" ]]
}

# Pure-data variant for tests. 0 when needrestart reports a pending kernel
# reboot: NEEDRESTART-KSTA in {2,3}. 2 is included on purpose — an
# ABI-compatible kernel still needs a reboot to actually run.
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

# Is a reboot required? Three signals, none universal: reboot-required exists
# only with update-notifier-common, needrestart is the portable preference,
# and the kernel comparison catches a host that has neither.
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

# --- Update Audit ---

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
    # NTP / time-sync is audited authoritatively by the timezone module
    # (_timezone_check_ntp). It used to be duplicated here; removed so a
    # single module owns the NTP score signal.
}

_update_audit_apt_lock() {
    # Three-way on purpose: `if pkg_manager_locked` collapses "could not
    # determine" into the passing branch. `|| lock_rc=$?`, never a bare call
    # plus `$?` — that form aborts the caller outside a condition context.
    local lock_rc=0
    pkg_manager_locked || lock_rc=$?

    if (( lock_rc == 0 )); then
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
    elif (( lock_rc == 2 )); then
        # failed + info, and both halves are deliberate: a passed check
        # renders as a one-line tick nobody expands, and putting a number on
        # a non-observation is how a host earns a free pass.
        local check=$(create_check_json \
            "update.lock_state_unknown" \
            "update" \
            "low" \
            "failed" \
            "$(i18n 'update.lock_state_unknown')" \
            "$(i18n 'update.lock_state_unknown_desc')" \
            "$(i18n 'update.lock_state_unknown_fix')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'update.lock_state_unknown')"
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
    # NEVER refresh the index here: an audit must not mutate state, and it
    # would defeat the index-age signal below. Both primitives return non-zero
    # when the QUERY failed, which is not "no updates".
    local update_count security_count sec_shown
    if ! update_count=$(pkg_update_count) || \
       ! security_count=$(pkg_security_update_count); then
        local check=$(create_check_json \
            "update.check_failed" \
            "update" \
            "low" \
            "failed" \
            "$(i18n 'update.check_failed')" \
            "$(i18n 'update.check_failed_desc')" \
            "$(i18n 'update.check_failed_fix')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'update.check_failed')"
        return 0
    fi

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
        # low for routine packages, medium once security updates are pending,
        # high when the index is also stale — the lag IS the finding.
        # A negative count means no security channel, so no escalation.
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

# (No local index-age duplicate here either — ask distro.sh.)

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

# --- Update Fix Functions ---

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

    # NEVER fall back to `apt-get upgrade -y`: that upgrades every package on
    # the host, which is not what "apply security updates" may do. Install
    # unattended-upgrades and use it, or surface the failure.
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
        # rollback restores config FILES, so installed packages are invisible
        # to it. This message is the operator's only pointer to what changed.
        print_info "$(i18n 'update.security_applied_revert_hint')"
        log_info "update.apply_security: upgraded packages are listed in /var/log/apt/history.log"
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

    # backup_file is UNCONDITIONAL: recording an absent path is the only
    # thing that lets a rollback delete this file, and on a first run — the
    # common case here — it does not exist.
    backup_file "$UPDATE_AUTO_UPGRADES_CONF" >/dev/null || return 1
    if ! write_file_atomic "$UPDATE_AUTO_UPGRADES_CONF" 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";'; then
        print_error "$(i18n 'update.auto_upgrades_write_failed' "file=$UPDATE_AUTO_UPGRADES_CONF")"
        return 1
    fi

    # A 52- fragment read AFTER 50, never an overwrite of the distro conffile.
    # MUST be Origins-Pattern with codename=/label=: Allowed-Origins matches on
    # Suite, and Debian's is "stable-security", so it matches NOTHING.
    local uu_dropin="$UPDATE_UU_DROPIN"
    local origins
    if [[ "$(detect_os)" == "ubuntu" ]]; then
        origins='    "origin=${distro_id},archive=${distro_codename}-security";
    "origin=${distro_id}ESMApps,archive=${distro_codename}-apps-security";
    "origin=${distro_id}ESM,archive=${distro_codename}-infra-security";'
    else
        origins='    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";'
    fi

    # Unconditional, for the reason given above: this drop-in is vpssec's own
    # file, so it never exists on a first run and the rollback needs it
    # recorded as created.
    backup_file "$uu_dropin" >/dev/null || return 1
    # Double-quoted so ${origins} interpolates. The ${distro_id} placeholders
    # inside it were single-quoted at assignment, so bash's single expansion
    # pass inserts them verbatim with no set -u risk.
    if ! write_file_atomic "$uu_dropin" "// vpssec: automatic SECURITY upgrades only.
// Dropped after 50unattended-upgrades so the distro conffile and operator
// settings (Mail, Package-Blacklist, ...) in it are preserved; #clear resets
// the inherited origin lists so only the security patterns below are active.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
${origins}
};
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";
Unattended-Upgrade::Automatic-Reboot \"false\";
Unattended-Upgrade::SyslogEnable \"true\";"; then
        print_error "$(i18n 'update.uu_dropin_write_failed' "file=$uu_dropin")"
        return 1
    fi

    # --dry-run exercises the real origin match before success is claimed,
    # which is exactly what broke silently before.
    if command -v unattended-upgrade >/dev/null 2>&1; then
        unattended-upgrade --dry-run -d >/dev/null 2>&1 \
            || print_warn "$(i18n 'update.unattended_dryrun_warn')"
    fi

    # The TIMER is what runs unattended-upgrade on a schedule; the service
    # only flushes at shutdown, so enabling it alone hides a masked timer.
    systemctl enable --now apt-daily-upgrade.timer 2>/dev/null || true
    systemctl enable unattended-upgrades 2>/dev/null || true
    systemctl start unattended-upgrades 2>/dev/null || true

    if _update_unattended_enabled; then
        print_ok "$(i18n 'update.unattended_configured')"
        return 0
    else
        print_error "$(i18n 'update.unattended_enable_failed')"
        return 1
    fi
}
