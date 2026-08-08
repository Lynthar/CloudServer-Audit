#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# System update module
# Copyright (c) 2024

# ==============================================================================
# Update Configuration
# ==============================================================================

# The two files the unattended-upgrades fix writes. Module variables rather than
# literals so the fix is reachable from a test — the audit reads the MERGED
# `apt-config dump` rather than either file (that is deliberate: a drop-in can
# override them), so these are the fix's alone.
UPDATE_AUTO_UPGRADES_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
UPDATE_UU_DROPIN="/etc/apt/apt.conf.d/52vpssec-unattended-security"

# ==============================================================================
# Update Helper Functions
# ==============================================================================

# No _update_apt_locked here: it was a byte-identical copy of
# pkg_manager_locked's apt branch with ZERO callers — the audit has always
# asked core/distro.sh. It was the eighth instance of the duplicate-predicate
# family and survived the same file's `auto_update_*` de-duplication, so it
# is deleted rather than delegated. Ask distro.sh.

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

# Whether automatic updates are installed / effective. Both delegate to
# core/distro.sh, which is what the AUDIT asks — so the fix's success gate and
# the finding it is supposed to clear can no longer disagree. The module used to
# carry its own copy of both (a `dpkg -l` check and the whole three-step
# apt-config walk), reachable only from the fix; they agreed with distro.sh at
# the time, so nothing was broken, but keeping two implementations of the
# predicate that decides "did this fix work" is how a fix comes to report
# success on a host the audit still flags.
#
# Distro coverage is distro.sh's problem, not a second copy's: on a dnf host
# these answer about dnf-automatic while the fix bodies below still run apt
# commands. That gap is C5-#6 (fix_id not gated by distro) and is tracked
# there — it is not made better or worse by this delegation.
_update_unattended_installed() {
    auto_update_installed
}

_update_unattended_enabled() {
    [[ "$(auto_update_status)" == "ok" ]]
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
    # NTP / time-sync is audited authoritatively by the timezone module
    # (_timezone_check_ntp). It used to be duplicated here; removed so a
    # single module owns the NTP score signal.
}

_update_audit_apt_lock() {
    # Three-way on purpose. `if pkg_manager_locked` collapsed "could not
    # determine" into the passing branch, so a host missing the probe tool
    # was handed a green — and SCORED — "package manager available" for a
    # question nobody asked. See _pkg_lock_held in core/distro.sh.
    # `pkg_manager_locked || lock_rc=$?` rather than a bare call followed by
    # `$?`. The bare form works today only because engine.sh invokes audits as
    # `if "$audit_func"; then`, and bash's condition-context exemption reaches
    # into the body — so `set -e` ignores the 1 that "not locked" returns.
    # Measured: outside that context the bare form aborts the caller
    # immediately, i.e. on the NORMAL path. The `||` form is exempt anywhere.
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
        # status=failed, category=info. Both halves are deliberate:
        #
        # `failed` because report.sh renders a passed check as the one-liner
        # "- ✓ <title>", and a green tick beside "could not determine" is the
        # same contradiction this batch exists to remove — the operator would
        # never see the desc explaining what was skipped or the suggestion
        # that restores it. A failed low renders the full block.
        #
        # `info` in CHECK_SCORE_CATEGORY so this check enters neither the
        # base nor the penalty — calculate_score reads scored_total and
        # *_failed, both gated on the category. Putting a number on a
        # non-observation is how the scored `update.apt_available` came to
        # pass for free in the first place.
        #
        # Be precise about what that does and does not mean. The check itself
        # is worth nothing either way, but a host that lands here scores
        # LOWER than it used to, because the pass it was being handed for
        # free is gone: measured on an unmeasurable host with
        # `--include=update`, scored_total 4→3 and passed 3→2, i.e. 75→66.
        # That drop IS the fix. A host where /proc/locks is readable — every
        # normal Linux box — never reaches this branch and does not move: the
        # full-audit container measured 31 / scored_total 43 before and after.
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
        # `vpssec rollback` restores config FILES. Installed packages are not
        # files it tracks, so this is the only pointer the operator gets to
        # what changed — and unlike a drop-in, it cannot be undone by the tool
        # at all. Same reasoning as baseline's disable_unused revert hint.
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

    # Create the auto-upgrades config.
    #
    # backup_file is called UNCONDITIONALLY. Its second job is recording an
    # absent path in .vpssec_created, which is the only thing that lets a
    # rollback delete a file the fix created — and on a first run, which is the
    # common case for this fix, the file does not exist. Under the old
    # `[[ -f ]] && backup_file` guard nothing was recorded, so an operator who
    # rolled the whole plan back still had a host installing packages
    # unattended. Same defect as logging's journald drop-in and webapp's three
    # conf.d writers; this is where it mattered most.
    backup_file "$UPDATE_AUTO_UPGRADES_CONF" >/dev/null 2>&1 || true
    if ! write_file_atomic "$UPDATE_AUTO_UPGRADES_CONF" 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";'; then
        print_error "$(i18n 'update.auto_upgrades_write_failed' "file=$UPDATE_AUTO_UPGRADES_CONF")"
        return 1
    fi

    # Security-only origins.
    #
    # We deliberately DO NOT overwrite the distro's 50unattended-upgrades
    # conffile (it carries operator settings: Mail, Package-Blacklist,
    # Automatic-Reboot, ...). Instead we drop a 52-prefixed fragment, read
    # AFTER 50, that #clears the inherited origin lists and sets a
    # security-only Origins-Pattern.
    #
    # The previous code overwrote 50unattended-upgrades with an
    # Allowed-Origins "Debian:<codename>-security" entry. On Debian that
    # matched NOTHING — the security archive's Suite is "stable-security",
    # not "<codename>-security", and Allowed-Origins matches on the Suite —
    # so security auto-updates silently stopped while the audit still
    # reported them enabled. Origins-Pattern with an explicit
    # codename=<codename>-security,label=Debian-Security entry is the form
    # Debian's own default ships and the only one that matches; Ubuntu's
    # security Suite IS <codename>-security, so archive= matches there.
    # ${distro_id}/${distro_codename} are written literally (single-quoted
    # below); unattended-upgrades expands them, not the shell.
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
    backup_file "$uu_dropin" >/dev/null 2>&1 || true
    # Double-quoted so ${origins} interpolates; the literal ${distro_id} /
    # ${distro_codename} inside $origins were single-quoted at assignment
    # and are inserted verbatim (bash does a single expansion pass), so
    # there is no set -u risk from those unbound names.
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

    # Verify the merged config actually parses and selects packages before
    # claiming success: --dry-run exercises the real origin match, which is
    # exactly what silently broke before. A non-zero result is surfaced, not
    # swallowed (the fix's success gate below is the authority).
    if command -v unattended-upgrade >/dev/null 2>&1; then
        unattended-upgrade --dry-run -d >/dev/null 2>&1 \
            || print_warn "$(i18n 'update.unattended_dryrun_warn')"
    fi

    # Enable the periodic driver (apt-daily-upgrade.timer) AND the shutdown
    # flusher service. The timer is what actually runs unattended-upgrade on
    # a schedule; enabling only the service (as before) left a masked timer
    # undetected.
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
