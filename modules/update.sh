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
# apt's main config file, read after every apt.conf.d part (see apply_security).
UPDATE_APT_MAIN_CONF="/etc/apt/apt.conf"

# An index older than this cannot vouch for "no updates", and lagging this far
# behind pending security updates escalates them to high.
UPDATE_INDEX_STALE_DAYS=30

# --- Update Helper Functions ---

# There is deliberately no local lock / count / index-age / reboot predicate
# here: they were apt-only copies of distro.sh primitives. Ask distro.sh — a
# second copy only grows a second version of the truth.

# Whether automatic updates are installed / effective. Both delegate to
# core/distro.sh, which is what the AUDIT asks, so the fix's success gate and
# the finding it clears cannot disagree. Never keep a second copy.
_update_unattended_installed() {
    auto_update_installed
}

_update_unattended_enabled() {
    [[ "$(auto_update_status)" == "ok" ]]
}

# No security update pending (a negative count means no security channel).
# A failed query is not "none pending".
_update_no_security_pending() {
    local n
    n=$(pkg_security_update_count) || return 1
    (( n <= 0 ))
}

# The refresh command for this host's package manager; a generic line when
# there is none to name.
_update_refresh_suggestion() {
    local cmd
    if cmd=$(pkg_refresh_hint); then
        i18n 'update.check_failed_fix' "cmd=$cmd"
    else
        i18n 'update.check_failed_fix_generic'
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
        check_emit "update.apt_locked" low failed \
            desc="$(i18n 'update.apt_locked_desc' "pm=${VPSSEC_PKG_MGR:-}")" \
            suggestion="$(i18n 'update.apt_locked_suggestion')"
        print_severity "low" "$(i18n 'update.apt_locked')"
    elif (( lock_rc == 2 )); then
        # failed + info, and both halves are deliberate: a passed check
        # renders as a one-line tick nobody expands, and putting a number on
        # a non-observation is how a host earns a free pass.
        local desc fix
        case "${VPSSEC_PKG_MGR:-}" in
            # The tool each branch of pkg_manager_locked could not run.
            apt)
                desc=$(i18n 'update.lock_state_unknown_desc')
                fix=$(i18n 'update.lock_state_unknown_fix' "cmd=$(pkg_install_hint lsof)") ;;
            dnf)
                desc=$(i18n 'update.lock_state_unknown_desc_dnf')
                fix=$(i18n 'update.lock_state_unknown_fix_dnf' "cmd=$(pkg_install_hint "$(distro_packages_for_commands pgrep)")") ;;
            *)
                desc=$(i18n 'update.lock_state_unknown_desc_other')
                fix=$(i18n 'update.lock_state_unknown_fix_other') ;;
        esac
        check_emit "update.lock_state_unknown" low failed desc="$desc" suggestion="$fix"
        print_severity "low" "$(i18n 'update.lock_state_unknown')"
    else
        check_emit "update.apt_available" low passed
        print_ok "$(i18n 'update.apt_available')"
    fi
}

_update_audit_available() {
    # NEVER refresh the index here: an audit must not mutate state, and it
    # would defeat the index-age signal below. Both primitives return non-zero
    # when the QUERY failed, which is not "no updates".
    local update_count security_count
    if ! update_count=$(pkg_update_count) || \
       ! security_count=$(pkg_security_update_count); then
        check_emit "update.check_failed" low failed \
            desc="$(i18n 'update.check_failed_desc')" \
            suggestion="$(_update_refresh_suggestion)"
        print_severity "low" "$(i18n 'update.check_failed')"
        return 0
    fi

    if ((update_count == 0)); then
        # Zero read from an index never refreshed, or refreshed long ago, is not
        # "up to date": that data cannot answer the question.
        local age
        age=$(pkg_index_age_days)
        if [[ -z "$age" ]]; then
            check_emit "update.index_stale" low failed \
                desc="$(i18n 'update.index_never_refreshed_desc')" \
                suggestion="$(_update_refresh_suggestion)"
            print_severity "low" "$(i18n 'update.index_stale')"
        elif (( age > UPDATE_INDEX_STALE_DAYS )); then
            check_emit "update.index_stale" low failed \
                desc="$(i18n 'update.index_stale_desc' "days=$age")" \
                suggestion="$(_update_refresh_suggestion)"
            print_severity "low" "$(i18n 'update.index_stale')"
        else
            check_emit "update.no_updates" low passed \
                desc="$(i18n 'update.index_age_desc' "days=$age")"
            print_ok "$(i18n 'update.no_updates')"
        fi
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

            sec_desc="$(i18n 'update.security_updates_count' "count=$security_count")"

            local stale_days
            stale_days=$(pkg_index_age_days)
            if [[ -n "$stale_days" ]] && (( stale_days > UPDATE_INDEX_STALE_DAYS )); then
                severity="high"
            fi
        fi

        check_emit "update.updates_available" "$severity" failed \
            title="$(i18n 'update.updates_available' "count=$update_count")" \
            desc="$sec_desc" \
            suggestion="$(i18n 'update.updates_available_suggestion')" \
            fix="$fix_id"

        if ((security_count > 0)); then
            print_severity "$severity" "$(i18n 'update.security_updates' "count=$security_count")"
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
        check_emit "update.unattended_unsupported" low passed
        print_ok "$(i18n 'update.unattended_unsupported')"
        return
    fi

    if ! auto_update_installed; then
        check_emit "update.unattended_not_installed" low failed \
            title="$(i18n 'update.unattended_disabled')" \
            desc="$(i18n 'update.unattended_not_installed_desc')" \
            suggestion="$(i18n 'update.fix_install_unattended')" \
            fix="update.install_unattended"
        print_severity "low" "$(i18n 'update.unattended_disabled')"
        return
    fi

    if [[ "$status" == "unknown" ]]; then
        check_emit "update.unattended_state_unknown" low failed \
            desc="$(i18n 'update.unattended_state_unknown_desc')"
        print_severity "low" "$(i18n 'update.unattended_state_unknown')"
        return
    fi

    if [[ "$status" == "ok" ]]; then
        check_emit "update.unattended_enabled" low passed
        print_ok "$(i18n 'update.unattended_enabled')"
    else
        local reason_desc
        case "$status" in
            service_disabled)
                reason_desc="$(i18n 'update.unattended_service_disabled')" ;;
            refresh_disabled)
                reason_desc="$(i18n 'update.unattended_refresh_disabled')" ;;
            periodic_off)
                reason_desc="$(i18n 'update.unattended_periodic_off')" ;;
            no_origins)
                reason_desc="$(i18n 'update.unattended_no_origins')" ;;
            *)
                reason_desc="$(i18n 'update.unattended_not_effective')" ;;
        esac

        check_emit "update.unattended_disabled" low failed \
            desc="$reason_desc" \
            suggestion="$(i18n 'update.fix_install_unattended')" \
            fix="update.enable_unattended"
        print_severity "low" "$(i18n 'update.unattended_disabled')"
    fi
}

_update_audit_reboot() {
    # Three-way, like the lock: a host nothing can answer for (a container
    # with no kernel package) is not "no reboot required".
    local reasons rc=0
    reasons=$(pkg_reboot_required) || rc=$?

    if (( rc == 0 )); then
        local -a shown=()
        local desc="" list total
        # The last five: Ubuntu's list ends with the newest request.
        [[ -n "$reasons" ]] && mapfile -t shown < <(tail -5 <<<"$reasons")
        total=$(count_lines "$reasons")
        if (( total > ${#shown[@]} )); then
            printf -v list '%s, ' "${shown[@]}"
            desc="$(i18n 'update.reboot_required_desc_more' "count=$total" "list=${list%, }")"
        elif (( ${#shown[@]} )); then
            printf -v list '%s, ' "${shown[@]}"
            desc="$(i18n 'update.reboot_required_desc' "list=${list%, }")"
        fi
        check_emit "update.reboot_required" medium failed \
            desc="$desc" \
            suggestion="$(i18n 'update.reboot_required_suggestion')"
        print_severity "medium" "$(i18n 'update.reboot_required')"
    elif (( rc == 1 )); then
        check_emit "update.no_reboot" low passed
        print_ok "$(i18n 'update.no_reboot')"
    else
        # failed + info, for the reasons given at the lock check above.
        check_emit "update.reboot_state_unknown" low failed \
            desc="$(i18n 'update.reboot_state_unknown_desc')"
        print_severity "low" "$(i18n 'update.reboot_state_unknown')"
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
    local installed_uu=0
    if ! _update_unattended_installed; then
        print_info "$(i18n 'update.installing_unattended_for_security')"
        export DEBIAN_FRONTEND=noninteractive
        # Installed as the tool for this one run, not to turn on daily upgrades:
        # left alone, its postinst writes 20auto-upgrades enabling them.
        backup_file "$UPDATE_AUTO_UPGRADES_CONF" >/dev/null || return 1
        _update_uu_no_auto_enable
        apt_refresh_index
        if ! apt_install unattended-upgrades; then
            print_error "$(i18n 'update.unattended_install_failed')"
            print_info "$(i18n 'update.security_aborted_install_uu_first')"
            return 1
        fi
        installed_uu=1
    fi

    # The operator's origins can include the main archive (Debian's default
    # does), so the run gets the security ones only, through a throwaway
    # APT_CONFIG: nothing under /etc changes.
    local cfg out rc=0
    cfg=$(_update_security_only_apt_config) || { print_error "$(i18n 'update.updates_failed')"; return 1; }
    # As apt_install: the run's output goes to the log, not into the guide, and
    # only a failure puts its last lines on stderr.
    out=$(APT_CONFIG="$cfg/apt.conf" unattended-upgrade -d </dev/null 2>&1) || rc=$?
    rm -rf "$cfg"
    log_info "unattended-upgrade -d exited $rc:"$'\n'"$out"
    (( rc == 0 )) || tail -n 5 <<<"$out" >&2

    if (( rc == 0 )); then
        print_ok "$(i18n 'update.updates_applied')"
        # rollback restores config FILES, so installed packages are invisible
        # to it. This message is the operator's only pointer to what changed.
        print_info "$(i18n 'update.security_applied_revert_hint')"
        log_info "update.apply_security: upgraded packages are listed in /var/log/apt/history.log"
        (( installed_uu )) && record_undo update.apply_security "apt purge unattended-upgrades"
        return 0
    fi

    print_error "$(i18n 'update.updates_failed')"
    print_info "$(i18n 'update.check_uu_log')"
    return 1
}

# The apt.conf lines that leave unattended-upgrade the security origins only.
# MUST be Origins-Pattern with codename=/label=: Allowed-Origins matches on
# Suite, and Debian's is "stable-security", so it matches NOTHING.
_update_security_origins_conf() {
    local origins
    if [[ "$(detect_os)" == "ubuntu" ]]; then
        origins='    "origin=${distro_id},archive=${distro_codename}-security";
    "origin=${distro_id}ESMApps,archive=${distro_codename}-apps-security";
    "origin=${distro_id}ESM,archive=${distro_codename}-infra-security";'
    else
        origins='    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";'
    fi
    # The placeholders were single-quoted: unattended-upgrades expands them.
    printf '%s\n' '#clear Unattended-Upgrade::Allowed-Origins;' \
        '#clear Unattended-Upgrade::Origins-Pattern;' \
        'Unattended-Upgrade::Origins-Pattern {' "$origins" '};'
}

# A throwaway APT_CONFIG naming the security origins as apt's main config file,
# which apt reads after every apt.conf.d part, so its #clear wins. Echoes the
# directory; the caller removes it.
_update_security_only_apt_config() {
    local dir
    dir=$(mktemp -d) || return 1
    # The real main file is still read, through #include — only when it exists:
    # including a missing file is a syntax error.
    if {
        [[ -f "$UPDATE_APT_MAIN_CONF" ]] && printf '#include "%s";\n' "$UPDATE_APT_MAIN_CONF"
        _update_security_origins_conf
    } > "$dir/security.conf" && printf 'Dir::Etc::main "%s";\n' "$dir/security.conf" > "$dir/apt.conf"; then
        echo "$dir"
        return 0
    fi
    rm -rf "$dir"
    return 1
}

# Preseed "do not enable automatic updates", so installing unattended-upgrades
# does not by itself write 20auto-upgrades; a file that already exists keeps
# deciding (the package's config script reads it back).
_update_uu_no_auto_enable() {
    echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean false' \
        | debconf-set-selections 2>/dev/null \
        || log_warn "debconf preseed failed: unattended-upgrades may enable itself"
}

_update_fix_install_unattended() {
    print_info "$(i18n 'update.installing_unattended')"

    export DEBIAN_FRONTEND=noninteractive

    # Snapshot before the install: the package's postinst writes this file,
    # and a copy taken afterwards would already be the changed one.
    backup_file "$UPDATE_AUTO_UPGRADES_CONF" >/dev/null || return 1
    local -a missing=()
    mapfile -t missing < <(pkg_missing unattended-upgrades apt-listchanges)

    apt_refresh_index
    if apt_install unattended-upgrades apt-listchanges; then
        _update_fix_enable_unattended || return 1
        (( ${#missing[@]} )) && record_undo update.install_unattended "$(pkg_remove_hint "${missing[@]}")"
        return 0
    else
        print_error "$(i18n 'update.unattended_install_failed')"
        return 1
    fi
}

# 20auto-upgrades content $1 with both intervals on: one already on (an
# operator's "7") is kept, one off or missing becomes "1", other lines stay.
_update_auto_upgrades_content() {
    local line key out=""
    local -A seen=()
    if [[ -n "$1" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)[[:space:]]+\"([^\"]*)\"\; ]]; then
                key=${BASH_REMATCH[1]}
                seen[$key]=1
                _auto_update_apt_interval_on "${BASH_REMATCH[2]}" || line="APT::Periodic::$key \"1\";"
            elif [[ "$line" =~ ^[[:space:]]*APT::Periodic::AutocleanInterval[[:space:]] ]]; then
                seen[AutocleanInterval]=1
            fi
            out+="$line"$'\n'
        done <<<"$1"
    fi
    for key in Update-Package-Lists Unattended-Upgrade; do
        [[ -n "${seen[$key]:-}" ]] || out+="APT::Periodic::$key \"1\";"$'\n'
    done
    [[ -n "${seen[AutocleanInterval]:-}" ]] || out+='APT::Periodic::AutocleanInterval "7";'$'\n'
    printf '%s' "${out%$'\n'}"
}

_update_fix_enable_unattended() {
    print_info "$(i18n 'update.configuring_unattended')"

    # backup_file is UNCONDITIONAL: recording an absent path is the only
    # thing that lets a rollback delete this file, and on a first run — the
    # common case here — it does not exist.
    backup_file "$UPDATE_AUTO_UPGRADES_CONF" >/dev/null || return 1
    local current=""
    if [[ -e "$UPDATE_AUTO_UPGRADES_CONF" ]]; then
        current=$(<"$UPDATE_AUTO_UPGRADES_CONF") || return 1
    fi
    if ! write_file_atomic "$UPDATE_AUTO_UPGRADES_CONF" "$(_update_auto_upgrades_content "$current")"; then
        print_error "$(i18n 'update.auto_upgrades_write_failed' "file=$UPDATE_AUTO_UPGRADES_CONF")"
        return 1
    fi

    # A 52- fragment read AFTER 50, never an overwrite of the distro conffile.
    local uu_dropin="$UPDATE_UU_DROPIN"

    # Unconditional, for the reason given above: this drop-in is vpssec's own
    # file, so it never exists on a first run and the rollback needs it
    # recorded as created.
    backup_file "$uu_dropin" >/dev/null || return 1
    # Origins only: any other key here would override what the operator set
    # in 50 (Automatic-Reboot, Remove-Unused-Dependencies...).
    local dropin_text
    dropin_text="// vpssec: automatic SECURITY upgrades only.
// Read after 50unattended-upgrades and sets nothing but the origin lists, so
// the operator's settings there (Mail, Package-Blacklist, ...) still apply.
$(_update_security_origins_conf)"
    if ! write_file_atomic "$uu_dropin" "$dropin_text"; then
        print_error "$(i18n 'update.uu_dropin_write_failed' "file=$uu_dropin")"
        return 1
    fi

    # --dry-run exercises the real origin match before success is claimed,
    # which is exactly what broke silently before.
    if command -v unattended-upgrade >/dev/null 2>&1; then
        unattended-upgrade --dry-run -d >/dev/null 2>&1 \
            || print_warn "$(i18n 'update.unattended_dryrun_warn')"
    fi

    # The TIMERS run on a schedule: apt-daily refreshes the index, apt-daily-
    # upgrade installs from it. The service only flushes at shutdown. FIX_VERIFY
    # (_update_unattended_enabled, the audit's own predicate) decides the outcome.
    local timer
    local -a turned_on=()
    for timer in apt-daily.timer apt-daily-upgrade.timer; do
        if systemctl is-enabled "$timer" &>/dev/null; then
            systemctl enable --now "$timer" 2>/dev/null || true
        elif systemctl enable --now "$timer" 2>/dev/null; then
            turned_on+=("$timer")
        fi
    done
    systemctl enable unattended-upgrades 2>/dev/null || true
    systemctl start unattended-upgrades 2>/dev/null || true

    # Switched-on timers are state a rollback cannot reach.
    (( ${#turned_on[@]} )) && record_undo update.enable_unattended "systemctl disable --now ${turned_on[*]}"
    print_ok "$(i18n 'update.unattended_configured')"
    return 0
}
