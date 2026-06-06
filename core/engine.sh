#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core engine - module loading, scheduling, and execution
# Copyright (c) 2024

# ==============================================================================
# Security Levels
# ==============================================================================

# Source security level configuration
VPSSEC_SECURITY_LEVELS_FILE="${VPSSEC_CORE}/security_levels.sh"
if [[ -f "$VPSSEC_SECURITY_LEVELS_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$VPSSEC_SECURITY_LEVELS_FILE"
fi

# ==============================================================================
# Module Management
# ==============================================================================

# Available modules (order matters for execution)
# Organized from basic to advanced:
#   1. System Basics: preflight, cloud, timezone
#   2. Access Control: users, ssh
#   3. Network Security: ufw, fail2ban
#   4. System Hardening: update, kernel, filesystem, baseline
#   5. Service Security: docker, nginx, cloudflared, webapp
#   6. Security Scanning: malware
#   7. Operations & Compliance: logging, backup, alerts
declare -ga VPSSEC_MODULE_ORDER=(
    # System Basics
    "preflight"
    "cloud"
    "timezone"
    # Access Control
    "users"
    "ssh"
    # Network Security
    "ufw"
    "fail2ban"
    "networking"
    # System Hardening
    "update"
    "kernel"
    "filesystem"
    "baseline"
    # Service Security
    "docker"
    "nginx"
    "cloudflared"
    "webapp"
    # Security Scanning
    "malware"
    # Operations & Compliance
    "logging"
    "backup"
    "alerts"
    "scheduling"
)

# Module category definitions for grouped reporting
declare -gA VPSSEC_MODULE_CATEGORY=(
    ["preflight"]="basics"
    ["cloud"]="basics"
    ["timezone"]="basics"
    ["users"]="access"
    ["ssh"]="access"
    ["ufw"]="network"
    ["fail2ban"]="network"
    ["networking"]="network"
    ["update"]="hardening"
    ["kernel"]="hardening"
    ["filesystem"]="hardening"
    ["baseline"]="hardening"
    ["docker"]="services"
    ["nginx"]="services"
    ["cloudflared"]="services"
    ["webapp"]="services"
    ["malware"]="security"
    ["logging"]="operations"
    ["backup"]="operations"
    ["alerts"]="operations"
    ["scheduling"]="operations"
)

# Category order for reporting (basic to advanced)
declare -ga VPSSEC_CATEGORY_ORDER=(
    "basics"
    "access"
    "network"
    "hardening"
    "services"
    "security"
    "operations"
)

# Module metadata. -g keeps these visible across function boundaries
# (matters for bats tests that source engine.sh from a setup helper).
declare -gA VPSSEC_MODULE_ENABLED=()
declare -gA VPSSEC_MODULE_LOADED=()
declare -gA VPSSEC_MODULE_UNAVAILABLE=()  # Modules unavailable due to missing deps

# Load a module
module_load() {
    local module="$1"
    local module_file="${VPSSEC_MODULES}/${module}.sh"

    if [[ ! -f "$module_file" ]]; then
        log_warn "Module file not found: $module_file"
        return 1
    fi

    # Validate module file is readable
    if [[ ! -r "$module_file" ]]; then
        log_error "Module file not readable: $module_file"
        return 1
    fi

    # Source module with error handling
    # shellcheck source=/dev/null
    if ! source "$module_file" 2>/dev/null; then
        log_error "Failed to source module: $module_file"
        return 1
    fi

    # Verify the module's audit function exists
    local audit_func="${module}_audit"
    if ! declare -f "$audit_func" > /dev/null 2>&1; then
        log_warn "Module $module loaded but missing ${audit_func}() function"
        # Still mark as loaded, but log warning
    fi

    VPSSEC_MODULE_LOADED[$module]=1
    log_debug "Module loaded: $module"
    return 0
}

# Check if module is available (has required deps)
module_available() {
    local module="$1"

    # Check module-specific dependencies
    case "$module" in
        ufw)
            # UFW module should always run - it detects all firewall types
            # (ufw, firewalld, nftables, iptables) not just UFW
            return 0
            ;;
        docker)
            check_command docker || return 1
            ;;
        nginx)
            check_command nginx || return 1
            ;;
        cloudflared)
            check_command cloudflared || return 1
            ;;
        logging)
            # Always available - uses standard tools
            return 0
            ;;
        backup)
            # Always available - generates templates
            return 0
            ;;
        alerts)
            # Always available - generates config
            return 0
            ;;
        webapp)
            # Always available - will report "no webserver" if none installed
            return 0
            ;;
        malware)
            # Always available - uses built-in Linux tools
            return 0
            ;;
    esac

    return 0
}

# Load all available modules
module_load_all() {
    local include="${1:-}"
    local exclude="${2:-}"

    # Validate filter tokens against known module names.
    # Rationale: previously a typo like `--include=ssg` silently
    # produced an empty audit (no module name matched), which the
    # caller could mistake for "everything passed". Fail loud on
    # unknown include tokens; warn-only on unknown exclude tokens
    # because a wrong exclude is at worst conservative (you ran an
    # extra module you didn't want to skip).
    _module_validate_filter "$include" "include" "fatal"
    _module_validate_filter "$exclude" "exclude" "warn"

    for module in "${VPSSEC_MODULE_ORDER[@]}"; do
        # Check include filter
        if [[ -n "$include" ]]; then
            if [[ ! ",$include," == *",$module,"* ]]; then
                log_debug "Module skipped (not in include list): $module"
                continue
            fi
        fi

        # Check exclude filter
        if [[ -n "$exclude" ]]; then
            if [[ ",$exclude," == *",$module,"* ]]; then
                log_debug "Module skipped (in exclude list): $module"
                continue
            fi
        fi

        # Check availability
        if ! module_available "$module"; then
            log_info "Module unavailable (missing deps): $module"
            VPSSEC_MODULE_ENABLED[$module]=0
            VPSSEC_MODULE_UNAVAILABLE[$module]=1
            continue
        fi

        # Load module
        if module_load "$module"; then
            VPSSEC_MODULE_ENABLED[$module]=1
        else
            VPSSEC_MODULE_ENABLED[$module]=0
        fi
    done
}

# Validate a comma-separated list of module names.
#
# Args: <list> <flag-name> <severity>
#   list      — comma-separated, possibly empty
#   flag-name — "include" or "exclude" (only used in messages)
#   severity  — "fatal" exits with code 2 on any unknown token;
#               "warn" prints a warning and lets the run continue
_module_validate_filter() {
    local list="$1"
    local flag="$2"
    local severity="$3"

    [[ -z "$list" ]] && return 0

    local invalid=()
    local IFS=','
    local token
    for token in $list; do
        # Trim incidental whitespace so `--include="ssh, ufw"` is
        # forgiving. We deliberately do not silently *correct* the
        # value; we just normalise before lookup.
        token="${token#"${token%%[![:space:]]*}"}"
        token="${token%"${token##*[![:space:]]}"}"
        [[ -z "$token" ]] && continue

        local known=0
        local known_mod
        for known_mod in "${VPSSEC_MODULE_ORDER[@]}"; do
            if [[ "$token" == "$known_mod" ]]; then
                known=1
                break
            fi
        done
        (( known == 0 )) && invalid+=("$token")
    done

    (( ${#invalid[@]} == 0 )) && return 0

    if [[ "$severity" == "fatal" ]]; then
        print_error "Unknown module(s) in --${flag}: ${invalid[*]}"
        print_msg "Available modules: ${VPSSEC_MODULE_ORDER[*]}"
        exit 2
    else
        print_warn "Unknown module(s) in --${flag} (ignored): ${invalid[*]}"
    fi
}

# Get list of enabled modules
module_get_enabled() {
    for module in "${VPSSEC_MODULE_ORDER[@]}"; do
        if [[ "${VPSSEC_MODULE_ENABLED[$module]:-0}" == "1" ]]; then
            echo "$module"
        fi
    done
}

# ==============================================================================
# Audit Mode Execution
# ==============================================================================

# Run audit for a single module
audit_module() {
    local module="$1"

    if [[ "${VPSSEC_MODULE_LOADED[$module]:-0}" != "1" ]]; then
        log_warn "Module not loaded, cannot audit: $module"
        return 1
    fi

    # Call module's audit function
    local audit_func="${module}_audit"
    if declare -f "$audit_func" > /dev/null; then
        log_info "Running audit: $module"
        print_subheader "$(i18n "${module}.title")"

        # Execute audit, capturing the module's REAL exit code. `if ! fn; then
        # r=$?` would capture the status of `!` (always 0), so the warning
        # always logged "returned non-zero: 0". `if fn; then : ; else r=$?`
        # records the actual non-zero in the else branch, and the `if` still
        # suppresses set -e so one module's failure can't abort the whole audit.
        local audit_result=0
        if "$audit_func"; then
            :
        else
            audit_result=$?
            log_warn "Audit function $audit_func returned non-zero: $audit_result"
            # Don't fail the whole audit for individual module failures.
        fi

        return 0  # Module audit completed (even if with warnings)
    else
        log_warn "Audit function not found: $audit_func"
        print_error "$(i18n 'error.audit_func_not_found' "func=$audit_func" 2>/dev/null || echo "Audit function not found: $audit_func")"
        return 1
    fi
}

# Record unavailable modules in state
_record_unavailable_modules() {
    for module in "${!VPSSEC_MODULE_UNAVAILABLE[@]}"; do
        if [[ "${VPSSEC_MODULE_UNAVAILABLE[$module]}" == "1" ]]; then
            local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
            local check=$(create_check_json \
                "${module}.not_installed" \
                "${module}" \
                "low" \
                "passed" \
                "$(i18n "${module}.not_installed" 2>/dev/null || echo "${mod_title} not installed")" \
                "$(i18n 'common.skipping' 2>/dev/null || echo "Skipping") - $(i18n 'common.not_installed' 2>/dev/null || echo "Not installed")" \
                "" \
                "")
            state_add_check "$check"
        fi
    done
}

# Run one full audit pass: state_init → enumerate modules → invoke
# every <module>_audit → record unavailable modules. Used by both
# `audit_all` (read-only mode) and `guide_mode` (which needs the same
# audit results before computing fixes). Pulled out of the two
# callers so a behavioural change to the audit pass only has to land
# in one place.
#
# Side effects (intentional, preserved from the previous inline
# implementations):
#   * state/checks.json is reset and refilled (state_init handles
#     the .prev backup).
#   * VPSSEC_QUIET_SCAN is exported as 1 during the loop and reset
#     to 0 on return — both callers expect QUIET_SCAN=0 immediately
#     afterwards (audit_all calls report_generate_all, guide_mode
#     calls report_print_details / report_print_summary).
#   * The per-module progress line is rewritten in place via \r;
#     we clear it before returning so the next print starts on a
#     fresh column.
#
# Loop variables (`module`, `mod_title`, etc.) are declared local
# here even though the previous inline blocks let `module` leak as
# a global — leaking was harmless (no caller referenced it after
# return) but making it local means a future caller can't be
# surprised by a stale value.
_run_audit_pass() {
    state_init

    local -a modules=()
    local m
    while IFS= read -r m; do
        modules+=("$m")
    done < <(module_get_enabled)

    local unavailable_count=0
    local module
    for module in "${!VPSSEC_MODULE_UNAVAILABLE[@]}"; do
        [[ "${VPSSEC_MODULE_UNAVAILABLE[$module]}" == "1" ]] && ((unavailable_count++)) || true
    done

    local total=$((${#modules[@]} + unavailable_count))
    local current=0

    export VPSSEC_QUIET_SCAN=1

    print_msg ""
    print_msg "$(i18n 'scan.scanning' 2>/dev/null || echo 'Scanning...')"
    print_msg ""

    # Pre-warm the cloud-detection cache in *this* shell before any
    # module spawns a `$(...)` subshell. The getters in core/common.sh
    # write VPSSEC_CLOUD_PROVIDER / VPSSEC_CLOUD_TIER as `declare -g`
    # globals, but a subshell's assignment dies with the subshell — so
    # without this pre-warm every $(vpssec_cloud_provider) call across
    # the audit would re-run DMI detection. Calling the getters here
    # (no command substitution) sets the globals in the parent shell;
    # every subsequent subshell inherits the cached values.
    vpssec_cloud_provider >/dev/null
    vpssec_cloud_tier >/dev/null

    local mod_title
    for module in "${modules[@]}"; do
        ((current++)) || true
        mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
        printf "\r  [%d/%d] %s...                    " "$current" "$total" "$mod_title"

        audit_module "$module"
    done

    for module in "${VPSSEC_MODULE_ORDER[@]}"; do
        if [[ "${VPSSEC_MODULE_UNAVAILABLE[$module]:-0}" == "1" ]]; then
            ((current++)) || true
            mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
            printf "\r  [%d/%d] %s ($(i18n 'common.not_installed' 2>/dev/null || echo 'not installed'))...        " "$current" "$total" "$mod_title"
        fi
    done
    _record_unavailable_modules

    # Clear progress line
    printf "\r                                                              \r"

    export VPSSEC_QUIET_SCAN=0
}

# Run audit for all enabled modules
audit_all() {
    _run_audit_pass

    # Generate reports and print summary
    report_generate_all
}

# ==============================================================================
# Guide Mode Execution
# ==============================================================================

# Get available fixes from audit results
get_available_fixes() {
    local show_all="${1:-false}"
    local checks=$(state_get_checks)

    # Get fixes that have a fix_id (failed items + passed items with fix_id for optional config like timezone)
    local fixes=$(echo "$checks" | jq -r '[.[] | select(.fix_id != null and .fix_id != "" and (.status == "failed" or (.status == "passed" and (.fix_id | startswith("timezone.")))))]')

    # Add safety classification if security_levels is loaded
    if declare -f get_fix_safety &>/dev/null; then
        local enriched_fixes="[]"
        while read -r fix; do
            local fix_id=$(echo "$fix" | jq -r '.fix_id')
            local safety=$(get_fix_safety "$fix_id" 2>/dev/null || echo "unknown")
            local warning=$(get_fix_warning "$fix_id" 2>/dev/null || echo "")
            local can_fix_result=$(can_fix "$fix_id" 2>/dev/null && echo "true" || echo "false")

            # Add safety info to fix
            local enriched=$(echo "$fix" | jq --arg safety "$safety" --arg warning "$warning" --arg can_fix "$can_fix_result" \
                '. + {safety: $safety, safety_warning: $warning, can_auto_fix: ($can_fix == "true")}')

            enriched_fixes=$(echo "$enriched_fixes" | jq --argjson fix "$enriched" '. + [$fix]')
        done < <(echo "$fixes" | jq -c '.[]')

        # Filter out alert_only items from selection (unless show_all is true)
        if [[ "$show_all" != "true" ]]; then
            # Hide alert_only items - they can't be auto-fixed
            echo "$enriched_fixes" | jq '[.[] | select(.safety != "alert_only")]'
        else
            echo "$enriched_fixes"
        fi
    else
        echo "$fixes"
    fi
}

# Generate execution plan
generate_plan() {
    local selected_fixes="$1"  # Space-separated list of fix IDs
    local plan_fixes=()

    local checks=$(state_get_checks)

    for fix_id in $selected_fixes; do
        local check=$(echo "$checks" | jq -r --arg id "$fix_id" '.[] | select(.fix_id == $id)')
        if [[ -n "$check" && "$check" != "null" ]]; then
            plan_fixes+=("$check")
        fi
    done

    # Create plan JSON
    local plan_json=$(printf '%s\n' "${plan_fixes[@]}" | jq -s '{
        "timestamp": "'"$(date -Iseconds)"'",
        "fixes": .
    }')

    state_save_plan "$plan_json"
    echo "$plan_json"
}

# Execute a single fix
execute_fix() {
    local fix_id="$1"
    local skip_safety_check="${2:-false}"
    local module="${fix_id%%.*}"

    # Check fix safety (unless explicitly skipped)
    if [[ "$skip_safety_check" != "true" ]]; then
        local safety=$(get_fix_safety "$fix_id" 2>/dev/null || echo "unknown")

        # Alert-only fixes are never auto-applied — filtered from the selection
        # UI in get_available_fixes, rejected here as defense-in-depth.
        if [[ "$safety" == "alert_only" ]]; then
            local warning=$(get_fix_warning "$fix_id" 2>/dev/null || echo "No auto-fix available")
            print_warn "$(i18n 'fix.alert_only' 2>/dev/null || echo "Alert only"): $warning"
            return 1
        fi

        # Enforce confirmation for confirm/risky fixes centrally so none can be
        # applied without acknowledgement. Fixes in FIX_SELF_CONFIRMED prompt
        # themselves at a more precise point and are skipped here to avoid a
        # double prompt (see fix_needs_engine_confirmation). Risky fixes use
        # confirm_critical (ignores --yes, requires a typed "yes" + tty);
        # confirm-class fixes use confirm (honors --yes for non-critical runs).
        if fix_needs_engine_confirmation "$fix_id"; then
            local warning
            warning=$(get_fix_warning "$fix_id" 2>/dev/null || echo "")
            if fix_is_risky "$fix_id"; then
                if ! confirm_critical "$(i18n 'fix.risky'): $warning"; then
                    print_warn "$(i18n 'fix.risky_skipped')"
                    return 1
                fi
            else
                if ! confirm "$(i18n 'fix.confirm'): $warning"; then
                    print_warn "$(i18n 'fix.confirm_skipped')"
                    return 1
                fi
            fi
        fi
    fi

    # Call module's fix function
    local fix_func="${module}_fix"
    if declare -f "$fix_func" > /dev/null; then
        log_info "Executing fix: $fix_id"
        if "$fix_func" "$fix_id"; then
            state_mark_fix_complete "$fix_id"
            return 0
        else
            log_error "Fix failed: $fix_id"
            return 1
        fi
    else
        log_error "Fix function not found: $fix_func"
        return 1
    fi
}

# Execute plan
execute_plan() {
    local plan=$(state_load_plan)
    local fixes=$(echo "$plan" | jq -r '.fixes')
    local total=$(echo "$fixes" | jq 'length')
    local completed=()
    local failed=()

    # Open a backup session: every backup_file call by the fixes below lands in
    # this one directory (VPSSEC_BACKUP_SESSION), so a rollback restores the
    # whole plan, not just the files backed up in the last wall-clock second.
    VPSSEC_BACKUP_SESSION=$(backup_create_session)
    local backup_dir="$VPSSEC_BACKUP_SESSION"
    log_info "Backup session created: $backup_dir"

    local i=0
    while read -r fix; do
        local fix_id=$(echo "$fix" | jq -r '.fix_id')
        local title=$(echo "$fix" | jq -r '.title')

        ((i++)) || true

        # Save progress
        local completed_json=$(printf '%s\n' "${completed[@]}" | jq -Rs 'split("\n") | map(select(. != ""))')
        state_save_progress "$fix_id" "$total" "$completed_json"

        print_msg ""
        print_info "[$i/$total] $title"

        if execute_fix "$fix_id"; then
            print_ok "$(i18n 'common.success')"
            completed+=("$fix_id")
        else
            print_error "$(i18n 'common.failed')"
            failed+=("$fix_id")

            # Ask user what to do
            if [[ "${VPSSEC_YES}" != "1" ]]; then
                local choice
                echo ""
                echo "  1) $(i18n 'common.skip')"
                echo "  2) $(i18n 'common.retry')"
                echo "  3) $(i18n 'common.rollback')"
                echo -n "  > "
                read -r choice </dev/tty 2>/dev/null || choice="1"

                case "$choice" in
                    2)
                        # Retry
                        if execute_fix "$fix_id"; then
                            print_ok "$(i18n 'common.success')"
                            completed+=("$fix_id")
                            # Remove from failed. Bash `${arr[@]/pat}`
                            # replaces pat with empty — it does NOT
                            # delete the element, so the previous
                            # version left a zero-length slot and made
                            # ${#failed[@]} overcount. Rebuild the
                            # array instead.
                            local _kept=()
                            local _f
                            for _f in "${failed[@]}"; do
                                [[ "$_f" != "$fix_id" ]] && _kept+=("$_f")
                            done
                            failed=("${_kept[@]}")
                        fi
                        ;;
                    3)
                        # Rollback and exit. Restore THIS plan's session (which
                        # holds every fix's backup), not merely the latest dir.
                        print_warn "$(i18n 'backup.restoring')"
                        backup_restore "$(basename "$VPSSEC_BACKUP_SESSION")"
                        VPSSEC_BACKUP_SESSION=""
                        state_clear_progress
                        return 1
                        ;;
                    *)
                        # Skip, continue
                        ;;
                esac
            fi
        fi
    done < <(echo "$fixes" | jq -c '.[]')

    # Clear progress
    state_clear_progress

    # Prune old backup sessions. Each guide run creates a new
    # timestamped directory under backups/, so without cleanup the
    # directory grows unbounded. 30 sessions is a generous retention
    # window for an interactive tool — easily covers months of
    # occasional hardening work — and rollback works against any of
    # them as long as the timestamp dir survives.
    backup_cleanup 30 || true

    # Print summary
    print_msg ""
    if [[ ${#failed[@]} -eq 0 ]]; then
        print_ok "$(i18n 'guide.complete')"
    elif [[ ${#completed[@]} -eq 0 ]]; then
        print_error "$(i18n 'guide.all_failed')"
    else
        print_warn "$(i18n 'guide.partial_complete' "count=${#failed[@]}")"
    fi

    print_msg ""
    print_info "$(i18n 'guide.rollback_available')"

    # Close the session so any later standalone backup_file call timestamps
    # its own directory again.
    VPSSEC_BACKUP_SESSION=""
    return 0
}

# Resume the previously-interrupted plan.
#
# Strategy: load state/last_plan.json (the full plan the user
# approved), filter out fix_ids already in state/progress.json's
# `.completed` array, and feed the remainder to execute_plan.
#
# What this DOES re-run: the fix that was in flight when the
# interrupt happened (progress.current_fix). vpssec's fix functions
# are idempotent (backup + atomic write + validate), so re-applying
# a half-applied change converges to the intended end state. What
# this does NOT do: cope with system changes made *between*
# interruption and resume by other actors. The user is asked to
# opt into resume explicitly; if they suspect the system has moved
# on, they should pick "discard" instead.
_guide_resume() {
    local plan plan_count
    plan=$(state_load_plan)
    plan_count=$(echo "$plan" | jq '.fixes | length')

    if (( plan_count == 0 )); then
        print_error "$(i18n 'guide.resume_empty_plan')"
        state_clear_progress
        return 1
    fi

    local progress completed remaining_fixes remaining_count
    progress=$(state_load_progress)
    completed=$(echo "$progress" | jq -c '.completed // []')

    # Single jq pass: drop every fix whose fix_id is already in the
    # completed array. progress.current_fix is intentionally NOT in
    # completed (it's only moved there after execute_fix returns
    # success) so a mid-fix interrupt re-runs that fix on resume.
    #
    # NB: the jq variable is `$completed_ids`, not `$done`. The bash
    # keyword `done` inside a single-quoted jq filter triggers
    # ShellCheck SC1010 even though it's syntactically opaque to bash.
    # Renaming the jq variable is the cheapest way to keep the linter
    # quiet without rewriting the filter.
    remaining_fixes=$(echo "$plan" | jq --argjson completed_ids "$completed" \
        '.fixes | map(select(.fix_id as $id | ($completed_ids | index($id)) | not))')
    remaining_count=$(echo "$remaining_fixes" | jq 'length')

    if (( remaining_count == 0 )); then
        print_ok "$(i18n 'guide.resume_already_done')"
        state_clear_progress
        return 0
    fi

    print_header "$(i18n 'guide.resume_executing' "count=$remaining_count" "total=$plan_count")"
    print_msg ""

    # Replace the on-disk plan with only the remaining fixes;
    # execute_plan re-creates progress.json against this trimmed
    # plan so a *second* interrupt-then-resume composes correctly.
    # A fresh backup session is created inside execute_plan; the
    # backup directory from the original (interrupted) run remains
    # rollback-able by its timestamp.
    local resume_plan
    resume_plan=$(echo "$plan" | jq --argjson fixes "$remaining_fixes" \
        '.fixes = $fixes')
    state_save_plan "$resume_plan"

    execute_plan

    # Deliberately don't re-audit + re-render the report here:
    # auditing 19 modules takes ~10s and the user can trigger it
    # with `vpssec audit` if they want a current view. Match the
    # existing post-execute_plan flow which also doesn't re-audit.
    print_msg ""
    print_info "$(i18n 'guide.resume_complete_hint')"
}

# Guide mode main flow
guide_mode() {
    # Guide/fix paths are apt/dpkg-based and only validated on Debian/
    # Ubuntu. The audit path is distro-aware (RHEL/Arch), but automated
    # remediation is not ported — refuse here instead of running apt
    # against a system that lacks it. Audit still works on those hosts.
    if ! is_debian_based; then
        print_warn "$(i18n 'guide.fix_debian_only')"
        return 0
    fi

    # Resume gate. If state/progress.json exists, the previous plan
    # was killed mid-execution. Ask before re-auditing — saves the
    # user from waiting through a fresh ~10s scan they might not
    # want, and lets them decide to either continue applying fixes
    # they already approved, or wipe progress and start over.
    if state_has_progress; then
        local _progress _current _total _completed_count _ts
        _progress=$(state_load_progress)
        _current=$(echo "$_progress" | jq -r '.current_fix')
        _total=$(echo "$_progress" | jq -r '.total_fixes')
        _completed_count=$(echo "$_progress" | jq -r '.completed | length')
        _ts=$(echo "$_progress" | jq -r '.timestamp')

        print_warn "$(i18n 'guide.interrupted_detected' \
            "step=$((_completed_count + 1))" \
            "total=$_total" \
            "current=$_current" \
            "ts=$_ts")"
        print_msg ""
        print_msg "  1) $(i18n 'guide.resume_option')"
        print_msg "  2) $(i18n 'guide.discard_option')"
        print_msg "  3) $(i18n 'guide.cancel_option')"
        echo -n "  > "

        local _choice
        if ! read -r _choice </dev/tty 2>/dev/null; then
            _choice=3
        fi

        case "$_choice" in
            1)
                _guide_resume
                return 0
                ;;
            2)
                state_clear_progress
                # Fall through to the fresh-audit flow below.
                ;;
            *)
                print_msg "$(i18n 'common.cancel')"
                return 0
                ;;
        esac
    fi

    # First run audit
    print_header "$(i18n 'guide.welcome')"
    print_msg ""

    # Show security level info
    if declare -f get_security_level &>/dev/null; then
        local level=$(get_security_level)
        print_msg "$(i18n 'guide.security_level' 2>/dev/null || echo "Security Level"): $level"
        print_security_level_info "$level" 2>/dev/null | while read -r line; do
            print_msg "  $line"
        done
        print_msg ""
    fi

    # Run audit pass (shared with audit_all). state/checks.json is
    # repopulated in-place; QUIET_SCAN is reset to 0 on return so the
    # report-print calls below render correctly.
    _run_audit_pass

    # Get available fixes
    local fixes=$(get_available_fixes)
    local fix_count=$(echo "$fixes" | jq 'length')

    if ((fix_count == 0)); then
        # Show full report same as audit mode
        report_generate_all
        print_ok "$(i18n 'common.safe') - $(i18n 'guide.complete')"
        return 0
    fi

    # Show full report (same as audit mode)
    report_print_details
    report_print_summary

    # Module/fix selection
    print_subheader "$(i18n 'guide.select_fixes')"

    local selected_fixes=""
    if tui_available; then
        # TUI mode
        declare -a fix_array
        while read -r fix; do
            fix_array+=("$fix")
        done < <(echo "$fixes" | jq -c '.[]')

        selected_fixes=$(ui_select_fixes fix_array)
    else
        # Text mode - show numbered list
        local i=1
        echo ""
        while read -r fix; do
            local fix_id=$(echo "$fix" | jq -r '.fix_id')
            local title=$(echo "$fix" | jq -r '.title')
            local severity=$(echo "$fix" | jq -r '.severity')
            local safety=$(echo "$fix" | jq -r '.safety // "unknown"')
            local can_fix=$(echo "$fix" | jq -r '.can_auto_fix // false')

            local prefix=""
            case "$severity" in
                high)   prefix="${RED}[!]${NC}" ;;
                medium) prefix="${YELLOW}[*]${NC}" ;;
                low)    prefix="${BLUE}[-]${NC}" ;;
            esac

            # Add safety indicator
            local safety_indicator=""
            case "$safety" in
                safe)       safety_indicator="${GREEN}[safe]${NC}" ;;
                confirm)    safety_indicator="${YELLOW}[confirm]${NC}" ;;
                risky)      safety_indicator="${RED}[risky]${NC}" ;;
                alert_only) safety_indicator="${CYAN}[alert]${NC}" ;;
                *)          safety_indicator="" ;;
            esac

            # Show whether it can be auto-fixed at current level
            if [[ "$can_fix" == "true" ]]; then
                echo -e "  $i) $prefix $title $safety_indicator"
            else
                echo -e "  $i) $prefix $title $safety_indicator ${DIM}(manual)${NC}"
            fi
            ((i++))
        done < <(echo "$fixes" | jq -c '.[]')

        echo ""
        echo "$(i18n 'guide.enter_numbers')"
        echo -n "> "
        read -r selection </dev/tty 2>/dev/null || selection=""

        if [[ "$selection" == "all" ]]; then
            selected_fixes=$(echo "$fixes" | jq -r '.[].fix_id' | tr '\n' ' ')
        else
            for num in $selection; do
                if [[ "$num" =~ ^[0-9]+$ ]]; then
                    local fix_id=$(echo "$fixes" | jq -r ".[$((num-1))].fix_id")
                    if [[ -n "$fix_id" && "$fix_id" != "null" ]]; then
                        selected_fixes+="$fix_id "
                    fi
                fi
            done
        fi
    fi

    if [[ -z "$selected_fixes" ]]; then
        print_warn "$(i18n 'common.cancel')"
        return 0
    fi

    # Generate and show plan
    local plan=$(generate_plan "$selected_fixes")

    # Create temporary file for plan preview with cleanup trap
    local plan_preview
    plan_preview=$(mktemp -t vpssec-plan.XXXXXX) || {
        print_error "Failed to create temp file"
        return 1
    }
    chmod 600 "$plan_preview"

    # Set up trap to clean up temp file on exit/interrupt
    trap "rm -f '$plan_preview'" EXIT INT TERM

    echo "# $(i18n 'guide.review_plan')" > "$plan_preview"
    echo "" >> "$plan_preview"
    echo "$(date -Iseconds)" >> "$plan_preview"
    echo "" >> "$plan_preview"
    echo "## $(i18n 'guide.select_fixes')" >> "$plan_preview"
    echo "" >> "$plan_preview"
    # List each fix; append the safety warning for confirm/risky fixes so the
    # operator sees what will need acknowledgement before the per-fix prompts.
    local pp_fix pp_id pp_sev pp_title pp_safety pp_warn
    while read -r pp_fix; do
        pp_id=$(echo "$pp_fix" | jq -r '.fix_id')
        pp_sev=$(echo "$pp_fix" | jq -r '.severity')
        pp_title=$(echo "$pp_fix" | jq -r '.title')
        pp_safety=$(get_fix_safety "$pp_id" 2>/dev/null || echo "unknown")
        if [[ "$pp_safety" == "risky" || "$pp_safety" == "confirm" ]]; then
            pp_warn=$(get_fix_warning "$pp_id" 2>/dev/null || echo "")
            echo "- [$pp_sev] $pp_title ($pp_id) [$pp_safety${pp_warn:+: $pp_warn}]" >> "$plan_preview"
        else
            echo "- [$pp_sev] $pp_title ($pp_id)" >> "$plan_preview"
        fi
    done < <(echo "$plan" | jq -c '.fixes[]')

    if tui_available; then
        ui_review_plan "$plan_preview"
    else
        cat "$plan_preview"
        echo ""
    fi
    rm -f "$plan_preview"
    trap - EXIT INT TERM  # Remove trap after cleanup

    # Confirm execution
    if ! ui_confirm_execute; then
        print_warn "$(i18n 'common.cancel')"
        return 0
    fi

    # Execute plan
    print_header "$(i18n 'guide.executing')"
    execute_plan

    # Re-audit before rendering the final report. execute_plan has applied
    # (or rolled back) changes, so the checks.json from the pre-fix audit is
    # now stale: without a fresh pass, fixes that just succeeded still show as
    # "failed" and the score / summary.sarif misrepresent the post-hardening
    # state (a CI/dashboard consuming the SARIF would see false-positive open
    # findings). _run_audit_pass calls state_init to reset and refill it.
    _run_audit_pass

    # Final report (now reflects the post-fix state)
    report_generate_all
}

# ==============================================================================
# Rollback Mode
# ==============================================================================

rollback_mode() {
    local timestamp="${1:-}"

    print_header "$(i18n 'common.rollback')"

    # List available backups
    local backups=$(backup_list)

    if [[ -z "$backups" ]]; then
        print_error "$(i18n 'backup.no_backup')"
        return 1
    fi

    if [[ -z "$timestamp" ]]; then
        # Interactive selection
        print_msg "$(i18n 'common.info'): Available backups:"
        echo ""

        local i=1
        local -a backup_array=()
        while read -r ts; do
            backup_array+=("$ts")
            local contents=$(backup_list_contents "$ts" | wc -l)
            echo "  $i) $ts ($contents files)"
            ((i++))
        done <<< "$backups"

        echo ""
        local choice
        # Always print prompt first
        echo -n "$(i18n 'common.enter_choice') [1-${#backup_array[@]}] > "
        if ! read -r choice </dev/tty 2>/dev/null; then
            echo ""
            print_error "$(i18n 'error.cannot_read_input')"
            return 1
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#backup_array[@]})); then
            timestamp="${backup_array[$((choice-1))]}"
        else
            print_error "$(i18n 'common.cancel')"
            return 1
        fi
    fi

    # Confirm rollback
    print_msg ""
    print_warn "$(i18n 'backup.restoring') $timestamp"

    local contents=$(backup_list_contents "$timestamp")
    if [[ -n "$contents" ]]; then
        print_msg ""
        print_msg "$(i18n 'common.info'): Files to restore:"
        echo "$contents" | while read -r f; do
            print_item "$f"
        done
    fi

    print_msg ""
    if ! confirm_critical "$(i18n 'common.confirm')?"; then
        print_warn "$(i18n 'common.cancel')"
        return 0
    fi

    # Execute rollback
    if backup_restore "$timestamp"; then
        print_ok "$(i18n 'backup.restored')"

        # Reload affected services
        print_info "Reloading services..."
        systemctl daemon-reload 2>/dev/null || true
        systemctl reload ssh 2>/dev/null || true
        systemctl reload nginx 2>/dev/null || true

        return 0
    else
        print_error "$(i18n 'error.rollback_failed')"
        return 1
    fi
}

# ==============================================================================
# Status Mode
# ==============================================================================

status_mode() {
    print_header "vpssec $(i18n 'cli.cmd_status')"

    # Last run info
    local ok_state="${STATE_OK_FILE}"
    if [[ -f "$ok_state" ]]; then
        local last_run=$(jq -r '.last_run // "never"' "$ok_state")
        print_msg "  Last run: $last_run"

        local completed=$(jq -r '.completed_fixes | length' "$ok_state")
        print_msg "  Completed fixes: $completed"
    fi

    # Backup info
    local latest_backup=$(backup_get_latest)
    if [[ -n "$latest_backup" ]]; then
        print_msg "  Latest backup: $latest_backup"
    fi

    # Progress info. We only persist progress.json during plan
    # execution and clear it on completion or rollback, so its
    # presence here means the previous run was killed mid-fix.
    # Resumption is not implemented — be honest about that and steer
    # the user to the two productive next steps.
    if state_has_progress; then
        local progress=$(state_load_progress)
        local current=$(echo "$progress" | jq -r '.current_fix')
        local total=$(echo "$progress" | jq -r '.total_fixes')
        print_warn "  $(i18n 'status.interrupted' "current=$current" "total=$total")"
        print_msg "    $(i18n 'status.interrupted_hint')"
    fi

    print_msg ""
}
