#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core engine - module loading, scheduling, and execution
# Copyright (c) 2024

# --- Security Levels ---

# Source security level configuration
VPSSEC_SECURITY_LEVELS_FILE="${VPSSEC_CORE}/security_levels.sh"
if [[ -f "$VPSSEC_SECURITY_LEVELS_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$VPSSEC_SECURITY_LEVELS_FILE"
fi

# --- Module Management ---

# Execution order, basics first: system basics, access control, network,
# hardening, services, scanning, operations. Adding a module means appending
# here AND to VPSSEC_MODULE_CATEGORY below.
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

# Modules that did NOT complete: failed to source, missing audit function, or
# audit returned non-zero. This is the ONLY signal for an incomplete audit —
# add new failure modes here rather than inventing a parallel one.
declare -ga VPSSEC_MODULES_FAILED=()

# Load-failed modules, separately: loading happens BEFORE state_init, so
# their _internal.module_failed check cannot be emitted at record time — it
# would be wiped. _run_audit_pass emits one per entry after state_init.
declare -gA VPSSEC_MODULE_LOAD_FAILED=()

# Record a module failure once (kind is "load" or "audit").
_module_record_failure() {
    local module="$1" kind="$2"
    [[ "$kind" == "load" ]] && VPSSEC_MODULE_LOAD_FAILED[$module]=1
    local entry
    for entry in ${VPSSEC_MODULES_FAILED[@]+"${VPSSEC_MODULES_FAILED[@]}"}; do
        [[ "$entry" == "$module" ]] && return 0
    done
    VPSSEC_MODULES_FAILED+=("$module")
    log_error "Module did not complete ($kind): $module"
}

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
        _module_record_failure "$module" "load"
        return 1
    fi

    # Verify the module's audit function exists
    local audit_func="${module}_audit"
    if ! declare -f "$audit_func" > /dev/null 2>&1; then
        log_warn "Module $module loaded but missing ${audit_func}() function"
        # Still mark as loaded, but record it: a module without an audit
        # function will contribute zero checks, which is indistinguishable
        # from "everything fine" unless the incompleteness is surfaced.
        _module_record_failure "$module" "load"
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
            # podman counts: the module's own probe reports an uninspectable
            # runtime, but only if the module actually loads.
            check_command docker || check_command podman || return 1
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

# Trim each comma-separated token and re-join. Validation and the matching
# loop MUST share this, or `--include="ssh, ufw"` validates and drops ufw.
_module_normalize_filter() {
    local list="$1" out="" token
    local IFS=','
    for token in $list; do
        token="${token#"${token%%[![:space:]]*}"}"
        token="${token%"${token##*[![:space:]]}"}"
        [[ -z "$token" ]] && continue
        out+="${out:+,}${token}"
    done
    printf '%s' "$out"
}

# Load all available modules
module_load_all() {
    local include="${1:-}"
    local exclude="${2:-}"

    include=$(_module_normalize_filter "$include")
    exclude=$(_module_normalize_filter "$exclude")

    # Context modules run with every filtered audit: users.sh keys its
    # cloud-init account list off the detected provider, so an --include
    # without them classifies differently. An explicit --exclude still wins.
    if [[ -n "$include" ]]; then
        include="preflight,cloud,timezone,${include}"
    fi

    # Unknown include tokens are fatal — a typo would otherwise produce an
    # empty audit that reads as "everything passed". Unknown exclude tokens
    # only warn: a wrong exclude is at worst conservative.
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

# Validate a comma-separated module list.
# Args: <list> <flag-name: include|exclude> <severity: fatal|warn>
# fatal exits 2 on any unknown token; warn continues.
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

# --- Audit Mode Execution ---

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

        # `if fn; then : ; else r=$?` captures the module's REAL status —
        # `if ! fn` would capture the status of `!`, which is always 0.
        # The `if` still suppresses set -e so one module cannot abort the run.
        local audit_result=0
        if "$audit_func"; then
            :
        else
            audit_result=$?
            log_warn "Audit function $audit_func returned non-zero: $audit_result"
            # Recorded, not hidden: without this, "module crashed" and
            # "module found nothing wrong" produce identical reports.
            _module_record_failure "$module" "audit"
            state_add_check "$(create_check_json \
                "_internal.module_failed" \
                "_internal" \
                "low" \
                "failed" \
                "$(i18n 'error.module_failed' "module=$module")" \
                "$(i18n 'error.module_failed_desc' "module=$module" "rc=$audit_result")" \
                "$(i18n 'error.module_failed_fix')" \
                "")"
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

# One full audit pass, shared by audit_all and guide_mode.
# Side effects both callers rely on: checks.json is reset and refilled, and
# VPSSEC_QUIET_SCAN is 1 during the loop but 0 again on return.
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

    # Pre-warm the cloud cache in THIS shell, with no command substitution:
    # a subshell's assignment dies with it, so every later
    # $(vpssec_cloud_provider) would otherwise re-run DMI detection.
    vpssec_cloud_provider >/dev/null
    vpssec_cloud_tier >/dev/null

    # Bypasses print_msg for \r, so it must repeat print_msg's --json-only
    # guard: otherwise these lines precede the JSON document on stdout.
    _progress() {
        [[ "${VPSSEC_JSON_ONLY:-0}" == "1" ]] && return 0
        # shellcheck disable=SC2059  # caller supplies the format string
        printf "$@"
    }

    local mod_title
    for module in "${modules[@]}"; do
        ((current++)) || true
        mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
        _progress "\r  [%d/%d] %s...                    " "$current" "$total" "$mod_title"

        audit_module "$module"
    done

    for module in "${VPSSEC_MODULE_ORDER[@]}"; do
        if [[ "${VPSSEC_MODULE_UNAVAILABLE[$module]:-0}" == "1" ]]; then
            ((current++)) || true
            mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
            _progress "\r  [%d/%d] %s ($(i18n 'common.not_installed' 2>/dev/null || echo 'not installed'))...        " "$current" "$total" "$mod_title"
        fi
    done
    _record_unavailable_modules

    # Modules that failed to LOAD never reach audit_module, so their
    # incompleteness record is emitted here, after state_init (emitting at
    # load time would be wiped by the next pass's reset).
    for module in "${!VPSSEC_MODULE_LOAD_FAILED[@]}"; do
        state_add_check "$(create_check_json \
            "_internal.module_failed" \
            "_internal" \
            "low" \
            "failed" \
            "$(i18n 'error.module_failed' "module=$module")" \
            "$(i18n 'error.module_failed_load_desc' "module=$module")" \
            "$(i18n 'error.module_failed_fix')" \
            "")"
    done

    # Clear progress line
    _progress "\r                                                              \r"

    export VPSSEC_QUIET_SCAN=0
}

# Run audit for all enabled modules
audit_all() {
    _run_audit_pass

    # Generate reports and print summary
    report_generate_all

    # Exit contract: 0 only for a COMPLETE audit; 3 = incomplete, distinct
    # from generic failure. Reports are written and printed either way.
    if (( ${#VPSSEC_MODULES_FAILED[@]} > 0 )); then
        return 3
    fi
    return 0
}

# --- Guide Mode Execution ---

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

    # One plan entry per unique fix id: the selection can name a fix twice and
    # the select() matches every check sharing it. first() keeps one
    # representative check; the fix function only receives the fix_id.
    local -A plan_seen=()
    for fix_id in $selected_fixes; do
        [[ -n "${plan_seen[$fix_id]:-}" ]] && continue
        plan_seen[$fix_id]=1
        local check=$(echo "$checks" | jq -r --arg id "$fix_id" 'first(.[] | select(.fix_id == $id))')
        if [[ -n "$check" && "$check" != "null" ]]; then
            plan_fixes+=("$check")
        fi
    done

    # Create plan JSON
    local plan_json=$(printf '%s\n' "${plan_fixes[@]}" | jq -s '{
        "timestamp": "'"$(date -Iseconds)"'",
        "fixes": .
    }')

    # Propagated: execute_plan re-reads the plan from disk, so a swallowed
    # save failure would execute whatever plan the file held before.
    state_save_plan "$plan_json" || return 1
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

        # Confirmation is enforced centrally so no confirm/risky fix can apply
        # unacknowledged. FIX_SELF_CONFIRMED fixes prompt themselves and are
        # skipped here. Risky uses confirm_critical, which ignores --yes.
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
            # Declared postcondition: a FIX_VERIFY fix reports success only
            # once the audit's own predicate sees the new state — a written
            # file is not yet an effective setting.
            local verify_fn
            verify_fn=$(get_fix_verify "$fix_id" 2>/dev/null || echo "")
            if [[ -n "$verify_fn" ]]; then
                if ! declare -f "$verify_fn" >/dev/null 2>&1; then
                    log_error "Verify predicate not found: $verify_fn ($fix_id)"
                    print_warn "$(i18n 'fix.verify_failed')"
                    return 1
                fi
                if ! "$verify_fn"; then
                    log_error "Fix verify failed: $fix_id ($verify_fn)"
                    print_warn "$(i18n 'fix.verify_failed')"
                    return 1
                fi
            fi
            # Returning 0 means "my work succeeded", not "the finding is
            # resolved" — for FIX_TEMPLATE_ONLY it never can be. The exit
            # status stays honest about the work; the map carries the rest.
            if fix_is_template_only "$fix_id"; then
                log_info "Fix applied, manual step remains: $fix_id"
                print_warn "$(i18n 'fix.manual_step_remains')"
                print_info "$(get_fix_manual_step "$fix_id")"
            else
                state_mark_fix_complete "$fix_id"
            fi
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

    # Buffered first, then iterated: feeding the loop from `< <(jq ...)` makes
    # that pipe the stdin of every fix body, and a fix that reads stdin would
    # swallow the remaining plan.
    local -a fix_lines=()
    local _line
    while IFS= read -r _line; do
        [[ -n "$_line" ]] && fix_lines+=("$_line")
    done < <(echo "$fixes" | jq -c '.[]')

    local i=0
    local fix
    for fix in "${fix_lines[@]}"; do
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
                read -r choice 2>/dev/null </dev/tty || choice="1"

                case "$choice" in
                    2)
                        # Retry
                        if execute_fix "$fix_id"; then
                            print_ok "$(i18n 'common.success')"
                            completed+=("$fix_id")
                            # Rebuilt, not filtered: `${arr[@]/pat}` blanks
                            # the element instead of removing it.
                            local _kept=()
                            local _f
                            for _f in "${failed[@]}"; do
                                [[ "$_f" != "$fix_id" ]] && _kept+=("$_f")
                            done
                            failed=("${_kept[@]}")
                        fi
                        ;;
                    3)
                        # Restore THIS plan's session, not merely the latest
                        # dir. rc is swallowed so set -e cannot kill the run
                        # mid-rollback, but the outcome is reported.
                        print_warn "$(i18n 'backup.restoring')"
                        local _rb_rc=0
                        backup_restore "$(basename "$VPSSEC_BACKUP_SESSION")" || _rb_rc=$?
                        if (( _rb_rc == 1 )); then
                            print_error "$(i18n 'error.rollback_failed')"
                        fi
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
    done

    # Clear progress
    state_clear_progress

    # Each guide run adds a timestamped directory, so prune. Rollback works
    # against any session that survives.
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

    # The exit status must carry the outcome the summary just printed.
    (( ${#failed[@]} > 0 )) && return 1
    return 0
}

# Resume the interrupted plan: last_plan.json minus progress.json's completed
# ids. The in-flight fix IS re-run (fix functions are idempotent). System
# changes made by other actors meanwhile are NOT handled.
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

    # current_fix is deliberately not in completed, so a mid-fix interrupt
    # re-runs it. The jq variable avoids the name `done`, which trips
    # ShellCheck SC1010 inside a single-quoted filter.
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

    # The on-disk plan is trimmed so a second interrupt-then-resume composes.
    # The interrupted run's backup dir stays rollback-able by its timestamp.
    local resume_plan
    resume_plan=$(echo "$plan" | jq --argjson fixes "$remaining_fixes" \
        '.fixes = $fixes')
    # Stop rather than resume from a plan the trim failed to write: execute_plan
    # reads the file, and the untrimmed plan re-runs completed fixes.
    if ! state_save_plan "$resume_plan"; then
        print_error "$(i18n 'common.failed')"
        return 1
    fi

    # Same rc-capture as guide_mode: a failed fix must not abort the
    # completion hint under set -e, but the status must still propagate.
    local plan_rc=0
    execute_plan || plan_rc=$?

    # No re-audit here, matching the normal post-execute_plan flow.
    print_msg ""
    print_info "$(i18n 'guide.resume_complete_hint')"
    return "$plan_rc"
}

# Guide mode main flow
guide_mode() {
    # Fix paths are apt/dpkg-based; refuse rather than run apt where it is
    # absent. Exit 4 = capability not supported, distinct from success (0) and
    # a failed fix (1) — automation must tell "done" from "refused to start".
    if ! is_debian_based; then
        print_warn "$(i18n 'guide.fix_debian_only')"
        return 4
    fi

    # progress.json exists = the previous plan was killed mid-execution.
    # Ask before re-auditing, so the user can resume or start over.
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
        if ! read -r _choice 2>/dev/null </dev/tty; then
            _choice=3
        fi

        case "$_choice" in
            1)
                # rc-capture: a bare call would let set -e abort guide_mode on
                # a failed resumed fix; the status still propagates via return.
                local _resume_rc=0
                _guide_resume || _resume_rc=$?
                return "$_resume_rc"
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
        read -r selection 2>/dev/null </dev/tty || selection=""

        if [[ "$selection" == "all" ]]; then
            selected_fixes=$(echo "$fixes" | jq -r '.[].fix_id' | tr '\n' ' ')
        else
            for num in $selection; do
                # Lower bound matters: "0" passes ^[0-9]+$ but $((0-1)) is -1,
                # which jq treats as "last element" — typing 0 silently
                # selected the final fix in the list.
                if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 )); then
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

    # Generate and show plan. Status captured: a failed plan save must stop
    # here, not fall through to execute a stale on-disk plan.
    local plan
    if ! plan=$(generate_plan "$selected_fixes"); then
        print_error "$(i18n 'common.failed')"
        log_error "generate_plan failed for selection: $selected_fixes"
        return 1
    fi

    # An empty plan means the UI handed over ids the planner cannot map.
    # Executing nothing while printing success is the worst outcome.
    local plan_count=$(echo "$plan" | jq '.fixes | length')
    if (( plan_count == 0 )); then
        print_error "$(i18n 'guide.plan_empty')"
        log_error "generate_plan resolved 0 fixes from selection: $selected_fixes"
        return 1
    fi

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

    # Status captured, not called bare: under set -e a non-zero execute_plan
    # would abort here and skip the re-audit and final report.
    print_header "$(i18n 'guide.executing')"
    local plan_rc=0
    execute_plan || plan_rc=$?

    # Re-audit before the final report: the pre-fix checks.json is now stale,
    # so successful fixes would still render as failed and the SARIF would
    # carry false-positive open findings.
    _run_audit_pass

    # Final report (now reflects the post-fix state)
    report_generate_all

    return "$plan_rc"
}

# --- Rollback Mode ---

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
        if ! read -r choice 2>/dev/null </dev/tty; then
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

    # backup_restore has three outcomes; do not collapse them to a boolean.
    # 2 (partial) still reloads services, since the restored files must take
    # effect, but reports the partial result honestly.
    local restore_rc=0
    backup_restore "$timestamp" || restore_rc=$?

    if (( restore_rc == 1 )); then
        print_error "$(i18n 'error.rollback_failed')"
        return 1
    fi

    if (( restore_rc == 0 )); then
        print_ok "$(i18n 'backup.restored')"
    else
        print_warn "$(i18n 'backup.restored_partial')"
    fi

    # Reload affected services
    print_info "Reloading services..."
    systemctl daemon-reload 2>/dev/null || true
    systemctl reload ssh 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || true

    return "$restore_rc"
}

# --- Status Mode ---

status_mode() {
    print_header "vpssec $(i18n 'cli.cmd_status')"

    # Non-root honesty: state/ is deliberately chmod 700 root, so a normal
    # user's status can never show run data on a root-owned install. Say so
    # instead of printing a header followed by silence.
    if [[ -d "${VPSSEC_STATE}" && ! -r "${VPSSEC_STATE}" ]]; then
        print_msg "  $(i18n 'status.state_unreadable')"
        print_msg ""
        return 0
    fi

    print_msg "  $(i18n 'status.version' "version=${VPSSEC_VERSION}")"

    # The only command that reaches the network to compare versions. audit and
    # guide never do: an audit that phones home on every CI run is a different
    # product, and an unreachable GitHub must not colour a security verdict.
    local latest
    latest=$(_vpssec_latest_release_tag)
    if [[ -n "$latest" && "$VPSSEC_VERSION" != "unknown" ]] \
       && _vpssec_version_lt "v${VPSSEC_VERSION}" "$latest"; then
        print_warn "  $(i18n 'status.update_available' "latest=$latest")"
    fi

    # Last run info
    local ok_state="${STATE_OK_FILE}"
    if [[ -f "$ok_state" ]]; then
        local last_run=$(jq -r '.last_run // "never"' "$ok_state")
        print_msg "  $(i18n 'status.last_run' "time=$last_run")"

        local completed=$(jq -r '.completed_fixes | length' "$ok_state")
        print_msg "  $(i18n 'status.completed_fixes' "count=$completed")"
    fi

    # Backup info
    local latest_backup=$(backup_get_latest)
    if [[ -n "$latest_backup" ]]; then
        print_msg "  $(i18n 'status.latest_backup' "time=$latest_backup")"
    fi

    # progress.json is only present between a mid-fix kill and the next
    # guide run, which offers to resume it.
    if state_has_progress; then
        local progress=$(state_load_progress)
        local current=$(echo "$progress" | jq -r '.current_fix')
        local total=$(echo "$progress" | jq -r '.total_fixes')
        print_warn "  $(i18n 'status.interrupted' "current=$current" "total=$total")"
        print_msg "    $(i18n 'status.interrupted_hint')"
    fi

    print_msg ""
}
