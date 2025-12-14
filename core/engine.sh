#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core engine - module loading, scheduling, and execution
# Copyright (c) 2024

# ==============================================================================
# Module Management
# ==============================================================================

# Available modules (order matters for execution)
declare -a VPSSEC_MODULE_ORDER=(
    "preflight"
    "ssh"
    "ufw"
    "update"
    "docker"
    "nginx"
    "baseline"
    "logging"
    "cloudflared"
    "backup"
    "alerts"
)

# Module metadata
declare -A VPSSEC_MODULE_ENABLED=()
declare -A VPSSEC_MODULE_LOADED=()

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
            check_command ufw || return 1
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
    esac

    return 0
}

# Load all available modules
module_load_all() {
    local include="${1:-}"
    local exclude="${2:-}"

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

        # Execute audit with error capture
        local audit_result=0
        if ! "$audit_func"; then
            audit_result=$?
            log_warn "Audit function $audit_func returned non-zero: $audit_result"
            # Don't fail the whole audit for individual module failures
        fi

        return 0  # Module audit completed (even if with warnings)
    else
        log_warn "Audit function not found: $audit_func"
        print_error "$(i18n 'error.audit_func_not_found' "func=$audit_func" 2>/dev/null || echo "Audit function not found: $audit_func")"
        return 1
    fi
}

# Run audit for all enabled modules
audit_all() {
    state_init

    # Get enabled modules as array
    local -a modules=()
    while IFS= read -r m; do
        modules+=("$m")
    done < <(module_get_enabled)

    local total=${#modules[@]}
    local current=0

    # Enable quiet scan mode for cleaner output
    export VPSSEC_QUIET_SCAN=1

    print_msg ""
    print_msg "$(i18n 'scan.scanning' 2>/dev/null || echo 'Scanning...')"
    print_msg ""

    for module in "${modules[@]}"; do
        ((current++)) || true
        # Show progress line
        local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
        printf "\r  [%d/%d] %s...                    " "$current" "$total" "$mod_title"

        audit_module "$module"
    done

    # Clear progress line
    printf "\r                                                              \r"

    # Disable quiet mode for summary output
    export VPSSEC_QUIET_SCAN=0

    # Generate reports and print summary
    report_generate_all
}

# ==============================================================================
# Guide Mode Execution
# ==============================================================================

# Get available fixes from audit results
get_available_fixes() {
    local checks=$(state_get_checks)
    echo "$checks" | jq -r '[.[] | select(.status == "failed" and .fix_id != null and .fix_id != "")]'
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
    local module="${fix_id%%.*}"

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

    # Create backup session
    local backup_dir=$(backup_create_session)
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
                            # Remove from failed
                            failed=("${failed[@]/$fix_id}")
                        fi
                        ;;
                    3)
                        # Rollback and exit
                        print_warn "$(i18n 'backup.restoring')"
                        backup_restore_latest
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

    return 0
}

# Guide mode main flow
guide_mode() {
    # First run audit
    print_header "$(i18n 'guide.welcome')"
    print_msg ""

    # Run audit
    state_init
    for module in $(module_get_enabled); do
        audit_module "$module"
    done

    # Get available fixes
    local fixes=$(get_available_fixes)
    local fix_count=$(echo "$fixes" | jq 'length')

    if ((fix_count == 0)); then
        print_ok "$(i18n 'common.safe') - $(i18n 'guide.complete')"
        report_generate_all
        return 0
    fi

    # Show results
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

            local prefix=""
            case "$severity" in
                high)   prefix="${RED}[!]${NC}" ;;
                medium) prefix="${YELLOW}[*]${NC}" ;;
                low)    prefix="${BLUE}[-]${NC}" ;;
            esac

            echo -e "  $i) $prefix $title ($fix_id)"
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
    echo "$plan" | jq -r '.fixes[] | "- [\(.severity)] \(.title) (\(.fix_id))"' >> "$plan_preview"

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

    # Final report
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
    print_header "vpssec $(i18n 'cmd_status')"

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

    # Progress info
    if state_has_progress; then
        local progress=$(state_load_progress)
        local current=$(echo "$progress" | jq -r '.current_fix')
        local total=$(echo "$progress" | jq -r '.total_fixes')
        print_warn "  Interrupted operation detected: $current ($total total)"
    fi

    print_msg ""
}
