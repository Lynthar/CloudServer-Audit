#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# State management for tracking checks, fixes, and backups
# Copyright (c) 2024

# ==============================================================================
# State File Paths
# ==============================================================================

STATE_OK_FILE="${VPSSEC_STATE}/ok.json"
STATE_PLAN_FILE="${VPSSEC_STATE}/last_plan.json"
STATE_PROGRESS_FILE="${VPSSEC_STATE}/progress.json"
STATE_CHECKS_FILE="${VPSSEC_STATE}/checks.json"

# ==============================================================================
# State Initialization
# ==============================================================================

state_init() {
    mkdir -p "${VPSSEC_STATE}"

    # Set secure permissions on state directory
    chmod 700 "${VPSSEC_STATE}"

    # Initialize ok.json if not exists (atomic check with mkdir lock pattern)
    # Using a lock to prevent race condition
    local lock_file="${VPSSEC_STATE}/.init.lock"
    (
        flock -n 200 || exit 0  # Skip if another process is initializing
        if [[ ! -f "$STATE_OK_FILE" ]]; then
            echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"
        fi
    ) 200>"$lock_file"

    # Initialize checks.json (always start fresh for each run)
    echo '[]' > "$STATE_CHECKS_FILE"
}

# ==============================================================================
# Check State Management
# ==============================================================================

# Add a check result to state (thread-safe with file locking)
state_add_check() {
    local check_json="$1"
    local lock_file="${VPSSEC_STATE}/.checks.lock"

    (
        flock -x 200  # Exclusive lock for write operation

        # Initialize if file doesn't exist
        [[ -f "$STATE_CHECKS_FILE" ]] || echo '[]' > "$STATE_CHECKS_FILE"

        # Read current state, add check, write to temp file, then move atomically
        local temp_file
        temp_file=$(mktemp "${STATE_CHECKS_FILE}.XXXXXX") || return 1

        if jq --argjson check "$check_json" '. += [$check]' "$STATE_CHECKS_FILE" > "$temp_file" 2>/dev/null; then
            mv -f "$temp_file" "$STATE_CHECKS_FILE"
        else
            rm -f "$temp_file"
            return 1
        fi
    ) 200>"$lock_file"
}

# Get all checks
state_get_checks() {
    if [[ -f "$STATE_CHECKS_FILE" ]]; then
        cat "$STATE_CHECKS_FILE"
    else
        echo '[]'
    fi
}

# Get checks by status
state_get_checks_by_status() {
    local status="$1"
    state_get_checks | jq -r --arg status "$status" '[.[] | select(.status == $status)]'
}

# Get checks by severity
state_get_checks_by_severity() {
    local severity="$1"
    state_get_checks | jq -r --arg sev "$severity" '[.[] | select(.severity == $sev)]'
}

# Get checks by module
state_get_checks_by_module() {
    local module="$1"
    state_get_checks | jq -r --arg mod "$module" '[.[] | select(.module == $mod)]'
}

# Count checks by status
state_count_checks() {
    local status="$1"
    state_get_checks | jq -r --arg status "$status" '[.[] | select(.status == $status)] | length'
}

# ==============================================================================
# Fix State Management
# ==============================================================================

# Record a completed fix (thread-safe with file locking)
state_mark_fix_complete() {
    local fix_id="$1"
    local timestamp
    timestamp=$(date -Iseconds)
    local lock_file="${VPSSEC_STATE}/.ok.lock"

    (
        flock -x 200  # Exclusive lock for write operation

        # Initialize if file doesn't exist
        [[ -f "$STATE_OK_FILE" ]] || echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"

        # Read, modify, write atomically
        local temp_file
        temp_file=$(mktemp "${STATE_OK_FILE}.XXXXXX") || return 1

        if jq --arg id "$fix_id" --arg ts "$timestamp" \
            '.completed_fixes += [{"id": $id, "timestamp": $ts}] | .last_run = $ts' \
            "$STATE_OK_FILE" > "$temp_file" 2>/dev/null; then
            mv -f "$temp_file" "$STATE_OK_FILE"
        else
            rm -f "$temp_file"
            return 1
        fi
    ) 200>"$lock_file"

    log_info "Fix marked complete: $fix_id"
}

# Check if a fix was already applied
state_is_fix_applied() {
    local fix_id="$1"
    local result=$(jq -r --arg id "$fix_id" '.completed_fixes[] | select(.id == $id) | .id' "$STATE_OK_FILE" 2>/dev/null)
    [[ -n "$result" ]]
}

# Get all completed fixes
state_get_completed_fixes() {
    jq -r '.completed_fixes' "$STATE_OK_FILE" 2>/dev/null || echo '[]'
}

# Clear fix state (for testing or reset)
state_clear_fixes() {
    echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"
    log_info "Fix state cleared"
}

# ==============================================================================
# Plan State Management
# ==============================================================================

# Save execution plan
state_save_plan() {
    local plan_json="$1"
    echo "$plan_json" > "$STATE_PLAN_FILE"
    log_info "Plan saved to $STATE_PLAN_FILE"
}

# Load last plan
state_load_plan() {
    if [[ -f "$STATE_PLAN_FILE" ]]; then
        cat "$STATE_PLAN_FILE"
    else
        echo '{"fixes": [], "timestamp": null}'
    fi
}

# Clear plan
state_clear_plan() {
    rm -f "$STATE_PLAN_FILE"
}

# ==============================================================================
# Progress Tracking (for interrupted operations)
# ==============================================================================

# Save progress
state_save_progress() {
    local current_fix="$1"
    local total_fixes="$2"
    local completed_ids="$3"  # JSON array of completed fix IDs

    cat > "$STATE_PROGRESS_FILE" <<EOF
{
  "current_fix": "$current_fix",
  "total_fixes": $total_fixes,
  "completed": $completed_ids,
  "timestamp": "$(date -Iseconds)"
}
EOF
    log_debug "Progress saved: $current_fix of $total_fixes"
}

# Load progress
state_load_progress() {
    if [[ -f "$STATE_PROGRESS_FILE" ]]; then
        cat "$STATE_PROGRESS_FILE"
    else
        echo '{"current_fix": null, "total_fixes": 0, "completed": []}'
    fi
}

# Clear progress
state_clear_progress() {
    rm -f "$STATE_PROGRESS_FILE"
}

# Check if there's interrupted progress
state_has_progress() {
    [[ -f "$STATE_PROGRESS_FILE" ]]
}

# ==============================================================================
# Backup Management
# ==============================================================================

# List all backups
backup_list() {
    if [[ -d "${VPSSEC_BACKUPS}" ]]; then
        ls -1 "${VPSSEC_BACKUPS}" 2>/dev/null | sort -r
    fi
}

# Get latest backup timestamp
backup_get_latest() {
    backup_list | head -n1
}

# Create a new backup session
backup_create_session() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"
    mkdir -p "$backup_dir"
    echo "$backup_dir"
}

# Backup a file in current session
backup_file_to_session() {
    local file="$1"
    local session_dir="$2"

    if [[ -f "$file" ]]; then
        local relative_path="${file#/}"
        local backup_path="${session_dir}/${relative_path}"
        mkdir -p "$(dirname "$backup_path")"
        cp -p "$file" "$backup_path"
        log_info "Backed up: $file -> $backup_path"
        echo "$backup_path"
    fi
}

# Restore from a specific backup
backup_restore() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup not found: $timestamp"
        return 1
    fi

    log_info "Restoring from backup: $timestamp"

    # Find all backed up files and restore them
    while IFS= read -r -d '' backup_file; do
        local relative_path="${backup_file#$backup_dir/}"
        local original_path="/${relative_path}"
        local original_dir=$(dirname "$original_path")

        mkdir -p "$original_dir"
        cp -p "$backup_file" "$original_path"
        log_info "Restored: $backup_file -> $original_path"
    done < <(find "$backup_dir" -type f -print0)

    return 0
}

# Restore latest backup
backup_restore_latest() {
    local latest=$(backup_get_latest)
    if [[ -n "$latest" ]]; then
        backup_restore "$latest"
    else
        log_error "No backups found"
        return 1
    fi
}

# Get backup contents (for preview)
backup_list_contents() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    if [[ -d "$backup_dir" ]]; then
        find "$backup_dir" -type f | while read -r f; do
            echo "${f#$backup_dir}"
        done
    fi
}

# Clean old backups (keep last N)
backup_cleanup() {
    local keep="${1:-10}"
    local count=0

    backup_list | while read -r timestamp; do
        ((count++)) || true
        if ((count > keep)); then
            local backup_path="${VPSSEC_BACKUPS}/${timestamp}"
            # Safety: validate path is under backup directory
            if [[ -n "$timestamp" ]] && [[ "$backup_path" =~ ^${VPSSEC_BACKUPS}/[0-9]{8}-[0-9]{6}$ ]] && [[ -d "$backup_path" ]]; then
                rm -rf "$backup_path"
                log_info "Removed old backup: $timestamp"
            fi
        fi
    done
}

# ==============================================================================
# Score Calculation
# ==============================================================================

calculate_score() {
    local checks=$(state_get_checks)
    local total=$(echo "$checks" | jq 'length')
    local high_fail=$(echo "$checks" | jq '[.[] | select(.status == "failed" and .severity == "high")] | length')
    local medium_fail=$(echo "$checks" | jq '[.[] | select(.status == "failed" and .severity == "medium")] | length')
    local low_fail=$(echo "$checks" | jq '[.[] | select(.status == "failed" and .severity == "low")] | length')
    local passed=$(echo "$checks" | jq '[.[] | select(.status == "passed")] | length')

    # Score calculation:
    # Start at 100, deduct for failures
    # High: -15 points each (max 60)
    # Medium: -5 points each (max 25)
    # Low: -2 points each (max 10)

    local score=100
    local high_deduct=$((high_fail * 15))
    ((high_deduct > 60)) && high_deduct=60
    local medium_deduct=$((medium_fail * 5))
    ((medium_deduct > 25)) && medium_deduct=25
    local low_deduct=$((low_fail * 2))
    ((low_deduct > 10)) && low_deduct=10

    score=$((score - high_deduct - medium_deduct - low_deduct))
    ((score < 0)) && score=0

    echo "$score"
}

# Get check statistics
get_check_stats() {
    local checks=$(state_get_checks)
    local high=$(echo "$checks" | jq '[.[] | select(.status == "failed" and .severity == "high")] | length')
    local medium=$(echo "$checks" | jq '[.[] | select(.status == "failed" and .severity == "medium")] | length')
    local low=$(echo "$checks" | jq '[.[] | select(.status == "failed" and .severity == "low")] | length')
    local passed=$(echo "$checks" | jq '[.[] | select(.status == "passed")] | length')

    echo "{\"high\": $high, \"medium\": $medium, \"low\": $low, \"passed\": $passed}"
}
