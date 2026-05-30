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

    # Initialize checks.json (always start fresh for each run).
    # Preserve the previous run's checks as .prev so partial results
    # from an interrupted run (Ctrl+C, OOM kill, module crash) can be
    # inspected post-mortem instead of being wiped silently.
    if [[ -f "$STATE_CHECKS_FILE" ]]; then
        cp -p "$STATE_CHECKS_FILE" "${STATE_CHECKS_FILE}.prev" 2>/dev/null || true
    fi
    echo '[]' > "$STATE_CHECKS_FILE"
}

# ==============================================================================
# Check State Management
# ==============================================================================

# Add a check result to state (thread-safe with file locking).
#
# Defence in depth: if a module produced invalid JSON (historically the
# hand-written heredocs in cloud/malware/users/webapp did this whenever
# an interpolated $var contained a quote, newline or CR), swap it for a
# synthetic "malformed check" record so the breakage is visible in the
# report instead of silently disappearing. The downstream jq append
# would have dropped it anyway; this path adds diagnostics.
state_add_check() {
    local check_json="$1"
    local lock_file="${VPSSEC_STATE}/.checks.lock"

    if ! printf '%s' "$check_json" | jq empty 2>/dev/null; then
        log_error "state_add_check received malformed JSON (first 200 bytes): ${check_json:0:200}"
        local raw_preview="${check_json:0:500}"
        check_json=$(create_check_json \
            "_internal.malformed_check" \
            "_internal" \
            "medium" \
            "failed" \
            "Malformed check JSON dropped" \
            "A module emitted invalid JSON for a check. Raw payload (first 500 bytes): ${raw_preview}" \
            "Please report to vpssec maintainers with the relevant logs/vpssec.log entry" \
            "")
    fi

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

# Create a new backup session directory. execute_plan assigns the returned
# path to the global VPSSEC_BACKUP_SESSION, so every backup_file call during the
# plan lands here and a rollback can restore the whole plan. (The former
# backup_file_to_session helper was unused — backup_file is now session-aware.)
backup_create_session() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    echo "$backup_dir"
}

# Restore from a specific backup.
#
# Defense-in-depth path checks (none of these block a known live
# attack today, but they make backup_restore *not* a "write to any
# host path" primitive even if backup contents are partially
# tampered or the timestamp argument is malformed):
#
#   1. timestamp must match the YYYYMMDD_HHMMSS format that
#      backup_create_session emits. This refuses things like
#      `vpssec rollback ../../etc` or selecting a hand-placed
#      `evil/` directory under backups/.
#   2. Each entry under backup_dir must be a *regular* file, not
#      a symlink. find -type f normally excludes symlinks, but a
#      directory symlink along the path can let find traverse
#      out of backup_dir; we cross-check that the resolved file
#      stays inside backup_dir.
#   3. Each restore destination must be a regular file (or absent)
#      and its parent must be a real directory, not a symlink. A
#      symlink-replaced parent could redirect cp into an
#      attacker-chosen location. This is a TOCTOU window between
#      backup time and restore time; treating any symlink in the
#      destination path as "abort and skip" is the cheap mitigation.
backup_restore() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    # Check 1: timestamp shape. The same regex backup_cleanup uses,
    # extracted here so a typo'd or attacker-chosen argument can't
    # become a write primitive via a hand-placed sibling directory.
    if [[ ! "$timestamp" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
        log_error "Refusing to restore: timestamp '$timestamp' does not match YYYYMMDD_HHMMSS"
        return 1
    fi

    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup not found: $timestamp"
        return 1
    fi

    log_info "Restoring from backup: $timestamp"

    # Resolve backup_dir once for symlink-escape detection on each
    # found file. realpath handles the "is this still under
    # backup_dir after symlink resolution" question.
    local backup_dir_real
    backup_dir_real=$(realpath "$backup_dir" 2>/dev/null) || {
        log_error "Cannot resolve backup directory: $backup_dir"
        return 1
    }

    local skipped=0
    local restored=0

    # Find all backed up files and restore them
    while IFS= read -r -d '' backup_file; do
        # Check 2a: source must not itself be a symlink. find -type f
        # follows symlinks during the test, which means a symlink
        # pointing at an arbitrary host file would be matched.
        if [[ -L "$backup_file" ]]; then
            log_warn "Skipping symlinked backup entry: $backup_file"
            ((skipped++)) || true
            continue
        fi

        # Check 2b: source must still resolve to under backup_dir.
        # This catches a directory symlink farther up the path.
        local backup_file_real
        backup_file_real=$(realpath "$backup_file" 2>/dev/null) || {
            log_warn "Cannot resolve backup file, skipping: $backup_file"
            ((skipped++)) || true
            continue
        }
        if [[ "$backup_file_real" != "$backup_dir_real"/* ]]; then
            log_warn "Skipping backup entry that escapes backup_dir via symlink: $backup_file -> $backup_file_real"
            ((skipped++)) || true
            continue
        fi

        local relative_path="${backup_file#"$backup_dir"/}"
        local original_path="/${relative_path}"
        local original_dir
        original_dir=$(dirname "$original_path")

        # Check 3a: destination directory must not be a symlink. A
        # TOCTOU swap between backup and restore could swing
        # /etc/ssh into an attacker-controlled tree; refusing to
        # write through symlinks closes that window.
        if [[ -L "$original_dir" ]]; then
            log_warn "Skipping restore: parent directory is a symlink: $original_dir"
            ((skipped++)) || true
            continue
        fi

        # Check 3b: existing destination must not be a symlink.
        # cp -p would dereference and write through it.
        if [[ -L "$original_path" ]]; then
            log_warn "Skipping restore: target path is a symlink: $original_path"
            ((skipped++)) || true
            continue
        fi

        mkdir -p "$original_dir"
        cp -p "$backup_file" "$original_path"
        log_info "Restored: $backup_file -> $original_path"
        ((restored++)) || true
    done < <(find "$backup_dir" -type f -print0)

    if (( skipped > 0 )); then
        log_warn "Restore complete with skips: ${restored} restored, ${skipped} skipped (see logs/vpssec.log)"
    else
        log_info "Restore complete: ${restored} files"
    fi

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
            echo "${f#"$backup_dir"}"
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
            # Safety: validate path is under backup directory.
            # backup_create_session formats timestamps as YYYYMMDD_HHMMSS
            # (underscore). The regex used to check for a hyphen, which
            # never matched, so backup_cleanup was a no-op and old
            # backups accumulated indefinitely.
            if [[ -n "$timestamp" ]] && [[ "$backup_path" =~ ^${VPSSEC_BACKUPS}/[0-9]{8}_[0-9]{6}$ ]] && [[ -d "$backup_path" ]]; then
                rm -rf "$backup_path"
                log_info "Removed old backup: $timestamp"
            fi
        fi
    done
}

# ==============================================================================
# Score Calculation
# ==============================================================================

# Detect which conditional components are installed
# Returns a JSON object with component installation status
_detect_installed_components() {
    local checks="$1"

    # Check for each conditional component by looking for checks that indicate installation
    # If we only have a "not_installed" check for a module, the component is not installed

    local docker_installed="false"
    local nginx_installed="false"
    local cloudflared_installed="false"

    # Docker: installed if we have any docker.* check that is NOT docker.not_installed
    if echo "$checks" | jq -e '[.[] | select(.id | startswith("docker.")) | select(.id != "docker.not_installed")] | length > 0' >/dev/null 2>&1; then
        docker_installed="true"
    fi

    # Nginx: installed if we have any nginx.* check that is NOT nginx.not_installed
    if echo "$checks" | jq -e '[.[] | select(.id | startswith("nginx.")) | select(.id != "nginx.not_installed")] | length > 0' >/dev/null 2>&1; then
        nginx_installed="true"
    fi

    # Cloudflared: installed if we have any cloudflared.* check that is NOT cloudflared.not_installed
    if echo "$checks" | jq -e '[.[] | select(.id | startswith("cloudflared.")) | select(.id != "cloudflared.not_installed")] | length > 0' >/dev/null 2>&1; then
        cloudflared_installed="true"
    fi

    echo "{\"docker\": $docker_installed, \"nginx\": $nginx_installed, \"cloudflared\": $cloudflared_installed}"
}

# Check if a check should be included in score calculation
# Args: check_id, installed_components_json
_check_counts_in_score() {
    local check_id="$1"
    local installed="$2"

    # Get category (default to required if not found)
    local category
    if declare -f get_check_score_category &>/dev/null; then
        category=$(get_check_score_category "$check_id")
    else
        category="required"
    fi

    case "$category" in
        required|recommended)
            # Always count
            return 0
            ;;
        conditional)
            # Only count if parent component is installed
            local module="${check_id%%.*}"
            case "$module" in
                docker)
                    [[ $(echo "$installed" | jq -r '.docker') == "true" ]]
                    ;;
                nginx)
                    [[ $(echo "$installed" | jq -r '.nginx') == "true" ]]
                    ;;
                cloudflared)
                    [[ $(echo "$installed" | jq -r '.cloudflared') == "true" ]]
                    ;;
                *)
                    return 0  # Unknown module, include
                    ;;
            esac
            ;;
        optional)
            # Only count in strict mode
            [[ "${VPSSEC_SECURITY_LEVEL:-standard}" == "strict" ]]
            ;;
        info)
            # Never count
            return 1
            ;;
        *)
            # Unknown category, include by default
            return 0
            ;;
    esac
}

calculate_score() {
    local checks=$(state_get_checks)
    local installed=$(_detect_installed_components "$checks")

    # Count failures by severity, but only for checks that should count in score
    local high_fail=0
    local medium_fail=0
    local low_fail=0
    local scored_total=0

    # Read checks into array and process
    local check_ids
    check_ids=$(echo "$checks" | jq -r '.[] | @json')

    while IFS= read -r check_json; do
        [[ -z "$check_json" ]] && continue

        local check_id status severity
        check_id=$(echo "$check_json" | jq -r '.id // empty')
        status=$(echo "$check_json" | jq -r '.status // empty')
        severity=$(echo "$check_json" | jq -r '.severity // "low"')

        [[ -z "$check_id" ]] && continue

        # Check if this check should be included in score
        if ! _check_counts_in_score "$check_id" "$installed"; then
            continue
        fi

        ((scored_total++)) || true

        if [[ "$status" == "failed" ]]; then
            case "$severity" in
                high|critical)
                    ((high_fail++)) || true
                    ;;
                medium)
                    ((medium_fail++)) || true
                    ;;
                low|info)
                    ((low_fail++)) || true
                    ;;
            esac
        fi
    done <<< "$(echo "$checks" | jq -c '.[]')"

    # Score calculation (pass-rate based, with severity penalty on top).
    #
    # History:
    #   v1 — additive/capped (-80/-40/-15) hit its combined cap of
    #        -135 on any real server with a handful of mediums; could
    #        not distinguish "needs hardening" from "rooted".
    #   v2 — pass_rate − (8h + 2m + 0.5l). Better, but the penalty
    #        still saturated for typical cloud VPSes: 4 high alone
    #        consumed 32 points on top of a base that was already at
    #        ~57 (a server with ~57% pass rate ⇒ 0). The classification
    #        pass that landed alongside this trim cuts most of the
    #        spurious highs, so the residual penalty here can be
    #        reduced too without losing signal on actually-bad hosts.
    #   v3 — pass_rate − (5h + 1.5m + 0.25l). Same shape, lower
    #        weights. A server with no failures still gets 100; a
    #        rooted box (10h + 20m + 30l = 87.5 penalty on top of a
    #        ~33% pass rate) still floors at 0.
    #
    # Final formula:
    #     base    = 100 × passed / scored_total     (the pass rate, 0..100)
    #     penalty = 5×high + 1.5×medium + 0.25×low  (additive, severity-weighted)
    #     score   = clamp(0, 100, base − penalty)
    #
    # info-category checks (see security_levels.sh) are excluded from
    # `scored_total`, so they don't dilute the pass rate in either
    # direction — a clean way to carry advisory findings in the report
    # without them distorting the number.
    #
    # Expected outcomes (all on a 50-check scored total):
    #   0 failures                   → 100 (Excellent)
    #   1 medium only                → 97  (Excellent)
    #   1 high only                  → 93  (Excellent)
    #   3 high only                  → 79  (Good)
    #   3 high + 6 medium + 3 low    → 53  (Needs work)
    #   7 high + 11 medium + 3 low (the typical fresh-VPS shape after
    #    the v3 classification trim drops 5 spurious highs to ≈2 high)
    #                                ≈ ~40 — distinguishable from
    #                                "actually broken"
    #   10 high + 20 medium + 30 low → 0   (Broken)

    if (( scored_total == 0 )); then
        echo 100
        return
    fi

    local passed_count=$(( scored_total - high_fail - medium_fail - low_fail ))
    (( passed_count < 0 )) && passed_count=0

    local base=$(( 100 * passed_count / scored_total ))

    # Penalty in 4× space so we don't lose the 0.25 weight on low.
    # penalty*4 = 20*high + 6*medium + 1*low  (= 5h + 1.5m + 0.25l ×4)
    local penalty_4x=$(( 20 * high_fail + 6 * medium_fail + low_fail ))
    local penalty=$(( penalty_4x / 4 ))

    local score=$(( base - penalty ))
    (( score < 0 )) && score=0
    (( score > 100 )) && score=100

    echo "$score"
}

# Get check statistics (only for scored checks)
get_check_stats() {
    local checks=$(state_get_checks)
    local installed=$(_detect_installed_components "$checks")

    local high=0
    local medium=0
    local low=0
    local passed=0
    local info_count=0

    while IFS= read -r check_json; do
        [[ -z "$check_json" ]] && continue

        local check_id status severity
        check_id=$(echo "$check_json" | jq -r '.id // empty')
        status=$(echo "$check_json" | jq -r '.status // empty')
        severity=$(echo "$check_json" | jq -r '.severity // "low"')

        [[ -z "$check_id" ]] && continue

        # Track info-category (not-scored) checks as a SEPARATE
        # dimension. Previously this branched off with `continue`,
        # excluding info-category checks from every other bucket —
        # which made the summary table's "Low: N" undercount by ~25
        # because most ergonomic SSH-option findings, history hygiene,
        # umask, etc. are classified info. The body filters purely on
        # `.severity`, so the summary needs the same semantics for the
        # two numbers to match. Score impact is unaffected: scoring
        # has its own _check_counts_in_score filter inside
        # calculate_score().
        if ! _check_counts_in_score "$check_id" "$installed"; then
            ((info_count++)) || true
            # no `continue` — still flow into the severity / passed
            # buckets below so the displayed count matches the body.
        fi

        if [[ "$status" == "passed" ]]; then
            ((passed++)) || true
        elif [[ "$status" == "failed" ]]; then
            case "$severity" in
                high|critical)
                    ((high++)) || true
                    ;;
                medium)
                    ((medium++)) || true
                    ;;
                low|info)
                    ((low++)) || true
                    ;;
            esac
        fi
    done <<< "$(echo "$checks" | jq -c '.[]')"

    echo "{\"high\": $high, \"medium\": $medium, \"low\": $low, \"passed\": $passed, \"info\": $info_count}"
}
