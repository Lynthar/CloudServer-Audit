#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# State management for tracking checks, fixes, and backups
# Copyright (c) 2024

# --- State File Paths ---

STATE_OK_FILE="${VPSSEC_STATE}/ok.json"
STATE_PLAN_FILE="${VPSSEC_STATE}/last_plan.json"
STATE_PROGRESS_FILE="${VPSSEC_STATE}/progress.json"
STATE_CHECKS_FILE="${VPSSEC_STATE}/checks.json"

# --- State Initialization ---

state_init() {
    mkdir -p "${VPSSEC_STATE}"

    chmod 700 "${VPSSEC_STATE}"

    # Locked so concurrent runs do not both seed ok.json.
    local lock_file="${VPSSEC_STATE}/.init.lock"
    (
        flock -n 200 || exit 0  # Skip if another process is initializing
        if [[ ! -f "$STATE_OK_FILE" ]]; then
            echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"
        fi
    ) 200>"$lock_file"

    # Fresh checks.json each run; the previous one is kept as .prev
    # so an interrupted run's partial results stay inspectable.
    if [[ -f "$STATE_CHECKS_FILE" ]]; then
        cp -p "$STATE_CHECKS_FILE" "${STATE_CHECKS_FILE}.prev" 2>/dev/null || true
    fi
    echo '[]' > "$STATE_CHECKS_FILE"
}

# --- Check State Management ---

# Append a check to state under a write lock. Invalid JSON is replaced by a
# synthetic "malformed check" record so the breakage shows up in the report.
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
            "$(i18n 'error.malformed_check_fix')" \
            "")
    fi

    (
        flock -x 200
        [[ -f "$STATE_CHECKS_FILE" ]] || echo '[]' > "$STATE_CHECKS_FILE"

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

# --- Fix State Management ---

# Record a completed fix (thread-safe with file locking)
state_mark_fix_complete() {
    local fix_id="$1"
    local timestamp
    timestamp=$(date -Iseconds)
    local lock_file="${VPSSEC_STATE}/.ok.lock"

    (
        flock -x 200
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

# --- Plan State Management ---

# Save execution plan. Atomic and checked: execute_plan re-reads this file,
# so a truncated or silently-failed write would execute a stale plan.
state_save_plan() {
    local plan_json="$1"
    write_file_atomic "$STATE_PLAN_FILE" "$plan_json" || return 1
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

# --- Progress Tracking (for interrupted operations) ---

# Save progress. Built via jq (escaped fields) and written atomically: a kill
# or full disk mid-write must not leave truncated JSON for the resume path.
state_save_progress() {
    local current_fix="$1"
    local total_fixes="$2"
    local completed_ids="$3"  # JSON array of completed fix IDs

    local progress_json
    progress_json=$(jq -n \
        --arg     current   "$current_fix" \
        --argjson total     "$total_fixes" \
        --argjson completed "$completed_ids" \
        --arg     ts        "$(date -Iseconds)" \
        '{current_fix: $current, total_fixes: $total, completed: $completed, timestamp: $ts}') \
        || { log_error "state_save_progress: could not build progress JSON"; return 1; }
    write_file_atomic "$STATE_PROGRESS_FILE" "$progress_json" || return 1
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

# --- Backup Management ---

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

# execute_plan assigns the returned path to VPSSEC_BACKUP_SESSION, so every
# backup_file call during the plan lands here and rollback restores it as one.
backup_create_session() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    echo "$backup_dir"
}

# Re-apply the mode recorded by backup_track_mode; a backup with no entry
# keeps whatever cp -p gave it. The path reaches awk through ENVIRON, never
# `-v` — awk expands escapes in -v, mangling any path with a backslash.
_backup_restore_mode() {
    local path="$1" manifest="$2"
    [[ -f "$manifest" ]] || return 0

    local mode
    mode=$(VPSSEC_MODE_PATH="$path" awk '
        BEGIN { want = ENVIRON["VPSSEC_MODE_PATH"] }
        { m = $1; sub(/^[0-7]+ /, ""); if ($0 == want) { print m; exit } }
    ' "$manifest" 2>/dev/null) || return 0
    # Anything awk printed is already a valid mode; only emptiness needs a guard.
    [[ -n "$mode" ]] || return 0

    if ! chmod "$mode" "$path" 2>/dev/null; then
        log_warn "Restored content but could not restore mode $mode on $path"
    fi
}

# Restore one backup session. 0 = all restored, 2 = partial, 1 = nothing;
# callers MUST distinguish all three. The numbered path checks below keep
# this from being a write-to-any-path primitive (see the design notes).
backup_restore() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    # Check 1: timestamp shape, so a crafted argument cannot select a
    # hand-placed sibling directory. Same regex as backup_cleanup.
    if [[ ! "$timestamp" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
        log_error "Refusing to restore: timestamp '$timestamp' does not match YYYYMMDD_HHMMSS"
        return 1
    fi

    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup not found: $timestamp"
        return 1
    fi

    log_info "Restoring from backup: $timestamp"

    # Resolved once, for the symlink-escape check on each found file.
    local backup_dir_real
    backup_dir_real=$(realpath "$backup_dir" 2>/dev/null) || {
        log_error "Cannot resolve backup directory: $backup_dir"
        return 1
    }

    local skipped=0
    local restored=0
    local modes_manifest="${backup_dir}/${VPSSEC_MODES_MANIFEST}"

    while IFS= read -r -d '' backup_file; do
        # Check 2a: source must not be a symlink — find -type f follows them,
        # so a symlink to an arbitrary host file would be matched.
        if [[ -L "$backup_file" ]]; then
            log_warn "Skipping symlinked backup entry: $backup_file"
            ((skipped++)) || true
            continue
        fi

        # Check 2b: catches a directory symlink farther up the path.
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

        # Check 3a: a symlinked parent could redirect cp elsewhere.
        if [[ -L "$original_dir" ]]; then
            log_warn "Skipping restore: parent directory is a symlink: $original_dir"
            ((skipped++)) || true
            continue
        fi

        # Check 3b: cp -p would dereference an existing symlink target.
        if [[ -L "$original_path" ]]; then
            log_warn "Skipping restore: target path is a symlink: $original_path"
            ((skipped++)) || true
            continue
        fi

        # Checked explicitly: errexit is off here, so a failing cp would
        # otherwise fall through and be counted as restored.
        if ! mkdir -p "$original_dir" || ! cp -p "$backup_file" "$original_path"; then
            log_error "Restore FAILED (copy error): $backup_file -> $original_path"
            ((skipped++)) || true
            continue
        fi
        # cp -p copied the backup's mode, which backup_file chmods to 600.
        _backup_restore_mode "$original_path" "$modes_manifest"
        log_info "Restored: $backup_file -> $original_path"
        ((restored++)) || true
    done < <(find "$backup_dir" -type f ! -name '.vpssec_created' ! -name '.vpssec_modes' -print0)

    # Files a fix CREATED have no prior version, so rollback must delete them.
    # Same symlink safety as restore: never delete through a symlinked path.
    local created_manifest="${backup_dir}/.vpssec_created"
    if [[ -f "$created_manifest" ]]; then
        local created_path created_parent
        while IFS= read -r created_path; do
            [[ -n "$created_path" ]] || continue
            [[ "$created_path" == /* ]] || continue   # absolute paths only
            [[ -e "$created_path" ]] || continue       # already gone
            created_parent=$(dirname "$created_path")
            if [[ -L "$created_parent" || -L "$created_path" ]]; then
                log_warn "Skipping delete of created file (symlink in path): $created_path"
                ((skipped++)) || true
                continue
            fi
            if [[ -f "$created_path" ]]; then
                if rm -f "$created_path"; then
                    log_info "Removed fix-created file on rollback: $created_path"
                    ((restored++)) || true
                else
                    # Counted, so the exit status reports the incomplete rollback.
                    log_error "Rollback could not remove fix-created file: $created_path"
                    ((skipped++)) || true
                fi
            fi
        done < "$created_manifest"
    fi

    # Counts go to the terminal, not just the log; restored == 0 is a failure.
    if (( restored == 0 )); then
        if (( skipped > 0 )); then
            log_error "Restore failed: 0 restored, ${skipped} skipped (see logs/vpssec.log)"
            print_error "$(i18n 'backup.restore_none_skipped' "skipped=${skipped}")"
        else
            log_error "Restore failed: backup '${timestamp}' contained no restorable files"
            print_error "$(i18n 'backup.restore_empty' "timestamp=${timestamp}")"
        fi
        return 1
    fi

    if (( skipped > 0 )); then
        log_warn "Restore complete with skips: ${restored} restored, ${skipped} skipped (see logs/vpssec.log)"
        print_warn "$(i18n 'backup.restore_partial' "restored=${restored}" "skipped=${skipped}")"
        return 2
    fi

    log_info "Restore complete: ${restored} files"
    print_info "$(i18n 'backup.restore_count' "restored=${restored}")"
    return 0
}

# Preview one backup. Same timestamp-shape gate as backup_restore, so an
# unvalidated argument cannot list arbitrary directories.
backup_list_contents() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    [[ "$timestamp" =~ ^[0-9]{8}_[0-9]{6}$ ]] || return 1

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
            # Underscore, matching what backup_create_session emits.
            if [[ -n "$timestamp" ]] && [[ "$backup_path" =~ ^${VPSSEC_BACKUPS}/[0-9]{8}_[0-9]{6}$ ]] && [[ -d "$backup_path" ]]; then
                rm -rf "$backup_path"
                log_info "Removed old backup: $timestamp"
            fi
        fi
    done
}

# --- Score Calculation ---

# --- Check Metrics: one jq reduction over checks.json, cached on
# (path, mtime, size). The scoring inclusion rules live in that jq
# program and nowhere else — see the design notes. ---

declare -gA VPSSEC_METRICS=()
_VPSSEC_METRICS_KEY=""
_VPSSEC_CATMAP_JSON=""

# Serialise CHECK_SCORE_CATEGORY into JSON once per process so jq can classify
# every check without a round-trip per id. Empty string = map not loaded.
_score_category_map_json() {
    if [[ -n "$_VPSSEC_CATMAP_JSON" ]]; then
        printf '%s' "$_VPSSEC_CATMAP_JSON"
        return 0
    fi
    declare -p CHECK_SCORE_CATEGORY >/dev/null 2>&1 || return 1
    local k
    _VPSSEC_CATMAP_JSON=$(
        for k in "${!CHECK_SCORE_CATEGORY[@]}"; do
            printf '%s\t%s\n' "$k" "${CHECK_SCORE_CATEGORY[$k]}"
        done | jq -Rn '[inputs | split("\t") | {key: .[0], value: .[1]}] | from_entries'
    ) || { _VPSSEC_CATMAP_JSON=""; return 1; }
    printf '%s' "$_VPSSEC_CATMAP_JSON"
}

# Cache key. mtime and size are each insufficient alone; together they hold
# because every state_add_check grows the file. Empty = never serve from cache.
_checks_fingerprint() {
    local file="$STATE_CHECKS_FILE"
    [[ -f "$file" ]] || { printf '%s|missing' "$file"; return 0; }
    local s
    s=$(stat -c '%Y:%s' "$file" 2>/dev/null) \
        || s=$(stat -f '%m:%z' "$file" 2>/dev/null) \
        || return 1
    printf '%s|%s' "$file" "$s"
}

_check_metrics_refresh() {
    local key
    key=$(_checks_fingerprint) || key=""

    if [[ -n "$key" && "$key" == "$_VPSSEC_METRICS_KEY" && ${#VPSSEC_METRICS[@]} -gt 0 ]]; then
        return 0
    fi

    local catmap default_cat
    if catmap=$(_score_category_map_json) && [[ -n "$catmap" ]]; then
        # Unlisted ids default to "info" — the fail-safe documented on
        # get_check_score_category (a forgotten classification must not
        # silently drag the score down).
        default_cat="info"
    else
        # security_levels.sh not loaded: mirror the historical fallback
        # in _check_counts_in_score, which treated every check as
        # "required" when get_check_score_category was unavailable.
        catmap="{}"
        default_cat="required"
    fi

    local strict="false"
    [[ "${VPSSEC_SECURITY_LEVEL:-standard}" == "strict" ]] && strict="true"

    local checks_file="$STATE_CHECKS_FILE"
    local metrics_out=""
    if [[ -f "$checks_file" ]]; then
        metrics_out=$(jq -r \
            --argjson catmap "$catmap" \
            --arg     default_cat "$default_cat" \
            --argjson strict "$strict" '
            def present($arr; $p):
              any($arr[]; ((.id // "") | startswith($p + "."))
                          and ((.id // "") != ($p + ".not_installed")));
            def category($catmap; $default_cat; $id): ($catmap[$id] // $default_cat);
            def scored($catmap; $default_cat; $installed; $strict; $id):
              category($catmap; $default_cat; $id) as $c
              | if   $c == "required" or $c == "recommended" then true
                elif $c == "conditional" then
                  ($id | split(".") | .[0]) as $m
                  | if   $m == "docker"      then $installed.docker
                    elif $m == "nginx"       then $installed.nginx
                    elif $m == "cloudflared" then $installed.cloudflared
                    else true end
                elif $c == "optional" then $strict
                elif $c == "info"     then false
                else true end;
            [ .[] | select(((.id // "") | length) > 0) ] as $all
            | { docker:      present($all; "docker"),
                nginx:       present($all; "nginx"),
                cloudflared: present($all; "cloudflared") } as $installed
            | reduce $all[] as $chk (
                {total:0, high:0, medium:0, low:0, passed:0, info:0,
                 scored_total:0, high_failed:0, medium_failed:0, low_failed:0};
                ($chk.id)                  as $id
                | ($chk.status   // "")    as $st
                | ($chk.severity // "low") as $sev
                | (scored($catmap; $default_cat; $installed; $strict; $id)) as $in
                | .total += 1
                # info = carried in the report but not scored. A separate
                # dimension: the check still falls into a severity bucket below.
                | (if $in then . else .info += 1 end)
                | (if   $st == "passed" then .passed += 1
                   elif $st == "failed" then
                          (if   $sev == "high" or $sev == "critical" then .high += 1
                           elif $sev == "medium"                     then .medium += 1
                           elif $sev == "low" or $sev == "info"      then .low += 1
                           else . end)
                   else . end)
                | (if $in then
                     .scored_total += 1
                     | (if $st == "failed" then
                          (if   $sev == "high" or $sev == "critical" then .high_failed += 1
                           elif $sev == "medium"                     then .medium_failed += 1
                           elif $sev == "low" or $sev == "info"      then .low_failed += 1
                           else . end)
                        else . end)
                   else . end)
              )
            | to_entries[] | "\(.key)=\(.value)"
        ' "$checks_file" 2>/dev/null) || metrics_out=""
    fi

    VPSSEC_METRICS=()
    local line k v
    while IFS='=' read -r k v; do
        [[ -n "$k" ]] && VPSSEC_METRICS["$k"]="$v"
    done <<< "$metrics_out"

    # A malformed/absent checks.json must still yield a complete metric set.
    for k in total high medium low passed info scored_total high_failed medium_failed low_failed; do
        [[ -n "${VPSSEC_METRICS[$k]:-}" ]] || VPSSEC_METRICS["$k"]=0
    done

    _VPSSEC_METRICS_KEY="$key"
}

# Read one metric by name (see the bucket list above).
check_metric() {
    _check_metrics_refresh
    echo "${VPSSEC_METRICS[$1]:-0}"
}

calculate_score() {
    _check_metrics_refresh
    local scored_total="${VPSSEC_METRICS[scored_total]:-0}"
    local high_fail="${VPSSEC_METRICS[high_failed]:-0}"
    local medium_fail="${VPSSEC_METRICS[medium_failed]:-0}"
    local low_fail="${VPSSEC_METRICS[low_failed]:-0}"

    # base = 100 x passed/scored_total; penalty = 5*high + 1.5*medium + 0.25*low;
    # score = clamp(0,100, base - penalty). Only comparable across runs with the
    # same module set -- score_is_partial() flags the rest. See the design notes.

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

# Summary statistics for the reports. Severity and score-category are
# orthogonal: `info` counts checks excluded from the score and deliberately
# overlaps the severity buckets. `scored_total` is the score's denominator.
get_check_stats() {
    _check_metrics_refresh
    printf '{"high": %d, "medium": %d, "low": %d, "passed": %d, "info": %d, "scored_total": %d, "total": %d}\n' \
        "${VPSSEC_METRICS[high]:-0}" \
        "${VPSSEC_METRICS[medium]:-0}" \
        "${VPSSEC_METRICS[low]:-0}" \
        "${VPSSEC_METRICS[passed]:-0}" \
        "${VPSSEC_METRICS[info]:-0}" \
        "${VPSSEC_METRICS[scored_total]:-0}" \
        "${VPSSEC_METRICS[total]:-0}"
}

# True when this run audited only part of the module set, so the score is not
# comparable with a full run. Both --include and --exclude shrink the denominator.
score_is_partial() {
    [[ -n "${VPSSEC_INCLUDE:-}" || -n "${VPSSEC_EXCLUDE:-}" ]]
}
