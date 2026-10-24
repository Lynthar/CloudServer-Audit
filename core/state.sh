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

    if [[ ! -f "$STATE_OK_FILE" ]]; then
        echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"
    fi

    # Fresh checks.json each run; the previous one is kept as .prev
    # so an interrupted run's partial results stay inspectable.
    if [[ -f "$STATE_CHECKS_FILE" ]]; then
        cp -p "$STATE_CHECKS_FILE" "${STATE_CHECKS_FILE}.prev" 2>/dev/null || true
    fi
    echo '[]' > "$STATE_CHECKS_FILE"
}

# --- Check State Management ---

# Append a check to state; returns 1 when the write fails.
# Invalid JSON (an empty string included: jq accepts it) is replaced by a
# synthetic "malformed check" record so the breakage shows up in the report.
state_add_check() {
    local check_json="$1"

    if [[ -z "$check_json" ]] || ! printf '%s' "$check_json" | jq empty 2>/dev/null; then
        log_error "state_add_check received malformed JSON (first 200 bytes): ${check_json:0:200}"
        local raw_preview="${check_json:0:500}"
        check_json=$(create_check_json \
            "_internal.malformed_check" \
            "_internal" \
            "medium" \
            "failed" \
            "$(i18n 'error.malformed_check')" \
            "$(i18n 'error.malformed_check_desc' "raw=$raw_preview")" \
            "$(i18n 'error.malformed_check_fix')" \
            "")
    fi

    # No lock: the run lock serializes writers. Writing from parallel jobs needs
    # one here first, or two appends read the same file and one is lost.
    [[ -f "$STATE_CHECKS_FILE" ]] || echo '[]' > "$STATE_CHECKS_FILE"

    local temp_file
    temp_file=$(mktemp "${STATE_CHECKS_FILE}.XXXXXX") || return 1

    # The check goes in on stdin, not --argjson: argv caps one string at
    # 128 KiB, and a check carrying a long host value would be dropped.
    if { cat "$STATE_CHECKS_FILE"; printf '%s' "$check_json"; } \
            | jq -s '.[0] + .[1:]' > "$temp_file" 2>/dev/null; then
        mv -f "$temp_file" "$STATE_CHECKS_FILE"
    else
        rm -f "$temp_file"
        return 1
    fi
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

# Record a completed fix. Always returns 0: the fix itself succeeded, and a
# record that could not be written is logged, not reported as a failed fix.
state_mark_fix_complete() {
    local fix_id="$1"
    local timestamp temp_file=""
    timestamp=$(date -Iseconds)

    [[ -f "$STATE_OK_FILE" ]] || echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"
    if temp_file=$(mktemp "${STATE_OK_FILE}.XXXXXX") \
        && jq --arg id "$fix_id" --arg ts "$timestamp" \
            '.completed_fixes += [{"id": $id, "timestamp": $ts}] | .last_run = $ts' \
            "$STATE_OK_FILE" > "$temp_file" 2>/dev/null \
        && mv -f "$temp_file" "$STATE_OK_FILE"; then
        log_info "Fix marked complete: $fix_id"
    else
        [[ -z "$temp_file" ]] || rm -f "$temp_file"
        log_warn "Could not record the fix in $STATE_OK_FILE: $fix_id"
    fi
}

# Record a finished audit pass for `status`: when, the score, and whether every
# module finished. Without it status showed "never" after any number of audits;
# last_run above is the last fix applied.
state_record_audit() {
    local score="$1" complete="$2"
    local timestamp
    timestamp=$(date -Iseconds)

    [[ -f "$STATE_OK_FILE" ]] || echo '{"completed_fixes": [], "last_run": null}' > "$STATE_OK_FILE"
    local temp_file
    temp_file=$(mktemp "${STATE_OK_FILE}.XXXXXX") || return 1
    if jq --arg ts "$timestamp" --argjson score "$score" --argjson complete "$complete" \
        '.last_audit = {timestamp: $ts, score: $score, complete: $complete}' \
        "$STATE_OK_FILE" > "$temp_file" 2>/dev/null; then
        mv -f "$temp_file" "$STATE_OK_FILE"
    else
        rm -f "$temp_file"
        return 1
    fi
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

# The plan's session path, for VPSSEC_BACKUP_SESSION: every backup_file of the
# plan lands there and rolls back as one. Not created here — backup_file does
# that on first use, so a plan that backed nothing up leaves no empty session.
backup_create_session() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    echo "${VPSSEC_BACKUPS}/${timestamp}"
}

# Re-apply the mode recorded by backup_track_mode; 1 when there is none to
# apply or chmod fails, and the file keeps the copy's 600. The path reaches awk
# through ENVIRON, never `-v` — awk expands escapes in -v, mangling backslashes.
_backup_restore_mode() {
    local path="$1" manifest="$2"
    [[ -f "$manifest" ]] || return 1

    local mode
    mode=$(VPSSEC_MODE_PATH="$path" awk '
        BEGIN { want = ENVIRON["VPSSEC_MODE_PATH"] }
        { m = $1; sub(/^[0-7]+ /, ""); if ($0 == want) { print m; exit } }
    ' "$manifest" 2>/dev/null) || return 1
    # Anything awk printed is already a valid mode; only emptiness needs a guard.
    [[ -n "$mode" ]] || return 1

    if ! chmod "$mode" "$path" 2>/dev/null; then
        log_warn "Restored content but could not restore mode $mode on $path"
        return 1
    fi
}

# What rolling back session dir $1 involves. Rollback acts on exactly these
# and its preview lists exactly these, so the two cannot disagree.
# The backed-up copies, NUL-terminated: not the manifests, not a partial copy.
_backup_session_copies() {
    # Check 2 of backup_restore: never add -L. Without it find neither yields a
    # symlink nor enters a symlinked directory, so a planted link is never restored.
    find "$1" -type f ! -name "$VPSSEC_CREATED_MANIFEST" ! -name "$VPSSEC_MODES_MANIFEST" \
        ! -name "${VPSSEC_PARTIAL_PREFIX}*" -print0
}

# Files a fix created that are still there, one per line: rollback deletes
# them (a symlinked one is refused and counted). Directories are listed apart.
_backup_session_created() {
    local manifest="$1/$VPSSEC_CREATED_MANIFEST" path
    [[ -f "$manifest" ]] || return 0
    while IFS= read -r path || [[ -n "$path" ]]; do
        [[ "$path" == /* && -e "$path" ]] || continue
        [[ -f "$path" || -L "$path" ]] && printf '%s\n' "$path"
    done < "$manifest"
    return 0
}

# Directories a fix created that are still there, recorded as "<dir>/" and
# printed without the slash, deepest first: rollback removes each left empty.
_backup_session_created_dirs() {
    local manifest="$1/$VPSSEC_CREATED_MANIFEST" path
    [[ -f "$manifest" ]] || return 0
    while IFS= read -r path || [[ -n "$path" ]]; do
        [[ "$path" == /*/ ]] || continue
        path="${path%/}"
        [[ -d "$path" || -L "$path" ]] && printf '%s\n' "$path"
    done < "$manifest" | LC_ALL=C sort -ru
    return 0
}

# Files whose mode was recorded but whose copy is gone, one per line: the
# session is damaged, and a rollback must say it could not restore them.
_backup_session_missing() {
    local backup_dir="$1" manifest="$1/$VPSSEC_MODES_MANIFEST" line path
    [[ -f "$manifest" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[0-7]+\ / ]] || continue
        path="${line#* }"
        [[ -e "${backup_dir}${path}" || -L "${backup_dir}${path}" ]] || printf '%s\n' "$path"
    done < "$manifest"
    return 0
}

# Restore one backup session. 0 = all restored, 2 = partial, 1 = nothing;
# callers MUST distinguish all three. The numbered path checks (Check 2 is the
# find in _backup_session_copies) keep this from writing to any path it is given.
backup_restore() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    # Check 1: timestamp shape, so a crafted argument cannot select a
    # hand-placed sibling directory.
    if [[ ! "$timestamp" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
        log_error "Refusing to restore: timestamp '$timestamp' does not match YYYYMMDD_HHMMSS"
        return 1
    fi

    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup not found: $timestamp"
        return 1
    fi

    log_info "Restoring from backup: $timestamp"

    local skipped=0
    local restored=0
    local mode_lost=0
    local modes_manifest="${backup_dir}/${VPSSEC_MODES_MANIFEST}"

    local missing_path
    while IFS= read -r missing_path; do
        log_error "Restore FAILED (backup copy missing): $missing_path"
        ((skipped++)) || true
    done < <(_backup_session_missing "$backup_dir")

    # backup_file writes this manifest with the session: without it, files the
    # plan's fixes created cannot be found, so they stay and the restore is partial.
    if [[ ! -f "${backup_dir}/${VPSSEC_CREATED_MANIFEST}" ]]; then
        log_error "Restore incomplete: ${backup_dir}/${VPSSEC_CREATED_MANIFEST} is missing; files created by this session's fixes are left in place"
        ((skipped++)) || true
    fi

    while IFS= read -r -d '' backup_file; do
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
        # otherwise fall through and be counted as restored. -T: a directory
        # now at the path fails the copy instead of receiving the file.
        if ! mkdir -p "$original_dir" || ! cp -pT "$backup_file" "$original_path"; then
            log_error "Restore FAILED (copy error): $backup_file -> $original_path"
            ((skipped++)) || true
            continue
        fi
        # cp -p copied the backup's mode, which backup_file chmods to 600.
        if ! _backup_restore_mode "$original_path" "$modes_manifest"; then
            log_error "Restored content without its original mode: $original_path"
            ((mode_lost++)) || true
        fi
        log_info "Restored: $backup_file -> $original_path"
        ((restored++)) || true
    done < <(_backup_session_copies "$backup_dir")

    # Files a fix CREATED have no prior version, so rollback must delete them.
    # Same symlink safety as restore: never delete through a symlinked path.
    local created_path created_parent
    while IFS= read -r created_path; do
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
    done < <(_backup_session_created "$backup_dir")

    # After the files, so a directory they emptied goes too. rmdir removes only
    # an empty one: whatever an operator has put there since keeps it.
    local created_dir dirs_removed=0
    while IFS= read -r created_dir; do
        if [[ -L "$created_dir" ]]; then
            log_warn "Skipping removal of created directory (now a symlink): $created_dir"
            ((skipped++)) || true
        elif rmdir -- "$created_dir" 2>/dev/null; then
            log_info "Removed fix-created directory on rollback: $created_dir"
            ((dirs_removed++)) || true
        else
            log_info "Kept fix-created directory, not empty: $created_dir"
        fi
    done < <(_backup_session_created_dirs "$backup_dir")

    # Counts go to the terminal, not just the log; nothing undone is a failure.
    if (( restored == 0 && dirs_removed == 0 )); then
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
    fi
    if (( mode_lost > 0 )); then
        print_warn "$(i18n 'backup.restore_mode_lost' "count=${mode_lost}")"
    fi
    (( skipped > 0 || mode_lost > 0 )) && return 2

    log_info "Restore complete: ${restored} files, ${dirs_removed} directories removed"
    print_info "$(i18n 'backup.restore_count' "restored=${restored}")"
    return 0
}

# Preview one backup: "restore", "delete", "rmdir" and "missing" lines, from the
# same lists backup_restore acts on. Same timestamp-shape gate as backup_restore,
# so an unvalidated argument cannot list arbitrary dirs.
backup_list_contents() {
    local timestamp="$1"
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    [[ "$timestamp" =~ ^[0-9]{8}_[0-9]{6}$ ]] || return 1
    [[ -d "$backup_dir" ]] || return 0

    local f
    while IFS= read -r -d '' f; do
        printf 'restore /%s\n' "${f#"$backup_dir"/}"
    done < <(_backup_session_copies "$backup_dir")
    _backup_session_created "$backup_dir" | sed 's/^/delete /'
    _backup_session_created_dirs "$backup_dir" | sed 's/^/rmdir /'
    _backup_session_missing "$backup_dir" | sed 's/^/missing /'
}

# --- Score Calculation ---

# --- Check Metrics: one jq reduction over checks.json, cached on
# (path, mtime, size). The scoring and bucketing rules live in _VPSSEC_JQ_DEFS
# and nowhere else: two copies once disagreed on where info checks belong. ---

declare -gA VPSSEC_METRICS=()
_VPSSEC_METRICS_KEY=""

# CHECK_SCORE_CATEGORY as one JSON object, so jq can classify every check
# without a round-trip per id. Fails when the map is not loaded.
_score_category_map_json() {
    declare -p CHECK_SCORE_CATEGORY >/dev/null 2>&1 || return 1
    local k
    for k in "${!CHECK_SCORE_CATEGORY[@]}"; do
        printf '%s\t%s\n' "$k" "${CHECK_SCORE_CATEGORY[$k]}"
    done | jq -Rn '[inputs | split("\t") | {key: .[0], value: .[1]}] | from_entries'
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

# jq definitions every count and every report shares. bucket: the one rule for
# which list a check lands in — passed, or the severity of anything else, info
# and unknown counting as low. scored: whether the check moves the score.
_VPSSEC_JQ_DEFS='
def bucket:
  if .status == "passed" then "passed"
  elif .severity == "high" or .severity == "critical" then "high"
  elif .severity == "medium" then "medium"
  else "low" end;
def present($arr; $p):
  any($arr[]; ((.id // "") | startswith($p + "."))
              and ((.id // "") != ($p + ".not_installed")));
def installed($all):
  { docker:      present($all; "docker"),
    nginx:       present($all; "nginx"),
    cloudflared: present($all; "cloudflared") };
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
'

# The inputs the scoring defs take, as globals _SCORE_CATMAP, _SCORE_DEFAULT_CAT
# and _SCORE_STRICT (no fork). Read once per jq program that scores.
_score_context() {
    _SCORE_CATMAP=$(_score_category_map_json) || return 1
    # Unlisted ids score as info: a check nobody classified must not
    # drag the score down until it is deliberately promoted.
    _SCORE_DEFAULT_CAT="info"
    _SCORE_STRICT="false"
    [[ "${VPSSEC_SECURITY_LEVEL:-standard}" == "strict" ]] && _SCORE_STRICT="true"
    return 0
}

# checks.json with each check carrying `scored`, for the reports.
checks_with_scoring() {
    _score_context
    state_get_checks | jq \
        --argjson catmap "$_SCORE_CATMAP" \
        --arg     default_cat "$_SCORE_DEFAULT_CAT" \
        --argjson strict "$_SCORE_STRICT" \
        "$_VPSSEC_JQ_DEFS"'
        installed(.) as $installed
        | map(. + {scored: scored($catmap; $default_cat; $installed; $strict; (.id // ""))})
    '
}

_check_metrics_refresh() {
    local key
    key=$(_checks_fingerprint) || key=""

    if [[ -n "$key" && "$key" == "$_VPSSEC_METRICS_KEY" && ${#VPSSEC_METRICS[@]} -gt 0 ]]; then
        return 0
    fi

    _score_context

    local checks_file="$STATE_CHECKS_FILE"
    local metrics_out=""
    if [[ -f "$checks_file" ]]; then
        metrics_out=$(jq -r \
            --argjson catmap "$_SCORE_CATMAP" \
            --arg     default_cat "$_SCORE_DEFAULT_CAT" \
            --argjson strict "$_SCORE_STRICT" "$_VPSSEC_JQ_DEFS"'
            [ .[] | select(((.id // "") | length) > 0) ] as $all
            | installed($all) as $installed
            | reduce $all[] as $chk (
                {total:0, high:0, medium:0, low:0, passed:0, info:0,
                 scored_total:0, high_failed:0, medium_failed:0, low_failed:0};
                ($chk | bucket) as $b
                | (scored($catmap; $default_cat; $installed; $strict; $chk.id)) as $in
                | .total += 1
                # info = carried in the report but not scored. A separate
                # dimension: the check still falls into a severity bucket below.
                | (if $in then . else .info += 1 end)
                | .[$b] += 1
                | (if $in then
                     .scored_total += 1
                     | (if $b == "passed" then . else .[$b + "_failed"] += 1 end)
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

calculate_score() {
    _check_metrics_refresh
    local scored_total="${VPSSEC_METRICS[scored_total]:-0}"
    local high_fail="${VPSSEC_METRICS[high_failed]:-0}"
    local medium_fail="${VPSSEC_METRICS[medium_failed]:-0}"
    local low_fail="${VPSSEC_METRICS[low_failed]:-0}"

    # base = 100 x passed/scored_total; penalty = 5*high + 1.5*medium + 0.25*low;
    # score = clamp(0,100, base - penalty). Only comparable across runs with the
    # same module set -- score_is_partial() flags the rest.

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
