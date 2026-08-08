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
#
# Exit status (callers MUST distinguish these — this used to be an
# unconditional `return 0`, so a rollback that restored nothing, or
# skipped every entry on a symlink check, still printed a green
# "restored" to the user):
#   0 — every entry restored, nothing skipped
#   2 — partial: some entries restored, some skipped
#   1 — nothing restored (empty backup dir, or every entry skipped)
# Counts are also written to stdout via print_*, not only to the log.
# Re-apply the mode recorded by backup_track_mode. A backup directory made
# before this manifest existed simply has no entry, so the file keeps
# whatever cp -p gave it — restoring content without the mode is still
# better than refusing to restore.
#
# The path reaches awk through ENVIRON, never `-v`: awk expands escape
# sequences in a -v assignment, so a path containing a backslash would
# arrive mangled and match nothing, silently skipping the chmod.
_backup_restore_mode() {
    local path="$1" manifest="$2"
    [[ -f "$manifest" ]] || return 0

    local mode
    mode=$(VPSSEC_MODE_PATH="$path" awk '
        BEGIN { want = ENVIRON["VPSSEC_MODE_PATH"] }
        { m = $1; sub(/^[0-7]+ /, ""); if ($0 == want) { print m; exit } }
    ' "$manifest" 2>/dev/null) || return 0
    # Emptiness is the only case to guard: the awk above matches a line only
    # when its first field is octal (that is what the sub() strips before
    # comparing the path), so anything it prints is already a valid mode.
    [[ -n "$mode" ]] || return 0

    if ! chmod "$mode" "$path" 2>/dev/null; then
        log_warn "Restored content but could not restore mode $mode on $path"
    fi
}

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
    local modes_manifest="${backup_dir}/${VPSSEC_MODES_MANIFEST}"

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
        # cp -p copies the mode of the BACKUP copy, which backup_file
        # deliberately chmods to 600. Put the file's own mode back.
        _backup_restore_mode "$original_path" "$modes_manifest"
        log_info "Restored: $backup_file -> $original_path"
        ((restored++)) || true
    done < <(find "$backup_dir" -type f ! -name '.vpssec_created' ! -name '.vpssec_modes' -print0)

    # Delete files that fixes CREATED during this plan (they had no prior
    # version, so restoring is not enough — the file must be removed). Paths are
    # recorded by backup_track_created. Apply the same symlink-safety as restore:
    # never delete through a symlinked target or parent, and only remove a
    # regular file that still exists.
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
            if [[ -f "$created_path" ]] && rm -f "$created_path"; then
                log_info "Removed fix-created file on rollback: $created_path"
                ((restored++)) || true
            fi
        done < "$created_manifest"
    fi

    # Surface the counts to the TERMINAL, not just the log, and let the
    # exit status carry the outcome. A rollback that restored nothing is
    # a failure from the operator's point of view — they asked for their
    # config back and did not get it — so it must not read as success.
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

# Scoring inclusion rules live in the jq program inside
# _check_metrics_refresh below — a single implementation shared by the
# score and the summary statistics. There used to be two bash copies of
# this walk (calculate_score and get_check_stats), and they had already
# drifted apart on how info-category checks were bucketed.
#
# The rules, for reference:
#   required | recommended  — always scored
#   conditional             — scored only if the parent component
#                             (docker / nginx / cloudflared) is present,
#                             detected from the presence of any
#                             <module>.* check other than
#                             <module>.not_installed
#   optional                — scored only under --strict
#                             (VPSSEC_SECURITY_LEVEL=strict): weak SSH
#                             algorithms, weak SGID, nginx DoS
#                             hardening, ... are shown but do not move
#                             the score by default
#   info                    — never scored
#   unlisted id             — treated as info (fail-safe: a forgotten
#                             classification must not silently lower
#                             the score)

# ==============================================================================
# Check Metrics — one jq reduction, memoised
# ==============================================================================
#
# Every number the score / summary / report layers need comes from ONE
# jq pass over checks.json, cached on (path, mtime, size).
#
# Why this exists: calculate_score() and get_check_stats() used to walk
# the array in bash and spawn three `jq -r` calls PER CHECK just to pull
# .id / .status / .severity. report_generate_json, report_generate_markdown
# and report_print_summary each call BOTH functions, so one report re-parsed
# the same immutable data six times — ~1600 jq process creations on an
# 89-check host, which measured as several times more wall-clock than the
# scan itself. The two public functions below are now thin readers over
# this cache; their outputs are unchanged.
#
# Keeping the classification logic in jq (rather than calling the bash
# helpers per check) also removes the per-check `echo | jq -r '.docker'`
# inside _check_counts_in_score's `conditional` branch.

declare -gA VPSSEC_METRICS=()
_VPSSEC_METRICS_KEY=""
_VPSSEC_CATMAP_JSON=""

# Serialise CHECK_SCORE_CATEGORY (core/security_levels.sh) into a JSON
# object once per process so jq can classify every check without a
# round-trip per id. Returns an empty string when the map is not loaded
# — the caller then falls back to the historical "unlisted = required"
# default that _check_counts_in_score used in that situation.
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

# Cache key for checks.json. Size alone is not enough (state_init
# truncates back to "[]"), mtime alone is not enough (1s granularity);
# together they are, because every state_add_check grows the file.
# An empty key means "cannot fingerprint" -> never serve from cache.
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
                # info == "carried in the report but not scored". Tracked as a
                # SEPARATE dimension: the check still flows into the severity /
                # passed buckets below so the summary counts match the body,
                # which filters purely on .severity.
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

    # Defensive zero-fill: a malformed/absent checks.json must yield a
    # complete metric set rather than "unbound variable" downstream.
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
    #
    # KNOWN LIMITATION — the score is only comparable across runs with
    # the SAME module set. `base` is a rate (scales with scored_total)
    # but `penalty` is absolute (does not), so on a small subset the
    # penalty eats a proportionally larger share; and when every scored
    # check in the subset fails, base is 0 and the score floors at 0
    # regardless of how mild the findings are. `vpssec audit
    # --include=ufw` on a host with two medium findings therefore reads
    # "0/100" — technically correct for that denominator, badly
    # misleading as an absolute verdict.
    #
    # Deliberately NOT fixed by normalising the penalty: that would
    # move every existing host's score and invalidate the expected
    # outcomes above (and the README examples / tests that pin them).
    # Instead the presentation layer labels a filtered run as a PARTIAL
    # score and prints scored_total alongside it — see
    # score_is_partial() below and report_print_summary().

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

# Summary statistics for the terminal / Markdown / JSON reports.
#
# Severity and score-category are ORTHOGONAL dimensions here:
#   - high/medium/low/passed count every check by `.severity`, so the
#     summary line matches the body listing (which filters purely on
#     severity). Info-category checks are included.
#   - `info` counts checks EXCLUDED from the score (info category, or a
#     conditional check whose component isn't installed). It overlaps
#     the buckets above on purpose: it answers "how many of these are
#     advisory only", not "which bucket do they live in".
#   - `scored_total` is the denominator calculate_score() actually used.
#     Exposed so a reader can tell a 40/100 computed over 60 checks
#     from one computed over 4.
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

# True when this run only audited part of the module set, so the score
# is not comparable with a full-run score (see the KNOWN LIMITATION note
# in calculate_score). Both filters count: --exclude shrinks the
# denominator exactly the same way --include does.
score_is_partial() {
    [[ -n "${VPSSEC_INCLUDE:-}" || -n "${VPSSEC_EXCLUDE:-}" ]]
}
