#!/usr/bin/env bash
# Scheduling module: cron and at job inventory plus anomaly detection.
# Looks for network fetches piped to a shell; filesystem.sh greps the same
# files for its own pattern list.

# --- Helpers ---

# Every cron table vpssec reads, one path per line: the system crontab,
# /etc/cron.d, and the per-user spool (its directory differs by distro family).
_sched_cron_files() {
    local f spool
    [[ -f /etc/crontab ]] && printf '%s\n' /etc/crontab
    for f in /etc/cron.d/*; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "$f"
    done
    spool=$(cron_spool_dir)
    for f in "$spool"/*; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "$f"
    done
}

# A network fetch piped into a shell: the canonical supply-chain / persistence
# trigger. Matched against the entry only, never its file name.
_SCHED_FETCH_TO_SHELL='(curl|wget|fetch|http_proxy)[^|]*\|[[:space:]]*(sh|bash|zsh|ash|dash)([[:space:]]|$)'

# "<file>:<line>" of every active entry that pipes a fetch into a shell. Never
# the entry itself: cron lines carry tokens (Authorization headers, URL
# userinfo), and this output lands in every report format.
_sched_find_internet_fetch_in_cron() {
    local f n
    while IFS= read -r f; do
        while IFS= read -r n; do
            printf '%s:%s\n' "$f" "$n"
        done < <(grep -nE "$_SCHED_FETCH_TO_SHELL" "$f" 2>/dev/null \
                     | grep -vE '^[0-9]+:[[:space:]]*#' | cut -d: -f1)
    done < <(_sched_cron_files)
}

# Return at-job IDs (one per line). `atq` columns: id  date  queue  user
_sched_list_at_jobs() {
    command -v atq >/dev/null 2>&1 || return 0
    atq 2>/dev/null | awk '{print $1}'
}

# --- Audit ---

scheduling_audit() {
    local module="scheduling"

    print_item "$(i18n 'scheduling.check_at_jobs')"
    _sched_audit_at_jobs

    print_item "$(i18n 'scheduling.check_cron_internet_fetch')"
    _sched_audit_cron_anomalies
}

_sched_audit_at_jobs() {
    if ! command -v atq >/dev/null 2>&1; then
        # at not installed → silent pass (the typical state)
        return
    fi

    local jobs
    jobs=$(_sched_list_at_jobs)

    if [[ -n "$jobs" ]]; then
        local count
        count=$(echo "$jobs" | wc -l)
        check_emit "scheduling.at_jobs_present" low failed \
            title="$(i18n 'scheduling.at_jobs_present' "count=$count")" \
            desc="$(i18n 'scheduling.at_jobs_present_desc' "list=$(echo "$jobs" | tr '\n' ' ')")" \
            suggestion="$(i18n 'scheduling.at_jobs_present_suggestion')"
        print_severity "low" "$(i18n 'scheduling.at_jobs_present' "count=$count")"
    else
        check_emit "scheduling.no_at_jobs" low passed
        print_ok "$(i18n 'scheduling.no_at_jobs')"
    fi
}

_sched_audit_cron_anomalies() {
    local hits
    hits=$(_sched_find_internet_fetch_in_cron)

    if [[ -n "$hits" ]]; then
        local count
        count=$(echo "$hits" | wc -l)
        check_emit "scheduling.cron_fetches_internet" low failed \
            title="$(i18n 'scheduling.cron_fetches_internet' "count=$count")" \
            desc="$(i18n 'scheduling.cron_fetches_internet_desc' "list=${hits//$'\n'/; }")" \
            suggestion="$(i18n 'scheduling.cron_fetches_internet_suggestion')"
        print_severity "low" "$(i18n 'scheduling.cron_fetches_internet' "count=$count")"
    else
        check_emit "scheduling.cron_clean" low passed
        print_ok "$(i18n 'scheduling.cron_clean')"
    fi
}

# --- Fix Functions — alert-only. ---

scheduling_fix() {
    local fix_id="$1"
    log_error "scheduling module has no automated fixes (fix_id=$fix_id)"
    return 1
}
