#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Backup template module - generates backup configurations
# Copyright (c) 2024

# --- Backup Configuration ---

BACKUP_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/backup"
BACKUP_CRON_ROOT="${BACKUP_CRON_ROOT:-/etc}"

# The backup tools recognised, by command name: installed, named in a cron
# line or in a timer's name.
declare -ga BACKUP_TOOLS=(restic borg borgmatic rclone rsnapshot)
_BACKUP_TOOL_ALT=$(IFS='|'; echo "${BACKUP_TOOLS[*]}")

# A backup tool run from a schedule line, as a whole word. A bare "backup"
# matched dpkg's own database backup (cron.daily/dpkg, dpkg-db-backup.timer),
# present on every Debian and Ubuntu host.
BACKUP_TOOL_RE="(^|[^[:alnum:]_-])(${_BACKUP_TOOL_ALT})([^[:alnum:]_-]|\$)"

# --- Backup Helper Functions ---

# root's crontab and the system cron locations, comment lines dropped (Debian's
# crontab template talks about backups). Captured first: grep -q closing the
# pipe early would fail the producer under pipefail.
_backup_check_cron_job() {
    local c="$BACKUP_CRON_ROOT" lines
    lines=$({
        crontab -l 2>/dev/null
        grep -rhs '' "$c/crontab" "$c/cron.d" "$c/cron.daily" "$c/cron.weekly" "$c/cron.monthly"
    } | grep -v '^[[:space:]]*#') || true
    grep -qE "$BACKUP_TOOL_RE" <<<"$lines"
}

# Active timers named after a backup tool, or "backup" as vpssec's own
# template names it, one per line; dpkg-db-backup.timer backs up dpkg's
# database only.
_backup_timers() {
    local timers
    timers=$(systemctl list-timers --no-legend 2>/dev/null \
        | grep -oE '[^[:space:]]+[.]timer' | grep -vx 'dpkg-db-backup[.]timer') || true
    grep -iE "(${_BACKUP_TOOL_ALT}|backup)" <<<"$timers" || true
}

# The unit timer $1 starts, when its last run failed. Nothing when it
# succeeded, has not run yet (systemd reports "success" then) or systemd
# cannot say: only a failure systemd reports counts as one.
_backup_timer_failed_unit() {
    local unit result
    unit=$(systemctl show -p Unit --value -- "$1" 2>/dev/null) || return 0
    [[ -n "$unit" ]] || return 0
    result=$(systemctl show -p Result --value -- "$unit" 2>/dev/null) || return 0
    if [[ -n "$result" && "$result" != success ]]; then
        echo "$unit"
    fi
}

# The BACKUP_TOOLS installed here, one per line. The tools check and the flow
# gate both read it, so the backup checks cannot contradict each other.
_backup_installed_tools() {
    local tool
    for tool in "${BACKUP_TOOLS[@]}"; do
        if check_command "$tool"; then
            echo "$tool"
        fi
    done
}

# --- Backup Audit ---

backup_audit() {
    local module="backup"
    local tools
    tools=$(_backup_installed_tools)

    # Check for backup tools
    print_item "$(i18n 'backup.check_tools')"
    _backup_audit_tools "$tools"

    # Only meaningful once a tool is installed: otherwise a stray cron line
    # containing "backup" emits a pass next to "no backup tools".
    if [[ -n "$tools" ]]; then
        print_item "$(i18n 'backup.check_scheduled')"
        _backup_audit_scheduled

        print_item "$(i18n 'backup.check_critical_paths')"
        _backup_audit_critical_paths
    fi
}

# $1: what _backup_installed_tools printed.
_backup_audit_tools() {
    local tools="$1" tool

    if [[ -z "$tools" ]]; then
        check_emit "backup.no_tools" low failed \
            desc="$(i18n 'backup.no_tools_desc' "tools=${BACKUP_TOOLS[*]}")" \
            suggestion="$(i18n 'backup.fix_install_tool')" \
            fix="backup.generate_templates"
        print_severity "low" "$(i18n 'backup.no_tools')"
        return 0
    fi

    while IFS= read -r tool; do
        print_ok "$(i18n 'backup.tool_installed' "tool=$tool")"
    done <<<"$tools"
    check_emit "backup.tools_installed" low passed \
        title="$(i18n 'backup.tools_count' "count=$(count_lines "$tools")")"
}

_backup_audit_scheduled() {
    local scheduled=0 timer unit failing=()

    if _backup_check_cron_job; then
        ((scheduled++)) || true
        print_ok "$(i18n 'backup.cron_found')"
    fi

    # A timer whose backup failed last time is no working schedule, and
    # "configured" beside it would be a false green.
    while IFS= read -r timer; do
        [[ -n "$timer" ]] || continue
        unit=$(_backup_timer_failed_unit "$timer")
        if [[ -n "$unit" ]]; then
            failing+=("$unit")
        else
            ((scheduled++)) || true
            print_ok "$(i18n 'backup.timer_found')"
        fi
    done <<<"$(_backup_timers)"

    if ((${#failing[@]} > 0)); then
        local journal="journalctl -n 50"
        for unit in "${failing[@]}"; do journal+=" -u $unit"; done
        check_emit "backup.schedule_failing" low failed \
            desc="$(i18n 'backup.schedule_failing_desc' "units=${failing[*]}")" \
            suggestion="$(i18n 'backup.fix_schedule_failing' "cmd=$journal")"
        print_severity "low" "$(i18n 'backup.schedule_failing')"
    fi

    if ((scheduled > 0)); then
        check_emit "backup.scheduled" low passed \
            title="$(i18n 'backup.schedule_configured')"
    elif ((${#failing[@]} == 0)); then
        check_emit "backup.no_schedule" low failed \
            title="$(i18n 'backup.no_scheduled')" \
            desc="$(i18n 'backup.no_scheduled_desc')" \
            suggestion="$(i18n 'backup.fix_setup_schedule')" \
            fix="backup.generate_templates"
        print_severity "low" "$(i18n 'backup.no_scheduled')"
    fi
}

_backup_audit_critical_paths() {
    local critical_paths=(
        "/etc"
        "/home"
        "/var/www"
        "/var/lib/docker/volumes"
        "/opt"
    )

    local existing=()
    for path in "${critical_paths[@]}"; do
        if [[ -d "$path" ]]; then
            existing+=("$path")
        fi
    done

    local paths_list="${existing[*]}"
    check_emit "backup.critical_paths" low passed \
        title="$(i18n 'backup.paths_identified')" \
        desc="$(i18n 'backup.paths_list' "paths=$paths_list")"
    print_ok "$(i18n 'backup.critical_paths' "paths=$paths_list")"
}

# --- Backup Fix Functions ---

backup_fix() {
    local fix_id="$1"

    case "$fix_id" in
        backup.generate_templates)
            _backup_fix_generate_templates
            ;;
        *)
            log_warn "Backup fix not implemented: $fix_id"
            return 1
            ;;
    esac
}

_backup_fix_generate_templates() {
    print_info "$(i18n 'backup.generating_templates')"

    # Each generator's status used to be discarded, so a templates tree that
    # could not be written still ended in "backup templates generated" and a
    # fix the engine recorded as complete.
    _backup_generate_restic_template || return 1
    _backup_generate_borg_template || return 1
    _backup_generate_systemd_template || return 1

    print_ok "$(i18n 'backup.templates_generated' "path=$BACKUP_TEMPLATES_DIR")"
    return 0
}

_backup_generate_restic_template() {
    # 700 rather than +x (which yields 755): the backup script holds
    # credentials (repo URL, possibly S3 keys inline if the user adds
    # them) and is not something other users need to read or execute.
    write_template "$BACKUP_TEMPLATES_DIR/restic-backup.sh" 700 <<'EOF' || return 1
#!/bin/bash
# Restic Backup Script - Generated by vpssec
# Configure and adapt for your needs

set -euo pipefail

# Configuration
export RESTIC_REPOSITORY="s3:s3.amazonaws.com/your-bucket/restic"
# Or for local: export RESTIC_REPOSITORY="/mnt/backup/restic"
# Or for B2: export RESTIC_REPOSITORY="b2:bucket-name:restic"

export RESTIC_PASSWORD_FILE="/root/.restic-password"
# Before running: create that file with your passphrase and lock it
# down — any user who can read this file can decrypt every backup:
#   umask 077
#   printf '%s\n' 'your-passphrase' > /root/.restic-password
#   chmod 600 /root/.restic-password
# Do NOT replace RESTIC_PASSWORD_FILE with RESTIC_PASSWORD="..."
# inline: if this script ever loses its 600 mode the password leaks
# with it.

# AWS credentials (if using S3)
# export AWS_ACCESS_KEY_ID="your-key"
# export AWS_SECRET_ACCESS_KEY="your-secret"

# Paths to backup
BACKUP_PATHS=(
    "/etc"
    "/home"
    "/var/www"
    "/opt"
)

# Exclude patterns
EXCLUDE_PATTERNS=(
    "*.tmp"
    "*.log"
    "*.cache"
    ".cache"
    "node_modules"
    "__pycache__"
    "*.pyc"
)

# Retention policy
KEEP_LAST=7
KEEP_DAILY=7
KEEP_WEEKLY=4
KEEP_MONTHLY=12
KEEP_YEARLY=3

# Build exclude arguments as array (safe, no eval needed)
EXCLUDE_ARGS=()
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    EXCLUDE_ARGS+=("--exclude" "$pattern")
done

# Log file
LOG_FILE="/var/log/restic-backup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Initialize repository if needed
if ! restic snapshots &>/dev/null; then
    log "Initializing repository..."
    restic init
fi

# Run backup (using array expansion - safe, no eval)
log "Starting backup..."
restic backup "${BACKUP_PATHS[@]}" "${EXCLUDE_ARGS[@]}" --verbose 2>&1 | tee -a "$LOG_FILE"

# Prune old snapshots
log "Pruning old snapshots..."
restic forget \
    --keep-last "$KEEP_LAST" \
    --keep-daily "$KEEP_DAILY" \
    --keep-weekly "$KEEP_WEEKLY" \
    --keep-monthly "$KEEP_MONTHLY" \
    --keep-yearly "$KEEP_YEARLY" \
    --prune 2>&1 | tee -a "$LOG_FILE"

# Check repository integrity (weekly)
if [[ $(date +%u) -eq 7 ]]; then
    log "Running integrity check..."
    restic check 2>&1 | tee -a "$LOG_FILE"
fi

log "Backup completed successfully"
EOF

}

_backup_generate_borg_template() {
    # See restic template above for rationale on 700 vs +x.
    write_template "$BACKUP_TEMPLATES_DIR/borg-backup.sh" 700 <<'EOF' || return 1
#!/bin/bash
# Borg Backup Script - Generated by vpssec
# Configure and adapt for your needs

set -euo pipefail

# Configuration
export BORG_REPO="/mnt/backup/borg"
# Or for remote: export BORG_REPO="user@backup-server:/path/to/repo"

export BORG_PASSPHRASE="CHANGE-ME-BEFORE-USE"   # required: pick a real passphrase and store it OUTSIDE this host too
# Or use: export BORG_PASSCOMMAND="cat /root/.borg-passphrase"

# Paths to backup
BACKUP_PATHS=(
    "/etc"
    "/home"
    "/var/www"
    "/opt"
)

# Exclude patterns
EXCLUDE_PATTERNS=(
    "*.tmp"
    "*.log"
    "*.cache"
    ".cache"
    "node_modules"
    "__pycache__"
)

# Retention policy
KEEP_LAST=7
KEEP_DAILY=7
KEEP_WEEKLY=4
KEEP_MONTHLY=12

# Log file
LOG_FILE="/var/log/borg-backup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Build exclude arguments as array (safe, no eval needed)
EXCLUDE_ARGS=()
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    EXCLUDE_ARGS+=("--exclude" "$pattern")
done

# Initialize repository if needed
if ! borg info "$BORG_REPO" &>/dev/null; then
    log "Initializing repository..."
    borg init --encryption=repokey "$BORG_REPO"
fi

# Create archive name with timestamp
ARCHIVE_NAME="$(hostname)-$(date +%Y%m%d-%H%M%S)"

# Run backup (using array expansion - safe, no eval)
log "Starting backup: $ARCHIVE_NAME"
borg create \
    --verbose \
    --stats \
    --compression lz4 \
    "${EXCLUDE_ARGS[@]}" \
    "$BORG_REPO::$ARCHIVE_NAME" \
    "${BACKUP_PATHS[@]}" 2>&1 | tee -a "$LOG_FILE"

# Prune old archives
log "Pruning old archives..."
borg prune \
    --keep-last "$KEEP_LAST" \
    --keep-daily "$KEEP_DAILY" \
    --keep-weekly "$KEEP_WEEKLY" \
    --keep-monthly "$KEEP_MONTHLY" \
    "$BORG_REPO" 2>&1 | tee -a "$LOG_FILE"

# Compact repository
borg compact "$BORG_REPO" 2>&1 | tee -a "$LOG_FILE"

log "Backup completed successfully"
EOF

}

_backup_generate_systemd_template() {
    # Service file
    write_template "$BACKUP_TEMPLATES_DIR/backup.service" <<'EOF' || return 1
# Backup Service - Generated by vpssec
# Copy to /etc/systemd/system/backup.service

[Unit]
Description=System Backup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup.sh
# Use appropriate backup script:
# ExecStart=/path/to/restic-backup.sh
# ExecStart=/path/to/borg-backup.sh

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log -/mnt/backup
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    # Timer file
    write_template "$BACKUP_TEMPLATES_DIR/backup.timer" <<'EOF' || return 1
# Backup Timer - Generated by vpssec
# Copy to /etc/systemd/system/backup.timer

[Unit]
Description=Daily Backup Timer

[Timer]
# Run daily at 3:00 AM
OnCalendar=*-*-* 03:00:00
# Randomize start time by up to 1 hour
RandomizedDelaySec=3600
# Run immediately if last run was missed
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Installation instructions
    write_template "$BACKUP_TEMPLATES_DIR/README.md" <<'EOF' || return 1
# Backup Configuration - vpssec

## Quick Start

### Using Restic

1. Install restic:
   ```bash
   apt install restic
   # or download from https://github.com/restic/restic/releases
   ```

2. Configure the backup script:
   ```bash
   cp restic-backup.sh /usr/local/bin/backup.sh
   chmod +x /usr/local/bin/backup.sh
   # Edit and configure repository, paths, and credentials
   ```

3. Create password file:
   ```bash
   echo "your-secure-password" > /root/.restic-password
   chmod 600 /root/.restic-password
   ```

4. Test backup:
   ```bash
   /usr/local/bin/backup.sh
   ```

### Using Borg

1. Install borg:
   ```bash
   apt install borgbackup
   ```

2. Configure the backup script:
   ```bash
   cp borg-backup.sh /usr/local/bin/backup.sh
   chmod +x /usr/local/bin/backup.sh
   # Edit and configure repository and paths
   ```

3. Test backup:
   ```bash
   /usr/local/bin/backup.sh
   ```

### Setting Up Scheduled Backups

1. Copy systemd files:
   ```bash
   cp backup.service /etc/systemd/system/
   cp backup.timer /etc/systemd/system/
   ```

2. Enable and start timer:
   ```bash
   systemctl daemon-reload
   systemctl enable backup.timer
   systemctl start backup.timer
   ```

3. Check timer status:
   ```bash
   systemctl list-timers backup.timer
   ```

## Restore Commands

### Restic
```bash
# List snapshots
restic snapshots

# Restore specific snapshot
restic restore <snapshot-id> --target /restore/path

# Mount snapshots for browsing
restic mount /mnt/restic-mount
```

### Borg
```bash
# List archives
borg list /path/to/repo

# Restore specific archive
borg extract /path/to/repo::archive-name

# Mount for browsing
borg mount /path/to/repo /mnt/borg-mount
```
EOF
}
