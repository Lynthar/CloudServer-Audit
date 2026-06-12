#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Backup template module - generates backup configurations
# Copyright (c) 2024

# ==============================================================================
# Backup Configuration
# ==============================================================================

BACKUP_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/backup"

# ==============================================================================
# Backup Helper Functions
# ==============================================================================

_backup_restic_installed() {
    check_command restic
}

_backup_borg_installed() {
    check_command borg
}

_backup_rclone_installed() {
    check_command rclone
}

_backup_check_cron_job() {
    # root's personal crontab...
    crontab -l 2>/dev/null | grep -qE "(restic|borg|backup)" && return 0
    # ...and the system cron locations a backup job is at least as likely to
    # live in (/etc/cron.d, the cron.{daily,weekly,monthly} dirs, /etc/crontab).
    # Missing paths just make grep skip them (2>/dev/null).
    grep -rqsE "(restic|borg|backup)" \
        /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
}

_backup_check_systemd_timer() {
    systemctl list-timers 2>/dev/null | grep -qiE "(restic|borg|backup)"
}

# Single source of truth for "is a backup tool installed?". Both the
# tools audit and the audit-flow gate consult this so the three backup
# checks can't disagree (previously: no_tools failed while scheduled
# and critical_paths both passed, because the latter two only looked
# for cron entries / on-disk paths without cross-referencing tools).
_backup_count_tools() {
    local count=0
    _backup_restic_installed && ((count++)) || true
    _backup_borg_installed && ((count++)) || true
    _backup_rclone_installed && ((count++)) || true
    echo "$count"
}

# ==============================================================================
# Backup Audit
# ==============================================================================

backup_audit() {
    local module="backup"
    local tools_found
    tools_found=$(_backup_count_tools)

    # Check for backup tools
    print_item "$(i18n 'backup.check_tools')"
    _backup_audit_tools

    # Schedule and critical-paths checks are meaningful only when at
    # least one backup tool is installed — otherwise a stray cron line
    # whose name contains "backup", or the mere existence of /etc on
    # disk, would emit a passing check next to "no backup tools",
    # giving the operator a false sense that backups are in place.
    if (( tools_found > 0 )); then
        print_item "$(i18n 'backup.check_scheduled')"
        _backup_audit_scheduled

        print_item "$(i18n 'backup.check_critical_paths')"
        _backup_audit_critical_paths
    fi
}

_backup_audit_tools() {
    local tools_found=0

    if _backup_restic_installed; then
        ((tools_found++)) || true
        print_ok "$(i18n 'backup.restic_installed')"
    fi

    if _backup_borg_installed; then
        ((tools_found++)) || true
        print_ok "$(i18n 'backup.borg_installed')"
    fi

    if _backup_rclone_installed; then
        ((tools_found++)) || true
        print_ok "$(i18n 'backup.rclone_installed')"
    fi

    if ((tools_found == 0)); then
        local check=$(create_check_json \
            "backup.no_tools" \
            "backup" \
            "low" \
            "failed" \
            "$(i18n 'backup.no_tools')" \
            "$(i18n 'backup.no_tools_desc')" \
            "$(i18n 'backup.fix_install_tool')" \
            "backup.generate_templates")
        state_add_check "$check"
        print_severity "low" "$(i18n 'backup.no_tools')"
    else
        local check=$(create_check_json \
            "backup.tools_installed" \
            "backup" \
            "low" \
            "passed" \
            "$(i18n 'backup.tools_count' "count=$tools_found")" \
            "" \
            "" \
            "")
        state_add_check "$check"
    fi
}

_backup_audit_scheduled() {
    local scheduled=0

    if _backup_check_cron_job; then
        ((scheduled++)) || true
        print_ok "$(i18n 'backup.cron_found')"
    fi

    if _backup_check_systemd_timer; then
        ((scheduled++)) || true
        print_ok "$(i18n 'backup.timer_found')"
    fi

    if ((scheduled == 0)); then
        local check=$(create_check_json \
            "backup.no_schedule" \
            "backup" \
            "low" \
            "failed" \
            "$(i18n 'backup.no_scheduled')" \
            "$(i18n 'backup.no_scheduled_desc')" \
            "$(i18n 'backup.fix_setup_schedule')" \
            "backup.generate_templates")
        state_add_check "$check"
        print_severity "low" "$(i18n 'backup.no_scheduled')"
    else
        local check=$(create_check_json \
            "backup.scheduled" \
            "backup" \
            "low" \
            "passed" \
            "$(i18n 'backup.schedule_configured')" \
            "" \
            "" \
            "")
        state_add_check "$check"
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
    local check=$(create_check_json \
        "backup.critical_paths" \
        "backup" \
        "low" \
        "passed" \
        "$(i18n 'backup.paths_identified')" \
        "$(i18n 'backup.paths_list' "paths=$paths_list")" \
        "" \
        "")
    state_add_check "$check"
    print_ok "$(i18n 'backup.critical_paths' "paths=$paths_list")"
}

# ==============================================================================
# Backup Fix Functions
# ==============================================================================

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
    mkdir -p "$BACKUP_TEMPLATES_DIR"

    print_info "$(i18n 'backup.generating_templates')"

    # Generate Restic template
    _backup_generate_restic_template

    # Generate Borg template
    _backup_generate_borg_template

    # Generate systemd timer template
    _backup_generate_systemd_template

    print_ok "$(i18n 'backup.templates_generated' "path=$BACKUP_TEMPLATES_DIR")"
    return 0
}

_backup_generate_restic_template() {
    cat > "${BACKUP_TEMPLATES_DIR}/restic-backup.sh" <<'EOF'
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

    # 700 rather than +x (which yields 755): the backup script holds
    # credentials (repo URL, possibly S3 keys inline if the user adds
    # them) and is not something other users need to read or execute.
    chmod 700 "${BACKUP_TEMPLATES_DIR}/restic-backup.sh"
    print_item "$(i18n 'backup.template_created' "name=restic-backup.sh")"
}

_backup_generate_borg_template() {
    cat > "${BACKUP_TEMPLATES_DIR}/borg-backup.sh" <<'EOF'
#!/bin/bash
# Borg Backup Script - Generated by vpssec
# Configure and adapt for your needs

set -euo pipefail

# Configuration
export BORG_REPO="/mnt/backup/borg"
# Or for remote: export BORG_REPO="user@backup-server:/path/to/repo"

export BORG_PASSPHRASE="your-passphrase"
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

    # See restic template above for rationale on 700 vs +x.
    chmod 700 "${BACKUP_TEMPLATES_DIR}/borg-backup.sh"
    print_item "$(i18n 'backup.template_created' "name=borg-backup.sh")"
}

_backup_generate_systemd_template() {
    # Service file
    cat > "${BACKUP_TEMPLATES_DIR}/backup.service" <<'EOF'
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
ReadWritePaths=/var/log /mnt/backup
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    # Timer file
    cat > "${BACKUP_TEMPLATES_DIR}/backup.timer" <<'EOF'
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

    print_item "$(i18n 'backup.template_created' "name=backup.service")"
    print_item "$(i18n 'backup.template_created' "name=backup.timer")"

    # Installation instructions
    cat > "${BACKUP_TEMPLATES_DIR}/README.md" <<'EOF'
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

    print_item "$(i18n 'backup.template_created' "name=README.md")"
}
