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
    crontab -l 2>/dev/null | grep -qE "(restic|borg|backup)"
}

_backup_check_systemd_timer() {
    systemctl list-timers 2>/dev/null | grep -qiE "(restic|borg|backup)"
}

# ==============================================================================
# Backup Audit
# ==============================================================================

backup_audit() {
    local module="backup"

    # Check for backup tools
    print_item "Checking backup tools installation..."
    _backup_audit_tools

    # Check for scheduled backups
    print_item "Checking scheduled backup jobs..."
    _backup_audit_scheduled

    # Check critical paths for backup
    print_item "Identifying critical paths for backup..."
    _backup_audit_critical_paths
}

_backup_audit_tools() {
    local tools_found=0

    if _backup_restic_installed; then
        ((tools_found++)) || true
        print_ok "Restic backup tool installed"
    fi

    if _backup_borg_installed; then
        ((tools_found++)) || true
        print_ok "Borg backup tool installed"
    fi

    if _backup_rclone_installed; then
        ((tools_found++)) || true
        print_ok "Rclone (remote sync) installed"
    fi

    if ((tools_found == 0)); then
        local check=$(create_check_json \
            "backup.no_tools" \
            "backup" \
            "medium" \
            "failed" \
            "No backup tools installed" \
            "No restic, borg, or rclone found" \
            "Install a backup tool" \
            "backup.generate_templates")
        state_add_check "$check"
        print_severity "medium" "No backup tools installed"
    else
        local check=$(create_check_json \
            "backup.tools_installed" \
            "backup" \
            "low" \
            "passed" \
            "$tools_found backup tool(s) installed" \
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
        print_ok "Backup cron job found"
    fi

    if _backup_check_systemd_timer; then
        ((scheduled++)) || true
        print_ok "Backup systemd timer found"
    fi

    if ((scheduled == 0)); then
        local check=$(create_check_json \
            "backup.no_schedule" \
            "backup" \
            "medium" \
            "failed" \
            "No scheduled backups found" \
            "No cron jobs or systemd timers for backup" \
            "Set up scheduled backups" \
            "backup.generate_templates")
        state_add_check "$check"
        print_severity "medium" "No scheduled backups found"
    else
        local check=$(create_check_json \
            "backup.scheduled" \
            "backup" \
            "low" \
            "passed" \
            "Backup schedule configured" \
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

    local check=$(create_check_json \
        "backup.critical_paths" \
        "backup" \
        "low" \
        "passed" \
        "Critical paths identified for backup" \
        "Paths: ${existing[*]}" \
        "" \
        "")
    state_add_check "$check"
    print_ok "Critical paths for backup: ${existing[*]}"
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

    print_info "Generating backup configuration templates..."

    # Generate Restic template
    _backup_generate_restic_template

    # Generate Borg template
    _backup_generate_borg_template

    # Generate systemd timer template
    _backup_generate_systemd_template

    print_ok "Backup templates generated in: $BACKUP_TEMPLATES_DIR"
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
# Or use: export RESTIC_PASSWORD="your-password"

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

    chmod +x "${BACKUP_TEMPLATES_DIR}/restic-backup.sh"
    print_item "Created: restic-backup.sh"
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

    chmod +x "${BACKUP_TEMPLATES_DIR}/borg-backup.sh"
    print_item "Created: borg-backup.sh"
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

    print_item "Created: backup.service"
    print_item "Created: backup.timer"

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

    print_item "Created: README.md"
}
