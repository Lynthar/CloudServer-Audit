#!/usr/bin/env bats
# "Backup schedule configured" needs a schedule that runs a backup tool. Every
# Debian and Ubuntu host ships dpkg's own database backup (cron.daily/dpkg and
# dpkg-db-backup.timer), which said "backup" and passed the check everywhere.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/backup.sh"

    etc=$(_vpssec_fake_etc)
    BACKUP_CRON_ROOT="$etc"
    mkdir -p "$etc/cron.d" "$etc/cron.daily"
    # What a stock Debian 12 ships: dpkg's job and passwd's /var/backups one.
    printf '%s\n' '#!/bin/sh' 'if [ -x /usr/libexec/dpkg/dpkg-db-backup ]; then' \
        '    /usr/libexec/dpkg/dpkg-db-backup' 'fi' > "$etc/cron.daily/dpkg"
    printf '%s\n' '#!/bin/sh' 'cd /var/backups || exit 0' > "$etc/cron.daily/passwd"

    _vpssec_stub restic
    _vpssec_absent_command borg
    _vpssec_absent_command rclone
    _vpssec_stub crontab 1 "no crontab for root"
    _timers "dpkg-db-backup.timer dpkg-db-backup.service"
}

# systemctl list-timers --no-legend with one row per argument (UNIT ACTIVATES).
_timers() {
    local row out=""
    for row in "$@"; do
        out+="Fri 2026-10-10 00:00:00 UTC 14h Thu 2026-10-09 00:00:00 UTC 9h ago $row"$'\n'
    done
    printf '%s' "$out" > "$BATS_TEST_TMPDIR/timers"
    _vpssec_stub_script systemctl <<SH
[[ "\$*" == "list-timers --no-legend" ]] && cat "$BATS_TEST_TMPDIR/timers"
exit 0
SH
}

_schedule_check() {
    backup_audit >/dev/null
    jq -r '[.[] | select(.id | test("schedule")) | "\(.id) \(.status)"] | join(",")' \
        "$VPSSEC_STATE/checks.json"
}

@test "a stock Debian host with restic installed has no backup schedule" {
    [ "$(_schedule_check)" = "backup.no_schedule failed" ]
}

@test "a cron job running restic is a schedule" {
    printf '%s\n' '15 3 * * * root restic -r /srv/repo backup /etc' > "$etc/cron.d/restic"
    [ "$(_schedule_check)" = "backup.scheduled passed" ]
}

@test "root's crontab running borgmatic is a schedule" {
    _vpssec_stub crontab 0 "0 2 * * * /usr/bin/borgmatic --verbosity 0"
    [ "$(_schedule_check)" = "backup.scheduled passed" ]
}

@test "a commented-out job is not a schedule" {
    _vpssec_stub crontab 0 "# 0 2 * * * restic backup /home   (disabled while migrating)"
    printf '%s\n' '#15 3 * * * root rclone sync /srv remote:srv' > "$etc/cron.d/old"
    [ "$(_schedule_check)" = "backup.no_schedule failed" ]
}

@test "a word that merely contains a tool name is not a schedule" {
    printf '%s\n' '0 4 * * * root /usr/local/bin/cyborgs-report' > "$etc/cron.d/report"
    [ "$(_schedule_check)" = "backup.no_schedule failed" ]
}

@test "a timer named after a tool, or vpssec's own backup.timer, is a schedule" {
    _timers "dpkg-db-backup.timer dpkg-db-backup.service" "restic-backup.timer restic-backup.service"
    [ "$(_schedule_check)" = "backup.scheduled passed" ]

    state_init
    _timers "dpkg-db-backup.timer dpkg-db-backup.service" "backup.timer backup.service"
    [ "$(_schedule_check)" = "backup.scheduled passed" ]
}
