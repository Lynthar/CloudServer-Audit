#!/usr/bin/env bats
#
# Regression tests for the backup template generator.
#
# The defect: _backup_fix_generate_templates called three sub-generators and
# discarded every one of their statuses, then `return 0`. Each sub-generator
# was in turn a bare `cat >` whose status it also discarded. errexit is off
# inside a fix (execute_fix invokes it in a condition context, and bash's
# exemption reaches into the function body), so a templates tree that could
# not be written still ended in "Backup templates generated in: ..." and a
# fix the engine recorded as complete via state_mark_fix_complete.
#
# This module writes only into vpssec's own templates tree — never /etc — and
# calls neither backup_file nor write_file_atomic. That is deliberate, and the
# last two tests pin it: the artifacts must stay inert, and nothing here may
# end up in a rollback manifest.
#
# Note what this suite deliberately does NOT assert. backup.generate_templates
# returns 0 while the findings it is attached to (backup.no_tools,
# backup.no_schedule) both stay red — installing restic and wiring up the timer
# are manual steps. That is the convention shared by the whole FIX_SAFE
# "template generation only" group (docker.generate_proxy_template,
# cloudflared.generate_config), and webapp's manual-step fixes take the
# opposite one (return 1). Reconciling the two is a design question recorded
# in the review archive, not something to settle inside one suite.

load helpers.bash

setup() {
    _vpssec_load
    # Without this, i18n echoes the KEY, and a grep for the key name passes
    # whether or not the string exists in either language file.
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/backup.sh"

    VPSSEC_QUIET_SCAN=0

    # BACKUP_TEMPLATES_DIR derives from VPSSEC_TEMPLATES at source time, and
    # _vpssec_load has already pointed that at this test's tmpdir.

    # Anything that "installs" rather than "generates" would have to go
    # through one of these; stub them so "never called" is a real refutation.
    _vpssec_stub systemctl
    _vpssec_stub crontab

    etc=$(_vpssec_fake_etc)
}

# ---- the dispatcher --------------------------------------------------

@test "backup_fix: an unknown fix_id fails rather than silently doing nothing" {
    run backup_fix backup.not_a_real_fix
    [ "$status" -eq 1 ]
}

@test "backup_fix: generate_templates routes to the generator" {
    run backup_fix backup.generate_templates
    [ "$status" -eq 0 ]
    [ -f "$BACKUP_TEMPLATES_DIR/restic-backup.sh" ]
}

# ---- the generated artifacts ----------------------------------------

@test "generate_templates: all five artifacts are written" {
    run _backup_fix_generate_templates
    [ "$status" -eq 0 ]
    [ -f "$BACKUP_TEMPLATES_DIR/restic-backup.sh" ]
    [ -f "$BACKUP_TEMPLATES_DIR/borg-backup.sh" ]
    [ -f "$BACKUP_TEMPLATES_DIR/backup.service" ]
    [ -f "$BACKUP_TEMPLATES_DIR/backup.timer" ]
    [ -f "$BACKUP_TEMPLATES_DIR/README.md" ]
    [[ "$output" == *"Backup templates generated in"* ]]
}

@test "generate_templates: the two backup scripts are 700, not 755" {
    # They carry repository URLs and, once the operator fills them in, cloud
    # credentials. `chmod +x` would yield 755 under the usual umask and make
    # them world-readable.
    run _backup_fix_generate_templates
    [ "$status" -eq 0 ]
    [ "$(stat -c '%a' "$BACKUP_TEMPLATES_DIR/restic-backup.sh")" = "700" ]
    [ "$(stat -c '%a' "$BACKUP_TEMPLATES_DIR/borg-backup.sh")" = "700" ]
}

@test "generate_templates: the unit files and README are not made executable" {
    run _backup_fix_generate_templates
    [ "$status" -eq 0 ]
    _vpssec_refute test -x "$BACKUP_TEMPLATES_DIR/backup.service"
    _vpssec_refute test -x "$BACKUP_TEMPLATES_DIR/backup.timer"
    _vpssec_refute test -x "$BACKUP_TEMPLATES_DIR/README.md"
}

@test "generate_templates: the restic template keeps the passphrase out of the script" {
    # A RESTIC_PASSWORD="..." inline would leak with the file the moment it
    # loses its 700 mode; the template uses a password FILE and says so.
    run _backup_fix_generate_templates
    [ "$status" -eq 0 ]
    grep -q 'RESTIC_PASSWORD_FILE=' "$BACKUP_TEMPLATES_DIR/restic-backup.sh"
    _vpssec_refute grep -qE '^export RESTIC_PASSWORD=' "$BACKUP_TEMPLATES_DIR/restic-backup.sh"
}

# ---- failures are reported, not swallowed ---------------------------

@test "generate_templates: an uncreatable templates directory is reported" {
    printf 'blocker\n' > "$BATS_TEST_TMPDIR/blocker"
    BACKUP_TEMPLATES_DIR="$BATS_TEST_TMPDIR/blocker/backup"

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not create the backup templates directory"* ]]
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

@test "generate_templates: a failed first write is reported and stops the run" {
    # The restic script's path is a directory, so `cat >` fails.
    mkdir -p "$BACKUP_TEMPLATES_DIR/restic-backup.sh"

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the backup template"* ]]
    # The borg generator runs after restic; a discarded status would have let
    # it run anyway and the function reach its success line.
    _vpssec_refute test -f "$BACKUP_TEMPLATES_DIR/borg-backup.sh"
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

@test "generate_templates: a failure in the middle generator still fails the fix" {
    # borg is the second of three. This is the case a per-generator `|| return
    # 1` catches and a trailing bare `return 0` does not.
    mkdir -p "$BACKUP_TEMPLATES_DIR/borg-backup.sh"

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [ -f "$BACKUP_TEMPLATES_DIR/restic-backup.sh" ]
    _vpssec_refute test -f "$BACKUP_TEMPLATES_DIR/backup.service"
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

@test "generate_templates: a failure in the last generator still fails the fix" {
    # backup.service is written by the third generator, after both scripts
    # have succeeded — the path a "check only the first one" fix would miss.
    mkdir -p "$BACKUP_TEMPLATES_DIR/backup.service"

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [ -f "$BACKUP_TEMPLATES_DIR/borg-backup.sh" ]
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

@test "generate_templates: a failed timer write also fails the fix" {
    # backup.timer is the second of the three files the systemd generator
    # writes — the one a "check only the first write" implementation misses.
    mkdir -p "$BACKUP_TEMPLATES_DIR/backup.timer"

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [ -f "$BACKUP_TEMPLATES_DIR/backup.service" ]
    _vpssec_refute test -f "$BACKUP_TEMPLATES_DIR/README.md"
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

@test "generate_templates: a failed README write also fails the fix" {
    # The very last artifact, after everything else has succeeded.
    mkdir -p "$BACKUP_TEMPLATES_DIR/README.md"

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [ -f "$BACKUP_TEMPLATES_DIR/backup.timer" ]
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

@test "generate_templates: a failed chmod is reported, not left as a readable script" {
    _vpssec_stub chmod 1

    run _backup_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the backup template"* ]]
    _vpssec_refute grep -q "Backup templates generated in" <<<"$output"
}

# ---- what the report claims -----------------------------------------

@test "critical-paths check: the report does not claim those paths are backed up" {
    # This check is hardcoded `passed` and only asks which of five directories
    # exist on disk. It never reads the backup tool's configuration, its
    # exclude list, or whether a single snapshot exists — so worded as
    # "critical paths identified for backup" next to a green tick it read as
    # "your backup covers these", which the operator can disprove by pointing
    # at their own excludes. The wording now says what was measured, and this
    # pins the disclaimer against a later "cleanup".
    #
    # i18n parity only checks that a key exists and bats only checks which
    # branch runs, so this family has no other automated guard.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/state.sh"
    state_init

    _backup_audit_critical_paths

    local desc
    desc=$(jq -r '.[] | select(.id == "backup.critical_paths") | .desc' \
        "$VPSSEC_STATE/checks.json")
    [[ "$desc" == *"does not check whether your backup actually covers them"* ]]
}

# ---- the artifacts stay inert ---------------------------------------

@test "generate_templates: nothing is installed, only written under the templates dir" {
    run _backup_fix_generate_templates
    [ "$status" -eq 0 ]

    _vpssec_refute _vpssec_stub_called systemctl
    _vpssec_refute _vpssec_stub_called crontab
    [ -z "$(ls -A "$etc")" ]
}

@test "generate_templates: nothing is registered for rollback" {
    # The artifacts live in vpssec's own templates tree. A path recorded in
    # .vpssec_created would make `vpssec rollback` delete part of vpssec's
    # own installation.
    _vpssec_begin_backup_session

    run _backup_fix_generate_templates
    [ "$status" -eq 0 ]
    _vpssec_refute test -f "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}
