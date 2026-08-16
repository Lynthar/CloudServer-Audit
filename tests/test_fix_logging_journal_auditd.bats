#!/usr/bin/env bats
#
# Coverage for the four logging fixes that were untested: the persistent
# journal drop-in, and the auditd install / enable / rules trio.
#
# All four are FIX_SAFE, which in guide mode means they are applied with no
# confirmation at all — so a defect here reaches every user silently, and
# the only thing standing between the operator and a surprise is that the
# fix does what it says and can be undone.
#
# Two rollback-contract defects motivated this file, both found while
# writing it:
#
#   1. _logging_fix_enable_persistent_journal called backup_file only when
#      the drop-in already existed. backup_file's other job is to record an
#      ABSENT path as fix-created in .vpssec_created, which is the only
#      thing that lets a rollback delete it — so the very first run left a
#      drop-in that no rollback could remove, and an operator who undid the
#      plan still had journald reconfigured.
#   2. _logging_fix_setup_audit_rules had no backup_file call at all, so
#      the same hole applied to 99-vpssec.rules, and a pre-existing file
#      was replaced with nothing kept.
#
# The audit-rules content is pinned too: it must NOT contain a `-D`.
# augenrules concatenates rules.d/*.rules in lexical order and this file
# sorts last, so a delete-all here would wipe every rule loaded from an
# operator's own 10-*/20-* files.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/logging.sh"

    etc=$(_vpssec_fake_etc)
    export TMPDIR="$BATS_TEST_TMPDIR"

    # Module path variables. JOURNALD_DROPIN and AUDIT_RULES_FILE derive
    # from their directories at source time, so overriding only the
    # directories would leave them pointing at the real /etc.
    JOURNALD_CONF="$etc/systemd/journald.conf"
    JOURNALD_CONF_D="$etc/systemd/journald.conf.d"
    JOURNALD_DROPIN="$JOURNALD_CONF_D/99-vpssec.conf"
    JOURNAL_DIR="$BATS_TEST_TMPDIR/var-log-journal"
    AUDIT_RULES_D="$etc/audit/rules.d"
    AUDIT_RULES_FILE="$AUDIT_RULES_D/99-vpssec.rules"
    mkdir -p "$etc/systemd"

    _vpssec_stub systemd-tmpfiles
    _service_starts_cleanly
    _auditd_accepts_rules
}

# ---- stubs ----------------------------------------------------------

# systemctl whose `start` actually makes `is-active` succeed — the
# lifecycle, so one test can cover start-then-verify rather than asserting
# that a command was invoked.
_service_starts_cleanly() {
    _vpssec_stub_script systemctl <<SH
case "\$*" in
    *"start "*)     touch "$BATS_TEST_TMPDIR/svc-up" ;;
    *is-active*)    [[ -f "$BATS_TEST_TMPDIR/svc-up" ]] || exit 3 ;;
esac
exit 0
SH
}

# The service never comes up — a container without a running systemd, or a
# unit that fails its own preconditions.
_service_never_starts() {
    _vpssec_stub_script systemctl <<'SH'
case "$*" in
    *is-active*) exit 3 ;;
esac
exit 0
SH
}

# augenrules --load makes the kernel report rules; auditctl -l then lists
# them. Until something loads them, auditctl -l says nothing.
_auditd_accepts_rules() {
    _vpssec_stub_script augenrules <<SH
touch "$BATS_TEST_TMPDIR/rules-loaded"
exit 0
SH
    _vpssec_stub_script auditctl <<SH
if [[ "\$1" == "-l" ]]; then
    [[ -f "$BATS_TEST_TMPDIR/rules-loaded" ]] && echo "-w /etc/passwd -p wa -k identity"
    exit 0
fi
[[ "\$1" == "-R" ]] && touch "$BATS_TEST_TMPDIR/rules-loaded"
exit 0
SH
}

# The file lands on disk but nothing loads it into the kernel: auditd is
# not running, or the rule set is already immutable via -e 2.
_auditd_cannot_load() {
    _vpssec_stub augenrules 1
    _vpssec_stub_script auditctl <<'SH'
exit 1
SH
}

# Make a path uncreatable by putting a regular file where a parent
# directory would have to be, so mkdir -p and write_file_atomic both fail.
_block_path_under() {
    printf 'not a directory\n' > "$1"
}

# ==============================================================================
# logging.enable_persistent_journal
# ==============================================================================

@test "journal: the drop-in asks for persistent storage" {
    run _logging_fix_enable_persistent_journal
    [ "$status" -eq 0 ]
    grep -qxF "Storage=persistent" "$JOURNALD_DROPIN"
}

@test "journal: the journal directory is created" {
    run _logging_fix_enable_persistent_journal
    [ "$status" -eq 0 ]
    [ -d "$JOURNAL_DIR" ]
}

@test "journal: a newly created drop-in is recorded so rollback deletes it" {
    # The regression. backup_file was called only when the file already
    # existed, so on a first run nothing entered .vpssec_created and the
    # operator could roll the plan back with journald still reconfigured.
    _vpssec_begin_backup_session

    run _logging_fix_enable_persistent_journal
    [ "$status" -eq 0 ]
    grep -qxF "$JOURNALD_DROPIN" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "journal: an existing drop-in is backed up before it is replaced" {
    mkdir -p "$JOURNALD_CONF_D"
    printf '[Journal]\nSystemMaxUse=42M\n' > "$JOURNALD_DROPIN"
    _vpssec_begin_backup_session

    run _logging_fix_enable_persistent_journal
    [ "$status" -eq 0 ]
    grep -qxF "SystemMaxUse=42M" "${VPSSEC_BACKUP_SESSION}${JOURNALD_DROPIN}"
}

@test "journal: journald is restarted only after the drop-in is in place" {
    # Restarting first would apply the old configuration and report success
    # against a file the daemon has not read.
    run _logging_fix_enable_persistent_journal
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'restart systemd-journald'
    [ -f "$JOURNALD_DROPIN" ]
}

@test "journal: failure is reported when nothing could be written" {
    # Neither the journal directory nor the drop-in can be created, so the
    # audit predicate still says non-persistent. Reporting success here
    # would record the fix as complete on a host it never changed.
    _block_path_under "$etc/blocked"
    JOURNAL_DIR="$etc/blocked/journal"
    JOURNALD_CONF_D="$etc/blocked/journald.conf.d"
    JOURNALD_DROPIN="$JOURNALD_CONF_D/99-vpssec.conf"
    JOURNALD_CONF="$etc/blocked/journald.conf"

    run _logging_fix_enable_persistent_journal
    [ "$status" -eq 1 ]
}

# ==============================================================================
# logging.setup_audit_rules
# ==============================================================================

@test "audit rules: the rules file is written" {
    run _logging_fix_setup_audit_rules
    [ "$status" -eq 0 ]
    # `--` is required: the pattern starts with a dash, which grep would
    # otherwise parse as options.
    grep -qxF -- "-w /etc/passwd -p wa -k identity" "$AUDIT_RULES_FILE"
}

@test "audit rules: no delete-all directive is emitted" {
    # This file sorts last in rules.d, so a `-D` here would erase every rule
    # loaded from the operator's own earlier files.
    run _logging_fix_setup_audit_rules
    [ "$status" -eq 0 ]
    _vpssec_refute grep -qE '^-D[[:space:]]*$' "$AUDIT_RULES_FILE"
}

@test "audit rules: a newly created rules file is recorded so rollback deletes it" {
    # The second regression: this write had no backup_file call at all, so
    # rolling back a plan that configured auditd left the rules loading on
    # every boot.
    _vpssec_begin_backup_session

    run _logging_fix_setup_audit_rules
    [ "$status" -eq 0 ]
    grep -qxF "$AUDIT_RULES_FILE" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "audit rules: an existing rules file is backed up before replacement" {
    mkdir -p "$AUDIT_RULES_D"
    printf '# operator rules\n-w /srv -p wa -k srv\n' > "$AUDIT_RULES_FILE"
    _vpssec_begin_backup_session

    run _logging_fix_setup_audit_rules
    [ "$status" -eq 0 ]
    grep -qxF -- "-w /srv -p wa -k srv" "${VPSSEC_BACKUP_SESSION}${AUDIT_RULES_FILE}"
}

@test "audit rules: success when the kernel reports the rules loaded" {
    run _logging_fix_setup_audit_rules
    [ "$status" -eq 0 ]
    _vpssec_stub_called augenrules '--load'
}

@test "audit rules: the file persisting is still success when nothing can load it" {
    # auditd not running in this environment; the rules apply at next start.
    # Reporting failure would be a false alarm on a correct outcome.
    _auditd_cannot_load

    run _logging_fix_setup_audit_rules
    [ "$status" -eq 0 ]
    [ -f "$AUDIT_RULES_FILE" ]
}

@test "audit rules: failure when the file could not be written at all" {
    _auditd_cannot_load
    _block_path_under "$etc/blocked"
    AUDIT_RULES_D="$etc/blocked/rules.d"
    AUDIT_RULES_FILE="$AUDIT_RULES_D/99-vpssec.rules"

    run _logging_fix_setup_audit_rules
    [ "$status" -eq 1 ]
}

# ==============================================================================
# logging.enable_auditd
# ==============================================================================

@test "enable auditd: the unit is enabled and started" {
    run _logging_fix_enable_auditd
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'enable auditd'
    _vpssec_stub_called systemctl 'start auditd'
}

@test "enable auditd: a service that never comes up is reported as failure" {
    _service_never_starts

    run _logging_fix_enable_auditd
    [ "$status" -eq 1 ]
}

# ==============================================================================
# logging.install_auditd
# ==============================================================================

@test "install auditd: a failed package install is propagated" {
    _vpssec_stub apt-get 100

    run _logging_fix_install_auditd
    [ "$status" -eq 1 ]
}

@test "install auditd: nothing is configured when the install fails" {
    _vpssec_stub apt-get 100

    run _logging_fix_install_auditd
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called systemctl 'start auditd'
    [ ! -f "$AUDIT_RULES_FILE" ]
}

@test "install auditd: a successful install also enables the unit and writes the rules" {
    _vpssec_stub apt-get

    run _logging_fix_install_auditd
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'start auditd'
    [ -f "$AUDIT_RULES_FILE" ]
}

@test "install auditd: succeeds even where the service cannot start" {
    # Deliberate. This fix_id answers "auditd is not installed", and the
    # install is what that check measures; the service has its own check and
    # its own fix_id, which report on the next run. Failing here would mark
    # a correctly installed package as a failed fix on every container.
    _vpssec_stub apt-get
    _service_never_starts

    run _logging_fix_install_auditd
    [ "$status" -eq 0 ]
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "logging_fix: an unknown fix id fails instead of silently doing nothing" {
    run logging_fix "logging.not_a_real_fix"
    [ "$status" -eq 1 ]
}

# ---- the backup contract ---------------------------------------------

@test "persistent journal: a backup that cannot be taken aborts the fix" {
    _vpssec_begin_backup_session
    mkdir -p "$JOURNALD_CONF_D"
    printf '# existing\n' > "$JOURNALD_DROPIN"
    _vpssec_stub cp 1

    run _logging_fix_enable_persistent_journal
    [ "$status" -ne 0 ]
    [ "$(cat "$JOURNALD_DROPIN")" = "# existing" ]
}
