#!/usr/bin/env bats
#
# Regression tests for _logging_fix_setup_logrotate.
#
# The original implementation discarded apt's exit status and ended with an
# unconditional `return 0`, so on a host that could not install logrotate it
# printed "log rotation configured", the engine recorded the fix as complete
# via state_mark_fix_complete, and the very next audit re-flagged logrotate as
# missing — a fix permanently at odds with its own audit. It also wrote
# /etc/logrotate.conf with a bare `cat >` redirect: an interrupted write could
# truncate the file, and because it bypassed backup_file the created path was
# never recorded in the session's .vpssec_created manifest, so a rollback could
# not remove a file the fix itself had created.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/logging.sh"

    etc=$(_vpssec_fake_etc)
    LOGROTATE_CONF="$etc/logrotate.conf"
    LOGROTATE_D="$etc/logrotate.d"
    mkdir -p "$LOGROTATE_D"

    # systemctl is not involved in this fix, but stub it so an accidental
    # future call cannot touch the host.
    _vpssec_stub systemctl

    # Without this, i18n echoes the KEY, so a grep for a word in the message
    # matches the key name and passes whether or not the string is registered.
    i18n_load en_US
}

# ---- install failure must propagate ----------------------------------
#
# Every test below reaches the apt block, which the fix guards with
# `check_command logrotate`. That guard must be answered by the test and not by
# the host: stubbing steers it the wrong way (a stub on PATH makes the binary
# look INSTALLED), so absence is only ever whatever the test box lacks. These
# three passed in the Debian container, which ships no logrotate, and went red
# on ubuntu-latest, which preinstalls it — the fix skipped the whole block and
# returned 0 without calling apt-get. The fourth test stayed green while
# proving nothing, since skipping the block hands it the status 0 it asserts.

@test "logrotate: apt install failure returns non-zero" {
    _vpssec_absent_command logrotate
    _vpssec_stub apt-get 100

    run _logging_fix_setup_logrotate
    [ "$status" -eq 1 ]
}

@test "logrotate: apt install failure leaves no half-written config behind" {
    _vpssec_absent_command logrotate
    _vpssec_stub apt-get 100

    run _logging_fix_setup_logrotate
    [ "$status" -eq 1 ]
    [ ! -f "$LOGROTATE_CONF" ]
}

@test "logrotate: the package index is refreshed before installing" {
    # Without an `apt-get update` first, a host whose /var/lib/apt/lists is
    # empty or stale gets "Unable to locate package" and the fix can never
    # succeed.
    _vpssec_absent_command logrotate
    _vpssec_stub apt-get 100

    run _logging_fix_setup_logrotate
    _vpssec_stub_called apt-get 'update'
    _vpssec_stub_called apt-get 'install .*logrotate'
}

@test "logrotate: a failing apt-get update alone does not fail the fix" {
    # One broken third-party repo makes `apt-get update` non-zero while the
    # package is still installable from the rest of the index. Only the
    # install's own status may decide.
    _vpssec_absent_command logrotate
    _vpssec_stub_script apt-get <<'SH'
case "$*" in
    *update*)  exit 100 ;;
    *install*) exit 0 ;;
esac
exit 0
SH

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
    # Assert the branch actually ran. Without this the test cannot tell "the
    # install's status decided" from "the apt block never executed".
    _vpssec_stub_called apt-get 'update'
    _vpssec_stub_called apt-get 'install .*logrotate'
}

# ---- config writing --------------------------------------------------

@test "logrotate: config is written when the package ships none" {
    # The name is the scenario: the install ran and still left no
    # logrotate.conf behind, which is the only case this branch is for. That
    # needs the apt block to execute, so the guard is answered here too.
    _vpssec_absent_command logrotate
    _vpssec_stub apt-get 0

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
    [ -f "$LOGROTATE_CONF" ]
    grep -q 'include /etc/logrotate.d' "$LOGROTATE_CONF"
    grep -q '^weekly$' "$LOGROTATE_CONF"
}

@test "logrotate: an existing config is left untouched" {
    _vpssec_stub apt-get 0
    printf '# operator config\ndaily\nrotate 30\n' > "$LOGROTATE_CONF"

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
    grep -q '^daily$' "$LOGROTATE_CONF"
    grep -q 'operator config' "$LOGROTATE_CONF"
    _vpssec_refute grep -q '^weekly$' "$LOGROTATE_CONF"
}

@test "logrotate: a config the fix creates is registered for rollback" {
    # backup_file records a not-yet-existing path in .vpssec_created so
    # backup_restore DELETES it on rollback. The bare `cat >` this replaced
    # skipped backup_file entirely, so the new file survived a rollback.
    _vpssec_stub apt-get 0
    _vpssec_begin_backup_session

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
    [ -f "$VPSSEC_BACKUP_SESSION/.vpssec_created" ]
    grep -qxF "$LOGROTATE_CONF" "$VPSSEC_BACKUP_SESSION/.vpssec_created"
}

@test "logrotate: a write that fails is reported as a write failure" {
    # The only branch of this fix nothing reached. write_file_atomic mkdir -p's
    # the parent, so a merely-missing directory is not enough to fail it — make
    # the parent a regular FILE, which defeats both the mkdir and the mktemp.
    #
    # Both failure paths return 1, so status alone cannot tell a failed write
    # from a failed install. "write" appears only in logrotate_failed.
    VPSSEC_QUIET_SCAN=0
    _vpssec_absent_command logrotate
    _vpssec_stub apt-get 0
    : > "$etc/notadir"
    LOGROTATE_CONF="$etc/notadir/logrotate.conf"

    run _logging_fix_setup_logrotate
    [ "$status" -eq 1 ]
    grep -q 'write' <<<"$output"
    _vpssec_refute grep -qi 'install' <<<"$output"
}

# ---- guard -----------------------------------------------------------

@test "logrotate: already installed and configured skips apt entirely" {
    _vpssec_stub logrotate 0
    _vpssec_stub apt-get 0
    printf 'weekly\n' > "$LOGROTATE_CONF"

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called apt-get
}

@test "logrotate: a backup that cannot be recorded aborts the fix" {
    # This call site only fires when the package shipped no conffile, so the
    # failing branch has to be the created-file manifest rather than cp.
    _vpssec_absent_command logrotate
    _vpssec_stub apt-get 0
    _vpssec_begin_backup_session
    mkdir -p "$VPSSEC_BACKUP_SESSION/$VPSSEC_CREATED_MANIFEST"

    run _logging_fix_setup_logrotate
    [ "$status" -ne 0 ]
    [ ! -f "$LOGROTATE_CONF" ]
}
