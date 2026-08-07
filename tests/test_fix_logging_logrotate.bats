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
}

# ---- install failure must propagate ----------------------------------

@test "logrotate: apt install failure returns non-zero" {
    _vpssec_stub apt-get 100

    run _logging_fix_setup_logrotate
    [ "$status" -eq 1 ]
}

@test "logrotate: apt install failure leaves no half-written config behind" {
    _vpssec_stub apt-get 100

    run _logging_fix_setup_logrotate
    [ "$status" -eq 1 ]
    [ ! -f "$LOGROTATE_CONF" ]
}

@test "logrotate: the package index is refreshed before installing" {
    # Without an `apt-get update` first, a host whose /var/lib/apt/lists is
    # empty or stale gets "Unable to locate package" and the fix can never
    # succeed.
    _vpssec_stub apt-get 100

    run _logging_fix_setup_logrotate
    _vpssec_stub_called apt-get 'update'
    _vpssec_stub_called apt-get 'install .*logrotate'
}

@test "logrotate: a failing apt-get update alone does not fail the fix" {
    # One broken third-party repo makes `apt-get update` non-zero while the
    # package is still installable from the rest of the index. Only the
    # install's own status may decide.
    _vpssec_stub_script apt-get <<'SH'
case "$*" in
    *update*)  exit 100 ;;
    *install*) exit 0 ;;
esac
exit 0
SH

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
}

# ---- config writing --------------------------------------------------

@test "logrotate: config is written when the package ships none" {
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

# ---- guard -----------------------------------------------------------

@test "logrotate: already installed and configured skips apt entirely" {
    _vpssec_stub logrotate 0
    _vpssec_stub apt-get 0
    printf 'weekly\n' > "$LOGROTATE_CONF"

    run _logging_fix_setup_logrotate
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called apt-get
}
