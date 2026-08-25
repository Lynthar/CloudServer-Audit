#!/usr/bin/env bats
# The SSH hardening write path: drop-in validation, rollback, and the
# post-reload effectiveness assertion. File ordering is an assumption and the
# merged config is the fact, so `sshd -T` after the reload is what these guard.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"

    etc=$(_vpssec_fake_etc)
    SSH_CONFIG="$etc/ssh/sshd_config"
    SSH_DROPIN_DIR="$etc/ssh/sshd_config.d"
    SSH_HARDENING_DROPIN="$SSH_DROPIN_DIR/00-vpssec-hardening.conf"
    SSH_HARDENING_DROPIN_LEGACY="$SSH_DROPIN_DIR/99-vpssec-hardening.conf"
    mkdir -p "$SSH_DROPIN_DIR"

    export VPSSEC_TEST_SSHD_DIR="$BATS_TEST_TMPDIR"
    # _ssh_write_hardening_config stages through `mktemp -t`, which honours
    # TMPDIR. Without this the staging files land in the shared /tmp and one
    # leftover from an earlier run makes the leak assertion below fail forever.
    export TMPDIR="$BATS_TEST_TMPDIR"
    _stub_sshd
    _vpssec_stub systemctl
}

# One sshd stub for every invocation shape, driven by files so a test can change
# its mind mid-run: sshd-t-f.rc is `sshd -t -f <file>` (drop-in alone), sshd-t.rc
# is `sshd -t` (full merged context), sshd-T.out is what `sshd -T` prints.
_stub_sshd() {
    _vpssec_stub_script sshd <<'SH'
d="${VPSSEC_TEST_SSHD_DIR:-/nonexistent}"
case "$*" in
    *-T*)      cat "$d/sshd-T.out" 2>/dev/null; exit 0 ;;
    *"-t -f"*) exit "$(cat "$d/sshd-t-f.rc" 2>/dev/null || echo 0)" ;;
    *-t*)      exit "$(cat "$d/sshd-t.rc" 2>/dev/null || echo 0)" ;;
esac
exit 0
SH
}

_sshd_dropin_check() { echo "$1" > "$BATS_TEST_TMPDIR/sshd-t-f.rc"; }
_sshd_fullcontext_check() { echo "$1" > "$BATS_TEST_TMPDIR/sshd-t.rc"; }
_sshd_effective() { printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/sshd-T.out"; }

# ---- _ssh_write_hardening_config -------------------------------------

@test "ssh write: a valid drop-in lands with the requested content" {
    run _ssh_write_hardening_config "PasswordAuthentication no"
    [ "$status" -eq 0 ]
    grep -q '^PasswordAuthentication no$' "$SSH_HARDENING_DROPIN"
}

@test "ssh write: the drop-in is world-readable, not 600" {
    # It is written through a 600 temp file; sshd must still be able to read
    # it after the move.
    _ssh_write_hardening_config "PasswordAuthentication no"
    [ "$(stat -c '%a' "$SSH_HARDENING_DROPIN")" = "644" ]
}

@test "ssh write: a drop-in sshd rejects is never installed" {
    _sshd_dropin_check 1

    run _ssh_write_hardening_config "ThisIsNotADirective yes"
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "ssh write: no temp file survives a rejected drop-in" {
    _sshd_dropin_check 1
    _ssh_write_hardening_config "ThisIsNotADirective yes" || true

    local leaked=("$BATS_TEST_TMPDIR"/vpssec-sshd.*)
    # A literal, unmatched glob is bash's "no such file" answer.
    [ ! -e "${leaked[0]}" ]
}

@test "ssh write: the staging file is gone after a successful install too" {
    _ssh_write_hardening_config "PasswordAuthentication no"

    local leaked=("$BATS_TEST_TMPDIR"/vpssec-sshd.*)
    [ ! -e "${leaked[0]}" ]
    # ...because it was moved into place, not because it was never created.
    [ -f "$SSH_HARDENING_DROPIN" ]
}

@test "ssh write: an existing drop-in is backed up before being replaced" {
    printf 'X11Forwarding no\n' > "$SSH_HARDENING_DROPIN"
    _vpssec_begin_backup_session

    _ssh_write_hardening_config "PasswordAuthentication no"
    [ -n "$SSH_LAST_DROPIN_BACKUP" ]
    [ "$SSH_LAST_DROPIN_BACKUP" != "NEW" ]
    grep -q 'X11Forwarding no' "$SSH_LAST_DROPIN_BACKUP"
}

@test "ssh write: a first-run drop-in is registered for deletion on rollback" {
    # backup_file records a not-yet-existing path in .vpssec_created, so a
    # plan-level rollback DELETES it. Without this the created drop-in
    # survived "rollback" and SSH stayed hardened after the user undid it.
    _vpssec_begin_backup_session

    _ssh_write_hardening_config "PasswordAuthentication no"
    [ "$SSH_LAST_DROPIN_BACKUP" = "NEW" ]
    grep -qxF "$SSH_HARDENING_DROPIN" "$VPSSEC_BACKUP_SESSION/.vpssec_created"
}

# ---- _ssh_rollback_dropin --------------------------------------------

@test "ssh rollback: a newly created drop-in is deleted" {
    _vpssec_begin_backup_session
    _ssh_write_hardening_config "PasswordAuthentication no"

    _ssh_rollback_dropin
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "ssh rollback: a replaced drop-in is restored with its old content" {
    printf 'X11Forwarding no\n' > "$SSH_HARDENING_DROPIN"
    _vpssec_begin_backup_session
    _ssh_write_hardening_config "PasswordAuthentication no"

    _ssh_rollback_dropin
    grep -q 'X11Forwarding no' "$SSH_HARDENING_DROPIN"
    _vpssec_refute grep -q 'PasswordAuthentication no' "$SSH_HARDENING_DROPIN"
    [ "$(stat -c '%a' "$SSH_HARDENING_DROPIN")" = "644" ]
}

# ---- _ssh_reload_safe: the precedence trap ---------------------------

@test "ssh reload: succeeds when the merged config confirms the new value" {
    _sshd_effective "passwordauthentication no"
    run _ssh_reload_safe PasswordAuthentication no
    [ "$status" -eq 0 ]
}

@test "ssh reload: a drop-in that lost the merge is a FAILURE, not a success" {
    # The file written, sshd -t passed and the reload succeeded, yet the effective
    # value can still be `yes` because another drop-in sorts earlier. Reporting
    # success there is how an SSH fix silently does nothing on a cloud image.
    _vpssec_begin_backup_session
    _ssh_write_hardening_config "PasswordAuthentication no"
    _sshd_effective "passwordauthentication yes"

    run _ssh_reload_safe PasswordAuthentication no
    [ "$status" -eq 1 ]
}

@test "ssh reload: losing the merge also rolls the drop-in back" {
    _vpssec_begin_backup_session
    _ssh_write_hardening_config "PasswordAuthentication no"
    _sshd_effective "passwordauthentication yes"

    _ssh_reload_safe PasswordAuthentication no || true
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "ssh reload: an unanswerable sshd -T fails closed" {
    # No dump at all (sshd gone, or refusing to print). "Could not confirm"
    # must not be read as "confirmed".
    _vpssec_begin_backup_session
    _ssh_write_hardening_config "PasswordAuthentication no"
    _sshd_effective ""

    run _ssh_reload_safe PasswordAuthentication no
    [ "$status" -eq 1 ]
}

@test "ssh reload: full-context validation failure rolls back" {
    # The drop-in parses in isolation but breaks the merged config — the
    # state that blocks sshd on the next restart if left on disk.
    _vpssec_begin_backup_session
    _ssh_write_hardening_config "PasswordAuthentication no"
    _sshd_fullcontext_check 1

    run _ssh_reload_safe PasswordAuthentication no
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "ssh reload: no assertion pairs means no assertion" {
    # Callers that pass no key/value simply want the reload.
    _sshd_effective "passwordauthentication yes"
    run _ssh_reload_safe
    [ "$status" -eq 0 ]
}

# ---- _ssh_verify_effective -------------------------------------------

@test "ssh verify: keyword and value compare case-insensitively" {
    _sshd_effective "permitrootlogin No"
    run _ssh_verify_effective PermitRootLogin no
    [ "$status" -eq 0 ]
}

@test "ssh verify: a different value is a mismatch" {
    _sshd_effective "permitrootlogin yes"
    run _ssh_verify_effective PermitRootLogin no
    [ "$status" -ne 0 ]
}

@test "ssh verify: a keyword sshd never reports is a mismatch" {
    _sshd_effective "permitrootlogin no"
    run _ssh_verify_effective PasswordAuthentication no
    [ "$status" -ne 0 ]
}

# ---- _ssh_migrate_legacy_dropin --------------------------------------

@test "ssh migrate: the legacy 99- drop-in becomes the 00- one" {
    printf 'X11Forwarding no\n' > "$SSH_HARDENING_DROPIN_LEGACY"

    _ssh_migrate_legacy_dropin
    [ ! -e "$SSH_HARDENING_DROPIN_LEGACY" ]
    grep -q 'X11Forwarding no' "$SSH_HARDENING_DROPIN"
}

@test "ssh migrate: an existing 00- drop-in is never clobbered" {
    printf 'X11Forwarding no\n'   > "$SSH_HARDENING_DROPIN_LEGACY"
    printf 'MaxAuthTries 4\n'     > "$SSH_HARDENING_DROPIN"

    _ssh_migrate_legacy_dropin
    grep -q 'MaxAuthTries 4' "$SSH_HARDENING_DROPIN"
    [ -e "$SSH_HARDENING_DROPIN_LEGACY" ]
}

@test "ssh migrate: nothing to migrate is a no-op" {
    run _ssh_migrate_legacy_dropin
    [ "$status" -eq 0 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

# ---- the backup contract ---------------------------------------------

@test "hardening drop-in: a backup that cannot be taken aborts the write" {
    _vpssec_begin_backup_session
    printf '# existing\n' > "$SSH_HARDENING_DROPIN"
    _vpssec_stub cp 1

    run _ssh_write_hardening_config "PasswordAuthentication no"
    [ "$status" -ne 0 ]
    [ "$(cat "$SSH_HARDENING_DROPIN")" = "# existing" ]
}

@test "hardening drop-in: a first-run backup that cannot be recorded aborts the write" {
    # The other branch: with no drop-in yet, backup_file registers the path as
    # fix-created instead of snapshotting it, and that registration is what a
    # rollback needs in order to delete the file.
    _vpssec_begin_backup_session
    mkdir -p "$VPSSEC_BACKUP_SESSION/$VPSSEC_CREATED_MANIFEST"
    rm -f "$SSH_HARDENING_DROPIN"

    run _ssh_write_hardening_config "PasswordAuthentication no"
    [ "$status" -ne 0 ]
    [ ! -f "$SSH_HARDENING_DROPIN" ]
}
