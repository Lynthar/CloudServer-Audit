#!/usr/bin/env bats
#
# The two safety gates that stand between a user and being locked out of
# their own server: disabling password authentication, and disabling root
# login. Both refuse to proceed unless a working way back in survives.
#
# The defects these encode:
#
#   - The password-off gate counted root's authorized_keys unconditionally.
#     On a host with PermitRootLogin=no and a keyless sudo admin it passed,
#     and after the change nobody could authenticate at all: the admin had
#     no key, and root was refused by PermitRootLogin.
#   - Disabling root login only required "a sudo user exists". With password
#     auth already off (say an earlier fix in the same plan turned it off),
#     an admin without a key is not a way back in either. The two fixes are
#     individually safe and jointly fatal, in either order.
#
# The gates are the seam under test, so the predicates that feed them
# (which admins exist, who holds a usable key, whether password auth is on)
# are redefined per test. The rescue daemon is stubbed out: it launches a
# real sshd, which a unit test must not do.

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
    export TMPDIR="$BATS_TEST_TMPDIR"

    _vpssec_stub systemctl
    _stub_sshd_honours_dropin

    # Never start a real rescue daemon.
    _ssh_open_rescue_port() { return 0; }
    _ssh_close_rescue_port() { return 0; }
    get_current_ssh_ip() { echo "203.0.113.9"; }

    # Default: the operator says yes at the critical prompt, so a refusal in
    # the tests below can only have come from a gate.
    confirm_critical() { return 0; }

    _install_world
}

# `sshd -T` answers from whatever the module last wrote into the drop-in,
# lowercased the way real sshd prints it. That models a host where our
# drop-in wins the merge — the precondition for a fix to legitimately
# report success. Losing the merge is covered in test_fix_ssh_dropin.bats;
# without a stub like this every "the gate lets it through" assertion would
# fail for the unrelated reason that the effective value never confirmed.
_stub_sshd_honours_dropin() {
    export VPSSEC_TEST_DROPIN="$SSH_HARDENING_DROPIN"
    _vpssec_stub_script sshd <<'SH'
case "$*" in
    *-T*)
        if [[ -f "${VPSSEC_TEST_DROPIN:-}" ]]; then
            grep -v '^#' "$VPSSEC_TEST_DROPIN" | tr '[:upper:]' '[:lower:]'
        fi
        ;;
esac
exit 0
SH
}

# The world the gate sees. State lives in globals rather than being closed
# over: a function defined inside another captures the NAME of a `local`,
# not its value, so by the time the gate calls it the variable is out of
# scope and `set -u` aborts — which looks exactly like the gate refusing.
# Every "the gate refuses" assertion would have passed for the wrong reason.
_TEST_ADMINS=""
_TEST_KEYED=""
_TEST_ROOT_KEY_LOGIN="no"
_TEST_PASSWORD_AUTH="on"

_install_world() {
    _ssh_get_admin_users()      { printf '%s\n' ${_TEST_ADMINS:-}; }
    # shellcheck disable=SC2317
    _ssh_user_has_key()         { [[ " ${_TEST_KEYED} " == *" $1 "* ]]; }
    _ssh_can_login_with_key()   { [[ "$_TEST_ROOT_KEY_LOGIN" == yes ]]; }
    _ssh_password_auth_enabled() { [[ "$_TEST_PASSWORD_AUTH" == on ]]; }
}

_admins_are()         { _TEST_ADMINS="$*"; }
_users_with_keys()    { _TEST_KEYED="$*"; }
_root_can_key_login() { _TEST_ROOT_KEY_LOGIN="$1"; }
_password_auth()      { _TEST_PASSWORD_AUTH="$1"; }

# ---- disable password authentication ---------------------------------

@test "password-off gate: refuses when nobody holds a usable key" {
    _admins_are alice
    _users_with_keys
    _root_can_key_login no

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "password-off gate: root's key does NOT count when root login is refused" {
    # The exact combination that used to pass and then lock everyone out:
    # PermitRootLogin=no, a sudo admin with no key, and a root key sitting in
    # /root/.ssh/authorized_keys that nothing can use.
    _admins_are alice
    _users_with_keys
    _root_can_key_login no

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "password-off gate: a non-root admin with a key is enough" {
    _admins_are alice bob
    _users_with_keys bob
    _root_can_key_login no

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 0 ]
    grep -q '^PasswordAuthentication no$' "$SSH_HARDENING_DROPIN"
}

@test "password-off gate: root's key alone proceeds, but warns" {
    # Legitimate on a fresh cloud image with no admin yet — the operator is
    # told the path back in is fragile. helpers.bash sets VPSSEC_QUIET_SCAN=1
    # to keep test output readable, which also swallows print_warn; turn it
    # back on for this one assertion.
    _admins_are
    _users_with_keys
    _root_can_key_login yes
    export VPSSEC_QUIET_SCAN=0

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 0 ]
    [[ "$output" == *only_root_key_warning* ]]
    grep -q '^PasswordAuthentication no$' "$SSH_HARDENING_DROPIN"
}

@test "password-off gate: declining the rescue-port confirmation changes nothing" {
    _admins_are alice
    _users_with_keys alice
    _root_can_key_login no
    confirm_critical() { return 1; }

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "password-off gate: a rescue daemon that will not start aborts the fix" {
    _admins_are alice
    _users_with_keys alice
    _ssh_open_rescue_port() { return 1; }

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "password-off gate: existing hardening directives are preserved" {
    printf '# vpssec\nX11Forwarding no\nPasswordAuthentication yes\n' > "$SSH_HARDENING_DROPIN"
    _admins_are alice
    _users_with_keys alice

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 0 ]
    grep -q '^X11Forwarding no$' "$SSH_HARDENING_DROPIN"
    # ...and the stale opposite value is gone rather than duplicated.
    [ "$(grep -c '^PasswordAuthentication' "$SSH_HARDENING_DROPIN")" = "1" ]
    grep -q '^PasswordAuthentication no$' "$SSH_HARDENING_DROPIN"
}

# ---- disable root login ----------------------------------------------

@test "root-off gate: refuses when there is no other admin at all" {
    _admins_are
    _password_auth on

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "root-off gate: a keyless admin is enough while passwords still work" {
    _admins_are alice
    _users_with_keys
    _password_auth on

    run _ssh_fix_disable_root_login
    [ "$status" -eq 0 ]
    grep -q '^PermitRootLogin no$' "$SSH_HARDENING_DROPIN"
}

@test "root-off gate: a keyless admin is NOT enough once passwords are off" {
    # The joint-lockout case. Each fix is safe alone; together, in this
    # order, they would leave no authentication path at all.
    _admins_are alice
    _users_with_keys
    _password_auth off

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "root-off gate: an admin with a key is enough with passwords off" {
    _admins_are alice bob
    _users_with_keys bob
    _password_auth off

    run _ssh_fix_disable_root_login
    [ "$status" -eq 0 ]
    grep -q '^PermitRootLogin no$' "$SSH_HARDENING_DROPIN"
}

@test "root-off gate: the reverse apply order is guarded too" {
    # Root login off first, then password auth off. The password-off gate
    # must independently insist on a usable key.
    _admins_are alice
    _users_with_keys
    _password_auth on
    _root_can_key_login no

    run _ssh_fix_disable_root_login
    [ "$status" -eq 0 ]

    _password_auth off
    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    # The root-login hardening from the first step stays; only the second
    # change is refused.
    grep -q '^PermitRootLogin no$' "$SSH_HARDENING_DROPIN"
    _vpssec_refute grep -q '^PasswordAuthentication no$' "$SSH_HARDENING_DROPIN"
}
