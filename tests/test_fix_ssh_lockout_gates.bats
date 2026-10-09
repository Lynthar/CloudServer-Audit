#!/usr/bin/env bats
# The two gates between a user and being locked out of their own server:
# disabling password authentication, and disabling root login. Each is safe
# alone and fatal with the other, so both must check a surviving way back in.

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
    _vpssec_stub_sshd_merging

    # Never start a real rescue daemon; record that it was opened and is up.
    _ssh_open_rescue_port() { touch "$BATS_TEST_TMPDIR/rescue-opened" "$BATS_TEST_TMPDIR/rescue-up"; }
    _ssh_close_rescue_port() { rm -f "$BATS_TEST_TMPDIR/rescue-up"; }
    get_current_ssh_ip() { echo "203.0.113.9"; }

    # Default: the operator says yes at the critical prompt, so a refusal in
    # the tests below can only have come from a gate.
    confirm_critical() { return 0; }

    _install_world
}

# The gate's inputs (sudo grants, keys, password hashes, sshd settings), so its
# own predicates run for real. Globals, not locals closed over: by call time a
# local is out of scope and `set -u` aborts, which reads as the gate refusing.
_TEST_ADMINS=""
_TEST_KEYED=""
_TEST_PASSWORDS=""
_TEST_NOPASSWD=""
_TEST_PUBKEY="on"
_TEST_PASSWORD_AUTH="on"

_install_world() {
    sudo_admin_users()           { printf '%s\n' root ${_TEST_ADMINS:-}; }
    # shellcheck disable=SC2317
    sudo_nopasswd_admin()        { [[ " ${_TEST_NOPASSWD} " == *" $1 "* ]]; }
    _ssh_user_has_key()          { [[ " ${_TEST_KEYED} " == *" $1 "* ]]; }
    _ssh_password_usable()       { [[ " ${_TEST_PASSWORDS} " == *" $1 "* ]]; }
    _ssh_pubkey_enabled()        { [[ "$_TEST_PUBKEY" == on ]]; }
    _ssh_password_auth_enabled() { [[ "$_TEST_PASSWORD_AUTH" == on ]]; }
}

# By default every admin has a usable password, so sudo works for them.
_admins_are()         { _TEST_ADMINS="$*"; _TEST_PASSWORDS="$*"; }
_users_with_keys()    { _TEST_KEYED="$*"; }
_with_passwords()     { _TEST_PASSWORDS="$*"; }
_nopasswd_for()       { _TEST_NOPASSWD="$*"; }
_pubkey_auth()        { _TEST_PUBKEY="$1"; }
_password_auth()      { _TEST_PASSWORD_AUTH="$1"; }
# Root's key is usable unless PermitRootLogin says no; both halves are real.
_root_can_key_login() {
    if [[ "$1" == yes ]]; then
        _TEST_KEYED="$_TEST_KEYED root"
    else
        _TEST_KEYED="$_TEST_KEYED root"
        printf 'PermitRootLogin no\n' > "$SSH_DROPIN_DIR/50-test.conf"
    fi
}

# ---- disable password authentication ---------------------------------

@test "password-off gate: refuses when nobody holds a usable key" {
    _admins_are alice
    _users_with_keys

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
    # Legitimate on a fresh cloud image with no admin yet — the operator is told
    # the path back in is fragile. helpers.bash sets VPSSEC_QUIET_SCAN=1, which
    # swallows print_warn; turn it back on for this one assertion.
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
    [ -e "$BATS_TEST_TMPDIR/rescue-opened" ]
    [ ! -e "$BATS_TEST_TMPDIR/rescue-up" ]
}

@test "password-off gate: refuses while public key authentication is off" {
    # Keys on disk are no way in when sshd will not offer publickey: with
    # passwords off too, sshd would accept no method at all.
    _admins_are alice
    _users_with_keys alice root
    _pubkey_auth off

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "password-off gate: a keyed admin who cannot pass sudo is not enough" {
    _admins_are alice
    _with_passwords
    _users_with_keys alice

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
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

@test "root-off gate: a keyless admin with a usable password is enough while passwords work" {
    _admins_are alice
    _users_with_keys
    _password_auth on

    run _ssh_fix_disable_root_login
    [ "$status" -eq 0 ]
    grep -q '^PermitRootLogin no$' "$SSH_HARDENING_DROPIN"
}

@test "root-off gate: an admin with neither a usable password nor a key is refused" {
    # `useradd -G sudo alice` and nothing else: the shadow hash is `!`, there
    # is no key, so once root is refused nobody can log in at all.
    _admins_are alice
    _with_passwords
    _users_with_keys
    _password_auth on

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "root-off gate: a key-only admin who cannot pass sudo is refused" {
    # Logs in by key, but sudo asks for a password the account does not have.
    _admins_are alice
    _with_passwords
    _users_with_keys alice
    _password_auth on

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]

    # A NOPASSWD grant is the other way through sudo (the cloud-image shape).
    _nopasswd_for alice
    run _ssh_fix_disable_root_login
    [ "$status" -eq 0 ]
}

@test "root-off gate: an admin whose account cannot log in is refused" {
    _admins_are dave
    _ssh_account_can_login() { [[ "$1" != dave ]]; }

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "root-off gate: root itself never counts as the admin who survives" {
    # sudo_admin_users lists root too; root with a password and a key is
    # exactly the account this change shuts out.
    _admins_are
    _with_passwords root
    _users_with_keys root
    _password_auth on

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
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

@test "root-off gate: declining the rescue-port confirmation changes nothing" {
    _admins_are alice
    _users_with_keys alice
    confirm_critical() { return 1; }

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
    [ -e "$BATS_TEST_TMPDIR/rescue-opened" ]
    [ ! -e "$BATS_TEST_TMPDIR/rescue-up" ]
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

# ---- the password half of the predicate --------------------------------

@test "a usable password is a real hash; locked, starred or empty is none" {
    unset -f _ssh_password_usable
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    _vpssec_stub_script getent <<'SH'
case "$2" in
    alice) echo 'alice:$y$j9T$abc$def:19000:0:99999:7:::' ;;
    bob)   echo 'bob:!$y$j9T$abc$def:19000:0:99999:7:::' ;;
    carol) echo 'carol:*:19000:0:99999:7:::' ;;
    dave)  echo 'dave::19000:0:99999:7:::' ;;
    *) exit 2 ;;
esac
SH
    _ssh_password_usable alice
    _vpssec_refute _ssh_password_usable bob
    _vpssec_refute _ssh_password_usable carol
    _vpssec_refute _ssh_password_usable dave
    _vpssec_refute _ssh_password_usable nobody-here
}
