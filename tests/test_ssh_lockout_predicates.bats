#!/usr/bin/env bats
# The predicates the two SSH lockout gates stand on, fed what sshd, getent and
# the key files would say. test_fix_ssh_lockout_gates.bats replaces them to
# test how the gates combine them; here nothing in modules/ssh.sh is replaced.

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
    # Debian's stock main file: drop-ins first, then its own two settings.
    printf 'Include %s/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n' \
        "$SSH_DROPIN_DIR" > "$SSH_CONFIG"

    HOMES="$BATS_TEST_TMPDIR/home"
    : > "$BATS_TEST_TMPDIR/passwd"
    : > "$BATS_TEST_TMPDIR/shadow"
    _account root /bin/bash
    _stub_getent
    _vpssec_stub_sshd_merging
    _vpssec_stub systemctl

    # The admin list and NOPASSWD answer are core's, covered by test_sudo_admins.
    _TEST_ADMINS=""
    sudo_admin_users()    { printf '%s\n' root ${_TEST_ADMINS}; }
    sudo_nopasswd_admin() { return 1; }

    # A rescue daemon that only records whether it is up.
    _ssh_open_rescue_port()  { : > "$BATS_TEST_TMPDIR/rescue-up"; }
    _ssh_close_rescue_port() { rm -f "$BATS_TEST_TMPDIR/rescue-up"; }
    get_current_ssh_ip() { echo "203.0.113.9"; }
    confirm_critical() { return 0; }
}

# $1 user, $2 shell, $3 shadow hash (default a usable one), $4 expiry day. A
# non-root runner owns every fixture file, so there each account takes its uid:
# StrictModes refuses a key file its user does not own.
_account() {
    local uid=$(( $(wc -l < "$BATS_TEST_TMPDIR/passwd") + 1000 ))
    [[ "$1" == root ]] && uid=0
    [[ "$(id -u)" != 0 ]] && uid=$(id -u)
    mkdir -p "$HOMES/$1"
    chmod 755 "$HOMES/$1"
    printf '%s:x:%s:%s::%s:%s\n' "$1" "$uid" "$uid" "$HOMES/$1" "$2" >> "$BATS_TEST_TMPDIR/passwd"
    printf '%s:%s:19000:0:99999:7::%s:\n' "$1" "${3-\$y\$j9T\$abc\$def}" "${4:-}" >> "$BATS_TEST_TMPDIR/shadow"
}

# $1 user, $2 file under the home (default .ssh/authorized_keys), rest: lines.
_key() {
    local user="$1" rel="${2:-.ssh/authorized_keys}"
    shift 2 || shift $#
    mkdir -p "$(dirname "$HOMES/$user/$rel")"
    chmod 755 "$(dirname "$HOMES/$user/$rel")"
    if (( $# )); then
        printf '%s\n' "$@" >> "$HOMES/$user/$rel"
    else
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample $user@laptop" >> "$HOMES/$user/$rel"
    fi
    chmod 644 "$HOMES/$user/$rel"
}

_dropin() { printf '%s\n' "${@:2}" > "$SSH_DROPIN_DIR/$1"; }

_stub_getent() {
    export VPSSEC_TEST_PASSWD="$BATS_TEST_TMPDIR/passwd" VPSSEC_TEST_SHADOW="$BATS_TEST_TMPDIR/shadow"
    _vpssec_stub_script getent <<'SH'
case "$1" in
    passwd) f="$VPSSEC_TEST_PASSWD" ;;
    shadow) f="$VPSSEC_TEST_SHADOW" ;;
    *) exit 2 ;;
esac
grep "^$2:" "$f" || exit 2
SH
}

# ---- can this account log in by key ----------------------------------

@test "key login: root's key does not count once PermitRootLogin is no" {
    _key root
    _ssh_can_login_with_key root

    _dropin 50-cloud.conf 'PermitRootLogin no'
    _vpssec_refute _ssh_can_login_with_key root
}

@test "key login: prohibit-password and yes both leave root's key usable" {
    _key root
    _dropin 50-cloud.conf 'PermitRootLogin prohibit-password'
    _ssh_can_login_with_key root
    _dropin 50-cloud.conf 'PermitRootLogin yes'
    _ssh_can_login_with_key root
}

@test "key login: the first drop-in to set PermitRootLogin decides, as in sshd" {
    _key root
    _dropin 10-admin.conf 'PermitRootLogin no'
    _dropin 50-cloud.conf 'PermitRootLogin yes'
    _vpssec_refute _ssh_can_login_with_key root
}

@test "key login: a key is no way in while PubkeyAuthentication is off" {
    _account alice /bin/bash
    _key alice
    _dropin 50-test.conf 'PubkeyAuthentication no'
    _vpssec_refute _ssh_can_login_with_key alice
}

# ---- does this account hold a key sshd will read ----------------------

@test "keys: a commented-out key is not a key" {
    _account alice /bin/bash
    _key alice .ssh/authorized_keys '# ssh-ed25519 AAAAC3Nza rotated-out' ''
    _vpssec_refute _ssh_user_has_key alice
    _key alice
    _ssh_user_has_key alice
}

@test "keys: only the AuthorizedKeysFile sshd uses counts, with %h expanded" {
    _account alice /bin/bash
    _key alice
    _dropin 50-keys.conf 'AuthorizedKeysFile %h/.ssh/keys'
    _vpssec_refute _ssh_user_has_key alice

    _key alice .ssh/keys
    _ssh_user_has_key alice
}

@test "keys: authorized_keys2 still counts under the default AuthorizedKeysFile" {
    _account alice /bin/bash
    _key alice .ssh/authorized_keys2
    _ssh_user_has_key alice
}

# ---- can this account log in at all -----------------------------------

@test "account: a nologin or false shell cannot log in" {
    _account alice /usr/sbin/nologin
    _account bob /bin/false
    _vpssec_refute _ssh_account_can_login alice
    _vpssec_refute _ssh_account_can_login bob
}

@test "account: an expired account cannot log in, one expiring later can" {
    local today=$(( $(date +%s) / 86400 ))
    _account alice /bin/bash '$y$j9T$abc$def' "$(( today - 1 ))"
    _account bob /bin/bash '$y$j9T$abc$def' "$(( today + 30 ))"
    _vpssec_refute _ssh_account_can_login alice
    _ssh_account_can_login bob
}

@test "account: a locked password does not stop a key login" {
    _account alice /bin/bash '!$y$j9T$abc$def'
    _ssh_account_can_login alice
}

# ---- the gates on these inputs ------------------------------------------

@test "password-off gate: PermitRootLogin no, a keyless admin and a root key is refused" {
    # The combination behind the first lockout: root's key sits on disk but
    # sshd refuses root, and the only admin logs in by password alone.
    _account alice /bin/bash
    _TEST_ADMINS="alice"
    _key root
    _dropin 50-cloud.conf 'PermitRootLogin no'

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
    [ ! -e "$BATS_TEST_TMPDIR/rescue-up" ]
}

@test "password-off gate: an admin with a key and a password proceeds and sshd agrees" {
    _account alice /bin/bash
    _TEST_ADMINS="alice"
    _key alice

    run _ssh_fix_disable_password_auth
    [ "$status" -eq 0 ]
    grep -q '^PasswordAuthentication no$' "$SSH_HARDENING_DROPIN"
    [ "$(_ssh_get_config PasswordAuthentication yes)" = "no" ]
    [ ! -e "$BATS_TEST_TMPDIR/rescue-up" ]
}

@test "root-off gate: an admin with a key but a nologin shell is refused" {
    _account alice /usr/sbin/nologin
    _TEST_ADMINS="alice"
    _key alice

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}

@test "root-off gate: an expired admin is refused" {
    local today=$(( $(date +%s) / 86400 ))
    _account alice /bin/bash '$y$j9T$abc$def' "$(( today - 1 ))"
    _TEST_ADMINS="alice"
    _key alice

    run _ssh_fix_disable_root_login
    [ "$status" -eq 1 ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}
