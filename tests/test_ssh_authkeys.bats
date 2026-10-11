#!/usr/bin/env bats
# Key files judged as sshd's StrictModes judges them: the file and each directory
# up to the home owned by the user (or root), writable by no one else. That
# decides what the audit reports and which keys the password-off gate counts.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    etc=$(_vpssec_fake_etc)
    SSH_CONFIG="$etc/ssh/sshd_config"
    SSH_DROPIN_DIR="$etc/ssh/sshd_config.d"
    mkdir -p "$SSH_DROPIN_DIR"
    printf 'Include %s/*.conf\n' "$SSH_DROPIN_DIR" > "$SSH_CONFIG"
    _vpssec_stub_sshd_merging

    HOMES="$BATS_TEST_TMPDIR/home"
    mkdir -p "$HOMES"
    chmod 755 "$HOMES"
    export VPSSEC_TEST_PASSWD="$BATS_TEST_TMPDIR/passwd" VPSSEC_TEST_GROUP="$BATS_TEST_TMPDIR/group"
    : > "$VPSSEC_TEST_PASSWD"
    : > "$VPSSEC_TEST_GROUP"
    _vpssec_stub_script getent <<'SH'
case "$1" in
    passwd) f="$VPSSEC_TEST_PASSWD" ;;
    group)  f="$VPSSEC_TEST_GROUP" ;;
    *) exit 2 ;;
esac
[[ -z "${2:-}" ]] && { cat "$f"; exit 0; }
awk -F: -v k="$2" '$1 == k || $3 == k { print; found = 1; exit } END { exit !found }' "$f"
SH
    # The files below belong to whoever runs the tests; the fixture accounts own
    # them by uid, as a real user owns their home.
    ME=$(id -u)
    MYGID=$(id -g)
    _TEST_ADMINS=""
    sudo_admin_users() { printf '%s\n' root ${_TEST_ADMINS}; }
}

# $1 user: an account whose uid owns the files (root runs: a uid of its own).
_account() {
    local uid=$ME
    (( ME == 0 )) && uid=$(( 1000 + $(wc -l < "$VPSSEC_TEST_PASSWD") ))
    printf '%s:x:%s:%s::%s:/bin/bash\n' "$1" "$uid" "$MYGID" "$HOMES/$1" >> "$VPSSEC_TEST_PASSWD"
    install -d -m 755 "$HOMES/$1" "$HOMES/$1/.ssh"
    (( ME == 0 )) && chown -R "$uid" "$HOMES/$1"
    return 0
}

# $1 user, $2 file under the home: one key, mode 600.
_key() {
    local f="$HOMES/$1/${2:-.ssh/authorized_keys}"
    mkdir -p "$(dirname "$f")"
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample $1@laptop" > "$f"
    chmod 600 "$f"
    (( ME == 0 )) && chown "$(awk -F: -v u="$1" '$1 == u { print $3 }' "$VPSSEC_TEST_PASSWD")" "$f"
    return 0
}

_finding() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

# ---- the predicate -----------------------------------------------------------

@test "strictmodes: 600 or 400 files and a 700, 750, 711 or 500 .ssh are accepted" {
    _account alice
    _key alice
    local f="$HOMES/alice/.ssh/authorized_keys" m
    for m in 600 400 644; do
        chmod "$m" "$f"
        _vpssec_refute strictmodes_refused_path alice "$f"
    done
    for m in 700 750 711 500; do
        chmod "$m" "$HOMES/alice/.ssh"
        _vpssec_refute strictmodes_refused_path alice "$f"
    done
    chmod 755 "$HOMES/alice/.ssh"   # so bats can clean up as a non-root user
}

@test "strictmodes: a world-writable home is refused, and named" {
    _account alice
    _key alice
    chmod 757 "$HOMES/alice"
    run strictmodes_refused_path alice "$HOMES/alice/.ssh/authorized_keys"
    [ "$status" -eq 0 ]
    [ "$(cut -f1,2 <<<"$output")" = "$HOMES/alice	757" ]
}

@test "strictmodes: the walk stops at the home, as sshd's does" {
    # The fixture's parent directories are the test runner's; above the home
    # sshd does not look, so neither may this.
    _account alice
    _key alice
    chmod 777 "$HOMES"
    _vpssec_refute strictmodes_refused_path alice "$HOMES/alice/.ssh/authorized_keys"
}

@test "strictmodes: group write is refused, except a private group on Debian" {
    _account alice
    _key alice
    local f="$HOMES/alice/.ssh/authorized_keys"
    chmod 664 "$f"
    printf 'alice:x:%s:\n' "$MYGID" > "$VPSSEC_TEST_GROUP"

    VPSSEC_DISTRO_FAMILY=rhel run strictmodes_refused_path alice "$f"
    [ "$status" -eq 0 ]
    VPSSEC_DISTRO_FAMILY=debian run strictmodes_refused_path alice "$f"
    [ "$status" -eq 1 ]

    # One other member, and the group is no longer alice's alone.
    printf 'alice:x:%s:bob\n' "$MYGID" > "$VPSSEC_TEST_GROUP"
    VPSSEC_DISTRO_FAMILY=debian run strictmodes_refused_path alice "$f"
    [ "$status" -eq 0 ]
}

@test "strictmodes: a key file owned by another user is refused" {
    _account alice
    _key alice
    local f="$HOMES/alice/.ssh/authorized_keys"
    if (( ME == 0 )); then
        chown 4242 "$f"
    else
        # Not root: give alice another uid, so the runner's files are foreign.
        sed -i "s/^alice:x:$ME:/alice:x:$(( ME + 1 )):/" "$VPSSEC_TEST_PASSWD"
    fi
    run strictmodes_refused_path alice "$f"
    [ "$status" -eq 0 ]
}

# ---- the password-off gate ----------------------------------------------------

@test "key login: a key sshd refuses under StrictModes does not count" {
    _account alice
    _key alice
    _ssh_user_has_key alice
    chmod 757 "$HOMES/alice"
    _vpssec_refute _ssh_user_has_key alice
    _vpssec_refute _ssh_can_login_with_key alice
}

@test "key login: with StrictModes no, sshd reads that key after all" {
    _account alice
    _key alice
    chmod 757 "$HOMES/alice"
    printf 'StrictModes no\n' > "$SSH_DROPIN_DIR/50-test.conf"
    _ssh_user_has_key alice
}

@test "key login: a key file over the size cap is not read and does not count" {
    _account alice
    _key alice
    truncate -s 2M "$HOMES/alice/.ssh/authorized_keys"
    _vpssec_refute _ssh_user_has_key alice
}

# sshd -T as it answers with a Match User block for $1 that sets the rest of
# the arguments ("keyword value"); every other user gets the defaults.
_sshd_match_user() {
    export VPSSEC_TEST_MATCH_USER="$1"
    shift
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/match-user.out"
    _vpssec_stub_script sshd <<'SH'
[[ "$1" == -T ]] || exit 0
printf '%s\n' "port 22" "listenaddress [::]:22" "listenaddress 0.0.0.0:22" "strictmodes yes"
if [[ "${2:-} ${3:-}" == "-C user=$VPSSEC_TEST_MATCH_USER,"* ]]; then
    cat "$VPSSEC_TEST_TMPDIR/match-user.out"
else
    printf '%s\n' "pubkeyauthentication yes" "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"
fi
SH
    export VPSSEC_TEST_TMPDIR="$BATS_TEST_TMPDIR"
}

@test "key login: the AuthorizedKeysFile a Match User block gives the user is the one read" {
    # Without the user in -C, sshd reports the global value: a key there was
    # counted while sshd, reading another file for this user, refused it.
    _account alice
    _key alice
    _sshd_match_user alice "pubkeyauthentication yes" "authorizedkeysfile .ssh/alice_keys"
    _vpssec_refute _ssh_user_has_key alice

    _key alice .ssh/alice_keys
    _ssh_user_has_key alice
}

@test "key login: a Match User block that turns pubkey off for the user refuses the key" {
    _account alice
    _key alice
    _sshd_match_user alice "pubkeyauthentication no" "authorizedkeysfile .ssh/authorized_keys"
    _vpssec_refute _ssh_can_login_with_key alice
    # Another user is still judged on the global value.
    _account bob
    _key bob
    _ssh_can_login_with_key bob
}

# ---- the audit ----------------------------------------------------------------

@test "authkeys audit: every admin's key file is judged, not only the first admin's" {
    _account alice
    _account bob
    _key alice
    _key bob
    chmod 666 "$HOMES/bob/.ssh/authorized_keys"
    _TEST_ADMINS="alice bob"

    _ssh_audit_admin_user
    [[ "$(_finding ssh.authkeys_permissions)" == *"$HOMES/bob/.ssh/authorized_keys (mode 666"* ]]
}

@test "authkeys audit: the AuthorizedKeysFile sshd uses is the one judged" {
    _account alice
    _key alice .ssh/keys
    chmod 666 "$HOMES/alice/.ssh/keys"
    printf 'AuthorizedKeysFile .ssh/keys\n' > "$SSH_DROPIN_DIR/50-keys.conf"
    _TEST_ADMINS="alice"

    _ssh_audit_admin_user
    [[ "$(_finding ssh.authkeys_permissions)" == *"$HOMES/alice/.ssh/keys (mode 666"* ]]
}

@test "authkeys audit: a home others can write is reported like the file" {
    _account alice
    _key alice
    chmod 757 "$HOMES/alice"
    _TEST_ADMINS="alice"

    _ssh_audit_admin_user
    [[ "$(_finding ssh.authkeys_permissions)" == *"$HOMES/alice (mode 757"* ]]
    # sshd will not take that key, so the admin has none it can use.
    [ -n "$(_finding ssh.admin_no_key)" ]
}

@test "authkeys audit: every admin without a usable key is named, not only the first" {
    _account alice
    _account bob
    _key alice
    _TEST_ADMINS="alice bob"

    _ssh_audit_admin_user
    [ "$(jq -r '.[] | select(.id == "ssh.admin_no_key") | .title' "$VPSSEC_STATE/checks.json")" = \
      "Admins without a usable SSH key: bob" ]
}

@test "authkeys audit: a 400 key file under a 750 .ssh is clean" {
    _account alice
    _key alice
    chmod 400 "$HOMES/alice/.ssh/authorized_keys"
    chmod 750 "$HOMES/alice/.ssh"
    _TEST_ADMINS="alice"

    _ssh_audit_admin_user
    [ -z "$(_finding ssh.authkeys_permissions)" ]
    [ -z "$(_finding ssh.admin_no_key)" ]
    [ -n "$(_finding ssh.admin_user_exists)" ]
}
