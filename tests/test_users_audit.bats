#!/usr/bin/env bats
# users_audit end to end on fixture account databases: the sudo findings read
# sudoers as sudo does, and the shell, home, faillog and pwquality findings
# report what the distribution really ships rather than a Debian-shaped guess.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    VPSSEC_CLOUD_PROVIDER=unknown
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/users.sh"

    local d="$BATS_TEST_TMPDIR"
    USERS_SHADOW_FILE="$d/shadow"; : > "$USERS_SHADOW_FILE"
    USERS_LOGIN_DEFS="$d/login.defs"; : > "$USERS_LOGIN_DEFS"
    USERS_PWQUALITY_CONF="$d/pwquality.conf"
    SUDOERS_FILE="$d/sudoers"
    printf 'root ALL=(ALL:ALL) ALL\n' > "$SUDOERS_FILE"

    export FAKE_PASSWD="$d/passwd" FAKE_GROUP="$d/group"
    printf '%s\n' 'root:x:0:0::/root:/bin/bash' > "$FAKE_PASSWD"
    : > "$FAKE_GROUP"
    _vpssec_stub_script getent <<'SH'
case "$1" in
    passwd) f="$FAKE_PASSWD" ;;
    group)  f="$FAKE_GROUP" ;;
    *) exit 2 ;;
esac
[[ -z "${2:-}" ]] && { cat "$f"; exit 0; }
awk -F: -v k="$2" '$1 == k || $3 == k { print; found = 1; exit } END { exit !found }' "$f"
SH
    # No sshd answers, whatever the host: key files are sshd's defaults.
    _vpssec_stub sshd 255
}

_account() { printf '%s\n' "$@" >> "$FAKE_PASSWD"; }

_desc() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

_emitted() {
    jq -e --arg id "$1" 'any(.[]; .id == $id)' "$VPSSEC_STATE/checks.json" >/dev/null
}

# ---- sudo ------------------------------------------------------------------

_sudo_fixture() {
    _account 'alice:x:1001:1001::/home/alice:/bin/bash' 'bob:x:1002:1002::/home/bob:/bin/bash' \
        'carol:x:1003:1003::/home/carol:/bin/bash' 'dave:x:1004:1004::/home/dave:/bin/bash' \
        'erin:x:1005:1005::/home/erin:/bin/bash' 'frank:x:1006:1006::/home/frank:/bin/bash' \
        'gina:x:1007:1007::/home/gina:/bin/bash' 'hank:x:1008:1008::/home/hank:/bin/bash'
    printf 'frank ALL=(ALL) NOPASSWD: ALL\n' > "$BATS_TEST_TMPDIR/sudoers.local"
    cat >> "$SUDOERS_FILE" <<S
Defaults:erin !authenticate
#1001 ALL=(ALL) NOPASSWD: ALL
bob ALL=(ALL) NOPASSWD : ALL
carol, dave ALL=(ALL) ALL
User_Alias ADMINS = gina
ADMINS ALL=(ALL) ALL
erin ALL=(ALL) ALL
hank ALL=(ALL) ALL # NOPASSWD: removed last week
@include $BATS_TEST_TMPDIR/sudoers.local
S
}

@test "users audit: privileged users are accounts sudo grants, never alias names" {
    _sudo_fixture
    users_audit
    [ "$(_desc users.sudo_users)" = "alice,bob,carol,dave,erin,frank,gina,hank,root" ]
}

@test "users audit: every passwordless rule is named, a NOPASSWD in a comment is not" {
    _sudo_fixture
    users_audit
    local desc
    desc=$(_desc users.nopasswd_sudo)
    [[ "$desc" == *"#1001 ALL=(ALL) NOPASSWD: ALL"* ]]
    [[ "$desc" == *"bob ALL=(ALL) NOPASSWD : ALL"* ]]
    [[ "$desc" == *"sudoers.local: frank ALL=(ALL) NOPASSWD: ALL"* ]]
    [[ "$desc" == *"Defaults:erin !authenticate"* ]]
    [[ "$desc" != *hank* ]]
}

@test "users audit: no passwordless rule, no NOPASSWD finding" {
    _account 'hank:x:1008:1008::/home/hank:/bin/bash'
    printf 'hank ALL=(ALL) ALL # NOPASSWD: removed\n' >> "$SUDOERS_FILE"
    users_audit
    ! _emitted users.nopasswd_sudo
}

# ---- shells and homes ---------------------------------------------------------

@test "users audit: RHEL's shutdown and halt are not login shells" {
    # As Rocky 8/9 and Alma 10 ship them.
    _account 'sync:x:5:0:sync:/sbin:/bin/sync' 'shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown' \
        'halt:x:7:0:halt:/sbin:/sbin/halt'
    users_audit
    ! _emitted users.system_with_shell
}

@test "users audit: a system account with a real shell is still reported" {
    _account 'daemon:x:1:1:daemon:/usr/sbin:/bin/bash' 'games:x:5:60::/usr/games:'
    users_audit
    [ "$(_desc users.system_with_shell)" = "daemon (/bin/bash), games ()" ]
}

@test "users audit: a shell /etc/shells does not list still logs in over ssh" {
    # sshd only needs the shell to exist and run; a planted interpreter counts.
    _account 'daemon:x:1:1:daemon:/usr/sbin:/usr/bin/python3'
    users_audit
    [ "$(_desc users.system_with_shell)" = "daemon (/usr/bin/python3)" ]
}

@test "users audit: nobody's home of / on RHEL and Arch is not unusual" {
    _account 'nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin'
    users_audit
    ! _emitted users.unusual_home
}

@test "users audit: a login account living in / is still unusual" {
    _account 'odd:x:1500:1500::/:/bin/bash'
    users_audit
    [ "$(_desc users.unusual_home)" = "odd:/" ]
}

# ---- login.defs FAILLOG_ENAB ---------------------------------------------------

@test "users audit: LOG_UNKFAIL_ENAB is not asked for (it logs mistyped passwords)" {
    printf 'FAILLOG_ENAB\t\tyes\nLOG_UNKFAIL_ENAB\tno\n' > "$USERS_LOGIN_DEFS"
    users_audit
    ! _emitted users.faillog_disabled
}

@test "users audit: FAILLOG_ENAB no is reported, in login.defs' own format" {
    printf 'FAILLOG_ENAB no\n' > "$USERS_LOGIN_DEFS"
    users_audit
    [ "$(_desc users.faillog_disabled)" = "FAILLOG_ENAB no (should be yes)" ]
}

@test "users audit: the last FAILLOG_ENAB line is the one shadow uses" {
    printf 'FAILLOG_ENAB yes\nFAILLOG_ENAB no\n' > "$USERS_LOGIN_DEFS"
    users_audit
    [ "$(_desc users.faillog_disabled)" = "FAILLOG_ENAB no (should be yes)" ]
}

@test "users audit: a malformed line after a valid yes changes nothing" {
    # shadow skips the malformed line; Debian 12/13 and Rocky 9 checked.
    printf 'FAILLOG_ENAB yes\nFAILLOG_ENAB=no\n' > "$USERS_LOGIN_DEFS"
    users_audit
    ! _emitted users.faillog_disabled
}

@test "users audit: a quoted yes is yes" {
    printf 'FAILLOG_ENAB "yes"\n' > "$USERS_LOGIN_DEFS"
    users_audit
    ! _emitted users.faillog_disabled
}

@test "users audit: a trailing comment is part of the value, so it is not yes" {
    printf 'FAILLOG_ENAB yes # on\n' > "$USERS_LOGIN_DEFS"
    users_audit
    [ "$(_desc users.faillog_disabled)" = "FAILLOG_ENAB yes # on (should be yes)" ]
}

@test "users audit: FAILLOG_ENAB=yes is not a setting and does not pass" {
    printf 'FAILLOG_ENAB=yes\n' > "$USERS_LOGIN_DEFS"
    users_audit
    [ "$(_desc users.faillog_disabled)" = "FAILLOG_ENAB=yes: not a login.defs setting, so FAILLOG_ENAB stays off" ]
}

# ---- pwquality --------------------------------------------------------------

# Expected values are libpwquality 1.4.5's own (python3-pwquality on Debian 12):
# drop-ins in byte order, the main file last and winning.
@test "users audit: pwquality.conf wins over its drop-ins" {
    mkdir -p "$USERS_PWQUALITY_CONF.d"
    printf 'minlen = 6\ndcredit = -1\nucredit = -1\n' > "$USERS_PWQUALITY_CONF"
    printf 'minlen = 14\n' > "$USERS_PWQUALITY_CONF.d/50-site.conf"
    users_audit
    [[ "$(_desc users.pwquality_weak)" == *"minlen=6"* ]]
}

@test "users audit: drop-ins are read in byte order, not the locale's" {
    locale -a 2>/dev/null | grep -ix 'en_US.utf-\?8' >/dev/null || skip "no en_US.UTF-8 locale"
    mkdir -p "$USERS_PWQUALITY_CONF.d"
    printf 'dcredit = -1\nucredit = -1\n' > "$USERS_PWQUALITY_CONF"
    printf 'minlen = 14\n' > "$USERS_PWQUALITY_CONF.d/B-site.conf"
    printf 'minlen = 7\n' > "$USERS_PWQUALITY_CONF.d/a-local.conf"
    LC_ALL=en_US.UTF-8 users_audit
    [[ "$(_desc users.pwquality_weak)" == *"minlen=7"* ]]
}

# ---- one backdoor, one finding --------------------------------------------------

@test "users audit: a second UID 0 account is uid0_found's alone" {
    _account 'toor:x:0:0::/root:/bin/bash' 'svc1:x:1501:1501::/home/svc1:/bin/bash' \
        'svc2:x:1501:1501::/home/svc2:/bin/bash'
    users_audit
    [ "$(_desc users.uid0_found)" = "toor" ]
    # Scored once: no duplicate-UID or system-shell finding for the same account.
    [ "$(_desc users.duplicate_uids)" = "UID=1501:svc1,svc2" ]
    _vpssec_refute _emitted users.system_with_shell
}

# ---- empty passwords --------------------------------------------------------------

@test "users audit: a shadow line with no account behind it is not an empty password" {
    # NIS compat "+" lines and orphans have no passwd entry, so no login.
    _account 'eve:x:1502:1502::/home/eve:/bin/bash'
    printf '+::::::::\nghost::19000:0:99999:7:::\neve::19000:0:99999:7:::\n' > "$USERS_SHADOW_FILE"
    users_audit
    [ "$(_desc users.empty_password)" = "eve" ]
}

# ---- cloud-init default accounts ----------------------------------------------------

@test "users audit: the provider's default user is neither suspicious nor recent" {
    _account "admin:x:1503:1503::$BATS_TEST_TMPDIR/admin:/bin/bash"
    mkdir -p "$BATS_TEST_TMPDIR/admin"
    VPSSEC_CLOUD_PROVIDER=aws VPSSEC_CLOUD_TIER=""
    users_audit
    _vpssec_refute _emitted users.suspicious_names
    _vpssec_refute _emitted users.recent_users
}

@test "users audit: with no recognised provider, admin is still a name to review" {
    _account "admin:x:1503:1503::$BATS_TEST_TMPDIR/admin:/bin/bash" \
        "ubuntu:x:1504:1504::$BATS_TEST_TMPDIR/ubuntu:/bin/bash"
    mkdir -p "$BATS_TEST_TMPDIR/admin" "$BATS_TEST_TMPDIR/ubuntu"
    VPSSEC_CLOUD_PROVIDER=unknown VPSSEC_CLOUD_TIER=""
    users_audit
    [ "$(_desc users.suspicious_names)" = "admin" ]
    [[ "$(_desc users.recent_users)" == *"ubuntu ("* ]]
}

# ---- authorized_keys -----------------------------------------------------------------

# $1 user, $2 key file mode; the account's uid owns its files.
_keyed_account() {
    local me uid home="$BATS_TEST_TMPDIR/home/$1"
    me=$(id -u)
    uid=$me
    (( me == 0 )) && uid=$(( 1600 + $(wc -l < "$FAKE_PASSWD") ))
    _account "$1:x:$uid:$uid::$home:/bin/bash"
    install -d -m 755 "$home" "$home/.ssh"
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample $1@laptop" > "$home/.ssh/authorized_keys"
    chmod "$2" "$home/.ssh/authorized_keys"
    (( me == 0 )) && chown -R "$uid" "$home"
    return 0
}

@test "users audit: a 644 or 400 authorized_keys is what sshd accepts, not a finding" {
    _keyed_account alice 644
    _keyed_account bob 400
    users_audit
    _vpssec_refute _emitted users.ssh_keys_perms
    [[ "$(jq -r '.[] | select(.id == "users.ssh_keys_info") | .title' "$VPSSEC_STATE/checks.json")" == *": 2" ]]
}

@test "users audit: a home others can write is a key-permission finding" {
    _keyed_account alice 600
    chmod 757 "$BATS_TEST_TMPDIR/home/alice"
    users_audit
    _emitted users.ssh_keys_perms
}

@test "users audit: keys are read from the files sshd reads for each user" {
    # AuthorizedKeysFile moved the keys; the fixed ~/.ssh/authorized_keys saw none.
    _keyed_account alice 600
    local home="$BATS_TEST_TMPDIR/home/alice"
    mv "$home/.ssh/authorized_keys" "$home/.ssh/keys"
    _vpssec_stub sshd 0 'authorizedkeysfile .ssh/keys'
    users_audit
    [[ "$(jq -r '.[] | select(.id == "users.ssh_keys_info") | .title' "$VPSSEC_STATE/checks.json")" == *": 1" ]]
}

@test "users audit: an authorized_keys over the size cap is reported, never read" {
    _keyed_account alice 600
    local f="$BATS_TEST_TMPDIR/home/alice/.ssh/authorized_keys"
    truncate -s 2M "$f"
    users_audit
    [[ "$(_desc users.ssh_keys_unread)" == *"$f"* ]]
    _vpssec_refute _emitted users.ssh_keys_info
}

# ---- sudoers syntax ----------------------------------------------------------------------

# visudo -c: $1 is what checking the main file prints (empty: it passes), $2 a
# drop-in that fails on its own. sudo 1.9 names the file holding the error.
_stub_visudo() {
    export VPSSEC_TEST_SUDOERS="$SUDOERS_FILE" VPSSEC_TEST_MAIN_OUT="$1" VPSSEC_TEST_BROKEN="${2:-}"
    _vpssec_stub_script visudo <<'SH'
[[ "$1 $2" == "-c -f" ]] || exit 0
if [[ "$3" == "$VPSSEC_TEST_SUDOERS" && -n "$VPSSEC_TEST_MAIN_OUT" ]]; then
    echo "$VPSSEC_TEST_MAIN_OUT" >&2; exit 1
fi
if [[ -n "$VPSSEC_TEST_BROKEN" && "$3" == "$VPSSEC_TEST_BROKEN" ]]; then
    echo "$3:1:10: syntax error" >&2; exit 1
fi
exit 0
SH
}

@test "users audit: one broken drop-in is named alone, not the sudoers that includes it" {
    mkdir -p "$SUDOERS_FILE.d"
    : > "$SUDOERS_FILE.d/broken"
    _stub_visudo "$SUDOERS_FILE.d/broken:1:10: syntax error" "$SUDOERS_FILE.d/broken"
    users_audit
    [ "$(_desc users.sudoers_syntax_invalid)" = "$SUDOERS_FILE.d/broken syntax invalid" ]
}

@test "users audit: an error in the main sudoers names it" {
    mkdir -p "$SUDOERS_FILE.d"
    _stub_visudo "$SUDOERS_FILE:55:10: syntax error"
    users_audit
    [ "$(_desc users.sudoers_syntax_invalid)" = "$SUDOERS_FILE syntax invalid" ]
}

@test "users audit: a visudo failure naming no file blames the file it checked" {
    mkdir -p "$SUDOERS_FILE.d"
    _stub_visudo "visudo: unable to parse"
    users_audit
    [ "$(_desc users.sudoers_syntax_invalid)" = "$SUDOERS_FILE syntax invalid" ]
}
