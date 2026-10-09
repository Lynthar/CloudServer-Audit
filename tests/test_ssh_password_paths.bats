#!/usr/bin/env bats
# Every way sshd takes a password, not just PasswordAuthentication: through
# keyboard-interactive, PAM asks pam_unix for the same password. The fix only
# writes PasswordAuthentication, so it must not claim the other path closed.

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
    SSH_HARDENING_DROPIN="$SSH_DROPIN_DIR/00-vpssec-hardening.conf"
    SSH_HARDENING_DROPIN_LEGACY="$SSH_DROPIN_DIR/99-vpssec-hardening.conf"
    mkdir -p "$SSH_DROPIN_DIR"
    export SSHD_T_OUT="$BATS_TEST_TMPDIR/sshd-T.out"
    _vpssec_stub_script sshd <<'SH'
[[ "$1" == -T ]] && cat "$SSHD_T_OUT"
exit 0
SH
}

# What sshd -T reports, one "keyword value" per argument.
_sshd() { printf '%s\n' "$@" > "$SSHD_T_OUT"; }

_check() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | "\(.status) \(.severity) fix=\(.fix_id // "")"' \
        "$VPSSEC_STATE/checks.json"
}

@test "kbd-int through PAM is a password login when PasswordAuthentication is no" {
    # Recorded on Debian 12 (OpenSSH 9.2) with the report's E7 config, where a
    # password logged in over keyboard-interactive.
    _sshd 'passwordauthentication no' 'kbdinteractiveauthentication yes' 'usepam yes' \
        'authenticationmethods any'
    _ssh_audit_password_auth
    [ "$(_check ssh.password_auth_enabled)" = "failed high fix=" ]
    jq -e '.[] | select(.id == "ssh.password_auth_enabled") | .desc | test("keyboard-interactive")' \
        "$VPSSEC_STATE/checks.json" >/dev/null
    _vpssec_refute _ssh_password_auth_disabled
}

@test "kbd-int that every AuthenticationMethods list pairs with a key is not a password login" {
    _sshd 'passwordauthentication no' 'kbdinteractiveauthentication yes' 'usepam yes' \
        'authenticationmethods publickey,keyboard-interactive'
    _ssh_audit_password_auth
    [ "$(_check ssh.password_auth_disabled)" = "passed low fix=" ]
}

@test "one AuthenticationMethods list of keyboard-interactive alone is enough" {
    _sshd 'passwordauthentication no' 'kbdinteractiveauthentication yes' 'usepam yes' \
        'authenticationmethods publickey,keyboard-interactive keyboard-interactive:pam'
    _vpssec_refute _ssh_password_auth_disabled
}

@test "kbd-int without PAM, or switched off, asks for no password" {
    _sshd 'passwordauthentication no' 'kbdinteractiveauthentication yes' 'usepam no'
    _ssh_password_auth_disabled
    _sshd 'passwordauthentication no' 'kbdinteractiveauthentication no' 'usepam yes'
    _ssh_password_auth_disabled
}

@test "PasswordAuthentication yes alone keeps its fix" {
    _sshd 'passwordauthentication yes' 'kbdinteractiveauthentication no' 'usepam yes'
    _ssh_audit_password_auth
    [ "$(_check ssh.password_auth_enabled)" = "failed high fix=ssh.disable_password_auth" ]
}

@test "with the kbd-int path open, the fix is neither offered nor run" {
    _sshd 'passwordauthentication yes' 'kbdinteractiveauthentication yes' 'usepam yes'
    _ssh_audit_password_auth
    [ "$(_check ssh.password_auth_enabled)" = "failed high fix=" ]

    _ssh_open_rescue_port() { touch "$BATS_TEST_TMPDIR/rescue-opened"; return 0; }
    run _ssh_fix_disable_password_auth
    [ "$status" -eq 1 ]
    [[ "$output" == *"keyboard-interactive"* ]]
    [ ! -e "$BATS_TEST_TMPDIR/rescue-opened" ]
    [ ! -e "$SSH_HARDENING_DROPIN" ]
}
