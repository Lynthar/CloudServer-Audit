#!/usr/bin/env bats
# What the SSH audit says when it cannot judge: no sshd at all, or an sshd that
# cannot print its effective configuration. Neither may grade defaults or the
# files' text as if sshd had answered.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    etc=$(_vpssec_fake_etc)
    SSH_CONFIG="$etc/ssh/sshd_config"
    SSH_DROPIN_DIR="$etc/ssh/sshd_config.d"
    mkdir -p "$SSH_DROPIN_DIR"
    printf 'Include %s/*.conf\n' "$SSH_DROPIN_DIR" > "$SSH_CONFIG"
    sudo_admin_users() { echo root; }
    get_ssh_ports() { echo 22; }
}

# An sshd whose -T fails the way a bad drop-in makes it fail; sshd ends the
# lines it writes to stderr with \r\n.
_silent_sshd() {
    _vpssec_stub_script sshd <<'SH'
[[ "$1" == -T ]] || exit 0
printf '%s\r\n' "/etc/ssh/sshd_config.d/70-typo.conf: line 1: Bad configuration option: ThisIsNotADirective" \
    "terminating, 1 bad configuration options" >&2
exit 255
SH
}

_ids() { jq -r '.[] | "\(.id) \(.status)"' "$VPSSEC_STATE/checks.json"; }

# As audit_module runs it: in a condition, so errexit is off as in production.
_audit() { if ssh_audit; then :; fi; }

@test "ssh audit: without sshd there is one unscored finding and no verdict" {
    _vpssec_absent_command sshd

    _audit
    [ "$(_ids)" = "ssh.not_installed passed" ]
    [ "$(checks_with_scoring | jq -r '.[0].scored')" = false ]
}

@test "ssh audit: an sshd that cannot print its config is named, and the audit is incomplete" {
    _silent_sshd
    _dropin() { printf '%s\n' "${@:2}" > "$SSH_DROPIN_DIR/$1"; }
    _dropin 50-a.conf 'PasswordAuthentication yes'
    _dropin 60-b.conf 'PasswordAuthentication no'

    _audit
    [ "$(_ids)" = "ssh.config_unreadable failed" ]
    [ "$(jq -r '.[0].desc' "$VPSSEC_STATE/checks.json")" = \
      "sshd -T failed, so no SSH setting could be judged: /etc/ssh/sshd_config.d/70-typo.conf: line 1: Bad configuration option: ThisIsNotADirective" ]
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" ssh "* ]]
}

@test "ssh audit: an sshd that answers is audited and the module completes" {
    _vpssec_stub_sshd_merging

    _audit
    _ids | grep -qx 'ssh.password_auth_enabled failed'
    _vpssec_refute grep -q 'config_unreadable\|not_installed' <<<"$(_ids)"
    [ "${#VPSSEC_MODULES_FAILED[@]}" -eq 0 ]
}

@test "ssh config: a silent sshd gives the default and status 1, never a value from the files" {
    # The files say "no" last and "yes" first; sshd takes the first. Reading
    # them instead of asking sshd answered "no".
    _silent_sshd
    printf 'PasswordAuthentication yes\n' > "$SSH_DROPIN_DIR/50-a.conf"
    printf 'PasswordAuthentication no\n' > "$SSH_DROPIN_DIR/60-b.conf"

    run _ssh_get_config PasswordAuthentication yes
    [ "$status" -eq 1 ]
    [ "$output" = "yes" ]
}

@test "ssh config: a keyword sshd leaves out is its default, status 0" {
    _vpssec_stub_sshd_merging
    printf 'AllowUsers deploy\n' > "$SSH_DROPIN_DIR/50-a.conf"
    run _ssh_get_config AllowUsers ""
    [ "$status" -eq 0 ]
    [ "$output" = "deploy" ]

    rm "$SSH_DROPIN_DIR/50-a.conf"
    run _ssh_get_config AllowUsers ""
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "ssh algorithms: the fix's check fails when sshd cannot say what it offers" {
    _silent_sshd
    run _ssh_weak_algorithms
    [ "$status" -eq 1 ]
    _vpssec_refute _ssh_algorithms_ok
}
