#!/usr/bin/env bats
# sudo_admin_users is the one answer to "who can become root through sudo":
# the users audit, the ssh audit and both ssh lockout gates read it. Anything
# it lists must really reach root, or a gate clears a change that locks out.

load helpers.bash

setup() {
    _vpssec_load
    local d="$BATS_TEST_TMPDIR"
    SUDOERS_FILE="$d/sudoers"
    SUDOERS_DIR="$d/sudoers.d"
    mkdir -p "$SUDOERS_DIR"
    printf 'Defaults\tenv_reset\nroot\tALL=(ALL:ALL) ALL\n%%sudo\tALL=(ALL:ALL) ALL\n' > "$SUDOERS_FILE"

    export FAKE_PASSWD="$d/passwd" FAKE_GROUP="$d/group"
    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'alice:x:1000:1000::/home/alice:/bin/bash' \
        'bob:x:1001:27::/home/bob:/bin/bash' 'zabbix:x:1002:1002::/var/lib/zabbix:/bin/bash' \
        'deploy:x:1003:1003::/home/deploy:/bin/bash' > "$FAKE_PASSWD"
    printf '%s\n' 'sudo:x:27:alice' 'ops:x:2000:deploy' > "$FAKE_GROUP"
    _vpssec_stub_script getent <<'SH'
case "$1" in
    passwd) f="$FAKE_PASSWD" ;;
    group)  f="$FAKE_GROUP" ;;
    *) exit 2 ;;
esac
[[ -z "${2:-}" ]] && { cat "$f"; exit 0; }
awk -F: -v k="$2" '$1 == k { print; found = 1 } END { exit !found }' "$f"
SH
}

_rule() {
    printf '%s\n' "$2" > "$SUDOERS_DIR/$1"
}

@test "%sudo grants every member, by secondary and by primary GID" {
    run sudo_admin_users
    [ "$status" -eq 0 ]
    [ "$output" = "$(printf 'alice\nbob\nroot')" ]
}

@test "group membership without a sudoers rule grants nothing" {
    # Arch ships `%wheel ALL=(ALL:ALL) ALL` commented out: wheel members
    # cannot sudo there, and counting them would clear the root-off gate.
    printf 'root\tALL=(ALL:ALL) ALL\n# %%sudo\tALL=(ALL:ALL) ALL\n' > "$SUDOERS_FILE"
    run sudo_admin_users
    [ "$output" = "root" ]
}

@test "a full user rule in a drop-in sudo reads counts" {
    _rule 90-deploy 'deploy ALL=(ALL) ALL'
    run sudo_admin_users
    [[ "$output" == *deploy* ]]
}

@test "a rule in a drop-in sudo ignores does not count" {
    # @includedir skips names with a dot or a trailing tilde.
    _rule 90-deploy.bak 'deploy ALL=(ALL) ALL'
    _rule 91-deploy~ 'deploy ALL=(ALL) ALL'
    run sudo_admin_users
    [[ "$output" != *deploy* ]]
}

@test "a command-restricted rule is not a way to root" {
    _rule 90-zabbix 'zabbix ALL=(ALL) NOPASSWD: /usr/bin/zabbix_get'
    run sudo_admin_users
    [[ "$output" != *zabbix* ]]
}

@test "the Runas list must hold root or ALL" {
    _rule 90-deploy 'deploy ALL=(www-data) ALL'
    run sudo_admin_users
    [[ "$output" != *deploy* ]]

    _rule 90-deploy 'deploy ALL=(root, www-data) NOPASSWD: ALL'
    run sudo_admin_users
    [[ "$output" == *deploy* ]]
}

@test "names that are not accounts drop out: aliases, removed users" {
    _rule 90-alias 'User_Alias ADMINS = deploy'
    _rule 91-admins 'ADMINS ALL=(ALL) ALL'
    _rule 92-ghost 'ghost ALL=(ALL) ALL'
    run sudo_admin_users
    [[ "$output" != *ADMINS* ]]
    [[ "$output" != *ghost* ]]
}

@test "a %group rule grants its members" {
    _rule 90-ops '%ops ALL=(ALL:ALL) ALL'
    run sudo_admin_users
    [[ "$output" == *deploy* ]]
}

@test "a name that is not an account, read last, does not hide earlier grants" {
    # Under pipefail the last line's status was the pipeline's: a dropped
    # name at the end made every NOPASSWD lookup answer no.
    _rule 90-deploy 'deploy ALL=(ALL) NOPASSWD:ALL'
    _rule 99-ghost 'ghost ALL=(ALL) ALL'
    sudo_nopasswd_admin deploy
}

@test "sudo_nopasswd_admin: only a full NOPASSWD grant answers yes" {
    _rule 90-deploy 'deploy ALL=(ALL) NOPASSWD:ALL'
    sudo_nopasswd_admin deploy
    # alice reaches root only through %sudo, which asks for her password.
    _vpssec_refute sudo_nopasswd_admin alice
    _rule 91-zabbix 'zabbix ALL=(ALL) NOPASSWD: /usr/bin/zabbix_get'
    _vpssec_refute sudo_nopasswd_admin zabbix
}
