#!/usr/bin/env bats
# sudo_admin_users is the one answer to "who can become root through sudo":
# the users audit, the ssh audit and both ssh lockout gates read it. Anything
# it lists must really reach root, or a gate clears a change that locks out.

load helpers.bash

setup() {
    _vpssec_load
    local d="$BATS_TEST_TMPDIR"
    SUDOERS_FILE="$d/sudoers"
    _DROPINS="$d/sudoers.d"
    mkdir -p "$_DROPINS"
    printf 'Defaults\tenv_reset\nroot\tALL=(ALL:ALL) ALL\n%%sudo\tALL=(ALL:ALL) ALL\n@includedir %s\n' \
        "$_DROPINS" > "$SUDOERS_FILE"

    export FAKE_PASSWD="$d/passwd" FAKE_GROUP="$d/group"
    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'alice:x:1000:1000::/home/alice:/bin/bash' \
        'bob:x:1001:27::/home/bob:/bin/bash' 'zabbix:x:1002:1002::/var/lib/zabbix:/bin/bash' \
        'deploy:x:1003:1003::/home/deploy:/bin/bash' 'carol:x:1004:1004::/home/carol:/bin/bash' \
        'dave:x:1005:1005::/home/dave:/bin/bash' 'erin:x:1006:1006::/home/erin:/bin/bash' > "$FAKE_PASSWD"
    printf '%s\n' 'sudo:x:27:alice' 'ops:x:2000:deploy' > "$FAKE_GROUP"
    _vpssec_stub_script getent <<'SH'
case "$1" in
    passwd) f="$FAKE_PASSWD" ;;
    group)  f="$FAKE_GROUP" ;;
    *) exit 2 ;;
esac
[[ -z "${2:-}" ]] && { cat "$f"; exit 0; }
# By name, or by number as glibc's getent also answers.
awk -F: -v k="$2" '$1 == k || $3 == k { print; found = 1; exit } END { exit !found }' "$f"
SH
    # Classic sudo unless a test says otherwise, whatever the host runs.
    _vpssec_stub sudo 0 'Sudo version 1.9.16'
}

_rule() {
    printf '%s\n' "$2" > "$_DROPINS/$1"
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
    [ "$status" -eq 0 ]
    [[ "$output" != *deploy* ]]
}

@test "a command-restricted rule is not a way to root" {
    _rule 90-zabbix 'zabbix ALL=(ALL) NOPASSWD: /usr/bin/zabbix_get'
    run sudo_admin_users
    [ "$status" -eq 0 ]
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
    [ "$status" -eq 0 ]
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

# ---- the forms sudo reads that a line-by-line regex did not ---------------
# Expected answers are sudo's own: `sudo -l -U` and `sudo -n true` per account
# on Debian 12's sudo 1.9.13 with the same rules.

@test "a comma list grants every account in it" {
    _rule 90-pair 'carol, dave ALL=(ALL) ALL'
    run sudo_admin_users
    [[ "$output" == *carol* && "$output" == *dave* ]]
}

@test "a User_Alias grants its members, groups included, and is not itself a user" {
    _rule 90-alias 'User_Alias ADMINS = carol, %ops'
    _rule 91-admins 'ADMINS ALL=(ALL) NOPASSWD: ALL'
    run sudo_admin_users
    [ "$status" -eq 0 ]
    [[ "$output" == *carol* && "$output" == *deploy* && "$output" != *ADMINS* ]]
    sudo_nopasswd_admin carol
    sudo_nopasswd_admin deploy
}

@test "#uid is an account, not a comment" {
    _rule 90-uid '#1004 ALL=(ALL) NOPASSWD: ALL'
    run sudo_admin_users
    [[ "$output" == *carol* ]]
    sudo_nopasswd_admin carol
}

@test "NOPASSWD with a space before its colon is still NOPASSWD" {
    _rule 90-dave 'dave ALL=(ALL) NOPASSWD : ALL'
    sudo_nopasswd_admin dave
}

@test "@include reaches a file outside sudoers.d; sudoers.d unread when not included" {
    printf 'erin ALL=(ALL) NOPASSWD: ALL\n' > "$BATS_TEST_TMPDIR/sudoers.local"
    printf '@include %s\n' "$BATS_TEST_TMPDIR/sudoers.local" >> "$SUDOERS_FILE"
    sudo_nopasswd_admin erin

    _rule 90-deploy 'deploy ALL=(ALL) ALL'
    printf 'root ALL=(ALL:ALL) ALL\n' > "$SUDOERS_FILE"
    run sudo_admin_users
    [ "$output" = "root" ]
}

@test "Defaults !authenticate, per user or for root, makes an untagged grant passwordless" {
    _rule 90-erin 'erin ALL=(ALL) ALL'
    _vpssec_refute sudo_nopasswd_admin erin
    _rule 80-defaults 'Defaults:erin !authenticate'
    sudo_nopasswd_admin erin
    _vpssec_refute sudo_nopasswd_admin alice
    _rule 80-defaults 'Defaults>root !authenticate'
    sudo_nopasswd_admin erin
    _rule 80-defaults 'Defaults>www-data !authenticate'
    _vpssec_refute sudo_nopasswd_admin erin
}

@test "on sudo-rs, Defaults !authenticate decides nothing: the password is still asked" {
    # sudo-rs has no authenticate setting: it warns of an unknown setting and asks.
    _vpssec_stub sudo 0 'sudo-rs 0.2.13-0ubuntu1.2'
    _rule 80-defaults 'Defaults:erin !authenticate'
    _rule 90-erin 'erin ALL=(ALL) ALL'
    _vpssec_refute sudo_nopasswd_admin erin
    run sudo_admin_users
    [[ "$output" == *erin* ]]
}

@test "a runas Defaults is applied after a user one, as in sudo" {
    printf 'Defaults:erin authenticate\nDefaults>root !authenticate\n' > "$_DROPINS/80-defaults"
    _rule 90-erin 'erin ALL=(ALL) ALL'
    sudo_nopasswd_admin erin
}

@test "a Cmnd_Alias holding ALL is a grant of every command" {
    _rule 90-cmnd 'Cmnd_Alias EVERYTHING = /bin/ls, ALL'
    _rule 91-dave 'dave ALL=(ALL) NOPASSWD: EVERYTHING'
    sudo_nopasswd_admin dave
    _rule 90-cmnd 'Cmnd_Alias EVERYTHING = /bin/ls, !ALL'
    run sudo_admin_users
    [ "$status" -eq 0 ]
    [[ "$output" != *dave* ]]
}

@test "a PASSWD tag wins over Defaults !authenticate, a later user Defaults over a global one" {
    _rule 80-defaults 'Defaults !authenticate'
    _rule 90-erin 'erin ALL=(ALL) PASSWD: ALL'
    _vpssec_refute sudo_nopasswd_admin erin
    _rule 90-erin 'erin ALL=(ALL) ALL'
    sudo_nopasswd_admin erin
    printf 'Defaults !authenticate\nDefaults:erin authenticate\n' > "$_DROPINS/80-defaults"
    _vpssec_refute sudo_nopasswd_admin erin
}

@test "NOPASSWD in a trailing comment is a comment" {
    _rule 90-carol 'carol ALL=(ALL) ALL # NOPASSWD: removed last week'
    run sudo_admin_users
    [[ "$output" == *carol* ]]
    _vpssec_refute sudo_nopasswd_admin carol
}

@test "the last grant naming an account decides, as in sudo" {
    # deploy is in ops: NOPASSWD first, then %ops asks for the password.
    _rule 90-deploy 'deploy ALL=(ALL) NOPASSWD: ALL'
    _rule 95-ops '%ops ALL=(ALL) ALL'
    _vpssec_refute sudo_nopasswd_admin deploy
    _rule 85-ops '%ops ALL=(ALL) ALL'
    rm "$_DROPINS/95-ops"
    sudo_nopasswd_admin deploy
}

@test "@includedir is read in byte order, as sudo reads it, whatever the locale" {
    # sudo sorts with strcmp, Ops before admins; en_US.UTF-8 puts admins first.
    locale -a 2>/dev/null | grep -ix 'en_US.utf-\?8' >/dev/null || skip "no en_US.UTF-8 locale"
    _rule Ops 'deploy ALL=(ALL) NOPASSWD: ALL'
    _rule admins 'deploy ALL=(ALL) ALL'
    LC_ALL=en_US.UTF-8 _vpssec_refute sudo_nopasswd_admin deploy
    _rule Ops 'deploy ALL=(ALL) ALL'
    _rule admins 'deploy ALL=(ALL) NOPASSWD: ALL'
    LC_ALL=en_US.UTF-8 sudo_nopasswd_admin deploy
}

@test "a continued line is one rule; a tag carries to the next command" {
    printf 'carol ALL=(ALL) NOPASSWD: /bin/ls, \\\n    ALL\n' > "$_DROPINS/90-carol"
    sudo_nopasswd_admin carol
}

@test "runas only as a group runs as the invoking user, not root" {
    _rule 90-carol 'carol ALL=(:ALL) NOPASSWD: ALL'
    run sudo_admin_users
    [ "$status" -eq 0 ]
    [[ "$output" != *carol* ]]
}

@test "a negated name is taken out of the list" {
    _rule 90-all '%ops, carol, !carol ALL=(ALL) ALL'
    run sudo_admin_users
    [ "$status" -eq 0 ]
    [[ "$output" == *deploy* && "$output" != *carol* ]]
}

@test "oracle: the parse agrees with cvtsudoers on who holds which grant" {
    command -v cvtsudoers >/dev/null 2>&1 || skip "cvtsudoers not installed"
    command -v jq >/dev/null 2>&1 || skip "jq not installed"
    # cvtsudoers refuses an included directory not owned by root.
    [ "$(id -u)" = 0 ] || skip "cvtsudoers reads only root-owned includes"
    _rule 90-a 'User_Alias A = carol, %ops, #1006'
    _rule 91-a 'A ALL=(ALL) NOPASSWD : ALL'
    _rule 92-b 'dave, bob ALL=(root) ALL, PASSWD: /bin/ls'
    _rule 93-c 'alice ALL=(www-data) NOPASSWD: ALL'
    printf 'kim ALL=(ALL) \\\n  NOPASSWD: ALL\n' > "$_DROPINS/94-d"
    chmod 0440 "$SUDOERS_FILE" "$_DROPINS"/*

    # "<principal> <N|P|->" for every grant of ALL as root; aliases expanded.
    local ours theirs
    ours=$(_sudoers_records | awk -F'\t' '$1 == "G" { n = split($3, p, ","); for (i = 1; i <= n; i++) print substr(p[i], 2), $4 }' | sort)
    theirs=$(cvtsudoers -e -f json "$SUDOERS_FILE" 2>/dev/null | jq -r '
        .User_Specs[] | . as $s | .Cmnd_Specs[]
        | select(any(.Commands[]; .command == "ALL" and (.negated | not)))
        | select((.runasusers // [{username: "root"}]) | any(.username == "ALL" or .username == "root"))
        | ((.Options // []) | map(select(has("authenticate"))) | last | .authenticate) as $a
        | ($a | if . == false then "N" elif . == true then "P" else "-" end) as $t
        | $s.User_List[]
        | if .username then .username elif .usergroup then "%" + .usergroup
          else "#\(.userid)" end
        | "\(.) \($t)"' | sort)
    [ -n "$theirs" ]
    [ "$ours" = "$theirs" ]
}
