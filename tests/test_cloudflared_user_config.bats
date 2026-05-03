#!/usr/bin/env bats
#
# Regression tests for _cloudflared_find_user_config_from_passwd. The
# original code probed "$HOME/.cloudflared/config.yml" — under sudo
# (audits run as root) $HOME is /root, so user-mode tunnel installs at
# /home/<user>/.cloudflared/config.yml were never seen.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"
    mkdir -p "$BATS_TEST_TMPDIR"
}

@test "user config: alice has config.yml → emitted" {
    mkdir -p "$BATS_TEST_TMPDIR/home/alice/.cloudflared"
    touch "$BATS_TEST_TMPDIR/home/alice/.cloudflared/config.yml"
    local passwd_text="root:x:0:0::/root:/bin/bash
daemon:x:1:1::/usr/sbin:/usr/sbin/nologin
alice:x:1001:1001::$BATS_TEST_TMPDIR/home/alice:/bin/bash"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -eq 0 ]
    [ "$output" = "$BATS_TEST_TMPDIR/home/alice/.cloudflared/config.yml" ]
}

@test "user config: regression — root \$HOME does not contain config but alice's does" {
    # Defensive: simulate the buggy behavior. Even if /root has no
    # ~/.cloudflared, the function should walk to alice and find hers.
    mkdir -p "$BATS_TEST_TMPDIR/home/alice/.cloudflared"
    touch "$BATS_TEST_TMPDIR/home/alice/.cloudflared/config.yml"
    # /root deliberately empty
    local passwd_text="root:x:0:0::$BATS_TEST_TMPDIR/root_empty:/bin/bash
alice:x:1001:1001::$BATS_TEST_TMPDIR/home/alice:/bin/bash"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice"* ]]
}

@test "user config: system users (UID < 1000) skipped" {
    # Even if a system user happened to have ~/.cloudflared/config.yml
    # at their home, we don't probe — system accounts shouldn't run
    # user-mode tunnels.
    mkdir -p "$BATS_TEST_TMPDIR/var/lib/sysuser/.cloudflared"
    touch "$BATS_TEST_TMPDIR/var/lib/sysuser/.cloudflared/config.yml"
    local passwd_text="sysuser:x:101:101::$BATS_TEST_TMPDIR/var/lib/sysuser:/bin/false"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -ne 0 ]
}

@test "user config: no user has the file → exit 1" {
    mkdir -p "$BATS_TEST_TMPDIR/home/alice"
    # alice has a home but no .cloudflared
    local passwd_text="alice:x:1001:1001::$BATS_TEST_TMPDIR/home/alice:/bin/bash"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -ne 0 ]
    [[ -z "$output" ]]
}

@test "user config: first match wins (alice before bob)" {
    mkdir -p "$BATS_TEST_TMPDIR/home/alice/.cloudflared"
    mkdir -p "$BATS_TEST_TMPDIR/home/bob/.cloudflared"
    touch "$BATS_TEST_TMPDIR/home/alice/.cloudflared/config.yml"
    touch "$BATS_TEST_TMPDIR/home/bob/.cloudflared/config.yml"
    local passwd_text="alice:x:1001:1001::$BATS_TEST_TMPDIR/home/alice:/bin/bash
bob:x:1002:1002::$BATS_TEST_TMPDIR/home/bob:/bin/bash"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice"* ]]
    [[ "$output" != *"bob"* ]]
}

@test "user config: malformed UID field (non-numeric) skipped without error" {
    # Defensive: NSS plugins occasionally emit weird entries; don't let
    # `[[ "$uid" -lt 1000 ]]` blow up under set -e.
    mkdir -p "$BATS_TEST_TMPDIR/home/alice/.cloudflared"
    touch "$BATS_TEST_TMPDIR/home/alice/.cloudflared/config.yml"
    local passwd_text="weird:x:abc:1001::/tmp/weird:/bin/bash
alice:x:1001:1001::$BATS_TEST_TMPDIR/home/alice:/bin/bash"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice"* ]]
}

@test "user config: empty home field skipped" {
    mkdir -p "$BATS_TEST_TMPDIR/home/alice/.cloudflared"
    touch "$BATS_TEST_TMPDIR/home/alice/.cloudflared/config.yml"
    local passwd_text="empty:x:1100:1100:::/bin/bash
alice:x:1001:1001::$BATS_TEST_TMPDIR/home/alice:/bin/bash"
    run _cloudflared_find_user_config_from_passwd "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice"* ]]
}
