#!/usr/bin/env bats
# write_template is the one writer for vpssec's own template files (alerts,
# backup, cloudflared, docker). Every failure must reach the caller: a fix runs
# with errexit off, so a lost status ends in "templates generated".

load helpers.bash

setup() {
    _vpssec_load
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    dir="$BATS_TEST_TMPDIR/tpl"
}

@test "write_template: stdin lands at the path, its directory created" {
    run write_template "$dir/sub/a.conf" <<<'line one'
    [ "$status" -eq 0 ]
    [ "$(cat "$dir/sub/a.conf")" = "line one" ]
    [[ "$output" == *"Created: a.conf"* ]]
}

@test "write_template: MODE is applied verbatim" {
    run write_template "$dir/run.sh" 700 <<<'#!/bin/sh'
    [ "$status" -eq 0 ]
    [ "$(stat -c '%a' "$dir/run.sh")" = "700" ]
}

@test "write_template: without MODE nothing is made executable" {
    run write_template "$dir/README.md" <<<'text'
    [ "$status" -eq 0 ]
    _vpssec_refute test -x "$dir/README.md"
}

@test "write_template: a write that fails is reported and returns 1" {
    mkdir -p "$dir/taken.conf"

    run write_template "$dir/taken.conf" <<<'x'
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template: $dir/taken.conf"* ]]
    _vpssec_refute grep -q 'Created:' <<<"$output"
}

@test "write_template: a parent that cannot be created is reported" {
    printf 'a file\n' > "$BATS_TEST_TMPDIR/blocker"

    run write_template "$BATS_TEST_TMPDIR/blocker/a.conf" <<<'x'
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template"* ]]
}

@test "write_template: a failed chmod is reported, not left with the wrong mode" {
    _vpssec_stub chmod 1

    run write_template "$dir/run.sh" 700 <<<'#!/bin/sh'
    [ "$status" -eq 1 ]
    [ -f "$dir/run.sh" ]
    [[ "$output" == *"Could not write the template: $dir/run.sh"* ]]
    _vpssec_refute grep -q 'Created:' <<<"$output"
}
