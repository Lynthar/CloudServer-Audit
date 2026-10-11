#!/usr/bin/env bats
# cloudflared.generate_config writes two templates into vpssec's own tree. A fix
# runs with errexit off, so each write's status must reach the caller, or a
# full disk ends in "Templates generated" over files that are not there.

load helpers.bash

setup() {
    _vpssec_load
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"
    CLOUDFLARED_TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates/cloudflared"
}

@test "generate_config: both templates are written" {
    run _cloudflared_fix_generate_config
    [ "$status" -eq 0 ]
    [ -f "$CLOUDFLARED_TEMPLATES_DIR/config.yml.example" ]
    [ -f "$CLOUDFLARED_TEMPLATES_DIR/cloudflared.service.example" ]
    [[ "$output" == *"Templates generated in"* ]]
}

@test "generate_config: a failed config write stops the fix" {
    mkdir -p "$CLOUDFLARED_TEMPLATES_DIR/config.yml.example"

    run _cloudflared_fix_generate_config
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template: $CLOUDFLARED_TEMPLATES_DIR/config.yml.example"* ]]
    _vpssec_refute test -f "$CLOUDFLARED_TEMPLATES_DIR/cloudflared.service.example"
    _vpssec_refute grep -q "Templates generated in" <<<"$output"
}

@test "generate_config: a failed service-template write fails the fix too" {
    mkdir -p "$CLOUDFLARED_TEMPLATES_DIR/cloudflared.service.example"

    run _cloudflared_fix_generate_config
    [ "$status" -eq 1 ]
    [ -f "$CLOUDFLARED_TEMPLATES_DIR/config.yml.example" ]
    [[ "$output" == *"Could not write the template: $CLOUDFLARED_TEMPLATES_DIR/cloudflared.service.example"* ]]
    _vpssec_refute grep -q "Templates generated in" <<<"$output"
}
