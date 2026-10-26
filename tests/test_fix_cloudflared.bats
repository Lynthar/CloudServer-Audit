#!/usr/bin/env bats
# cloudflared.generate_config writes a config template into vpssec's own tree. A
# fix runs with errexit off, so the write's status must reach the caller, or a
# full disk ends in "Templates generated" over a file that is not there.

load helpers.bash

setup() {
    _vpssec_load
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"
    CLOUDFLARED_TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates/cloudflared"
}

@test "generate_config: the config template is written, and only that" {
    # No unit template: the official package ships no cloudflared user, and
    # `cloudflared service install`, which the next steps name, writes the unit.
    run _cloudflared_fix_generate_config
    [ "$status" -eq 0 ]
    [ -f "$CLOUDFLARED_TEMPLATES_DIR/config.yml.example" ]
    [ "$(ls "$CLOUDFLARED_TEMPLATES_DIR")" = "config.yml.example" ]
    [[ "$output" == *"Templates generated in"* ]]
    [[ "$output" == *"cloudflared service install"* ]]
}

@test "generate_config: a failed config write stops the fix" {
    mkdir -p "$CLOUDFLARED_TEMPLATES_DIR/config.yml.example"

    run _cloudflared_fix_generate_config
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template: $CLOUDFLARED_TEMPLATES_DIR/config.yml.example"* ]]
    _vpssec_refute grep -q "Templates generated in" <<<"$output"
}
