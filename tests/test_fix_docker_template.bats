#!/usr/bin/env bats
# docker.generate_proxy_template writes a compose file, a Traefik config and an
# empty acme.json into vpssec's own tree. Each step's status must reach the
# caller: the fix runs with errexit off.

load helpers.bash

setup() {
    _vpssec_load
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/docker.sh"
    DOCKER_TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates/docker"
    _vpssec_stub docker 0
    tpl="$DOCKER_TEMPLATES_DIR"
}

@test "proxy template: all three artifacts are written, acme.json private" {
    run _docker_fix_generate_proxy_template
    [ "$status" -eq 0 ]
    [ -f "$tpl/docker-compose.proxy.yml" ]
    [ -f "$tpl/traefik/traefik.yml" ]
    [ "$(stat -c '%a' "$tpl/traefik/acme.json")" = "600" ]
    [[ "$output" == *"Template generated"* ]]
}

@test "proxy template: writing it asks the daemon nothing" {
    # The template is the same on every host; nothing it writes comes from docker.
    run _docker_fix_generate_proxy_template
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called docker
}

@test "proxy template: an existing acme.json keeps its certificates" {
    mkdir -p "$tpl/traefik"
    printf '{"letsencrypt":{}}\n' > "$tpl/traefik/acme.json"

    run _docker_fix_generate_proxy_template
    [ "$status" -eq 0 ]
    [ "$(cat "$tpl/traefik/acme.json")" = '{"letsencrypt":{}}' ]
}

@test "proxy template: a failed compose write stops the fix" {
    mkdir -p "$tpl/docker-compose.proxy.yml"

    run _docker_fix_generate_proxy_template
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template: $tpl/docker-compose.proxy.yml"* ]]
    _vpssec_refute test -e "$tpl/traefik/traefik.yml"
    _vpssec_refute grep -q "Template generated" <<<"$output"
}

@test "proxy template: a failed Traefik config write fails the fix" {
    mkdir -p "$tpl/traefik/traefik.yml"

    run _docker_fix_generate_proxy_template
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template: $tpl/traefik/traefik.yml"* ]]
    _vpssec_refute test -e "$tpl/traefik/acme.json"
}

@test "proxy template: an acme.json left readable fails the fix" {
    _vpssec_stub chmod 1

    run _docker_fix_generate_proxy_template
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the template: $tpl/traefik/acme.json"* ]]
    _vpssec_refute grep -q "Template generated" <<<"$output"
}
