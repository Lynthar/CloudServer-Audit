#!/usr/bin/env bats
#
# Regression tests for _cloudflared_check_ingress_security.
#
# All three checks used unanchored greps that matched inside YAML comments,
# and the damage ran both ways:
#
#   False positive — this module GENERATES a config.yml.example whose header
#   says "Copy this file to /etc/cloudflared/config.yml", and whose commented
#   "private network access" example contains
#       #     noTLSVerify: true  # Only for internal services
#   so anyone who followed the tool's own instructions was flagged for a
#   setting they never enabled. The last test here closes that loop directly:
#   it generates the template and feeds it to the checker.
#
#   False negative — the two `! grep -q` checks were satisfied by a
#   commented-out catch-all rule or originRequest block, quietly passing a
#   config that has neither.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"

    config="$BATS_TEST_TMPDIR/config.yml"
}

# A config that is clean on every axis, for tests that vary one thing.
_write_clean_config() {
    cat > "$config" <<'EOF'
tunnel: abc123
originRequest:
  noTLSVerify: false
ingress:
  - hostname: app.example.com
    service: http://localhost:8080
  - service: http_status:404
EOF
}

# ---- noTLSVerify: the false positive ---------------------------------

@test "ingress: an active noTLSVerify: true is flagged" {
    _write_clean_config
    printf '    originRequest:\n      noTLSVerify: true\n' >> "$config"

    run _cloudflared_check_ingress_security "$config"
    [[ "$output" == *notls_verify* ]]
}

@test "ingress: a commented-out noTLSVerify: true is NOT flagged" {
    _write_clean_config
    printf '  #     noTLSVerify: true  # Only for internal services\n' >> "$config"

    run _cloudflared_check_ingress_security "$config"
    [[ "$output" != *notls_verify* ]]
}

@test "ingress: a trailing comment on a live line still counts" {
    # `noTLSVerify: true  # temporary` is the common YAML idiom and is very
    # much active — the comment guard must not swallow it.
    _write_clean_config
    printf '      noTLSVerify: true  # temporary, remove me\n' >> "$config"

    run _cloudflared_check_ingress_security "$config"
    [[ "$output" == *notls_verify* ]]
}

@test "ingress: the space-less noTLSVerify:true is flagged too" {
    _write_clean_config
    printf '      noTLSVerify:true\n' >> "$config"

    run _cloudflared_check_ingress_security "$config"
    [[ "$output" == *notls_verify* ]]
}

# ---- catch-all and originRequest: the false negatives -----------------

@test "ingress: a commented-out catch-all does not satisfy the check" {
    cat > "$config" <<'EOF'
tunnel: abc123
originRequest:
  noTLSVerify: false
ingress:
  - hostname: app.example.com
    service: http://localhost:8080
  # - service: http_status:404
EOF

    run _cloudflared_check_ingress_security "$config"
    [[ "$output" == *no_catchall* ]]
}

@test "ingress: a commented-out originRequest does not satisfy the check" {
    cat > "$config" <<'EOF'
tunnel: abc123
# originRequest:
#   noTLSVerify: false
ingress:
  - service: http_status:404
EOF

    run _cloudflared_check_ingress_security "$config"
    [[ "$output" == *no_origin_request* ]]
}

@test "ingress: a fully configured file reports nothing" {
    _write_clean_config

    run _cloudflared_check_ingress_security "$config"
    [ -z "${output//[[:space:]]/}" ]
}

# ---- the loop that started it ----------------------------------------

@test "ingress: the tool does not flag the template the tool itself writes" {
    # End-to-end: generate config.yml.example exactly as the fix does, then
    # audit it as if the user had copied it to /etc/cloudflared/config.yml,
    # which is what its own header tells them to do.
    CLOUDFLARED_TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates"
    run _cloudflared_fix_generate_config
    [ "$status" -eq 0 ]

    local template="$CLOUDFLARED_TEMPLATES_DIR/config.yml.example"
    [ -f "$template" ]
    # The commented example that used to trip the audit is still in there —
    # this test would be vacuous if the template had simply dropped it.
    grep -qE '^\s*#.*noTLSVerify: true' "$template"

    run _cloudflared_check_ingress_security "$template"
    [ -z "${output//[[:space:]]/}" ]
}
