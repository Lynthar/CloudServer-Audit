#!/usr/bin/env bats
#
# Regression tests for the _nginx_catchall_state fallback path (used when
# `nginx -T` is unavailable).
#
# H18 regression: original chained
#   grep -r ... | head -1 | xargs -I{} grep -l "return 444"
# which fed xargs the entire `path:matched-line` string from grep -r,
# so it looked for a file literally named "path:matched-line" — broken
# both ways (false positive on stray matches, false negative otherwise).
#
# M7 follow-up: state now distinguishes "80only" / "443only" / "both" /
# "none" so HTTPS-only catchalls don't get reported as fully covered.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"
    # Steer the module at a scratch dir.
    NGINX_CONF_DIR="$BATS_TEST_TMPDIR/nginx"
    NGINX_SITES_AVAILABLE="$NGINX_CONF_DIR/sites-available"
    NGINX_SITES_ENABLED="$NGINX_CONF_DIR/sites-enabled"
    mkdir -p "$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED"

    # Force the fallback branch: _nginx_catchall_state takes it when
    # `nginx -T` exits non-zero or prints nothing.
    #
    # This used to prepend an EMPTY directory to PATH and claim it hid
    # nginx. It does not — `nginx` still resolves further down PATH — so on
    # any host that actually has nginx these tests silently stopped
    # exercising the fallback and read the host's real configuration
    # instead. They passed only because the test host happened to have no
    # nginx installed, which is not a property CI guarantees. A stub of the
    # same name is what actually shadows the binary.
    _vpssec_stub nginx 1
}

@test "catchall fallback: only port 80 with return 444 → 80only" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall fallback: default_server present but no return 444 → none" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall fallback: return 444 present but no default_server → none" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 80;
    server_name api.example.com;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall fallback: H18 path:line regression — file detected without xargs bug" {
    # Original chained grep that fed `path:matched-line` to xargs and
    # looked for a literal filename. Now the loop iterates `grep -rl`
    # filenames and probes each; this still works.
    cat >"$NGINX_SITES_ENABLED/weird.conf" <<'EOF'
# server: api  listen 80 default_server; / hostname:port confusion
server {
    listen 80 default_server;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall fallback: empty config dir → none" {
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall fallback: 80 catchall in one file, vhost on 443 in another → 80only" {
    cat >"$NGINX_SITES_ENABLED/01-app.conf" <<'EOF'
server {
    listen 8080;
    server_name app.example.com;
}
EOF
    cat >"$NGINX_SITES_ENABLED/99-catchall.conf" <<'EOF'
server {
    listen 80 default_server;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall fallback: separate files for 80 and 443 catchalls → both" {
    # The behavior change M7 was about: full coverage requires BOTH
    # ports. Common deployment: catchalls split into two files.
    cat >"$NGINX_SITES_ENABLED/00-catchall-80.conf" <<'EOF'
server {
    listen 80 default_server;
    return 444;
}
EOF
    cat >"$NGINX_SITES_ENABLED/01-catchall-443.conf" <<'EOF'
server {
    listen 443 ssl default_server;
    ssl_certificate /etc/ssl/dummy.crt;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}
