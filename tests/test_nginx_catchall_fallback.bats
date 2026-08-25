#!/usr/bin/env bats
# Regression tests for the _nginx_catchall_state fallback path, taken when
# `nginx -T` is unavailable. It must distinguish 80only / 443only / both / none,
# so an HTTPS-only catchall is never reported as fully covered.

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

    # Force the fallback branch: _nginx_catchall_state takes it when `nginx -T`
    # exits non-zero or prints nothing. It must be a STUB of the same name —
    # an empty directory prepended to PATH does not hide a real nginx.
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

@test "catchall fallback: 443 listen without default_server → none" {
    # Mirror of the port-80 case above. With no default_server ANYWHERE in the
    # file the outer `grep -rl "listen.*default_server"` never lists it, so the
    # per-port greps are not reached; the "same file" tests below pin those.
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 443 ssl;
    server_name api.example.com;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall fallback: an ordinary port-80 vhost beside a 443 catchall is not counted" {
    # The scan is file-level: one block with default_server gets the whole file
    # listed, so each per-port grep must require default_server for the port IT
    # asks about, or a mixed file reports coverage it does not have.
    cat >"$NGINX_SITES_ENABLED/00-mixed.conf" <<'EOF'
server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    server_name app.example.com;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "443only" ]
}

@test "catchall fallback: an ordinary port-443 vhost beside an 80 catchall is not counted" {
    cat >"$NGINX_SITES_ENABLED/00-mixed.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl;
    server_name app.example.com;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall fallback: port 8080 must NOT match port 80" {
    # The state parser's own suite pins this for `nginx -T` output; the fallback
    # runs a different, file-level regex. The 8080 vhost in the two-file test
    # below carries no `return 444`, so it is skipped before the port match.
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 8080 default_server;
    server_name _;
    return 444;
}
EOF
    run _nginx_catchall_state
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall fallback: port 4430 must NOT match port 443" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 4430 ssl default_server;
    server_name _;
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
    # Full coverage requires BOTH ports. Common deployment: the catchalls are
    # split into two files.
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
