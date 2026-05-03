#!/usr/bin/env bats
#
# Regression tests for the _nginx_has_catchall fallback path (used when
# `nginx -T` is unavailable). Original chained
#   grep -r ... | head -1 | xargs -I{} grep -l "return 444"
# which fed xargs the entire `path:matched-line` string from grep -r,
# so it looked for a file literally named "path:matched-line" — broken
# both ways (false positive when a stray match happened, false negative
# in the normal case).

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"
    # Steer the module away from any host /etc/nginx and at our scratch
    # dir. nginx -T is unavailable on the test host, so the fallback
    # path is what the function exercises.
    NGINX_CONF_DIR="$BATS_TEST_TMPDIR/nginx"
    NGINX_SITES_AVAILABLE="$NGINX_CONF_DIR/sites-available"
    NGINX_SITES_ENABLED="$NGINX_CONF_DIR/sites-enabled"
    mkdir -p "$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED"

    # Make sure nginx isn't on PATH so the function falls into the
    # filesystem-scan branch deterministically.
    export PATH="$BATS_TEST_TMPDIR/empty_bin:$PATH"
    mkdir -p "$BATS_TEST_TMPDIR/empty_bin"
}

@test "catchall: file with default_server AND return 444 → detected" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
EOF
    run _nginx_has_catchall
    [ "$status" -eq 0 ]
}

@test "catchall: default_server present but no return 444 → not detected" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
}
EOF
    run _nginx_has_catchall
    [ "$status" -ne 0 ]
}

@test "catchall: return 444 present but no default_server → not detected" {
    cat >"$NGINX_SITES_ENABLED/00-default.conf" <<'EOF'
server {
    listen 80;
    server_name api.example.com;
    return 444;
}
EOF
    run _nginx_has_catchall
    [ "$status" -ne 0 ]
}

@test "catchall: regression — broken xargs chain returned wrong result on path:line input" {
    # The original code did `grep -r ... | head -1 | xargs -I{} grep -l "return 444"`.
    # When the matching line happened to contain text that looked like
    # a filename with a colon, grep -l would fail looking for that
    # nonsense file and return non-zero. With both default_server and
    # return 444 in the same file, the new loop correctly detects.
    cat >"$NGINX_SITES_ENABLED/weird.conf" <<'EOF'
# server: api  listen 80 default_server; / hostname:port confusion
server {
    listen 80 default_server;
    return 444;
}
EOF
    run _nginx_has_catchall
    [ "$status" -eq 0 ]
}

@test "catchall: empty config dir → not detected (no false positive)" {
    run _nginx_has_catchall
    [ "$status" -ne 0 ]
}

@test "catchall: detection looks across multiple files in conf dir" {
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
    run _nginx_has_catchall
    [ "$status" -eq 0 ]
}
