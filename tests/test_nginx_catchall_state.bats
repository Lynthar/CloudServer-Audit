#!/usr/bin/env bats
#
# Tests for _nginx_catchall_state_from_text (M7). The original
# _nginx_has_catchall returned "yes" if both `default_server` and
# `return 444` appeared anywhere in the merged config — it didn't
# distinguish port 80 vs 443 nor enforce same-server-block scope.
# A config with port 80 catchall and a separate vhost on 443 (no
# catchall) was misreported as fully covered.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"
}

@test "catchall: both 80 and 443 in one server block → both" {
    local cfg='server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: 80 and 443 in separate blocks → both" {
    local cfg='server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: only port 80 has catchall, 443 vhost present (regression)" {
    # The exact M7 case: 80 catchall but 443 has a real cert vhost
    # without catchall. Old code saw default_server somewhere AND
    # return 444 somewhere → reported "passed".
    local cfg='server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate /etc/ssl/cert.pem;
    return 200 "ok";
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall: only port 443 has catchall" {
    local cfg='server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    server_name app.example.com;
    return 200 "ok";
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "443only" ]
}

@test "catchall: neither port has catchall" {
    local cfg='server {
    listen 80;
    server_name app.example.com;
    return 200 "ok";
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: empty config → none" {
    run _nginx_catchall_state_from_text ""
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: IPv6-bracket form [::]:80 default_server detected" {
    local cfg='server {
    listen [::]:80 default_server;
    listen [::]:443 ssl default_server;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: 0.0.0.0:80 default_server detected" {
    local cfg='server {
    listen 0.0.0.0:80 default_server;
    listen 0.0.0.0:443 ssl default_server;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: port 8080 must NOT match port 80" {
    # Defensive against a substring-match bug. listen 8080 default_server
    # with return 444 should NOT count as a port-80 catchall.
    local cfg='server {
    listen 8080 default_server;
    server_name _;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: port 4430 must NOT match port 443" {
    local cfg='server {
    listen 4430 default_server;
    server_name _;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: return 444 in ONE block does not propagate to another" {
    # Cross-block scope check: 80 has default_server but no return 444;
    # 443 has return 444 but no default_server. Should not aggregate.
    local cfg='server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
}

server {
    listen 443;
    server_name app.example.com;
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: commented-out catchall is ignored" {
    local cfg='server {
    listen 80 default_server;
    server_name _;
    # return 444;
    return 200 "still alive";
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: location blocks inside server don't break brace tracking" {
    local cfg='server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    location / {
        deny all;
    }
    location /healthz {
        return 200 "ok";
    }
    return 444;
}'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: one-liner server block handled" {
    local cfg='server { listen 80 default_server; return 444; }'
    run _nginx_catchall_state_from_text "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}
