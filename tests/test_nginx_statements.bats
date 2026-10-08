#!/usr/bin/env bats
# nginx_statements, the one reading of an nginx config both modules share. It
# has to tokenize as nginx does and put included files back where they were
# included, or a vhost in sites-enabled reads as outside http{}.

load helpers.bash

setup() {
    _vpssec_load
    FIXTURE="$(_vpssec_repo_root)/tests/fixtures/nginx-T-debian12.txt"
}

# Statements of a config text, one "<sid>|<context>|<name>|<args>" per line.
_stmts() {
    nginx_statements <<<"$1" | tr '\t' '|'
}

@test "statements: a stock Debian 12 dump puts the default vhost inside http{}" {
    run nginx_statements < "$FIXTURE"
    [ "$status" -eq 0 ]
    grep -qxF $'1\thttp/server\tlisten\t80 default_server' <<<"$output"
    grep -qxF $'0\thttp\tssl_protocols\tTLSv1 TLSv1.1 TLSv1.2 TLSv1.3' <<<"$output"
    # mime.types is included inside http{} too, so its entries land there.
    grep -qxF $'0\thttp/types\ttext/css\tcss' <<<"$output"
}

@test "statements: commented-out directives in the stock dump never appear" {
    run nginx_statements < "$FIXTURE"
    # The reading happened at all, or the refutations below hold of an error.
    grep -qF $'\tlisten\t80 default_server' <<<"$output"
    _vpssec_refute grep -q $'\tserver_tokens\t' <<<"$output"
    # The default vhost's 443 listens are commented out.
    _vpssec_refute grep -q $'\tlisten\t443' <<<"$output"
}

@test "statements: a trailing comment ends the directive, not the line before it" {
    run _stmts 'http { gzip on; # gzip off;
}'
    [ "$output" = "0|http|gzip|on" ]
}

@test "statements: # inside quotes or mid-token is data, not a comment" {
    run _stmts "http { add_header CSP \"script-src 'sha256-a#b'\" always; set \$x a#b; }"
    grep -qxF "0|http|add_header|CSP script-src 'sha256-a#b' always" <<<"$output"
    grep -qxF '0|http|set|$x a#b' <<<"$output"
}

@test "statements: ; and { inside quotes do not end or open anything" {
    run _stmts 'http { server { location / { return 200 "a;b{c}"; } listen 81; } }'
    grep -qxF '1|http/server/location|return|200 a;b{c}' <<<"$output"
    grep -qxF '1|http/server|listen|81' <<<"$output"
}

@test "statements: \${var} is a variable, not a block" {
    run _stmts 'http { server { set $a "${host}x"; set $b ${host}; listen 82; } }'
    grep -qxF '1|http/server|set|$b ${host}' <<<"$output"
    grep -qxF '1|http/server|listen|82' <<<"$output"
}

@test "statements: several blocks on one line get their own server ids" {
    run _stmts 'http { server { listen 80; } server { listen 443 ssl; } } stream { server { listen 993 ssl; } }'
    [ "$output" = $'1|http/server|listen|80\n2|http/server|listen|443 ssl\n3|stream/server|listen|993 ssl' ]
}

@test "statements: a relative include resolves against the main file's directory" {
    local dump='# configuration file /opt/ng/conf/nginx.conf:
http { include sites/*.conf; }

# configuration file /opt/ng/conf/sites/a.conf:
server { listen 8081; }

# configuration file /opt/ng/conf/other/b.conf:
server { listen 8082; }
'
    run _stmts "$dump"
    [ "$output" = '1|http/server|listen|8081' ]
}

@test "statements: a file included twice is read at both places" {
    local dump='# configuration file /etc/nginx/nginx.conf:
http { server { include snippets/tls.conf; listen 1; } server { include /etc/nginx/snippets/tls.conf; listen 2; } }

# configuration file /etc/nginx/snippets/tls.conf:
ssl_protocols TLSv1.2;
'
    run _stmts "$dump"
    grep -qxF '1|http/server|ssl_protocols|TLSv1.2' <<<"$output"
    grep -qxF '2|http/server|ssl_protocols|TLSv1.2' <<<"$output"
}

@test "statements: a file that includes itself does not loop" {
    local dump='# configuration file /etc/nginx/nginx.conf:
include nginx.conf;
worker_processes 1;
'
    run _stmts "$dump"
    [ "$status" -eq 0 ]
    [ "$output" = '0||worker_processes|1' ]
}

@test "dump: loaded once, and a failing config reports nginx's own error" {
    _vpssec_stub_script nginx <<'SH'
case "$*" in
    *-T*) exit 1 ;;
esac
echo 'nginx: [emerg] unknown directive "sevrer" in /etc/nginx/sites-enabled/x:1' >&2
echo 'nginx: configuration file /etc/nginx/nginx.conf test failed' >&2
exit 1
SH
    nginx_dump_reset
    _vpssec_refute nginx_dump_load
    [[ "$NGINX_DUMP_ERROR" == *'unknown directive "sevrer"'* ]]
    [ -z "$NGINX_DUMP" ]
}

@test "dump: the cache holds until reset, in the caller's shell" {
    _vpssec_stub_script nginx <<SH
echo call >> "$BATS_TEST_TMPDIR/calls"
echo 'http { }'
SH
    nginx_dump_reset
    nginx_dump_load
    nginx_dump_load
    [ "$(wc -l < "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
    nginx_dump_reset
    nginx_dump_load
    [ "$(wc -l < "$BATS_TEST_TMPDIR/calls")" -eq 2 ]
}
