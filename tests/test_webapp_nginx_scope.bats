#!/usr/bin/env bats
# The webapp nginx checks read nginx_statements, so a value is judged where it
# applies: per server, inherited from http{} when the server sets none, and TLS
# checks only where a server speaks TLS.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    FIXTURE="$(_vpssec_repo_root)/tests/fixtures/nginx-T-debian12.txt"
    _vpssec_stub_script nginx <<SH
case "\$*" in
    *-T*) cat "$BATS_TEST_TMPDIR/dump" ;;
esac
exit 0
SH
    # The headers check requests every site: no test may reach a real one.
    _curl_answers
}

# curl answers a URL from $BATS_TEST_TMPDIR/curl, an exit code on the first line
# and the header block after it; a URL with no answer there is refused (exit 7).
_curl_answers() {
    export CURL_ANSWERS="$BATS_TEST_TMPDIR/curl"
    mkdir -p "$CURL_ANSWERS"
    _vpssec_stub_script curl <<'SH'
f="$CURL_ANSWERS/$(printf '%s' "${@: -1}" | tr -c 'A-Za-z0-9' _)"
[[ -f "$f" ]] || exit 7
tail -n +2 "$f"
exit "$(head -1 "$f")"
SH
}

# _answer URL RC [HEADER-LINE...]: what curl gets back from URL, lines CRLF-ended.
_answer() {
    local url="$1" rc="$2"
    shift 2
    { printf '%s\n' "$rc"; printf '%s\r\n' "$@"; } > "$CURL_ANSWERS/$(printf '%s' "$url" | tr -c 'A-Za-z0-9' _)"
}

_ALL_FOUR=('X-Frame-Options: DENY' 'X-Content-Type-Options: nosniff' 'X-XSS-Protection: 0' 'Referrer-Policy: no-referrer')

# An nginx -T dump of one nginx.conf whose http{} holds $1.
_dump_http() {
    printf '# configuration file /etc/nginx/nginx.conf:\nhttp {\n%s\n}\n' "$1" > "$BATS_TEST_TMPDIR/dump"
}

# The `nginx -T` text the stub answers with: the stock Debian 12 dump with
# one more file included from sites-enabled, as a vhost would be.
_dump_with_site() {
    {
        cat "$FIXTURE"
        printf '# configuration file /etc/nginx/sites-enabled/site:\n%s\n' "$1"
    } > "$BATS_TEST_TMPDIR/dump"
}

_audit_nginx() {
    nginx_dump_reset
    nginx_dump_load
    _webapp_audit_nginx
}

_ids() { jq -r '.[].id' "$VPSSEC_STATE/checks.json"; }
_desc() { _field "$1" desc; }
_field() { jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f] // ""' "$VPSSEC_STATE/checks.json"; }

@test "tls: stock Debian 12 with no TLS server raises no TLS finding" {
    # nginx.conf's http{} ships TLSv1 and TLSv1.1, but nothing listens with ssl.
    cp "$FIXTURE" "$BATS_TEST_TMPDIR/dump"
    _audit_nginx
    _vpssec_refute grep -qE 'webapp\.nginx_(weak_ssl|weak_ciphers|hsts_missing|hsts_weak)$' <<<"$(_ids)"
}

@test "tls: a TLS server inheriting the stock http{} line is reported, naming http" {
    _dump_with_site 'server { listen 443 ssl; server_name shop.example; }'
    _audit_nginx
    [ "$(_desc webapp.nginx_weak_ssl)" = "shop.example: TLSv1, TLSv1.1, set in the http block" ]
}

@test "tls: a server setting its own protocols passes under the stock http{} line" {
    # The certbot form: the options file is included inside the server.
    {
        cat "$FIXTURE"
        printf '# configuration file /etc/nginx/sites-enabled/site:\n'
        printf 'server { listen 443 ssl; server_name shop.example; include /etc/letsencrypt/options-ssl-nginx.conf; }\n'
        printf '# configuration file /etc/letsencrypt/options-ssl-nginx.conf:\n'
        printf 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;\n'
        printf 'ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";\n'
    } > "$BATS_TEST_TMPDIR/dump"
    _audit_nginx
    _vpssec_refute grep -qxF webapp.nginx_weak_ssl <<<"$(_ids)"
    _vpssec_refute grep -qxF webapp.nginx_weak_ciphers <<<"$(_ids)"
}

@test "tls: each weak server is named once, its own setting saying nothing about inheritance" {
    _dump_with_site 'server { listen 443 ssl; server_name a.example; ssl_protocols TLSv1.1 TLSv1.2; }
server { listen 443 ssl; server_name b.example; ssl_protocols TLSv1.3; }'
    _audit_nginx
    [ "$(_desc webapp.nginx_weak_ssl)" = "a.example: TLSv1.1" ]
}

@test "tls: weak ciphers are reported per server, excluded ones ignored" {
    _dump_with_site 'server { listen 443 ssl; server_name a.example; ssl_ciphers "HIGH:!RC4:!MD5:3DES"; }'
    _audit_nginx
    [ "$(_desc webapp.nginx_weak_ciphers)" = "a.example: DES, 3DES" ]
}

@test "tls: HSTS is asked where a TLS server exists, and not on plain HTTP" {
    _dump_with_site 'server { listen 443 ssl http2; server_name a.example; ssl_protocols TLSv1.3; }'
    _audit_nginx
    grep -qxF webapp.nginx_hsts_missing <<<"$(_ids)"

    state_init
    _dump_with_site 'server { listen 80; server_name a.example; }'
    _audit_nginx
    _vpssec_refute grep -qxF webapp.nginx_hsts_missing <<<"$(_ids)"
}

@test "server_tokens: off in one server leaves the other reported" {
    _dump_with_site 'server { listen 80; server_name a.example; server_tokens off; }
server { listen 80; server_name b.example; }'
    nginx_dump_reset
    nginx_dump_load
    run _webapp_nginx_server_tokens
    [ "$output" = "_
b.example" ]
}

@test "server_tokens: off at http{} covers servers that set nothing" {
    {
        printf 'http {\n    server_tokens off;\n    server { listen 80; server_name a.example; }\n}\n'
    } > "$BATS_TEST_TMPDIR/dump"
    nginx_dump_reset
    nginx_dump_load
    run _webapp_nginx_server_tokens
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ---- security headers: what each site's response carries --------------------------

@test "headers: a proxied site whose application sends all four passes" {
    # No add_header anywhere: the application behind proxy_pass sends them.
    _dump_http 'server { listen 80; server_name app.example; location / { proxy_pass http://127.0.0.1:3000; } }'
    _answer 'http://app.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
    _vpssec_refute grep -qxF webapp.nginx_security_headers <<<"$(_ids)"
}

@test "headers: a site is named with the headers its response lacks" {
    _dump_http 'server { listen 80; server_name app.example; location / { proxy_pass http://127.0.0.1:3000; } }'
    _answer 'http://app.example/' 0 'HTTP/2 200' 'x-frame-options: DENY' 'x-content-type-options: nosniff'
    _audit_nginx
    [ "$(_desc webapp.nginx_security_headers)" = "http://app.example/: Referrer-Policy, X-XSS-Protection" ]
    [ "$(_field webapp.nginx_security_headers fix_id)" = webapp.nginx_security_headers ]
}

@test "headers: a server with add_header of its own is named apart, with no fix that cannot reach it" {
    # nginx hands http{}'s add_header only to a server that sets none: the drop-in
    # would be written and every verify would fail. Certbot's --hsts writes one there.
    _dump_http 'server { listen 80; server_name app.example; add_header Strict-Transport-Security "max-age=1" always; }'
    _answer 'http://app.example/' 0 'HTTP/1.1 200 OK' 'strict-transport-security: max-age=1'
    _audit_nginx
    [ "$(_desc webapp.nginx_security_headers)" = "http://app.example/: Referrer-Policy, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection ($(i18n 'webapp.headers_own_add_header'))" ]
    [ -z "$(_field webapp.nginx_security_headers fix_id)" ]
    [ "$(_field webapp.nginx_security_headers suggestion)" = "$(i18n 'webapp.add_security_headers_in_server')" ]
}

@test "headers: the fix is offered for the sites it reaches, the others named apart" {
    _dump_http 'server { listen 80; server_name a.example; }
server { listen 80; server_name b.example; add_header Cache-Control no-store; }'
    _answer 'http://a.example/' 0 'HTTP/1.1 200 OK'
    _answer 'http://b.example/' 0 'HTTP/1.1 200 OK' 'cache-control: no-store'
    _audit_nginx
    [ "$(_field webapp.nginx_security_headers fix_id)" = webapp.nginx_security_headers ]
    [[ "$(_desc webapp.nginx_security_headers)" == "http://a.example/: "*"; http://b.example/: "*"($(i18n 'webapp.headers_own_add_header'))" ]]
}

@test "headers: the request names the server and goes to its listen address" {
    _dump_http 'server { listen [::]:8443 ssl; listen 8443 ssl; server_name app.example www.app.example; }'
    _answer 'https://app.example:8443/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    _vpssec_stub_called curl '--resolve app\.example:8443:127\.0\.0\.1 https://app\.example:8443/$'
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
}

@test "headers: a server on both 80 and 443 is asked over TLS" {
    _dump_http 'server { listen 80; listen 443 ssl; server_name app.example; }'
    _answer 'https://app.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
}

@test "headers: an IPv6-only listen is asked at ::1" {
    _dump_http 'server { listen [::]:80; server_name v6.example; }'
    _answer 'http://v6.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    _vpssec_stub_called curl '--resolve v6\.example:80:\[::1\] '
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
}

@test "headers: a nameless server is asked by address only when it is the default" {
    _dump_http 'server { listen 80; server_name a.example; }
server { listen 80 default_server; server_name _; }
server { listen 80; server_name _; }'
    _answer 'http://a.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _answer 'http://127.0.0.1/' 0 'HTTP/1.1 200 OK'
    _audit_nginx
    [ "$(_desc webapp.nginx_security_headers)" = "http://127.0.0.1/: Referrer-Policy, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection" ]
    [ "$(_desc webapp.nginx_security_headers_not_checked)" = "_: no server_name to request it by, and not the default server of its port" ]
}

@test "headers: with no default_server, the first server on a port is its default" {
    _dump_http 'server { listen 8080; server_name _; }
server { listen 8080; server_name ""; }'
    _answer 'http://127.0.0.1:8080/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
    [ "$(_desc webapp.nginx_security_headers_not_checked)" = "8080: no server_name to request it by, and not the default server of its port" ]
}

@test "headers: a redirect within the site is followed, one off it serves no page" {
    _dump_http 'server { listen 80; server_name a.example; return 301 https://www.a.example$request_uri; }
server { listen 443 ssl; server_name a.example; }'
    _answer 'http://a.example/' 0 'HTTP/1.1 301 Moved Permanently' 'Location: https://www.a.example/'
    _answer 'https://a.example/' 0 'HTTP/1.1 302 Found' 'Location: /login'
    _answer 'https://a.example/login' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
    _vpssec_refute grep -qE '^webapp\.nginx_security_headers(_not_checked)?$' <<<"$(_ids)"
}

@test "headers: a redirect loop is given up after three hops" {
    _dump_http 'server { listen 80; server_name a.example; }'
    _answer 'http://a.example/' 0 'HTTP/1.1 302 Found' 'Location: /'
    _audit_nginx
    [ "$(grep -c '^curl ' "$VPSSEC_STUB_LOG")" -eq 4 ]
    _vpssec_refute grep -qE '^webapp\.nginx_security_headers' <<<"$(_ids)"
}

@test "headers: a server that closes the connection serves no page" {
    _dump_http 'server { listen 80 default_server; server_name _; return 444; }'
    _answer 'http://127.0.0.1/' 52
    _audit_nginx
    _vpssec_stub_called curl 'http://127\.0\.0\.1/$'
    _vpssec_refute grep -qE '^webapp\.nginx_security_headers' <<<"$(_ids)"
}

@test "headers: a server refusing every TLS handshake is not asked" {
    _dump_http 'server { listen 443 ssl default_server; server_name _; ssl_reject_handshake on; }
server { listen 80; server_name a.example; }'
    _answer 'http://a.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
    _vpssec_refute _vpssec_stub_called curl 'https://'
}

@test "headers: a stream server is not an http site" {
    printf '# configuration file /etc/nginx/nginx.conf:\nstream { server { listen 5353; proxy_pass 10.0.0.1:53; } }\nhttp { server { listen 80; server_name a.example; } }\n' > "$BATS_TEST_TMPDIR/dump"
    _answer 'http://a.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _audit_nginx
    grep -qxF webapp.nginx_security_headers_ok <<<"$(_ids)"
    _vpssec_refute grep -qxF webapp.nginx_security_headers_not_checked <<<"$(_ids)"
}

@test "headers: a server only on a unix socket is not checked, and not scored" {
    _dump_http 'server { listen unix:/run/app.sock; server_name up.example; }'
    _audit_nginx
    [ "$(_desc webapp.nginx_security_headers_not_checked)" = "up.example: no listen address this host can send a request to (a unix socket, QUIC, proxy_protocol or a host name)" ]
    [ "${CHECK_SCORE_CATEGORY[webapp.nginx_security_headers_not_checked]}" = info ]
    _vpssec_refute _vpssec_stub_called curl
}

@test "headers: a request that fails is not checked rather than missing" {
    _dump_http 'server { listen 80; server_name a.example; }'
    _answer 'http://a.example/' 28
    _audit_nginx
    [ "$(_desc webapp.nginx_security_headers_not_checked)" = "http://a.example/: the request failed (curl exit code 28)" ]
    _vpssec_refute grep -qxF webapp.nginx_security_headers <<<"$(_ids)"
}

@test "headers: sites past the time budget are not checked" {
    _dump_http 'server { listen 80; server_name a.example; }'
    WEBAPP_PROBE_BUDGET=0
    _audit_nginx
    [ "$(_desc webapp.nginx_security_headers_not_checked)" = "http://a.example/: not requested: the time allowed for these requests ran out" ]
    _vpssec_refute _vpssec_stub_called curl
}

@test "verify: a site still missing a header right after a reload is asked again" {
    _dump_http 'server { listen 80; server_name a.example; }'
    sleep() { :; }
    # The first answer comes from the old workers, the second from the new ones.
    _vpssec_stub_script curl <<SH
n=\$(( \$(cat "$BATS_TEST_TMPDIR/n" 2>/dev/null || echo 0) + 1 ))
echo "\$n" > "$BATS_TEST_TMPDIR/n"
printf 'HTTP/1.1 200 OK\r\n'
(( n < 2 )) || printf '%s\r\n' 'X-Frame-Options: DENY' 'X-Content-Type-Options: nosniff' 'X-XSS-Protection: 0' 'Referrer-Policy: no-referrer'
SH
    run _webapp_nginx_security_headers_ok
    [ "$status" -eq 0 ]
    [ "$(cat "$BATS_TEST_TMPDIR/n")" -eq 2 ]
}

@test "verify: a site missing a header on every try fails after three" {
    _dump_http 'server { listen 80; server_name a.example; }'
    sleep() { :; }
    _answer 'http://a.example/' 0 'HTTP/1.1 200 OK'
    run _webapp_nginx_security_headers_ok
    [ "$status" -eq 1 ]
    [ "$(grep -c '^curl ' "$VPSSEC_STUB_LOG")" -eq 3 ]
}

@test "verify: a site whose own add_header keeps http{}'s out does not fail the fix" {
    _dump_http 'server { listen 80; server_name a.example; }
server { listen 80; server_name b.example; add_header Cache-Control no-store; }'
    sleep() { :; }
    _answer 'http://a.example/' 0 'HTTP/1.1 200 OK' "${_ALL_FOUR[@]}"
    _answer 'http://b.example/' 0 'HTTP/1.1 200 OK'
    _webapp_nginx_security_headers_ok
}

@test "verify: no site answering is no proof that the headers went out" {
    _dump_http 'server { listen 80; server_name a.example; }'
    sleep() { :; }
    _answer 'http://a.example/' 28
    run _webapp_nginx_security_headers_ok
    [ "$status" -eq 1 ]
}

@test "presence: nginx with its config outside /etc/nginx is still audited" {
    # LNMP-style: the binary on PATH, the config under /usr/local/nginx.
    NGINX_CONF="$BATS_TEST_TMPDIR/absent/nginx.conf"
    APACHE_CONF="$BATS_TEST_TMPDIR/absent/apache2.conf"
    APACHE_CONF_ALT="$BATS_TEST_TMPDIR/absent/httpd.conf"
    WEB_ROOTS=("$BATS_TEST_TMPDIR/absent-www")
    _webapp_php_installed() { return 1; }
    cp "$FIXTURE" "$BATS_TEST_TMPDIR/dump"

    if webapp_audit >/dev/null; then :; fi
    grep -qE '^webapp\.nginx_server_tokens' <<<"$(_ids)"
    _vpssec_refute grep -qxF webapp.no_webserver <<<"$(_ids)"
    # A config nginx could read: the module finished.
    [ "${#VPSSEC_MODULES_FAILED[@]}" -eq 0 ]
}

@test "unreadable: a config nginx -t rejects gets one finding and no nginx passes" {
    NGINX_CONF="$BATS_TEST_TMPDIR/absent/nginx.conf"
    APACHE_CONF="$BATS_TEST_TMPDIR/absent/apache2.conf"
    APACHE_CONF_ALT="$BATS_TEST_TMPDIR/absent/httpd.conf"
    WEB_ROOTS=("$BATS_TEST_TMPDIR/absent-www")
    _webapp_php_installed() { return 1; }
    _vpssec_stub_script nginx <<'SH'
case "$*" in
    *-T*) exit 1 ;;
esac
echo 'nginx: [emerg] unknown directive "sevrer" in /etc/nginx/sites-enabled/x:1' >&2
exit 1
SH

    # In a condition, as the engine calls it, so the module's record survives.
    if webapp_audit >/dev/null; then :; fi
    grep -qxF webapp.nginx_config_unreadable <<<"$(_ids)"
    [[ "$(_desc webapp.nginx_config_unreadable)" == *'unknown directive "sevrer"'* ]]
    _vpssec_refute grep -qE '^webapp\.nginx_.*_ok$' <<<"$(_ids)"
    _vpssec_refute grep -qxF webapp.no_webserver <<<"$(_ids)"
    # None of the nginx checks ran: the audit is incomplete (exit 3).
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" webapp "* ]]
}

@test "sensitive files: an .htaccess is not one" {
    # Every WordPress / Laravel site ships it; Apache refuses .ht* by default.
    mkdir -p "$BATS_TEST_TMPDIR/www/blog"
    printf 'RewriteEngine On\n' > "$BATS_TEST_TMPDIR/www/blog/.htaccess"
    printf 'user:$apr1$x$y\n' > "$BATS_TEST_TMPDIR/www/blog/.htpasswd"
    WEB_ROOTS=("$BATS_TEST_TMPDIR/www")

    run _webapp_sensitive_files
    [ "$output" = "$BATS_TEST_TMPDIR/www/blog/.htpasswd" ]
}

# ---- certificate expiry: what nginx serves is checked -------------------------

# A self-signed certificate as `openssl req -x509` makes it, expiring in $2 days.
# OpenSSL 3 marks it CA:TRUE, the shape that read as a CA and was never checked.
_self_signed() {
    command -v openssl >/dev/null || skip "openssl not installed"
    mkdir -p "${1%/*}"
    openssl req -x509 -nodes -newkey rsa:2048 -days "$2" -subj /CN=self \
        -keyout "$BATS_TEST_TMPDIR/self.key" -out "$1" 2>/dev/null
}

# The same without extensions (`x509 -req`), so not a CA: kept by the scan too.
_leaf_cert() {
    command -v openssl >/dev/null || skip "openssl not installed"
    mkdir -p "${1%/*}"
    openssl req -new -nodes -newkey rsa:2048 -subj /CN=leaf \
        -keyout "$BATS_TEST_TMPDIR/leaf.key" -out "$BATS_TEST_TMPDIR/leaf.csr" 2>/dev/null
    openssl x509 -req -in "$BATS_TEST_TMPDIR/leaf.csr" -signkey "$BATS_TEST_TMPDIR/leaf.key" \
        -days "$2" -out "$1" 2>/dev/null
}

@test "certs: a self-signed CA:TRUE certificate nginx serves is checked" {
    _self_signed "$BATS_TEST_TMPDIR/ssl/self.crt" 3
    _webapp_cert_is_ca "$BATS_TEST_TMPDIR/ssl/self.crt" || skip "this openssl does not mark it CA:TRUE"
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/ssl")
    _dump_with_site "server { listen 443 ssl; ssl_certificate $BATS_TEST_TMPDIR/ssl/self.crt; }"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/ssl/self.crt|expiring|"* ]]
}

@test "certs: the same CA certificate, served by nothing, is still skipped" {
    _self_signed "$BATS_TEST_TMPDIR/ssl/self.crt" 3
    _webapp_cert_is_ca "$BATS_TEST_TMPDIR/ssl/self.crt" || skip "this openssl does not mark it CA:TRUE"
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/ssl")
    cp "$FIXTURE" "$BATS_TEST_TMPDIR/dump"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "certs: a served certificate outside the scanned directories is checked, once" {
    _self_signed "$BATS_TEST_TMPDIR/elsewhere/site.crt" 3
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/ssl")
    _dump_with_site "server { listen 443 ssl; ssl_certificate $BATS_TEST_TMPDIR/elsewhere/site.crt; }
server { listen 8443 ssl; ssl_certificate $BATS_TEST_TMPDIR/elsewhere/site.crt; }"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/elsewhere/site.crt|expiring|"* ]]
    [ "$(wc -l <<<"$output")" -eq 1 ]
}

@test "certs: a served certificate inside a scanned directory is reported once" {
    _leaf_cert "$BATS_TEST_TMPDIR/ssl/leaf.crt" 3
    _vpssec_refute _webapp_cert_is_ca "$BATS_TEST_TMPDIR/ssl/leaf.crt"
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/ssl")
    _dump_with_site "server { listen 443 ssl; ssl_certificate $BATS_TEST_TMPDIR/ssl/leaf.crt; }"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/ssl/leaf.crt|expiring|"* ]]
    [ "$(wc -l <<<"$output")" -eq 1 ]
}

# Let's Encrypt's live/<domain>/: cert.pem, and fullchain.pem holding it again.
_le_live() {
    _leaf_cert "$1/cert.pem" "$2"
    _self_signed "$1/chain.pem" 900
    cat "$1/cert.pem" "$1/chain.pem" > "$1/fullchain.pem"
}

@test "certs: Let's Encrypt's cert.pem and fullchain.pem are one certificate" {
    _le_live "$BATS_TEST_TMPDIR/le/live/a.example" 3
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/le/live")
    cp "$FIXTURE" "$BATS_TEST_TMPDIR/dump"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/le/live/a.example/"*"|expiring|"* ]]
    [ "$(wc -l <<<"$output")" -eq 1 ]
}

@test "certs: a certificate found twice is reported by the path nginx serves" {
    _le_live "$BATS_TEST_TMPDIR/le/live/a.example" 3
    mkdir -p "$BATS_TEST_TMPDIR/elsewhere"
    cp "$BATS_TEST_TMPDIR/le/live/a.example/fullchain.pem" "$BATS_TEST_TMPDIR/elsewhere/a.pem"
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/le/live")
    _dump_with_site "server { listen 443 ssl; ssl_certificate $BATS_TEST_TMPDIR/elsewhere/a.pem; }"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/elsewhere/a.pem|expiring|"* ]]
    [ "$(wc -l <<<"$output")" -eq 1 ]
}

@test "certs: a relative ssl_certificate resolves against nginx.conf's directory" {
    _self_signed "$BATS_TEST_TMPDIR/conf/certs/r.crt" 3
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/ssl")
    printf '# configuration file %s:\nhttp { server { listen 443 ssl; ssl_certificate certs/r.crt; } }\n' \
        "$BATS_TEST_TMPDIR/conf/nginx.conf" > "$BATS_TEST_TMPDIR/dump"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/conf/certs/r.crt|expiring|"* ]]
}
