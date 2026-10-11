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
_desc() { jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"; }

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

@test "headers: an add_header that is only a comment is missing" {
    _dump_with_site 'server { listen 80;
    # add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always; }'
    nginx_dump_reset
    nginx_dump_load
    run _webapp_nginx_security_headers
    grep -qxF X-Frame-Options <<<"$output"
    _vpssec_refute grep -qxF X-Content-Type-Options <<<"$output"
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

@test "certs: a relative ssl_certificate resolves against nginx.conf's directory" {
    _self_signed "$BATS_TEST_TMPDIR/conf/certs/r.crt" 3
    SSL_CERT_PATHS=("$BATS_TEST_TMPDIR/ssl")
    printf '# configuration file %s:\nhttp { server { listen 443 ssl; ssl_certificate certs/r.crt; } }\n' \
        "$BATS_TEST_TMPDIR/conf/nginx.conf" > "$BATS_TEST_TMPDIR/dump"
    nginx_dump_reset; nginx_dump_load

    run _webapp_ssl_cert_expiry
    [[ "$output" == "$BATS_TEST_TMPDIR/conf/certs/r.crt|expiring|"* ]]
}
