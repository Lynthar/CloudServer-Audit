#!/usr/bin/env bats
#
# Coverage for webapp's four nginx fixes — the ones that actually write
# files. The other webapp fix_ids print advice and return 1.
#
# Two of the four are FIX_SAFE, so guide mode applies them with no
# confirmation, to a live web server's configuration. What makes that
# survivable is a chain each of them has to keep intact: back up, write
# atomically, run `nginx -t`, and put the old file back if it does not
# validate. Every step is pinned here.
#
# Three defects motivated this file:
#
#   1. All three drop-in writers called backup_file only when the target
#      already existed. backup_file's other job is recording an ABSENT path
#      as fix-created, which is the only thing that lets a plan rollback
#      delete it — so a first run left an active conf.d drop-in that no
#      rollback could remove.
#   2. server_tokens was appended unconditionally. On a host with an
#      explicit `server_tokens on;` that produces two of the directive in
#      one http{} context, which nginx rejects as a duplicate — so `nginx
#      -t` failed, the backup was restored, and the fix could never repair
#      the hosts that had most explicitly opted into leaking their version.
#   3. The headers drop-in sent `X-XSS-Protection: 1; mode=block`. OWASP's
#      HTTP Headers cheat sheet recommends `0`: the XSS Auditor is gone
#      from current browsers and, where it survives, has been shown to
#      introduce XSS into otherwise safe pages. The audit only checks that
#      the header is present, never its value, so correcting this moves no
#      host's score.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"

    etc=$(_vpssec_fake_etc)
    export TMPDIR="$BATS_TEST_TMPDIR"

    NGINX_CONF="$etc/nginx/nginx.conf"
    NGINX_CONFD="$etc/nginx/conf.d"
    NGINX_SNIPPETS="$etc/nginx/snippets"
    mkdir -p "$NGINX_CONFD" "$NGINX_SNIPPETS"

    _vpssec_stub systemctl
    _nginx_validates
}

# ---- stubs ----------------------------------------------------------

_nginx_validates() { _vpssec_stub nginx 0; }
_nginx_rejects()   { _vpssec_stub nginx 1; }

# A stock Debian nginx.conf: the directive ships commented out.
_stock_nginx_conf() {
    cat > "$NGINX_CONF" <<'EOF'
user www-data;
worker_processes auto;

http {
    sendfile on;
    # server_tokens off;

    include /etc/nginx/conf.d/*.conf;
}
EOF
}

# Count the ACTIVE (uncommented) server_tokens directives.
_active_server_tokens() {
    grep -cE '^[^#]*server_tokens[[:space:]]' "$NGINX_CONF"
}

# ==============================================================================
# webapp.nginx_server_tokens  (FIX_SAFE — edits the live nginx.conf)
# ==============================================================================

@test "server_tokens: an already-active directive is left alone" {
    printf 'http {\n    server_tokens off;\n}\n' > "$NGINX_CONF"

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    [ "$(_active_server_tokens)" -eq 1 ]
    _vpssec_refute _vpssec_stub_called systemctl 'reload nginx'
}

@test "server_tokens: the commented default does not count as configured" {
    # Debian ships `# server_tokens off;`. Treating that as done is how this
    # fix used to report success while changing nothing, leaving the audit
    # to re-flag it forever.
    _stock_nginx_conf

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    [ "$(_active_server_tokens)" -eq 1 ]
}

@test "server_tokens: an explicit 'on' is rewritten, not duplicated" {
    # The regression. Two server_tokens in one http{} is a duplicate
    # directive; nginx refuses the config and the fix would roll itself back.
    printf 'http {\n    server_tokens on;\n    sendfile on;\n}\n' > "$NGINX_CONF"

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    [ "$(_active_server_tokens)" -eq 1 ]
    grep -qE '^[[:space:]]*server_tokens[[:space:]]+off;' "$NGINX_CONF"
    _vpssec_refute grep -qE '^[^#]*server_tokens[[:space:]]+on;' "$NGINX_CONF"
}

@test "server_tokens: unrelated directives survive the rewrite" {
    printf 'http {\n    server_tokens on;\n    sendfile on;\n}\n' > "$NGINX_CONF"

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    grep -qE '^[[:space:]]*sendfile on;' "$NGINX_CONF"
}

@test "server_tokens: the directive is added inside the http block" {
    _stock_nginx_conf

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    # The inserted line must follow `http {`, not precede it.
    local http_line tokens_line
    http_line=$(grep -n '^http' "$NGINX_CONF" | head -1 | cut -d: -f1)
    tokens_line=$(grep -nE '^[^#]*server_tokens' "$NGINX_CONF" | head -1 | cut -d: -f1)
    [ "$tokens_line" -gt "$http_line" ]
}

@test "server_tokens: nginx.conf is backed up before it is edited" {
    _stock_nginx_conf
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    grep -qE '^[[:space:]]*# server_tokens off;' "${VPSSEC_BACKUP_SESSION}${NGINX_CONF}"
}

@test "server_tokens: a config nginx rejects is rolled back" {
    # FIX_SAFE, so nobody confirmed this. A broken nginx.conf left live would
    # not surface until the next reload, restart or reboot.
    _stock_nginx_conf
    local before
    before=$(cat "$NGINX_CONF")
    _nginx_rejects

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 1 ]
    [ "$(cat "$NGINX_CONF")" = "$before" ]
}

@test "server_tokens: nginx is not reloaded when validation fails" {
    _stock_nginx_conf
    _nginx_rejects

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called systemctl 'reload nginx'
}

@test "server_tokens: nginx is reloaded once the change validates" {
    _stock_nginx_conf

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'reload nginx'
}

# ==============================================================================
# webapp.nginx_security_headers  (FIX_SAFE — writes an auto-included drop-in)
# ==============================================================================

@test "headers: the drop-in carries the recommended headers" {
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -q 'add_header X-Frame-Options' "$NGINX_CONFD/security-headers.conf"
    grep -q 'add_header X-Content-Type-Options "nosniff"' "$NGINX_CONFD/security-headers.conf"
    grep -q 'add_header Referrer-Policy' "$NGINX_CONFD/security-headers.conf"
}

@test "headers: the legacy XSS auditor is disabled, not enabled" {
    # OWASP recommends X-XSS-Protection: 0. Sending "1; mode=block" turns on
    # a filter that is absent from current browsers and, where present, can
    # introduce XSS into a safe page — the opposite of this tool's purpose.
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    # Both patterns require an ACTIVE directive: the explanatory comment
    # above it quotes the old value, so an unanchored search for
    # "mode=block" matches the commentary rather than the configuration.
    grep -qE '^[^#]*add_header[[:space:]]+X-XSS-Protection[[:space:]]+"0"' \
        "$NGINX_CONFD/security-headers.conf"
    _vpssec_refute grep -qE '^[^#]*add_header[[:space:]]+X-XSS-Protection[[:space:]]+"1' \
        "$NGINX_CONFD/security-headers.conf"
}

@test "headers: a newly created drop-in is recorded so rollback deletes it" {
    # The regression: backup_file was called only for an existing file, so a
    # first run left an active drop-in that no rollback could remove.
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -qxF "$NGINX_CONFD/security-headers.conf" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "headers: an existing drop-in is backed up before replacement" {
    printf '# operator headers\nadd_header X-Custom "1";\n' > "$NGINX_CONFD/security-headers.conf"
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -q 'X-Custom' "${VPSSEC_BACKUP_SESSION}${NGINX_CONFD}/security-headers.conf"
}

@test "headers: a drop-in nginx rejects is removed again" {
    # conf.d is auto-included, so leaving a rejected file behind breaks the
    # next reload of a server this fix was supposed to harden.
    _nginx_rejects

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 1 ]
    [ ! -f "$NGINX_CONFD/security-headers.conf" ]
}

@test "headers: a rejected change restores the operator's previous drop-in" {
    printf '# operator headers\nadd_header X-Custom "1";\n' > "$NGINX_CONFD/security-headers.conf"
    _nginx_rejects

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 1 ]
    grep -q 'X-Custom' "$NGINX_CONFD/security-headers.conf"
}

# ==============================================================================
# webapp.nginx_hsts  (FIX_RISKY — a template, deliberately inert)
# ==============================================================================

@test "hsts: the template is written" {
    run _webapp_fix_nginx_hsts
    [ -f "$NGINX_CONFD/hsts.conf" ]
}

@test "hsts: the directive stays commented out" {
    # An active HSTS header here would apply to every site on the host, and
    # once a browser has seen it, plain HTTP is refused for max-age. This
    # file exists to be edited, not to take effect on write.
    run _webapp_fix_nginx_hsts
    _vpssec_refute grep -qE '^[^#]*add_header Strict-Transport-Security' "$NGINX_CONFD/hsts.conf"
    grep -q 'Strict-Transport-Security' "$NGINX_CONFD/hsts.conf"
}

@test "hsts: a newly created template is recorded so rollback deletes it" {
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_hsts
    grep -qxF "$NGINX_CONFD/hsts.conf" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "hsts: the fix reports a manual step rather than success" {
    # Returning 0 would mark the HSTS finding resolved while nothing is on
    # the wire; the operator still has to uncomment it in their server block.
    run _webapp_fix_nginx_hsts
    [ "$status" -eq 1 ]
}

# ==============================================================================
# webapp.nginx_ssl_protocols / _ciphers  (FIX_RISKY — a snippet, inert)
# ==============================================================================

@test "ssl: the snippet lands in snippets/, never in conf.d/" {
    # conf.d is auto-included into http{}, where nginx.conf already sets
    # ssl_protocols and ssl_prefer_server_ciphers. A second copy in the same
    # context is a fatal duplicate-directive error.
    run _webapp_fix_nginx_ssl
    [ -f "$NGINX_SNIPPETS/ssl-security.conf" ]
    [ ! -f "$NGINX_CONFD/ssl-security.conf" ]
}

@test "ssl: only TLS 1.2 and 1.3 are offered" {
    run _webapp_fix_nginx_ssl
    grep -qE '^ssl_protocols TLSv1\.2 TLSv1\.3;' "$NGINX_SNIPPETS/ssl-security.conf"
    _vpssec_refute grep -qE '^ssl_protocols.*(SSLv|TLSv1\.1|TLSv1;)' "$NGINX_SNIPPETS/ssl-security.conf"
}

@test "ssl: a newly created snippet is recorded so rollback deletes it" {
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_ssl
    grep -qxF "$NGINX_SNIPPETS/ssl-security.conf" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "ssl: the fix reports a manual step rather than success" {
    # The snippet is inert until the operator includes it, so the weak-SSL
    # finding must stay open.
    run _webapp_fix_nginx_ssl
    [ "$status" -eq 1 ]
}

@test "ssl: a rejected config is distinguishable from the ordinary manual step" {
    # This fix returns 1 on BOTH paths — the snippet is inert until the
    # operator includes it, so success also returns 1. The exit status
    # therefore cannot tell the two apart, and asserting on it alone is a
    # test that passes with the validation branch deleted (mutation testing
    # caught exactly that). The printed message is the operator's only
    # signal, so that is what this pins.
    #
    # helpers.bash sets VPSSEC_QUIET_SCAN=1, which silences print_*.
    VPSSEC_QUIET_SCAN=0
    _nginx_rejects

    run _webapp_fix_nginx_ssl
    [ "$status" -eq 1 ]
    grep -qiE 'test[ _]failed' <<<"$output"
}

@test "ssl: a config nginx accepts does not claim a validation failure" {
    VPSSEC_QUIET_SCAN=0

    run _webapp_fix_nginx_ssl
    [ "$status" -eq 1 ]
    _vpssec_refute grep -qiE 'test[ _]failed' <<<"$output"
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "webapp_fix: an unknown fix id fails instead of silently doing nothing" {
    run webapp_fix "webapp.not_a_real_fix"
    [ "$status" -eq 1 ]
}
