#!/usr/bin/env bats
# Coverage for webapp's four nginx fixes — the ones that write files; the other
# webapp fix_ids print advice and return 1. Two of the four are FIX_SAFE, so
# guide mode applies them unprompted: back up, write atomically, `nginx -t`, restore.

load helpers.bash

setup() {
    _vpssec_load
    # Without this, i18n echoes the KEY, so any assertion against a printed
    # message matches the key name and passes whether or not the string exists
    # — and a fix printing an unregistered key ships to the operator.
    i18n_load en_US
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

# nginx -T prints nginx.conf and each conf.d file, as nginx would after reading
# them; -t exits $1. The headers fix reads -T before it writes anything.
_nginx_stub() {
    export NGINX_TEST_CONF="$NGINX_CONF" NGINX_TEST_CONFD="$NGINX_CONFD" NGINX_TEST_RC="$1"
    _vpssec_stub_script nginx <<'SH'
if [[ "$*" == *-T* ]]; then
    for f in "$NGINX_TEST_CONF" "$NGINX_TEST_CONFD"/*.conf; do
        [[ -f "$f" ]] && printf '# configuration file %s:\n%s\n' "$f" "$(cat "$f")"
    done
    exit 0
fi
exit "$NGINX_TEST_RC"
SH
}

_nginx_validates() { _nginx_stub 0; }
_nginx_rejects()   { _nginx_stub 1; }

# nginx -t writes its diagnostic to stderr, which is the whole reason the fixes
# capture 2>&1 rather than discarding it.
_nginx_rejects_loudly() {
    _vpssec_stub_script nginx <<'SH'
echo "nginx: [emerg] unknown directive \"bogus\" in /etc/nginx/nginx.conf:7" >&2
exit 1
SH
}

_reload_fails() {
    _vpssec_stub_script systemctl <<'SH'
[[ "$1 $2" == "reload nginx" ]] && exit 1
exit 0
SH
}

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

# nginx.conf whose http{} holds the given lines and includes conf.d, as Debian's does.
_headers_nginx_conf() {
    { printf 'http {\n'; printf '%s\n' "$@"; printf '    include %s/*.conf;\n}\n' "$NGINX_CONFD"; } > "$NGINX_CONF"
}

# The value the map named $1 gives a response that lacks the header.
_map_value() {
    grep -A1 -F "\$vpssec_$1 {" "$NGINX_CONFD/security-headers.conf" | tail -1
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

@test "server_tokens: a reload that fails is a failed fix, not a success" {
    # Returning 0 here records the fix as complete while the running nginx is
    # still the one that leaks its version — the edit is on disk, not live.
    _stock_nginx_conf
    _reload_fails

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 1 ]
}

@test "server_tokens: nginx's own diagnostic reaches the operator" {
    # "Nginx configuration test failed" names neither the file nor the line;
    # discarding nginx's message leaves nothing to act on.
    VPSSEC_QUIET_SCAN=0
    _stock_nginx_conf
    _nginx_rejects_loudly

    run _webapp_fix_nginx_server_tokens
    [ "$status" -eq 1 ]
    grep -qF 'unknown directive' <<<"$output"
}

# ==============================================================================
# webapp.nginx_security_headers  (FIX_SAFE — writes an auto-included drop-in)
# ==============================================================================

@test "headers: each header is a map on the upstream's copy and an add_header of it" {
    # The map leaves the header empty, so unsent, when the application already
    # sends one: a second copy beside it is the conflict this fix used to cause.
    _headers_nginx_conf
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    local f="$NGINX_CONFD/security-headers.conf"
    grep -qxF 'map $upstream_http_x_frame_options $vpssec_x_frame_options {' "$f"
    [ "$(_map_value x_frame_options)" = '    ""      "SAMEORIGIN";' ]
    grep -qxF '    default "";' "$f"
    grep -qxF 'add_header X-Frame-Options $vpssec_x_frame_options always;' "$f"
    grep -qxF 'add_header X-Content-Type-Options $vpssec_x_content_type_options always;' "$f"
    grep -qxF 'add_header Referrer-Policy $vpssec_referrer_policy always;' "$f"
    grep -qxF 'add_header X-XSS-Protection $vpssec_x_xss_protection always;' "$f"
}

@test "headers: the legacy XSS auditor is disabled, not enabled" {
    # OWASP recommends X-XSS-Protection: 0. Sending "1; mode=block" turns on
    # a filter that is absent from current browsers and, where present, can
    # introduce XSS into a safe page — the opposite of this tool's purpose.
    _headers_nginx_conf
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    [ "$(_map_value x_xss_protection)" = '    ""      "0";' ]
}

@test "headers: one the operator sets in http{} is not written a second time" {
    _headers_nginx_conf '    add_header X-Frame-Options "DENY" always;'
    printf 'add_header Referrer-Policy "no-referrer";\n' > "$NGINX_CONFD/ops.conf"
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    local f="$NGINX_CONFD/security-headers.conf"
    _vpssec_refute grep -qE 'X-Frame-Options|Referrer-Policy' "$f"
    grep -qxF 'add_header X-Content-Type-Options $vpssec_x_content_type_options always;' "$f"
}

@test "headers: one a single server sets for itself is still written for the rest" {
    _headers_nginx_conf '    server { listen 80; server_name a.example; add_header X-Frame-Options DENY; }'
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -qxF 'add_header X-Frame-Options $vpssec_x_frame_options always;' "$NGINX_CONFD/security-headers.conf"
}

@test "headers: the drop-in's own earlier lines are not taken for the operator's" {
    _headers_nginx_conf
    printf '# Security headers - added by vpssec\nadd_header X-Frame-Options "SAMEORIGIN" always;\n' \
        > "$NGINX_CONFD/security-headers.conf"
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -qxF 'add_header X-Frame-Options $vpssec_x_frame_options always;' "$NGINX_CONFD/security-headers.conf"
}

@test "headers: with all four set in http{}, nothing is written and the fix fails" {
    # A site still missing one has its own add_header, which stops http{}'s
    # from reaching it; another http{}-level copy would change nothing there.
    VPSSEC_QUIET_SCAN=0
    _headers_nginx_conf '    add_header X-Frame-Options DENY;' '    add_header X-Content-Type-Options nosniff;' \
        '    add_header X-XSS-Protection 0;' '    add_header Referrer-Policy no-referrer;'
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 1 ]
    [ ! -f "$NGINX_CONFD/security-headers.conf" ]
    grep -qF 'has its own add_header' <<<"$output"
    _vpssec_refute _vpssec_stub_called systemctl 'reload nginx'
}

@test "headers: a config nginx -T cannot read fails the fix before it writes" {
    _headers_nginx_conf
    _vpssec_stub nginx 1
    _vpssec_begin_backup_session
    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 1 ]
    [ ! -f "$NGINX_CONFD/security-headers.conf" ]
    [ ! -s "${VPSSEC_BACKUP_SESSION}/.vpssec_created" ]
}

@test "headers: a newly created drop-in is recorded so rollback deletes it" {
    # The regression: backup_file was called only for an existing file, so a
    # first run left an active drop-in that no rollback could remove.
    _headers_nginx_conf
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -qxF "$NGINX_CONFD/security-headers.conf" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "headers: an existing drop-in is backed up before replacement" {
    _headers_nginx_conf
    printf '# operator headers\nadd_header X-Custom "1";\n' > "$NGINX_CONFD/security-headers.conf"
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -q 'X-Custom' "${VPSSEC_BACKUP_SESSION}${NGINX_CONFD}/security-headers.conf"
}

@test "headers: replacing the operator's drop-in says so and names the backup" {
    # This fix is FIX_SAFE, so it runs unprompted. Reporting "created" over a
    # file the operator wrote is the difference between a recoverable change
    # and one nobody knows happened.
    _headers_nginx_conf
    VPSSEC_QUIET_SCAN=0
    printf '# operator headers\nadd_header X-Custom "1";\n' > "$NGINX_CONFD/security-headers.conf"
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 0 ]
    grep -qi 'replaced' <<<"$output"
    grep -qF "${VPSSEC_BACKUP_SESSION}${NGINX_CONFD}/security-headers.conf" <<<"$output"
    _vpssec_refute grep -qi 'created' <<<"$output"
}

@test "headers: a reload that fails is a failed fix, not a success" {
    _headers_nginx_conf
    _reload_fails

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 1 ]
}

@test "headers: a drop-in nginx rejects is removed again" {
    # conf.d is auto-included, so leaving a rejected file behind breaks the
    # next reload of a server this fix was supposed to harden.
    _headers_nginx_conf
    _nginx_rejects

    run _webapp_fix_nginx_security_headers
    [ "$status" -eq 1 ]
    _vpssec_stub_called nginx '-t$'
    [ ! -f "$NGINX_CONFD/security-headers.conf" ]
}

@test "headers: a rejected change restores the operator's previous drop-in" {
    _headers_nginx_conf
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

@test "hsts: writing the template successfully is reported as success" {
    # The exit status is about the work done, not about whether the finding is
    # resolved: webapp.nginx_hsts is FIX_TEMPLATE_ONLY, and that is what keeps
    # the finding open while the template sits inert until the operator includes it.
    run _webapp_fix_nginx_hsts
    [ "$status" -eq 0 ]
}

@test "hsts: it tells the operator the header is commented out" {
    # The template alone is not actionable — the header ships commented, and
    # without this line the operator has a file and no reason to open it.
    VPSSEC_QUIET_SCAN=0
    run _webapp_fix_nginx_hsts
    [ "$status" -eq 0 ]
    grep -qiE 'uncomment|注释' <<<"$output"
}

@test "hsts: replacing an existing hsts.conf says so and names the backup" {
    # The template ships the header commented out, so overwriting an operator's
    # live hsts.conf turns HSTS off at the next reload. "Created" would hide that.
    VPSSEC_QUIET_SCAN=0
    printf 'add_header Strict-Transport-Security "max-age=300";\n' > "$NGINX_CONFD/hsts.conf"
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_hsts
    [ "$status" -eq 0 ]
    grep -qi 'replaced' <<<"$output"
    grep -qF "${VPSSEC_BACKUP_SESSION}${NGINX_CONFD}/hsts.conf" <<<"$output"
    _vpssec_refute grep -qi 'created' <<<"$output"
}

@test "hsts: a failed write is still a failure" {
    # The other direction: flipping the success path to 0 must not turn the
    # write-failure path green with it.
    rm -rf "$NGINX_CONFD"
    printf 'not a directory\n' > "$NGINX_CONFD"
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

@test "ssl: replacing an existing snippet says so and names the backup" {
    VPSSEC_QUIET_SCAN=0
    mkdir -p "$NGINX_SNIPPETS"
    printf 'ssl_protocols TLSv1.3;\n' > "$NGINX_SNIPPETS/ssl-security.conf"
    _vpssec_begin_backup_session

    run _webapp_fix_nginx_ssl
    [ "$status" -eq 0 ]
    grep -qi 'replaced' <<<"$output"
    grep -qF "${VPSSEC_BACKUP_SESSION}${NGINX_SNIPPETS}/ssl-security.conf" <<<"$output"
    _vpssec_refute grep -qi 'created' <<<"$output"
}

@test "ssl: writing the snippet successfully is reported as success" {
    # The exit status is about the work done; FIX_TEMPLATE_ONLY is what carries
    # "this does not resolve the finding" for a snippet that stays inert until
    # the operator includes it. Returning 1 here would report a good write as failure.
    run _webapp_fix_nginx_ssl
    [ "$status" -eq 0 ]
}

@test "ssl: it still tells the operator the snippet does nothing until included" {
    # The engine prints the map's manual-step text; this is the fix's own,
    # more specific instruction, and losing it would leave the operator with
    # a file and no include line.
    VPSSEC_QUIET_SCAN=0
    run _webapp_fix_nginx_ssl
    [ "$status" -eq 0 ]
    grep -qF 'include snippets/ssl-security.conf;' <<<"$output"
}

@test "ssl: a rejected config is distinguishable from the ordinary manual step" {
    # The two paths must differ in status, or "nginx refused the config" and "wrote
    # it, now go include it" are indistinguishable and a status-only assertion passes
    # with the validation branch deleted. helpers.bash sets QUIET_SCAN=1, silencing print_*.
    VPSSEC_QUIET_SCAN=0
    _nginx_rejects

    run _webapp_fix_nginx_ssl
    [ "$status" -eq 1 ]
    grep -qiE 'test[ _]failed' <<<"$output"
}

@test "ssl: a config nginx accepts does not claim a validation failure" {
    VPSSEC_QUIET_SCAN=0

    run _webapp_fix_nginx_ssl
    [ "$status" -eq 0 ]
    _vpssec_refute grep -qiE 'test[ _]failed' <<<"$output"
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "webapp_fix: an unknown fix id fails instead of silently doing nothing" {
    run webapp_fix "webapp.not_a_real_fix"
    [ "$status" -eq 1 ]
}

# ---- the backup contract ---------------------------------------------

@test "server_tokens: a backup that cannot be taken aborts the fix" {
    # This fix is FIX_SAFE and auto-applied, so a rewrite with no restorable
    # snapshot is the worst case of the whole batch.
    _vpssec_begin_backup_session
    printf 'http {\n    server_tokens on;\n}\n' > "$NGINX_CONF"
    _vpssec_stub cp 1

    run _webapp_fix_nginx_server_tokens
    [ "$status" -ne 0 ]
    grep -q 'server_tokens on;' "$NGINX_CONF"
}
