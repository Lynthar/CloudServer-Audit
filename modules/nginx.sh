#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Nginx catchall module
# Copyright (c) 2024

# ==============================================================================
# Nginx Paths
# ==============================================================================

NGINX_CONF_DIR="/etc/nginx"
NGINX_SITES_AVAILABLE="${NGINX_CONF_DIR}/sites-available"
NGINX_SITES_ENABLED="${NGINX_CONF_DIR}/sites-enabled"
NGINX_CATCHALL_CONF="${NGINX_SITES_AVAILABLE}/99-catchall.conf"

# ==============================================================================
# Nginx Helper Functions
# ==============================================================================

_nginx_installed() {
    check_command nginx
}

# Determine catchall coverage from a full nginx config dump (typically
# `nginx -T` output). Echoes one of: both | 80only | 443only | none.
# Best-effort awk parser that tracks brace depth to scope server blocks
# and looks within each block for (a) a listen directive on port 80 / 443
# carrying default_server and (b) a `return 444;` directive in the same
# block. Strips inline `#` comments. Comments at column 0 are stripped
# too — nginx config doesn't put `#` in quoted values.
_nginx_catchall_state_from_text() {
    awk '
        function reset_block() { d80=0; d443=0; ret=0 }
        BEGIN { depth=0; in_server=0; c80=0; c443=0; reset_block() }
        {
            sub(/[[:space:]]*#.*$/, "")
            if ($0 ~ /^[[:space:]]*$/) next

            opens  = gsub(/[{]/, "&")
            closes = gsub(/[}]/, "&")
            pre_depth = depth

            if (!in_server && /[[:space:]]*server[[:space:]]*[{]/) {
                in_server = 1
                close_depth = pre_depth
                reset_block()
            }

            if (in_server) {
                if (/listen/ && /default_server/) {
                    # Match port 80 / 443 with a colon-or-whitespace
                    # boundary, accommodating: `listen 80 ...`,
                    # `listen 0.0.0.0:80 ...`, `listen [::]:80 ...`,
                    # `listen *:80 ...`. The trailing class prevents
                    # 8080 / 4430 from matching.
                    if ($0 ~ /:80([[:space:]]|;)/    || $0 ~ /[[:space:]]80([[:space:]]|;)/)  d80  = 1
                    if ($0 ~ /:443([[:space:]]|;)/   || $0 ~ /[[:space:]]443([[:space:]]|;)/) d443 = 1
                }
                # Boundary: line-start or after { ; whitespace, so a
                # one-liner like server { listen 80 default_server; return 444; }
                # parses correctly while substrings such as something_return
                # do not false-match.
                if ($0 ~ /(^|[{;[:space:]])return[[:space:]]+444[[:space:]]*;/) ret = 1
            }

            depth += opens - closes

            if (in_server && depth <= close_depth) {
                if (ret) {
                    if (d80)  c80  = 1
                    if (d443) c443 = 1
                }
                in_server = 0
            }
        }
        END {
            if (c80 && c443) print "both"
            else if (c80)    print "80only"
            else if (c443)   print "443only"
            else             print "none"
        }
    ' <<<"$1"
}

_nginx_catchall_state() {
    local effective
    if effective=$(nginx -T 2>/dev/null) && [[ -n "$effective" ]]; then
        _nginx_catchall_state_from_text "$effective"
        return 0
    fi

    # Fallback when nginx -T is unavailable. File-level imprecision: we
    # can't track server-block scope across files so we accept any file
    # containing both a default_server listen on the port AND a
    # `return 444;` line. The previous implementation chained
    #   grep -r ... | head -1 | xargs -I{} grep -l "return 444"
    # which fed xargs the entire `path:matched-line` from grep -r and
    # looked for a file literally named "path:matched-line".
    local f found_80=0 found_443=0
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        grep -qE "^[[:space:]]*return[[:space:]]+444[[:space:]]*;" "$f" 2>/dev/null || continue
        grep -qE "listen[^;]*(:80([[:space:]]|;)|[[:space:]]80([[:space:]]|;))[^;]*default_server" "$f" 2>/dev/null && found_80=1
        grep -qE "listen[^;]*(:443([[:space:]]|;)|[[:space:]]443([[:space:]]|;))[^;]*default_server" "$f" 2>/dev/null && found_443=1
    done < <(grep -rlE "listen.*default_server" "$NGINX_CONF_DIR" 2>/dev/null)

    if   [[ $found_80 -eq 1 && $found_443 -eq 1 ]]; then echo "both"
    elif [[ $found_80 -eq 1 ]];                      then echo "80only"
    elif [[ $found_443 -eq 1 ]];                     then echo "443only"
    else                                                  echo "none"
    fi
}

# Backwards-compat boolean wrapper. Returns 0 only when both 80 and 443
# have catchalls — partial coverage is treated as missing because that's
# the behavior change M7 was about.
_nginx_has_catchall() {
    [[ "$(_nginx_catchall_state)" == "both" ]]
}

_nginx_test_config() {
    nginx -t 2>/dev/null
}

# ----- DoS-hardening helpers (timeouts + rate limiting) ----------------------
# nginx -T flattens every included config file into a single stream, so a
# single awk pass can find the *effective* last setting for a directive
# across http/server/location contexts. Per nginx semantics, a directive
# declared in a more specific context overrides a less specific one for
# that context's traffic; we treat "any occurrence > threshold" as a
# finding because that means at least one served hostname / location is
# weaker than the policy. Using END { print last } as the proxy is good
# enough for 90% of real configs; the alternative (full block-scope
# parsing) is too brittle for an auditor.

# Read the effective value of a directive from a `nginx -T` dump. If the
# directive doesn't appear anywhere, return the supplied default.
_nginx_get_directive_value() {
    local config="$1" key="$2" default="$3"
    local value
    value=$(awk -v k="$key" '
        # Strip inline comments first so a commented-out line never matches.
        { sub(/[[:space:]]*#.*$/, "") }
        $1 == k {
            sub("^[[:space:]]*" k "[[:space:]]+", "")
            sub(/[[:space:]]*;.*$/, "")
            last = $0
        }
        END { if (last != "") print last }
    ' <<<"$config")
    echo "${value:-$default}"
}

# Does the directive appear at least once in the effective config?
_nginx_has_directive() {
    local config="$1" key="$2"
    awk -v k="$key" '
        { sub(/[[:space:]]*#.*$/, "") }
        $1 == k { found = 1; exit }
        END { exit !found }
    ' <<<"$config"
}

# nginx time values can be a bare integer (seconds), or carry a ms/s/m/h
# suffix. Some directives accept multiple values (e.g. `keepalive_timeout
# 65s 60s` — server-side + Keep-Alive header) — first token wins for
# audit purposes. Anything unparseable returns 0 (treated as "safe"
# rather than fabricating a number that would trigger a false flag).
_nginx_parse_seconds() {
    local val="$1"
    # First whitespace-separated token only.
    val="${val%% *}"
    val="${val%;}"
    case "$val" in
        ''|0)         echo 0 ;;
        *[!0-9]*)
            if   [[ "$val" =~ ^([0-9]+)ms$ ]]; then echo $(( BASH_REMATCH[1] / 1000 ))
            elif [[ "$val" =~ ^([0-9]+)s$  ]]; then echo "${BASH_REMATCH[1]}"
            elif [[ "$val" =~ ^([0-9]+)m$  ]]; then echo $(( BASH_REMATCH[1] * 60 ))
            elif [[ "$val" =~ ^([0-9]+)h$  ]]; then echo $(( BASH_REMATCH[1] * 3600 ))
            elif [[ "$val" =~ ^([0-9]+)d$  ]]; then echo $(( BASH_REMATCH[1] * 86400 ))
            else                                    echo 0
            fi
            ;;
        *)            echo "$val" ;;
    esac
}

# ==============================================================================
# Nginx Audit
# ==============================================================================

nginx_audit() {
    local module="nginx"

    # Check if Nginx is installed
    print_item "$(i18n 'nginx.check_installed')"
    if ! _nginx_installed; then
        local check=$(create_check_json \
            "nginx.not_installed" \
            "nginx" \
            "low" \
            "passed" \
            "$(i18n 'nginx.not_installed')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'nginx.not_installed')"
        return
    fi

    # Check default server / catchall
    print_item "$(i18n 'nginx.check_default_server')"
    _nginx_audit_catchall

    # Check DoS hardening (timeouts, rate limiting, slow-attack defenses).
    # References: CIS NGINX Benchmark v2.0.1 (control 5.2.1 for
    # client_header_timeout / client_body_timeout) + nginx official
    # DDoS-mitigation guide (trac #2590, nginx.org blog).
    print_item "$(i18n 'nginx.check_dos_hardening' 2>/dev/null || echo 'Checking DoS hardening')"
    _nginx_audit_dos_hardening
}

_nginx_audit_catchall() {
    local state
    state=$(_nginx_catchall_state)

    case "$state" in
        both)
            local check=$(create_check_json \
                "nginx.catchall_exists" \
                "nginx" \
                "low" \
                "passed" \
                "$(i18n 'nginx.catchall_exists')" \
                "$(i18n 'nginx.catchall_both_desc')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'nginx.catchall_exists')"
            ;;
        80only)
            local check=$(create_check_json \
                "nginx.catchall_partial_80" \
                "nginx" \
                "low" \
                "failed" \
                "$(i18n 'nginx.catchall_partial_80')" \
                "$(i18n 'nginx.catchall_partial_80_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "low" "$(i18n 'nginx.catchall_partial_80')"
            ;;
        443only)
            local check=$(create_check_json \
                "nginx.catchall_partial_443" \
                "nginx" \
                "low" \
                "failed" \
                "$(i18n 'nginx.catchall_partial_443')" \
                "$(i18n 'nginx.catchall_partial_443_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "low" "$(i18n 'nginx.catchall_partial_443')"
            ;;
        *)
            local check=$(create_check_json \
                "nginx.no_catchall" \
                "nginx" \
                "low" \
                "failed" \
                "$(i18n 'nginx.no_catchall')" \
                "$(i18n 'nginx.no_catchall_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "low" "$(i18n 'nginx.no_catchall')"
            ;;
    esac
}

_nginx_audit_dos_hardening() {
    # Pull the effective config once; every sub-check awk-scans the same
    # blob instead of re-running nginx -T.
    local effective
    if ! effective=$(nginx -T 2>/dev/null) || [[ -z "$effective" ]]; then
        log_warn "nginx -T returned no output; skipping DoS hardening audit"
        return 0
    fi

    local issues=()
    local check

    # 1. client_header_timeout — CIS 5.2.1, default 60s, recommended ≤10s.
    local cht_raw cht
    cht_raw=$(_nginx_get_directive_value "$effective" "client_header_timeout" "60s")
    cht=$(_nginx_parse_seconds "$cht_raw")
    if (( cht > 10 )); then
        check=$(create_check_json \
            "nginx.client_header_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.client_header_timeout_high' 2>/dev/null || echo 'client_header_timeout too high')" \
            "client_header_timeout=$cht_raw (CIS 5.2.1: ≤10s; nginx default 60s leaves Slowloris vulnerable)" \
            "$(i18n 'nginx.fix_dos_timeouts' 2>/dev/null || echo 'Set client_header_timeout 10s; in /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("client_header_timeout=$cht_raw")
        print_severity "low" "$(i18n 'nginx.client_header_timeout_high' 2>/dev/null || echo 'client_header_timeout too high'): $cht_raw"
    fi

    # 2. client_body_timeout — CIS 5.2.1, default 60s, recommended ≤10s.
    local cbt_raw cbt
    cbt_raw=$(_nginx_get_directive_value "$effective" "client_body_timeout" "60s")
    cbt=$(_nginx_parse_seconds "$cbt_raw")
    if (( cbt > 10 )); then
        check=$(create_check_json \
            "nginx.client_body_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.client_body_timeout_high' 2>/dev/null || echo 'client_body_timeout too high')" \
            "client_body_timeout=$cbt_raw (CIS 5.2.1: ≤10s)" \
            "$(i18n 'nginx.fix_dos_timeouts' 2>/dev/null || echo 'Set client_body_timeout 10s; in /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("client_body_timeout=$cbt_raw")
        print_severity "low" "$(i18n 'nginx.client_body_timeout_high' 2>/dev/null || echo 'client_body_timeout too high'): $cbt_raw"
    fi

    # 3. keepalive_timeout — default 75s, recommended ≤30s (F5 NGINX STIG).
    local kt_raw kt
    kt_raw=$(_nginx_get_directive_value "$effective" "keepalive_timeout" "75s")
    kt=$(_nginx_parse_seconds "$kt_raw")
    if (( kt > 30 )); then
        check=$(create_check_json \
            "nginx.keepalive_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.keepalive_timeout_high' 2>/dev/null || echo 'keepalive_timeout too high')" \
            "keepalive_timeout=$kt_raw (recommended: ≤30s; nginx default 75s)" \
            "$(i18n 'nginx.fix_dos_keepalive' 2>/dev/null || echo 'Set keepalive_timeout 30s; in /etc/nginx/nginx.conf')" \
            "")
        state_add_check "$check"
        issues+=("keepalive_timeout=$kt_raw")
        print_severity "low" "$(i18n 'nginx.keepalive_timeout_high' 2>/dev/null || echo 'keepalive_timeout too high'): $kt_raw"
    fi

    # 4. send_timeout — default 60s, recommended ≤10s.
    local st_raw st
    st_raw=$(_nginx_get_directive_value "$effective" "send_timeout" "60s")
    st=$(_nginx_parse_seconds "$st_raw")
    if (( st > 10 )); then
        check=$(create_check_json \
            "nginx.send_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.send_timeout_high' 2>/dev/null || echo 'send_timeout too high')" \
            "send_timeout=$st_raw (recommended: ≤10s; nginx default 60s)" \
            "$(i18n 'nginx.fix_dos_timeouts' 2>/dev/null || echo 'Set send_timeout 10s; in /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("send_timeout=$st_raw")
        print_severity "low" "$(i18n 'nginx.send_timeout_high' 2>/dev/null || echo 'send_timeout too high'): $st_raw"
    fi

    # 5. Rate limiting presence — no severity escalation: many static
    # / internal sites legitimately don't need it. Recorded as low.
    if ! _nginx_has_directive "$effective" "limit_req_zone"; then
        check=$(create_check_json \
            "nginx.no_rate_limiting" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.no_rate_limiting' 2>/dev/null || echo 'No rate limiting configured (no limit_req_zone)')" \
            "No limit_req_zone directive in effective config — public-facing nginx benefits from per-IP request rate caps to throttle brute-force and scraping attacks" \
            "$(i18n 'nginx.fix_dos_rate_limit' 2>/dev/null || echo 'Add: limit_req_zone \$binary_remote_addr zone=perip:10m rate=10r/s; to nginx.conf http block, then apply per-location with limit_req zone=perip burst=20 nodelay;')" \
            "")
        state_add_check "$check"
        issues+=("no_rate_limiting")
        print_severity "low" "$(i18n 'nginx.no_rate_limiting' 2>/dev/null || echo 'No rate limiting configured')"
    fi

    # 6. reset_timedout_connection — default off, nginx mitigation guide
    # explicitly recommends "on" to close lingering misbehaving clients.
    local rtc
    rtc=$(_nginx_get_directive_value "$effective" "reset_timedout_connection" "off")
    if [[ "$rtc" != "on" ]]; then
        check=$(create_check_json \
            "nginx.reset_timedout_connection_off" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.reset_timedout_connection_off' 2>/dev/null || echo 'reset_timedout_connection not enabled')" \
            "reset_timedout_connection is off (nginx default). Enabling forcibly closes connections with misbehaving / slow clients, accelerating slowloris recovery" \
            "$(i18n 'nginx.fix_dos_reset_timedout' 2>/dev/null || echo 'Add: reset_timedout_connection on; to /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("reset_timedout_connection=off")
        print_severity "low" "$(i18n 'nginx.reset_timedout_connection_off' 2>/dev/null || echo 'reset_timedout_connection not enabled')"
    fi

    # Positive companion — only when EVERY directive met the threshold.
    if (( ${#issues[@]} == 0 )); then
        check=$(create_check_json \
            "nginx.dos_hardening_ok" \
            "nginx" \
            "low" \
            "passed" \
            "$(i18n 'nginx.dos_hardening_ok' 2>/dev/null || echo 'DoS hardening directives configured')" \
            "client_header/body/send_timeout, keepalive_timeout, rate limiting, and reset_timedout_connection all match CIS / nginx-mitigation recommendations" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'nginx.dos_hardening_ok' 2>/dev/null || echo 'DoS hardening directives configured')"
    fi
}

# ==============================================================================
# Nginx Fix Functions
# ==============================================================================

nginx_fix() {
    local fix_id="$1"

    case "$fix_id" in
        nginx.add_catchall)
            _nginx_fix_add_catchall
            ;;
        *)
            log_error "Unknown nginx fix: $fix_id"
            return 1
            ;;
    esac
}

_nginx_fix_add_catchall() {
    print_info "$(i18n 'nginx.creating_catchall')"

    mkdir -p "$NGINX_SITES_AVAILABLE"

    # Create catchall config
    cat > "$NGINX_CATCHALL_CONF" <<'EOF'
# vpssec - Nginx catchall configuration
# Prevents certificate/hostname leakage for unknown requests

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Return 444 (connection closed without response)
    return 444;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # Self-signed certificate for rejecting unknown hosts
    # Generate with: openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    #   -keyout /etc/nginx/ssl/default.key -out /etc/nginx/ssl/default.crt \
    #   -subj "/CN=invalid"
    ssl_certificate /etc/nginx/ssl/default.crt;
    ssl_certificate_key /etc/nginx/ssl/default.key;

    # Return 444 (connection closed without response)
    return 444;
}
EOF

    # Create SSL directory and self-signed cert if needed
    mkdir -p /etc/nginx/ssl

    if [[ ! -f /etc/nginx/ssl/default.crt ]]; then
        print_info "$(i18n 'nginx.generating_cert')"
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/default.key \
            -out /etc/nginx/ssl/default.crt \
            -subj "/CN=invalid" 2>/dev/null
        chmod 600 /etc/nginx/ssl/default.key
    fi

    # Enable the site
    if [[ -d "$NGINX_SITES_ENABLED" ]]; then
        ln -sf "$NGINX_CATCHALL_CONF" "${NGINX_SITES_ENABLED}/99-catchall.conf"
    fi

    # Test config first; on failure remove the staged files and bail.
    if ! _nginx_test_config; then
        print_error "$(i18n 'nginx.nginx_test_failed')"
        rm -f "$NGINX_CATCHALL_CONF" "${NGINX_SITES_ENABLED}/99-catchall.conf"
        return 1
    fi
    print_ok "$(i18n 'nginx.catchall_created' "path=$NGINX_CATCHALL_CONF")"

    # Reload nginx. The config tested clean, but if the reload itself fails
    # the catch-all is staged on disk yet NOT live, so the host is still
    # exposed to the hostname/cert leak this fix is meant to close. Report
    # that as a failure (return 1) instead of the previous silent success:
    # the old `if reload; then return 0; fi` fell through with no return, so
    # bash returned 0 (the `if` completes successfully even when the
    # condition is false) and the fix was recorded as done.
    if systemctl reload nginx 2>/dev/null; then
        print_ok "$(i18n 'nginx.nginx_reloaded')"
        return 0
    fi
    print_error "$(i18n 'nginx.reload_failed_staged')"
    return 1
}
