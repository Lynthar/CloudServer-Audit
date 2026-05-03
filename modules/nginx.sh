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
                "medium" \
                "failed" \
                "$(i18n 'nginx.catchall_partial_80')" \
                "$(i18n 'nginx.catchall_partial_80_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'nginx.catchall_partial_80')"
            ;;
        443only)
            local check=$(create_check_json \
                "nginx.catchall_partial_443" \
                "nginx" \
                "medium" \
                "failed" \
                "$(i18n 'nginx.catchall_partial_443')" \
                "$(i18n 'nginx.catchall_partial_443_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'nginx.catchall_partial_443')"
            ;;
        *)
            local check=$(create_check_json \
                "nginx.no_catchall" \
                "nginx" \
                "medium" \
                "failed" \
                "$(i18n 'nginx.no_catchall')" \
                "$(i18n 'nginx.no_catchall_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'nginx.no_catchall')"
            ;;
    esac
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

    # Test config
    if _nginx_test_config; then
        print_ok "$(i18n 'nginx.catchall_created' "path=$NGINX_CATCHALL_CONF")"

        # Reload nginx
        if systemctl reload nginx 2>/dev/null; then
            print_ok "$(i18n 'nginx.nginx_reloaded')"
            return 0
        fi
    else
        print_error "$(i18n 'nginx.nginx_test_failed')"
        rm -f "$NGINX_CATCHALL_CONF" "${NGINX_SITES_ENABLED}/99-catchall.conf"
        return 1
    fi
}
