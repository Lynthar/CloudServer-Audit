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

_nginx_has_catchall() {
    # Check if there's a default_server with return 444
    grep -rE "default_server.*;" "$NGINX_SITES_ENABLED" 2>/dev/null | grep -q "return 444" || \
    grep -rE "listen.*default_server" "$NGINX_CONF_DIR" 2>/dev/null | head -1 | xargs -I{} grep -l "return 444" 2>/dev/null
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
            "Nginx is not installed (skip)" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'nginx.not_installed') - Skipping"
        return
    fi

    # Check default server / catchall
    print_item "$(i18n 'nginx.check_default_server')"
    _nginx_audit_catchall
}

_nginx_audit_catchall() {
    if _nginx_has_catchall; then
        local check=$(create_check_json \
            "nginx.catchall_exists" \
            "nginx" \
            "low" \
            "passed" \
            "$(i18n 'nginx.catchall_exists')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'nginx.catchall_exists')"
    else
        local check=$(create_check_json \
            "nginx.no_catchall" \
            "nginx" \
            "medium" \
            "failed" \
            "$(i18n 'nginx.no_catchall')" \
            "Missing default_server with return 444" \
            "$(i18n 'nginx.fix_add_catchall')" \
            "nginx.add_catchall")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'nginx.no_catchall')"
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
    print_info "Creating Nginx catchall configuration..."

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
        print_info "Generating self-signed certificate for catchall..."
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
            print_ok "Nginx reloaded"
            return 0
        fi
    else
        print_error "Nginx configuration test failed"
        rm -f "$NGINX_CATCHALL_CONF" "${NGINX_SITES_ENABLED}/99-catchall.conf"
        return 1
    fi
}
