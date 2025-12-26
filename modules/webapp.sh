#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Web Application Security module
# Copyright (c) 2024
#
# This module checks:
# - Nginx security configuration
# - Apache security configuration
# - PHP security settings
# - SSL/TLS configuration
# - Sensitive file exposure
#
# Some fixes can be auto-applied (security headers),
# while others require manual review.

# ==============================================================================
# Configuration
# ==============================================================================

# Nginx configuration paths
NGINX_CONF="/etc/nginx/nginx.conf"
NGINX_CONFD="/etc/nginx/conf.d"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"

# Apache configuration paths
APACHE_CONF="/etc/apache2/apache2.conf"
APACHE_CONF_ALT="/etc/httpd/conf/httpd.conf"
APACHE_MODS_ENABLED="/etc/apache2/mods-enabled"
APACHE_SITES_ENABLED="/etc/apache2/sites-enabled"

# SSL certificate paths
SSL_CERT_PATHS=(
    "/etc/ssl/certs"
    "/etc/nginx/ssl"
    "/etc/letsencrypt/live"
    "/etc/apache2/ssl"
)

# Web root directories
WEB_ROOTS=(
    "/var/www/html"
    "/var/www"
    "/usr/share/nginx/html"
    "/home/*/public_html"
)

# Sensitive files/paths that should not be accessible
SENSITIVE_PATHS=(
    ".git"
    ".svn"
    ".env"
    ".htaccess"
    ".htpasswd"
    "wp-config.php.bak"
    "config.php.bak"
    "backup.sql"
    "dump.sql"
    "database.sql"
    "phpinfo.php"
    "info.php"
    "test.php"
    "adminer.php"
    ".DS_Store"
    "Thumbs.db"
    "composer.json"
    "package.json"
    ".env.local"
    ".env.production"
)

# Nginx security headers
declare -A NGINX_SECURITY_HEADERS=(
    ["X-Frame-Options"]="SAMEORIGIN"
    ["X-Content-Type-Options"]="nosniff"
    ["X-XSS-Protection"]="1; mode=block"
    ["Referrer-Policy"]="strict-origin-when-cross-origin"
)

# Weak SSL protocols
WEAK_SSL_PROTOCOLS=(
    "SSLv2"
    "SSLv3"
    "TLSv1"
    "TLSv1.0"
    "TLSv1.1"
)

# Weak cipher patterns
WEAK_CIPHER_PATTERNS=(
    "DES"
    "3DES"
    "RC4"
    "MD5"
    "NULL"
    "EXPORT"
    "anon"
    "SEED"
    "IDEA"
    "PSK"
)

# Apache dangerous modules
APACHE_DANGEROUS_MODULES=(
    "mod_info"
    "mod_status"
    "mod_userdir"
    "mod_autoindex"
)

# PHP dangerous functions
PHP_DANGEROUS_FUNCTIONS=(
    "exec"
    "passthru"
    "shell_exec"
    "system"
    "proc_open"
    "popen"
    "curl_exec"
    "curl_multi_exec"
    "show_source"
    "phpinfo"
    "eval"
    "assert"
    "create_function"
)

# Certificate expiry warning threshold (days)
CERT_EXPIRY_WARNING_DAYS=30

# ==============================================================================
# Helper Functions
# ==============================================================================

# Check if Nginx is installed
_webapp_nginx_installed() {
    command -v nginx &>/dev/null && [[ -f "$NGINX_CONF" ]]
}

# Check if Apache is installed
_webapp_apache_installed() {
    (command -v apache2 &>/dev/null || command -v httpd &>/dev/null) && \
    ([[ -f "$APACHE_CONF" ]] || [[ -f "$APACHE_CONF_ALT" ]])
}

# Check if PHP is installed
_webapp_php_installed() {
    command -v php &>/dev/null
}

# Get all Nginx configuration files
_webapp_get_nginx_configs() {
    local configs=()

    [[ -f "$NGINX_CONF" ]] && configs+=("$NGINX_CONF")

    # Add conf.d files
    if [[ -d "$NGINX_CONFD" ]]; then
        for f in "$NGINX_CONFD"/*.conf; do
            [[ -f "$f" ]] && configs+=("$f")
        done
    fi

    # Add sites-enabled
    if [[ -d "$NGINX_SITES_ENABLED" ]]; then
        for f in "$NGINX_SITES_ENABLED"/*; do
            [[ -f "$f" ]] && configs+=("$f")
        done
    fi

    printf '%s\n' "${configs[@]}"
}

# Get PHP configuration
_webapp_get_php_config() {
    local key="$1"
    php -i 2>/dev/null | grep -i "^$key" | head -1 | awk -F'=>' '{print $2}' | tr -d ' '
}

# Get PHP ini path
_webapp_get_php_ini() {
    php -i 2>/dev/null | grep "Loaded Configuration File" | awk -F'=>' '{print $2}' | tr -d ' '
}

# ==============================================================================
# Nginx Security Check Functions
# ==============================================================================

# Check server_tokens setting
_webapp_nginx_server_tokens() {
    local findings=()

    for config in $(_webapp_get_nginx_configs); do
        if grep -q "server_tokens\s*on" "$config" 2>/dev/null; then
            findings+=("$config: server_tokens on (exposes version)")
        fi
    done

    # Check if server_tokens is not explicitly set to off
    local has_off=false
    for config in $(_webapp_get_nginx_configs); do
        if grep -q "server_tokens\s*off" "$config" 2>/dev/null; then
            has_off=true
            break
        fi
    done

    if [[ "$has_off" == "false" ]]; then
        findings+=("server_tokens not explicitly disabled")
    fi

    printf '%s\n' "${findings[@]}"
}

# Check security headers
_webapp_nginx_security_headers() {
    local missing_headers=()

    for header in "${!NGINX_SECURITY_HEADERS[@]}"; do
        local found=false

        for config in $(_webapp_get_nginx_configs); do
            if grep -qi "add_header\s*$header" "$config" 2>/dev/null; then
                found=true
                break
            fi
        done

        if [[ "$found" == "false" ]]; then
            missing_headers+=("$header")
        fi
    done

    printf '%s\n' "${missing_headers[@]}"
}

# Check HSTS configuration
_webapp_nginx_hsts() {
    local has_hsts=false

    for config in $(_webapp_get_nginx_configs); do
        if grep -qi "Strict-Transport-Security" "$config" 2>/dev/null; then
            has_hsts=true
            break
        fi
    done

    [[ "$has_hsts" == "true" ]] && echo "configured" || echo "missing"
}

# Check directory listing
_webapp_nginx_directory_listing() {
    local findings=()

    for config in $(_webapp_get_nginx_configs); do
        if grep -q "autoindex\s*on" "$config" 2>/dev/null; then
            findings+=("$config: autoindex on")
        fi
    done

    printf '%s\n' "${findings[@]}"
}

# Check SSL protocols
_webapp_nginx_ssl_protocols() {
    local weak=()

    for config in $(_webapp_get_nginx_configs); do
        local protocols=$(grep -oP 'ssl_protocols\s+\K[^;]+' "$config" 2>/dev/null)
        [[ -z "$protocols" ]] && continue

        for weak_proto in "${WEAK_SSL_PROTOCOLS[@]}"; do
            if echo "$protocols" | grep -qi "$weak_proto"; then
                weak+=("$config: $weak_proto enabled")
            fi
        done
    done

    printf '%s\n' "${weak[@]}"
}

# Check SSL ciphers
_webapp_nginx_ssl_ciphers() {
    local weak=()

    for config in $(_webapp_get_nginx_configs); do
        local ciphers=$(grep -oP 'ssl_ciphers\s+["\047]?\K[^"\047;]+' "$config" 2>/dev/null)
        [[ -z "$ciphers" ]] && continue

        for weak_cipher in "${WEAK_CIPHER_PATTERNS[@]}"; do
            if echo "$ciphers" | grep -qi "$weak_cipher"; then
                weak+=("$weak_cipher")
            fi
        done
    done

    printf '%s\n' "${weak[@]}" | sort -u
}

# ==============================================================================
# Apache Security Check Functions
# ==============================================================================

# Get Apache configuration file
_webapp_get_apache_conf() {
    [[ -f "$APACHE_CONF" ]] && echo "$APACHE_CONF" && return
    [[ -f "$APACHE_CONF_ALT" ]] && echo "$APACHE_CONF_ALT" && return
    echo ""
}

# Check ServerSignature
_webapp_apache_server_signature() {
    local conf=$(_webapp_get_apache_conf)
    [[ -z "$conf" ]] && return

    if grep -qi "ServerSignature\s*On" "$conf" 2>/dev/null; then
        echo "on"
    elif grep -qi "ServerSignature\s*Off" "$conf" 2>/dev/null; then
        echo "off"
    else
        echo "default"  # Default is On
    fi
}

# Check ServerTokens
_webapp_apache_server_tokens() {
    local conf=$(_webapp_get_apache_conf)
    [[ -z "$conf" ]] && return

    local tokens=$(grep -ioP 'ServerTokens\s+\K\w+' "$conf" 2>/dev/null)
    echo "${tokens:-Full}"  # Default is Full
}

# Check TraceEnable
_webapp_apache_trace() {
    local conf=$(_webapp_get_apache_conf)
    [[ -z "$conf" ]] && return

    if grep -qi "TraceEnable\s*Off" "$conf" 2>/dev/null; then
        echo "off"
    else
        echo "on"  # Default is On
    fi
}

# Check directory indexing
_webapp_apache_directory_index() {
    local findings=()
    local conf=$(_webapp_get_apache_conf)
    [[ -z "$conf" ]] && return

    if grep -q "Options.*Indexes" "$conf" 2>/dev/null; then
        if ! grep -q "Options.*-Indexes" "$conf" 2>/dev/null; then
            findings+=("$conf: Indexes enabled")
        fi
    fi

    # Check sites-enabled
    if [[ -d "$APACHE_SITES_ENABLED" ]]; then
        for site in "$APACHE_SITES_ENABLED"/*; do
            [[ -f "$site" ]] || continue
            if grep -q "Options.*Indexes" "$site" 2>/dev/null; then
                if ! grep -q "Options.*-Indexes" "$site" 2>/dev/null; then
                    findings+=("$site: Indexes enabled")
                fi
            fi
        done
    fi

    printf '%s\n' "${findings[@]}"
}

# Check dangerous modules
_webapp_apache_modules() {
    local dangerous=()

    if [[ -d "$APACHE_MODS_ENABLED" ]]; then
        for mod in "${APACHE_DANGEROUS_MODULES[@]}"; do
            local mod_name="${mod#mod_}"
            if [[ -f "$APACHE_MODS_ENABLED/${mod_name}.load" ]]; then
                dangerous+=("$mod")
            fi
        done
    fi

    # Alternative: check with apachectl
    if command -v apachectl &>/dev/null; then
        local loaded=$(apachectl -M 2>/dev/null)
        for mod in "${APACHE_DANGEROUS_MODULES[@]}"; do
            local mod_name="${mod#mod_}_module"
            if echo "$loaded" | grep -qi "$mod_name"; then
                if ! printf '%s\n' "${dangerous[@]}" | grep -q "$mod"; then
                    dangerous+=("$mod")
                fi
            fi
        done
    fi

    printf '%s\n' "${dangerous[@]}"
}

# ==============================================================================
# PHP Security Check Functions
# ==============================================================================

# Check expose_php
_webapp_php_expose() {
    local val=$(_webapp_get_php_config "expose_php")
    echo "${val:-On}"
}

# Check display_errors
_webapp_php_display_errors() {
    local val=$(_webapp_get_php_config "display_errors")
    echo "${val:-Off}"
}

# Check allow_url_include
_webapp_php_allow_url_include() {
    local val=$(_webapp_get_php_config "allow_url_include")
    echo "${val:-Off}"
}

# Check allow_url_fopen
_webapp_php_allow_url_fopen() {
    local val=$(_webapp_get_php_config "allow_url_fopen")
    echo "${val:-On}"
}

# Check open_basedir
_webapp_php_open_basedir() {
    local val=$(_webapp_get_php_config "open_basedir")
    echo "${val:-none}"
}

# Check disable_functions
_webapp_php_disable_functions() {
    local disabled=$(_webapp_get_php_config "disable_functions")
    local not_disabled=()

    for func in "${PHP_DANGEROUS_FUNCTIONS[@]}"; do
        if ! echo "$disabled" | grep -qi "$func"; then
            not_disabled+=("$func")
        fi
    done

    printf '%s\n' "${not_disabled[@]}"
}

# Check session security
_webapp_php_session_security() {
    local issues=()

    # session.cookie_httponly
    local httponly=$(_webapp_get_php_config "session.cookie_httponly")
    if [[ "$httponly" != "1" && "$httponly" != "On" ]]; then
        issues+=("session.cookie_httponly not enabled")
    fi

    # session.cookie_secure
    local secure=$(_webapp_get_php_config "session.cookie_secure")
    if [[ "$secure" != "1" && "$secure" != "On" ]]; then
        issues+=("session.cookie_secure not enabled (for HTTPS sites)")
    fi

    # session.use_strict_mode
    local strict=$(_webapp_get_php_config "session.use_strict_mode")
    if [[ "$strict" != "1" && "$strict" != "On" ]]; then
        issues+=("session.use_strict_mode not enabled")
    fi

    printf '%s\n' "${issues[@]}"
}

# ==============================================================================
# SSL/TLS Security Check Functions
# ==============================================================================

# Check certificate expiry
_webapp_ssl_cert_expiry() {
    local findings=()

    for dir in "${SSL_CERT_PATHS[@]}"; do
        [[ -d "$dir" ]] || continue

        # Find certificate files
        while IFS= read -r -d '' cert; do
            local expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
            [[ -z "$expiry" ]] && continue

            local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
            [[ -z "$expiry_epoch" ]] && continue

            local now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            if [[ $days_left -lt 0 ]]; then
                findings+=("$cert|expired|$days_left days ago")
            elif [[ $days_left -lt $CERT_EXPIRY_WARNING_DAYS ]]; then
                findings+=("$cert|expiring|$days_left days left")
            fi
        done < <(find "$dir" -maxdepth 3 \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" \) -type f -print0 2>/dev/null)
    done

    printf '%s\n' "${findings[@]}"
}

# Check for self-signed certificates in production
_webapp_ssl_self_signed() {
    local findings=()

    for dir in "${SSL_CERT_PATHS[@]}"; do
        [[ -d "$dir" ]] || continue

        while IFS= read -r -d '' cert; do
            # Check if self-signed (issuer == subject)
            local issuer=$(openssl x509 -issuer -noout -in "$cert" 2>/dev/null | sed 's/issuer=//')
            local subject=$(openssl x509 -subject -noout -in "$cert" 2>/dev/null | sed 's/subject=//')

            if [[ "$issuer" == "$subject" ]]; then
                # Skip if it's in a "test" or "dev" path
                if [[ ! "$cert" =~ (test|dev|staging|localhost) ]]; then
                    findings+=("$cert")
                fi
            fi
        done < <(find "$dir" -maxdepth 3 \( -name "*.pem" -o -name "*.crt" \) -type f -print0 2>/dev/null)
    done

    printf '%s\n' "${findings[@]}"
}

# ==============================================================================
# Sensitive File Exposure Check Functions
# ==============================================================================

# Check for sensitive files in web roots
_webapp_sensitive_files() {
    local findings=()

    for root_pattern in "${WEB_ROOTS[@]}"; do
        for root in $root_pattern; do
            [[ -d "$root" ]] || continue

            for path in "${SENSITIVE_PATHS[@]}"; do
                # Check if file/directory exists
                local full_path="$root/$path"

                if [[ -e "$full_path" ]]; then
                    findings+=("$full_path")
                fi

                # Also check with find for pattern matching
                while IFS= read -r -d '' found; do
                    if ! printf '%s\n' "${findings[@]}" | grep -q "^$found$"; then
                        findings+=("$found")
                    fi
                done < <(find "$root" -maxdepth 3 -name "$path" -print0 2>/dev/null | head -20)
            done
        done
    done

    printf '%s\n' "${findings[@]}" | head -50
}

# Check for backup files
_webapp_backup_files() {
    local findings=()

    for root_pattern in "${WEB_ROOTS[@]}"; do
        for root in $root_pattern; do
            [[ -d "$root" ]] || continue

            # Common backup patterns
            while IFS= read -r -d '' file; do
                findings+=("$file")
            done < <(find "$root" -maxdepth 4 \( \
                -name "*.bak" -o \
                -name "*.backup" -o \
                -name "*.old" -o \
                -name "*~" -o \
                -name "*.save" -o \
                -name "*.orig" -o \
                -name "*.swp" -o \
                -name "*.sql" -o \
                -name "*.tar.gz" -o \
                -name "*.zip" \
            \) -type f -print0 2>/dev/null | head -30)
        done
    done

    printf '%s\n' "${findings[@]}"
}

# ==============================================================================
# Audit Function
# ==============================================================================

webapp_audit() {
    log_info "Running web application security audit"

    local check_json
    local has_webserver=false

    # === Nginx Security ===
    if _webapp_nginx_installed; then
        has_webserver=true
        print_item "$(i18n 'webapp.checking_nginx' 2>/dev/null || echo 'Checking Nginx security configuration...')"

        # 1. Server tokens
        local server_tokens=$(_webapp_nginx_server_tokens)
        local tokens_count=$(echo "$server_tokens" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$server_tokens" && "$tokens_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_server_tokens",
    "check_id": "webapp.nginx_server_tokens",
    "module": "webapp",
    "title": "$(i18n 'webapp.nginx_version_exposed' 2>/dev/null || echo 'Nginx Version Exposed')",
    "desc": "server_tokens not disabled - exposes Nginx version",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'webapp.add_server_tokens_off' 2>/dev/null || echo 'Add server_tokens off; to nginx.conf')",
    "fix_id": "webapp.nginx_server_tokens"
}
EOF
)
            state_add_check "$check_json"
        else
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_server_tokens_ok",
    "check_id": "webapp.nginx_server_tokens_ok",
    "module": "webapp",
    "title": "$(i18n 'webapp.nginx_version_hidden' 2>/dev/null || echo 'Nginx Version Hidden')",
    "desc": "server_tokens is disabled",
    "status": "passed",
    "severity": "info"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 2. Security headers
        local missing_headers=$(_webapp_nginx_security_headers)
        local missing_count=$(echo "$missing_headers" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$missing_headers" && "$missing_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_security_headers",
    "check_id": "webapp.nginx_security_headers",
    "module": "webapp",
    "title": "$(i18n 'webapp.missing_security_headers' 2>/dev/null || echo 'Missing Security Headers'): $missing_count",
    "desc": "$(echo "$missing_headers" | tr '\n' ', ' | sed 's/,$//')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.add_security_headers' 2>/dev/null || echo 'Add security headers to Nginx configuration')",
    "fix_id": "webapp.nginx_security_headers"
}
EOF
)
            state_add_check "$check_json"
        else
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_security_headers_ok",
    "check_id": "webapp.nginx_security_headers_ok",
    "module": "webapp",
    "title": "$(i18n 'webapp.security_headers_ok' 2>/dev/null || echo 'Security Headers Configured')",
    "desc": "All recommended security headers present",
    "status": "passed",
    "severity": "info"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 3. HSTS
        local hsts=$(_webapp_nginx_hsts)
        if [[ "$hsts" == "missing" ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_hsts_missing",
    "check_id": "webapp.nginx_hsts_missing",
    "module": "webapp",
    "title": "$(i18n 'webapp.hsts_missing' 2>/dev/null || echo 'HSTS Not Configured')",
    "desc": "Strict-Transport-Security header not found",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.add_hsts' 2>/dev/null || echo 'Add HSTS header for HTTPS enforcement')",
    "fix_id": "webapp.nginx_hsts"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 4. Directory listing
        local dir_listing=$(_webapp_nginx_directory_listing)
        local dir_count=$(echo "$dir_listing" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$dir_listing" && "$dir_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_directory_listing",
    "check_id": "webapp.nginx_directory_listing",
    "module": "webapp",
    "title": "$(i18n 'webapp.directory_listing_on' 2>/dev/null || echo 'Directory Listing Enabled')",
    "desc": "$(echo "$dir_listing" | tr '\n' '; ' | sed 's/;$//')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.disable_autoindex' 2>/dev/null || echo 'Set autoindex off; in Nginx configuration')",
    "fix_id": "webapp.nginx_directory_listing"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 5. SSL protocols
        local weak_ssl=$(_webapp_nginx_ssl_protocols)
        local weak_ssl_count=$(echo "$weak_ssl" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$weak_ssl" && "$weak_ssl_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_weak_ssl",
    "check_id": "webapp.nginx_weak_ssl",
    "module": "webapp",
    "title": "$(i18n 'webapp.weak_ssl_protocols' 2>/dev/null || echo 'Weak SSL/TLS Protocols Enabled'): $weak_ssl_count",
    "desc": "$(echo "$weak_ssl" | head -3 | tr '\n' '; ' | sed 's/;$//')",
    "status": "failed",
    "severity": "high",
    "suggestion": "$(i18n 'webapp.disable_weak_ssl' 2>/dev/null || echo 'Use only TLSv1.2 and TLSv1.3')",
    "fix_id": "webapp.nginx_ssl_protocols"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 6. SSL ciphers
        local weak_ciphers=$(_webapp_nginx_ssl_ciphers)
        local weak_cipher_count=$(echo "$weak_ciphers" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$weak_ciphers" && "$weak_cipher_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.nginx_weak_ciphers",
    "check_id": "webapp.nginx_weak_ciphers",
    "module": "webapp",
    "title": "$(i18n 'webapp.weak_ciphers' 2>/dev/null || echo 'Weak SSL Ciphers Detected'): $weak_cipher_count",
    "desc": "$(echo "$weak_ciphers" | tr '\n' ', ' | sed 's/,$//')",
    "status": "failed",
    "severity": "high",
    "suggestion": "$(i18n 'webapp.update_ciphers' 2>/dev/null || echo 'Update ssl_ciphers to use only strong ciphers')",
    "fix_id": "webapp.nginx_ssl_ciphers"
}
EOF
)
            state_add_check "$check_json"
        fi
    fi

    # === Apache Security ===
    if _webapp_apache_installed; then
        has_webserver=true
        print_item "$(i18n 'webapp.checking_apache' 2>/dev/null || echo 'Checking Apache security configuration...')"

        # 7. ServerSignature
        local sig=$(_webapp_apache_server_signature)
        if [[ "$sig" != "off" ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.apache_server_signature",
    "check_id": "webapp.apache_server_signature",
    "module": "webapp",
    "title": "$(i18n 'webapp.apache_signature_on' 2>/dev/null || echo 'Apache ServerSignature Enabled')",
    "desc": "ServerSignature exposes Apache version in error pages",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'webapp.set_signature_off' 2>/dev/null || echo 'Set ServerSignature Off in apache2.conf')",
    "fix_id": "webapp.apache_server_signature"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 8. ServerTokens
        local tokens=$(_webapp_apache_server_tokens)
        if [[ "$tokens" != "Prod" && "$tokens" != "ProductOnly" ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.apache_server_tokens",
    "check_id": "webapp.apache_server_tokens",
    "module": "webapp",
    "title": "$(i18n 'webapp.apache_tokens_verbose' 2>/dev/null || echo 'Apache ServerTokens Verbose')",
    "desc": "ServerTokens is $tokens - exposes too much information",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'webapp.set_tokens_prod' 2>/dev/null || echo 'Set ServerTokens Prod in apache2.conf')",
    "fix_id": "webapp.apache_server_tokens"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 9. TraceEnable
        local trace=$(_webapp_apache_trace)
        if [[ "$trace" != "off" ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.apache_trace_enabled",
    "check_id": "webapp.apache_trace_enabled",
    "module": "webapp",
    "title": "$(i18n 'webapp.apache_trace_on' 2>/dev/null || echo 'Apache TRACE Method Enabled')",
    "desc": "TRACE method can be used for XST attacks",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.disable_trace' 2>/dev/null || echo 'Set TraceEnable Off in apache2.conf')",
    "fix_id": "webapp.apache_trace"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 10. Directory indexing
        local dir_idx=$(_webapp_apache_directory_index)
        local dir_idx_count=$(echo "$dir_idx" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$dir_idx" && "$dir_idx_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.apache_directory_index",
    "check_id": "webapp.apache_directory_index",
    "module": "webapp",
    "title": "$(i18n 'webapp.apache_indexes_on' 2>/dev/null || echo 'Apache Directory Indexing Enabled')",
    "desc": "$(echo "$dir_idx" | tr '\n' '; ' | sed 's/;$//')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.disable_indexes' 2>/dev/null || echo 'Use Options -Indexes in configuration')",
    "fix_id": "webapp.apache_directory_index"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 11. Dangerous modules
        local danger_mods=$(_webapp_apache_modules)
        local danger_count=$(echo "$danger_mods" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$danger_mods" && "$danger_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.apache_dangerous_modules",
    "check_id": "webapp.apache_dangerous_modules",
    "module": "webapp",
    "title": "$(i18n 'webapp.dangerous_modules' 2>/dev/null || echo 'Potentially Dangerous Apache Modules'): $danger_count",
    "desc": "$(echo "$danger_mods" | tr '\n' ', ' | sed 's/,$//')",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'webapp.review_modules' 2>/dev/null || echo 'Review and disable unnecessary modules')",
    "fix_id": "webapp.apache_modules"
}
EOF
)
            state_add_check "$check_json"
        fi
    fi

    # === PHP Security ===
    if _webapp_php_installed; then
        print_item "$(i18n 'webapp.checking_php' 2>/dev/null || echo 'Checking PHP security configuration...')"

        local php_issues=()

        # 12. expose_php
        local expose=$(_webapp_php_expose)
        if [[ "$expose" == "On" || "$expose" == "1" ]]; then
            php_issues+=("expose_php=On")
        fi

        # 13. display_errors
        local display=$(_webapp_php_display_errors)
        if [[ "$display" == "On" || "$display" == "1" ]]; then
            php_issues+=("display_errors=On")
        fi

        # 14. allow_url_include
        local url_include=$(_webapp_php_allow_url_include)
        if [[ "$url_include" == "On" || "$url_include" == "1" ]]; then
            php_issues+=("allow_url_include=On (DANGEROUS)")
        fi

        if [[ ${#php_issues[@]} -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.php_security_issues",
    "check_id": "webapp.php_security_issues",
    "module": "webapp",
    "title": "$(i18n 'webapp.php_security_issues' 2>/dev/null || echo 'PHP Security Issues'): ${#php_issues[@]}",
    "desc": "$(printf '%s, ' "${php_issues[@]}" | sed 's/, $//')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.fix_php_settings' 2>/dev/null || echo 'Update php.ini with secure settings')",
    "fix_id": "webapp.php_security"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 15. Dangerous functions not disabled
        local not_disabled=$(_webapp_php_disable_functions)
        local not_disabled_count=$(echo "$not_disabled" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$not_disabled" && "$not_disabled_count" -gt 3 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.php_dangerous_functions",
    "check_id": "webapp.php_dangerous_functions",
    "module": "webapp",
    "title": "$(i18n 'webapp.dangerous_functions' 2>/dev/null || echo 'Dangerous PHP Functions Enabled'): $not_disabled_count",
    "desc": "$(echo "$not_disabled" | head -5 | tr '\n' ', ' | sed 's/,$//')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.disable_functions' 2>/dev/null || echo 'Add dangerous functions to disable_functions in php.ini')",
    "fix_id": "webapp.php_disable_functions"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 16. Session security
        local session_issues=$(_webapp_php_session_security)
        local session_count=$(echo "$session_issues" | grep -c '.' 2>/dev/null || echo 0)

        if [[ -n "$session_issues" && "$session_count" -gt 0 ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.php_session_security",
    "check_id": "webapp.php_session_security",
    "module": "webapp",
    "title": "$(i18n 'webapp.session_security' 2>/dev/null || echo 'PHP Session Security Issues'): $session_count",
    "desc": "$(echo "$session_issues" | tr '\n' '; ' | sed 's/;$//')",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'webapp.fix_session_settings' 2>/dev/null || echo 'Update session settings in php.ini')",
    "fix_id": "webapp.php_session"
}
EOF
)
            state_add_check "$check_json"
        fi

        # 17. open_basedir
        local basedir=$(_webapp_php_open_basedir)
        if [[ "$basedir" == "none" || -z "$basedir" ]]; then
            check_json=$(cat <<EOF
{
    "id": "webapp.php_open_basedir",
    "check_id": "webapp.php_open_basedir",
    "module": "webapp",
    "title": "$(i18n 'webapp.open_basedir_not_set' 2>/dev/null || echo 'PHP open_basedir Not Configured')",
    "desc": "No directory restriction for PHP file access",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'webapp.set_open_basedir' 2>/dev/null || echo 'Set open_basedir to restrict PHP file access')",
    "fix_id": "webapp.php_open_basedir"
}
EOF
)
            state_add_check "$check_json"
        fi
    fi

    # === SSL/TLS Certificate Checks ===
    print_item "$(i18n 'webapp.checking_ssl' 2>/dev/null || echo 'Checking SSL/TLS certificates...')"

    # 18. Certificate expiry
    local expiring=$(_webapp_ssl_cert_expiry)
    local expiring_count=$(echo "$expiring" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$expiring" && "$expiring_count" -gt 0 ]]; then
        local expired_list=""
        while IFS='|' read -r cert status days; do
            [[ -z "$cert" ]] && continue
            expired_list+="$cert ($days); "
        done <<< "$expiring"

        local severity="medium"
        echo "$expiring" | grep -q "expired" && severity="high"

        check_json=$(cat <<EOF
{
    "id": "webapp.ssl_cert_expiry",
    "check_id": "webapp.ssl_cert_expiry",
    "module": "webapp",
    "title": "$(i18n 'webapp.cert_expiring' 2>/dev/null || echo 'SSL Certificates Expiring/Expired'): $expiring_count",
    "desc": "${expired_list%;*}",
    "status": "failed",
    "severity": "$severity",
    "suggestion": "$(i18n 'webapp.renew_certs' 2>/dev/null || echo 'Renew SSL certificates before expiry')",
    "fix_id": "webapp.ssl_cert_expiry"
}
EOF
)
        state_add_check "$check_json"
    fi

    # === Sensitive File Exposure ===
    print_item "$(i18n 'webapp.checking_exposure' 2>/dev/null || echo 'Checking for sensitive file exposure...')"

    # 19. Sensitive files
    local sensitive=$(_webapp_sensitive_files)
    local sensitive_count=$(echo "$sensitive" | grep -c '.' 2>/dev/null || echo 0)

    if [[ -n "$sensitive" && "$sensitive_count" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "webapp.sensitive_files",
    "check_id": "webapp.sensitive_files",
    "module": "webapp",
    "title": "$(i18n 'webapp.sensitive_files_found' 2>/dev/null || echo 'Sensitive Files in Web Root'): $sensitive_count",
    "desc": "$(echo "$sensitive" | head -5 | tr '\n' '; ' | sed 's/;$//')",
    "status": "failed",
    "severity": "high",
    "suggestion": "$(i18n 'webapp.remove_sensitive' 2>/dev/null || echo 'Remove or restrict access to sensitive files')",
    "fix_id": "webapp.sensitive_files"
}
EOF
)
        state_add_check "$check_json"
    else
        check_json=$(cat <<EOF
{
    "id": "webapp.sensitive_files_ok",
    "check_id": "webapp.sensitive_files_ok",
    "module": "webapp",
    "title": "$(i18n 'webapp.no_sensitive_files' 2>/dev/null || echo 'No Sensitive Files Exposed')",
    "desc": "No common sensitive files found in web roots",
    "status": "passed",
    "severity": "info"
}
EOF
)
        state_add_check "$check_json"
    fi

    # 20. Backup files
    local backups=$(_webapp_backup_files)
    local backup_count=$(echo "$backups" | grep -c '.' 2>/dev/null || echo 0)

    if [[ -n "$backups" && "$backup_count" -gt 0 ]]; then
        check_json=$(cat <<EOF
{
    "id": "webapp.backup_files",
    "check_id": "webapp.backup_files",
    "module": "webapp",
    "title": "$(i18n 'webapp.backup_files_found' 2>/dev/null || echo 'Backup Files in Web Root'): $backup_count",
    "desc": "$(echo "$backups" | head -5 | tr '\n' '; ' | sed 's/;$//')",
    "status": "failed",
    "severity": "medium",
    "suggestion": "$(i18n 'webapp.remove_backups' 2>/dev/null || echo 'Remove backup files from web-accessible directories')",
    "fix_id": "webapp.backup_files"
}
EOF
)
        state_add_check "$check_json"
    fi

    # Summary if no webserver found
    if [[ "$has_webserver" == "false" ]]; then
        check_json=$(cat <<EOF
{
    "id": "webapp.no_webserver",
    "check_id": "webapp.no_webserver",
    "module": "webapp",
    "title": "$(i18n 'webapp.no_webserver' 2>/dev/null || echo 'No Web Server Detected')",
    "desc": "Neither Nginx nor Apache detected - skipping web server checks",
    "status": "passed",
    "severity": "info"
}
EOF
)
        state_add_check "$check_json"
    fi

    return 0
}

# ==============================================================================
# Fix Functions
# ==============================================================================

webapp_fix() {
    local fix_id="$1"

    case "$fix_id" in
        webapp.nginx_server_tokens)
            _webapp_fix_nginx_server_tokens
            ;;

        webapp.nginx_security_headers)
            _webapp_fix_nginx_security_headers
            ;;

        webapp.nginx_hsts)
            _webapp_fix_nginx_hsts
            ;;

        webapp.nginx_directory_listing)
            print_info "$(i18n 'webapp.manual_fix' 2>/dev/null || echo 'Manual fix required')"
            echo ""
            echo "$(i18n 'webapp.autoindex_fix' 2>/dev/null || echo 'To disable directory listing'):"
            echo ""
            echo "  # In nginx.conf or site config:"
            echo "  autoindex off;"
            echo ""
            return 1
            ;;

        webapp.nginx_ssl_protocols|webapp.nginx_ssl_ciphers)
            _webapp_fix_nginx_ssl
            ;;

        webapp.apache_server_signature|webapp.apache_server_tokens|webapp.apache_trace)
            _webapp_fix_apache_security
            ;;

        webapp.apache_directory_index)
            print_info "$(i18n 'webapp.manual_fix' 2>/dev/null || echo 'Manual fix required')"
            echo ""
            echo "$(i18n 'webapp.indexes_fix' 2>/dev/null || echo 'To disable directory indexing'):"
            echo ""
            echo "  # In apache2.conf or site config:"
            echo "  <Directory /var/www/html>"
            echo "      Options -Indexes"
            echo "  </Directory>"
            echo ""
            return 1
            ;;

        webapp.apache_modules)
            print_info "$(i18n 'webapp.review_alert' 2>/dev/null || echo 'Review Required')"
            echo ""
            echo "$(i18n 'webapp.modules_review' 2>/dev/null || echo 'Review and disable unnecessary modules'):"
            echo ""
            local mods=$(_webapp_apache_modules)
            for mod in $mods; do
                local mod_name="${mod#mod_}"
                echo "  a2dismod $mod_name"
            done
            echo ""
            echo "$(i18n 'webapp.then_restart' 2>/dev/null || echo 'Then restart Apache'):"
            echo "  systemctl restart apache2"
            return 1
            ;;

        webapp.php_security|webapp.php_dangerous_functions|webapp.php_session|webapp.php_open_basedir)
            _webapp_fix_php_info
            ;;

        webapp.ssl_cert_expiry)
            print_info "$(i18n 'webapp.cert_renewal' 2>/dev/null || echo 'Certificate Renewal Required')"
            echo ""
            echo "$(i18n 'webapp.renewal_options' 2>/dev/null || echo 'Renewal options'):"
            echo ""
            echo "  # For Let's Encrypt:"
            echo "  certbot renew"
            echo ""
            echo "  # For manual certificates:"
            echo "  # Purchase/obtain new certificate and replace"
            echo ""
            local expiring=$(_webapp_ssl_cert_expiry)
            echo "Expiring certificates:"
            echo "$expiring" | while IFS='|' read -r cert status days; do
                [[ -z "$cert" ]] && continue
                echo "  $cert ($days)"
            done
            return 1
            ;;

        webapp.sensitive_files)
            print_warn "$(i18n 'webapp.sensitive_warning' 2>/dev/null || echo 'Sensitive Files Detected')"
            echo ""
            echo "$(i18n 'webapp.files_to_remove' 2>/dev/null || echo 'Files to remove or protect'):"
            echo ""
            local sensitive=$(_webapp_sensitive_files)
            echo "$sensitive" | while read -r file; do
                [[ -z "$file" ]] && continue
                echo "  rm -f \"$file\"  # or move outside web root"
            done
            echo ""
            echo "$(i18n 'webapp.block_access' 2>/dev/null || echo 'Or block access in web server config'):"
            echo ""
            echo "  # Nginx:"
            echo "  location ~ /\\. { deny all; }"
            echo ""
            echo "  # Apache (.htaccess or config):"
            echo "  <FilesMatch \"^\\.(git|env|htaccess)\">"
            echo "      Require all denied"
            echo "  </FilesMatch>"
            return 1
            ;;

        webapp.backup_files)
            print_warn "$(i18n 'webapp.backup_warning' 2>/dev/null || echo 'Backup Files Detected')"
            echo ""
            echo "$(i18n 'webapp.backups_to_remove' 2>/dev/null || echo 'Backup files to remove'):"
            echo ""
            local backups=$(_webapp_backup_files)
            echo "$backups" | while read -r file; do
                [[ -z "$file" ]] && continue
                echo "  rm -f \"$file\""
            done
            return 1
            ;;

        *)
            log_warn "Unknown fix_id: $fix_id"
            return 1
            ;;
    esac
}

# Fix: Nginx server_tokens
_webapp_fix_nginx_server_tokens() {
    print_info "$(i18n 'webapp.fixing_server_tokens' 2>/dev/null || echo 'Adding server_tokens off...')"

    # Check if already in main nginx.conf http block
    if grep -q "server_tokens\s*off" "$NGINX_CONF" 2>/dev/null; then
        print_ok "$(i18n 'webapp.already_configured' 2>/dev/null || echo 'Already configured')"
        return 0
    fi

    # Backup
    backup_file "$NGINX_CONF"

    # Add to http block
    if grep -q "^http\s*{" "$NGINX_CONF" 2>/dev/null; then
        sed -i '/^http\s*{/a\    server_tokens off;' "$NGINX_CONF"
    else
        # Try adding after first opening brace in http section
        sed -i '/http\s*{/a\    server_tokens off;' "$NGINX_CONF"
    fi

    # Test and reload
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        print_ok "$(i18n 'webapp.server_tokens_fixed' 2>/dev/null || echo 'server_tokens off added and Nginx reloaded')"
        return 0
    else
        print_error "$(i18n 'webapp.nginx_test_failed' 2>/dev/null || echo 'Nginx configuration test failed')"
        return 1
    fi
}

# Fix: Nginx security headers
_webapp_fix_nginx_security_headers() {
    print_info "$(i18n 'webapp.adding_headers' 2>/dev/null || echo 'Adding security headers...')"

    # Create a drop-in configuration
    local headers_conf="$NGINX_CONFD/security-headers.conf"

    # Backup if exists
    [[ -f "$headers_conf" ]] && backup_file "$headers_conf"

    cat > "$headers_conf" << 'EOF'
# Security headers - added by vpssec
# Add to server blocks or include in http block

# Prevent clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# XSS protection (legacy, but still useful)
add_header X-XSS-Protection "1; mode=block" always;

# Referrer policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Note: Add Content-Security-Policy based on your application needs
# add_header Content-Security-Policy "default-src 'self';" always;
EOF

    # Test and reload
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        print_ok "$(i18n 'webapp.headers_added' 2>/dev/null || echo 'Security headers configuration created'): $headers_conf"
        print_info "$(i18n 'webapp.include_headers' 2>/dev/null || echo 'Include in server blocks if not automatic')"
        return 0
    else
        print_error "$(i18n 'webapp.nginx_test_failed' 2>/dev/null || echo 'Nginx configuration test failed')"
        return 1
    fi
}

# Fix: Nginx HSTS
_webapp_fix_nginx_hsts() {
    print_info "$(i18n 'webapp.adding_hsts' 2>/dev/null || echo 'Adding HSTS header...')"

    local hsts_conf="$NGINX_CONFD/hsts.conf"

    [[ -f "$hsts_conf" ]] && backup_file "$hsts_conf"

    cat > "$hsts_conf" << 'EOF'
# HSTS - added by vpssec
# Only enable for HTTPS sites!
# Uncomment in your SSL server blocks:
#
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
#
# Warning: Once enabled, browsers will refuse HTTP connections
# Make sure HTTPS is working properly before enabling
EOF

    print_ok "$(i18n 'webapp.hsts_template_created' 2>/dev/null || echo 'HSTS template created'): $hsts_conf"
    print_warn "$(i18n 'webapp.hsts_warning' 2>/dev/null || echo 'Uncomment and add to HTTPS server blocks manually')"
    return 1
}

# Fix: Nginx SSL configuration
_webapp_fix_nginx_ssl() {
    print_info "$(i18n 'webapp.updating_ssl' 2>/dev/null || echo 'Creating secure SSL configuration...')"

    local ssl_conf="$NGINX_CONFD/ssl-security.conf"

    [[ -f "$ssl_conf" ]] && backup_file "$ssl_conf"

    cat > "$ssl_conf" << 'EOF'
# Secure SSL configuration - added by vpssec
# Include in your SSL server blocks

# Only use TLS 1.2 and 1.3
ssl_protocols TLSv1.2 TLSv1.3;

# Prefer server ciphers
ssl_prefer_server_ciphers on;

# Modern cipher suite
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# Enable session resumption
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# DH parameters (generate with: openssl dhparam -out /etc/nginx/dhparam.pem 2048)
# ssl_dhparam /etc/nginx/dhparam.pem;
EOF

    print_ok "$(i18n 'webapp.ssl_config_created' 2>/dev/null || echo 'Secure SSL configuration created'): $ssl_conf"
    print_info "$(i18n 'webapp.include_in_ssl' 2>/dev/null || echo 'Include in SSL server blocks'): include $ssl_conf;"
    return 0
}

# Fix: Apache security settings
_webapp_fix_apache_security() {
    print_info "$(i18n 'webapp.apache_security_info' 2>/dev/null || echo 'Apache Security Configuration')"
    echo ""
    echo "$(i18n 'webapp.add_to_apache' 2>/dev/null || echo 'Add to apache2.conf or httpd.conf'):"
    echo ""
    echo "  # Hide Apache version"
    echo "  ServerTokens Prod"
    echo "  ServerSignature Off"
    echo ""
    echo "  # Disable TRACE method"
    echo "  TraceEnable Off"
    echo ""
    echo "  # Security headers"
    echo "  Header always set X-Frame-Options \"SAMEORIGIN\""
    echo "  Header always set X-Content-Type-Options \"nosniff\""
    echo "  Header always set X-XSS-Protection \"1; mode=block\""
    echo ""
    echo "$(i18n 'webapp.enable_headers_mod' 2>/dev/null || echo 'Enable headers module'):"
    echo "  a2enmod headers"
    echo "  systemctl restart apache2"
    return 1
}

# Fix: PHP security information
_webapp_fix_php_info() {
    local ini=$(_webapp_get_php_ini)
    print_info "$(i18n 'webapp.php_security_info' 2>/dev/null || echo 'PHP Security Configuration')"
    echo ""
    echo "$(i18n 'webapp.php_ini_location' 2>/dev/null || echo 'PHP configuration file'): $ini"
    echo ""
    echo "$(i18n 'webapp.recommended_settings' 2>/dev/null || echo 'Recommended settings'):"
    echo ""
    echo "  ; Hide PHP version"
    echo "  expose_php = Off"
    echo ""
    echo "  ; Don't display errors in production"
    echo "  display_errors = Off"
    echo "  log_errors = On"
    echo ""
    echo "  ; Disable dangerous features"
    echo "  allow_url_include = Off"
    echo "  allow_url_fopen = Off"
    echo ""
    echo "  ; Disable dangerous functions"
    echo "  disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,show_source,phpinfo"
    echo ""
    echo "  ; Session security"
    echo "  session.cookie_httponly = 1"
    echo "  session.cookie_secure = 1"
    echo "  session.use_strict_mode = 1"
    echo ""
    echo "  ; Directory restriction"
    echo "  open_basedir = /var/www/:/tmp/"
    echo ""
    echo "$(i18n 'webapp.restart_php' 2>/dev/null || echo 'After changes, restart PHP-FPM'):"
    echo "  systemctl restart php*-fpm"
    return 1
}
