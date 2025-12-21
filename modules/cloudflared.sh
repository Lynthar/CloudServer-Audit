#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Cloudflared / Zero Trust module
# Copyright (c) 2024

# ==============================================================================
# Cloudflared Configuration
# ==============================================================================

CLOUDFLARED_CONFIG="/etc/cloudflared/config.yml"
CLOUDFLARED_SERVICE="cloudflared"
CLOUDFLARED_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/cloudflared"

# ==============================================================================
# Cloudflared Helper Functions
# ==============================================================================

_cloudflared_installed() {
    check_command cloudflared
}

_cloudflared_service_active() {
    systemctl is-active --quiet "$CLOUDFLARED_SERVICE" 2>/dev/null || \
    systemctl is-active --quiet "cloudflared-tunnel" 2>/dev/null || \
    systemctl is-active --quiet "cloudflared@*" 2>/dev/null
}

_cloudflared_has_config() {
    [[ -f "$CLOUDFLARED_CONFIG" ]] || \
    [[ -f "$HOME/.cloudflared/config.yml" ]] || \
    [[ -d "/etc/cloudflared" && -n "$(ls -A /etc/cloudflared/*.yml 2>/dev/null)" ]]
}

_cloudflared_get_tunnels() {
    cloudflared tunnel list 2>/dev/null | tail -n +2 | awk '{print $1, $2}'
}

_cloudflared_tunnel_running() {
    pgrep -f "cloudflared.*tunnel" &>/dev/null
}

_cloudflared_check_ingress_security() {
    local config="$1"
    local issues=()

    if [[ -f "$config" ]]; then
        # Check for catch-all rule
        if ! grep -q "service: http_status:404" "$config" 2>/dev/null; then
            issues+=("no_catchall")
        fi

        # Check for noTLSVerify
        if grep -q "noTLSVerify: true" "$config" 2>/dev/null; then
            issues+=("notls_verify")
        fi

        # Check originRequest settings
        if ! grep -q "originRequest:" "$config" 2>/dev/null; then
            issues+=("no_origin_request")
        fi
    fi

    echo "${issues[*]}"
}

# ==============================================================================
# Cloudflared Audit
# ==============================================================================

cloudflared_audit() {
    local module="cloudflared"

    # Check if Cloudflared is installed
    print_item "$(i18n 'cloudflared.check_installed')"
    if ! _cloudflared_installed; then
        local check=$(create_check_json \
            "cloudflared.not_installed" \
            "cloudflared" \
            "low" \
            "passed" \
            "$(i18n 'cloudflared.not_installed')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'cloudflared.not_installed')"
        return
    fi
    print_ok "$(i18n 'cloudflared.installed')"

    # Check service status
    print_item "$(i18n 'cloudflared.check_service')"
    _cloudflared_audit_service

    # Check configuration
    print_item "$(i18n 'cloudflared.check_config')"
    _cloudflared_audit_config

    # Check tunnel status
    print_item "$(i18n 'cloudflared.check_tunnels')"
    _cloudflared_audit_tunnels
}

_cloudflared_audit_service() {
    if _cloudflared_service_active; then
        local check=$(create_check_json \
            "cloudflared.service_active" \
            "cloudflared" \
            "low" \
            "passed" \
            "$(i18n 'cloudflared.service_active')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'cloudflared.service_active')"
    elif _cloudflared_tunnel_running; then
        local check=$(create_check_json \
            "cloudflared.tunnel_running" \
            "cloudflared" \
            "low" \
            "passed" \
            "$(i18n 'cloudflared.tunnel_running_manual')" \
            "$(i18n 'cloudflared.tunnel_not_systemd')" \
            "$(i18n 'cloudflared.fix_setup_service')" \
            "cloudflared.setup_service")
        state_add_check "$check"
        print_ok "$(i18n 'cloudflared.tunnel_running_manual')"
    else
        local check=$(create_check_json \
            "cloudflared.service_inactive" \
            "cloudflared" \
            "medium" \
            "failed" \
            "$(i18n 'cloudflared.service_not_running')" \
            "$(i18n 'cloudflared.no_tunnel_detected')" \
            "$(i18n 'cloudflared.fix_start_service')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'cloudflared.service_not_running')"
    fi
}

_cloudflared_audit_config() {
    if ! _cloudflared_has_config; then
        local check=$(create_check_json \
            "cloudflared.no_config" \
            "cloudflared" \
            "medium" \
            "failed" \
            "$(i18n 'cloudflared.config_not_found')" \
            "$(i18n 'cloudflared.config_not_found_desc')" \
            "$(i18n 'cloudflared.fix_create_config')" \
            "cloudflared.generate_config")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'cloudflared.config_not_found')"
        return
    fi

    # Find the config file
    local config=""
    if [[ -f "$CLOUDFLARED_CONFIG" ]]; then
        config="$CLOUDFLARED_CONFIG"
    elif [[ -f "$HOME/.cloudflared/config.yml" ]]; then
        config="$HOME/.cloudflared/config.yml"
    fi

    if [[ -n "$config" ]]; then
        local issues=$(_cloudflared_check_ingress_security "$config")

        if [[ -n "$issues" ]]; then
            local check=$(create_check_json \
                "cloudflared.config_issues" \
                "cloudflared" \
                "medium" \
                "failed" \
                "$(i18n 'cloudflared.config_has_issues')" \
                "$(i18n 'cloudflared.config_issues_desc' "issues=$issues")" \
                "$(i18n 'cloudflared.fix_review_config')" \
                "cloudflared.generate_config")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'cloudflared.config_issues_desc' "issues=$issues")"
        else
            local check=$(create_check_json \
                "cloudflared.config_ok" \
                "cloudflared" \
                "low" \
                "passed" \
                "$(i18n 'cloudflared.config_ok')" \
                "" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'cloudflared.config_ok')"
        fi
    fi
}

_cloudflared_audit_tunnels() {
    local tunnels=$(_cloudflared_get_tunnels)

    if [[ -n "$tunnels" ]]; then
        local tunnel_count=$(echo "$tunnels" | wc -l)
        local check=$(create_check_json \
            "cloudflared.tunnels_configured" \
            "cloudflared" \
            "low" \
            "passed" \
            "$(i18n 'cloudflared.tunnels_count' "count=$tunnel_count")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'cloudflared.tunnels_count' "count=$tunnel_count")"
    else
        local check=$(create_check_json \
            "cloudflared.no_tunnels" \
            "cloudflared" \
            "low" \
            "failed" \
            "$(i18n 'cloudflared.no_tunnels')" \
            "$(i18n 'cloudflared.no_tunnels_desc')" \
            "$(i18n 'cloudflared.fix_create_tunnel')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'cloudflared.no_tunnels')"
    fi
}

# ==============================================================================
# Cloudflared Fix Functions
# ==============================================================================

cloudflared_fix() {
    local fix_id="$1"

    case "$fix_id" in
        cloudflared.generate_config)
            _cloudflared_fix_generate_config
            ;;
        cloudflared.setup_service)
            _cloudflared_fix_setup_service
            ;;
        *)
            log_warn "Cloudflared fix not implemented: $fix_id"
            print_warn "$(i18n 'cloudflared.fix_manual_required')"
            return 1
            ;;
    esac
}

_cloudflared_fix_generate_config() {
    local template_dir="${CLOUDFLARED_TEMPLATES_DIR}"
    mkdir -p "$template_dir"

    local output_file="${template_dir}/config.yml.example"

    print_info "$(i18n 'cloudflared.generating_template')"

    cat > "$output_file" <<'EOF'
# Cloudflared Tunnel Configuration Template
# Generated by vpssec
#
# Instructions:
# 1. Create a tunnel: cloudflared tunnel create my-tunnel
# 2. Copy this file to /etc/cloudflared/config.yml
# 3. Replace <TUNNEL_ID> with your tunnel ID
# 4. Configure your ingress rules
# 5. Run: cloudflared service install

tunnel: <TUNNEL_ID>
credentials-file: /etc/cloudflared/<TUNNEL_ID>.json

# Origin request settings (security hardening)
originRequest:
  # Timeout for establishing connection to origin
  connectTimeout: 30s
  # Timeout for TCP keepalive
  tcpKeepAlive: 30s
  # Disable TLS verification (set to false in production!)
  noTLSVerify: false
  # Disable HTTP/2 to origin
  disableChunkedEncoding: false
  # HTTP Host header
  # httpHostHeader: ""

ingress:
  # Example: Web application
  - hostname: app.example.com
    service: http://localhost:8080
    originRequest:
      noTLSVerify: false

  # Example: SSH access via browser
  # - hostname: ssh.example.com
  #   service: ssh://localhost:22

  # Example: Private network access
  # - hostname: internal.example.com
  #   service: http://192.168.1.100:80
  #   originRequest:
  #     noTLSVerify: true  # Only for internal services

  # Catch-all rule (REQUIRED - must be last)
  - service: http_status:404

# Logging configuration
# loglevel: info
# logfile: /var/log/cloudflared/cloudflared.log

# Metrics server (optional)
# metrics: localhost:2000
EOF

    # Also create a systemd service template
    cat > "${template_dir}/cloudflared.service.example" <<'EOF'
# Cloudflared Systemd Service
# Copy to /etc/systemd/system/cloudflared.service

[Unit]
Description=Cloudflare Tunnel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=on-failure
RestartSec=5s

# Security hardening
User=cloudflared
Group=cloudflared
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/cloudflared
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF

    print_ok "$(i18n 'cloudflared.templates_generated' "dir=$template_dir")"
    print_info "$(i18n 'cloudflared.config_template' "file=$output_file")"
    print_info "$(i18n 'cloudflared.service_template' "file=${template_dir}/cloudflared.service.example")"
    print_msg ""
    print_msg "$(i18n 'cloudflared.next_steps')"
    print_msg "  1. $(i18n 'cloudflared.step_create_tunnel')"
    print_msg "  2. $(i18n 'cloudflared.step_copy_config' "file=$output_file")"
    print_msg "  3. $(i18n 'cloudflared.step_install_service')"

    return 0
}

_cloudflared_fix_setup_service() {
    print_info "$(i18n 'cloudflared.setting_up_service')"

    # Check if config exists
    if ! _cloudflared_has_config; then
        print_error "$(i18n 'cloudflared.config_required')"
        return 1
    fi

    # Install service using cloudflared
    if cloudflared service install 2>/dev/null; then
        print_ok "$(i18n 'cloudflared.service_installed')"

        # Enable and start
        systemctl enable cloudflared
        systemctl start cloudflared

        if _cloudflared_service_active; then
            print_ok "$(i18n 'cloudflared.service_now_active')"
            return 0
        else
            print_error "$(i18n 'cloudflared.service_start_failed')"
            print_info "$(i18n 'cloudflared.check_logs')"
            return 1
        fi
    else
        print_error "$(i18n 'cloudflared.service_install_failed')"
        return 1
    fi
}
