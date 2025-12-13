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
    print_item "Checking Cloudflared installation..."
    if ! _cloudflared_installed; then
        local check=$(create_check_json \
            "cloudflared.not_installed" \
            "cloudflared" \
            "low" \
            "passed" \
            "Cloudflared not installed" \
            "Cloudflared tunnel is not installed (skip)" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Cloudflared not installed - Skipping"
        return
    fi
    print_ok "Cloudflared installed"

    # Check service status
    print_item "Checking Cloudflared service status..."
    _cloudflared_audit_service

    # Check configuration
    print_item "Checking Cloudflared configuration..."
    _cloudflared_audit_config

    # Check tunnel status
    print_item "Checking tunnel status..."
    _cloudflared_audit_tunnels
}

_cloudflared_audit_service() {
    if _cloudflared_service_active; then
        local check=$(create_check_json \
            "cloudflared.service_active" \
            "cloudflared" \
            "low" \
            "passed" \
            "Cloudflared service is active" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Cloudflared service is active"
    elif _cloudflared_tunnel_running; then
        local check=$(create_check_json \
            "cloudflared.tunnel_running" \
            "cloudflared" \
            "low" \
            "passed" \
            "Cloudflared tunnel is running (manual)" \
            "Tunnel running but not as systemd service" \
            "Consider configuring as systemd service" \
            "cloudflared.setup_service")
        state_add_check "$check"
        print_ok "Cloudflared tunnel running (manual mode)"
    else
        local check=$(create_check_json \
            "cloudflared.service_inactive" \
            "cloudflared" \
            "medium" \
            "failed" \
            "Cloudflared service not running" \
            "No active Cloudflared tunnel detected" \
            "Start the Cloudflared service" \
            "")
        state_add_check "$check"
        print_severity "medium" "Cloudflared service not running"
    fi
}

_cloudflared_audit_config() {
    if ! _cloudflared_has_config; then
        local check=$(create_check_json \
            "cloudflared.no_config" \
            "cloudflared" \
            "medium" \
            "failed" \
            "Cloudflared configuration not found" \
            "No config.yml found in standard locations" \
            "Create configuration file" \
            "cloudflared.generate_config")
        state_add_check "$check"
        print_severity "medium" "Cloudflared configuration not found"
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
                "Cloudflared configuration has security issues" \
                "Issues: $issues" \
                "Review and fix configuration" \
                "cloudflared.generate_config")
            state_add_check "$check"
            print_severity "medium" "Configuration issues: $issues"
        else
            local check=$(create_check_json \
                "cloudflared.config_ok" \
                "cloudflared" \
                "low" \
                "passed" \
                "Cloudflared configuration OK" \
                "" \
                "" \
                "")
            state_add_check "$check"
            print_ok "Cloudflared configuration OK"
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
            "$tunnel_count Cloudflare tunnel(s) configured" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$tunnel_count Cloudflare tunnel(s) configured"
    else
        local check=$(create_check_json \
            "cloudflared.no_tunnels" \
            "cloudflared" \
            "low" \
            "failed" \
            "No Cloudflare tunnels configured" \
            "No tunnels found in cloudflared" \
            "Create a tunnel: cloudflared tunnel create <name>" \
            "")
        state_add_check "$check"
        print_severity "low" "No Cloudflare tunnels configured"
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
            print_warn "This fix requires manual configuration"
            return 1
            ;;
    esac
}

_cloudflared_fix_generate_config() {
    local template_dir="${CLOUDFLARED_TEMPLATES_DIR}"
    mkdir -p "$template_dir"

    local output_file="${template_dir}/config.yml.example"

    print_info "Generating Cloudflared configuration template..."

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

    print_ok "Templates generated in: $template_dir"
    print_info "Configuration template: $output_file"
    print_info "Service template: ${template_dir}/cloudflared.service.example"
    print_msg ""
    print_msg "Next steps:"
    print_msg "  1. Create tunnel: cloudflared tunnel create my-tunnel"
    print_msg "  2. Edit and copy config: cp $output_file /etc/cloudflared/config.yml"
    print_msg "  3. Install service: cloudflared service install"

    return 0
}

_cloudflared_fix_setup_service() {
    print_info "Setting up Cloudflared as systemd service..."

    # Check if config exists
    if ! _cloudflared_has_config; then
        print_error "Configuration file not found. Run generate_config first."
        return 1
    fi

    # Install service using cloudflared
    if cloudflared service install 2>/dev/null; then
        print_ok "Cloudflared service installed"

        # Enable and start
        systemctl enable cloudflared
        systemctl start cloudflared

        if _cloudflared_service_active; then
            print_ok "Cloudflared service is now active"
            return 0
        else
            print_error "Service installed but failed to start"
            print_info "Check logs: journalctl -u cloudflared"
            return 1
        fi
    else
        print_error "Failed to install Cloudflared service"
        return 1
    fi
}
