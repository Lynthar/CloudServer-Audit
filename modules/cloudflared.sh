#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Cloudflared / Zero Trust module
# Copyright (c) 2024

# --- Cloudflared Configuration ---

# Where cloudflared itself looks for config.yml / config.yaml (upstream
# config/configuration.go): these system directories, and every user's
# ~/.cloudflared, ~/.cloudflare-warp and ~/cloudflare-warp.
CLOUDFLARED_CONFIG_DIRS=(/etc/cloudflared /usr/local/etc/cloudflared)
CLOUDFLARED_SERVICE="cloudflared"
CLOUDFLARED_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/cloudflared"

# --- Cloudflared Helper Functions ---

_cloudflared_installed() {
    check_command cloudflared
}

_cloudflared_service_active() {
    if systemctl is-active --quiet "$CLOUDFLARED_SERVICE" 2>/dev/null; then
        return 0
    fi
    if systemctl is-active --quiet "cloudflared-tunnel" 2>/dev/null; then
        return 0
    fi
    # Template instances (cloudflared@<name>.service): plain `is-active` with
    # a quoted glob has implementation-defined behavior on zero matches
    # (systemd issue #6379), so use list-units which is deterministic.
    [[ -n "$(systemctl list-units --type=service --state=running --no-legend 'cloudflared@*' 2>/dev/null)" ]]
}

# The first config file in directory $1 under cloudflared's own names.
_cloudflared_config_in() {
    local f
    for f in "$1/config.yml" "$1/config.yaml"; do
        [[ -f "$f" ]] && { echo "$f"; return 0; }
    done
    return 1
}

# Pure-data variant of _cloudflared_find_user_config for testability.
# $1: getent-passwd content (multi-line). Echoes the first user config
# (UID >= 1000, cloudflared's user directories) that exists, exits 1 if none.
_cloudflared_find_user_config_from_passwd() {
    local passwd_text="$1"
    local user pwd uid gid gecos home shell d
    while IFS=: read -r user pwd uid gid gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [[ "$uid" -lt 1000 ]] && continue
        [[ -n "$home" ]] || continue
        for d in .cloudflared .cloudflare-warp cloudflare-warp; do
            _cloudflared_config_in "$home/$d" && return 0
        done
    done <<<"$passwd_text"
    return 1
}

# Walk real users via getent (covers LDAP/SSSD/AD too). Plain $HOME is /root
# under sudo, which misses every user-mode tunnel install.
_cloudflared_find_user_config() {
    _cloudflared_find_user_config_from_passwd "$(getent passwd 2>/dev/null)"
}

# The config to audit: the system directories, then each user's, then any other
# YAML in the system directories (a named tunnel run with --config). Exit 1 if none.
_cloudflared_find_config() {
    local d f
    for d in "${CLOUDFLARED_CONFIG_DIRS[@]}"; do
        _cloudflared_config_in "$d" && return 0
    done
    _cloudflared_find_user_config && return 0
    for d in "${CLOUDFLARED_CONFIG_DIRS[@]}"; do
        for f in "$d"/*.yml "$d"/*.yaml; do
            [[ -f "$f" ]] && { echo "$f"; return 0; }
        done
    done
    return 1
}

# Is a tunnel run from a token (a dashboard-managed tunnel)? Its ingress lives
# in Cloudflare, not in a local file. Asks the units and the running processes;
# the token itself never leaves this function.
_cloudflared_token_managed() {
    local units procs
    units=$(systemctl cat cloudflared.service 2>/dev/null; systemctl cat 'cloudflared@*' 2>/dev/null) || true
    procs=$(pgrep -a cloudflared 2>/dev/null) || true
    [[ "$units"$'\n'"$procs" =~ (--token|TUNNEL_TOKEN) ]]
}

# Echoes "<id> <name>" for each tunnel; non-zero exit signals enumeration
# failure (e.g. cloudflared can't find cert.pem) — distinct from a valid
# query that returned zero tunnels.
_cloudflared_get_tunnels() {
    local out
    # Wrap in `timeout`: `cloudflared tunnel list` is a Cloudflare API call and
    # will hang on a black-holed network — the read-only audit must never stall.
    # (The IMDS probes in cloud.sh are bounded the same way.)
    if ! out=$(timeout 8 cloudflared tunnel list 2>/dev/null); then
        return 1
    fi
    echo "$out" | tail -n +2 | awk '{print $1, $2}'
}

_cloudflared_tunnel_running() {
    pgrep -f "cloudflared.*tunnel" &>/dev/null
}

# True when PATTERN occurs on a line that is not commented out. Every check
# here MUST use it: matching inside YAML comments has produced both false
# positives and false negatives. A trailing comment on a live line matches.
_cloudflared_yaml_has_active() {
    local config="$1" pattern="$2"
    grep -qE "^[^#]*${pattern}" "$config" 2>/dev/null
}

_cloudflared_check_ingress_security() {
    local config="$1"
    local issues=()

    if [[ -f "$config" ]]; then
        # Check for catch-all rule
        if ! _cloudflared_yaml_has_active "$config" 'service:[[:space:]]*http_status:404'; then
            issues+=("no_catchall")
        fi

        # Check for noTLSVerify. The whitespace class also catches the
        # space-less `noTLSVerify:true`, which is valid YAML and just as
        # unsafe as the spaced form the literal match required.
        if _cloudflared_yaml_has_active "$config" 'noTLSVerify:[[:space:]]*true'; then
            issues+=("notls_verify")
        fi

        # Check originRequest settings
        if ! _cloudflared_yaml_has_active "$config" 'originRequest:'; then
            issues+=("no_origin_request")
        fi
    fi

    echo "${issues[*]}"
}

# --- Cloudflared Audit ---

cloudflared_audit() {
    local module="cloudflared"

    # Check if Cloudflared is installed
    print_item "$(i18n 'cloudflared.check_installed')"
    if ! _cloudflared_installed; then
        check_emit "cloudflared.not_installed" low passed
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
        check_emit "cloudflared.service_active" low passed
        print_ok "$(i18n 'cloudflared.service_active')"
    elif _cloudflared_tunnel_running; then
        check_emit "cloudflared.tunnel_running" low passed \
            title="$(i18n 'cloudflared.tunnel_running_manual')" \
            desc="$(i18n 'cloudflared.tunnel_not_systemd')" \
            suggestion="$(i18n 'cloudflared.fix_setup_service')"
        print_ok "$(i18n 'cloudflared.tunnel_running_manual')"
    else
        check_emit "cloudflared.service_inactive" low failed \
            title="$(i18n 'cloudflared.service_not_running')" \
            desc="$(i18n 'cloudflared.no_tunnel_detected')" \
            suggestion="$(i18n 'cloudflared.fix_start_service')"
        print_severity "low" "$(i18n 'cloudflared.service_not_running')"
    fi
}

_cloudflared_audit_config() {
    # A token tunnel takes its ingress from the dashboard; a local file, if any,
    # is not what it serves, so neither its absence nor its content is judged.
    if _cloudflared_token_managed; then
        check_emit "cloudflared.config_remote" info failed \
            title="$(i18n 'cloudflared.config_remote')" \
            desc="$(i18n 'cloudflared.config_remote_desc')"
        print_msg "$(i18n 'cloudflared.config_remote')"
        return
    fi

    local config
    if ! config=$(_cloudflared_find_config); then
        check_emit "cloudflared.no_config" low failed \
            title="$(i18n 'cloudflared.config_not_found')" \
            desc="$(i18n 'cloudflared.config_not_found_desc')" \
            suggestion="$(i18n 'cloudflared.fix_create_config')" \
            fix="cloudflared.generate_config"
        print_severity "low" "$(i18n 'cloudflared.config_not_found')"
        return
    fi

    local issues=$(_cloudflared_check_ingress_security "$config")

    if [[ -n "$issues" ]]; then
        local tok issues_text=""
        for tok in $issues; do
            issues_text+="$(i18n "cloudflared.issue_$tok"); "
        done
        issues="${issues_text%; }"
        check_emit "cloudflared.config_issues" low failed \
            title="$(i18n 'cloudflared.config_has_issues')" \
            desc="$(i18n 'cloudflared.config_issues_desc' "issues=$issues")" \
            suggestion="$(i18n 'cloudflared.fix_review_config')" \
            fix="cloudflared.generate_config"
        print_severity "low" "$(i18n 'cloudflared.config_issues_desc' "issues=$issues")"
    else
        check_emit "cloudflared.config_ok" low passed
        print_ok "$(i18n 'cloudflared.config_ok')"
    fi
}

_cloudflared_audit_tunnels() {
    local tunnels rc
    tunnels=$(_cloudflared_get_tunnels)
    rc=$?

    if [[ $rc -ne 0 ]]; then
        # Enumeration failed (typically: no ~/.cloudflared/cert.pem, so no API
        # auth). A query that did not answer is not a pass: failed, unscored.
        check_emit "cloudflared.tunnel_list_unavailable" info failed \
            desc="$(i18n 'cloudflared.tunnel_list_unavailable_desc')"
        print_msg "$(i18n 'cloudflared.tunnel_list_unavailable')"
    elif [[ -n "$tunnels" ]]; then
        local tunnel_count=$(echo "$tunnels" | wc -l)
        check_emit "cloudflared.tunnels_configured" low passed \
            title="$(i18n 'cloudflared.tunnels_count' "count=$tunnel_count")"
        print_ok "$(i18n 'cloudflared.tunnels_count' "count=$tunnel_count")"
    else
        check_emit "cloudflared.no_tunnels" low failed \
            desc="$(i18n 'cloudflared.no_tunnels_desc')" \
            suggestion="$(i18n 'cloudflared.fix_create_tunnel')"
        print_severity "low" "$(i18n 'cloudflared.no_tunnels')"
    fi
}

# --- Cloudflared Fix Functions ---

cloudflared_fix() {
    local fix_id="$1"

    case "$fix_id" in
        cloudflared.generate_config)
            _cloudflared_fix_generate_config
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
    local output_file="${template_dir}/config.yml.example"

    print_info "$(i18n 'cloudflared.generating_template')"

    write_template "$output_file" <<'EOF' || return 1
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
    write_template "${template_dir}/cloudflared.service.example" <<'EOF' || return 1
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
