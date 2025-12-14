#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Docker security module (Enhanced v0.2)
# Copyright (c) 2024

# ==============================================================================
# Docker Configuration
# ==============================================================================

DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
DOCKER_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/docker"

# ==============================================================================
# Docker Helper Functions
# ==============================================================================

_docker_installed() {
    check_command docker && docker info &>/dev/null
}

_docker_get_exposed_ports() {
    docker ps --format '{{.Ports}}' 2>/dev/null | grep -oE '0\.0\.0\.0:[0-9]+' | cut -d: -f2 | sort -u
}

_docker_get_privileged_containers() {
    local privileged=()
    for container in $(docker ps -q 2>/dev/null); do
        if docker inspect "$container" 2>/dev/null | jq -e '.[0].HostConfig.Privileged == true' &>/dev/null; then
            local name=$(docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            privileged+=("$name")
        fi
    done
    printf '%s\n' "${privileged[@]}"
}

_docker_get_root_containers() {
    local root_containers=()
    for container in $(docker ps -q 2>/dev/null); do
        local user=$(docker inspect "$container" --format '{{.Config.User}}' 2>/dev/null)
        if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
            local name=$(docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            root_containers+=("$name")
        fi
    done
    printf '%s\n' "${root_containers[@]}"
}

_docker_get_containers_with_caps() {
    local cap_containers=()
    for container in $(docker ps -q 2>/dev/null); do
        local caps=$(docker inspect "$container" 2>/dev/null | jq -r '.[0].HostConfig.CapAdd // [] | length')
        if [[ "$caps" -gt 0 ]]; then
            local name=$(docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            cap_containers+=("$name")
        fi
    done
    printf '%s\n' "${cap_containers[@]}"
}

_docker_check_userns() {
    docker info 2>/dev/null | grep -q "userns"
}

_docker_check_live_restore() {
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON" &>/dev/null
    else
        return 1
    fi
}

_docker_check_no_new_privileges() {
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        jq -e '.["no-new-privileges"] == true' "$DOCKER_DAEMON_JSON" &>/dev/null
    else
        return 1
    fi
}

# ==============================================================================
# Docker Audit
# ==============================================================================

docker_audit() {
    local module="docker"

    # Check if Docker is installed
    print_item "$(i18n 'docker.check_installed')"
    if ! _docker_installed; then
        local check=$(create_check_json \
            "docker.not_installed" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.not_installed')" \
            "Docker is not installed (skip)" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.not_installed') - Skipping"
        return
    fi
    print_ok "Docker installed and running"

    # Check exposed ports
    print_item "$(i18n 'docker.check_exposed_ports')"
    _docker_audit_exposed_ports

    # Check privileged containers
    print_item "$(i18n 'docker.check_privileged')"
    _docker_audit_privileged

    # Check containers running as root
    print_item "Checking containers running as root..."
    _docker_audit_root_containers

    # Check containers with added capabilities
    print_item "Checking containers with added capabilities..."
    _docker_audit_capabilities

    # Check daemon security settings
    print_item "Checking Docker daemon security settings..."
    _docker_audit_daemon_settings
}

_docker_audit_exposed_ports() {
    local ports=$(_docker_get_exposed_ports)
    local count=$(echo "$ports" | grep -c . 2>/dev/null || echo "0")

    if ((count > 0)); then
        local port_list=$(echo "$ports" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.exposed_ports" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.exposed_ports' "count=$count")" \
            "Exposed ports: $port_list" \
            "Use reverse proxy or bind to 127.0.0.1" \
            "docker.generate_proxy_template")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.exposed_ports' "count=$count"): $port_list"
    else
        local check=$(create_check_json \
            "docker.no_exposed_ports" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.no_exposed_ports')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_exposed_ports')"
    fi
}

_docker_audit_privileged() {
    local containers=$(_docker_get_privileged_containers)
    local count=$(echo "$containers" | grep -c . 2>/dev/null || echo "0")

    if ((count > 0)); then
        local container_list=$(echo "$containers" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.privileged_containers" \
            "docker" \
            "high" \
            "failed" \
            "$(i18n 'docker.privileged_containers' "count=$count")" \
            "Privileged containers: $container_list" \
            "Remove --privileged flag, use specific capabilities instead" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'docker.privileged_containers' "count=$count"): $container_list"
    else
        local check=$(create_check_json \
            "docker.no_privileged" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.no_privileged')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_privileged')"
    fi
}

_docker_audit_root_containers() {
    local containers=$(_docker_get_root_containers)
    local count=$(echo "$containers" | grep -c . 2>/dev/null || echo "0")
    local total=$(docker ps -q 2>/dev/null | wc -l)

    if ((count > 0 && count == total)); then
        local check=$(create_check_json \
            "docker.all_root_containers" \
            "docker" \
            "medium" \
            "failed" \
            "All containers running as root ($count)" \
            "All containers are running as root user" \
            "Use USER directive in Dockerfile or --user flag" \
            "")
        state_add_check "$check"
        print_severity "medium" "All $count containers running as root"
    elif ((count > 0)); then
        local check=$(create_check_json \
            "docker.some_root_containers" \
            "docker" \
            "low" \
            "failed" \
            "$count of $total containers running as root" \
            "Some containers are running as root user" \
            "Use USER directive in Dockerfile or --user flag" \
            "")
        state_add_check "$check"
        print_severity "low" "$count of $total containers running as root"
    else
        local check=$(create_check_json \
            "docker.no_root_containers" \
            "docker" \
            "low" \
            "passed" \
            "No containers running as root" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "No containers running as root"
    fi
}

_docker_audit_capabilities() {
    local containers=$(_docker_get_containers_with_caps)
    local count=$(echo "$containers" | grep -c . 2>/dev/null || echo "0")

    if ((count > 0)); then
        local container_list=$(echo "$containers" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.containers_with_caps" \
            "docker" \
            "medium" \
            "failed" \
            "$count containers with added capabilities" \
            "Containers: $container_list" \
            "Review if added capabilities are necessary" \
            "")
        state_add_check "$check"
        print_severity "medium" "$count containers with added capabilities"
    else
        local check=$(create_check_json \
            "docker.no_extra_caps" \
            "docker" \
            "low" \
            "passed" \
            "No containers with added capabilities" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "No containers with added capabilities"
    fi
}

_docker_audit_daemon_settings() {
    local issues=0

    # Check live-restore
    if ! _docker_check_live_restore; then
        local check=$(create_check_json \
            "docker.no_live_restore" \
            "docker" \
            "low" \
            "failed" \
            "Docker live-restore not enabled" \
            "Containers will stop during Docker daemon restart" \
            "Enable live-restore in daemon.json" \
            "docker.enable_live_restore")
        state_add_check "$check"
        print_severity "low" "Docker live-restore not enabled"
        ((issues++)) || true
    fi

    # Check no-new-privileges
    if ! _docker_check_no_new_privileges; then
        local check=$(create_check_json \
            "docker.no_new_privileges_disabled" \
            "docker" \
            "medium" \
            "failed" \
            "Docker no-new-privileges not set as default" \
            "Containers can gain new privileges by default" \
            "Enable no-new-privileges in daemon.json" \
            "docker.enable_no_new_privileges")
        state_add_check "$check"
        print_severity "medium" "Docker no-new-privileges not set as default"
        ((issues++)) || true
    fi

    if ((issues == 0)); then
        local check=$(create_check_json \
            "docker.daemon_secure" \
            "docker" \
            "low" \
            "passed" \
            "Docker daemon security settings OK" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Docker daemon security settings OK"
    fi
}

# ==============================================================================
# Docker Fix Functions
# ==============================================================================

docker_fix() {
    local fix_id="$1"

    case "$fix_id" in
        docker.generate_proxy_template)
            _docker_fix_generate_proxy_template
            ;;
        docker.enable_live_restore)
            _docker_fix_enable_daemon_setting "live-restore" true
            ;;
        docker.enable_no_new_privileges)
            _docker_fix_enable_daemon_setting "no-new-privileges" true
            ;;
        *)
            log_warn "Docker fix not implemented: $fix_id"
            print_warn "This Docker fix requires manual intervention"
            return 1
            ;;
    esac
}

_docker_fix_generate_proxy_template() {
    local ports=$(_docker_get_exposed_ports)
    local template_dir="${DOCKER_TEMPLATES_DIR}"
    mkdir -p "$template_dir"

    local output_file="${template_dir}/docker-compose.proxy.yml"

    print_info "Generating reverse proxy template..."

    cat > "$output_file" <<'EOF'
# vpssec generated template - Docker Reverse Proxy Configuration
# This template shows how to bind containers to localhost only
# and use a reverse proxy (Traefik/Nginx) for external access

version: '3.8'

services:
  # Example: Your application bound to localhost only
  # app:
  #   image: your-app:latest
  #   ports:
  #     - "127.0.0.1:8080:8080"  # Only accessible from localhost
  #   networks:
  #     - internal
  #   labels:
  #     - "traefik.enable=true"
  #     - "traefik.http.routers.app.rule=Host(`app.example.com`)"
  #     - "traefik.http.routers.app.tls.certresolver=letsencrypt"

  # Traefik reverse proxy
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./traefik/acme.json:/acme.json
    networks:
      - proxy

networks:
  proxy:
    external: true
  internal:
    internal: true

# Security best practices applied:
# 1. Bind internal services to 127.0.0.1 only
# 2. Use no-new-privileges security option
# 3. Mount docker.sock as read-only
# 4. Use internal networks for service communication
# 5. Only expose ports through reverse proxy with TLS
EOF

    # Generate Traefik config
    mkdir -p "${template_dir}/traefik"
    cat > "${template_dir}/traefik/traefik.yml" <<'EOF'
# Traefik configuration
api:
  dashboard: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: proxy

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /acme.json
      httpChallenge:
        entryPoint: web
EOF

    touch "${template_dir}/traefik/acme.json"
    chmod 600 "${template_dir}/traefik/acme.json"

    print_ok "Template generated: $output_file"
    print_info "Review and adapt the template for your services"
    print_info "Template location: $template_dir"

    return 0
}

_docker_fix_enable_daemon_setting() {
    local setting="$1"
    local value="$2"

    print_info "Configuring Docker daemon: $setting = $value"

    # Create or update daemon.json
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        backup_file "$DOCKER_DAEMON_JSON"
        local current=$(cat "$DOCKER_DAEMON_JSON")
        echo "$current" | jq --arg key "$setting" --argjson val "$value" '.[$key] = $val' > "${DOCKER_DAEMON_JSON}.tmp"
        mv "${DOCKER_DAEMON_JSON}.tmp" "$DOCKER_DAEMON_JSON"
    else
        mkdir -p /etc/docker
        echo "{\"$setting\": $value}" | jq '.' > "$DOCKER_DAEMON_JSON"
    fi

    print_ok "Docker daemon configuration updated"
    print_warn "Restart Docker to apply changes: systemctl restart docker"

    return 0
}

# ==============================================================================
# Docker Utility Functions
# ==============================================================================

# Generate secure docker-compose snippet for a service
docker_generate_secure_service() {
    local service_name="$1"
    local image="$2"
    local internal_port="$3"

    cat <<EOF
  $service_name:
    image: $image
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    ports:
      - "127.0.0.1:$internal_port:$internal_port"
    networks:
      - internal
EOF
}
