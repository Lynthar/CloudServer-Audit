#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Docker security module
# Copyright (c) 2024

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
    docker ps --format '{{.Names}}' --filter "label=com.docker.compose.project" 2>/dev/null
    # Check for privileged flag
    for container in $(docker ps -q 2>/dev/null); do
        if docker inspect "$container" 2>/dev/null | jq -e '.[0].HostConfig.Privileged == true' &>/dev/null; then
            docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/'
        fi
    done
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

    # Check exposed ports
    print_item "$(i18n 'docker.check_exposed_ports')"
    _docker_audit_exposed_ports

    # Check privileged containers
    print_item "$(i18n 'docker.check_privileged')"
    _docker_audit_privileged
}

_docker_audit_exposed_ports() {
    local ports=$(_docker_get_exposed_ports)
    local count=$(echo "$ports" | grep -c . || echo "0")

    if ((count > 0)); then
        local check=$(create_check_json \
            "docker.exposed_ports" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.exposed_ports' "count=$count")" \
            "Exposed ports: $ports" \
            "Use reverse proxy or bind to 127.0.0.1" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.exposed_ports' "count=$count"): $ports"
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
    local count=$(echo "$containers" | grep -c . || echo "0")

    if ((count > 0)); then
        local check=$(create_check_json \
            "docker.privileged_containers" \
            "docker" \
            "high" \
            "failed" \
            "$(i18n 'docker.privileged_containers' "count=$count")" \
            "Privileged containers: $containers" \
            "Avoid using --privileged flag" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'docker.privileged_containers' "count=$count")"
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

# ==============================================================================
# Docker Fix (informational only)
# ==============================================================================

docker_fix() {
    local fix_id="$1"
    log_warn "Docker fixes require manual intervention"
    print_warn "Docker security issues require manual review of docker-compose.yml"
    return 1
}
