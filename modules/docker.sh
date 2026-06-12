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
    # Publicly-published host ports: the number immediately before "->" for any
    # binding that is NOT loopback. The old `0\.0\.0\.0:` regex caught ONLY the
    # IPv4-wildcard form and missed IPv6 wildcard (":::PORT"), bracketed IPv6
    # ("[2001:db8::1]:PORT") and specific-public-IP binds ("203.0.113.5:PORT") —
    # all of which are reachable from off-host. Loopback binds (127.0.0.0/8,
    # ::1) are intentionally excluded: they are not exposed.
    docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | awk '
        /->/ {
            hp = $0; sub(/->.*/, "", hp); gsub(/[[:space:]]/, "", hp)
            port = hp; sub(/.*:/, "", port)
            addr = hp; sub(/:[0-9]+$/, "", addr); gsub(/[][]/, "", addr)
            if (addr ~ /^127\./ || addr == "::1") next
            if (port ~ /^[0-9]+$/) print port
        }
    ' | sort -u
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
    # Only consider userns-remap actually active — docker info prints
    # warnings containing "userns" when the feature is NOT configured,
    # so a bare `grep -q userns` was misleading. The authoritative
    # signal is the SecurityOptions list which includes `name=userns`
    # only when the daemon is running with userns-remap.
    docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q 'name=userns'
}

# Return the numeric mode (e.g. "660") of /var/run/docker.sock if it
# exists; empty string otherwise.
_docker_sock_mode() {
    local sock=/var/run/docker.sock
    [[ -S "$sock" ]] || return 0
    stat -c '%a' "$sock" 2>/dev/null
}

# Return names of running containers that were started with
# --security-opt seccomp=unconfined (or equivalent), one per line.
_docker_seccomp_unconfined_containers() {
    local unconfined=()
    local container
    for container in $(docker ps -q 2>/dev/null); do
        # HostConfig.SecurityOpt is a list of strings like
        # "seccomp=unconfined" or "apparmor:unconfined". jq -e
        # returns non-zero if the filter produces no matches.
        if docker inspect "$container" 2>/dev/null \
            | jq -e '.[0].HostConfig.SecurityOpt // [] | any(. == "seccomp=unconfined")' &>/dev/null; then
            local name
            name=$(docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            [[ -n "$name" ]] && unconfined+=("$name")
        fi
    done
    printf '%s\n' "${unconfined[@]}"
}

_docker_check_live_restore() {
    # Prefer `docker info` — it reports the daemon's *effective*
    # state, which honours both daemon.json and any systemd drop-in
    # under /etc/systemd/system/docker.service.d/*.conf or
    # /etc/default/docker. Reading daemon.json alone missed the
    # common "I set X in daemon.json but a systemd ExecStart override
    # re-specified it" failure mode (the Docker analogue of the
    # sshd_config.d drop-in bug).
    if docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null | grep -qi '^true$'; then
        return 0
    fi
    # Fallback when the daemon is not running: at least surface the
    # user's stated intent in daemon.json.
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON" &>/dev/null
    else
        return 1
    fi
}

# `no-new-privileges` daemon-level default has no dedicated `docker
# info` field, so cross-check three sources: daemon.json, any
# `--no-new-privileges` flag in the systemd ExecStart drop-ins, and
# the legacy /etc/default/docker DOCKER_OPTS. Any of them enabling
# counts. systemctl cat returns the merged unit (main file + every
# drop-in), giving us full coverage without re-implementing the
# systemd merge order.
_docker_check_no_new_privileges() {
    if [[ -f "$DOCKER_DAEMON_JSON" ]] && \
        jq -e '.["no-new-privileges"] == true' "$DOCKER_DAEMON_JSON" &>/dev/null; then
        return 0
    fi
    if command -v systemctl &>/dev/null && \
        systemctl cat docker.service 2>/dev/null | \
        grep -E '^ExecStart=' | grep -q -- '--no-new-privileges'; then
        return 0
    fi
    if [[ -r /etc/default/docker ]] && \
        grep -E '^[[:space:]]*DOCKER_OPTS=' /etc/default/docker 2>/dev/null | \
        grep -q -- '--no-new-privileges'; then
        return 0
    fi
    return 1
}

# ----- Network isolation / secrets / resources (CIS additions) -----------------

# Containers running with --network=host. Sharing the host's network
# namespace bypasses Docker's isolation entirely: the container sees
# all host interfaces, can bind to any port, and any process inside
# it can sniff host traffic. CIS Docker 5.9 / NIST 800-190.
_docker_get_host_network_containers() {
    local hn=()
    local c name mode
    for c in $(docker ps -q 2>/dev/null); do
        mode=$(docker inspect "$c" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
        if [[ "$mode" == "host" ]]; then
            name=$(docker inspect "$c" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            hn+=("$name")
        fi
    done
    printf '%s\n' "${hn[@]}"
}

# Containers without a memory cap (Memory == 0 = unlimited).
# A misbehaving container can OOM the host. CIS Docker 5.10.
_docker_get_unlimited_memory_containers() {
    local um=()
    local c name mem
    for c in $(docker ps -q 2>/dev/null); do
        mem=$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)
        if [[ "$mem" == "0" ]]; then
            name=$(docker inspect "$c" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            um+=("$name")
        fi
    done
    printf '%s\n' "${um[@]}"
}

# Containers whose .Config.Env contains known-format credentials.
# Uses _vpssec_scan_secrets_in_content (same scanner as IMDS user-data).
# We scan `docker ps -aq` (all containers including stopped) because
# `docker inspect` exposes the env spec regardless of run state, and
# a stopped container is one `docker start` from re-activating the
# leak. Output format: "container_name: kind(xN) kind(xN)".
_docker_get_containers_with_env_secrets() {
    local hits=()
    local c name env_str finding
    for c in $(docker ps -aq 2>/dev/null); do
        env_str=$(docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)
        [[ -z "$env_str" ]] && continue
        finding=$(_vpssec_scan_secrets_in_content "$env_str")
        finding="${finding% }"
        [[ -z "$finding" ]] && continue
        name=$(docker inspect "$c" --format '{{.Name}}' 2>/dev/null | tr -d '/')
        hits+=("${name}: ${finding}")
    done
    printf '%s\n' "${hits[@]}"
}

# Is ICC (inter-container communication on the default bridge)
# explicitly disabled? CIS Docker 2.2 — default state is ENABLED,
# which is the laterall-movement-friendly state we want to flag.
# Same three-source pattern as _docker_check_no_new_privileges.
#
# Returns 0 (true) when ICC is DISABLED somewhere, 1 when defaults
# apply (= ICC enabled = the finding state).
_docker_check_icc_disabled() {
    if [[ -f "$DOCKER_DAEMON_JSON" ]] && \
        jq -e '.icc == false' "$DOCKER_DAEMON_JSON" &>/dev/null; then
        return 0
    fi
    if command -v systemctl &>/dev/null && \
        systemctl cat docker.service 2>/dev/null | \
        grep -E '^ExecStart=' | grep -q -- '--icc=false'; then
        return 0
    fi
    if [[ -r /etc/default/docker ]] && \
        grep -E '^[[:space:]]*DOCKER_OPTS=' /etc/default/docker 2>/dev/null | \
        grep -q -- '--icc=false'; then
        return 0
    fi
    return 1
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
    print_ok "$(i18n 'docker.installed_running')"

    # Check exposed ports
    print_item "$(i18n 'docker.check_exposed_ports')"
    _docker_audit_exposed_ports

    # Check privileged containers
    print_item "$(i18n 'docker.check_privileged')"
    _docker_audit_privileged

    # Check containers running as root
    print_item "$(i18n 'docker.check_root_containers')"
    _docker_audit_root_containers

    # Check containers with added capabilities
    print_item "$(i18n 'docker.check_capabilities')"
    _docker_audit_capabilities

    # Check daemon security settings
    print_item "$(i18n 'docker.check_daemon_security')"
    _docker_audit_daemon_settings

    # Check /var/run/docker.sock permissions (world-writable socket =
    # effective root for any local user).
    print_item "$(i18n 'docker.check_sock_perms')"
    _docker_audit_sock_perms

    # Check for containers running with seccomp=unconfined.
    print_item "$(i18n 'docker.check_seccomp')"
    _docker_audit_seccomp_unconfined

    # Check whether userns-remap is actually active (not just available).
    print_item "$(i18n 'docker.check_userns_remap')"
    _docker_audit_userns_remap

    # CIS Docker network / secrets / resources additions:
    print_item "$(i18n 'docker.check_host_network' 2>/dev/null || echo 'Checking host network usage')"
    _docker_audit_host_network

    print_item "$(i18n 'docker.check_default_bridge_icc' 2>/dev/null || echo 'Checking default-bridge ICC setting')"
    _docker_audit_default_bridge_icc

    print_item "$(i18n 'docker.check_secrets_in_env' 2>/dev/null || echo 'Scanning container env vars for embedded credentials')"
    _docker_audit_secrets_in_env

    print_item "$(i18n 'docker.check_unlimited_memory' 2>/dev/null || echo 'Checking container memory limits')"
    _docker_audit_unlimited_memory
}

_docker_audit_exposed_ports() {
    local ports=$(_docker_get_exposed_ports)
    local count=$(count_lines "$ports")

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
    local count=$(count_lines "$containers")

    if ((count > 0)); then
        local container_list=$(echo "$containers" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.privileged_containers" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.privileged_containers' "count=$count")" \
            "Privileged containers: $container_list" \
            "Remove --privileged flag, use specific capabilities instead" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.privileged_containers' "count=$count"): $container_list"
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
    local count=$(count_lines "$containers")
    local total=$(docker ps -q 2>/dev/null | wc -l)

    if ((count > 0 && count == total)); then
        local check=$(create_check_json \
            "docker.all_root_containers" \
            "docker" \
            "low" \
            "failed" \
            "All containers running as root ($count)" \
            "All containers are running as root user" \
            "Use USER directive in Dockerfile or --user flag" \
            "")
        state_add_check "$check"
        print_severity "low" "All $count containers running as root"
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
            "$(i18n 'docker.no_root_containers')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_root_containers')"
    fi
}

_docker_audit_capabilities() {
    local containers=$(_docker_get_containers_with_caps)
    local count=$(count_lines "$containers")

    if ((count > 0)); then
        local container_list=$(echo "$containers" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.containers_with_caps" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.added_capabilities' "count=$count")" \
            "" \
            "$(i18n 'docker.added_capabilities_desc')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.added_capabilities' "count=$count")"
    else
        local check=$(create_check_json \
            "docker.no_extra_caps" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.no_added_capabilities')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_added_capabilities')"
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
            "low" \
            "failed" \
            "Docker no-new-privileges not set as default" \
            "Containers can gain new privileges by default" \
            "Enable no-new-privileges in daemon.json" \
            "docker.enable_no_new_privileges")
        state_add_check "$check"
        print_severity "low" "Docker no-new-privileges not set as default"
        ((issues++)) || true
    fi

    if ((issues == 0)); then
        local check=$(create_check_json \
            "docker.daemon_secure" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.daemon_secure')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.daemon_secure')"
    fi
}

# /var/run/docker.sock exposes the Docker API over UNIX domain socket.
# Any process that can write to it can spawn privileged containers and
# thereby escalate to host root. Default distro packaging ships it 660
# root:docker. Mode 666 (world-writable) is a common misconfiguration
# when tutorials tell users to `chmod a+rw /var/run/docker.sock` to
# "fix permission denied" — we flag this as high severity.
_docker_audit_sock_perms() {
    local mode
    mode=$(_docker_sock_mode)

    if [[ -z "$mode" ]]; then
        # Socket not present — likely rootless Docker or daemon using
        # a non-default socket path. Nothing to report.
        return
    fi

    # Extract the "others" octal digit (last char of mode).
    local others="${mode: -1}"

    # Any non-zero bits in the others octet mean non-owner/non-group
    # processes can interact with the socket. 2 (write) and 6 (read+write)
    # are the clearly dangerous cases; 4 (read-only) leaks daemon state
    # but isn't immediate RCE.
    if [[ "$others" =~ ^[2367]$ ]]; then
        local check=$(create_check_json \
            "docker.sock_perms_loose" \
            "docker" \
            "high" \
            "failed" \
            "$(i18n 'docker.sock_perms_loose' "mode=$mode")" \
            "$(i18n 'docker.sock_perms_loose_desc' "mode=$mode")" \
            "$(i18n 'docker.sock_perms_fix')" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'docker.sock_perms_loose' "mode=$mode")"
    else
        local check=$(create_check_json \
            "docker.sock_perms_ok" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.sock_perms_ok' "mode=$mode")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.sock_perms_ok' "mode=$mode")"
    fi
}

# seccomp is the kernel-level syscall filter Docker applies by default
# to reduce the attack surface from inside containers. Running a
# container with `--security-opt seccomp=unconfined` disables that
# filter entirely, which is almost always a sign of either a debugging
# workaround that was never reverted or a poorly understood workload.
_docker_audit_seccomp_unconfined() {
    local containers
    containers=$(_docker_seccomp_unconfined_containers)
    local count
    count=$(count_lines "$containers")
    # Guard against the "empty input" edge case where `grep -c .` on
    # an empty string returns 0 but an empty var becomes "1" if not
    # piped; same idiom the neighbouring helpers use.
    [[ -z "$containers" ]] && count=0

    if ((count > 0)); then
        local list
        list=$(echo "$containers" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.seccomp_unconfined" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.seccomp_unconfined' "count=$count")" \
            "$(i18n 'docker.seccomp_unconfined_desc' "containers=$list")" \
            "$(i18n 'docker.seccomp_fix')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.seccomp_unconfined' "count=$count"): $list"
    else
        local check=$(create_check_json \
            "docker.no_seccomp_unconfined" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.no_seccomp_unconfined')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_seccomp_unconfined')"
    fi
}

# userns-remap maps container UID 0 to a non-root host UID, so a
# container-root compromise does NOT give host-root. The feature is
# compiled into every modern Docker build, but is only effective when
# the daemon is actually started with it (dockerd-level setting, not
# per-container). This check distinguishes "available" from "active".
_docker_audit_userns_remap() {
    if _docker_check_userns; then
        local check=$(create_check_json \
            "docker.userns_enabled" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.userns_enabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.userns_enabled')"
    else
        local check=$(create_check_json \
            "docker.userns_not_enabled" \
            "docker" \
            "low" \
            "failed" \
            "$(i18n 'docker.userns_not_enabled')" \
            "$(i18n 'docker.userns_not_enabled_desc')" \
            "$(i18n 'docker.userns_fix')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'docker.userns_not_enabled')"
    fi
}

# CIS Docker 5.9 — running with --network=host bypasses Docker's
# network isolation entirely. medium severity (not high): legitimate
# use cases exist (VPN daemons like Tailscale/Wireguard, network
# monitoring agents, custom DNS containers) so this is "review each
# one", not "broken-by-default".
_docker_audit_host_network() {
    local hn; hn=$(_docker_get_host_network_containers)
    local count; count=$(count_lines "$hn")

    if (( count > 0 )); then
        local hn_list=$(echo "$hn" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.host_network_used" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.host_network_used' "count=$count" 2>/dev/null || echo "${count} container(s) running with --network=host")" \
            "Containers: ${hn_list% }. These share the host network namespace (bind any port, see all host traffic). Review whether each container actually needs host network." \
            "$(i18n 'docker.fix_host_network' 2>/dev/null || echo 'Recreate the container without --network=host; use a user-defined bridge or default bridge instead unless host networking is truly required (VPN, monitoring)')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.host_network_used' "count=$count" 2>/dev/null || echo "${count} container(s) on host network")"
    else
        local check=$(create_check_json \
            "docker.no_host_network" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.no_host_network' 2>/dev/null || echo 'No containers using host network namespace')" \
            "" "" "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_host_network' 2>/dev/null || echo 'No containers using host network')"
    fi
}

# CIS Docker 2.2 — default bridge with ICC=true (Docker's out-of-box
# default) lets every container on docker0 talk freely to every
# other. low severity: this IS the default; flagging at medium would
# be noisy on essentially every Docker install. Surface as a
# defense-in-depth signal that operators can address with one daemon
# setting.
_docker_audit_default_bridge_icc() {
    if _docker_check_icc_disabled; then
        local check=$(create_check_json \
            "docker.default_bridge_icc_disabled" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.default_bridge_icc_disabled' 2>/dev/null || echo 'Default-bridge ICC disabled (containers cannot freely cross-talk)')" \
            "" "" "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.default_bridge_icc_disabled' 2>/dev/null || echo 'Default-bridge ICC disabled')"
    else
        local check=$(create_check_json \
            "docker.default_bridge_icc_enabled" \
            "docker" \
            "low" \
            "failed" \
            "$(i18n 'docker.default_bridge_icc_enabled' 2>/dev/null || echo 'Default-bridge ICC enabled (Docker default; allows lateral movement)')" \
            "Inter-container communication on the docker0 bridge is enabled. If any container is compromised it can reach every other container on the default bridge." \
            "$(i18n 'docker.fix_default_bridge_icc' 2>/dev/null || echo 'Add \"icc\": false to /etc/docker/daemon.json, restart docker. Use user-defined networks for containers that genuinely need to communicate.')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'docker.default_bridge_icc_enabled' 2>/dev/null || echo 'Default-bridge ICC enabled')"
    fi
}

# Container env scan. MEDIUM (not high like cloud.user_data_leaked_
# secrets): cloud user-data is readable by EVERY process on the host,
# whereas container env vars are scoped to the container's own
# processes plus docker-socket / `docker inspect` (root-equivalent)
# access — so realising the exposure needs the container, or docker
# access, to be compromised first. NEVER log raw values — finding desc
# records only "kind + count" output from the shared scanner.
_docker_audit_secrets_in_env() {
    local hits; hits=$(_docker_get_containers_with_env_secrets)
    local count; count=$(count_lines "$hits")

    if (( count > 0 )); then
        # Log the FACT of hits; the desc carries kinds, not values.
        log_info "docker env secret hits: $count container(s) with credential-format env vars"
        # Compress to first 5 lines + total — long lists overflow display.
        local sample; sample=$(echo "$hits" | head -5 | tr '\n' '; ' | sed 's/; $//')
        local check=$(create_check_json \
            "docker.secrets_in_env" \
            "docker" \
            "medium" \
            "failed" \
            "$(i18n 'docker.secrets_in_env' "count=$count" 2>/dev/null || echo "${count} container(s) with embedded credentials in env vars")" \
            "Containers (kinds + counts only; raw values withheld): ${sample}. Any process with docker socket access reads these via 'docker inspect'." \
            "$(i18n 'docker.fix_secrets_in_env' 2>/dev/null || echo 'Rotate the exposed credentials. Use docker secrets / mounted secret files / cloud-provider secret stores instead of -e/--env.')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'docker.secrets_in_env' "count=$count" 2>/dev/null || echo "${count} container(s) with secrets in env")"
    else
        local check=$(create_check_json \
            "docker.no_env_secrets" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.no_env_secrets' 2>/dev/null || echo 'No embedded credential patterns in container env vars')" \
            "" "" "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.no_env_secrets' 2>/dev/null || echo 'No embedded credentials in container env')"
    fi
}

# CIS Docker 5.10 — containers without a memory cap can OOM the host.
# low severity: single-app servers commonly run one container without
# memory limit (the container IS the workload, no reason to subdivide
# the host's RAM). Multi-tenant / co-located workloads care more.
_docker_audit_unlimited_memory() {
    local um; um=$(_docker_get_unlimited_memory_containers)
    local count; count=$(count_lines "$um")

    if (( count > 0 )); then
        local um_list=$(echo "$um" | tr '\n' ' ')
        local check=$(create_check_json \
            "docker.unlimited_memory" \
            "docker" \
            "low" \
            "failed" \
            "$(i18n 'docker.unlimited_memory' "count=$count" 2>/dev/null || echo "${count} container(s) without a memory limit")" \
            "Containers: ${um_list% }. Without --memory a runaway / leaking container can OOM the host. Acceptable on single-app servers; address on multi-tenant hosts." \
            "$(i18n 'docker.fix_unlimited_memory' 2>/dev/null || echo 'Re-run the container with --memory=<size> (e.g. --memory=512m) or set mem_limit in docker-compose.')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'docker.unlimited_memory' "count=$count" 2>/dev/null || echo "${count} container(s) without memory limit")"
    else
        local check=$(create_check_json \
            "docker.memory_limits_set" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.memory_limits_set' 2>/dev/null || echo 'All running containers have memory limits configured')" \
            "" "" "")
        state_add_check "$check"
        print_ok "$(i18n 'docker.memory_limits_set' 2>/dev/null || echo 'All containers have memory limits')"
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
            print_warn "$(i18n 'docker.fix_manual')"
            return 1
            ;;
    esac
}

_docker_fix_generate_proxy_template() {
    local ports=$(_docker_get_exposed_ports)
    local template_dir="${DOCKER_TEMPLATES_DIR}"
    mkdir -p "$template_dir"

    local output_file="${template_dir}/docker-compose.proxy.yml"

    print_info "$(i18n 'docker.generating_template')"

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

    print_ok "$(i18n 'docker.template_generated' "path=$output_file")"
    print_info "$(i18n 'docker.review_template')"
    print_info "$(i18n 'docker.template_location' "path=$template_dir")"

    return 0
}

_docker_fix_enable_daemon_setting() {
    local setting="$1"
    local value="$2"
    local tmp_file="${DOCKER_DAEMON_JSON}.tmp"

    print_info "$(i18n 'docker.configuring_daemon' "setting=$setting" "value=$value")"

    # Create or update daemon.json
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        # Refuse to edit if the existing file is not valid JSON. Without
        # this guard, a failed jq on malformed input used to write an
        # empty tmp file that then clobbered the user's daemon.json.
        if ! jq empty "$DOCKER_DAEMON_JSON" 2>/dev/null; then
            print_error "$(i18n 'docker.daemon_invalid_json' "path=$DOCKER_DAEMON_JSON")"
            return 1
        fi

        backup_file "$DOCKER_DAEMON_JSON"

        if ! jq --arg key "$setting" --argjson val "$value" '.[$key] = $val' \
               "$DOCKER_DAEMON_JSON" > "$tmp_file" 2>/dev/null; then
            rm -f "$tmp_file"
            print_error "$(i18n 'docker.daemon_update_failed')"
            return 1
        fi

        # Double-check the produced file is non-empty valid JSON before
        # overwriting the original.
        if [[ ! -s "$tmp_file" ]] || ! jq empty "$tmp_file" 2>/dev/null; then
            rm -f "$tmp_file"
            print_error "$(i18n 'docker.daemon_update_failed')"
            return 1
        fi

        mv "$tmp_file" "$DOCKER_DAEMON_JSON"
    else
        mkdir -p /etc/docker
        if ! jq -n --arg key "$setting" --argjson val "$value" \
               '{($key): $val}' > "$tmp_file" 2>/dev/null; then
            rm -f "$tmp_file"
            print_error "$(i18n 'docker.daemon_update_failed')"
            return 1
        fi
        mv "$tmp_file" "$DOCKER_DAEMON_JSON"
    fi

    print_ok "$(i18n 'docker.daemon_updated')"

    # Docker does not auto-reload daemon.json; the change only takes
    # effect on daemon restart. Ask before restarting since it briefly
    # pauses every running container. confirm_critical intentionally
    # ignores --yes so automated runs cannot restart silently.
    if confirm_critical "$(i18n 'docker.confirm_restart')"; then
        if systemctl restart docker 2>/dev/null; then
            print_ok "$(i18n 'docker.restarted')"
        else
            print_error "$(i18n 'docker.restart_failed')"
            return 1
        fi
    else
        print_warn "$(i18n 'docker.restart_skipped')"
    fi

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
