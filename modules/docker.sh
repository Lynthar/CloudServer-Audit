#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Docker security module (Enhanced v0.2)
# Copyright (c) 2024

# --- Docker Configuration ---

DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
DOCKER_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/docker"

# --- Docker Helper Functions ---

_docker_installed() {
    check_command docker && docker info &>/dev/null
}

# A container runtime is present that this module cannot audit. Needed because
# _docker_installed only answers "can I reach a daemon", and both rootless
# Docker and Podman answer No while running containers.
_docker_unaudited_runtime() {
    local found=() uid home
    # check_command, not `command -v`, so a test can make the binary absent.
    # `if`, not `&&`: a bare `a && b` returns non-zero wherever podman is
    # missing and would abort this function under errexit.
    if check_command podman; then found+=("podman"); fi

    while IFS=: read -r _ _ uid _ _ home _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid >= 1000 )) || continue
        if [[ -S "/run/user/${uid}/docker.sock" ]] || \
           [[ -n "$home" && -S "${home}/.docker/run/docker.sock" ]]; then
            found+=("rootless-docker")
            break
        fi
    done < <(getent passwd 2>/dev/null)

    printf '%s' "${found[*]:-}"
}

_docker_get_exposed_ports() {
    # Publicly published ports: the number before "->" on any NON-loopback
    # binding. Must cover IPv6 wildcard, bracketed IPv6 and specific public
    # IPs — all reachable off-host. Loopback binds are deliberately excluded.
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
    # SecurityOptions is the authoritative signal: docker info also prints
    # warnings containing "userns" when the feature is NOT configured, so a
    # bare grep reads the opposite of the truth.
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
    # `docker info` reports the daemon's EFFECTIVE state, honouring both
    # daemon.json and any systemd override. When the daemon answers, its
    # answer is FINAL — including "false"; never fall through to the file.
    local live=""
    if live=$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null); then
        [[ "${live,,}" == "true" ]]
        return
    fi
    # Daemon unreachable (stopped, or docker not installed at all): fall back
    # to the user's stated intent in daemon.json.
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        jq -e '.["live-restore"] == true' "$DOCKER_DAEMON_JSON" &>/dev/null
    else
        return 1
    fi
}

# No dedicated `docker info` field, so cross-check three sources: daemon.json,
# the systemd ExecStart drop-ins, and the legacy DOCKER_OPTS. `systemctl cat`
# returns the merged unit, so the systemd merge order need not be reproduced.
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

# Containers with --network=host, which share the host's network namespace:
# all interfaces visible, any port bindable, host traffic sniffable.
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

# Containers whose .Config.Env holds known-format credentials. Scans ALL
# containers including stopped ones: inspect exposes the env spec regardless
# of state, and a stopped container is one `docker start` from the leak.
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

# Is inter-container communication on the default bridge explicitly disabled?
# Same three-source pattern as _docker_check_no_new_privileges.
# 0 = disabled somewhere, 1 = defaults apply, which is the finding state.
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

# --- Docker Audit ---

docker_audit() {
    local module="docker"

    # Check if Docker is installed
    print_item "$(i18n 'docker.check_installed')"
    if ! _docker_installed; then
        local runtime
        runtime=$(_docker_unaudited_runtime)
        if check_command docker || [[ -n "$runtime" ]]; then
            # Something is there, we just cannot reach it. Reporting "not
            # installed" here is the check claiming it looked when it did not.
            local check=$(create_check_json \
                "docker.daemon_unreachable" \
                "docker" \
                "low" \
                "failed" \
                "$(i18n 'docker.daemon_unreachable')" \
                "$(i18n 'docker.daemon_unreachable_desc' "found=${runtime:-docker}")" \
                "$(i18n 'docker.daemon_unreachable_fix')" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'docker.daemon_unreachable')"
            return
        fi

        local check=$(create_check_json \
            "docker.not_installed" \
            "docker" \
            "low" \
            "passed" \
            "$(i18n 'docker.not_installed')" \
            "$(i18n 'docker.not_installed_desc')" \
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
            "$(i18n 'docker.exposed_ports_desc' "list=$port_list")" \
            "$(i18n 'docker.exposed_ports_suggestion')" \
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
            "$(i18n 'docker.privileged_containers_desc' "list=$container_list")" \
            "$(i18n 'docker.privileged_containers_suggestion')" \
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
            "$(i18n 'docker.all_root_containers' "count=$count")" \
            "$(i18n 'docker.all_root_containers_desc')" \
            "$(i18n 'docker.root_containers_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "low" "All $count containers running as root"
    elif ((count > 0)); then
        local check=$(create_check_json \
            "docker.some_root_containers" \
            "docker" \
            "low" \
            "failed" \
            "$(i18n 'docker.some_root_containers' "count=$count" "total=$total")" \
            "$(i18n 'docker.some_root_containers_desc')" \
            "$(i18n 'docker.root_containers_suggestion')" \
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
            "$(i18n 'docker.no_live_restore')" \
            "$(i18n 'docker.no_live_restore_desc')" \
            "$(i18n 'docker.no_live_restore_suggestion')" \
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
            "$(i18n 'docker.no_new_privileges_disabled')" \
            "$(i18n 'docker.no_new_privileges_disabled_desc')" \
            "$(i18n 'docker.no_new_privileges_disabled_suggestion')" \
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

# Any process that can write docker.sock can spawn privileged containers and
# reach host root, so a world-writable socket is high severity. Distro
# packaging ships it 660 root:docker.
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

    # Any non-zero others bit lets outside processes reach the socket.
    # 2 and 6 are the dangerous cases; 4 leaks state without immediate RCE.
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

# seccomp=unconfined disables the default syscall filter entirely — almost
# always a debugging workaround that was never reverted.
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

# userns-remap maps container UID 0 to a non-root host UID. It is a
# daemon-level setting, not per-container, so this check must distinguish
# "compiled in and available" from "actually active".
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

# --network=host bypasses network isolation entirely. Medium, not high:
# VPN daemons and monitoring agents have legitimate reasons, so this is
# "review each one", not "broken by default".
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
            "$(i18n 'docker.host_network_used_desc' "list=${hn_list% }")" \
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

# ICC=true lets every container on docker0 talk to every other. Low, because
# this IS the out-of-box default and medium would be noisy on every install.
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
            "$(i18n 'docker.default_bridge_icc_enabled_desc')" \
            "$(i18n 'docker.fix_default_bridge_icc' 2>/dev/null || echo 'Add \"icc\": false to /etc/docker/daemon.json, restart docker. Use user-defined networks for containers that genuinely need to communicate.')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'docker.default_bridge_icc_enabled' 2>/dev/null || echo 'Default-bridge ICC enabled')"
    fi
}

# Medium, not high like the cloud user-data scan: those are readable by every
# process on the host, while container env needs the container or docker
# access first. NEVER log raw values — desc records only kind and count.
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
            "$(i18n 'docker.secrets_in_env_desc' "sample=${sample}")" \
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

# Containers without a memory cap can OOM the host. Low: a single-app server
# legitimately runs one uncapped container, since it IS the workload.
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
            "$(i18n 'docker.unlimited_memory_desc' "list=${um_list% }")" \
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

# --- Docker Fix Functions ---

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
# Publish nothing from app containers; let the reverse proxy be the only
# ingress. Before first use:   docker network create proxy
# (the `proxy` network is declared external so several compose projects
# can share one Traefik).

services:
  # Example application. NO host `ports:` at all — Traefik reaches it over
  # the shared `proxy` network, so nothing listens on the host. A service
  # must sit on the SAME network as Traefik to be routable; keep `internal`
  # for app<->db traffic that Traefik should never see.
  # app:
  #   image: your-app:latest
  #   networks:
  #     - proxy
  #     - internal
  #   labels:
  #     - "traefik.enable=true"
  #     - "traefik.http.routers.app.rule=Host(`app.example.com`)"
  #     - "traefik.http.routers.app.tls.certresolver=letsencrypt"
  #     - "traefik.http.services.app.loadbalancer.server.port=8080"

  # Traefik reverse proxy
  traefik:
    image: traefik:v3.5
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      # SECURITY NOTE: access to the Docker socket is root-equivalent on
      # the host — the `:ro` mount option only stops replacing the socket
      # FILE; the API behind it stays fully read-write. Anyone who can make
      # Traefik talk to this socket can start privileged containers. For
      # stricter setups, front the socket with a filtering proxy (e.g.
      # linuxserver/socket-proxy or tecnativa/docker-socket-proxy) and point
      # Traefik's endpoint at that instead.
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./traefik/acme.json:/acme.json
    networks:
      - proxy

networks:
  proxy:
    external: true    # create once: docker network create proxy
  internal:
    internal: true

# Security practices applied:
# 1. App containers publish no host ports; Traefik is the only ingress
# 2. no-new-privileges on the proxy container
# 3. Docker socket exposure documented honestly (root-equivalent; see note)
# 4. `internal` network for backend traffic Traefik should never route
# 5. TLS via Let's Encrypt on the proxy
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
    # No postcondition here: FIX_VERIFY declares the audit predicate for each
    # daemon setting, and execute_fix runs it after this returns.
    local tmp_file="${DOCKER_DAEMON_JSON}.tmp"

    print_info "$(i18n 'docker.configuring_daemon' "setting=$setting" "value=$value")"

    # Refuse to edit an existing file that is not valid JSON: a failed jq
    # would write an empty temp file over it. Checked BEFORE the backup, so a
    # file we refuse to touch leaves no trace in the session.
    if [[ -f "$DOCKER_DAEMON_JSON" ]] && ! jq empty "$DOCKER_DAEMON_JSON" 2>/dev/null; then
        print_error "$(i18n 'docker.daemon_invalid_json' "path=$DOCKER_DAEMON_JSON")"
        return 1
    fi

    # UNCONDITIONAL, covering BOTH branches below: for an absent path
    # backup_file records it in .vpssec_created, which is what lets a rollback
    # delete it. Docker ships no daemon.json, so create is the common case.
    backup_file "$DOCKER_DAEMON_JSON" >/dev/null || return 1

    # Create or update daemon.json
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
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
        # Derived from the path variable, never hardcoded: a literal makes
        # this write outside whatever tree a caller pointed it at.
        mkdir -p "$(dirname "$DOCKER_DAEMON_JSON")"
        if ! jq -n --arg key "$setting" --argjson val "$value" \
               '{($key): $val}' > "$tmp_file" 2>/dev/null; then
            rm -f "$tmp_file"
            print_error "$(i18n 'docker.daemon_update_failed')"
            return 1
        fi
        mv "$tmp_file" "$DOCKER_DAEMON_JSON"
    fi

    print_ok "$(i18n 'docker.daemon_updated')"

    # daemon.json is not auto-reloaded, and a restart briefly pauses every
    # container. confirm_critical ignores --yes, so no silent restart.
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

# --- Docker Utility Functions ---

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
