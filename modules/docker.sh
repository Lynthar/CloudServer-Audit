#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Docker security module (Enhanced v0.2)
# Copyright (c) 2024

# --- Docker Configuration ---

DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
DOCKER_SOCK="/var/run/docker.sock"
DOCKER_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/docker"
# Seconds a daemon gets to answer `docker info` before it counts as unreachable.
DOCKER_PROBE_TIMEOUT=10

# --- Docker Helper Functions ---

# Bounded: a deadlocked dockerd never answers, and the whole audit would wait.
# Without timeout(1) the probe runs unbounded, as the filesystem walks do.
_docker_installed() {
    check_command docker || return 1
    if check_command timeout; then
        timeout "$DOCKER_PROBE_TIMEOUT" docker info &>/dev/null
    else
        docker info &>/dev/null
    fi
}

# podman-docker's `docker` is podman, which has no dockerd behind it: the
# daemon settings below do not exist there and must not be read as "off".
_docker_is_podman() {
    [[ "$(docker --version 2>/dev/null)" == [Pp]odman* ]]
}

# Major version of the answering dockerd; fails when none answers.
_docker_server_major() {
    local v
    v=$(docker info --format '{{.ServerVersion}}' 2>/dev/null) || return 1
    [[ "${v%%.*}" =~ ^[0-9]+$ ]] || return 1
    echo "${v%%.*}"
}

# dockerd's configured argv, one token per line: the unit's effective ExecStart
# as systemd merged it (drop-in resets, continuation lines), with $DOCKER_OPTS
# filled in from the unit's EnvironmentFile as systemd would.
_docker_dockerd_argv() {
    local cmd opts="" f val
    command -v systemctl &>/dev/null || return 1
    cmd=$(systemctl show -p ExecStart --value docker.service 2>/dev/null \
        | sed -n '/argv\[\]=/{s/.*argv\[\]=\([^;]*\) ;.*/\1/p;q;}') || cmd=""
    [[ -n "$cmd" ]] || return 1
    if [[ "$cmd" == *'$DOCKER_OPTS'* || "$cmd" == *'${DOCKER_OPTS}'* ]]; then
        while IFS= read -r f; do
            [[ -r "$f" ]] || continue
            val=$(sed -n 's/^[[:space:]]*DOCKER_OPTS=//p' "$f" | tail -1)
            [[ -n "$val" ]] && opts="$val"
        done < <(systemctl show -p EnvironmentFiles --value docker.service 2>/dev/null \
            | grep -o '/[^ ]*')
        opts="${opts#[\"\']}"; opts="${opts%[\"\']}"
        cmd="${cmd//'${DOCKER_OPTS}'/$opts}"
        cmd="${cmd//'$DOCKER_OPTS'/$opts}"
    fi
    tr -s ' ' '\n' <<<"$cmd"
}

# Value of dockerd flag --$1 on that command line, as true/false for a Go
# bool; the last occurrence wins, as in dockerd. Fails when it is not there.
_docker_flag_value() {
    local tok val="" found=1
    while IFS= read -r tok; do
        case "$tok" in
            "--$1") val=true; found=0 ;;
            "--$1="*) val="${tok#*=}"; found=0 ;;
        esac
    done < <(_docker_dockerd_argv)
    (( found == 0 )) || return 1
    case "$val" in
        1|t|T|TRUE|true|True) echo true ;;
        0|f|F|FALSE|false|False) echo false ;;
        *) echo "$val" ;;
    esac
}

# A daemon setting as configured, for a daemon that cannot say: the command-line
# flag wins (dockerd refuses to start when daemon.json repeats it), else
# daemon.json. $1 key, $2 the JSON value that passes.
_docker_configured_setting() {
    local val
    if val=$(_docker_flag_value "$1"); then
        [[ "$val" == "$2" ]]
        return
    fi
    [[ -f "$DOCKER_DAEMON_JSON" ]] && \
        jq -e --arg k "$1" --argjson w "$2" '.[$k] == $w' "$DOCKER_DAEMON_JSON" &>/dev/null
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
    # Publicly published ports: the port or range ("9000-9001", the CLI merges
    # adjacent ones) before "->" on any NON-loopback binding — IPv6 wildcard,
    # bracketed IPv6 and specific public IPs included.
    docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | awk '
        /->/ {
            hp = $0; sub(/->.*/, "", hp); gsub(/[[:space:]]/, "", hp)
            port = hp; sub(/.*:/, "", port)
            addr = hp; sub(/:[0-9]+(-[0-9]+)?$/, "", addr); gsub(/[][]/, "", addr)
            if (addr ~ /^127\./ || addr == "::1") next
            if (port ~ /^[0-9]+(-[0-9]+)?$/) print port
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
        # user[:group]; only the user part decides who the process runs as.
        user="${user%%:*}"
        if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
            local name=$(docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            root_containers+=("$name")
        fi
    done
    printf '%s\n' "${root_containers[@]}"
}

# "name: CAP,CAP" for each running container granted capabilities.
_docker_get_containers_with_caps() {
    local cap_containers=()
    for container in $(docker ps -q 2>/dev/null); do
        local caps=$(docker inspect "$container" 2>/dev/null | jq -r '.[0].HostConfig.CapAdd // [] | join(",")')
        if [[ -n "$caps" ]]; then
            local name=$(docker inspect "$container" --format '{{.Name}}' 2>/dev/null | tr -d '/')
            cap_containers+=("${name}: ${caps}")
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

# Numeric mode (e.g. "660") of the docker socket, empty when there is none.
# -L: podman-docker links it to podman.sock, and a link's own mode is 777.
_docker_sock_mode() {
    [[ -S "$DOCKER_SOCK" ]] || return 0
    stat -L -c '%a' "$DOCKER_SOCK" 2>/dev/null
}

# Return names of running containers that were started with
# --security-opt seccomp=unconfined, one per line. dockerd still accepts the
# old seccomp:unconfined spelling and stores it as typed, so both count.
_docker_seccomp_unconfined_containers() {
    local unconfined=()
    local container
    for container in $(docker ps -q 2>/dev/null); do
        # jq -e returns non-zero if the filter produces no matches.
        if docker inspect "$container" 2>/dev/null \
            | jq -e '.[0].HostConfig.SecurityOpt // [] | any(test("^seccomp[=:]unconfined$"))' &>/dev/null; then
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

# From Engine 24 the daemon lists name=no-new-privileges in SecurityOptions
# when it is the default, and that answer is final: a written but unloaded
# setting is not on. Older or stopped daemons fall back to the configuration.
_docker_check_no_new_privileges() {
    local major opts
    major=$(_docker_server_major) || major=0
    if (( major >= 24 )) && opts=$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null); then
        [[ "$opts" == *'name=no-new-privileges'* ]]
        return
    fi
    _docker_configured_setting no-new-privileges true
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

# Is inter-container communication on the default bridge disabled? The bridge
# network's enable_icc option is the daemon's own answer and is final; a
# daemon that cannot say falls back to the configuration.
_docker_check_icc_disabled() {
    local icc
    icc=$(docker network inspect bridge \
        --format '{{index .Options "com.docker.network.bridge.enable_icc"}}' 2>/dev/null) || icc=""
    if [[ "$icc" == "true" || "$icc" == "false" ]]; then
        [[ "$icc" == "false" ]]
        return
    fi
    _docker_configured_setting icc false
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
            check_emit "docker.daemon_unreachable" low failed \
                desc="$(i18n 'docker.daemon_unreachable_desc' "found=${runtime:-docker}")" \
                suggestion="$(i18n 'docker.daemon_unreachable_fix')"
            print_severity "low" "$(i18n 'docker.daemon_unreachable')"
            return
        fi

        check_emit "docker.not_installed" low passed \
            desc="$(i18n 'docker.not_installed_desc')"
        print_ok "$(i18n 'docker.not_installed') - $(i18n 'common.skipping')"
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

    # Daemon-level settings: dockerd only. Under podman-docker they name
    # options podman does not have, so say they were not checked.
    local podman=0
    if _docker_is_podman; then
        podman=1
        check_emit "docker.podman_daemon_not_checked" low failed \
            desc="$(i18n 'docker.podman_daemon_not_checked_desc')"
        print_severity "low" "$(i18n 'docker.podman_daemon_not_checked')"
    else
        print_item "$(i18n 'docker.check_daemon_security')"
        _docker_audit_daemon_settings
    fi

    # Check /var/run/docker.sock permissions (world-writable socket =
    # effective root for any local user).
    print_item "$(i18n 'docker.check_sock_perms')"
    _docker_audit_sock_perms

    # Check for containers running with seccomp=unconfined.
    print_item "$(i18n 'docker.check_seccomp')"
    _docker_audit_seccomp_unconfined

    # Check whether userns-remap is actually active (not just available).
    if (( ! podman )); then
        print_item "$(i18n 'docker.check_userns_remap')"
        _docker_audit_userns_remap
    fi

    # CIS Docker network / secrets / resources additions:
    print_item "$(i18n 'docker.check_host_network')"
    _docker_audit_host_network

    if (( ! podman )); then
        print_item "$(i18n 'docker.check_default_bridge_icc')"
        _docker_audit_default_bridge_icc
    fi

    print_item "$(i18n 'docker.check_secrets_in_env')"
    _docker_audit_secrets_in_env

    print_item "$(i18n 'docker.check_unlimited_memory')"
    _docker_audit_unlimited_memory
}

_docker_audit_exposed_ports() {
    local ports=$(_docker_get_exposed_ports)
    local count=$(count_lines "$ports")

    if ((count > 0)); then
        local port_list=$(echo "$ports" | tr '\n' ' ')
        check_emit "docker.exposed_ports" medium failed \
            title="$(i18n 'docker.exposed_ports' "count=$count")" \
            desc="$(i18n 'docker.exposed_ports_desc' "list=$port_list")" \
            suggestion="$(i18n 'docker.exposed_ports_suggestion')" \
            fix="docker.generate_proxy_template"
        print_severity "medium" "$(i18n 'docker.exposed_ports' "count=$count"): $port_list"
    else
        check_emit "docker.no_exposed_ports" low passed
        print_ok "$(i18n 'docker.no_exposed_ports')"
    fi
}

_docker_audit_privileged() {
    local containers=$(_docker_get_privileged_containers)
    local count=$(count_lines "$containers")

    if ((count > 0)); then
        local container_list=$(echo "$containers" | tr '\n' ' ')
        check_emit "docker.privileged_containers" medium failed \
            title="$(i18n 'docker.privileged_containers' "count=$count")" \
            desc="$(i18n 'docker.privileged_containers_desc' "list=$container_list")" \
            suggestion="$(i18n 'docker.privileged_containers_suggestion')"
        print_severity "medium" "$(i18n 'docker.privileged_containers' "count=$count"): $container_list"
    else
        check_emit "docker.no_privileged" low passed
        print_ok "$(i18n 'docker.no_privileged')"
    fi
}

_docker_audit_root_containers() {
    local containers=$(_docker_get_root_containers)
    local count=$(count_lines "$containers")
    local total=$(docker ps -q 2>/dev/null | wc -l)

    if ((count > 0 && count == total)); then
        check_emit "docker.all_root_containers" low failed \
            title="$(i18n 'docker.all_root_containers' "count=$count")" \
            desc="$(i18n 'docker.all_root_containers_desc')" \
            suggestion="$(i18n 'docker.root_containers_suggestion')"
        print_severity "low" "$(i18n 'docker.all_root_containers' "count=$count")"
    elif ((count > 0)); then
        check_emit "docker.some_root_containers" low failed \
            title="$(i18n 'docker.some_root_containers' "count=$count" "total=$total")" \
            desc="$(i18n 'docker.some_root_containers_desc')" \
            suggestion="$(i18n 'docker.root_containers_suggestion')"
        print_severity "low" "$(i18n 'docker.some_root_containers' "count=$count" "total=$total")"
    else
        check_emit "docker.no_root_containers" low passed
        print_ok "$(i18n 'docker.no_root_containers')"
    fi
}

_docker_audit_capabilities() {
    local containers=$(_docker_get_containers_with_caps)
    local count=$(count_lines "$containers")

    if ((count > 0)); then
        local container_list="${containers//$'\n'/; }"
        check_emit "docker.containers_with_caps" medium failed \
            title="$(i18n 'docker.added_capabilities' "count=$count")" \
            desc="$(i18n 'docker.added_capabilities_desc' "list=$container_list")" \
            suggestion="$(i18n 'docker.added_capabilities_suggestion')"
        print_severity "medium" "$(i18n 'docker.added_capabilities' "count=$count"): $container_list"
    else
        check_emit "docker.no_extra_caps" low passed \
            title="$(i18n 'docker.no_added_capabilities')"
        print_ok "$(i18n 'docker.no_added_capabilities')"
    fi
}

_docker_audit_daemon_settings() {
    local issues=0

    # Check live-restore
    if ! _docker_check_live_restore; then
        check_emit "docker.no_live_restore" low failed \
            desc="$(i18n 'docker.no_live_restore_desc')" \
            suggestion="$(i18n 'docker.no_live_restore_suggestion')" \
            fix="docker.enable_live_restore"
        print_severity "low" "$(i18n 'docker.no_live_restore')"
        ((issues++)) || true
    fi

    # Check no-new-privileges
    if ! _docker_check_no_new_privileges; then
        check_emit "docker.no_new_privileges_disabled" low failed \
            desc="$(i18n 'docker.no_new_privileges_disabled_desc')" \
            suggestion="$(i18n 'docker.no_new_privileges_disabled_suggestion')" \
            fix="docker.enable_no_new_privileges"
        print_severity "low" "$(i18n 'docker.no_new_privileges_disabled')"
        ((issues++)) || true
    fi

    if ((issues == 0)); then
        check_emit "docker.daemon_secure" low passed
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
        check_emit "docker.sock_perms_loose" high failed \
            title="$(i18n 'docker.sock_perms_loose' "mode=$mode")" \
            desc="$(i18n 'docker.sock_perms_loose_desc' "mode=$mode")" \
            suggestion="$(i18n 'docker.sock_perms_fix')"
        print_severity "high" "$(i18n 'docker.sock_perms_loose' "mode=$mode")"
    else
        check_emit "docker.sock_perms_ok" low passed \
            title="$(i18n 'docker.sock_perms_ok' "mode=$mode")"
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
        check_emit "docker.seccomp_unconfined" medium failed \
            title="$(i18n 'docker.seccomp_unconfined' "count=$count")" \
            desc="$(i18n 'docker.seccomp_unconfined_desc' "containers=$list")" \
            suggestion="$(i18n 'docker.seccomp_fix')"
        print_severity "medium" "$(i18n 'docker.seccomp_unconfined' "count=$count"): $list"
    else
        check_emit "docker.no_seccomp_unconfined" low passed
        print_ok "$(i18n 'docker.no_seccomp_unconfined')"
    fi
}

# userns-remap maps container UID 0 to a non-root host UID. It is a
# daemon-level setting, not per-container, so this check must distinguish
# "compiled in and available" from "actually active".
_docker_audit_userns_remap() {
    if _docker_check_userns; then
        check_emit "docker.userns_enabled" low passed
        print_ok "$(i18n 'docker.userns_enabled')"
    else
        check_emit "docker.userns_not_enabled" low failed \
            desc="$(i18n 'docker.userns_not_enabled_desc')" \
            suggestion="$(i18n 'docker.userns_fix')"
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
        check_emit "docker.host_network_used" medium failed \
            title="$(i18n 'docker.host_network_used' "count=$count")" \
            desc="$(i18n 'docker.host_network_used_desc' "list=${hn_list% }")" \
            suggestion="$(i18n 'docker.fix_host_network')"
        print_severity "medium" "$(i18n 'docker.host_network_used' "count=$count")"
    else
        check_emit "docker.no_host_network" low passed
        print_ok "$(i18n 'docker.no_host_network')"
    fi
}

# ICC=true lets every container on docker0 talk to every other. Low, because
# this IS the out-of-box default and medium would be noisy on every install.
_docker_audit_default_bridge_icc() {
    if _docker_check_icc_disabled; then
        check_emit "docker.default_bridge_icc_disabled" low passed
        print_ok "$(i18n 'docker.default_bridge_icc_disabled')"
    else
        check_emit "docker.default_bridge_icc_enabled" low failed \
            desc="$(i18n 'docker.default_bridge_icc_enabled_desc')" \
            suggestion="$(i18n 'docker.fix_default_bridge_icc')"
        print_severity "low" "$(i18n 'docker.default_bridge_icc_enabled')"
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
        # The first five containers only: longer lists overflow the display,
        # and the title carries the count.
        local sample; sample=$(head -5 <<<"$hits")
        sample="${sample//$'\n'/; }"
        check_emit "docker.secrets_in_env" medium failed \
            title="$(i18n 'docker.secrets_in_env' "count=$count")" \
            desc="$(i18n 'docker.secrets_in_env_desc' "sample=${sample}")" \
            suggestion="$(i18n 'docker.fix_secrets_in_env')"
        print_severity "medium" "$(i18n 'docker.secrets_in_env' "count=$count")"
    else
        check_emit "docker.no_env_secrets" low passed
        print_ok "$(i18n 'docker.no_env_secrets')"
    fi
}

# Containers without a memory cap can OOM the host. Low: a single-app server
# legitimately runs one uncapped container, since it IS the workload.
_docker_audit_unlimited_memory() {
    local um; um=$(_docker_get_unlimited_memory_containers)
    local count; count=$(count_lines "$um")

    if (( count > 0 )); then
        local um_list=$(echo "$um" | tr '\n' ' ')
        check_emit "docker.unlimited_memory" low failed \
            title="$(i18n 'docker.unlimited_memory' "count=$count")" \
            desc="$(i18n 'docker.unlimited_memory_desc' "list=${um_list% }")" \
            suggestion="$(i18n 'docker.fix_unlimited_memory')"
        print_severity "low" "$(i18n 'docker.unlimited_memory' "count=$count")"
    else
        check_emit "docker.memory_limits_set" low passed
        print_ok "$(i18n 'docker.memory_limits_set')"
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
    local template_dir="${DOCKER_TEMPLATES_DIR}"
    local output_file="${template_dir}/docker-compose.proxy.yml"

    print_info "$(i18n 'docker.generating_template')"

    write_template "$output_file" <<'EOF' || return 1
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
    write_template "${template_dir}/traefik/traefik.yml" <<'EOF' || return 1
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

    # touch, not a write: an acme.json already there holds issued certificates.
    local acme="${template_dir}/traefik/acme.json"
    if ! touch "$acme" || ! chmod 600 "$acme"; then
        print_error "$(i18n 'common.template_write_failed' "path=$acme")"
        return 1
    fi

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

    print_info "$(i18n 'docker.configuring_daemon' "setting=$setting" "value=$value")"

    # dockerd refuses to start when a setting is both a flag and in daemon.json,
    # so a flag already on its command line is changed there, by the operator.
    if _docker_flag_value "$setting" >/dev/null; then
        print_error "$(i18n 'docker.daemon_flag_set' "flag=--$setting")"
        return 1
    fi

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

    # Merge into an existing file, or create one.
    local merged=""
    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        merged=$(jq --arg key "$setting" --argjson val "$value" '.[$key] = $val' \
                   "$DOCKER_DAEMON_JSON" 2>/dev/null) || merged=""
    else
        merged=$(jq -n --arg key "$setting" --argjson val "$value" \
                   '{($key): $val}' 2>/dev/null) || merged=""
    fi

    # write_file_atomic keeps the file's mode and owner: daemon.json can hold
    # registry or proxy credentials, so a 0600 file must not come back 0644.
    # Keep the -z test: the appended newline slips an empty merge past its check.
    if [[ -z "$merged" ]] || ! write_file_atomic "$DOCKER_DAEMON_JSON" "$merged"$'\n'; then
        print_error "$(i18n 'docker.daemon_update_failed')"
        return 1
    fi

    print_ok "$(i18n 'docker.daemon_updated')"

    # live-restore is reloadable: SIGHUP applies it with every container left
    # running. no-new-privileges needs a restart, which stops every container
    # unless live-restore is already on; confirm_critical ignores --yes.
    if [[ "$setting" == "live-restore" ]]; then
        if systemctl reload docker 2>/dev/null; then
            print_ok "$(i18n 'docker.reloaded')"
            return 0
        fi
        print_error "$(i18n 'docker.reload_failed')"
        return 1
    fi
    local confirm_key="docker.confirm_restart"
    _docker_check_live_restore && confirm_key="docker.confirm_restart_live"
    if ! confirm_critical "$(i18n "$confirm_key")"; then
        print_warn "$(i18n 'docker.restart_skipped')"
        # daemon.json is already written, so this "no" is a failure, not a
        # skipped fix: execute_fix must not read it as a declined one.
        _VPSSEC_DECLINED=0
        return 1
    fi
    if ! systemctl restart docker 2>/dev/null; then
        print_error "$(i18n 'docker.restart_failed')"
        return 1
    fi
    print_ok "$(i18n 'docker.restarted')"
    return 0
}

# --- Docker Utility Functions ---
