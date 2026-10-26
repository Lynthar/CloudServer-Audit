#!/usr/bin/env bats
# What docker_audit reports from what the docker CLI shows: published ports as
# the CLI prints them, the socket a symlink points at, and podman-docker, whose
# `docker` has no dockerd behind it.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/docker.sh"
    etc=$(_vpssec_fake_etc)
    DOCKER_DAEMON_JSON="$etc/docker/daemon.json"
    DOCKER_SOCK="$BATS_TEST_TMPDIR/docker.sock"
    _vpssec_stub systemctl
    _vpssec_stub getent 0 ""
}

_emitted() {
    jq -r '.[] | "\(.id) \(.status)"' "$VPSSEC_STATE/checks.json" 2>/dev/null
}

_field() {
    jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f] // ""' \
        "$VPSSEC_STATE/checks.json"
}

# A Docker 29 CLI whose `docker ps --format {{.Ports}}` prints $1.
_docker_with_ports() {
    printf '%s\n' "$1" > "$BATS_TEST_TMPDIR/ports"
    _vpssec_stub_script docker <<SH
case "\$*" in
    "--version") echo "Docker version 29.1.3, build f52814d" ;;
    "ps --format {{.Ports}}") cat "$BATS_TEST_TMPDIR/ports" ;;
    *ServerVersion*) echo "29.1.3" ;;
    *LiveRestoreEnabled*) echo true ;;
    *SecurityOptions*) echo '["name=no-new-privileges"]' ;;
    "network inspect bridge"*) echo false ;;
    *) echo "" ;;
esac
exit 0
SH
}

# ---- published ports ---------------------------------------------------

@test "ports: a range the CLI merged is reported, not dropped" {
    # Recorded from Docker 29.8.2 for -p 39000-39001:39000-39001 plus a
    # loopback range and one single port.
    _docker_with_ports '0.0.0.0:39000-39001->39000-39001/tcp, [::]:39000-39001->39000-39001/tcp, 127.0.0.1:39020-39021->39020-39021/tcp, 0.0.0.0:39010->80/tcp, [::]:39010->80/tcp'
    docker_audit >/dev/null
    _emitted | grep -qx 'docker.exposed_ports failed'
    [ "$(_field docker.exposed_ports desc)" = "Exposed ports: 39000-39001 39010 " ]
}

@test "ports: only ranges published is not 'no exposed ports'" {
    _docker_with_ports '0.0.0.0:9000-9001->9000-9001/tcp, [::]:9000-9001->9000-9001/tcp'
    docker_audit >/dev/null
    _emitted | grep -qx 'docker.exposed_ports failed'
    _vpssec_refute grep -q 'docker.no_exposed_ports' <<<"$(_emitted)"
}

@test "ports: loopback-only bindings, ranges included, are not exposed" {
    _docker_with_ports '127.0.0.1:39020-39021->39020-39021/tcp, [::1]:9000-9001->9000-9001/tcp, 127.0.0.1:8080->80/tcp'
    docker_audit >/dev/null
    _emitted | grep -qx 'docker.no_exposed_ports passed'
}

# ---- the socket --------------------------------------------------------

@test "socket: a symlinked docker.sock is judged by the socket it points at" {
    # podman-docker links /run/docker.sock to podman.sock; the link itself is 777.
    command -v python3 >/dev/null 2>&1 || skip "python3 is needed to create the test socket"
    local real="$BATS_TEST_TMPDIR/real.sock"
    python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" \
        "$real" || skip "cannot create an AF_UNIX socket here"
    chmod 660 "$real"
    ln -s "$real" "$DOCKER_SOCK"
    _docker_with_ports ''

    docker_audit >/dev/null
    _emitted | grep -qx 'docker.sock_perms_ok passed'
    [ "$(_field docker.sock_perms_ok title)" = "$(i18n 'docker.sock_perms_ok' 'mode=660')" ]
}

# ---- podman-docker -----------------------------------------------------

# podman-docker's shim, answering as podman 4.3.1 did on Debian 12: `info`
# works, but Docker's template fields do not exist there (rc 125).
_podman_shim() {
    _vpssec_stub_script docker <<'SH'
echo "Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg." >&2
case "$*" in
    "--version") echo "podman version 4.3.1" ;;
    "info") echo "host: {}" ;;
    "info --format"*)
        echo "Error: template: info:1:2: executing \"info\": can't evaluate field in type *define.Info" >&2
        exit 125 ;;
    "network inspect bridge"*) echo "Error: unable to find network with name or ID bridge" >&2; exit 125 ;;
    *) echo "" ;;
esac
exit 0
SH
}

@test "podman-docker: daemon settings are not reported as off, and no daemon fix is offered" {
    _podman_shim
    docker_audit >/dev/null

    _emitted | grep -qx 'docker.podman_daemon_not_checked failed'
    [ "${CHECK_SCORE_CATEGORY[docker.podman_daemon_not_checked]}" = "info" ]
    local id
    for id in docker.no_live_restore docker.no_new_privileges_disabled \
              docker.daemon_secure docker.userns_not_enabled docker.userns_enabled \
              docker.default_bridge_icc_enabled docker.default_bridge_icc_disabled; do
        _vpssec_refute grep -q "$id" <<<"$(_emitted)"
    done
    _vpssec_refute grep -q 'docker.enable_' "$VPSSEC_STATE/checks.json"
}

@test "podman-docker: container checks still run" {
    _podman_shim
    docker_audit >/dev/null
    _emitted | grep -qx 'docker.no_exposed_ports passed'
    _emitted | grep -qx 'docker.no_privileged passed'
}

@test "a real Docker CLI still gets the daemon checks" {
    _docker_with_ports ''
    docker_audit >/dev/null
    _emitted | grep -qx 'docker.daemon_secure passed'
    _emitted | grep -qx 'docker.default_bridge_icc_disabled passed'
    _vpssec_refute grep -q 'docker.podman_daemon_not_checked' <<<"$(_emitted)"
}

# ---- what the containers run with ---------------------------------------

# Container $1 named $2, as `docker inspect $1` prints it, edited by the jq
# expression $3. Read by _docker_with_containers.
_ctr() {
    mkdir -p "$BATS_TEST_TMPDIR/ctr"
    jq -n --arg n "/$2" "[{Name: \$n, Config: {User: \"\"},
        HostConfig: {Privileged: false, CapAdd: null, SecurityOpt: null,
                     NetworkMode: \"bridge\", Memory: 268435456}} | $3]" \
        > "$BATS_TEST_TMPDIR/ctr/$1.json"
}

# A Docker 29 CLI running the containers _ctr wrote; inspect's --format
# queries are answered from the same JSON.
_docker_with_containers() {
    _vpssec_stub_script docker <<SH
dir="$BATS_TEST_TMPDIR/ctr"
case "\$1 \${2:-}" in
    "--version ") echo "Docker version 29.1.3, build f52814d" ;;
    "ps -q"|"ps -aq") ls "\$dir" | sed 's/\.json\$//' ;;
    "inspect "*)
        f="\$dir/\$2.json"
        [[ "\${3:-}" == --format ]] || { cat "\$f"; exit 0; }
        case "\$4" in
            "{{.Name}}") jq -r '.[0].Name' "\$f" ;;
            "{{.Config.User}}") jq -r '.[0].Config.User' "\$f" ;;
            "{{.HostConfig.NetworkMode}}") jq -r '.[0].HostConfig.NetworkMode' "\$f" ;;
            "{{.HostConfig.Memory}}") jq -r '.[0].HostConfig.Memory' "\$f" ;;
            "{{range .Config.Env}}{{println .}}{{end}}") jq -r '.[0].Config.Env // [] | .[]' "\$f" ;;
        esac ;;
    "info --format")
        case "\$3" in
            *ServerVersion*) echo "29.1.3" ;;
            *LiveRestoreEnabled*) echo true ;;
            *SecurityOptions*) echo '["name=no-new-privileges"]' ;;
        esac ;;
    "network inspect") echo false ;;
esac
exit 0
SH
}

@test "seccomp: the colon spelling seccomp:unconfined is unconfined too" {
    # dockerd still accepts the colon and stores it as typed.
    _ctr c1 web '.HostConfig.SecurityOpt = ["seccomp:unconfined"]'
    _ctr c2 db '.HostConfig.SecurityOpt = ["seccomp=unconfined"]'
    _ctr c3 app '.HostConfig.SecurityOpt = ["apparmor:unconfined", "seccomp=/etc/p.json"]'
    _docker_with_containers

    docker_audit >/dev/null
    _emitted | grep -qx 'docker.seccomp_unconfined failed'
    [ "$(_field docker.seccomp_unconfined title)" = "$(i18n docker.seccomp_unconfined count=2)" ]
    [[ "$(_field docker.seccomp_unconfined desc)" != *app* ]]
}

@test "root containers: a user:group whose user is 0 or root runs as root" {
    _ctr c1 web '.Config.User = "0:0"'
    _ctr c2 db '.Config.User = "root:root"'
    _ctr c3 app '.Config.User = "1000:0"'
    _docker_with_containers

    docker_audit >/dev/null
    _emitted | grep -qx 'docker.some_root_containers failed'
    [ "$(_field docker.some_root_containers title)" = "$(i18n docker.some_root_containers count=2 total=3)" ]
}

@test "capabilities: the finding names each container and what it was granted" {
    _ctr c1 web '.HostConfig.CapAdd = ["NET_ADMIN", "SYS_TIME"]'
    _ctr c2 db '.HostConfig.CapAdd = null'
    _ctr c3 proxy '.HostConfig.CapAdd = ["NET_BIND_SERVICE"]'
    _docker_with_containers

    docker_audit >/dev/null
    _emitted | grep -qx 'docker.containers_with_caps failed'
    [ "$(_field docker.containers_with_caps title)" = "$(i18n docker.added_capabilities count=2)" ]
    [ "$(_field docker.containers_with_caps desc)" = \
      "$(i18n docker.added_capabilities_desc 'list=web: NET_ADMIN,SYS_TIME; proxy: NET_BIND_SERVICE')" ]
    [ "$(_field docker.containers_with_caps suggestion)" = "$(i18n docker.added_capabilities_suggestion)" ]
}

@test "env secrets: the sample names each container, joined by '; '" {
    local gh; gh="ghp_$(printf 'a%.0s' {1..36})"
    _ctr c1 web ".Config.Env = [\"GITHUB_TOKEN=$gh\"]"
    _ctr c2 db '.Config.Env = ["AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"]'
    _ctr c3 app '.Config.Env = ["PATH=/usr/bin"]'
    _docker_with_containers

    docker_audit >/dev/null
    _emitted | grep -qx 'docker.secrets_in_env failed'
    [ "$(_field docker.secrets_in_env desc)" = \
      "$(i18n docker.secrets_in_env_desc 'sample=web: github_token(x1); db: aws_access_key(x1)')" ]
}

@test "env secrets: the sample stops at five containers; the title counts all" {
    local i
    for i in 1 2 3 4 5 6; do
        _ctr "c$i" "app$i" '.Config.Env = ["AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"]'
    done
    _docker_with_containers

    docker_audit >/dev/null
    [ "$(_field docker.secrets_in_env title)" = "$(i18n docker.secrets_in_env count=6)" ]
    [[ "$(_field docker.secrets_in_env desc)" == *"app5: aws_access_key(x1)."* ]]
}

@test "a daemon that does not answer docker info in time is unreachable, not a hung audit" {
    _vpssec_stub_script docker <<'SH'
[[ "$1" == info ]] && exec sleep 5
exit 0
SH
    DOCKER_PROBE_TIMEOUT=1
    local t0=$SECONDS

    docker_audit >/dev/null
    [ $((SECONDS - t0)) -lt 4 ]
    _emitted | grep -qx 'docker.daemon_unreachable failed'
}

@test "a daemon that hangs after the probe costs one timeout, not one per container" {
    # Every docker call was unbounded past `docker info`: a dockerd that froze
    # mid-audit hung vpssec, and bounding each call alone waits once per call.
    _vpssec_stub_script docker <<'SH'
case "$*" in
    "info") exit 0 ;;
    "ps -q"|"ps -aq") printf 'c1\nc2\nc3\n' ;;
    inspect*|"network inspect"*) exec sleep 5 ;;
esac
exit 0
SH
    DOCKER_PROBE_TIMEOUT=1
    local t0=$SECONDS

    docker_audit >/dev/null
    [ $((SECONDS - t0)) -lt 4 ]
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" docker "* ]]
    [ "$(_field docker.query_incomplete status)" = "failed" ]
    [ "$(_field docker.query_incomplete severity)" = "info" ]
}

@test "a check whose docker calls timed out is not reported passed" {
    _vpssec_stub_script docker <<'SH'
case "$*" in
    "info"|"--version") exit 0 ;;
esac
exec sleep 5
SH
    DOCKER_PROBE_TIMEOUT=1

    docker_audit >/dev/null
    local ok
    for ok in no_exposed_ports no_privileged no_root_containers no_extra_caps no_seccomp_unconfined \
              no_host_network no_env_secrets memory_limits_set; do
        _vpssec_refute grep -q "^docker.$ok " <<<"$(_emitted)"
    done
}

@test "userns is not called off once docker has stalled" {
    # docker info is its only source: a stall left grep nothing to match, read as "not enabled".
    _vpssec_stub_script docker <<'SH'
case "$*" in
    "info"|"--version") exit 0 ;;
esac
exec sleep 5
SH
    DOCKER_PROBE_TIMEOUT=1

    docker_audit >/dev/null
    _vpssec_refute grep -q '^docker.userns_' <<<"$(_emitted)"
}

@test "a docker audit that never timed out is complete" {
    _docker_with_ports ''
    docker_audit >/dev/null
    [ "${#VPSSEC_MODULES_FAILED[@]}" -eq 0 ]
    _vpssec_refute grep -q 'docker.query_incomplete' <<<"$(_emitted)"
    _emitted | grep -qx 'docker.no_privileged passed'
}

@test "a stall recorded by an earlier run does not skip this run's docker calls" {
    _docker_with_ports ''
    : > "$DOCKER_STALL_MARK"
    docker_audit >/dev/null
    _emitted | grep -qx 'docker.no_privileged passed'
    _vpssec_refute grep -q 'docker.daemon_unreachable' <<<"$(_emitted)"
}

@test "a host without timeout(1) still asks the daemon, unbounded" {
    _vpssec_stub docker
    _vpssec_absent_command timeout
    timeout() { return 127; }

    run _docker_installed
    [ "$status" -eq 0 ]
}
