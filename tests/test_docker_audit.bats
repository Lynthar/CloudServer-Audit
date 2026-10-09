#!/usr/bin/env bats
# What docker_audit reports from what the docker CLI shows: published ports as
# the CLI prints them, the socket a symlink points at, and podman-docker, whose
# `docker` has no dockerd behind it.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
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
