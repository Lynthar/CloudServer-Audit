#!/usr/bin/env bats
#
# The audit must not describe a host it did not look at.
#
# Four checks used to state something false about real machines, and all four
# were passed or silently absent, which is what made them hard to notice:
#
#   docker    a daemon it could not reach was reported as "not installed",
#             and every container check was skipped behind a green tick.
#             Rootless Docker answers exactly this way to a sudo'd audit.
#   webapp    a host running caddy or openresty was reported as having no web
#             server at all — a passed check meaning "nothing to see here".
#   baseline  a profile symlinked into apparmor.d/disable appears in neither
#             the enforcing nor the complain count, so disabling one left no
#             trace anywhere in the report.
#   preflight a Debian derivative (Mint, Kali, Armbian) failed the supported-OS
#             test and made the entry point ask "Continue anyway?" with a
#             default of no, while every distro.sh primitive resolved fine.
#
# These are one family: the tool asserting something the operator can disprove
# by looking at their own machine. There is no automated gate for it — i18n
# parity only checks that keys exist, and bats only checks which branch ran —
# so the assertions here are about the emitted check, not about a code path.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    etc=$(_vpssec_fake_etc)
}

# check ids currently in state, one per line
_emitted_ids() {
    jq -r '.[].id' "$VPSSEC_STATE/checks.json" 2>/dev/null | sort
}

_check_field() {
    jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f]' \
        "$VPSSEC_STATE/checks.json" 2>/dev/null
}

# ==============================================================================
# docker: "not installed" vs "could not reach it"
# ==============================================================================

_load_docker() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/docker.sh"
    # Every audit past the early return needs a reachable daemon; these tests
    # only exercise the early return, so nothing else has to be stubbed.
    _vpssec_stub getent 0 ""
}

@test "docker: a present-but-unreachable daemon is not reported as not installed" {
    _load_docker
    # `command -v docker` succeeds, `docker info` fails — exactly what a
    # sudo'd audit sees on a rootless install, and what a stopped daemon
    # gives too.
    _vpssec_stub docker 1

    run docker_audit

    [[ "$(_emitted_ids)" == *"docker.daemon_unreachable"* ]]
    _vpssec_refute grep -q 'docker.not_installed' "$VPSSEC_STATE/checks.json"
    [ "$(_check_field docker.daemon_unreachable status)" = "failed" ]
}

@test "docker: podman alone is enough to refuse the not-installed claim" {
    _load_docker
    _vpssec_absent_command docker
    _vpssec_stub podman 0

    run docker_audit

    [[ "$(_emitted_ids)" == *"docker.daemon_unreachable"* ]]
    [[ "$(_check_field docker.daemon_unreachable desc)" == *"podman"* ]]
}

@test "docker: a rootless socket under a user's runtime dir is found" {
    _load_docker
    # A real socket, not a regular file: the predicate tests -S, and a plain
    # file would let it pass while the production check stayed broken.
    # Short root on purpose — an AF_UNIX path is capped near 104 bytes and
    # BATS_TEST_TMPDIR alone is longer than that on macOS.
    local sock_root
    sock_root=$(mktemp -d "${TMPDIR:-/tmp}/vpsk.XXXXXX")
    sock_root=$(cd "$sock_root" && pwd -P)
    local sock_dir="$sock_root/h/.docker/run"
    mkdir -p "$sock_dir"
    # Two different reasons to skip, kept apart on purpose. The single
    # message used to blame AF_UNIX for both, and on Arch — where the base
    # image ships no python at all — it sent the reader looking at sockets
    # and path lengths for a missing interpreter. A skip that names the
    # wrong cause is worse than a failure.
    command -v python3 >/dev/null 2>&1 || skip "python3 is needed to create the test socket"
    python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" \
        "$sock_dir/docker.sock" || skip "cannot create an AF_UNIX socket here"
    _vpssec_absent_command docker
    _vpssec_stub_script getent <<SH
printf 'dev:x:1000:1000::%s:/bin/bash\n' "$sock_root/h"
SH

    # Called directly, NOT through `run`: `run` disables errexit, and the
    # defect this pins is a non-zero status mid-function aborting the scan
    # before it reaches the socket. Under `run` the broken version passed.
    local out
    out=$(_docker_unaudited_runtime)

    [[ "$out" == *"rootless-docker"* ]]
}

@test "docker: a host with no runtime at all still reports not installed" {
    _load_docker
    _vpssec_absent_command docker
    _vpssec_absent_command podman

    run docker_audit

    [[ "$(_emitted_ids)" == *"docker.not_installed"* ]]
    [ "$(_check_field docker.not_installed status)" = "passed" ]
}

# ==============================================================================
# webapp: a web server vpssec does not audit is still a web server
# ==============================================================================

@test "webapp: caddy is detected as an unaudited web server" {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    _vpssec_stub caddy 0

    run _webapp_other_webserver

    # Containment, not equality: a host that also ships lighttpd answers with
    # both, and asserting the exact string would make this test a statement
    # about the runner's package list rather than about the predicate.
    [[ "$output" == *caddy* ]]
}

@test "webapp: several unaudited servers are all named" {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    _vpssec_stub caddy 0
    _vpssec_stub lighttpd 0

    run _webapp_other_webserver

    [[ "$output" == *"caddy"* ]]
    [[ "$output" == *"lighttpd"* ]]
}

@test "webapp: a host with nothing serving reports nothing serving" {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    local c
    for c in caddy openresty lighttpd traefik haproxy; do
        _vpssec_absent_command "$c"
    done
    # Absence has to be asserted, not inherited: whether this host ships caddy
    # is a property of the runner, and a test that depends on it passes in one
    # environment and fails in another. That is how this suite went red on
    # ubuntu-latest, which preinstalls podman.
    run _webapp_other_webserver

    [ -z "$output" ]
}

@test "webapp: the audit emits the unaudited-server check, not no_webserver" {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    # Point every scan at the empty fake tree so this exercises the summary
    # branch rather than the host's real web roots.
    NGINX_CONF="$etc/nginx/nginx.conf"
    APACHE_CONF="$etc/apache2/apache2.conf"
    APACHE_CONF_ALT="$etc/httpd/conf/httpd.conf"
    _vpssec_stub caddy 0

    run webapp_audit

    [[ "$(_emitted_ids)" == *"webapp.other_webserver"* ]]
    _vpssec_refute grep -q 'webapp.no_webserver' "$VPSSEC_STATE/checks.json"
    # info, so a host is not penalised for a gap in vpssec's coverage.
    [ "$(_check_field webapp.other_webserver status)" = "failed" ]
}

@test "webapp: detection goes through the project's own command wrapper" {
    # Stub caddy so `command -v caddy` succeeds, and declare it absent so
    # check_command fails. The two answers now differ, which is the only way
    # to tell the wrapper from a bare `command -v` on a host that does not
    # ship caddy — and every host in CI and in the container is such a host.
    # Without this the difference is invisible until it is invisible in the
    # wrong direction, which is how ubuntu-latest went red.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    local c
    for c in caddy openresty lighttpd traefik haproxy; do
        _vpssec_absent_command "$c"
    done
    _vpssec_stub caddy 0

    run _webapp_other_webserver

    # Only caddy is asserted about — the others are declared absent so the
    # host cannot contribute, but the claim under test is narrow: a binary the
    # wrapper says is absent must not appear, however loudly `command -v`
    # answers.
    [[ "$output" != *caddy* ]]
}

# ==============================================================================
# baseline: profiles switched off appear in neither count
# ==============================================================================

_load_baseline() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/baseline.sh"
    BASELINE_APPARMOR_DISABLE_DIR="$etc/apparmor.d/disable"
    # The check is gated on AppArmor being installed at all.
    _vpssec_stub aa-status 0
}

@test "baseline: disabled profiles are reported, by name" {
    _load_baseline
    mkdir -p "$BASELINE_APPARMOR_DISABLE_DIR" "$etc/apparmor.d"
    ln -sf "$etc/apparmor.d/usr.sbin.sshd" "$BASELINE_APPARMOR_DISABLE_DIR/usr.sbin.sshd"
    ln -sf "$etc/apparmor.d/usr.bin.man" "$BASELINE_APPARMOR_DISABLE_DIR/usr.bin.man"

    run _baseline_audit_apparmor_disabled_profiles

    [ "$(_check_field baseline.apparmor_profiles_disabled status)" = "failed" ]
    local desc
    desc=$(_check_field baseline.apparmor_profiles_disabled desc)
    [[ "$desc" == *"usr.sbin.sshd"* ]]
    [[ "$desc" == *"usr.bin.man"* ]]
}

@test "baseline: an absent disable directory emits nothing" {
    _load_baseline

    run _baseline_audit_apparmor_disabled_profiles

    [ "$status" -eq 0 ]
    _vpssec_refute test -s "$VPSSEC_STATE/checks.json"
}

@test "baseline: an empty disable directory emits nothing" {
    _load_baseline
    mkdir -p "$BASELINE_APPARMOR_DISABLE_DIR"

    run _baseline_audit_apparmor_disabled_profiles

    _vpssec_refute test -s "$VPSSEC_STATE/checks.json"
}

@test "baseline: a dotfile in the disable directory is not a disabled profile" {
    _load_baseline
    mkdir -p "$BASELINE_APPARMOR_DISABLE_DIR"
    : > "$BASELINE_APPARMOR_DISABLE_DIR/.keep"

    run _baseline_apparmor_disabled_profiles

    [ -z "$output" ]
}

# ==============================================================================
# supported-OS gate: derivatives of the project's own main platform
# ==============================================================================

@test "supported OS: a Debian derivative is accepted by family" {
    detect_os() { echo "linuxmint"; }
    detect_os_version() { echo "21.3"; }
    VPSSEC_DISTRO_FAMILY="debian"

    run is_supported_os

    [ "$status" -eq 0 ]
}

@test "supported OS: an unknown family is still rejected" {
    detect_os() { echo "plan9"; }
    detect_os_version() { echo "4"; }
    VPSSEC_DISTRO_FAMILY="unknown"

    run is_supported_os

    [ "$status" -ne 0 ]
}

@test "supported OS: accepting the derivative does not widen fix mode" {
    # The audit runs on Mint; guide must still refuse, because is_debian_based
    # is an ID allowlist and rolling fixes out to derivatives is a separate
    # decision. Pinned so widening one does not silently widen the other.
    detect_os() { echo "linuxmint"; }
    VPSSEC_DISTRO_FAMILY="debian"

    run is_debian_based

    [ "$status" -ne 0 ]
}
