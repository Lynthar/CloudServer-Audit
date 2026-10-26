#!/usr/bin/env bats
# The audit must not describe a host it did not look at. Nothing gates this
# automatically — i18n parity only checks that keys exist and bats only checks
# which branch ran — so every assertion here is about the emitted check.

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

# A user `dev` whose home holds a rootless Docker socket, and neither docker
# nor podman on root's PATH.
_rootless_docker_only() {
    # A real socket, not a regular file: the predicate tests -S, and a plain file
    # would let it pass while the production check stayed broken. Short root on
    # purpose — an AF_UNIX path is capped near 104 bytes.
    local sock_root
    sock_root=$(mktemp -d "${TMPDIR:-/tmp}/vpsk.XXXXXX")
    sock_root=$(cd "$sock_root" && pwd -P)
    local sock_dir="$sock_root/h/.docker/run"
    mkdir -p "$sock_dir"
    # Two reasons to skip, kept apart on purpose: one message blaming AF_UNIX for
    # a missing interpreter sends the reader looking at sockets and path lengths.
    # A skip that names the wrong cause is worse than a failure.
    command -v python3 >/dev/null 2>&1 || skip "python3 is needed to create the test socket"
    python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" \
        "$sock_dir/docker.sock" || skip "cannot create an AF_UNIX socket here"
    _vpssec_absent_command docker
    _vpssec_absent_command podman
    _vpssec_stub_script getent <<SH
printf 'dev:x:1000:1000::%s:/bin/bash\n' "$sock_root/h"
SH
}

@test "docker: a rootless socket under a user's runtime dir is found" {
    _load_docker
    _rootless_docker_only

    # Called directly, NOT through `run`: `run` disables errexit, and the
    # defect this pins is a non-zero status mid-function aborting the scan
    # before it reaches the socket. Under `run` the broken version passed.
    local out
    out=$(_docker_unaudited_runtime)

    [[ "$out" == *"rootless-docker"* ]]
}

@test "docker: rootless Docker that root's PATH cannot see is unreachable, not absent" {
    # The whole run, engine included: the module's own probe is what tells
    # the two apart, so a gate in front of it decides the answer.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/security_levels.sh"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/engine.sh"
    _rootless_docker_only
    VPSSEC_MODULE_ORDER=(docker)

    module_load_all "" ""
    _run_audit_pass >/dev/null

    [[ "$(_emitted_ids)" == *"docker.daemon_unreachable"* ]]
    [[ "$(_check_field docker.daemon_unreachable desc)" == *"rootless-docker"* ]]
    _vpssec_refute grep -q 'docker.not_installed' "$VPSSEC_STATE/checks.json"
}

@test "docker: through the engine, a host with no runtime still reports not installed" {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/security_levels.sh"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/engine.sh"
    _vpssec_absent_command docker
    _vpssec_absent_command podman
    _vpssec_stub getent 0 ""
    VPSSEC_MODULE_ORDER=(docker)

    module_load_all "" ""
    _run_audit_pass >/dev/null

    [ "$(_check_field docker.not_installed status)" = "passed" ]
    _vpssec_refute grep -q 'docker.daemon_unreachable' "$VPSSEC_STATE/checks.json"
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
    # Absence has to be asserted, not inherited: whether this host ships caddy is
    # a property of the runner, and a test that depends on it passes in one
    # environment and fails in another.
    run _webapp_other_webserver
    [ "$status" -eq 0 ]

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
    _vpssec_absent_command nginx
    _vpssec_stub caddy 0

    run webapp_audit

    [[ "$(_emitted_ids)" == *"webapp.other_webserver"* ]]
    _vpssec_refute grep -q 'webapp.no_webserver' "$VPSSEC_STATE/checks.json"
    # info, so a host is not penalised for a gap in vpssec's coverage.
    [ "$(_check_field webapp.other_webserver status)" = "failed" ]
}

# webapp_audit on a host with nothing but what the test plants.
_webapp_bare_host() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    NGINX_CONF="$etc/nginx/nginx.conf"
    APACHE_CONF="$etc/apache2/apache2.conf"
    APACHE_CONF_ALT="$etc/httpd/conf/httpd.conf"
    WEB_ROOTS=("$etc/www")
    _vpssec_absent_command nginx
    _webapp_php_installed() { return 1; }
    _webapp_other_webserver() { :; }
    _vpssec_stub pgrep 1
}

@test "webapp: no web root at all is no sensitive-files pass" {
    # Scanning nothing found nothing, and the pass is scored (required).
    _webapp_bare_host
    run webapp_audit
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'webapp.sensitive_files_ok' "$VPSSEC_STATE/checks.json"
}

@test "webapp: an empty web root that was scanned still passes" {
    _webapp_bare_host
    mkdir -p "$etc/www"
    run webapp_audit
    [[ "$(_emitted_ids)" == *"webapp.sensitive_files_ok"* ]]
}

@test "webapp: a page that only discloses information is medium, not high" {
    # Matched by name alone: an info.php that only echoes was reported high.
    _webapp_bare_host
    mkdir -p "$etc/www/app"
    printf '<?php echo "ok";\n' > "$etc/www/app/info.php"
    : > "$etc/www/app/.DS_Store"
    run webapp_audit
    [ "$(_check_field webapp.sensitive_files severity)" = "medium" ]
}

@test "webapp: one file holding secrets keeps the finding high" {
    _webapp_bare_host
    mkdir -p "$etc/www/app"
    printf '<?php echo "ok";\n' > "$etc/www/app/info.php"
    printf 'DB_PASSWORD=x\n' > "$etc/www/app/.env"
    run webapp_audit
    [ "$(_check_field webapp.sensitive_files severity)" = "high" ]
    [[ "$(_check_field webapp.sensitive_files desc)" == *"/app/.env"* ]]
}

@test "webapp: an nginx running from outside PATH is named, not 'no web server'" {
    # A source build in /usr/local/nginx/sbin: sudo's secure_path lacks it.
    _webapp_bare_host
    _vpssec_stub pgrep 0
    run webapp_audit
    [[ "$(_emitted_ids)" == *"webapp.nginx_not_on_path"* ]]
    _vpssec_refute grep -q 'webapp.no_webserver' "$VPSSEC_STATE/checks.json"
    [ "$(_check_field webapp.nginx_not_on_path status)" = "failed" ]
    _vpssec_stub_called pgrep '-x nginx'
}

@test "webapp: no nginx binary and no nginx process is still no web server" {
    _webapp_bare_host
    run webapp_audit
    [[ "$(_emitted_ids)" == *"webapp.no_webserver"* ]]
    _vpssec_refute grep -q 'webapp.nginx_not_on_path' "$VPSSEC_STATE/checks.json"
}

@test "webapp: detection goes through the project's own command wrapper" {
    # Stub caddy so `command -v caddy` succeeds while check_command reports it
    # absent: the two answers differing is the only way to tell the project's own
    # wrapper from a bare `command -v` on a host that does not ship caddy.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    local c
    for c in caddy openresty lighttpd traefik haproxy; do
        _vpssec_absent_command "$c"
    done
    _vpssec_stub caddy 0

    run _webapp_other_webserver
    [ "$status" -eq 0 ]

    # Only caddy is asserted about — the others are declared absent so the host
    # cannot contribute. The claim is narrow: a binary the wrapper calls absent
    # must not appear, however loudly `command -v` answers.
    [[ "$output" != *caddy* ]]
}

@test "webapp: the Apache advice names the file that sets the directive on this host" {
    # A RHEL httpd host was told to edit apache2.conf, which it does not have.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    NGINX_CONF="$etc/nginx/nginx.conf"
    APACHE_CONF="$etc/apache2/apache2.conf"
    APACHE_CONF_ALT="$etc/httpd/conf/httpd.conf"
    APACHE_CONF_DIRS="$etc/httpd/conf.d"
    mkdir -p "${APACHE_CONF_ALT%/*}"
    printf 'ServerRoot "/etc/httpd"\n' > "$APACHE_CONF_ALT"
    _vpssec_absent_command nginx
    _vpssec_stub httpd 0

    run webapp_audit
    [[ "$(_check_field webapp.apache_server_signature suggestion)" == *" $APACHE_CONF_ALT"* ]]
    [ "$(_check_field webapp.apache_server_signature suggestion)" = \
        "$(i18n 'webapp.set_signature_off' "conf=$APACHE_CONF_ALT")" ]

    # An included file read later overrides the main one, so it is the one
    # to edit; a directive set nowhere goes in the main file.
    printf 'ServerTokens Full\n' >> "$APACHE_CONF_ALT"
    mkdir -p "$APACHE_CONF_DIRS"
    printf 'ServerTokens OS\n' > "$APACHE_CONF_DIRS/security.conf"
    state_init
    run webapp_audit
    [ "$(_check_field webapp.apache_server_tokens suggestion)" = \
        "$(i18n 'webapp.set_tokens_prod' "conf=$APACHE_CONF_DIRS/security.conf")" ]
    [ "$(_check_field webapp.apache_server_signature suggestion)" = \
        "$(i18n 'webapp.set_signature_off' "conf=$APACHE_CONF_ALT")" ]
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
    [ "$status" -eq 0 ]

    _vpssec_refute test -s "$VPSSEC_STATE/checks.json"
}

@test "baseline: a dotfile in the disable directory is not a disabled profile" {
    _load_baseline
    mkdir -p "$BASELINE_APPARMOR_DISABLE_DIR"
    : > "$BASELINE_APPARMOR_DISABLE_DIR/.keep"

    run _baseline_apparmor_disabled_profiles
    [ "$status" -eq 0 ]

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
