#!/usr/bin/env bats
# Where the cloudflared audit looks for a tunnel's configuration: cloudflared's
# own file names and directories, and no local file at all for a tunnel run
# from a token, whose ingress lives in the Cloudflare dashboard.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"
    CLOUDFLARED_CONFIG_DIRS=("$BATS_TEST_TMPDIR/etc" "$BATS_TEST_TMPDIR/usr-local")
    # No user homes, no units, no processes unless a test says so.
    _vpssec_stub getent 0
    _vpssec_stub systemctl 1
    _vpssec_stub pgrep 1
}

_ids() { jq -r '[.[].id] | join(",")' "$VPSSEC_STATE/checks.json"; }

_clean_config() {
    mkdir -p "${1%/*}"
    printf 'tunnel: abc\noriginRequest:\n  noTLSVerify: false\ningress:\n  - service: http_status:404\n' > "$1"
}

@test "config: a tunnel installed from a token is not reported as missing a config" {
    # What `cloudflared service install <token>` leaves: the token in a file.
    _vpssec_stub_script systemctl <<'SH'
[[ "$1" == cat ]] || exit 3
printf '%s\n' '# /etc/systemd/system/cloudflared.service' '[Service]' \
    'ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token'
SH
    _cloudflared_audit_config
    [ "$(_ids)" = "cloudflared.config_remote" ]
    run jq -r '.[0] | "\(.status) \(.severity)"' "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed info" ]
}

@test "config: a token on a running process counts, and never reaches the report" {
    _vpssec_stub pgrep 0 "4242 cloudflared tunnel run --token eyJTOKENCANARY"
    _cloudflared_audit_config
    [ "$(_ids)" = "cloudflared.config_remote" ]
    _vpssec_refute grep -q TOKENCANARY "$VPSSEC_STATE/checks.json"
}

@test "config: a token tunnel's local file is not graded either" {
    # Its ingress comes from the dashboard, so a local file's gaps are not the
    # tunnel's.
    mkdir -p "$BATS_TEST_TMPDIR/etc"
    printf 'tunnel: abc\n' > "$BATS_TEST_TMPDIR/etc/config.yml"
    _vpssec_stub pgrep 0 "4242 cloudflared tunnel run --token x"
    _cloudflared_audit_config
    [ "$(_ids)" = "cloudflared.config_remote" ]
}

@test "config: config.yaml under /usr/local/etc/cloudflared is found" {
    _clean_config "$BATS_TEST_TMPDIR/usr-local/config.yaml"
    _cloudflared_audit_config
    [ "$(_ids)" = "cloudflared.config_ok" ]
}

@test "config: another YAML in the system directory is audited, not ignored" {
    # A named tunnel run with --config /etc/cloudflared/<name>.yml.
    mkdir -p "$BATS_TEST_TMPDIR/etc"
    printf 'tunnel: abc\n' > "$BATS_TEST_TMPDIR/etc/web.yml"
    _cloudflared_audit_config
    [ "$(_ids)" = "cloudflared.config_issues" ]
}

@test "config: neither a config nor a token is still no_config" {
    _cloudflared_audit_config
    [ "$(_ids)" = "cloudflared.no_config" ]
}
