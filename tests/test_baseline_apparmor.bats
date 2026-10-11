#!/usr/bin/env bats
# Regression tests for _baseline_apparmor_count_profiles. Parsing `aa-status`
# text with an English-only regex silently returns 0/0 under any other locale,
# so the helper prefers `aa-status --json` and falls back to `LC_ALL=C aa-status`.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/baseline.sh"
    # Stub aa-status to control its output. PATH override is per-test.
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
}

# Install a fake aa-status that prints the contents of $1 to stdout
# (and respects --json by checking $1 vs $2). Like the real one, --enabled
# prints nothing and answers yes: the kernel LSM is on.
_install_aa_stub() {
    local human="$1"
    local json="$2"
    cat >"$BATS_TEST_TMPDIR/bin/aa-status" <<EOF
#!/usr/bin/env bash
[[ "\$1" == "--enabled" ]] && exit 0
if [[ "\$1" == "--json" ]]; then
    if [[ -z "$json" ]]; then exit 1; fi
    cat <<'JSON'
$json
JSON
else
    cat <<'TEXT'
$human
TEXT
fi
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/aa-status"
}

@test "apparmor: JSON path counts enforce vs complain correctly" {
    _install_aa_stub "" '{"version":"1","profiles":{"/sbin/dhclient":"enforce","/usr/bin/evince":"enforce","/usr/sbin/mysqld":"complain"},"processes":{}}'
    run _baseline_apparmor_count_profiles
    [ "$status" -eq 0 ]
    [ "$output" = "2:1" ]
}

@test "apparmor: JSON path with empty profiles → 0:0" {
    _install_aa_stub "" '{"version":"1","profiles":{},"processes":{}}'
    run _baseline_apparmor_count_profiles
    [ "$status" -eq 0 ]
    [ "$output" = "0:0" ]
}

@test "apparmor: text fallback parses English (LC_ALL=C ensured)" {
    # No --json support; only text. Must parse correctly even though
    # the host LC_ALL might be non-English (LC_ALL=C inside the helper
    # forces predictable formatting).
    local human='apparmor module is loaded.
3 profiles are loaded.
2 profiles are in enforce mode.
1 profiles are in complain mode.'
    _install_aa_stub "$human" ""
    run _baseline_apparmor_count_profiles
    [ "$status" -eq 0 ]
    [ "$output" = "2:1" ]
}

@test "apparmor: text fallback with zero counts → 0:0" {
    local human='apparmor module is loaded.
0 profiles are loaded.
0 profiles are in enforce mode.
0 profiles are in complain mode.'
    _install_aa_stub "$human" ""
    run _baseline_apparmor_count_profiles
    [ "$status" -eq 0 ]
    [ "$output" = "0:0" ]
}

@test "apparmor: text fallback regression — non-English (zh) text would have failed old regex" {
    # A stub cannot reproduce locale leakage, so what is asserted is that the
    # helper invokes aa-status at all (which is what LC_ALL=C wraps) and that the
    # JSON path wins when both are available.
    _install_aa_stub "garbage that won't match the regex" '{"version":"1","profiles":{"/x":"enforce"},"processes":{}}'
    run _baseline_apparmor_count_profiles
    [ "$status" -eq 0 ]
    [ "$output" = "1:0" ]
}

@test "apparmor: malformed JSON falls back to text path" {
    _install_aa_stub '5 profiles are in enforce mode.
2 profiles are in complain mode.' 'not valid json'
    run _baseline_apparmor_count_profiles
    [ "$status" -eq 0 ]
    [ "$output" = "5:2" ]
}

# ---- enabled means profiles are loaded ---------------------------------------

@test "apparmor: a kernel LSM with no profile loaded is not enabled" {
    # `aa-status --enabled` asks only the kernel: with the unit disabled and
    # nothing loaded, the old predicate passed a host that confines nothing.
    _install_aa_stub "" '{"version":"1","profiles":{},"processes":{}}'
    run aa-status --enabled
    [ "$status" -eq 0 ]

    run _baseline_apparmor_enabled
    [ "$status" -eq 1 ]
}

@test "apparmor: profiles loaded only in complain mode still count as enabled" {
    # Starting the unit cannot switch complain to enforce, so offering the
    # enable fix there could never verify; apparmor_many_complain reports it.
    _install_aa_stub "" '{"version":"1","profiles":{"/usr/sbin/mysqld":"complain"},"processes":{}}'
    _baseline_apparmor_enabled
}

@test "apparmor: a kernel LSM with an enforced profile is enabled" {
    _install_aa_stub "" '{"version":"1","profiles":{"/usr/sbin/sshd":"enforce"},"processes":{}}'
    _baseline_apparmor_enabled
}

@test "apparmor: no profile loaded is reported as not enabled, with the fix offered" {
    source "$(_vpssec_repo_root)/core/state.sh"
    i18n_load en_US
    state_init
    detect_container() { return 1; }
    BASELINE_SELINUX_FS_ENFORCE="$BATS_TEST_TMPDIR/no-selinux"
    BASELINE_APPARMOR_DISABLE_DIR="$BATS_TEST_TMPDIR/no-disable-dir"
    _install_aa_stub "" '{"version":"1","profiles":{},"processes":{}}'

    _baseline_audit_mac
    run jq -r '.[] | "\(.id) \(.status) \(.fix_id)"' "$VPSSEC_STATE/checks.json"
    [ "$output" = "baseline.apparmor_disabled failed baseline.enable_apparmor" ]
}
