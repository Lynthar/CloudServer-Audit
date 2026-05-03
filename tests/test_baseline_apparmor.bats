#!/usr/bin/env bats
#
# Regression tests for _baseline_apparmor_count_profiles. Original code
# parsed `aa-status` text output with an English-only regex
# ("X profiles are in enforce mode"), which silently returns 0/0 on
# hosts running zh_CN.UTF-8 / de_DE.UTF-8 / etc. The new helper prefers
# `aa-status --json` (machine-readable, locale-immune) and falls back
# to `LC_ALL=C aa-status` so the human-text path is also locale-safe.

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
# (and respects --json by checking $1 vs $2).
_install_aa_stub() {
    local human="$1"
    local json="$2"
    cat >"$BATS_TEST_TMPDIR/bin/aa-status" <<EOF
#!/usr/bin/env bash
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
    # The original regex `^\s*[0-9]+ profiles are in enforce mode` only
    # matches English. With LC_ALL=C the stub still returns English
    # (because we pass it directly), but if the helper didn't apply
    # LC_ALL=C and the host locale was zh_CN, aa-status would emit
    # localized strings and the regex would silently return 0/0. This
    # test asserts the helper does invoke aa-status (so LC_ALL=C wraps
    # it) — we can't fully reproduce locale leakage in a stub, but we
    # verify the JSON-first path is preferred when both are available.
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
