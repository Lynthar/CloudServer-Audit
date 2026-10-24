#!/usr/bin/env bats
# A report has to say which host it describes, including what vpssec could not
# have done there: the audit runs on Debian, RHEL and Arch, but hardening and
# rollback refuse anywhere but Debian and Ubuntu, and every format must say so.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh core/report.sh
    i18n_load en_US
    state_init

    # One failed check with a fix, so the "the fixes it lists are unreachable"
    # case is actually represented in the reports under test.
    state_add_check "$(create_check_json \
        "ufw.disabled" "ufw" "medium" "failed" \
        "Firewall disabled" "ufw is installed but inactive" \
        "Enable ufw" "ufw.enable")"
}

# The reports read the family from the global and the gate from
# is_debian_based, so a test picks its host by setting both.
_on_debian() {
    VPSSEC_DISTRO_FAMILY=debian
    is_debian_based() { return 0; }
}

_on_rocky() {
    VPSSEC_DISTRO_FAMILY=rhel
    is_debian_based() { return 1; }
}

# ==============================================================================
# summary.json
# ==============================================================================

@test "json: a Debian host reports its family and that guide is available" {
    _on_debian
    run report_generate_json "$BATS_TEST_TMPDIR/summary.json"
    [ "$status" -eq 0 ]

    jq -e '.meta.distro_family == "debian"' "$BATS_TEST_TMPDIR/summary.json"
    jq -e '.meta.guide_supported == true' "$BATS_TEST_TMPDIR/summary.json"
}

@test "json: a RHEL host reports that guide is not available" {
    _on_rocky
    run report_generate_json "$BATS_TEST_TMPDIR/summary.json"
    [ "$status" -eq 0 ]

    jq -e '.meta.distro_family == "rhel"' "$BATS_TEST_TMPDIR/summary.json"
    jq -e '.meta.guide_supported == false' "$BATS_TEST_TMPDIR/summary.json"
    # The point of the field: the document still offers a fix_id.
    jq -e '[.checks[] | select(.fix_id != "")] | length > 0' \
        "$BATS_TEST_TMPDIR/summary.json"
}

@test "json: guide_supported is a boolean, not the string \"false\"" {
    # It arrives through --argjson. As --arg it would be "false", which is
    # truthy in every consumer that checks it.
    _on_rocky
    run report_generate_json "$BATS_TEST_TMPDIR/summary.json"
    jq -e '.meta.guide_supported | type == "boolean"' "$BATS_TEST_TMPDIR/summary.json"
}

@test "json: an undetected family says unknown rather than nothing" {
    _on_rocky
    VPSSEC_DISTRO_FAMILY=""
    run report_generate_json "$BATS_TEST_TMPDIR/summary.json"
    jq -e '.meta.distro_family == "unknown"' "$BATS_TEST_TMPDIR/summary.json"
}

# ==============================================================================
# summary.sarif
# ==============================================================================

@test "sarif: the run carries the same two facts" {
    _on_rocky
    run report_generate_sarif "$BATS_TEST_TMPDIR/summary.sarif"
    [ "$status" -eq 0 ]

    jq -e '.runs[0].properties.distroFamily == "rhel"' "$BATS_TEST_TMPDIR/summary.sarif"
    jq -e '.runs[0].properties.guideSupported == false' "$BATS_TEST_TMPDIR/summary.sarif"
}

@test "sarif: it stays valid SARIF" {
    _on_debian
    run report_generate_sarif "$BATS_TEST_TMPDIR/summary.sarif"
    [ "$status" -eq 0 ]

    # The properties bag hangs off the run, beside tool/results/invocations —
    # not inside the tool driver, where it would not be a run property.
    jq -e '.runs[0] | has("tool") and has("results") and has("properties")' \
        "$BATS_TEST_TMPDIR/summary.sarif"
    jq -e '.version == "2.1.0"' "$BATS_TEST_TMPDIR/summary.sarif"
}

# ==============================================================================
# summary.md — the one a human reads
# ==============================================================================

@test "markdown: the hardening row states availability on both kinds of host" {
    # Stated either way on purpose. A row that appeared only when hardening
    # was unavailable would make its absence mean "available", and absence is
    # not evidence.
    _on_debian
    run report_generate_markdown "$BATS_TEST_TMPDIR/debian.md"
    [ "$status" -eq 0 ]
    grep -qE '^\| Distro Family \| debian \|' "$BATS_TEST_TMPDIR/debian.md"
    grep -qE '^\| Hardening \| available' "$BATS_TEST_TMPDIR/debian.md"

    _on_rocky
    run report_generate_markdown "$BATS_TEST_TMPDIR/rocky.md"
    [ "$status" -eq 0 ]
    grep -qE '^\| Distro Family \| rhel \|' "$BATS_TEST_TMPDIR/rocky.md"
    grep -qE '^\| Hardening \| not available' "$BATS_TEST_TMPDIR/rocky.md"
}

@test "markdown: the host table labels come from i18n too" {
    i18n_load zh_CN
    _on_debian
    run report_generate_markdown "$BATS_TEST_TMPDIR/zh.md"
    [ "$status" -eq 0 ]
    grep -qF "| $(i18n 'report.host_family') | debian |" "$BATS_TEST_TMPDIR/zh.md"
    _vpssec_refute grep -q 'Distro Family' "$BATS_TEST_TMPDIR/zh.md"
}

@test "markdown: the hardening wording comes from i18n, not the source" {
    _on_rocky
    i18n_load zh_CN
    run report_generate_markdown "$BATS_TEST_TMPDIR/zh.md"
    [ "$status" -eq 0 ]
    # Whatever zh_CN says, it must not be the English string or the raw key.
    local label
    label=$(i18n 'report.host_hardening')
    _vpssec_refute grep -qE "^\| $label \| (not available|report\.)" \
        "$BATS_TEST_TMPDIR/zh.md"
    grep -qE "^\| $label \| .+" "$BATS_TEST_TMPDIR/zh.md"
}

# ---- what the host runs on --------------------------------------------------
# systemd-detect-virt prints "none" AND exits 1 on bare metal; a fallback that
# ran on the exit status appended a second line to the report's field.

@test "json: a bare-metal host's virtualization is the one word none" {
    _vpssec_stub systemd-detect-virt 1 none
    run report_generate_json "$VPSSEC_REPORTS/summary.json"
    [ "$status" -eq 0 ]
    [ "$(jq -r '.meta.virtualization' "$VPSSEC_REPORTS/summary.json")" = "none" ]
}

@test "virtualization: a VM is named as the detector names it" {
    _vpssec_stub systemd-detect-virt 0 kvm
    [ "$(detect_virtualization)" = "kvm" ]
}

@test "virtualization: a detector that fails without an answer is unknown, not none" {
    _vpssec_stub systemd-detect-virt 1
    [ "$(detect_virtualization)" = "unknown" ]
}

# A /proc holding these directories, for detect_container.
_proc_with() {
    DETECT_PROC_DIR="$BATS_TEST_TMPDIR/proc"
    mkdir -p "$DETECT_PROC_DIR/1"
    local d
    for d in "$@"; do mkdir -p "$DETECT_PROC_DIR/$d"; done
}

@test "container: an OpenVZ container has /proc/vz without /proc/bc" {
    _proc_with vz
    [ "$(detect_container)" = "openvz" ]
}

@test "container: an OpenVZ host node, which has both, is not an OpenVZ container" {
    # systemd's rule. The node's own kernel parameters are its to set, and it
    # was told they belong to "the host".
    _proc_with vz bc
    [ "$(detect_container || true)" != "openvz" ]
}
