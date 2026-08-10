#!/usr/bin/env bats
#
# A report has to say which host it describes, including what vpssec could
# not have done there.
#
# The audit runs on Debian, the RHEL family and Arch; hardening and rollback
# refuse to run anywhere but Debian and Ubuntu. Nothing in any of the three
# report formats said so, and every failed check still carried a fix_id — so
# a summary.json produced on Rocky listed dozens of fixes that the tool would
# have declined to apply on that machine, with nothing to distinguish it from
# one produced on Debian.
#
# guide_supported is named after what is actually gated: guide_mode as a
# whole, on is_debian_based. Naming it fix_supported would have made it a lie
# the day any single fix grew a non-Debian path.

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

@test "markdown: the hardening wording comes from i18n, not the source" {
    _on_rocky
    i18n_load zh_CN
    run report_generate_markdown "$BATS_TEST_TMPDIR/zh.md"
    [ "$status" -eq 0 ]
    # Whatever zh_CN says, it must not be the English string or the raw key.
    _vpssec_refute grep -qE '^\| Hardening \| (not available|report\.)' \
        "$BATS_TEST_TMPDIR/zh.md"
    grep -qE '^\| Hardening \| .+' "$BATS_TEST_TMPDIR/zh.md"
}
