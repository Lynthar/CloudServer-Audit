#!/usr/bin/env bats
#
# execute_fix must not record a completion a fix cannot deliver.
#
# A fix's exit status carries one fact — did my work succeed. Whether the
# FINDING is resolved is a second fact, and for the template generators it
# never can be: they write a template, or a file the operator still has to
# wire in. Two opposite conventions had grown around that single exit code,
# each defensible on its own:
#
#   - four FIX_SAFE generators returned 0, so state_mark_fix_complete wrote a
#     line into ok.json that the very next audit contradicted; and
#   - webapp's SSL fix returned 1 to avoid exactly that, and so reported a
#     FAILURE for a snippet it had written perfectly well.
#
# FIX_TEMPLATE_ONLY holds the second fact separately. These tests pin the
# behaviour that follows from it, in both directions — a map that only ever
# suppressed the record would be indistinguishable from one that suppressed
# every record.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    state_init
}

# A fix function the engine will dispatch to, whose outcome the test picks.
# Named for a real module so `${fix_id%%.*}` resolves, and defined here rather
# than sourced so no module's own behaviour leaks into the assertion.
_install_fake_fix() {
    local module="$1" rc="${2:-0}"
    eval "${module}_fix() { return $rc; }"
}

_completed_fixes() {
    jq -r '.completed_fixes[]?.fix_id // .completed_fixes[]? // empty' \
        "$VPSSEC_STATE/ok.json" 2>/dev/null
}

# ==============================================================================
# The template-only path
# ==============================================================================

@test "a template-only fix that succeeds is NOT recorded as complete" {
    _install_fake_fix docker 0
    run execute_fix docker.generate_proxy_template true
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'docker.generate_proxy_template' <<<"$(_completed_fixes)"
}

@test "it still reports success, because the work did succeed" {
    # The webapp convention's cost was exactly this: a fix that wrote its file
    # correctly showed up in the guide summary as a failure.
    _install_fake_fix webapp 0
    run execute_fix webapp.nginx_ssl_protocols true
    [ "$status" -eq 0 ]
}

@test "it tells the operator what is still outstanding" {
    _install_fake_fix docker 0
    run execute_fix docker.generate_proxy_template true
    [ "$status" -eq 0 ]
    [[ "$output" == *"does not resolve the finding"* ]]
    [[ "$output" == *"ports stay exposed"* ]]
}

@test "a template-only fix that FAILS is neither recorded nor called successful" {
    _install_fake_fix docker 1
    run execute_fix docker.generate_proxy_template true
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q 'docker.generate_proxy_template' <<<"$(_completed_fixes)"
}

# ==============================================================================
# The ordinary path must be untouched
# ==============================================================================

@test "an ordinary fix that succeeds IS still recorded as complete" {
    # The other direction. Without this, suppressing every completion record
    # would pass every test above.
    _install_fake_fix ufw 0
    run execute_fix ufw.allow_ssh true
    [ "$status" -eq 0 ]
    grep -q 'ufw.allow_ssh' <<<"$(_completed_fixes)"
}

@test "an ordinary fix does not print a manual-step notice" {
    _install_fake_fix ufw 0
    run execute_fix ufw.allow_ssh true
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'does not resolve the finding' <<<"$output"
}

# ==============================================================================
# The predicates the engine and the report both read
# ==============================================================================

@test "fix_is_template_only answers for both safety classes it spans" {
    # It is orthogonal to safety, not a fifth class: the generators are
    # FIX_SAFE, webapp's SSL pair and HSTS are FIX_CONFIRM/FIX_RISKY. A lookup
    # that assumed one class would silently miss the other half.
    run fix_is_template_only docker.generate_proxy_template
    [ "$status" -eq 0 ]
    run fix_is_template_only webapp.nginx_ssl_ciphers
    [ "$status" -eq 0 ]
    run fix_is_template_only ufw.allow_ssh
    [ "$status" -ne 0 ]
}

@test "the HSTS template fix is in the map too" {
    # Found by a sweep rather than by reading: `return 1` within three lines
    # after a print_ok/print_warn (not a print_error) turned up 20 candidates,
    # 19 of them legitimate refusals and this one the same family as the SSL
    # snippets. Leaving it out would have kept half the inconsistency item 9
    # named.
    run fix_is_template_only webapp.nginx_hsts
    [ "$status" -eq 0 ]

    _install_fake_fix webapp 0
    run execute_fix webapp.nginx_hsts true
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'webapp.nginx_hsts' <<<"$(_completed_fixes)"
}

@test "a fix whose manual step is conditional is NOT in the map" {
    # The key is a fix_id, so membership claims the fix can NEVER resolve its
    # finding. baseline's SELinux fix leaves a manual step only on a host with
    # no config file to persist to — dynamic, so it keeps returning 1 on that
    # branch instead. Putting it here would suppress the completion record on
    # the hosts where it genuinely succeeded.
    run fix_is_template_only baseline.selinux_set_enforcing
    [ "$status" -ne 0 ]
}

@test "get_fix_manual_step prefers the translation over the map's English" {
    VPSSEC_I18N["fixtmpl.docker.generate_proxy_template"]="TRANSLATED STEP"
    run get_fix_manual_step docker.generate_proxy_template
    [ "$output" = "TRANSLATED STEP" ]
}

@test "get_fix_manual_step falls back to the map, never to the key" {
    # The fallback is why a missing key degrades to a readable sentence instead
    # of printing 'fixtmpl.docker.generate_proxy_template' at the moment the
    # operator is deciding whether the work is finished.
    unset 'VPSSEC_I18N[fixtmpl.docker.generate_proxy_template]'
    run get_fix_manual_step docker.generate_proxy_template
    [[ "$output" == *"reverse-proxy template"* ]]
    _vpssec_refute grep -q 'fixtmpl\.' <<<"$output"
}

@test "get_fix_manual_step says nothing for a fix that is not template-only" {
    run get_fix_manual_step ufw.allow_ssh
    [ "$output" = "" ]
}

@test "get_fix_manual_step ignores a stray fixtmpl key for a fix not in the map" {
    # The map is the authority on which fixes leave a manual step; the i18n
    # file only supplies wording. Without the early return the lookup would run
    # for any fix_id, so a leftover or mistyped fixtmpl.* key would make an
    # ordinary fix announce a manual step that does not exist.
    #
    # This input is the ONLY thing that separates the guard from its absence:
    # with no such key both paths echo an empty string, which is why the
    # mutation removing the guard survived the assertion above.
    VPSSEC_I18N["fixtmpl.ufw.allow_ssh"]="SHOULD NOT BE SHOWN"
    run get_fix_manual_step ufw.allow_ssh
    [ "$output" = "" ]
}

@test "fix_template_only_ids_json emits one JSON array of the keys" {
    # The reporting layer passes this in as --argjson so the membership test
    # happens inside its existing jq program — one jq per document, never one
    # per check.
    run fix_template_only_ids_json
    [ "$status" -eq 0 ]
    jq -e 'type == "array"' <<<"$output"
    jq -e 'index("docker.generate_proxy_template") != null' <<<"$output"
    jq -e 'index("ufw.allow_ssh") == null' <<<"$output"
}

# ==============================================================================
# What the reports say
# ==============================================================================

@test "the JSON report marks a template-only finding and leaves the rest alone" {
    state_add_check "$(create_check_json \
        "docker.exposed_ports" "docker" "medium" "failed" \
        "Exposed ports" "Ports are published to 0.0.0.0" \
        "Use a reverse proxy" "docker.generate_proxy_template")"
    state_add_check "$(create_check_json \
        "ufw.disabled" "ufw" "medium" "failed" \
        "Firewall disabled" "ufw is installed but inactive" \
        "Enable ufw" "ufw.enable")"

    run report_generate_json "$BATS_TEST_TMPDIR/summary.json"
    [ "$status" -eq 0 ]

    jq -e '.checks[] | select(.id=="docker.exposed_ports") | .fix_type == "template_only"' \
        "$BATS_TEST_TMPDIR/summary.json"
    # Absence from the map is not evidence a fix is direct, so nothing is
    # stamped on the others.
    jq -e '.checks[] | select(.id=="ufw.disabled") | has("fix_type") | not' \
        "$BATS_TEST_TMPDIR/summary.json"
}

@test "the SARIF rule carries the same fact" {
    state_add_check "$(create_check_json \
        "docker.exposed_ports" "docker" "medium" "failed" \
        "Exposed ports" "Ports are published to 0.0.0.0" \
        "Use a reverse proxy" "docker.generate_proxy_template")"

    run report_generate_sarif "$BATS_TEST_TMPDIR/summary.sarif"
    [ "$status" -eq 0 ]
    jq -e '.runs[0].tool.driver.rules[]
           | select(.id=="docker.exposed_ports")
           | .properties.fixType == "template_only"' \
        "$BATS_TEST_TMPDIR/summary.sarif"
}

@test "the Markdown report annotates the Fix ID line" {
    # The human-facing report is where it matters most: without the note it
    # reads as though running every listed Fix ID makes the finding go away.
    state_add_check "$(create_check_json \
        "docker.exposed_ports" "docker" "medium" "failed" \
        "Exposed ports" "Ports are published to 0.0.0.0" \
        "Use a reverse proxy" "docker.generate_proxy_template")"

    run report_generate_markdown "$BATS_TEST_TMPDIR/summary.md"
    [ "$status" -eq 0 ]
    grep -q 'docker.generate_proxy_template' "$BATS_TEST_TMPDIR/summary.md"
    grep -q 'Template only' "$BATS_TEST_TMPDIR/summary.md"
}

@test "the Markdown report leaves an ordinary Fix ID unannotated" {
    state_add_check "$(create_check_json \
        "ufw.disabled" "ufw" "medium" "failed" \
        "Firewall disabled" "ufw is installed but inactive" \
        "Enable ufw" "ufw.enable")"

    run report_generate_markdown "$BATS_TEST_TMPDIR/summary.md"
    [ "$status" -eq 0 ]
    grep -q 'ufw.enable' "$BATS_TEST_TMPDIR/summary.md"
    _vpssec_refute grep -q 'Template only' "$BATS_TEST_TMPDIR/summary.md"
}
