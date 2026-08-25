#!/usr/bin/env bats
# Tests for calculate_score and get_check_stats in core/state.sh. The contract:
# base = 100 × passed / scored_total, penalty = 5×high + 1.5×medium + 0.25×low,
# score = clamp(0, 100, base − penalty); `info` checks stay out of scored_total.

load helpers

setup() {
    _vpssec_load core/security_levels.sh core/state.sh
}

# Write a checks.json from a list of (id, severity, status) tuples.
# Each tuple is one bash arg of the form "id|severity|status".
_write_checks() {
    local out="$VPSSEC_STATE/checks.json"
    : > "$out"
    local tuples=("$@")
    local jq_args=()
    local i=0
    local jq_filter='[]'
    for t in "${tuples[@]}"; do
        IFS='|' read -r id sev status <<< "$t"
        jq_args+=(--arg "id$i" "$id" --arg "sev$i" "$sev" --arg "st$i" "$status")
        jq_filter+=" + [{id: \$id$i, module: (\$id$i|split(\".\")[0]), severity: \$sev$i, status: \$st$i, title: \$id$i, desc: \"\", suggestion: \"\", fix_id: \"\"}]"
        # Pre-increment, not post: `((i++))` returns the OLD value as its exit
        # code, so at i==0 it exits 1 and set -e aborts.
        ((++i))
    done
    jq -n "${jq_args[@]}" "$jq_filter" > "$out"
    # Re-export so state.sh's STATE_CHECKS_FILE resolves correctly.
    export STATE_CHECKS_FILE="$out"
    # Invalidate the metrics memo. In production checks.json only grows,
    # so (mtime, size) is a sound cache key; a test that rewrites the
    # same path twice within one second can defeat it.
    _VPSSEC_METRICS_KEY=""
}

# ---- calculate_score: boundary cases --------------------------------

@test "calculate_score: no checks at all yields 100" {
    _write_checks
    run calculate_score
    [ "$output" = "100" ]
}

@test "calculate_score: all passed yields 100" {
    # Use 'required' category checks so they are scored.
    _write_checks \
        "ssh.password_auth_disabled|low|passed" \
        "ssh.root_login_disabled|low|passed" \
        "ufw.enabled|low|passed"
    run calculate_score
    [ "$output" = "100" ]
}

@test "calculate_score: 1 high failure on 3-check host" {
    # scored_total = 3, passed = 2, base = 66.
    # penalty = 5 (one high). score = 61.
    _write_checks \
        "ssh.password_auth_enabled|high|failed" \
        "ssh.root_login_disabled|low|passed" \
        "ufw.enabled|low|passed"
    run calculate_score
    [ "$output" = "61" ]
}

@test "calculate_score: 1 medium failure on 4-check host" {
    # scored = 4, passed = 3 → base = 75. penalty = 1.5; integer-
    # divided in 4× space: penalty_4x=6, penalty=1. score = 74.
    _write_checks \
        "ssh.password_auth_disabled|low|passed" \
        "ssh.root_login_disabled|low|passed" \
        "ufw.enabled|low|passed" \
        "fail2ban.service_inactive|medium|failed"
    run calculate_score
    [ "$output" = "74" ]
}

@test "calculate_score: info-category checks do not dilute" {
    # ssh.x11_forwarding_enabled is classified as 'info' and must stay out of
    # the scored_total denominator, or harmless info findings silently lower
    # the score on every host.
    _write_checks \
        "ssh.password_auth_disabled|low|passed" \
        "ssh.root_login_disabled|low|passed" \
        "ufw.enabled|low|passed" \
        "ssh.x11_forwarding_enabled|low|failed"   # info, ignored
    run calculate_score
    [ "$output" = "100" ]
}

@test "calculate_score: clamps to 0, never negative" {
    # 5 high failures × 8 penalty = 40, base = 0, score should be 0.
    _write_checks \
        "ssh.password_auth_enabled|high|failed" \
        "ssh.root_login_enabled|high|failed" \
        "ssh.empty_password_allowed|high|failed" \
        "users.uid0_found|high|failed" \
        "users.empty_password|high|failed"
    run calculate_score
    [ "$output" = "0" ]
}

@test "calculate_score: README example reproduces" {
    # 2 high + 1 medium failures on a 15-scored-check host with 12 safe; the
    # example shown in README.md / README.zh-CN.md. base = 100*12/15 = 80;
    # penalty = 5*2 + 1.5*1 = 11.5, integer-divided in 4× space → 11; score 69.
    local fails=(
        "ssh.password_auth_enabled|high|failed"
        "users.uid0_found|high|failed"
        "fail2ban.service_inactive|medium|failed"
    )
    local passes=(
        "ssh.root_login_disabled|low|passed"
        "ssh.pubkey_enabled|low|passed"
        "ssh.empty_password_denied|low|passed"
        "ssh.admin_user_exists|low|passed"
        "ufw.enabled|low|passed"
        "ufw.firewall_active|low|passed"
        "ufw.default_deny|low|passed"
        "ufw.ssh_allowed|low|passed"
        "kernel.aslr_full|low|passed"
        "kernel.network_params_ok|low|passed"
        "filesystem.sensitive_perms_ok|low|passed"
        "users.no_empty_password|low|passed"
    )
    _write_checks "${fails[@]}" "${passes[@]}"
    run calculate_score
    [ "$output" = "69" ]
}

# ---- get_check_stats -------------------------------------------------

@test "get_check_stats: counts by severity, info overlaps" {
    # Severity and category are orthogonal: `low` counts ALL failed low-severity
    # checks so the summary table matches the body listing, while `info` counts
    # info-category checks at any severity and does not touch the score.
    _write_checks \
        "ssh.password_auth_enabled|high|failed" \
        "fail2ban.service_inactive|medium|failed" \
        "ssh.x11_forwarding_enabled|low|failed" \
        "ssh.root_login_disabled|low|passed"

    run get_check_stats
    [ "$status" -eq 0 ]
    local high medium low passed info
    high=$(echo "$output" | jq '.high')
    medium=$(echo "$output" | jq '.medium')
    low=$(echo "$output" | jq '.low')
    passed=$(echo "$output" | jq '.passed')
    info=$(echo "$output" | jq '.info')
    [ "$high" = "1" ]
    [ "$medium" = "1" ]
    [ "$low" = "1" ]      # x11_forwarding flows into both low AND info
    [ "$passed" = "1" ]
    [ "$info" = "1" ]
}

@test "get_check_stats: exposes the score denominator" {
    # scored_total is what calculate_score actually divided by. Without it a
    # reader cannot tell "40/100 over 60 checks" from "40/100 over 3", which is
    # why a single-module run can print 0/100 on a nearly-clean host.
    _write_checks \
        "ssh.password_auth_enabled|high|failed" \
        "fail2ban.service_inactive|medium|failed" \
        "ssh.x11_forwarding_enabled|low|failed" \
        "ssh.root_login_disabled|low|passed"

    run get_check_stats
    [ "$status" -eq 0 ]
    [ "$(echo "$output" | jq '.total')" = "4" ]
    # x11_forwarding is info-category, so 3 of the 4 are scored.
    [ "$(echo "$output" | jq '.scored_total')" = "3" ]
}

# ---- score_is_partial ------------------------------------------------

@test "score_is_partial: false on a full run" {
    VPSSEC_INCLUDE="" VPSSEC_EXCLUDE=""
    run score_is_partial
    [ "$status" -ne 0 ]
}

@test "score_is_partial: true under --include" {
    VPSSEC_INCLUDE="ssh" VPSSEC_EXCLUDE=""
    run score_is_partial
    [ "$status" -eq 0 ]
}

@test "score_is_partial: true under --exclude" {
    # --exclude shrinks the denominator exactly like --include does, so
    # it has to mark the score partial too.
    VPSSEC_INCLUDE="" VPSSEC_EXCLUDE="malware"
    run score_is_partial
    [ "$status" -eq 0 ]
}

# ---- optional category / --strict ------------------------------------

@test "calculate_score: optional-category checks are inert by default" {
    # ssh.weak_algorithms is classified 'optional': reported, but it
    # must not move the score unless --strict was passed.
    _write_checks \
        "ssh.weak_algorithms|medium|failed" \
        "ssh.root_login_disabled|low|passed"
    run calculate_score
    [ "$output" = "100" ]
}

@test "calculate_score: --strict pulls optional checks into the score" {
    _write_checks \
        "ssh.weak_algorithms|medium|failed" \
        "ssh.root_login_disabled|low|passed"
    # scored = 2, passed = 1 -> base 50; penalty = 1.5 -> 1. score 49.
    export VPSSEC_SECURITY_LEVEL=strict
    run calculate_score
    unset VPSSEC_SECURITY_LEVEL
    [ "$output" = "49" ]
}
