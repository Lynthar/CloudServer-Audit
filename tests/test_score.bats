#!/usr/bin/env bats
#
# Tests for calculate_score and get_check_stats in core/state.sh.
#
# The scoring formula was reworked in e041a59 (commit message: "rework
# security score to pass-rate minus penalty + info reclassification").
# Today's contract:
#
#   base    = 100 × passed / scored_total
#   penalty = 8 × high + 2 × medium + 0.5 × low
#   score   = clamp(0, 100, base − penalty)
#
# `info`-category checks are excluded from `scored_total`, so they
# do NOT dilute the pass rate.
#
# These tests pin the formula end-to-end via fabricated checks.json
# files. Drift here would silently misreport host security posture.

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
        # Use pre-increment, not post: `((i++))` returns the OLD value
        # as exit code, so when i==0 it exits 1 and set -e aborts.
        # Production code dodges this with `|| true`; pre-increment is
        # equivalent and reads cleaner here.
        ((++i))
    done
    jq -n "${jq_args[@]}" "$jq_filter" > "$out"
    # Re-export so state.sh's STATE_CHECKS_FILE resolves correctly.
    export STATE_CHECKS_FILE="$out"
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
        "fail2ban.installed|medium|failed"
    run calculate_score
    [ "$output" = "74" ]
}

@test "calculate_score: info-category checks do not dilute" {
    # ssh.x11_forwarding_enabled is classified as 'info' — must be
    # excluded from the scored_total denominator. Without this the
    # presence of harmless info findings would silently lower scores
    # on every host.
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
    # 2 high + 1 medium failures on a 15-scored-check host with 12
    # safe; matches the example shown in README.md / README_zh.md.
    # base = 100 * 12 / 15 = 80; penalty = 5*2 + 1.5*1 = 11.5,
    # integer-divided in 4× space → 11. score = 69.
    local fails=(
        "ssh.password_auth_enabled|high|failed"
        "users.uid0_found|high|failed"
        "fail2ban.installed|medium|failed"
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

@test "get_check_stats: counts by severity, splits info" {
    _write_checks \
        "ssh.password_auth_enabled|high|failed" \
        "fail2ban.installed|medium|failed" \
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
    [ "$low" = "0" ]      # x11_forwarding is info, not low
    [ "$passed" = "1" ]
    [ "$info" = "1" ]
}
