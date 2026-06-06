#!/usr/bin/env bats
#
# Tests for the fix-classification and score-category lookups in
# core/security_levels.sh. These maps are the contract between
# guide-mode UI (which shows safety badges and gates auto-fix) and
# scoring (which excludes info-only checks). A regression here can
# either silently auto-apply a fix that should require confirmation
# or score the host wrongly — both user-visible.

load helpers

setup() {
    _vpssec_load core/security_levels.sh
}

# ---- get_fix_safety -------------------------------------------------

@test "get_fix_safety: known SAFE fix is 'safe'" {
    run get_fix_safety "ssh.disable_empty_password"
    [ "$status" -eq 0 ]
    [ "$output" = "safe" ]
}

@test "get_fix_safety: known CONFIRM fix is 'confirm'" {
    run get_fix_safety "ssh.harden_algorithms"
    [ "$output" = "confirm" ]
}

@test "get_fix_safety: known RISKY fix is 'risky'" {
    run get_fix_safety "ssh.disable_password_auth"
    [ "$output" = "risky" ]
}

@test "get_fix_safety: known ALERT_ONLY fix is 'alert_only'" {
    run get_fix_safety "malware.crypto_miner"
    [ "$output" = "alert_only" ]
}

@test "get_fix_safety: unknown fix_id is 'unknown'" {
    run get_fix_safety "nope.does_not_exist"
    [ "$output" = "unknown" ]
}

# ---- can_fix --------------------------------------------------------

@test "can_fix: safe fix can be auto-applied" {
    run can_fix "ssh.disable_empty_password"
    [ "$status" -eq 0 ]
}

@test "can_fix: alert-only fix cannot be auto-applied" {
    run can_fix "malware.crypto_miner"
    [ "$status" -ne 0 ]
}

@test "can_fix: unknown fix_id cannot be auto-applied" {
    run can_fix "totally.fake"
    [ "$status" -ne 0 ]
}

# ---- fix_requires_confirmation --------------------------------------

@test "fix_requires_confirmation: safe fix does NOT require confirm" {
    run fix_requires_confirmation "ssh.disable_empty_password"
    [ "$status" -ne 0 ]
}

@test "fix_requires_confirmation: confirm-class fix DOES require confirm" {
    run fix_requires_confirmation "ssh.harden_algorithms"
    [ "$status" -eq 0 ]
}

@test "fix_requires_confirmation: risky fix DOES require confirm" {
    run fix_requires_confirmation "ssh.disable_password_auth"
    [ "$status" -eq 0 ]
}

# ---- fix_is_risky ---------------------------------------------------

@test "fix_is_risky: safe fix is not risky" {
    run fix_is_risky "ssh.disable_empty_password"
    [ "$status" -ne 0 ]
}

@test "fix_is_risky: ufw enable IS risky" {
    run fix_is_risky "ufw.enable"
    [ "$status" -eq 0 ]
}

# ---- get_check_score_category ---------------------------------------

@test "get_check_score_category: SSH password_auth is required" {
    run get_check_score_category "ssh.password_auth_enabled"
    [ "$output" = "required" ]
}

@test "get_check_score_category: docker.* is conditional" {
    run get_check_score_category "docker.privileged_containers"
    [ "$output" = "conditional" ]
}

@test "get_check_score_category: ssh.x11 is info-only" {
    run get_check_score_category "ssh.x11_forwarding_enabled"
    [ "$output" = "info" ]
}

@test "get_check_score_category: unknown defaults to info (fail-safe, non-scoring)" {
    # An unclassified id must NOT move the score until deliberately promoted —
    # a forgotten/heuristic check should never silently penalize a host.
    run get_check_score_category "totally.fake"
    [ "$output" = "info" ]
}

# ---- Coverage invariants --------------------------------------------
#
# The malware module documents that everything it detects is alert-only
# (CLAUDE.md): "The `malware` module deliberately uses this for
# everything it detects." Pin that contract: any malware.* fix_id
# referenced as a check fix_id MUST land in FIX_ALERT_ONLY.

@test "malware.* findings are all alert_only or absent" {
    # Iterate over every fix_id we ship in any of the four maps and
    # confirm none of the malware ones fall outside ALERT_ONLY.
    local id
    for id in "${!FIX_SAFE[@]}" "${!FIX_CONFIRM[@]}" "${!FIX_RISKY[@]}"; do
        if [[ "$id" == malware.* ]]; then
            printf 'malware fix_id %s leaked out of ALERT_ONLY\n' "$id" >&2
            return 1
        fi
    done
}

@test "users.* findings are all alert_only or absent" {
    # Same contract: the users module must NEVER auto-modify users.
    local id
    for id in "${!FIX_SAFE[@]}" "${!FIX_CONFIRM[@]}" "${!FIX_RISKY[@]}"; do
        if [[ "$id" == users.* ]]; then
            printf 'users fix_id %s leaked out of ALERT_ONLY\n' "$id" >&2
            return 1
        fi
    done
}

# ---- fix_needs_engine_confirmation ----------------------------------
#
# This predicate is the single switch execute_fix branches on to decide
# whether to prompt for a fix itself. It must be true for every confirm/
# risky fix EXCEPT the ones that confirm themselves (FIX_SELF_CONFIRMED),
# and false for safe/alert-only fixes.

@test "fix_needs_engine_confirmation: risky non-self-confirming fix is gated by the engine (ufw.set_default_deny)" {
    # ufw.set_default_deny is RISKY (confirm_critical, ignores --yes) and not
    # self-confirmed, so the engine MUST gate it.
    run fix_needs_engine_confirmation "ufw.set_default_deny"
    [ "$status" -eq 0 ]
}

@test "fix_needs_engine_confirmation: risky non-self-confirming fix is gated by the engine" {
    # update.apply_security is FIX_RISKY but has no confirm_critical of its
    # own — the engine MUST gate it (the gap this change closes).
    run fix_needs_engine_confirmation "update.apply_security"
    [ "$status" -eq 0 ]
}

@test "fix_needs_engine_confirmation: self-confirming risky fix is NOT gated by the engine" {
    run fix_needs_engine_confirmation "ssh.disable_password_auth"
    [ "$status" -ne 0 ]
}

@test "fix_needs_engine_confirmation: self-confirming confirm fix is NOT gated by the engine" {
    run fix_needs_engine_confirmation "docker.enable_no_new_privileges"
    [ "$status" -ne 0 ]
}

@test "fix_needs_engine_confirmation: safe fix is NOT gated" {
    run fix_needs_engine_confirmation "ssh.disable_empty_password"
    [ "$status" -ne 0 ]
}

@test "fix_needs_engine_confirmation: alert-only fix is NOT gated" {
    run fix_needs_engine_confirmation "malware.crypto_miner"
    [ "$status" -ne 0 ]
}

# ---- FIX_SELF_CONFIRMED invariants ----------------------------------

@test "FIX_SELF_CONFIRMED: every entry is confirm- or risky-class" {
    # A safe/alert-only fix in the skip set would mean the engine never
    # gates it AND it has no business self-confirming — a silent hole.
    local id safety
    for id in "${!FIX_SELF_CONFIRMED[@]}"; do
        safety=$(get_fix_safety "$id")
        if [[ "$safety" != "confirm" && "$safety" != "risky" ]]; then
            printf 'FIX_SELF_CONFIRMED entry %s is %s, expected confirm/risky\n' \
                "$id" "$safety" >&2
            return 1
        fi
    done
}

@test "FIX_SELF_CONFIRMED: the four known self-confirming fixes are present" {
    local id
    for id in ssh.disable_password_auth ssh.disable_root_login \
              ufw.enable docker.enable_no_new_privileges; do
        [[ -n "${FIX_SELF_CONFIRMED[$id]:-}" ]] || {
            printf 'expected %s in FIX_SELF_CONFIRMED\n' "$id" >&2
            return 1
        }
    done
}

@test "FIX_SELF_CONFIRMED: each listed module still calls confirm_critical" {
    # Drift guard: if a module's confirm_critical is removed, the fix no
    # longer self-confirms and must be dropped from FIX_SELF_CONFIRMED, or
    # the engine will never gate it. Catch that here at PR time.
    local root id module
    root=$(_vpssec_repo_root)
    for id in "${!FIX_SELF_CONFIRMED[@]}"; do
        module="${id%%.*}"
        if ! grep -q 'confirm_critical' "$root/modules/$module.sh"; then
            printf '%s is in FIX_SELF_CONFIRMED but modules/%s.sh has no confirm_critical\n' \
                "$id" "$module" >&2
            return 1
        fi
    done
}
