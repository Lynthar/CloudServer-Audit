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

@test "get_check_score_category: unknown defaults to recommended" {
    run get_check_score_category "totally.fake"
    [ "$output" = "recommended" ]
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
