#!/usr/bin/env bats
#
# Guard against orphan fix_ids.
#
# Every fix_id a module emits (the 8th positional arg of create_check_json)
# must be classified in one of the FIX_* maps in core/security_levels.sh.
# An unclassified fix_id resolves to "unknown" in get_fix_safety(), which
# silently bypasses the alert_only filter and the safety badge: it shows up
# as a selectable "(manual)" fix that then fails, and the safety model is
# not applied. This is the bug class that produced webapp.php_disable_functions
# (name drift vs the classified/dispatched webapp.php_dangerous_functions),
# ssh.configure_access_control, ufw.review_rules, users.{nopasswd_sudo,
# history,password_policy,pwquality}, filesystem.review_caps, etc.
#
# Catch it here at PR time instead of at audit time on a user's box.

setup() {
    REPO="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    SL="$REPO/core/security_levels.sh"
}

# Keys of the four FIX_* maps = every ["..."] entry before the
# CHECK_SCORE_CATEGORY map starts.
_classified_fix_ids() {
    local end
    end=$(grep -n 'CHECK_SCORE_CATEGORY=' "$SL" | head -1 | cut -d: -f1)
    awk -v e="$end" 'NR<e' "$SL" \
        | grep -oE '\["[a-zA-Z0-9_.]+"\]' | tr -d '["]' | sort -u
}

# The fix_id is the last arg of create_check_json — the only line in the
# call block that does NOT end in a continuation backslash. Skip empty
# fix_ids ("") and variable ones ($fix_id, resolved at runtime).
_emitted_fix_ids() {
    local m
    for m in "$REPO"/modules/*.sh; do
        awk '
            /create_check_json/ { inblk=1; next }
            inblk && $0 !~ /\\[ \t]*$/ {
                inblk=0
                if (match($0, /"[^"]*"\)/)) {
                    tok=substr($0, RSTART+1, RLENGTH-3)
                    if (tok != "" && tok !~ /\$/) print tok
                }
            }' "$m"
    done | sort -u
}

@test "every emitted fix_id is classified in a FIX_* map" {
    local classified emitted orphans="" fid
    classified=$(_classified_fix_ids)
    emitted=$(_emitted_fix_ids)

    while IFS= read -r fid; do
        [[ -z "$fid" ]] && continue
        grep -qxF -- "$fid" <<<"$classified" || orphans+="$fid "
    done <<<"$emitted"

    if [[ -n "$orphans" ]]; then
        echo "Unclassified fix_id(s) — add to a FIX_* map in core/security_levels.sh:"
        echo "  $orphans"
        false
    fi
}
