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

# ---- the other direction ---------------------------------------------
#
# The test above only catches emitted-but-unclassified. Classified-but-never-
# emitted rotted undetected for as long: timezone.sync_time and
# alerts.generate_templates each had a FIX_SAFE entry, a dispatch case and an
# implementation, but no check ever handed the engine that fix_id — so they
# could never be selected, while `vpssec help <module>` cheerfully advertised
# them as auto-applied fixes. fail2ban.installed was the same rot in
# CHECK_SCORE_CATEGORY.
#
# One convention has to be respected or this fires on ~28 legitimate entries:
# FIX_ALERT_ONLY is keyed by CHECK id, not fix id. Alert-only findings emit an
# empty fix_id by definition; the map is what lets _help_collect_fixes explain
# them in the "alert only" section of `vpssec help <module>`.

# Keys of one named map.
_map_keys() {
    awk -v m="$1" '
        $0 ~ ("^declare -gA " m "=\\(") { f=1; next }
        f && /^\)/ { f=0 }
        f { print }
    ' "$SL" | grep -oE '\["[a-zA-Z0-9_.]+"\]' | tr -d '["]' | sort -u
}

# fix_ids the modules emit, in either form: as the literal last argument of
# create_check_json, or assigned to a variable that is then passed. core/ is
# included because state.sh emits checks too.
_emitted_fix_ids_all() {
    local m
    for m in "$REPO"/modules/*.sh "$REPO"/core/*.sh; do
        awk '
            /create_check_json/ { inblk=1; next }
            inblk && $0 !~ /\\[ \t]*$/ {
                inblk=0
                if (match($0, /"[^"]*"\)/)) {
                    tok = substr($0, RSTART+1, RLENGTH-3)
                    if (tok != "" && tok !~ /\$/) print tok
                }
            }' "$m"
    done
    grep -rhoE 'fix_id="[a-zA-Z0-9_.]+"' "$REPO"/modules/*.sh "$REPO"/core/*.sh 2>/dev/null \
        | sed 's/fix_id="//; s/"$//'
}

# check_ids: the FIRST argument of create_check_json, i.e. the line right
# after the call.
_emitted_check_ids() {
    local m
    for m in "$REPO"/modules/*.sh "$REPO"/core/*.sh; do
        awk '
            /create_check_json/ { n=1; next }
            n==1 {
                n=0
                if (match($0, /"[a-zA-Z0-9_.]+"/)) print substr($0, RSTART+1, RLENGTH-2)
            }' "$m"
    done
}

@test "every selectable fix_id classification is actually reachable" {
    local emitted orphans="" id
    emitted=$( { _emitted_fix_ids_all; } | sort -u )

    local map
    for map in FIX_SAFE FIX_CONFIRM FIX_RISKY; do
        while IFS= read -r id; do
            [[ -z "$id" ]] && continue
            grep -qxF -- "$id" <<<"$emitted" || orphans+="${map}:${id} "
        done < <(_map_keys "$map")
    done

    if [[ -n "$orphans" ]]; then
        echo "Classified but never emitted — no check hands the engine this fix_id,"
        echo "so it can never be selected, yet 'vpssec help' advertises it:"
        echo "  $orphans"
        false
    fi
}

@test "every FIX_ALERT_ONLY key names a real check or fix" {
    local known orphans="" id
    known=$( { _emitted_fix_ids_all; _emitted_check_ids; } | sort -u )

    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$known" || orphans+="$id "
    done < <(_map_keys FIX_ALERT_ONLY)

    if [[ -n "$orphans" ]]; then
        echo "FIX_ALERT_ONLY key matches neither an emitted check_id nor fix_id:"
        echo "  $orphans"
        false
    fi
}

# ---- FIX_TEMPLATE_ONLY --------------------------------------------------
#
# The map records which fixes cannot resolve the finding they hang off. It is
# ORTHOGONAL to the safety class, not a fifth class: all four generators are
# FIX_SAFE and webapp's SSL pair is FIX_CONFIRM. So it gets the same both-ways
# treatment as the others — a key naming nothing is a promise the engine can
# never keep, and a key with no safety class would slip past get_fix_safety.

@test "every FIX_TEMPLATE_ONLY key is a fix some check actually offers" {
    local emitted orphans="" id
    emitted=$( { _emitted_fix_ids_all; } | sort -u )

    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$emitted" || orphans+="$id "
    done < <(_map_keys FIX_TEMPLATE_ONLY)

    if [[ -n "$orphans" ]]; then
        echo "FIX_TEMPLATE_ONLY names a fix_id no check emits — execute_fix will"
        echo "never consult the entry, and 'vpssec help' shows a note on a fix"
        echo "the user cannot select:"
        echo "  $orphans"
        false
    fi
}

@test "every FIX_TEMPLATE_ONLY key also has a safety class" {
    # Without one get_fix_safety answers "unknown", which bypasses the
    # confirm/risky gate entirely — the template-only note would be the only
    # thing the operator ever saw about it.
    local id missing="" classes
    classes=$( { _map_keys FIX_SAFE; _map_keys FIX_CONFIRM; _map_keys FIX_RISKY; } | sort -u )

    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$classes" || missing+="$id "
    done < <(_map_keys FIX_TEMPLATE_ONLY)

    if [[ -n "$missing" ]]; then
        echo "FIX_TEMPLATE_ONLY entry with no FIX_SAFE/CONFIRM/RISKY class:"
        echo "  $missing"
        false
    fi
}

@test "every FIX_TEMPLATE_ONLY key has a fixtmpl translation in both languages" {
    # The map's English doubles as the fallback, so a missing key degrades to a
    # readable sentence rather than printing 'fixtmpl.docker.…' — but only the
    # English half. A zh_CN user would silently get English, which is the same
    # last-mile gap fixwarn.* was created to close.
    local id missing="" lang
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        for lang in en_US zh_CN; do
            jq -e --arg k "$id" '.fixtmpl[$k] // empty' \
                "$REPO/core/i18n/${lang}.json" >/dev/null 2>&1 \
                || missing+="${lang}:${id} "
        done
    done < <(_map_keys FIX_TEMPLATE_ONLY)

    if [[ -n "$missing" ]]; then
        echo "Missing fixtmpl.<fix_id> translation:"
        echo "  $missing"
        false
    fi
}

# ---- FIX_VERIFY ----------------------------------------------------------
#
# Same both-ways discipline: a key naming no emitted fix is a promise the
# engine never keeps, and a verify on a template-only fix would fail forever
# by definition — the two maps must stay disjoint.

@test "every FIX_VERIFY key is a fix some check actually offers" {
    local emitted orphans="" id
    emitted=$( { _emitted_fix_ids_all; } | sort -u )

    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$emitted" || orphans+="$id "
    done < <(_map_keys FIX_VERIFY)

    if [[ -n "$orphans" ]]; then
        echo "FIX_VERIFY names a fix_id no check emits:"
        echo "  $orphans"
        false
    fi
}

@test "every FIX_VERIFY key also has a safety class" {
    local id missing="" classes
    classes=$( { _map_keys FIX_SAFE; _map_keys FIX_CONFIRM; _map_keys FIX_RISKY; } | sort -u )

    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$classes" || missing+="$id "
    done < <(_map_keys FIX_VERIFY)

    if [[ -n "$missing" ]]; then
        echo "FIX_VERIFY entry with no FIX_SAFE/CONFIRM/RISKY class:"
        echo "  $missing"
        false
    fi
}

@test "FIX_VERIFY and FIX_TEMPLATE_ONLY are disjoint" {
    local overlap
    overlap=$(comm -12 <(_map_keys FIX_VERIFY | sort -u)                        <(_map_keys FIX_TEMPLATE_ONLY | sort -u))

    if [[ -n "$overlap" ]]; then
        echo "A template-only fix cannot pass a verify predicate by definition:"
        echo "  $overlap"
        false
    fi
}

@test "every scored check id is actually emitted" {
    local emitted orphans="" id
    emitted=$(_emitted_check_ids | sort -u)

    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$emitted" || orphans+="$id "
    done < <(_map_keys CHECK_SCORE_CATEGORY)

    if [[ -n "$orphans" ]]; then
        echo "CHECK_SCORE_CATEGORY entry for a check no module emits:"
        echo "  $orphans"
        false
    fi
}
