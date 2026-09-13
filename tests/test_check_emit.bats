#!/usr/bin/env bats
# check_emit is the one way a module records a check: module comes from the id
# prefix, the title defaults to the id's i18n text, and fields are key=value.
# The static tests keep every call site honest about keys and default titles.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    REPO="$(_vpssec_repo_root)"
    _log_file="$BATS_TEST_TMPDIR/vpssec.log"
}

_recorded() {
    jq -r ".[0].$1" "$STATE_CHECKS_FILE"
}

@test "check_emit: module is the id prefix and the title defaults to i18n of the id" {
    check_emit "ufw.firewall_active" low passed
    [ "$(jq length "$STATE_CHECKS_FILE")" -eq 1 ]
    [ "$(_recorded id)"         = "ufw.firewall_active" ]
    [ "$(_recorded module)"     = "ufw" ]
    [ "$(_recorded severity)"   = "low" ]
    [ "$(_recorded status)"     = "passed" ]
    [ "$(_recorded title)"      = "$(i18n 'ufw.firewall_active')" ]
    [ "$(_recorded desc)"       = "" ]
    [ "$(_recorded suggestion)" = "" ]
    [ "$(_recorded fix_id)"     = "" ]
}

@test "check_emit: every field lands, and a value may itself contain '='" {
    check_emit "ssh.x11_forwarding_enabled" medium failed \
        title="Custom title" \
        desc="X11Forwarding=yes" \
        suggestion="Set X11Forwarding=no" \
        fix="ssh.disable_x11_forwarding"
    [ "$(_recorded title)"      = "Custom title" ]
    [ "$(_recorded desc)"       = "X11Forwarding=yes" ]
    [ "$(_recorded suggestion)" = "Set X11Forwarding=no" ]
    [ "$(_recorded fix_id)"     = "ssh.disable_x11_forwarding" ]
    [ "$(_recorded severity)"   = "medium" ]
}

@test "check_emit: an unknown field is an error and nothing is recorded" {
    run check_emit "ssh.x11_forwarding_enabled" low failed dsec="typo"
    [ "$status" -eq 1 ]
    grep -q "unknown field 'dsec'" "$_log_file"
    [ ! -e "$STATE_CHECKS_FILE" ]
}

# Static views of the call sites. A site is `check_emit "<id>" …` or
# `_malware_emit_finding "<id>" …`, its fields on continuation lines.
_emit_field_keys() {
    awk '
        match($0, /(^|[ \t])(check_emit|_malware_emit_finding) "[a-zA-Z0-9_.]+"/) { inblk = 1 }
        inblk && match($0, /^[ \t]+[a-z_]+=/) {
            k = substr($0, RSTART, RLENGTH); gsub(/[ \t=]/, "", k)
            print FILENAME ":" FNR ":" k
        }
        inblk && $0 !~ /\\[ \t]*$/ { inblk = 0 }
    ' "$@"
}

_untitled_check_ids() {
    awk '
        function flush() { if (id != "" && !titled) print id; id = ""; titled = 0 }
        match($0, /(^|[ \t])(check_emit|_malware_emit_finding) "[a-zA-Z0-9_.]+"/) {
            flush(); split(substr($0, RSTART, RLENGTH), q, "\""); id = q[2]
        }
        id != "" && /(^|[ \t])title=/ { titled = 1 }
        id != "" && $0 !~ /\\[ \t]*$/ { flush() }
        END { flush() }
    ' "$@"
}

@test "every check_emit field key is one of title desc suggestion fix" {
    local bad
    bad=$(_emit_field_keys "$REPO"/modules/*.sh "$REPO"/core/*.sh \
        | grep -vE ':(title|desc|suggestion|fix)$' || true)
    if [[ -n "$bad" ]]; then
        echo "Unknown check_emit field — the check would be dropped at runtime:"
        echo "$bad"
        false
    fi
}

@test "every check emitted without a title has an en_US key for its id" {
    # The default title is i18n "$id"; without the key the report shows the
    # bare id, and i18n parity cannot see it because both languages lack it.
    local keys missing="" id
    keys=$(jq -r 'paths(scalars) | join(".")' "$REPO/core/i18n/en_US.json")
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        grep -qxF -- "$id" <<<"$keys" || missing+="$id "
    done < <(_untitled_check_ids "$REPO"/modules/*.sh "$REPO"/core/*.sh | sort -u)
    if [[ -n "$missing" ]]; then
        echo "check_emit without title= whose id is not an en_US key — pass title= or add the key:"
        echo "  $missing"
        false
    fi
}

@test "modules/ and core/engine.sh record checks only through check_emit" {
    # A direct create_check_json call restates the module and title by hand
    # and bypasses the two static checks above.
    local direct
    direct=$(grep -nE '^[^#]*create_check_json' "$REPO"/modules/*.sh "$REPO/core/engine.sh" || true)
    if [[ -n "$direct" ]]; then
        echo "create_check_json called directly — use check_emit:"
        echo "$direct"
        false
    fi
}
