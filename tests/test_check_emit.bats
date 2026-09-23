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

# Every `check_emit` / `_malware_emit_finding` command, continuation lines
# joined and split into words the way the shell would (quotes and $(...) kept
# whole). Prints "CALL:file:line", then "file:line:key" per field argument.
_emit_field_keys() {
    awk '
        function pop() { st = substr(st, 1, length(st) - 1) }
        function scan(s, at,    i, c, top, word, nw, w, k) {
            st = ""; word = ""; nw = 0
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1); top = substr(st, length(st))
                if (top == "S") { if (c == "\047") pop(); word = word c; continue }
                if (c == "\\") { word = word substr(s, i, 2); i++; continue }
                if (top == "D") {
                    if (c == "\"") pop()
                    else if (c == "$" && substr(s, i + 1, 1) == "(") { st = st "C"; c = "$("; i++ }
                    word = word c; continue
                }
                if (top == "" && (c == " " || c == "\t")) { if (word != "") w[++nw] = word; word = ""; continue }
                if (top == "" && (c ~ /[;&|)]/ || (c == "#" && word == ""))) break
                if (c == "\"") st = st "D"
                else if (c == "\047") st = st "S"
                else if (c == "(") st = st "C"
                else if (c == ")") pop()
                word = word c
            }
            if (word != "") w[++nw] = word
            print "CALL:" at
            for (k = 5; k <= nw; k++) {
                if (match(w[k], /^[A-Za-z_][A-Za-z0-9_]*=/)) print at ":" substr(w[k], 1, RLENGTH - 1)
                else print at ":?" w[k]
            }
        }
        FNR == 1 { buf = "" }
        buf != "" { buf = buf " " $0 }
        buf == "" && $0 !~ /^[ \t]*#/ && match($0, /(^|[ \t;&|(])(check_emit|_malware_emit_finding)[ \t]/) {
            if (substr($0, RSTART, 1) ~ /[ \t;&|(]/) RSTART++
            buf = substr($0, RSTART); at = FILENAME ":" FNR
        }
        buf != "" && buf ~ /\\[ \t]*$/ { sub(/\\[ \t]*$/, "", buf); next }
        buf != "" { scan(buf, at); buf = "" }
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
        /^declare -ga SSH_DIRECTIVE_CHECKS=\(/ { tbl = 1; next }
        tbl && /^\)/ { tbl = 0 }
        tbl && /^[ \t]*"/ { gsub(/^[ \t]*"|"[ \t]*$/, ""); split($0, c, "|"); print c[6]; print c[7] }
        END { flush() }
    ' "$@"
}

@test "every check_emit field key is one of title desc suggestion fix" {
    local bad
    bad=$(_emit_field_keys "$REPO"/modules/*.sh "$REPO"/core/*.sh \
        | grep -v '^CALL:' | grep -vE ':(title|desc|suggestion|fix)$' || true)
    if [[ -n "$bad" ]]; then
        echo "Unknown check_emit field — the check would be dropped at runtime:"
        echo "$bad"
        false
    fi
}

@test "the field-key scan sees every line that calls check_emit" {
    # A call shape the scan does not recognise is a call whose keys go unchecked.
    local mentions calls missed
    mentions=$(grep -nE '(check_emit|_malware_emit_finding)' "$REPO"/modules/*.sh "$REPO"/core/*.sh \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' \
        | grep -vE ':(check_emit|_malware_emit_finding)\(\) \{' \
        | grep -vF 'log_error "check_emit $id:' | cut -d: -f1,2 | sort)
    calls=$(_emit_field_keys "$REPO"/modules/*.sh "$REPO"/core/*.sh \
        | sed -n 's/^CALL://p' | sort)
    [ "$(wc -l <<<"$calls")" -gt 300 ]
    missed=$(comm -23 <(printf '%s\n' "$mentions") <(printf '%s\n' "$calls"))
    if [[ -n "$missed" ]]; then
        echo "check_emit mentioned but not scanned for field keys:"
        echo "$missed"
        false
    fi
}

@test "the field-key scan reads the first line and variable ids" {
    # Keys on the call's own line, and calls whose id is not a literal.
    local src="$BATS_TEST_TMPDIR/emit.sh"
    cat >"$src" <<'SH'
    check_emit "a.b" low failed dsec="typo" \
        suggestion="$(i18n 'x' "n=$n")"
    check_emit "$id" low passed desc="${k}=${v}" || true
    check_emit "${m}.c" low passed "$extra"
SH
    run _emit_field_keys "$src"
    [ "$status" -eq 0 ]
    [ "${lines[0]}" = "CALL:$src:1" ]
    [ "${lines[1]}" = "$src:1:dsec" ]
    [ "${lines[2]}" = "$src:1:suggestion" ]
    [ "${lines[3]}" = "CALL:$src:3" ]
    [ "${lines[4]}" = "$src:3:desc" ]
    [ "${lines[5]}" = "CALL:$src:4" ]
    [ "${lines[6]}" = "$src:4:?\"\$extra\"" ]
    [ "${#lines[@]}" -eq 7 ]
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
