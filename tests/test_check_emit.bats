#!/usr/bin/env bats
# check_emit is the one way a module records a check: module comes from the id
# prefix, the title defaults to the id's i18n text, and fields are key=value.
# The static tests keep every call site honest about keys and default titles.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    # Without it i18n echoes the key, so "the title is the id's i18n text"
    # would hold for a title that is the bare id.
    i18n_load en_US
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

@test "i18n: a substituted value is inserted verbatim, & and backslashes included" {
    # bash 5.2+ expands an unquoted & in a ${//} replacement to the match, so a
    # crontab line "a && b" would render as "a {cmd}{cmd} b".
    VPSSEC_I18N[test.cmd]='run: {cmd}'
    run i18n test.cmd 'cmd=a && b \x'
    [ "$output" = 'run: a && b \x' ]
}

@test "check_emit: an unknown field is an error and nothing is recorded" {
    run check_emit "ssh.x11_forwarding_enabled" low failed dsec="typo"
    [ "$status" -eq 1 ]
    grep -q "unknown field 'dsec'" "$_log_file"
    [ ! -e "$STATE_CHECKS_FILE" ]
}

# ---- a check that cannot be recorded is a failure, never an absence ----------

@test "check_emit: a desc past the 128 KiB argv limit is recorded whole" {
    local long
    long=$(head -c 200000 /dev/zero | tr '\0' a)
    check_emit "malware.crypto_miner" high failed desc="$long"
    [ "$(jq length "$STATE_CHECKS_FILE")" -eq 1 ]
    [ "$(_recorded 'desc | length')" -eq 200000 ]
}

@test "check_emit: a check that cannot be written marks its module incomplete and returns 0" {
    source "$REPO/core/engine.sh"
    mkdir "$STATE_CHECKS_FILE"   # a directory: every write to it fails
    local rc=0
    check_emit "ssh.x11_forwarding_enabled" low failed || rc=$?
    [ "$rc" -eq 0 ]
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" ssh "* ]]
    [ "${VPSSEC_MODULE_EMIT_FAILED[ssh]:-}" = "1" ]
    grep -q "check_emit ssh.x11_forwarding_enabled: the check could not be recorded" "$_log_file"
}

@test "check_emit: a lost _internal record does not list _internal as a failed module" {
    source "$REPO/core/engine.sh"
    mkdir "$STATE_CHECKS_FILE"
    check_emit "_internal.module_failed" low failed
    [ "${#VPSSEC_MODULES_FAILED[@]}" -eq 0 ]
}

@test "a check lost mid-audit is reported after the pass, and the audit exits 3" {
    source "$REPO/core/engine.sh"
    eval "_real_$(declare -f state_add_check)"
    state_add_check() {
        [[ "$1" == *'"fake.lost"'* ]] && return 1
        _real_state_add_check "$@"
    }
    VPSSEC_MODULE_ORDER=(fake)
    VPSSEC_MODULE_ENABLED[fake]=1
    VPSSEC_MODULE_LOADED[fake]=1
    fake_audit() {
        check_emit fake.lost low failed
        check_emit fake.kept low passed
    }
    report_generate_all() { :; }

    run audit_all
    [ "$status" -eq 3 ]
    jq -e 'any(.[]; .id == "fake.kept") and all(.[]; .id != "fake.lost")' "$STATE_CHECKS_FILE"
    run jq -r '.[] | select(.id == "_internal.module_failed") | .desc' "$STATE_CHECKS_FILE"
    [ "${#lines[@]}" -eq 1 ]
    [ "$output" = "$(i18n 'error.module_failed_emit_desc' "module=fake")" ]
}

@test "state_add_check: an empty record is malformed, not silently dropped" {
    state_init
    state_add_check ""
    [ "$(_recorded id)" = "_internal.malformed_check" ]
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

@test "every literal i18n key in the code is an en_US key" {
    # A key missing from BOTH languages passes parity and prints as the raw key.
    local keys missing="" key
    keys=$(jq -r 'paths(scalars) | join(".")' "$REPO/core/i18n/en_US.json")
    while IFS= read -r key; do
        grep -qxF -- "$key" <<<"$keys" || missing+="$key "
    done < <(grep -ohE "i18n ['\"][A-Za-z0-9_]+\.[A-Za-z0-9_.]+['\"]" \
                 "$REPO"/modules/*.sh "$REPO"/core/*.sh "$REPO/vpssec" \
             | sed -E "s/^i18n ['\"]//; s/['\"]$//" | sort -u)
    if [[ -n "$missing" ]]; then
        echo "i18n keys used in code but absent from en_US.json: $missing"
        false
    fi
}

@test "every issue token rendered through a key prefix has that key" {
    # These helpers return tokens the audit renders as "<prefix><token>" at
    # display time; a new token without its key shows up as the raw key.
    local keys missing="" spec file fn prefix tok
    keys=$(jq -r 'paths(scalars) | join(".")' "$REPO/core/i18n/en_US.json")
    for spec in "modules/kernel.sh _kernel_ipv6_check_security kernel.ipv6_issue_" \
                "modules/kernel.sh _kernel_check_core_dump kernel.core_issue_" \
                "modules/cloudflared.sh _cloudflared_check_ingress_security cloudflared.issue_"; do
        read -r file fn prefix <<<"$spec"
        while IFS= read -r tok; do
            grep -qxF -- "$prefix$tok" <<<"$keys" || missing+="$prefix$tok "
        done < <(sed -n "/^$fn() {/,/^}/p" "$REPO/$file" \
                     | grep -oE 'issues\+=\("[a-z_]+"\)' | cut -d'"' -f2)
    done
    [[ -z "$missing" ]] || { echo "missing: $missing"; false; }
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
