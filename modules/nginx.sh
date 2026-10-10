#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Nginx catchall module
# Copyright (c) 2024

# --- Nginx Paths ---

NGINX_CONF_DIR="/etc/nginx"
NGINX_SITES_ENABLED="${NGINX_CONF_DIR}/sites-enabled"
# A regular file, never a link into sites-available: rollback deletes the files
# a fix created but not links, and a link left pointing at nothing fails nginx -t.
NGINX_CATCHALL_CONF="${NGINX_SITES_ENABLED}/99-catchall.conf"
NGINX_SSL_DIR="${NGINX_CONF_DIR}/ssl"
NGINX_CATCHALL_CERT="${NGINX_SSL_DIR}/default.crt"
NGINX_CATCHALL_KEY="${NGINX_SSL_DIR}/default.key"

# --- Nginx Helper Functions ---

# Catchall coverage of a config text, as "<needed> <have>". needed is "both" when
# nginx itself serves 443 and "80" when it does not; have is both | 80only |
# 443only | none, a port counting when a default_server there answers 444.
_nginx_catchall_coverage_from_text() {
    nginx_statements <<<"$1" | awk -F'\t' '
        function port(a,   r) {
            if (a ~ /^unix:/) return ""
            if (a ~ /^\[/) { r = substr(a, index(a, "]") + 1); return (r ~ /^:/) ? substr(r, 2) : "80" }
            if (a ~ /:/) { r = a; sub(/.*:/, "", r); return r }
            return (a ~ /^[0-9]+$/) ? a : "80"
        }
        $1 == 0 || $2 ~ /^(stream|mail)(\/|$)/ { next }
        $3 == "listen" {
            n = split($4, w, " ")
            p = port(w[1]); dflt = 0
            for (i = 2; i <= n; i++) if (w[i] == "default_server" || w[i] == "default") dflt = 1
            if (p == "80" && dflt) d80[$1] = 1
            if (p == "443") { on443[$1] = 1; if (dflt) d443[$1] = 1 }
        }
        $3 == "return" && $4 ~ /^444( |$)/ { ret[$1] = 1 }
        # nginx >= 1.19.4 refuses an unknown SNI outright; that covers 443 too.
        $3 == "ssl_reject_handshake" && $4 == "on" { rej[$1] = 1 }
        END {
            for (s in d80) if (s in ret) c80 = 1
            for (s in d443) if ((s in ret) || (s in rej)) c443 = 1
            for (s in on443) if (!((s in d443) && ((s in ret) || (s in rej)))) serves = 1
            have = (c80 && c443) ? "both" : c80 ? "80only" : c443 ? "443only" : "none"
            print (serves ? "both" : "80") " " have
        }
    '
}

# Does "<needed> <have>" cover what is needed? Port 443 needs a catchall only
# where nginx serves it: adding one elsewhere opens 443 to the world, or fails
# to bind next to whatever already holds it.
_nginx_catchall_covered() {
    case "$1" in
        "both both"|"80 both"|"80 80only") return 0 ;;
    esac
    return 1
}

# FIX_VERIFY predicate for nginx.add_catchall: the audit's own rule, re-read.
_nginx_has_catchall() {
    nginx_dump_reset
    nginx_dump_load || return 1
    _nginx_catchall_covered "$(_nginx_catchall_coverage_from_text "$NGINX_DUMP")"
}

# Validate the merged config. Returns nginx's own diagnostic on stdout as well
# as its status, because "configuration test failed" on its own is not
# something an operator can act on — see the fix's use of it.
_nginx_test_config() {
    nginx -t 2>&1
}

# --- DoS hardening. nginx_statements inlines every include, so one pass finds a
# directive's effective last value. Any occurrence past the threshold is the
# finding: one served location weaker than policy. ---

# The last value of a directive in nginx_statements output, or the default when
# nothing sets it.
_nginx_get_directive_value() {
    local stmts="$1" key="$2" default="$3"
    local value
    value=$(awk -F'\t' -v k="$key" '$3 == k { last = $4 } END { if (last != "") print last }' <<<"$stmts")
    echo "${value:-$default}"
}

# Does the directive appear at least once in nginx_statements output?
_nginx_has_directive() {
    awk -F'\t' -v k="$2" '$3 == k { found = 1; exit } END { exit !found }' <<<"$1"
}

# nginx time values: a bare integer of seconds, or an ms/s/m/h suffix. The
# first token wins where a directive takes several. Anything unparseable
# returns 0 — safe, rather than a fabricated number that would false-flag.
_nginx_parse_seconds() {
    local val="$1"
    # First whitespace-separated token only.
    val="${val%% *}"
    val="${val%;}"
    case "$val" in
        ''|0)         echo 0 ;;
        *[!0-9]*)
            if   [[ "$val" =~ ^([0-9]+)ms$ ]]; then echo $(( BASH_REMATCH[1] / 1000 ))
            elif [[ "$val" =~ ^([0-9]+)s$  ]]; then echo "${BASH_REMATCH[1]}"
            elif [[ "$val" =~ ^([0-9]+)m$  ]]; then echo $(( BASH_REMATCH[1] * 60 ))
            elif [[ "$val" =~ ^([0-9]+)h$  ]]; then echo $(( BASH_REMATCH[1] * 3600 ))
            elif [[ "$val" =~ ^([0-9]+)d$  ]]; then echo $(( BASH_REMATCH[1] * 86400 ))
            else                                    echo 0
            fi
            ;;
        *)            echo "$val" ;;
    esac
}

# --- Nginx Audit ---

nginx_audit() {
    local module="nginx"

    # Check if Nginx is installed
    print_item "$(i18n 'nginx.check_installed')"
    if ! nginx_present; then
        check_emit "nginx.not_installed" low passed
        print_ok "$(i18n 'nginx.not_installed')"
        return
    fi

    # Re-read: a fix since the last audit may have rewritten the config. A config
    # nginx itself rejects gets one finding, not a grade read from its files.
    nginx_dump_reset
    if ! nginx_dump_load; then
        check_emit "nginx.config_unreadable" info failed \
            desc="$(i18n 'nginx.config_unreadable_desc' "error=${NGINX_DUMP_ERROR:-nginx -t}")" \
            suggestion="$(i18n 'nginx.config_unreadable_fix')"
        print_warn "$(i18n 'nginx.config_unreadable')"
        return
    fi

    # Check default server / catchall
    print_item "$(i18n 'nginx.check_default_server')"
    _nginx_audit_catchall

    # Timeouts, rate limiting and slow-attack defences, per CIS NGINX
    # Benchmark 5.2.1 and nginx's own DDoS-mitigation guidance.
    print_item "$(i18n 'nginx.check_dos_hardening')"
    _nginx_audit_dos_hardening
}

_nginx_audit_catchall() {
    local coverage
    coverage=$(_nginx_catchall_coverage_from_text "$NGINX_DUMP")

    if _nginx_catchall_covered "$coverage"; then
        local desc_key='nginx.catchall_both_desc'
        [[ "$coverage" == 80\ * ]] && desc_key='nginx.catchall_80_desc'
        check_emit "nginx.catchall_exists" low passed desc="$(i18n "$desc_key")"
        print_ok "$(i18n 'nginx.catchall_exists')"
        return
    fi

    case "${coverage#* }" in
        80only)
            check_emit "nginx.catchall_partial_80" low failed \
                desc="$(i18n 'nginx.catchall_partial_80_desc')" \
                suggestion="$(i18n 'nginx.fix_add_catchall')" \
                fix="nginx.add_catchall"
            print_severity "low" "$(i18n 'nginx.catchall_partial_80')"
            ;;
        443only)
            check_emit "nginx.catchall_partial_443" low failed \
                desc="$(i18n 'nginx.catchall_partial_443_desc')" \
                suggestion="$(i18n 'nginx.fix_add_catchall')" \
                fix="nginx.add_catchall"
            print_severity "low" "$(i18n 'nginx.catchall_partial_443')"
            ;;
        *)
            check_emit "nginx.no_catchall" low failed \
                desc="$(i18n 'nginx.no_catchall_desc')" \
                suggestion="$(i18n 'nginx.fix_add_catchall')" \
                fix="nginx.add_catchall"
            print_severity "low" "$(i18n 'nginx.no_catchall')"
            ;;
    esac
}

_nginx_audit_dos_hardening() {
    local effective
    effective=$(nginx_statements <<<"$NGINX_DUMP")

    local issues=()

    # 1. client_header_timeout — CIS 5.2.1, default 60s, recommended ≤10s.
    local cht_raw cht
    cht_raw=$(_nginx_get_directive_value "$effective" "client_header_timeout" "60s")
    cht=$(_nginx_parse_seconds "$cht_raw")
    if (( cht > 10 )); then
        check_emit "nginx.client_header_timeout_high" low failed \
            desc="$(i18n 'nginx.client_header_timeout_high_desc' "cht_raw=$cht_raw")" \
            suggestion="$(i18n 'nginx.fix_dos_timeouts')"
        issues+=("client_header_timeout=$cht_raw")
        print_severity "low" "$(i18n 'nginx.client_header_timeout_high'): $cht_raw"
    fi

    # 2. client_body_timeout — CIS 5.2.1, default 60s, recommended ≤10s.
    local cbt_raw cbt
    cbt_raw=$(_nginx_get_directive_value "$effective" "client_body_timeout" "60s")
    cbt=$(_nginx_parse_seconds "$cbt_raw")
    if (( cbt > 10 )); then
        check_emit "nginx.client_body_timeout_high" low failed \
            desc="$(i18n 'nginx.client_body_timeout_high_desc' "cbt_raw=$cbt_raw")" \
            suggestion="$(i18n 'nginx.fix_dos_timeouts')"
        issues+=("client_body_timeout=$cbt_raw")
        print_severity "low" "$(i18n 'nginx.client_body_timeout_high'): $cbt_raw"
    fi

    # 3. keepalive_timeout — default 75s, recommended ≤30s (F5 NGINX STIG).
    local kt_raw kt
    kt_raw=$(_nginx_get_directive_value "$effective" "keepalive_timeout" "75s")
    kt=$(_nginx_parse_seconds "$kt_raw")
    if (( kt > 30 )); then
        check_emit "nginx.keepalive_timeout_high" low failed \
            desc="$(i18n 'nginx.keepalive_timeout_high_desc' "kt_raw=$kt_raw")" \
            suggestion="$(i18n 'nginx.fix_dos_keepalive')"
        issues+=("keepalive_timeout=$kt_raw")
        print_severity "low" "$(i18n 'nginx.keepalive_timeout_high'): $kt_raw"
    fi

    # 4. send_timeout — default 60s, recommended ≤10s.
    local st_raw st
    st_raw=$(_nginx_get_directive_value "$effective" "send_timeout" "60s")
    st=$(_nginx_parse_seconds "$st_raw")
    if (( st > 10 )); then
        check_emit "nginx.send_timeout_high" low failed \
            desc="$(i18n 'nginx.send_timeout_high_desc' "st_raw=$st_raw")" \
            suggestion="$(i18n 'nginx.fix_dos_timeouts')"
        issues+=("send_timeout=$st_raw")
        print_severity "low" "$(i18n 'nginx.send_timeout_high'): $st_raw"
    fi

    # 5. Rate limiting presence — no severity escalation: many static
    # / internal sites legitimately don't need it. Recorded as low.
    if ! _nginx_has_directive "$effective" "limit_req_zone"; then
        check_emit "nginx.no_rate_limiting" low failed \
            desc="$(i18n 'nginx.no_rate_limiting_desc')" \
            suggestion="$(i18n 'nginx.fix_dos_rate_limit')"
        issues+=("no_rate_limiting")
        print_severity "low" "$(i18n 'nginx.no_rate_limiting')"
    fi

    # 6. reset_timedout_connection — default off, nginx mitigation guide
    # explicitly recommends "on" to close lingering misbehaving clients.
    local rtc
    rtc=$(_nginx_get_directive_value "$effective" "reset_timedout_connection" "off")
    if [[ "$rtc" != "on" ]]; then
        check_emit "nginx.reset_timedout_connection_off" low failed \
            desc="$(i18n 'nginx.reset_timedout_connection_off_desc')" \
            suggestion="$(i18n 'nginx.fix_dos_reset_timedout')"
        issues+=("reset_timedout_connection=off")
        print_severity "low" "$(i18n 'nginx.reset_timedout_connection_off')"
    fi

    # Positive companion — only when EVERY directive met the threshold.
    if (( ${#issues[@]} == 0 )); then
        check_emit "nginx.dos_hardening_ok" low passed \
            desc="$(i18n 'nginx.dos_hardening_ok_desc')"
        print_ok "$(i18n 'nginx.dos_hardening_ok')"
    fi
}

# --- Nginx Fix Functions ---

nginx_fix() {
    local fix_id="$1"

    case "$fix_id" in
        nginx.add_catchall)
            _nginx_fix_add_catchall
            ;;
        *)
            log_error "Unknown nginx fix: $fix_id"
            return 1
            ;;
    esac
}

# The catchall config text; with "both", the 443 server as well. A function so
# the certificate paths come from the module variables. The heredoc EXPANDS, so
# no backslash continuations: they glue lines together.
_nginx_catchall_config() {
    cat <<EOF
# vpssec - Nginx catchall configuration
# Prevents certificate/hostname leakage for unknown requests

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Return 444 (connection closed without response)
    return 444;
}
EOF
    [[ "${1:-}" == both ]] || return 0
    cat <<EOF

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # Self-signed certificate for rejecting unknown hosts. Regenerate with:
    # openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${NGINX_CATCHALL_KEY} -out ${NGINX_CATCHALL_CERT} -subj "/CN=invalid"
    ssl_certificate ${NGINX_CATCHALL_CERT};
    ssl_certificate_key ${NGINX_CATCHALL_KEY};

    # Return 444 (connection closed without response)
    return 444;
}
EOF
}

_nginx_fix_add_catchall() {
    print_info "$(i18n 'nginx.creating_catchall')"

    # Checked FIRST, before anything is written: without it every later step
    # would succeed while nothing reads the catchall. Refuse, and print the
    # include line instead.
    if [[ ! -d "$NGINX_SITES_ENABLED" ]]; then
        print_error "$(i18n 'nginx.sites_enabled_missing' "dir=$NGINX_SITES_ENABLED")"
        print_info "$(i18n 'nginx.sites_enabled_hint' "dir=$NGINX_SITES_ENABLED")"
        log_error "nginx.add_catchall: $NGINX_SITES_ENABLED does not exist; refusing to stage a config nothing would read"
        return 1
    fi

    # Whether nginx serves 443 decides what to write, so a config nginx cannot
    # read is refused here, before anything is staged.
    nginx_dump_reset
    if ! nginx_dump_load; then
        print_error "$(i18n 'nginx.config_unreadable_desc' "error=${NGINX_DUMP_ERROR:-nginx -t}")"
        return 1
    fi
    local needed
    needed=$(_nginx_catchall_coverage_from_text "$NGINX_DUMP")
    needed=${needed%% *}
    [[ "$needed" == both ]] || print_info "$(i18n 'nginx.catchall_80_only')"

    # Decides what the validation-failure path may delete. A dangling link here
    # (what an older version's rollback left) counts as absent: the write
    # replaces it, and all it ever did was fail nginx -t.
    local conf_existed=0
    [[ -e "$NGINX_CATCHALL_CONF" ]] && conf_existed=1

    # UNCONDITIONAL: recording an absent path in .vpssec_created is the only
    # thing that lets a rollback delete what this fix creates, and on a first
    # run — the common case — none of these exist yet.
    backup_file "$NGINX_CATCHALL_CONF" >/dev/null || return 1
    # write_file_atomic creates the parent directory and reports its own
    # failures, so no separate mkdir with a status to discard.
    if ! write_file_atomic "$NGINX_CATCHALL_CONF" "$(_nginx_catchall_config "$needed")"; then
        print_error "$(i18n 'nginx.catchall_write_failed' "file=$NGINX_CATCHALL_CONF")"
        return 1
    fi

    if [[ "$needed" == both ]] && ! _nginx_ensure_catchall_cert; then
        return 1
    fi

    # On failure, undo only what THIS invocation staged: deleting
    # unconditionally costs an operator their own pre-existing file. Anything
    # that pre-existed is left for `vpssec rollback`, which has the snapshot.
    local test_output
    if ! test_output=$(_nginx_test_config); then
        print_error "$(i18n 'nginx.nginx_test_failed')"
        # Surface nginx's own message: on a stock Debian host this branch is
        # the COMMON outcome, and "configuration test failed" alone names
        # neither the file nor the line the operator must decide about.
        [[ -n "$test_output" ]] && print_info "$(i18n 'nginx.nginx_test_output' "msg=$test_output")"
        if (( conf_existed )); then
            print_warn "$(i18n 'nginx.catchall_conf_kept' "file=$NGINX_CATCHALL_CONF")"
        else
            rm -f "$NGINX_CATCHALL_CONF"
        fi
        return 1
    fi
    print_ok "$(i18n 'nginx.catchall_created' "path=$NGINX_CATCHALL_CONF")"

    # A failed reload leaves the catchall staged but NOT live, so the host is
    # still exposed. That must return 1: `if reload; then return 0; fi` falls
    # through to a successful `if` and records the fix as done.
    if ! systemctl reload nginx 2>/dev/null; then
        print_error "$(i18n 'nginx.reload_failed_staged')"
        return 1
    fi
    print_ok "$(i18n 'nginx.nginx_reloaded')"

    # Two postconditions, because the files and the running server can differ:
    # nginx -t passes and the reload signal returns 0 even when the new config
    # then fails to bind and the old one keeps serving.
    local coverage
    nginx_dump_reset
    nginx_dump_load && coverage=$(_nginx_catchall_coverage_from_text "$NGINX_DUMP")
    if ! _nginx_catchall_covered "${coverage:-}"; then
        print_error "$(i18n 'nginx.catchall_postcondition_failed' "state=${coverage#* }")"
        return 1
    fi
    local live=0
    _nginx_catchall_live || live=$?
    case "$live" in
        0) return 0 ;;
        2) print_error "$(i18n 'nginx.catchall_unverified')" ;;
        *) print_error "$(i18n 'nginx.catchall_not_live')" ;;
    esac
    return 1
}

# Ask the running nginx, not its files: an unknown Host on 127.0.0.1:<port, 80>
# must get no answer. 0 = closed unanswered, 1 = answered or refused, 2 = held
# open. An answer is retried briefly: a reload hands over to new workers async.
_nginx_catchall_live() {
    local port="${1:-80}" host="vpssec-$RANDOM$RANDOM.invalid" try rc=1
    for try in 1 2 3 4 5; do
        # A subshell: a peer that closes before the request is written raises
        # SIGPIPE there, not in vpssec, and 141 is exactly that unanswered close.
        (
            exec 3<>"/dev/tcp/127.0.0.1/$port" || exit 1
            printf 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' "$host" >&3
            IFS= read -r -n 1 -t 3 _ <&3 && exit 1
            (( $? > 128 )) && exit 2
            exit 0
        ) 2>/dev/null
        rc=$?
        (( rc == 141 )) && rc=0
        (( rc == 1 )) || break
        (( try < 5 )) && sleep 0.5
    done
    return "$rc"
}

# Create the SSL directory and self-signed certificate the 443 catchall needs.
# Split out so each status is checked: errexit is off inside a fix, so a
# failing openssl otherwise continues into the reload.
_nginx_ensure_catchall_cert() {
    [[ -f "$NGINX_CATCHALL_CERT" ]] && return 0

    if ! mkdir -p "$NGINX_SSL_DIR" 2>/dev/null; then
        print_error "$(i18n 'nginx.ssl_dir_failed' "dir=$NGINX_SSL_DIR")"
        return 1
    fi

    print_info "$(i18n 'nginx.generating_cert')"
    # Unconditional for the reason given at the config write: inside this
    # branch neither file is in a state worth keeping, and on a first run
    # .vpssec_created is what lets a rollback remove them.
    backup_file "$NGINX_CATCHALL_CERT" >/dev/null || return 1
    backup_file "$NGINX_CATCHALL_KEY" >/dev/null || return 1

    if ! openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$NGINX_CATCHALL_KEY" \
            -out "$NGINX_CATCHALL_CERT" \
            -subj "/CN=invalid" 2>/dev/null; then
        print_error "$(i18n 'nginx.cert_generate_failed' "file=$NGINX_CATCHALL_CERT")"
        return 1
    fi

    # The private key must not be world-readable. A failure here is reported
    # rather than swallowed: the alternative is a 644 key on disk under a
    # fix that told the operator it had hardened the host.
    if ! chmod 600 "$NGINX_CATCHALL_KEY" 2>/dev/null; then
        print_error "$(i18n 'nginx.cert_chmod_failed' "file=$NGINX_CATCHALL_KEY")"
        return 1
    fi
    return 0
}
