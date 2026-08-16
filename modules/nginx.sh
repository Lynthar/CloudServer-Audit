#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Nginx catchall module
# Copyright (c) 2024

# --- Nginx Paths ---

NGINX_CONF_DIR="/etc/nginx"
NGINX_SITES_AVAILABLE="${NGINX_CONF_DIR}/sites-available"
NGINX_SITES_ENABLED="${NGINX_CONF_DIR}/sites-enabled"
NGINX_CATCHALL_CONF="${NGINX_SITES_AVAILABLE}/99-catchall.conf"
# The symlink under sites-enabled is what makes the catchall live; it used to
# be spelled out at its two use sites instead of named here.
NGINX_CATCHALL_LINK="${NGINX_SITES_ENABLED}/99-catchall.conf"
NGINX_SSL_DIR="${NGINX_CONF_DIR}/ssl"
NGINX_CATCHALL_CERT="${NGINX_SSL_DIR}/default.crt"
NGINX_CATCHALL_KEY="${NGINX_SSL_DIR}/default.key"

# --- Nginx Helper Functions ---

_nginx_installed() {
    check_command nginx
}

# Catchall coverage from a full nginx config dump: both | 80only | 443only |
# none. Tracks brace depth to scope server blocks, requiring a default_server
# listen AND a `return 444;` in the SAME block. Inline comments are stripped.
_nginx_catchall_state_from_text() {
    awk '
        function reset_block() { d80=0; d443=0; ret=0 }
        BEGIN { depth=0; in_server=0; c80=0; c443=0; reset_block() }
        {
            sub(/[[:space:]]*#.*$/, "")
            if ($0 ~ /^[[:space:]]*$/) next

            opens  = gsub(/[{]/, "&")
            closes = gsub(/[}]/, "&")
            pre_depth = depth

            if (!in_server && /[[:space:]]*server[[:space:]]*[{]/) {
                in_server = 1
                close_depth = pre_depth
                reset_block()
            }

            if (in_server) {
                if (/listen/ && /default_server/) {
                    # Colon-or-whitespace boundary, so bare, IPv4, IPv6 and
                    # wildcard listen forms all match. The trailing class is
                    # what stops 8080 and 4430.
                    if ($0 ~ /:80([[:space:]]|;)/    || $0 ~ /[[:space:]]80([[:space:]]|;)/)  d80  = 1
                    if ($0 ~ /:443([[:space:]]|;)/   || $0 ~ /[[:space:]]443([[:space:]]|;)/) d443 = 1
                }
                # Line-start or after { ; whitespace, so a one-line server
                # block parses while something_return does not match.
                if ($0 ~ /(^|[{;[:space:]])return[[:space:]]+444[[:space:]]*;/) ret = 1
            }

            depth += opens - closes

            if (in_server && depth <= close_depth) {
                if (ret) {
                    if (d80)  c80  = 1
                    if (d443) c443 = 1
                }
                in_server = 0
            }
        }
        END {
            if (c80 && c443) print "both"
            else if (c80)    print "80only"
            else if (c443)   print "443only"
            else             print "none"
        }
    ' <<<"$1"
}

_nginx_catchall_state() {
    local effective
    if effective=$(nginx -T 2>/dev/null) && [[ -n "$effective" ]]; then
        _nginx_catchall_state_from_text "$effective"
        return 0
    fi

    # Fallback when nginx -T is unavailable, and file-level imprecise: block
    # scope cannot be tracked across files, so any file with both a
    # default_server listen and a `return 444;` counts.
    local f found_80=0 found_443=0
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        grep -qE "^[[:space:]]*return[[:space:]]+444[[:space:]]*;" "$f" 2>/dev/null || continue
        grep -qE "listen[^;]*(:80([[:space:]]|;)|[[:space:]]80([[:space:]]|;))[^;]*default_server" "$f" 2>/dev/null && found_80=1
        grep -qE "listen[^;]*(:443([[:space:]]|;)|[[:space:]]443([[:space:]]|;))[^;]*default_server" "$f" 2>/dev/null && found_443=1
    done < <(grep -rlE "listen.*default_server" "$NGINX_CONF_DIR" 2>/dev/null)

    if   [[ $found_80 -eq 1 && $found_443 -eq 1 ]]; then echo "both"
    elif [[ $found_80 -eq 1 ]];                      then echo "80only"
    elif [[ $found_443 -eq 1 ]];                     then echo "443only"
    else                                                  echo "none"
    fi
}

# Backwards-compat boolean wrapper. Returns 0 only when both 80 and 443
# have catchalls — partial coverage is treated as missing because that's
# the behavior change M7 was about.
_nginx_has_catchall() {
    [[ "$(_nginx_catchall_state)" == "both" ]]
}

# Validate the merged config. Returns nginx's own diagnostic on stdout as well
# as its status, because "configuration test failed" on its own is not
# something an operator can act on — see the fix's use of it.
_nginx_test_config() {
    nginx -t 2>&1
}

# --- DoS hardening. nginx -T flattens every include into one stream, so one
# awk pass finds a directive's effective last value. Any occurrence past the
# threshold is the finding: one served location weaker than policy. ---

# Read the effective value of a directive from a `nginx -T` dump. If the
# directive doesn't appear anywhere, return the supplied default.
_nginx_get_directive_value() {
    local config="$1" key="$2" default="$3"
    local value
    value=$(awk -v k="$key" '
        # Strip inline comments first so a commented-out line never matches.
        { sub(/[[:space:]]*#.*$/, "") }
        $1 == k {
            sub("^[[:space:]]*" k "[[:space:]]+", "")
            sub(/[[:space:]]*;.*$/, "")
            last = $0
        }
        END { if (last != "") print last }
    ' <<<"$config")
    echo "${value:-$default}"
}

# Does the directive appear at least once in the effective config?
_nginx_has_directive() {
    local config="$1" key="$2"
    awk -v k="$key" '
        { sub(/[[:space:]]*#.*$/, "") }
        $1 == k { found = 1; exit }
        END { exit !found }
    ' <<<"$config"
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
    if ! _nginx_installed; then
        local check=$(create_check_json \
            "nginx.not_installed" \
            "nginx" \
            "low" \
            "passed" \
            "$(i18n 'nginx.not_installed')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'nginx.not_installed')"
        return
    fi

    # Check default server / catchall
    print_item "$(i18n 'nginx.check_default_server')"
    _nginx_audit_catchall

    # Timeouts, rate limiting and slow-attack defences, per CIS NGINX
    # Benchmark 5.2.1 and nginx's own DDoS-mitigation guidance.
    print_item "$(i18n 'nginx.check_dos_hardening' 2>/dev/null || echo 'Checking DoS hardening')"
    _nginx_audit_dos_hardening
}

_nginx_audit_catchall() {
    local state
    state=$(_nginx_catchall_state)

    case "$state" in
        both)
            local check=$(create_check_json \
                "nginx.catchall_exists" \
                "nginx" \
                "low" \
                "passed" \
                "$(i18n 'nginx.catchall_exists')" \
                "$(i18n 'nginx.catchall_both_desc')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'nginx.catchall_exists')"
            ;;
        80only)
            local check=$(create_check_json \
                "nginx.catchall_partial_80" \
                "nginx" \
                "low" \
                "failed" \
                "$(i18n 'nginx.catchall_partial_80')" \
                "$(i18n 'nginx.catchall_partial_80_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "low" "$(i18n 'nginx.catchall_partial_80')"
            ;;
        443only)
            local check=$(create_check_json \
                "nginx.catchall_partial_443" \
                "nginx" \
                "low" \
                "failed" \
                "$(i18n 'nginx.catchall_partial_443')" \
                "$(i18n 'nginx.catchall_partial_443_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "low" "$(i18n 'nginx.catchall_partial_443')"
            ;;
        *)
            local check=$(create_check_json \
                "nginx.no_catchall" \
                "nginx" \
                "low" \
                "failed" \
                "$(i18n 'nginx.no_catchall')" \
                "$(i18n 'nginx.no_catchall_desc')" \
                "$(i18n 'nginx.fix_add_catchall')" \
                "nginx.add_catchall")
            state_add_check "$check"
            print_severity "low" "$(i18n 'nginx.no_catchall')"
            ;;
    esac
}

_nginx_audit_dos_hardening() {
    # Pull the effective config once; every sub-check awk-scans the same
    # blob instead of re-running nginx -T.
    local effective
    if ! effective=$(nginx -T 2>/dev/null) || [[ -z "$effective" ]]; then
        log_warn "nginx -T returned no output; skipping DoS hardening audit"
        return 0
    fi

    local issues=()
    local check

    # 1. client_header_timeout — CIS 5.2.1, default 60s, recommended ≤10s.
    local cht_raw cht
    cht_raw=$(_nginx_get_directive_value "$effective" "client_header_timeout" "60s")
    cht=$(_nginx_parse_seconds "$cht_raw")
    if (( cht > 10 )); then
        check=$(create_check_json \
            "nginx.client_header_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.client_header_timeout_high' 2>/dev/null || echo 'client_header_timeout too high')" \
            "client_header_timeout=$cht_raw (CIS 5.2.1: ≤10s; nginx default 60s leaves Slowloris vulnerable)" \
            "$(i18n 'nginx.fix_dos_timeouts' 2>/dev/null || echo 'Set client_header_timeout 10s; in /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("client_header_timeout=$cht_raw")
        print_severity "low" "$(i18n 'nginx.client_header_timeout_high' 2>/dev/null || echo 'client_header_timeout too high'): $cht_raw"
    fi

    # 2. client_body_timeout — CIS 5.2.1, default 60s, recommended ≤10s.
    local cbt_raw cbt
    cbt_raw=$(_nginx_get_directive_value "$effective" "client_body_timeout" "60s")
    cbt=$(_nginx_parse_seconds "$cbt_raw")
    if (( cbt > 10 )); then
        check=$(create_check_json \
            "nginx.client_body_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.client_body_timeout_high' 2>/dev/null || echo 'client_body_timeout too high')" \
            "client_body_timeout=$cbt_raw (CIS 5.2.1: ≤10s)" \
            "$(i18n 'nginx.fix_dos_timeouts' 2>/dev/null || echo 'Set client_body_timeout 10s; in /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("client_body_timeout=$cbt_raw")
        print_severity "low" "$(i18n 'nginx.client_body_timeout_high' 2>/dev/null || echo 'client_body_timeout too high'): $cbt_raw"
    fi

    # 3. keepalive_timeout — default 75s, recommended ≤30s (F5 NGINX STIG).
    local kt_raw kt
    kt_raw=$(_nginx_get_directive_value "$effective" "keepalive_timeout" "75s")
    kt=$(_nginx_parse_seconds "$kt_raw")
    if (( kt > 30 )); then
        check=$(create_check_json \
            "nginx.keepalive_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.keepalive_timeout_high' 2>/dev/null || echo 'keepalive_timeout too high')" \
            "keepalive_timeout=$kt_raw (recommended: ≤30s; nginx default 75s)" \
            "$(i18n 'nginx.fix_dos_keepalive' 2>/dev/null || echo 'Set keepalive_timeout 30s; in /etc/nginx/nginx.conf')" \
            "")
        state_add_check "$check"
        issues+=("keepalive_timeout=$kt_raw")
        print_severity "low" "$(i18n 'nginx.keepalive_timeout_high' 2>/dev/null || echo 'keepalive_timeout too high'): $kt_raw"
    fi

    # 4. send_timeout — default 60s, recommended ≤10s.
    local st_raw st
    st_raw=$(_nginx_get_directive_value "$effective" "send_timeout" "60s")
    st=$(_nginx_parse_seconds "$st_raw")
    if (( st > 10 )); then
        check=$(create_check_json \
            "nginx.send_timeout_high" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.send_timeout_high' 2>/dev/null || echo 'send_timeout too high')" \
            "send_timeout=$st_raw (recommended: ≤10s; nginx default 60s)" \
            "$(i18n 'nginx.fix_dos_timeouts' 2>/dev/null || echo 'Set send_timeout 10s; in /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("send_timeout=$st_raw")
        print_severity "low" "$(i18n 'nginx.send_timeout_high' 2>/dev/null || echo 'send_timeout too high'): $st_raw"
    fi

    # 5. Rate limiting presence — no severity escalation: many static
    # / internal sites legitimately don't need it. Recorded as low.
    if ! _nginx_has_directive "$effective" "limit_req_zone"; then
        check=$(create_check_json \
            "nginx.no_rate_limiting" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.no_rate_limiting' 2>/dev/null || echo 'No rate limiting configured (no limit_req_zone)')" \
            "No limit_req_zone directive in effective config — public-facing nginx benefits from per-IP request rate caps to throttle brute-force and scraping attacks" \
            "$(i18n 'nginx.fix_dos_rate_limit' 2>/dev/null || echo 'Add: limit_req_zone \$binary_remote_addr zone=perip:10m rate=10r/s; to nginx.conf http block, then apply per-location with limit_req zone=perip burst=20 nodelay;')" \
            "")
        state_add_check "$check"
        issues+=("no_rate_limiting")
        print_severity "low" "$(i18n 'nginx.no_rate_limiting' 2>/dev/null || echo 'No rate limiting configured')"
    fi

    # 6. reset_timedout_connection — default off, nginx mitigation guide
    # explicitly recommends "on" to close lingering misbehaving clients.
    local rtc
    rtc=$(_nginx_get_directive_value "$effective" "reset_timedout_connection" "off")
    if [[ "$rtc" != "on" ]]; then
        check=$(create_check_json \
            "nginx.reset_timedout_connection_off" \
            "nginx" \
            "low" \
            "failed" \
            "$(i18n 'nginx.reset_timedout_connection_off' 2>/dev/null || echo 'reset_timedout_connection not enabled')" \
            "reset_timedout_connection is off (nginx default). Enabling forcibly closes connections with misbehaving / slow clients, accelerating slowloris recovery" \
            "$(i18n 'nginx.fix_dos_reset_timedout' 2>/dev/null || echo 'Add: reset_timedout_connection on; to /etc/nginx/nginx.conf http block')" \
            "")
        state_add_check "$check"
        issues+=("reset_timedout_connection=off")
        print_severity "low" "$(i18n 'nginx.reset_timedout_connection_off' 2>/dev/null || echo 'reset_timedout_connection not enabled')"
    fi

    # Positive companion — only when EVERY directive met the threshold.
    if (( ${#issues[@]} == 0 )); then
        check=$(create_check_json \
            "nginx.dos_hardening_ok" \
            "nginx" \
            "low" \
            "passed" \
            "$(i18n 'nginx.dos_hardening_ok' 2>/dev/null || echo 'DoS hardening directives configured')" \
            "client_header/body/send_timeout, keepalive_timeout, rate limiting, and reset_timedout_connection all match CIS / nginx-mitigation recommendations" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'nginx.dos_hardening_ok' 2>/dev/null || echo 'DoS hardening directives configured')"
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

# The catchall config text, as a function so the certificate paths come from
# the module variables and the fix is testable against a scratch tree. The
# heredoc EXPANDS, so no backslash continuations: they glue lines together.
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

    # Checked FIRST, before anything is written: a sites-available config
    # nothing links to is never read, so every later step would succeed while
    # the catchall is not live. Refuse, and print the include line instead.
    if [[ ! -d "$NGINX_SITES_ENABLED" ]]; then
        print_error "$(i18n 'nginx.sites_enabled_missing' "dir=$NGINX_SITES_ENABLED")"
        print_info "$(i18n 'nginx.sites_enabled_hint' "dir=$NGINX_SITES_ENABLED")"
        log_error "nginx.add_catchall: $NGINX_SITES_ENABLED does not exist; refusing to stage a config nothing would read"
        return 1
    fi

    # These decide what the validation-failure path may delete. -L, not -e,
    # for the link: -e follows it and answers about the TARGET, so a dangling
    # link reads as absent and would then be deleted.
    local conf_existed=0 link_existed=0
    [[ -e "$NGINX_CATCHALL_CONF" ]] && conf_existed=1
    [[ -L "$NGINX_CATCHALL_LINK" || -e "$NGINX_CATCHALL_LINK" ]] && link_existed=1

    # UNCONDITIONAL: recording an absent path in .vpssec_created is the only
    # thing that lets a rollback delete what this fix creates, and on a first
    # run — the common case — none of these exist yet.
    backup_file "$NGINX_CATCHALL_CONF" >/dev/null || return 1
    # write_file_atomic creates the parent directory and reports its own
    # failures, so no separate mkdir with a status to discard.
    if ! write_file_atomic "$NGINX_CATCHALL_CONF" "$(_nginx_catchall_config)"; then
        print_error "$(i18n 'nginx.catchall_write_failed' "file=$NGINX_CATCHALL_CONF")"
        return 1
    fi

    if ! _nginx_ensure_catchall_cert; then
        return 1
    fi

    # The symlink is deliberately NOT registered for rollback: a created path
    # that is a symlink counts as skipped and drags a complete rollback to
    # "partial". Print and log the undo command instead.
    if ! ln -sfn "$NGINX_CATCHALL_CONF" "$NGINX_CATCHALL_LINK" 2>/dev/null; then
        print_error "$(i18n 'nginx.symlink_failed' "link=$NGINX_CATCHALL_LINK")"
        return 1
    fi
    local revert="rm -f $NGINX_CATCHALL_LINK"
    print_info "$(i18n 'nginx.symlink_revert_hint' "cmd=$revert")"
    log_info "nginx.add_catchall revert command: $revert"

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
        (( link_existed )) || rm -f "$NGINX_CATCHALL_LINK"
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

    # Postcondition via the audit's own question: `nginx -t` says the config
    # parses and the reload says it loaded, but neither says this host now
    # has a catchall on both ports.
    local state
    state=$(_nginx_catchall_state)
    if [[ "$state" != "both" ]]; then
        print_error "$(i18n 'nginx.catchall_postcondition_failed' "state=$state")"
        return 1
    fi
    return 0
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
