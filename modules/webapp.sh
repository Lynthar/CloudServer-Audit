#!/usr/bin/env bash
# Web application security: nginx, Apache, PHP, SSL/TLS and sensitive-file
# exposure. Some fixes auto-apply; others write a template the operator must
# wire in and are listed in FIX_TEMPLATE_ONLY.

# --- Configuration ---

# Nginx configuration paths the fixes write to. The audit reads nginx -T
# (core nginx_dump_load), which finds the config wherever nginx keeps it.
NGINX_CONF="/etc/nginx/nginx.conf"
NGINX_CONFD="/etc/nginx/conf.d"
# Snippets are NOT auto-included, unlike conf.d/*. SSL directives belong in a
# server{} block, and writing them to conf.d duplicates what nginx.conf already
# sets in http{} — a "duplicate directive" emerg on the next reload.
NGINX_SNIPPETS="/etc/nginx/snippets"

# Apache configuration paths
APACHE_CONF="/etc/apache2/apache2.conf"
APACHE_CONF_ALT="/etc/httpd/conf/httpd.conf"
APACHE_MODS_ENABLED="/etc/apache2/mods-enabled"
APACHE_SITES_ENABLED="/etc/apache2/sites-enabled"
# Where Apache includes *.conf from after the main file, in that order.
APACHE_CONF_DIRS="/etc/apache2/conf-enabled /etc/apache2/conf.d /etc/httpd/conf.d"

# SERVER certificate paths only. /etc/ssl/certs is deliberately absent: it is
# the package-managed CA trust store, where expired roots are normal and not
# an operator action. _webapp_cert_is_ca guards CA certs found here.
SSL_CERT_PATHS=(
    "/etc/nginx/ssl"
    "/etc/letsencrypt/live"
    "/etc/apache2/ssl"
    "/etc/pki/tls/certs"       # RHEL-family: httpd's localhost.crt lives here
)

# Web root directories
WEB_ROOTS=(
    "/var/www/html"
    "/var/www"
    "/usr/share/nginx/html"
    "/home/*/public_html"
)

# Files that should not be reachable in a web root, matched by name. HIGH: they
# hold secrets or open an admin interface; MEDIUM: they only disclose information.
SENSITIVE_HIGH_PATHS=(
    ".git"
    ".svn"
    ".env"
    ".env.local"
    ".env.production"
    ".htpasswd"
    "wp-config.php.bak"
    "config.php.bak"
    "backup.sql"
    "dump.sql"
    "database.sql"
    "adminer.php"
    # Not composer.json / package.json (manifests, routine in a web root) nor
    # .htaccess (every WordPress / Laravel site ships one; deleting it, as the old
    # suggestion said, breaks its routes): flagged, they diluted the entries above.
)
SENSITIVE_MEDIUM_PATHS=(
    "phpinfo.php"
    "info.php"
    "test.php"
    ".DS_Store"
    "Thumbs.db"
)
SENSITIVE_PATHS=("${SENSITIVE_HIGH_PATHS[@]}" "${SENSITIVE_MEDIUM_PATHS[@]}")

# Nginx security headers the audit asks every site for, and the value the fix
# sends where one is missing. X-XSS-Protection 0 turns the legacy XSS auditor
# off, as OWASP advises: where it survives, "1; mode=block" can open XSS.
declare -gA NGINX_SECURITY_HEADERS=(
    ["X-Frame-Options"]="SAMEORIGIN"
    ["X-Content-Type-Options"]="nosniff"
    ["X-XSS-Protection"]="0"
    ["Referrer-Policy"]="strict-origin-when-cross-origin"
)

# Seconds the headers check may spend on requests in one audit; sites left
# when it runs out are reported as not checked instead of holding the audit up.
WEBAPP_PROBE_BUDGET=60

# Weak SSL protocols
WEAK_SSL_PROTOCOLS=(
    "SSLv2"
    "SSLv3"
    "TLSv1"
    "TLSv1.0"
    "TLSv1.1"
)

# Weak cipher patterns
WEAK_CIPHER_PATTERNS=(
    "DES"
    "3DES"
    "RC4"
    "MD5"
    "NULL"
    "EXPORT"
    "anon"
    "SEED"
    "IDEA"
    "PSK"
)

# Apache dangerous modules
APACHE_DANGEROUS_MODULES=(
    "mod_info"
    "mod_status"
    "mod_userdir"
    "mod_autoindex"
)

# PHP dangerous functions
PHP_DANGEROUS_FUNCTIONS=(
    "exec"
    "passthru"
    "shell_exec"
    "system"
    "proc_open"
    "popen"
    "curl_exec"
    "curl_multi_exec"
    "show_source"
    "phpinfo"
    "eval"
    "assert"
    "create_function"
)

# Certificate expiry warning threshold (days)
CERT_EXPIRY_WARNING_DAYS=30

# --- Helper Functions ---

# Web servers this module does NOT audit, but whose presence makes "no web
# server detected" a false statement about the host. Detected by binary only:
# the point is not to audit them, but to stop claiming the host serves nothing.
_webapp_other_webserver() {
    local found=() candidate
    for candidate in caddy openresty lighttpd traefik haproxy; do
        # check_command + `if` rather than `command -v ... &&`: see the note in
        # docker.sh's _docker_unaudited_runtime. Same two reasons — steerable
        # from a test, and no non-zero status left lying around.
        if check_command "$candidate"; then found+=("$candidate"); fi
    done
    printf '%s' "${found[*]:-}"
}

_webapp_apache_installed() {
    (command -v apache2 &>/dev/null || command -v httpd &>/dev/null) && \
    ([[ -f "$APACHE_CONF" ]] || [[ -f "$APACHE_CONF_ALT" ]])
}

# Is PHP installed, as CLI or FPM? Production PHP typically ships only
# php-fpm with no CLI binary, so `command -v php` alone skips the entire
# audit exactly where it matters most.
_webapp_php_installed() {
    [[ -n "$(_webapp_php_bins)" ]] && return 0
    # FPM ini files exist whenever any php<ver>-fpm package is installed.
    compgen -G '/etc/php/*/fpm/php.ini' >/dev/null 2>&1 && return 0
    return 1
}

# Enumerate FPM php.ini files (one per installed PHP version).
# Returns absolute paths, one per line. Empty output if no FPM install.
_webapp_list_fpm_inis() {
    local ini
    for ini in /etc/php/*/fpm/php.ini; do
        [[ -f "$ini" ]] && printf '%s\n' "$ini"
    done
}

# Read one php.ini directive from the file plus its conf.d/, with PHP's
# last-occurrence-wins semantics. Args: <key> <main php.ini>.
_webapp_read_ini_directive() {
    local key="$1"
    local ini_file="$2"
    local conf_d="${ini_file%/*}/conf.d"
    grep -hE "^[[:space:]]*${key}[[:space:]]*=" \
        "$ini_file" "$conf_d"/*.ini 2>/dev/null | \
        tail -1 | \
        sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//; s/^"(.*)"$/\1/; s/^'\''(.*)'\''$/\1/'
}

# FPM pool overrides for a directive: php_admin_value / php_admin_flag force,
# php_value / php_flag allow runtime override (flag is the boolean form). The
# LAST value across all pools wins: one weakened pool exposes the host.
_webapp_read_pool_directive() {
    local key="$1"
    local fpm_ini="$2"
    local pool_d="${fpm_ini%/*}/pool.d"
    [[ -d "$pool_d" ]] || return 0
    grep -hE "^[[:space:]]*php_(admin_)?(value|flag)\[${key}\][[:space:]]*=" \
        "$pool_d"/*.conf 2>/dev/null | \
        tail -1 | \
        sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//; s/^"(.*)"$/\1/; s/^'\''(.*)'\''$/\1/'
}

# Effective PHP value for a directive. NEVER read it from `php -i`: that is
# the CLI SAPI, independent of the FPM SAPI that serves web requests. With FPM
# present this walks each FPM php.ini, then conf.d, then pool.d, last winning.
_webapp_get_php_config() {
    local key="$1"
    local result=""
    local found_fpm=0

    local ini
    while IFS= read -r ini; do
        [[ -z "$ini" ]] && continue
        found_fpm=1
        local v
        # Base value from php.ini + conf.d.
        v=$(_webapp_read_ini_directive "$key" "$ini")
        [[ -n "$v" ]] && result="$v"
        # Pool overrides (php_admin_value / php_value) win over base.
        local pool_v
        pool_v=$(_webapp_read_pool_directive "$key" "$ini")
        [[ -n "$pool_v" ]] && result="$pool_v"
    done < <(_webapp_list_fpm_inis)

    # Fallback: only when no FPM install was detected. We deliberately
    # do NOT mix CLI output with FPM output — that would let CLI
    # settings mask FPM weaknesses on hosts where both exist.
    if (( found_fpm == 0 )) && command -v php &>/dev/null; then
        result=$(php -i 2>/dev/null | grep -i "^$key" | head -1 | \
            awk -F'=>' '{print $2}' | tr -d ' ')
    fi

    echo "$result"
}

# --- Nginx Security Check Functions ---
# Each reads NGINX_DUMP, which webapp_audit (or the predicate) has loaded.

# server{} blocks whose effective server_tokens is not off, by name: their own
# value, else the http{} one, else nginx's default of on; or on in a location.
_webapp_nginx_server_tokens() {
    nginx_statements <<<"$NGINX_DUMP" | awk -F'\t' '
        $1 == 0 && $2 == "http" && $3 == "server_tokens" { top = $4; next }
        $1 == 0 || $2 !~ /^http\/server/ { next }
        { srv[$1] = 1 }
        $2 == "http/server" && $3 == "server_name" && !($1 in name) { split($4, w, " "); name[$1] = w[1] }
        $2 == "http/server" && $3 == "server_tokens" { own[$1] = $4; next }
        $3 == "server_tokens" && $4 != "off" { leak[$1] = 1 }
        END {
            for (s in srv) {
                v = (s in own) ? own[s] : (top != "" ? top : "on")
                if (v != "off" || (s in leak)) print s "\t" ((s in name) ? name[s] : "_")
            }
        }
    ' | sort -n | cut -f2
}

# The http servers the headers check requests, one per line: "url\t<url>\t<curl --resolve
# entry, or ->\t<own: it sets add_header itself, or ->", or "unchecked\t<name>\t<listen|name>"
# for one this host cannot address. One with ssl_reject_handshake on serves no page.
_webapp_nginx_header_targets() {
    nginx_statements <<<"$NGINX_DUMP" | LC_ALL=C awk -F'\t' '
        # A listen spec into A (address to connect to), P (port) and K (the
        # socket it names); 0 when it is not a TCP address of this host.
        function parse(spec,   i, a) {
            if (spec ~ /^unix:/) return 0
            if (spec ~ /^\[/) {
                i = index(spec, "]"); a = substr(spec, 2, i - 2); P = substr(spec, i + 1)
                P = (P ~ /^:/) ? substr(P, 2) : "80"
                K = "[" a "]:" P
                A = (a == "::") ? "::1" : a
            } else {
                if (spec ~ /^[0-9]+$/) { a = "*"; P = spec }
                else if (i = index(spec, ":")) { a = substr(spec, 1, i - 1); P = substr(spec, i + 1) }
                else { a = spec; P = "80" }
                if (a == "0.0.0.0") a = "*"
                K = a ":" P
                A = (a == "*" || a == "localhost") ? "127.0.0.1" : a
            }
            return P ~ /^[0-9]+$/ && (A ~ /^[0-9.]+$/ || A ~ /:/)
        }
        $2 ~ /^http\/server(\/|$)/ { seen[$1] = 1; if ($1 > last) last = $1 }
        $2 != "http/server" { next }
        $3 == "listen" { L[$1, ++nl[$1]] = $4 }
        $3 == "server_name" { names[$1] = names[$1] " " $4 }
        $3 == "ssl" && $4 == "on" { sslon[$1] = 1 }
        $3 == "ssl_reject_handshake" && $4 == "on" { reject[$1] = 1 }
        $3 == "add_header" { own[$1] = 1 }
        END {
            # A request with no matching name goes to the default_server of its
            # socket, else to the first server that listens there.
            for (s = 1; s <= last; s++) {
                if (!(s in seen)) continue
                if (!nl[s]) L[s, ++nl[s]] = "80"
                for (i = 1; i <= nl[s]; i++) {
                    n = split(L[s, i], w, " ")
                    if (!parse(w[1])) continue
                    if (!(K in first)) first[K] = s
                    for (j = 2; j <= n; j++) if (w[j] == "default_server" || w[j] == "default") dflt[K] = s
                }
            }
            for (s = 1; s <= last; s++) {
                if (!(s in seen) || (s in reject)) continue
                best = 0
                for (i = 1; i <= nl[s]; i++) {
                    n = split(L[s, i], w, " ")
                    tls = (s in sslon); bad = 0
                    for (j = 2; j <= n; j++) {
                        if (w[j] == "ssl") tls = 1
                        else if (w[j] == "quic" || w[j] == "proxy_protocol") bad = 1
                    }
                    if (bad || !parse(w[1])) continue
                    score = (tls ? 2 : 0) + (A ~ /:/ ? 1 : 2)
                    if (score > best) { best = score; bA = A; bP = P; bK = K; bT = tls }
                }
                name = ""; label = ""
                m = split(names[s], w, " ")
                for (j = 1; j <= m; j++) {
                    if (label == "") label = w[j]
                    if (name == "" && w[j] != "_" && w[j] !~ /^~/ && w[j] !~ /\*/) { name = w[j]; sub(/^\./, "", name) }
                }
                if (label == "") { split(L[s, 1], w, " "); label = w[1] }
                if (!best) { print "unchecked\t" label "\tlisten"; continue }
                addr = (bA ~ /:/) ? "[" bA "]" : bA
                if (name == "") {
                    if (((bK in dflt) ? dflt[bK] : first[bK]) != s) { print "unchecked\t" label "\tname"; continue }
                    host = addr; resolve = "-"
                } else {
                    host = name; resolve = name ":" bP ":" addr
                }
                print "url\t" (bT ? "https" : "http") "://" host (bP == (bT ? "443" : "80") ? "" : ":" bP) "/\t" resolve "\t" ((s in own) ? "own" : "-")
            }
        }
    '
}

# Print the lowercased names of the headers $1 answers with (curl --resolve $2,
# or -), comma-joined, following same-origin redirects up to three. 0 = a page;
# 1 = no page (empty reply, redirect elsewhere); 2 = curl failed, its code printed.
_webapp_probe_headers() {
    local url="$1" origin="" out rc hops=0 code location names
    local -a opts=(-gsk -o /dev/null -D - -A vpssec --connect-timeout 2 --max-time 5)
    [[ "$2" == - ]] || opts+=(--resolve "$2")
    [[ "$url" =~ ^[a-z]+://[^/]+ ]] && origin="${BASH_REMATCH[0]}"
    while :; do
        rc=0
        out=$(curl "${opts[@]}" "$url" 2>/dev/null) || rc=$?
        (( rc != 52 )) || return 1
        (( rc == 0 )) || { echo "$rc"; return 2; }
        { read -r code; read -r location; read -r names; } < <(LC_ALL=C awk '
            { sub(/\r$/, "") }
            /^HTTP\// { split($0, f, " "); code = f[2]; loc = ""; names = ""; next }
            (i = index($0, ":")) > 1 {
                n = tolower(substr($0, 1, i - 1))
                if (n == "location") { loc = substr($0, i + 1); sub(/^[ \t]+/, "", loc) }
                names = names (names == "" ? "" : ",") n
            }
            END { print code; print loc; print names }
        ' <<<"$out")
        if [[ "$code" != 3[0-9][0-9] || -z "$location" ]]; then
            echo "$names"
            return 0
        fi
        (( ++hops <= 3 )) || return 1
        [[ "$location" == //* ]] && location="${origin%%//*}$location"
        if [[ "$location" == /* ]]; then
            url="$origin$location"
        elif [[ "${location,,}" == "${origin,,}" || "${location,,}" == "${origin,,}"/* ]]; then
            url="$location"
        else
            return 1
        fi
    done
}

# One line per http server: "ok\t<url>", "missing\t<url>\t<headers>" ("own" from a server
# whose own add_header keeps http{}'s out), or "unchecked\t<url or name>\t<reason>" (listen,
# name, curl, budget, or curl's exit code). A server that answers with no page is left out.
_webapp_nginx_header_results() {
    local kind where how own out rc header joined deadline=$((SECONDS + WEBAPP_PROBE_BUDGET))
    local -a keys=() missing=()
    mapfile -t keys < <(printf '%s\n' "${!NGINX_SECURITY_HEADERS[@]}" | LC_ALL=C sort)
    while IFS=$'\t' read -r kind where how own; do
        if [[ "$kind" == unchecked ]]; then
            printf 'unchecked\t%s\t%s\n' "$where" "$how"
            continue
        elif (( SECONDS >= deadline )); then
            printf 'unchecked\t%s\tbudget\n' "$where"
            continue
        fi
        rc=0
        out=$(_webapp_probe_headers "$where" "$how") || rc=$?
        case "$rc" in
            0) ;;
            1) continue ;;
            *) printf 'unchecked\t%s\t%s\n' "$where" "$out"; continue ;;
        esac
        missing=()
        for header in "${keys[@]}"; do
            [[ ",$out," == *",${header,,},"* ]] || missing+=("$header")
        done
        if (( ${#missing[@]} == 0 )); then
            printf 'ok\t%s\n' "$where"
        else
            printf -v joined '%s, ' "${missing[@]}"
            kind=missing
            [[ "$own" == own ]] && kind=own
            printf '%s\t%s\t%s\n' "$kind" "$where" "${joined%, }"
        fi
    done < <(_webapp_nginx_header_targets)
}

# Header names (lowercased) the operator's own add_header sets in http{}, leaving
# out the drop-in at $1, which the headers fix rewrites.
_webapp_nginx_http_headers() {
    OWN="$1" LC_ALL=C awk '
        /^# configuration file .*:$/ { skip = (substr($0, 22, length($0) - 22) == ENVIRON["OWN"]) }
        !skip
    ' <<<"$NGINX_DUMP" | nginx_statements | LC_ALL=C awk -F'\t' '
        $1 == 0 && $2 == "http" && $3 == "add_header" { split($4, w, " "); print tolower(w[1]) }
    '
}

# Pass conditions of the two checks above, re-read: a re-check after a fix must
# see the new config, not the audit-time dump.
_webapp_nginx_server_tokens_ok() {
    nginx_dump_reset
    nginx_dump_load || return 1
    [[ -z "$(_webapp_nginx_server_tokens)" ]]
}

# No site the drop-in reaches lacks a header, and one was seen with all of them.
# nginx's reload returns before its new workers take over, so a request right
# after a fix can still meet the old configuration: ask again before failing.
_webapp_nginx_security_headers_ok() {
    local try results
    for try in 1 2 3; do
        nginx_dump_reset
        nginx_dump_load || return 1
        results=$(_webapp_nginx_header_results)
        if ! grep -q $'^missing\t' <<<"$results"; then
            grep -q $'^ok\t' <<<"$results"
            return
        fi
        (( try == 3 )) || sleep 1
    done
    return 1
}

# HSTS: missing / weak (no `always`, so error responses go without it) /
# configured. Asked only where a TLS server exists: HSTS on plain HTTP is ignored.
_webapp_nginx_hsts() {
    nginx_statements <<<"$NGINX_DUMP" | awk -F'\t' '
        $3 == "add_header" {
            n = split($4, w, " ")
            if (tolower(w[1]) == "strict-transport-security") { seen = 1; if (w[n] == "always") always = 1 }
        }
        END { print (!seen ? "missing" : always ? "configured" : "weak") }
    '
}

_webapp_nginx_directory_listing() {
    nginx_statements <<<"$NGINX_DUMP" | awk -F'\t' '$3 == "autoindex" && $4 == "on" { print "autoindex on"; exit }'
}

# Servers speaking TLS (a listen with ssl or quic, or the old `ssl on`), one per
# line: "<name>\t<protocols>\t<from>\t<ciphers>\t<from>", <from> being where the
# value is set (server, http, stream); "-" stands for unset in either field.
_webapp_nginx_tls_servers() {
    nginx_statements <<<"$NGINX_DUMP" | awk -F'\t' '
        $1 == 0 && ($2 == "http" || $2 == "stream") && ($3 == "ssl_protocols" || $3 == "ssl_ciphers") { top[$2, $3] = $4; next }
        $1 == 0 || $2 !~ /^(http|stream)\/server/ { next }
        { kind[$1] = substr($2, 1, index($2, "/") - 1) }
        $2 !~ /\/server$/ { next }
        $3 == "listen" && (" " $4 " ") ~ / (ssl|quic) / { tls[$1] = 1 }
        $3 == "ssl" && $4 == "on" { tls[$1] = 1 }
        $3 == "server_name" && !($1 in name) { split($4, w, " "); name[$1] = w[1] }
        $3 == "ssl_protocols" || $3 == "ssl_ciphers" { own[$1, $3] = $4 }
        END {
            split("ssl_protocols ssl_ciphers", keys, " ")
            for (s in tls) {
                line = s "\t" ((s in name) ? name[s] : "_")
                for (d = 1; d <= 2; d++) {
                    if ((s, keys[d]) in own)               line = line "\t" own[s, keys[d]] "\tserver"
                    else if ((kind[s], keys[d]) in top)    line = line "\t" top[kind[s], keys[d]] "\t" kind[s]
                    else                                   line = line "\t-\t-"
                }
                print line
            }
        }
    ' | sort -n | cut -f2-
}

# One finding line per TLS server: what it allows, and where that is set when
# the server inherits it, since that is the line the operator must change.
_webapp_tls_finding() {
    local server="$1" items="$2" from="$3"
    if [[ "$from" == server ]]; then
        i18n 'webapp.f_tls_server' "server=$server" "items=$items"
    else
        i18n 'webapp.f_tls_inherited' "server=$server" "items=$items" "block=$from"
    fi
}

# TLS servers allowing a protocol in WEAK_SSL_PROTOCOLS, one finding line each.
_webapp_nginx_ssl_protocols() {
    local name protos pfrom _c _cf tok wl weak
    while IFS=$'\t' read -r name protos pfrom _c _cf; do
        [[ "$protos" == - ]] && continue
        weak=()
        # Each token compared EXACTLY: a substring match makes the weak
        # "TLSv1" match "TLSv1.2", flagging every correctly hardened server.
        for tok in $protos; do
            for wl in "${WEAK_SSL_PROTOCOLS[@]}"; do
                [[ "${tok,,}" == "${wl,,}" ]] && weak+=("$wl")
            done
        done
        (( ${#weak[@]} )) || continue
        _webapp_tls_finding "$name" "$(printf '%s, ' "${weak[@]}" | sed 's/, $//')" "$pfrom"
    done < <(_webapp_nginx_tls_servers)
}

# TLS servers whose cipher list offers a WEAK_CIPHER_PATTERNS entry.
_webapp_nginx_ssl_ciphers() {
    local name _p _pf ciphers cfrom filtered pat weak
    while IFS=$'\t' read -r name _p _pf ciphers cfrom; do
        [[ "$ciphers" == - ]] && continue
        # Excluded tokens are dropped first: OpenSSL uses `!FOO` / `-FOO` to
        # REMOVE a cipher, so a hardened list that disables MD5 and RC4 would
        # otherwise match as though it offered them.
        filtered=$(tr ':' '\n' <<<"$ciphers" | grep -vE '^[!-]' | paste -sd':' -)
        weak=()
        for pat in "${WEAK_CIPHER_PATTERNS[@]}"; do
            grep -qi -- "$pat" <<<"$filtered" && weak+=("$pat")
        done
        (( ${#weak[@]} )) || continue
        _webapp_tls_finding "$name" "$(printf '%s, ' "${weak[@]}" | sed 's/, $//')" "$cfrom"
    done < <(_webapp_nginx_tls_servers)
}

# --- Apache Security Check Functions ---

# Get Apache main configuration file (single-file callers)
_webapp_get_apache_conf() {
    [[ -f "$APACHE_CONF" ]] && echo "$APACHE_CONF" && return
    [[ -f "$APACHE_CONF_ALT" ]] && echo "$APACHE_CONF_ALT" && return
    echo ""
}

# Every Apache config where the global hardening directives may live. On
# Debian they are conventionally in conf-enabled/security.conf, not
# apache2.conf. Main file first, includes after — later includes win.
_webapp_apache_conf_files() {
    local files=()
    [[ -f "$APACHE_CONF" ]] && files+=("$APACHE_CONF")
    [[ -f "$APACHE_CONF_ALT" ]] && files+=("$APACHE_CONF_ALT")
    local d f
    for d in $APACHE_CONF_DIRS; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.conf; do
            [[ -f "$f" ]] && files+=("$f")
        done
    done
    printf '%s\n' "${files[@]}"
}

# The file to tell the operator to edit for global directive $1: the last one
# that sets it, since a later file overrides an earlier one, else the main file.
_webapp_apache_setting_file() {
    local f last=""
    while IFS= read -r f; do
        grep -qiE "^[^#]*$1[[:space:]]" "$f" 2>/dev/null && last="$f"
    done < <(_webapp_apache_conf_files)
    echo "${last:-$(_webapp_get_apache_conf)}"
}

# The last uncommented value of Apache global directive $1 across the config
# files in the order Apache reads them (a later one overrides); empty if unset.
# Every global directive is read through here, so none judges differently.
_webapp_apache_directive() {
    local last="" f v
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        v=$(grep -ioP "^[^#]*$1\\s+\\K\\w+" "$f" 2>/dev/null | tail -1)
        [[ -n "$v" ]] && last="$v"
    done < <(_webapp_apache_conf_files)
    echo "$last"
}

# ServerSignature, lowercased; "default" (On) when unset.
_webapp_apache_server_signature() {
    local v
    v=$(_webapp_apache_directive ServerSignature)
    v="${v,,}"
    echo "${v:-default}"
}

# ServerTokens as written; Full, Apache's default, when unset.
_webapp_apache_server_tokens() {
    local v
    v=$(_webapp_apache_directive ServerTokens)
    echo "${v:-Full}"
}

# TraceEnable, lowercased; on, Apache's default, when unset.
_webapp_apache_trace() {
    local v
    v=$(_webapp_apache_directive TraceEnable)
    v="${v,,}"
    echo "${v:-on}"
}

# Check directory indexing
_webapp_apache_directory_index() {
    local findings=()
    local conf=$(_webapp_get_apache_conf)
    [[ -z "$conf" ]] && return

    if grep -q "Options.*Indexes" "$conf" 2>/dev/null; then
        if ! grep -q "Options.*-Indexes" "$conf" 2>/dev/null; then
            findings+=("$(i18n 'webapp.f_indexes_enabled' "file=$conf")")
        fi
    fi

    # Check sites-enabled
    if [[ -d "$APACHE_SITES_ENABLED" ]]; then
        for site in "$APACHE_SITES_ENABLED"/*; do
            [[ -f "$site" ]] || continue
            if grep -q "Options.*Indexes" "$site" 2>/dev/null; then
                if ! grep -q "Options.*-Indexes" "$site" 2>/dev/null; then
                    findings+=("$(i18n 'webapp.f_indexes_enabled' "file=$site")")
                fi
            fi
        done
    fi

    printf '%s\n' "${findings[@]}"
}

# Check dangerous modules
_webapp_apache_modules() {
    local dangerous=()

    if [[ -d "$APACHE_MODS_ENABLED" ]]; then
        for mod in "${APACHE_DANGEROUS_MODULES[@]}"; do
            local mod_name="${mod#mod_}"
            if [[ -f "$APACHE_MODS_ENABLED/${mod_name}.load" ]]; then
                dangerous+=("$mod")
            fi
        done
    fi

    # Alternative: check with apachectl
    if command -v apachectl &>/dev/null; then
        local loaded=$(apachectl -M 2>/dev/null)
        for mod in "${APACHE_DANGEROUS_MODULES[@]}"; do
            local mod_name="${mod#mod_}_module"
            if echo "$loaded" | grep -qi "$mod_name"; then
                if ! printf '%s\n' "${dangerous[@]}" | grep -q "$mod"; then
                    dangerous+=("$mod")
                fi
            fi
        done
    fi

    printf '%s\n' "${dangerous[@]}"
}

# --- PHP Security Check Functions ---

# Check expose_php
_webapp_php_expose() {
    local val=$(_webapp_get_php_config "expose_php")
    echo "${val:-On}"
}

# True when a PHP boolean ini value is enabled. PHP accepts On/True/Yes/1 in
# ANY case, so a case-sensitive comparison misreads it in both directions.
_webapp_php_is_true() {
    local v="${1,,}"
    [[ "$v" == "1" || "$v" == "on" || "$v" == "true" || "$v" == "yes" ]]
}

# Check display_errors
_webapp_php_display_errors() {
    local val=$(_webapp_get_php_config "display_errors")
    echo "${val:-Off}"
}

# Check allow_url_include
_webapp_php_allow_url_include() {
    local val=$(_webapp_get_php_config "allow_url_include")
    echo "${val:-Off}"
}

# Check open_basedir
_webapp_php_open_basedir() {
    local val=$(_webapp_get_php_config "open_basedir")
    echo "${val:-none}"
}

# The patch release that fixed php2shell (CVE-2026-109618 / 109619) on each
# branch, from PHP's 2026-10-21 notice. Older branches have no official fix.
declare -gA WEBAPP_PHP2SHELL_FIXED=([8.2]=35 [8.3]=36 [8.4]=27 [8.5]=12)

# True when PHP version $1 ("8.3.6", "8.1.2-1ubuntu2.22", "8.6.0RC3") is
# upstream-older than the fix. Distribution backports keep the old number.
_webapp_php2shell_affected() {
    [[ "$1" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]] || return 1
    local major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]} patch=${BASH_REMATCH[3]} rest=${BASH_REMATCH[4]}
    local fixed="${WEBAPP_PHP2SHELL_FIXED[$major.$minor]:-}"
    [[ -n "$fixed" ]] && return $(( patch < fixed ? 0 : 1 ))
    (( major < 8 || (major == 8 && minor < 2) )) && return 0
    # 8.6.0 took the fix in RC4; its earlier pre-releases do not have it.
    (( major == 8 && minor == 6 && patch == 0 )) && [[ "$rest" =~ ^(alpha|beta|RC[1-3]$) ]]
}

# Candidate PHP executables, one path per line: the CLI and FPM on PATH, and
# the versioned FPM binaries (php-fpm8.2, php-fpm7.4, ...).
_webapp_php_bins() {
    command -v php 2>/dev/null
    command -v php-fpm 2>/dev/null
    compgen -G '/usr/sbin/php-fpm*'
}

# "binary<TAB>version" for each PHP executable on the host, FPM and CLI, as
# its own -v reports it.
_webapp_php_versions() {
    local bin real v
    local -A seen=()
    while IFS= read -r bin; do
        [[ -x "$bin" ]] || continue
        real=$(readlink -f -- "$bin") || continue
        [[ -z "${seen[$real]:-}" ]] || continue
        seen[$real]=1
        v=$("$bin" -v 2>/dev/null | sed -n '1s/^PHP \([0-9][^ ]*\) .*/\1/p')
        [[ -n "$v" ]] && printf '%s\t%s\n' "$bin" "$v"
    done < <(_webapp_php_bins)
}

# PHP in php2shell's upstream range is an unscored note: a distribution may have
# backported the fix under the old number. It says how to confirm that, and
# whether the partial stopgap session.upload_progress.enabled=0 is set.
_webapp_audit_php2shell() {
    local bin v pkg hint confirm stopgap joined
    local -a found=() checks=()
    while IFS=$'\t' read -r bin v; do
        _webapp_php2shell_affected "$v" || continue
        if [[ "$v" =~ ^([0-7]|8\.[01])\. ]]; then
            found+=("$bin $v ($(i18n 'webapp.php2shell_no_fix'))")
        else
            found+=("$bin $v")
        fi
        if pkg=$(file_package_verified "$bin") \
           && hint=$(pkg_changelog_grep_hint "$pkg" 'CVE-2026-10961[89]') \
           && [[ " ${checks[*]} " != *" $hint "* ]]; then
            checks+=("$hint")
        fi
    done < <(_webapp_php_versions)
    (( ${#found[@]} )) || return 0

    if (( ${#checks[@]} )); then
        printf -v joined '%s; ' "${checks[@]}"
        confirm=$(i18n 'webapp.php2shell_confirm' "cmd=${joined%; }")
    else
        confirm=$(i18n 'webapp.php2shell_confirm_unknown')
    fi
    stopgap=$(_webapp_get_php_config session.upload_progress.enabled)
    if _webapp_php_is_true "${stopgap:-On}"; then
        stopgap=$(i18n 'webapp.php2shell_stopgap_on')
    else
        stopgap=$(i18n 'webapp.php2shell_stopgap_off')
    fi
    printf -v joined '%s; ' "${found[@]}"
    check_emit "webapp.php2shell" info failed \
        title="$(i18n 'webapp.php2shell')" \
        desc="$(i18n 'webapp.php2shell_desc' "versions=${joined%; }" "confirm=$confirm" "stopgap=$stopgap")" \
        suggestion="$(i18n 'webapp.php2shell_fix')"
    print_warn "$(i18n 'webapp.php2shell')"
}

# Missing entries in disable_functions, matched as comma-separated TOKENS.
# A substring match reports `popen` as disabled whenever `proc_open` is in
# the list, masking the real exposure.
_webapp_php_disable_functions() {
    local disabled=$(_webapp_get_php_config "disable_functions")
    local not_disabled=()

    for func in "${PHP_DANGEROUS_FUNCTIONS[@]}"; do
        # Match `func` as a whole token: at start-of-string OR after a
        # comma (with optional surrounding whitespace), and at
        # end-of-string OR before another comma/whitespace.
        if ! echo "$disabled" | grep -qiE "(^|,)[[:space:]]*${func}[[:space:]]*(,|$)"; then
            not_disabled+=("$func")
        fi
    done

    printf '%s\n' "${not_disabled[@]}"
}

# Check session security
_webapp_php_session_security() {
    local issues=()

    # session.cookie_httponly
    local httponly=$(_webapp_get_php_config "session.cookie_httponly")
    if ! _webapp_php_is_true "$httponly"; then
        issues+=("$(i18n 'webapp.f_php_not_enabled' "key=session.cookie_httponly")")
    fi

    # session.cookie_secure
    local secure=$(_webapp_get_php_config "session.cookie_secure")
    if ! _webapp_php_is_true "$secure"; then
        issues+=("$(i18n 'webapp.f_php_cookie_secure')")
    fi

    # session.use_strict_mode
    local strict=$(_webapp_get_php_config "session.use_strict_mode")
    if ! _webapp_php_is_true "$strict"; then
        issues+=("$(i18n 'webapp.f_php_not_enabled' "key=session.use_strict_mode")")
    fi

    printf '%s\n' "${issues[@]}"
}

# --- SSL/TLS Security Check Functions ---

# Is $1 a CA certificate? An expired CA is not an operator action item —
# trust stores are package-managed and intermediates are renewed by the ACME
# client. Needs OpenSSL 1.1.1+; older builds fall back to the text dump.
_webapp_cert_is_ca() {
    local cert="$1"
    local bc
    bc=$(openssl x509 -noout -ext basicConstraints -in "$cert" 2>/dev/null) || bc=""
    if [[ -z "$bc" ]]; then
        bc=$(openssl x509 -noout -text -in "$cert" 2>/dev/null \
             | grep -A1 'X509v3 Basic Constraints' || true)
    fi
    [[ "$bc" == *"CA:TRUE"* ]]
}

# Certificates nginx serves (ssl_certificate in NGINX_DUMP), one path per line.
# A relative path resolves against the main config file's directory, as nginx's
# own does; a path built from a variable cannot be known here and is skipped.
_webapp_nginx_served_certs() {
    [[ -n "$NGINX_DUMP" ]] || return 0
    local conf_dir
    conf_dir=$(sed -n '1s|^# configuration file \(.*\)/[^/]*:$|\1|p' <<<"$NGINX_DUMP")
    nginx_statements <<<"$NGINX_DUMP" | CONF_DIR="$conf_dir" awk -F'\t' '
        $3 == "ssl_certificate" && $4 !~ /[$]/ { print (($4 ~ /^\//) ? $4 : ENVIRON["CONF_DIR"] "/" $4) }
    ' | sort -u
}

# Days until certificate $1 expires, negative once it has; fails if unreadable.
_webapp_cert_days_left() {
    local expiry epoch
    expiry=$(openssl x509 -enddate -noout -in "$1" 2>/dev/null | cut -d= -f2)
    [[ -n "$expiry" ]] || return 1
    epoch=$(date -d "$expiry" +%s 2>/dev/null) || return 1
    echo $(( (epoch - $(date +%s)) / 86400 ))
}

# Check certificate expiry: every certificate nginx serves, CA:TRUE or not and
# wherever it lives (OpenSSL 3 makes `req -x509` self-signed ones CA:TRUE), then
# the server certificates under SSL_CERT_PATHS, CA ones skipped. Each once.
_webapp_ssl_cert_expiry() {
    local findings=() certs=() served=() cert dir days fp
    local -A seen=()
    mapfile -t served < <(_webapp_nginx_served_certs)
    certs=(${served[@]+"${served[@]}"})

    for dir in "${SSL_CERT_PATHS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' cert; do
            _webapp_cert_is_ca "$cert" && continue
            certs+=("$cert")
        # -L is required: Let's Encrypt exposes live/<domain>/*.pem as
        # SYMLINKS into archive/, so without it `-type f` rejects every
        # LE certificate, expired ones included.
        done < <(find -L "$dir" -maxdepth 3 \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" \) -type f -print0 2>/dev/null)
    done

    for cert in ${certs[@]+"${certs[@]}"}; do
        [[ -f "$cert" ]] || continue
        # By the first certificate's fingerprint, not the path: Let's Encrypt's
        # cert.pem and fullchain.pem both start with the same leaf.
        fp=$(openssl x509 -noout -fingerprint -sha256 -in "$cert" 2>/dev/null) || continue
        [[ -n "$fp" && -z "${seen[$fp]:-}" ]] || continue
        seen[$fp]=1
        days=$(_webapp_cert_days_left "$cert") || continue
        if (( days < 0 )); then
            findings+=("$cert|expired|$(( -days ))")
        elif (( days < CERT_EXPIRY_WARNING_DAYS )); then
            findings+=("$cert|expiring|$days")
        fi
    done

    printf '%s\n' "${findings[@]}"
}

# There is deliberately no self-signed-certificate check: `issuer == subject`
# is the definition of a root CA, so a directory walk would report the whole
# trust store. A real one must start from the cert the server actually serves.

# --- Sensitive File Exposure Check Functions ---

# The web roots that exist, one per line: WEB_ROOTS with its globs expanded.
_webapp_web_roots() {
    local pattern root
    for pattern in "${WEB_ROOTS[@]}"; do
        # shellcheck disable=SC2086 # WEB_ROOTS holds glob patterns to expand
        for root in $pattern; do
            if [[ -d "$root" ]]; then printf '%s\n' "$root"; fi
        done
    done
}

# Check for sensitive files in web roots
_webapp_sensitive_files() {
    local findings=() cut=0

    # One find name-expression, built once. Per-pattern finds also bypass
    # _fs_run_find and _FS_PRUNE_PATHS, which every walk must go through.
    local name_expr=()
    local first=1 path
    for path in "${SENSITIVE_PATHS[@]}"; do
        if (( first )); then
            name_expr+=( -name "$path" )
            first=0
        else
            name_expr+=( -o -name "$path" )
        fi
    done

    local prune_args=()
    _fs_build_prune_args prune_args

    local -a roots=()
    local root
    mapfile -t roots < <(_webapp_web_roots)
    for root in ${roots[@]+"${roots[@]}"}; do
        while IFS= read -r -d '' found; do
            [[ "$found" == *"$_FS_WALK_CUT" ]] && { cut=1; continue; }
            findings+=("$found")
        done < <(_fs_run_find "webapp-sensitive" \
            find "$root" -maxdepth 3 "${prune_args[@]}" \
            \( "${name_expr[@]}" \) -print0 2>/dev/null)
    done

    printf '%s\n' "${findings[@]}" | sort -u | head -50
    return "$cut"
}

# Check for backup files
_webapp_backup_files() {
    local findings=() cut=0

    local prune_args=()
    _fs_build_prune_args prune_args

    local -a roots=()
    local root
    mapfile -t roots < <(_webapp_web_roots)
    for root in ${roots[@]+"${roots[@]}"}; do
        # Common backup patterns
        while IFS= read -r -d '' file; do
            [[ "$file" == *"$_FS_WALK_CUT" ]] && { cut=1; continue; }
            findings+=("$file")
        done < <(_fs_run_find "webapp-backup" \
            find "$root" -maxdepth 4 "${prune_args[@]}" \( \
            -name "*.bak" -o \
            -name "*.backup" -o \
            -name "*.old" -o \
            -name "*~" -o \
            -name "*.save" -o \
            -name "*.orig" -o \
            -name "*.swp" -o \
            -name "*.sql" -o \
            -name "*.tar.gz" -o \
            -name "*.zip" \
        \) -type f -print0 2>/dev/null | head -30)
    done

    printf '%s\n' "${findings[@]}"
    return "$cut"
}

# --- Audit Function ---

# The nginx half of the audit, against the NGINX_DUMP webapp_audit loaded.
_webapp_audit_nginx() {
    # 1. Server tokens
    local server_tokens=$(_webapp_nginx_server_tokens)
    local tokens_count=$(count_lines "$server_tokens")

    if [[ -n "$server_tokens" && "$tokens_count" -gt 0 ]]; then
        check_emit "webapp.nginx_server_tokens" low failed \
            title="$(i18n 'webapp.nginx_version_exposed')" \
            desc="$(i18n 'webapp.nginx_server_tokens_desc')" \
            suggestion="$(i18n 'webapp.add_server_tokens_off')" \
            fix="webapp.nginx_server_tokens"
    else
        check_emit "webapp.nginx_server_tokens_ok" info passed \
            title="$(i18n 'webapp.nginx_version_hidden')" \
            desc="$(i18n 'webapp.nginx_server_tokens_ok_desc')"
    fi

    # 2. Security headers, as each site's response carries them: an application
    # behind proxy_pass may send them itself, which no nginx directive shows.
    local kind where what joined headers_ok=0 suggestion
    local -a headers_missing=() headers_own=() headers_unchecked=()
    while IFS=$'\t' read -r kind where what; do
        case "$kind" in
            missing) headers_missing+=("$where: $what") ;;
            own) headers_own+=("$where: $what ($(i18n 'webapp.headers_own_add_header'))") ;;
            ok) headers_ok=1 ;;
            unchecked)
                case "$what" in
                    listen) what=$(i18n 'webapp.headers_unchecked_listen') ;;
                    name) what=$(i18n 'webapp.headers_unchecked_name') ;;
                    budget) what=$(i18n 'webapp.headers_unchecked_budget') ;;
                    *) what=$(i18n 'webapp.headers_unchecked_failed' "rc=$what") ;;
                esac
                headers_unchecked+=("$where: $what") ;;
        esac
    done < <(_webapp_nginx_header_results)

    # The fix's drop-in sits in http{}: offered only where a site it reaches lacks one.
    if (( ${#headers_missing[@]} + ${#headers_own[@]} > 0 )); then
        local fix_id="webapp.nginx_security_headers"
        suggestion=$(i18n 'webapp.add_security_headers')
        if (( ${#headers_missing[@]} == 0 )); then
            fix_id=""
            suggestion=$(i18n 'webapp.add_security_headers_in_server')
        fi
        printf -v joined '%s; ' "${headers_missing[@]}" "${headers_own[@]}"
        check_emit "webapp.nginx_security_headers" low failed \
            title="$(i18n 'webapp.missing_security_headers' "count=$(( ${#headers_missing[@]} + ${#headers_own[@]} ))")" \
            desc="${joined%; }" \
            suggestion="$suggestion" \
            fix="$fix_id"
    elif (( headers_ok )); then
        check_emit "webapp.nginx_security_headers_ok" info passed \
            title="$(i18n 'webapp.security_headers_ok')" \
            desc="$(i18n 'webapp.nginx_security_headers_ok_desc')"
    fi
    if (( ${#headers_unchecked[@]} > 0 )); then
        printf -v joined '%s; ' "${headers_unchecked[@]}"
        check_emit "webapp.nginx_security_headers_not_checked" low failed \
            title="$(i18n 'webapp.security_headers_not_checked')" \
            desc="${joined%; }"
    fi

    # 3. Directory listing
    local dir_listing=$(_webapp_nginx_directory_listing)
    if [[ -n "$dir_listing" ]]; then
        check_emit "webapp.nginx_directory_listing" medium failed \
            title="$(i18n 'webapp.directory_listing_on')" \
            desc="$dir_listing" \
            suggestion="$(i18n 'webapp.disable_autoindex')"
    fi

    # TLS checks only where nginx serves TLS: Debian 12 and Ubuntu 22.04 / 24.04
    # ship weak protocols at http{} level, which matters only to a server that
    # inherits them, and HSTS means nothing on plain HTTP.
    [[ -n "$(_webapp_nginx_tls_servers)" ]] || return 0

    # 4. HSTS — three-way: missing / weak (no `always`) / configured.
    local hsts=$(_webapp_nginx_hsts)
    if [[ "$hsts" == "missing" ]]; then
        check_emit "webapp.nginx_hsts_missing" low failed \
            title="$(i18n 'webapp.hsts_missing')" \
            desc="$(i18n 'webapp.nginx_hsts_missing_desc')" \
            suggestion="$(i18n 'webapp.add_hsts')" \
            fix="webapp.nginx_hsts"
    elif [[ "$hsts" == "weak" ]]; then
        check_emit "webapp.nginx_hsts_weak" low failed \
            title="$(i18n 'webapp.hsts_weak')" \
            desc="$(i18n 'webapp.nginx_hsts_weak_desc')" \
            suggestion="$(i18n 'webapp.fix_hsts_always')" \
            fix="webapp.nginx_hsts"
    fi

    # 5. SSL protocols, per TLS server
    local weak_ssl=$(_webapp_nginx_ssl_protocols)
    local weak_ssl_count=$(count_lines "$weak_ssl")

    if [[ -n "$weak_ssl" && "$weak_ssl_count" -gt 0 ]]; then
        check_emit "webapp.nginx_weak_ssl" medium failed \
            title="$(i18n 'webapp.weak_ssl_protocols'): $weak_ssl_count" \
            desc="$(echo "$weak_ssl" | tr '\n' ';' | sed 's/;$//; s/;/; /g')" \
            suggestion="$(i18n 'webapp.disable_weak_ssl')" \
            fix="webapp.nginx_ssl_protocols"
    fi

    # 6. SSL ciphers, per TLS server
    local weak_ciphers=$(_webapp_nginx_ssl_ciphers)
    local weak_cipher_count=$(count_lines "$weak_ciphers")

    if [[ -n "$weak_ciphers" && "$weak_cipher_count" -gt 0 ]]; then
        check_emit "webapp.nginx_weak_ciphers" medium failed \
            title="$(i18n 'webapp.weak_ciphers'): $weak_cipher_count" \
            desc="$(echo "$weak_ciphers" | tr '\n' ';' | sed 's/;$//; s/;/; /g')" \
            suggestion="$(i18n 'webapp.update_ciphers')" \
            fix="webapp.nginx_ssl_ciphers"
    fi
}

webapp_audit() {
    log_info "Running web application security audit"

    local has_webserver=false
    _FS_CUT_WALKS=()

    # === Nginx Security ===
    # The binary alone says nginx is here, as for the nginx module: its config
    # may live anywhere, and nginx -T finds it.
    if nginx_present; then
        has_webserver=true
        print_item "$(i18n 'webapp.checking_nginx')"
        nginx_dump_reset
        if nginx_dump_load; then
            _webapp_audit_nginx
        else
            # As in the nginx module: one finding, and the audit is incomplete.
            check_emit "webapp.nginx_config_unreadable" info failed \
                desc="$(i18n 'nginx.config_unreadable_desc' "error=${NGINX_DUMP_ERROR:-nginx -t}")" \
                suggestion="$(i18n 'nginx.config_unreadable_fix')"
            _module_record_failure webapp query
        fi
    # A running nginx whose binary is not on PATH (a source build in
    # /usr/local/nginx/sbin) is not audited: say so, not "no web server".
    elif pgrep -x nginx >/dev/null 2>&1; then
        has_webserver=true
        check_emit "webapp.nginx_not_on_path" info failed \
            title="$(i18n 'webapp.nginx_not_on_path')" \
            desc="$(i18n 'webapp.nginx_not_on_path_desc')" \
            suggestion="$(i18n 'webapp.nginx_not_on_path_fix')"
    fi

    # === Apache Security ===
    if _webapp_apache_installed; then
        has_webserver=true
        print_item "$(i18n 'webapp.checking_apache')"

        # 7. ServerSignature
        local sig=$(_webapp_apache_server_signature)
        if [[ "$sig" != "off" ]]; then
            check_emit "webapp.apache_server_signature" low failed \
                title="$(i18n 'webapp.apache_signature_on')" \
                desc="$(i18n 'webapp.apache_server_signature_desc')" \
                suggestion="$(i18n 'webapp.set_signature_off' "conf=$(_webapp_apache_setting_file ServerSignature)")"
        fi

        # 8. ServerTokens
        local tokens=$(_webapp_apache_server_tokens)
        if [[ "$tokens" != "Prod" && "$tokens" != "ProductOnly" ]]; then
            check_emit "webapp.apache_server_tokens" low failed \
                title="$(i18n 'webapp.apache_tokens_verbose')" \
                desc="$(i18n 'webapp.apache_server_tokens_desc' "tokens=$tokens")" \
                suggestion="$(i18n 'webapp.set_tokens_prod' "conf=$(_webapp_apache_setting_file ServerTokens)")"
        fi

        # 9. TraceEnable
        local trace=$(_webapp_apache_trace)
        if [[ "$trace" != "off" ]]; then
            check_emit "webapp.apache_trace_enabled" low failed \
                title="$(i18n 'webapp.apache_trace_on')" \
                desc="$(i18n 'webapp.apache_trace_enabled_desc')" \
                suggestion="$(i18n 'webapp.disable_trace' "conf=$(_webapp_apache_setting_file TraceEnable)")"
        fi

        # 10. Directory indexing
        local dir_idx=$(_webapp_apache_directory_index)
        local dir_idx_count=$(count_lines "$dir_idx")

        if [[ -n "$dir_idx" && "$dir_idx_count" -gt 0 ]]; then
            check_emit "webapp.apache_directory_index" medium failed \
                title="$(i18n 'webapp.apache_indexes_on')" \
                desc="$(echo "$dir_idx" | tr '\n' '; ' | sed 's/;$//')" \
                suggestion="$(i18n 'webapp.disable_indexes')"
        fi

        # 11. Dangerous modules
        local danger_mods=$(_webapp_apache_modules)
        local danger_count=$(count_lines "$danger_mods")

        if [[ -n "$danger_mods" && "$danger_count" -gt 0 ]]; then
            check_emit "webapp.apache_dangerous_modules" low failed \
                title="$(i18n 'webapp.dangerous_modules'): $danger_count" \
                desc="$(echo "$danger_mods" | tr '\n' ', ' | sed 's/,$//')" \
                suggestion="$(i18n 'webapp.review_modules')"
        fi
    fi

    # === PHP Security ===
    if _webapp_php_installed; then
        print_item "$(i18n 'webapp.checking_php')"

        local php_issues=()

        # 12. expose_php
        local expose=$(_webapp_php_expose)
        if _webapp_php_is_true "$expose"; then
            php_issues+=("expose_php=On")
        fi

        # 13. display_errors
        local display=$(_webapp_php_display_errors)
        if _webapp_php_is_true "$display"; then
            php_issues+=("display_errors=On")
        fi

        # 14. allow_url_include
        local url_include=$(_webapp_php_allow_url_include)
        if _webapp_php_is_true "$url_include"; then
            php_issues+=("allow_url_include=On $(i18n 'webapp.f_dangerous')")
        fi

        if [[ ${#php_issues[@]} -gt 0 ]]; then
            check_emit "webapp.php_security_issues" medium failed \
                title="$(i18n 'webapp.php_security_issues'): ${#php_issues[@]}" \
                desc="$(printf '%s, ' "${php_issues[@]}" | sed 's/, $//')" \
                suggestion="$(i18n 'webapp.fix_php_settings')"
        fi

        # 15. Dangerous functions not disabled
        local not_disabled=$(_webapp_php_disable_functions)
        local not_disabled_count=$(count_lines "$not_disabled")

        if [[ -n "$not_disabled" && "$not_disabled_count" -gt 3 ]]; then
            check_emit "webapp.php_dangerous_functions" medium failed \
                title="$(i18n 'webapp.dangerous_functions'): $not_disabled_count" \
                desc="$(echo "$not_disabled" | head -5 | tr '\n' ', ' | sed 's/,$//')" \
                suggestion="$(i18n 'webapp.disable_functions')"
        fi

        # 16. Session security
        local session_issues=$(_webapp_php_session_security)
        local session_count=$(count_lines "$session_issues")

        if [[ -n "$session_issues" && "$session_count" -gt 0 ]]; then
            check_emit "webapp.php_session_security" low failed \
                title="$(i18n 'webapp.session_security'): $session_count" \
                desc="$(echo "$session_issues" | tr '\n' '; ' | sed 's/;$//')" \
                suggestion="$(i18n 'webapp.fix_session_settings')"
        fi

        # 17. open_basedir
        local basedir=$(_webapp_php_open_basedir)
        if [[ "$basedir" == "none" || -z "$basedir" ]]; then
            check_emit "webapp.php_open_basedir" low failed \
                title="$(i18n 'webapp.open_basedir_not_set')" \
                desc="$(i18n 'webapp.php_open_basedir_desc')" \
                suggestion="$(i18n 'webapp.set_open_basedir')"
        fi

        _webapp_audit_php2shell
    fi

    # === SSL/TLS Certificate Checks ===
    print_item "$(i18n 'webapp.checking_ssl')"

    # 18. Certificate expiry
    local expiring=$(_webapp_ssl_cert_expiry)
    local expiring_count=$(count_lines "$expiring" '|')

    if [[ -n "$expiring" && "$expiring_count" -gt 0 ]]; then
        local expired_list=""
        while IFS='|' read -r cert status days; do
            [[ -z "$cert" ]] && continue
            if [[ "$status" == "expired" ]]; then
                expired_list+="$cert ($(i18n 'webapp.f_days_ago' "n=$days")); "
            else
                expired_list+="$cert ($(i18n 'webapp.f_days_left' "n=$days")); "
            fi
        done <<< "$expiring"

        local severity="low"
        echo "$expiring" | grep -q "|expired|" && severity="medium"

        check_emit "webapp.ssl_cert_expiry" "$severity" failed \
            title="$(i18n 'webapp.cert_expiring'): $expiring_count" \
            desc="${expired_list%;*}" \
            suggestion="$(i18n 'webapp.renew_certs')"
    fi

    # === Sensitive File Exposure ===
    print_item "$(i18n 'webapp.checking_exposure')"

    # 19. Sensitive files
    # Declared apart from the assignment: `local x=$(…)` returns local's status.
    local sensitive walked=1
    sensitive=$(_webapp_sensitive_files) || { walked=0; _FS_CUT_WALKS+=(webapp-sensitive); }
    local sensitive_count=$(count_lines "$sensitive")

    if [[ -n "$sensitive" && "$sensitive_count" -gt 0 ]]; then
        # High as soon as one found name is on the high list, medium otherwise.
        local sensitive_sev=medium found name
        while IFS= read -r found; do
            for name in "${SENSITIVE_HIGH_PATHS[@]}"; do
                if [[ "${found##*/}" == "$name" ]]; then sensitive_sev=high; fi
            done
        done <<<"$sensitive"
        check_emit "webapp.sensitive_files" "$sensitive_sev" failed \
            title="$(i18n 'webapp.sensitive_files_found'): $sensitive_count" \
            desc="$(echo "$sensitive" | head -5 | tr '\n' '; ' | sed 's/;$//')" \
            suggestion="$(i18n 'webapp.remove_sensitive')"
    # No web root at all scanned nothing, and a pass here would score.
    elif (( walked )) && [[ -n "$(_webapp_web_roots)" ]]; then
        check_emit "webapp.sensitive_files_ok" info passed \
            title="$(i18n 'webapp.no_sensitive_files')" \
            desc="$(i18n 'webapp.sensitive_files_ok_desc')"
    fi

    # 20. Backup files
    local backups
    backups=$(_webapp_backup_files) || _FS_CUT_WALKS+=(webapp-backup)
    local backup_count=$(count_lines "$backups")

    if [[ -n "$backups" && "$backup_count" -gt 0 ]]; then
        check_emit "webapp.backup_files" medium failed \
            title="$(i18n 'webapp.backup_files_found'): $backup_count" \
            desc="$(echo "$backups" | head -5 | tr '\n' '; ' | sed 's/;$//')" \
            suggestion="$(i18n 'webapp.remove_backups')"
    fi

    # Same rule as filesystem_audit: a cut-short walk proves nothing absent.
    if (( ${#_FS_CUT_WALKS[@]} > 0 )); then
        check_emit "webapp.scan_incomplete" info failed \
            desc="$(i18n 'common.walk_incomplete_desc' "walks=${_FS_CUT_WALKS[*]}" "timeout=$_FS_FIND_TIMEOUT")" \
            suggestion="$(i18n 'common.walk_incomplete_fix')"
        _module_record_failure webapp walk
    fi

    # "No web server detected" is a claim about the host, and it is false on
    # one running caddy or openresty. Name what is there and say vpssec does
    # not audit it, so the gap reads as the tool's, not the host's.
    if [[ "$has_webserver" == "false" ]]; then
        local other
        other=$(_webapp_other_webserver)
        if [[ -n "$other" ]]; then
            check_emit "webapp.other_webserver" info failed \
                title="$(i18n 'webapp.other_webserver' "server=$other")" \
                desc="$(i18n 'webapp.other_webserver_desc' "server=$other")" \
                suggestion="$(i18n 'webapp.other_webserver_fix')"
        else
            check_emit "webapp.no_webserver" info passed \
                desc="$(i18n 'webapp.no_webserver_desc')"
        fi
    fi

    return 0
}

# --- Fix Functions ---

webapp_fix() {
    local fix_id="$1"

    case "$fix_id" in
        webapp.nginx_server_tokens)
            _webapp_fix_nginx_server_tokens
            ;;

        webapp.nginx_security_headers)
            _webapp_fix_nginx_security_headers
            ;;

        webapp.nginx_hsts)
            _webapp_fix_nginx_hsts
            ;;

        webapp.nginx_ssl_protocols|webapp.nginx_ssl_ciphers)
            _webapp_fix_nginx_ssl
            ;;

        *)
            log_warn "Unknown fix_id: $fix_id"
            return 1
            ;;
    esac
}

# Fix: Nginx server_tokens
_webapp_fix_nginx_server_tokens() {
    print_info "$(i18n 'webapp.fixing_server_tokens')"

    # Must be UNCOMMENTED: Debian's default nginx.conf ships the directive
    # commented out, so a bare match makes this FIX_SAFE fix report "already
    # configured", change nothing, and be re-flagged forever.
    if grep -qE '^[^#]*server_tokens[[:space:]]+off' "$NGINX_CONF" 2>/dev/null; then
        print_ok "$(i18n 'webapp.already_configured')"
        return 0
    fi

    # Backup, capturing the path so we can restore it if the edit fails to
    # validate. NGINX_CONF exists (we grep'd it above), so backup_file echoes
    # the backup path.
    local bak
    bak=$(backup_file "$NGINX_CONF") || return 1

    local updated
    if grep -qE '^[^#]*server_tokens[[:space:]]' "$NGINX_CONF" 2>/dev/null; then
        # Rewritten in place, never appended: a second server_tokens in the
        # same http{} is a duplicate directive, so nginx -t fails and the fix
        # rolls back — on exactly the hosts that opted into leaking.
        updated=$(sed -E 's/^([^#]*)server_tokens[[:space:]]+[^;]*;/\1server_tokens off;/' "$NGINX_CONF")
    elif grep -qE '^http[[:space:]]*\{' "$NGINX_CONF" 2>/dev/null; then
        updated=$(sed '/^http[[:space:]]*{/a\    server_tokens off;' "$NGINX_CONF")
    else
        # Fall back to the first http block opened at any indentation.
        updated=$(sed '/http[[:space:]]*{/a\    server_tokens off;' "$NGINX_CONF")
    fi

    if ! write_file_atomic "$NGINX_CONF" "$updated"; then
        print_error "$(i18n 'common.failed')"
        return 1
    fi

    # Test and reload. On failure, restore the backup before returning: this
    # fix is auto-applied (FIX_SAFE), so a broken nginx.conf left live would
    # silently fail the next reload/restart/reboot.
    local test_output
    if ! test_output=$(nginx -t 2>&1); then
        print_error "$(i18n 'webapp.nginx_test_failed')"
        # nginx names the file and the line; "configuration test failed" alone
        # is not something the operator can act on.
        [[ -n "$test_output" ]] && print_info "$(i18n 'webapp.nginx_test_output' "msg=$test_output")"
        if [[ -n "$bak" && -f "$bak" ]]; then
            cp -p "$bak" "$NGINX_CONF" && \
                print_warn "$(i18n 'webapp.nginx_restored')"
        fi
        return 1
    fi

    # A failed reload leaves the edit on disk but NOT live. Returning 0 here
    # records the fix as complete while the host still leaks its version.
    if ! systemctl reload nginx 2>/dev/null; then
        print_error "$(i18n 'webapp.reload_failed')"
        return 1
    fi

    print_ok "$(i18n 'webapp.server_tokens_fixed')"
    return 0
}

# Fix: Nginx security headers. Each goes out only where the response lacks it:
# a map on the upstream's copy leaves an application's own value alone, and one
# the operator sets in http{} is not written a second time beside theirs.
_webapp_fix_nginx_security_headers() {
    print_info "$(i18n 'webapp.adding_headers')"

    local headers_conf="$NGINX_CONFD/security-headers.conf"
    local pre_existed="false" bak="" header name declared block content=""
    [[ -f "$headers_conf" ]] && pre_existed="true"

    nginx_dump_reset
    if ! nginx_dump_load; then
        print_error "$(i18n 'webapp.nginx_test_failed')"
        [[ -n "$NGINX_DUMP_ERROR" ]] && print_info "$(i18n 'webapp.nginx_test_output' "msg=$NGINX_DUMP_ERROR")"
        return 1
    fi
    declared=$(_webapp_nginx_http_headers "$headers_conf")
    while IFS= read -r header; do
        name="${header,,}"
        grep -qxF "$name" <<<"$declared" && continue
        name="${name//-/_}"
        printf -v block 'map $upstream_http_%s $vpssec_%s {\n    ""      "%s";\n    default "";\n}\nadd_header %s $vpssec_%s always;\n' \
            "$name" "$name" "${NGINX_SECURITY_HEADERS[$header]}" "$header" "$name"
        content+=$'\n'"$block"
    done < <(printf '%s\n' "${!NGINX_SECURITY_HEADERS[@]}" | LC_ALL=C sort)
    # Every header is already set in http{}: a site still without one has its own
    # add_header, which stops http{}'s from reaching it, and no drop-in can help.
    if [[ -z "$content" ]]; then
        print_error "$(i18n 'webapp.headers_all_declared')"
        return 1
    fi
    printf -v content '%s\n%s\n%s\n%s' '# Security headers - added by vpssec' \
        '# Each header is sent only when the response does not already carry it,' \
        '# so one the application behind proxy_pass sets is left as it is.' "$content"

    # backup_file is UNCONDITIONAL: for an absent path it records the file as
    # fix-created, the only thing that lets a rollback delete this drop-in.
    # pre_existed is separate: the failure path chooses restore or remove.
    bak=$(backup_file "$headers_conf") || return 1

    if ! write_file_atomic "$headers_conf" "$content"; then
        print_error "$(i18n 'common.failed')"
        return 1
    fi

    # Test and reload. On failure, restore the prior drop-in or remove the one
    # we just wrote so an auto-included broken file can't fail the next reload.
    local test_output
    if ! test_output=$(nginx -t 2>&1); then
        print_error "$(i18n 'webapp.nginx_test_failed')"
        [[ -n "$test_output" ]] && print_info "$(i18n 'webapp.nginx_test_output' "msg=$test_output")"
        if [[ "$pre_existed" == "true" && -n "$bak" && -f "$bak" ]]; then
            cp -p "$bak" "$headers_conf"
        else
            rm -f "$headers_conf"
        fi
        print_warn "$(i18n 'webapp.nginx_restored')"
        return 1
    fi

    # Same reason as server_tokens: written is not live.
    if ! systemctl reload nginx 2>/dev/null; then
        print_error "$(i18n 'webapp.reload_failed')"
        return 1
    fi

    # "created" would be a lie on a host that already had this drop-in: the
    # operator's own file is gone and only the backup path leads back to it.
    if [[ "$pre_existed" == "true" && -n "$bak" ]]; then
        print_warn "$(i18n 'webapp.template_replaced' "file=$headers_conf" "backup=$bak")"
    else
        print_ok "$(i18n 'webapp.headers_added'): $headers_conf"
    fi
    print_info "$(i18n 'webapp.include_headers')"
    return 0
}

# Fix: Nginx HSTS
_webapp_fix_nginx_hsts() {
    print_info "$(i18n 'webapp.adding_hsts')"

    local hsts_conf="$NGINX_CONFD/hsts.conf"

    # Unconditional, as in the headers fix above: an absent path has to be
    # recorded as fix-created or a rollback cannot delete this file.
    local pre_existed="false" bak=""
    [[ -f "$hsts_conf" ]] && pre_existed="true"
    bak=$(backup_file "$hsts_conf") || return 1

    # Atomic writer, not `cat >`: this lands in auto-included conf.d, so a
    # truncated file is config nginx must parse on its next reload.
    local content
    content=$(cat << 'EOF'
# HSTS - added by vpssec
# Only enable for HTTPS sites!
# Uncomment in your SSL server blocks:
#
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
#
# Warning: Once enabled, browsers will refuse HTTP connections
# Make sure HTTPS is working properly before enabling
EOF
)

    if ! write_file_atomic "$hsts_conf" "$content"; then
        print_error "$(i18n 'common.failed')"
        return 1
    fi

    # An operator's own hsts.conf may have held a live header; say it is gone.
    if [[ "$pre_existed" == "true" && -n "$bak" ]]; then
        print_warn "$(i18n 'webapp.template_replaced' "file=$hsts_conf" "backup=$bak")"
    else
        print_ok "$(i18n 'webapp.hsts_template_created'): $hsts_conf"
    fi
    print_warn "$(i18n 'webapp.hsts_warning')"
    # The header is written commented out, so the finding is NOT resolved —
    # but the template was created. FIX_TEMPLATE_ONLY withholds the completion
    # record; this exit status is about the work.
    return 0
}

# Write a hardened SSL snippet for the operator to include in their server{}
# block. snippets/, NOT conf.d/: these directives are already set in the
# default http{} block, so an auto-included copy is a duplicate emerg.
_webapp_fix_nginx_ssl() {
    print_info "$(i18n 'webapp.updating_ssl')"

    if ! backup_mkdir "$NGINX_SNIPPETS" 2>/dev/null; then
        print_error "$(i18n 'common.failed')"
        return 1
    fi
    local ssl_conf="$NGINX_SNIPPETS/ssl-security.conf"

    # Unconditional: see _webapp_fix_nginx_security_headers. A snippet this
    # fix created must be deletable by a rollback.
    local pre_existed="false" bak=""
    [[ -f "$ssl_conf" ]] && pre_existed="true"
    bak=$(backup_file "$ssl_conf") || return 1

    local content
    content=$(cat << 'EOF'
# Secure SSL configuration - added by vpssec
# Include inside each SSL server{} block:  include snippets/ssl-security.conf;
# Do NOT include at http{} level: nginx.conf already sets ssl_protocols /
# ssl_prefer_server_ciphers there, and a second copy in the same context is a
# fatal "duplicate directive" error.

# Only use TLS 1.2 and 1.3
ssl_protocols TLSv1.2 TLSv1.3;

# Prefer server ciphers
ssl_prefer_server_ciphers on;

# Modern cipher suite
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# Enable session resumption
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# DH parameters (generate with: openssl dhparam -out /etc/nginx/dhparam.pem 2048)
# ssl_dhparam /etc/nginx/dhparam.pem;
EOF
)

    if ! write_file_atomic "$ssl_conf" "$content"; then
        print_error "$(i18n 'common.failed')"
        return 1
    fi

    # Sanity-check the whole nginx config still parses. The snippet is not
    # included anywhere yet, so this only confirms we did not disturb the live
    # config; if nginx -t is available and fails, surface it.
    local test_output
    if command -v nginx >/dev/null 2>&1 && ! test_output=$(nginx -t 2>&1); then
        print_error "$(i18n 'webapp.nginx_test_failed')"
        [[ -n "$test_output" ]] && print_info "$(i18n 'webapp.nginx_test_output' "msg=$test_output")"
        return 1
    fi

    if [[ "$pre_existed" == "true" && -n "$bak" ]]; then
        print_warn "$(i18n 'webapp.template_replaced' "file=$ssl_conf" "backup=$bak")"
    else
        print_ok "$(i18n 'webapp.ssl_config_created'): $ssl_conf"
    fi
    print_warn "$(i18n 'webapp.include_in_ssl'): include snippets/ssl-security.conf;"
    # The snippet is inert until the operator includes it, so the finding is
    # NOT resolved — but the write succeeded. FIX_TEMPLATE_ONLY is what stops
    # the completion record; this exit status is about the work.
    return 0
}
