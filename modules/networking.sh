#!/usr/bin/env bash
# Networking module: listening-socket analysis and interface posture.
# Surfaces services bound to a public address; all findings are alert-only.

# --- Configuration ---

# Ports that should almost never face the public internet; HIGH when bound
# to a wildcard. Deliberately conservative — 22/80/443/53 are omitted.
declare -ga NET_DANGEROUS_PUBLIC_PORTS=(
    21      # FTP (cleartext credentials)
    23      # Telnet (cleartext credentials/session) — merged from preflight
    2375    # Docker daemon (unencrypted!) — direct root RCE
    2376    # Docker daemon (TLS, but still mgmt plane on public is risky)
    3306    # MySQL / MariaDB
    4505    # SaltStack master publish
    4506    # SaltStack master return
    5432    # PostgreSQL
    5601    # Kibana
    5984    # CouchDB
    6379    # Redis
    7474    # Neo4j HTTP
    8086    # InfluxDB
    9090    # Prometheus / Cockpit
    9100    # node_exporter
    9200    # Elasticsearch HTTP
    9300    # Elasticsearch transport
    11211   # memcached
    25826   # collectd
    27017   # MongoDB
    27018   # MongoDB shard
    27019   # MongoDB config server
)

# Ports where wildcard binding is expected on a VPS: no finding even when
# public. SSH on 0.0.0.0 is covered by the ssh module instead.
declare -ga NET_PUBLIC_PORTS_OK=(
    22      # SSH (default port)
    80      # HTTP
    443     # HTTPS
    53      # DNS (when host runs a resolver)
    68      # DHCP client (bootpc) — udp/68 on 0.0.0.0 is the DHCP client on
            # virtually every cloud image using isc-dhcp/dhcpcd; flagging it as
            # a "non-standard public listener" was a scored false positive.
)

# Processes whose listeners are expected public on ANY port. Port 22 alone
# is not enough: ssh.sh approves a moved SSH port, so matching by port would
# make this module contradict it on the same listener.
declare -ga NET_PUBLIC_PROCESSES_OK=(
    sshd
)

# --- Helpers ---

_net_have_ss() { command -v ss >/dev/null 2>&1; }

# Emit TSV: proto, family, ip, port, process per listening socket.
# Prefers `ss -tulnpH`, falling back to netstat.
# The family field ("v4" / "v6" / "") keys the downstream checks.
_net_list_listeners() {
    local raw
    if _net_have_ss; then
        # -t TCP, -u UDP, -l listening, -n numeric, -p process,
        # -H suppress header.
        raw=$(ss -tulnpH 2>/dev/null) || raw=$(ss -tulnp 2>/dev/null | tail -n +2)
    elif command -v netstat >/dev/null 2>&1; then
        raw=$(netstat -tulnp 2>/dev/null | awk '/^(tcp|udp)/')
    else
        return 1
    fi
    [[ -z "$raw" ]] && return 0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local proto local_addr proc=""
        # Both ss and netstat list proto in column 1.
        proto=$(awk '{print $1}' <<< "$line")

        if _net_have_ss; then
            # `ss -tulnpH` column 5 is the local address:port.
            local_addr=$(awk '{print $5}' <<< "$line")
        else
            # `netstat -tulnp` column 4 is the local address:port.
            local_addr=$(awk '{print $4}' <<< "$line")
        fi

        # Strip [] and split addr/port. IPv6 form is [::]:port,
        # IPv4 is plain a.b.c.d:port. Port is always after the
        # last colon; everything before is the address.
        local port="${local_addr##*:}"
        local ip="${local_addr%:*}"
        ip="${ip#[}"
        ip="${ip%]}"

        # Family: presence of ':' inside `ip` means IPv6.
        local family="v4"
        [[ "$ip" == *:* || "$ip" == "*" && "$proto" == *6 ]] && family="v6"

        # Extract process name. ss emits users:(("name",pid=N,fd=N));
        # netstat emits pid/name as last column.
        if _net_have_ss && [[ "$line" =~ users:\(\(\"([^\"]+)\" ]]; then
            proc="${BASH_REMATCH[1]}"
        elif ! _net_have_ss; then
            proc=$(awk '{print $NF}' <<< "$line" | sed 's|.*/||;s|^-$||')
        fi

        printf '%s\t%s\t%s\t%s\t%s\n' "$proto" "$family" "$ip" "$port" "$proc"
    done <<< "$raw"
}

# Classify a (family, ip) pair as "loopback" / "wildcard" / "specific".
_net_classify_addr() {
    local family="$1" ip="$2"
    case "$family" in
        v4)
            [[ "$ip" =~ ^127\. ]] && { echo loopback; return; }
            [[ "$ip" == "0.0.0.0" || "$ip" == "*" ]] && { echo wildcard; return; }
            ;;
        v6)
            [[ "$ip" == "::1" ]] && { echo loopback; return; }
            [[ "$ip" == "::" || "$ip" == "*" ]] && { echo wildcard; return; }
            ;;
    esac
    echo specific
}

# Is a specific bind routable from off-host? A service on the VPS's own
# public IP is as reachable as one on 0.0.0.0. Private/link-local/CGNAT
# return 1, and so does anything unparseable — never a false HIGH.
_net_specific_addr_is_public() {
    local family="$1" ip="$2"
    case "$family" in
        v4)
            [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\. ]] || return 1
            local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}"
            (( o1 == 10 )) && return 1                          # 10/8
            (( o1 == 172 && o2 >= 16 && o2 <= 31 )) && return 1 # 172.16/12
            (( o1 == 192 && o2 == 168 )) && return 1            # 192.168/16
            (( o1 == 169 && o2 == 254 )) && return 1            # link-local
            (( o1 == 100 && o2 >= 64 && o2 <= 127 )) && return 1 # CGNAT 100.64/10
            (( o1 == 127 )) && return 1                         # loopback (defensive)
            (( o1 == 0 || o1 >= 224 )) && return 1              # 0/8, multicast+
            return 0
            ;;
        v6)
            local lc="${ip,,}"
            [[ "$lc" == fe8* || "$lc" == fe9* || "$lc" == fea* || "$lc" == feb* ]] && return 1  # fe80::/10
            [[ "$lc" == fc* || "$lc" == fd* ]] && return 1      # ULA fc00::/7
            [[ "$lc" == ::* ]] && return 1                      # ::/… specials
            return 0
            ;;
    esac
    return 1
}

_net_port_in() {
    local needle="$1"
    shift
    local p
    for p in "$@"; do
        [[ "$needle" == "$p" ]] && return 0
    done
    return 1
}

_net_proc_in() {
    local needle="$1"
    shift
    [[ -z "$needle" ]] && return 1
    local p
    for p in "$@"; do
        [[ "$needle" == "$p" ]] && return 0
    done
    return 1
}

# Interfaces in promiscuous mode, excluding loopback and the virtual/bridge/
# container families, for which it is the normal mode. veth pairs render as
# "vethXXXX@ifN", so the @peer suffix is stripped before matching.
_net_promiscuous_interfaces() {
    command -v ip >/dev/null 2>&1 || return 0
    ip -o link show 2>/dev/null \
        | awk -F': ' '/PROMISC/{print $2}' \
        | awk '{sub(/@.*/, "", $1); print $1}' \
        | grep -vE '^(lo|docker[0-9]*|br-[0-9a-f]+|veth[0-9a-z]*|virbr[0-9]*(-nic)?|cni[0-9]*|flannel\.[0-9]+|kube-[a-z0-9-]+)$' \
        || true
}

# --- Audit ---

networking_audit() {
    local module="networking"

    print_item "$(i18n 'networking.check_listeners' 2>/dev/null || echo 'Checking listening sockets')"
    _net_audit_listeners

    print_item "$(i18n 'networking.check_promisc' 2>/dev/null || echo 'Checking promiscuous interfaces')"
    _net_audit_promisc
}

_net_audit_listeners() {
    local listeners
    listeners=$(_net_list_listeners)

    if [[ -z "$listeners" ]]; then
        # Nothing listening is unusual but not a finding per se —
        # the host might be quiescent or the audit ran without root.
        return
    fi

    # Collapse (proto, port, proc) into a set: ss emits one row per address
    # family, so raw iteration double-counts every dual-stack listener.
    # Wildcard beats loopback when both are seen — worst case wins.
    local -A wildcard_set loopback_only_set specific_public_set
    local loopback_only=1
    local proto family ip port proc class key
    while IFS=$'\t' read -r proto family ip port proc; do
        [[ -z "$port" ]] && continue
        class=$(_net_classify_addr "$family" "$ip")
        key="${proto}/${port}/${proc:-?}"
        case "$class" in
            loopback)
                # Only record as loopback-only if not already marked
                # wildcard. Otherwise leave the wildcard entry alone.
                [[ -z "${wildcard_set[$key]:-}" ]] && loopback_only_set["$key"]=1
                ;;
            wildcard)
                loopback_only=0
                wildcard_set["$key"]=1
                # If we had previously logged it as loopback, promote.
                unset 'loopback_only_set[$key]' 2>/dev/null || true
                ;;
            specific)
                loopback_only=0
                # A public specific bind gets the same scrutiny as a
                # wildcard one, and carries the address so the finding
                # can name it.
                if _net_specific_addr_is_public "$family" "$ip"; then
                    specific_public_set["${proto}/${port}/${ip}/${proc:-?}"]=1
                fi
                ;;
        esac
    done <<< "$listeners"

    # Second pass: classify deduplicated wildcard listeners.
    local dangerous=()  # known-bad ports on wildcard
    local exposed=()    # any other non-whitelisted port/proc on wildcard

    for key in "${!wildcard_set[@]}"; do
        proto="${key%%/*}"
        local rest="${key#*/}"
        port="${rest%%/*}"
        proc="${rest#*/}"
        [[ "$proc" == "?" ]] && proc=""

        # Process-name whitelist wins first. sshd on a non-default
        # port is approved by ssh.sh; networking would otherwise
        # flag the same listener and contradict.
        if _net_proc_in "$proc" "${NET_PUBLIC_PROCESSES_OK[@]}"; then
            continue
        fi

        if _net_port_in "$port" "${NET_DANGEROUS_PUBLIC_PORTS[@]}"; then
            dangerous+=("${proto}/${port}${proc:+ ($proc)}")
        elif ! _net_port_in "$port" "${NET_PUBLIC_PORTS_OK[@]}"; then
            exposed+=("${proto}/${port}${proc:+ ($proc)}")
        fi
    done

    # Same classification for public-specific binds; the label carries the
    # bound address so the operator can see WHICH interface is exposed.
    local addr
    for key in ${specific_public_set[@]+"${!specific_public_set[@]}"}; do
        proto="${key%%/*}"
        local rest="${key#*/}"
        port="${rest%%/*}"
        rest="${rest#*/}"
        addr="${rest%/*}"
        proc="${rest##*/}"
        [[ "$proc" == "?" ]] && proc=""

        if _net_proc_in "$proc" "${NET_PUBLIC_PROCESSES_OK[@]}"; then
            continue
        fi

        if _net_port_in "$port" "${NET_DANGEROUS_PUBLIC_PORTS[@]}"; then
            dangerous+=("${proto}/${port}@${addr}${proc:+ ($proc)}")
        elif ! _net_port_in "$port" "${NET_PUBLIC_PORTS_OK[@]}"; then
            exposed+=("${proto}/${port}@${addr}${proc:+ ($proc)}")
        fi
    done

    if (( ${#dangerous[@]} > 0 )); then
        local list; list=$(printf '%s ' "${dangerous[@]}")
        local check=$(create_check_json \
            "networking.exposed_dangerous_ports" \
            "networking" \
            "high" \
            "failed" \
            "$(i18n 'networking.exposed_dangerous_ports' "count=${#dangerous[@]}" 2>/dev/null || echo "${#dangerous[@]} dangerous service(s) bound to wildcard address")" \
            "$(i18n 'networking.exposed_dangerous_ports_desc' "list=${list% }")" \
            "$(i18n 'networking.exposed_dangerous_ports_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "high" "$(i18n 'networking.exposed_dangerous_ports' "count=${#dangerous[@]}" 2>/dev/null || echo "${#dangerous[@]} dangerous public listener(s)")"
    fi

    if (( ${#exposed[@]} > 0 )); then
        local list; list=$(printf '%s ' "${exposed[@]}")
        local check=$(create_check_json \
            "networking.public_listeners_present" \
            "networking" \
            "medium" \
            "failed" \
            "$(i18n 'networking.public_listeners_present' "count=${#exposed[@]}" 2>/dev/null || echo "${#exposed[@]} non-standard service(s) on wildcard address")" \
            "$(i18n 'networking.public_listeners_present_desc' "list=${list% }")" \
            "$(i18n 'networking.public_listeners_present_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'networking.public_listeners_present' "count=${#exposed[@]}" 2>/dev/null || echo "${#exposed[@]} non-standard public listener(s)")"
    fi

    if (( ${#dangerous[@]} == 0 && ${#exposed[@]} == 0 )); then
        local title
        if (( loopback_only == 1 )); then
            title=$(i18n 'networking.listeners_loopback_only' 2>/dev/null || echo 'All listeners are loopback-only')
        else
            title=$(i18n 'networking.listeners_ok' 2>/dev/null || echo 'Public listeners match expected services (SSH/HTTP/HTTPS/DNS)')
        fi
        local check=$(create_check_json \
            "networking.listeners_ok" \
            "networking" \
            "low" \
            "passed" \
            "$title" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$title"
    fi
}

_net_audit_promisc() {
    local promisc
    promisc=$(_net_promiscuous_interfaces)
    promisc=$(echo "$promisc" | grep -v '^$' || true)

    if [[ -n "$promisc" ]]; then
        local list; list=$(echo "$promisc" | tr '\n' ' ')
        local check=$(create_check_json \
            "networking.promiscuous_interface" \
            "networking" \
            "medium" \
            "failed" \
            "$(i18n 'networking.promiscuous_interface' 2>/dev/null || echo 'Interface(s) in promiscuous mode')" \
            "$(i18n 'networking.promiscuous_interface_desc' "list=${list% }")" \
            "$(i18n 'networking.promiscuous_interface_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'networking.promiscuous_interface' 2>/dev/null || echo 'Promiscuous interface detected')"
    else
        local check=$(create_check_json \
            "networking.no_promisc" \
            "networking" \
            "low" \
            "passed" \
            "$(i18n 'networking.no_promisc' 2>/dev/null || echo 'No promiscuous interfaces')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'networking.no_promisc' 2>/dev/null || echo 'No promiscuous interfaces')"
    fi
}

# No fix functions: all networking findings are alert-only. Rebinding a
# service to localhost is per-daemon config that cannot be safely automated.

networking_fix() {
    local fix_id="$1"
    log_error "networking module has no automated fixes (fix_id=$fix_id)"
    return 1
}
