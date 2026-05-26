#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Networking module — listening sockets analysis + interface posture
# Copyright (c) 2024
#
# Why this module exists:
# Lynis NETW-3012 (and related) audit listening sockets and surface
# services bound to 0.0.0.0 / ::. On a cloud VPS, that's the single
# most common real-world misconfiguration that turns a private service
# into an internet-exposed one (DB, cache, monitoring exporter, …).
# vpssec's preflight previously only reported the *count* of listeners.

# ==============================================================================
# Configuration
# ==============================================================================

# Ports that should almost never face the public internet. Bound to a
# wildcard address → HIGH severity. The list is conservative — well-
# documented public services (22/80/443/53) deliberately omitted; intent
# for those is operator-specific.
declare -ga NET_DANGEROUS_PUBLIC_PORTS=(
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

# Ports where wildcard binding is the typical / expected setup on a
# VPS. We don't emit any finding for these even when public. Operators
# who explicitly want to flag SSH on 0.0.0.0 can do so via separate
# SSH-module checks.
declare -ga NET_PUBLIC_PORTS_OK=(
    22      # SSH (default port)
    80      # HTTP
    443     # HTTPS
    53      # DNS (when host runs a resolver)
)

# Processes whose listeners are always considered "expected public"
# regardless of which port they bind to. The reason port 22 isn't
# enough: operators routinely move SSH to a high port (2222, 22022,
# 33xxx, ...) — ssh.sh's port check already approves that move, so
# networking module flagging the same listener as "non-standard
# public listener" produces a contradictory pair of findings. Match
# by process name closes the loop.
declare -ga NET_PUBLIC_PROCESSES_OK=(
    sshd
)

# ==============================================================================
# Helpers
# ==============================================================================

_net_have_ss() { command -v ss >/dev/null 2>&1; }

# Emit TSV: proto<TAB>family<TAB>ip<TAB>port<TAB>process for each
# listening socket. `ss -tulnpH` is preferred (header-less, modern);
# falls back to netstat where ss is missing.
#
# IP family classification keys downstream checks: "v4", "v6", or "".
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

# Detect interfaces in promiscuous mode. On a server, promisc usually
# means tcpdump/wireshark is running — or something far worse.
#
# Exclude loopback and the virtual/bridge/container interface families
# that legitimately run promiscuous as their normal mode (Docker bridges
# and veth pairs, libvirt virbr, CNI/flannel/k8s bridges). Flagging those
# is a guaranteed false positive on any container/KVM host; a sniffer on a
# real NIC still shows up. veth pairs render as "vethXXXX@ifN" — strip the
# @peer suffix before matching.
_net_promiscuous_interfaces() {
    command -v ip >/dev/null 2>&1 || return 0
    ip -o link show 2>/dev/null \
        | awk -F': ' '/PROMISC/{print $2}' \
        | awk '{sub(/@.*/, "", $1); print $1}' \
        | grep -vE '^(lo|docker[0-9]*|br-[0-9a-f]+|veth[0-9a-z]*|virbr[0-9]*(-nic)?|cni[0-9]*|flannel\.[0-9]+|kube-[a-z0-9-]+)$' \
        || true
}

# ==============================================================================
# Audit
# ==============================================================================

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

    # First pass: collapse (proto, port, proc) tuples seen on
    # wildcard / loopback / specific. ss(8) emits separate rows for
    # the IPv4 and IPv6 sockets of the same service (sshd on
    # 0.0.0.0:22 and [::]:22 are two rows), so iterating raw would
    # double-count every dual-stack listener. The associative array
    # acts as a set; presence on wildcard wins over loopback when
    # both are seen (worst-case classification).
    local -A wildcard_set loopback_only_set
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
                # Specific-bind addresses are neither flagged nor
                # tracked — operator context required.
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

    if (( ${#dangerous[@]} > 0 )); then
        local list; list=$(printf '%s ' "${dangerous[@]}")
        local check=$(create_check_json \
            "networking.exposed_dangerous_ports" \
            "networking" \
            "high" \
            "failed" \
            "$(i18n 'networking.exposed_dangerous_ports' "count=${#dangerous[@]}" 2>/dev/null || echo "${#dangerous[@]} dangerous service(s) bound to wildcard address")" \
            "Public: ${list% }" \
            "Bind these services to 127.0.0.1 or a specific private IP and place behind authenticated reverse proxy / WireGuard / SSH tunnel" \
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
            "Public: ${list% }" \
            "Verify each is intentionally internet-facing; otherwise bind to 127.0.0.1" \
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
            "Interfaces: ${list% }" \
            "Investigate why an interface is in PROMISC — tcpdump/wireshark in progress, or unexpected sniffer" \
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

# ==============================================================================
# Fix Functions — none; all networking findings are alert-only.
# Binding databases to localhost is a per-service config change that
# cannot be safely automated (each daemon has its own config file and
# restart semantics).
# ==============================================================================

networking_fix() {
    local fix_id="$1"
    log_error "networking module has no automated fixes (fix_id=$fix_id)"
    return 1
}
