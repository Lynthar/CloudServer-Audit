#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Kernel and network security parameters module
# Copyright (c) 2024

# --- Kernel Security Configuration ---

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_D="/etc/sysctl.d"
VPSSEC_SYSCTL_CONF="${SYSCTL_D}/99-vpssec-hardening.conf"

# The directories systemd-sysctl reads at boot after SYSCTL_D, in precedence
# order: a file name found in an earlier one hides the same name in later ones.
# SYSCTL_CONF is read at boot only through a link from one of them.
declare -ga KERNEL_SYSCTL_BOOT_DIRS=(/run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d)

# Variables, not literals, so the audit predicate and the fix read the SAME
# locations, and so the fix is reachable from a test.
KERNEL_LIMITS_CONF="/etc/security/limits.conf"
KERNEL_COREDUMP_CONF="/etc/systemd/coredump.conf"
KERNEL_COREDUMP_D="/etc/systemd/coredump.conf.d"
KERNEL_COREDUMP_DROPIN="${KERNEL_COREDUMP_D}/99-vpssec.conf"

# The perf_event_paranoid level that blocks all unprivileged perf_event_open()
# is a distro kernel patch: Ubuntu's needs >= 4, Debian's > 2. Mainline (RHEL,
# Arch) has no such level, so 2 is its strictest and higher values equal 2.
_kernel_perf_paranoid_min() {
    if [[ "${VPSSEC_DISTRO_ID:-}" == "ubuntu" ]]; then
        echo 4
    elif [[ "${VPSSEC_DISTRO_FAMILY:-}" == "debian" ]]; then
        echo 3
    else
        echo 2
    fi
}

# Recommended sysctl settings with descriptions
# Format: parameter:recommended_value:severity:description
# recommended_value is one value, a |-set, or >=N for a param where a higher
# value is stricter; the fix writes the first token, so it never lowers one.
declare -ga KERNEL_SECURITY_PARAMS=(
    # Network security - IPv4
    "net.ipv4.ip_forward:0:medium:IP forwarding (should be disabled unless routing)"
    "net.ipv4.conf.all.send_redirects:0:medium:ICMP redirects sending"
    "net.ipv4.conf.default.send_redirects:0:medium:ICMP redirects sending (default)"
    "net.ipv4.conf.all.accept_redirects:0:medium:ICMP redirects acceptance"
    "net.ipv4.conf.default.accept_redirects:0:medium:ICMP redirects acceptance (default)"
    "net.ipv4.conf.all.secure_redirects:0:low:Secure ICMP redirects"
    "net.ipv4.conf.default.secure_redirects:0:low:Secure ICMP redirects (default)"
    "net.ipv4.conf.all.accept_source_route:0:medium:Source routing acceptance"
    "net.ipv4.conf.default.accept_source_route:0:medium:Source routing acceptance (default)"
    "net.ipv4.conf.all.log_martians:1:low:Log suspicious packets"
    "net.ipv4.conf.default.log_martians:1:low:Log suspicious packets (default)"
    "net.ipv4.conf.all.rp_filter:1:medium:Reverse path filtering"
    "net.ipv4.conf.default.rp_filter:1:medium:Reverse path filtering (default)"
    "net.ipv4.icmp_echo_ignore_broadcasts:1:low:Ignore ICMP broadcast"
    "net.ipv4.icmp_ignore_bogus_error_responses:1:low:Ignore bogus ICMP errors"
    "net.ipv4.tcp_syncookies:1:high:SYN flood protection"
    "net.ipv4.tcp_timestamps:1|0:low:TCP timestamps (on or off; 2 drops the random offset and exposes uptime)"
    # Niche-but-default-off IPv4 features (Lynis KRNL-6000 cross-check)
    "net.ipv4.conf.all.bootp_relay:0:low:BOOTP relay (default off; enable = relay agent role)"
    "net.ipv4.conf.all.mc_forwarding:0:low:Multicast forwarding (default off; enable = mrouted role)"
    "net.ipv4.conf.all.proxy_arp:0:low:Proxy ARP (default off; enable = bridge/router role)"

    # Network security - IPv6. accept_ra, accept_redirects and use_tempaddr set
    # under all/default reach only interfaces created later, not existing ones
    # (eth0); a key that exists only under "all" reaches none, so none is listed.
    "net.ipv6.conf.all.accept_redirects:0:medium:IPv6 ICMP redirects"
    "net.ipv6.conf.default.accept_redirects:0:medium:IPv6 ICMP redirects (default)"
    "net.ipv6.conf.all.accept_source_route:0:medium:IPv6 source routing"
    "net.ipv6.conf.default.accept_source_route:0:medium:IPv6 source routing (default)"
    "net.ipv6.conf.all.accept_ra:0:medium:IPv6 Router Advertisements (can be MITM vector)"
    "net.ipv6.conf.default.accept_ra:0:medium:IPv6 Router Advertisements (default)"
    "net.ipv6.conf.all.use_tempaddr:2:low:IPv6 privacy extensions (use temp addresses)"
    "net.ipv6.conf.default.use_tempaddr:2:low:IPv6 privacy extensions (default)"

    # ASLR is deliberately absent: it has its own check, and listing it here
    # too double-counts ASLR-off in the score.
    "kernel.dmesg_restrict:1:medium:Restrict dmesg access"
    "kernel.kptr_restrict:2:medium:Restrict kernel pointer exposure"
    "kernel.yama.ptrace_scope:>=1:medium:Restrict ptrace"
    "fs.suid_dumpable:0:medium:Disable SUID core dumps"
    "fs.protected_hardlinks:1:medium:Hardlink protection"
    "fs.protected_symlinks:1:medium:Symlink protection"
    "kernel.core_uses_pid:1:low:Core dump filename includes PID"

    # unprivileged_userns_clone stays MEDIUM: disabling it breaks rootless
    # containers, snap and browser sandboxes, and Debian ships =1 by default.
    # A real mitigation, but not one worth driving users into that loop.
    "kernel.unprivileged_userns_clone:0:medium:Disable unprivileged user namespaces (defence-in-depth; breaks Docker rootless / podman / snap / Chrome sandbox if enabled)"
    # 2 (the Debian/Ubuntu default) and 1 both deny unprivileged BPF; the fix
    # writes 2 because 1 locks the value until reboot, beyond any rollback.
    "kernel.unprivileged_bpf_disabled:2|1:medium:Disable unprivileged BPF (exploit prevention)"
    "net.core.bpf_jit_harden:2:medium:BPF JIT hardening"
    "kernel.sysrq:0|176:medium:Disable Magic SysRq key (0, or 176 for the safe subset)"
    "kernel.perf_event_paranoid:>=$(_kernel_perf_paranoid_min):medium:Restrict perf events"
    "fs.protected_fifos:2:low:FIFO protection"
    "fs.protected_regular:2:low:Regular file protection"
    # Console/console-equivalent attack surface (Lynis KRNL-6000 cross-check)
    "kernel.ctrl-alt-del:0:low:Console Ctrl-Alt-Del bypass disabled"
    # TTY line discipline autoload — CVE-2019-13272 / CVE-2020-14381
    # exploit primitive lives here. Mainline default is 0 since 5.x;
    # flag anything else.
    "dev.tty.ldisc_autoload:0:low:TTY line discipline autoload restricted"
)

# --- Kernel Helper Functions ---

# Detect if running in a container (OpenVZ, LXC, Docker)
# Many kernel parameters cannot be modified in containers
_kernel_is_container() {
    # Check for OpenVZ
    if [[ -f /proc/vz/veinfo ]] || [[ -d /proc/vz ]]; then
        echo "openvz"
        return 0
    fi

    # Check for LXC
    if grep -qa "lxc" /proc/1/cgroup 2>/dev/null; then
        echo "lxc"
        return 0
    fi

    # Check for Docker
    if [[ -f /.dockerenv ]] || grep -qa "docker" /proc/1/cgroup 2>/dev/null; then
        echo "docker"
        return 0
    fi

    # Check for systemd-nspawn
    if grep -qa "machine.slice" /proc/1/cgroup 2>/dev/null; then
        echo "nspawn"
        return 0
    fi

    # Check /proc/1/environ for container hints
    if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -q "container="; then
        echo "container"
        return 0
    fi

    # Not a container
    return 1
}

# Get current sysctl value
_kernel_get_sysctl() {
    local param="$1"
    sysctl -n "$param" 2>/dev/null
}

# True when value $1 meets expected spec $2: a |-separated set of acceptable
# values, e.g. sysrq "0|176", where a token may be >=N. A non-integer never
# meets >=N. The runtime and the boot-time checks both judge through this.
_kernel_value_meets() {
    local actual="$1" expected="$2" exp
    local IFS='|'
    for exp in $expected; do
        if [[ "$exp" == ">="* ]]; then
            [[ "$actual" =~ ^-?[0-9]+$ ]] && (( actual >= ${exp#>=} )) && return 0
        elif [[ "$actual" == "$exp" ]]; then
            return 0
        fi
    done
    return 1
}

# Check if parameter matches expected value
_kernel_check_param() {
    local param="$1"
    local expected="$2"

    local actual
    actual=$(_kernel_get_sysctl "$param")

    if [[ -z "$actual" ]]; then
        echo "unavailable"
        return 2  # Parameter not available
    fi

    _kernel_value_meets "$actual" "$expected" && return 0

    echo "$actual"
    return 1  # Incorrect
}

# The expected spec KERNEL_SECURITY_PARAMS gives parameter $1.
_kernel_param_expected() {
    local entry rest
    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        [[ "${entry%%:*}" == "$1" ]] || continue
        rest="${entry#*:}"
        echo "${rest%%:*}"
        return 0
    done
    return 1
}

# The value a fix writes for an expected spec: its first token, >= stripped.
_kernel_param_target() {
    local first="${1%%|*}"
    echo "${first#>=}"
}

# Check ASLR status
_kernel_check_aslr() {
    local value
    value=$(_kernel_get_sysctl "kernel.randomize_va_space")

    case "$value" in
        2) echo "full" ;;      # Full randomization
        1) echo "partial" ;;   # Partial randomization
        0) echo "disabled" ;;  # Disabled
        *) echo "unknown" ;;
    esac
}

# The pass condition of _kernel_audit_aslr.
_kernel_aslr_full() {
    [[ "$(_kernel_check_aslr)" == "full" ]]
}

# True when something here legitimately needs IP forwarding: container
# runtimes, VM hosts, mesh-VPN subnet routers, Kubernetes nodes. Mesh VPNs
# matter — they are the most common ip_forward=1 source on a cloud VPS.
_kernel_ip_forward_needed() {
    # Container / VM runtimes
    systemctl is-active --quiet docker 2>/dev/null && return 0
    systemctl is-active --quiet podman 2>/dev/null && return 0
    systemctl is-active --quiet lxc 2>/dev/null && return 0
    systemctl is-active --quiet lxd 2>/dev/null && return 0
    systemctl is-active --quiet incus 2>/dev/null && return 0
    systemctl is-active --quiet libvirtd 2>/dev/null && return 0

    # VPN / mesh-network daemons. tailscaled and openvpn(.service)
    # match directly; wg-quick@<iface>.service and openvpn-{client,
    # server}@<name>.service are template units and need a listing scan.
    systemctl is-active --quiet tailscaled 2>/dev/null && return 0
    systemctl is-active --quiet openvpn 2>/dev/null && return 0
    if systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
        | awk '{print $1}' \
        | grep -qE '^(wg-quick@|openvpn-(client|server)@)'; then
        return 0
    fi

    # Kubernetes node
    systemctl is-active --quiet k3s 2>/dev/null && return 0
    systemctl is-active --quiet kubelet 2>/dev/null && return 0

    # Wireguard via manual `ip link add` (no systemd unit). Cheaper
    # than `wg show` and works without the wireguard-tools package.
    if command -v ip >/dev/null 2>&1; then
        ip -br link show type wireguard 2>/dev/null | grep -q . && return 0
    fi

    return 1
}

# --- IPv6 Detection Functions ---

# Check if IPv6 is enabled system-wide
_kernel_ipv6_enabled() {
    # Check kernel module
    if [[ -d /proc/sys/net/ipv6 ]]; then
        # Check if disabled via sysctl
        local disabled=$(_kernel_get_sysctl "net.ipv6.conf.all.disable_ipv6")
        [[ "$disabled" != "1" ]]
        return $?
    fi
    return 1
}

# Check if IPv6 is actively used (has global addresses)
_kernel_ipv6_in_use() {
    # Check for global IPv6 addresses (not link-local fe80::)
    ip -6 addr show scope global 2>/dev/null | grep -q "inet6" 2>/dev/null
}

# Get IPv6 statistics
_kernel_ipv6_get_stats() {
    local stats=""

    # `|| true`, never `|| echo 0`: grep -c already prints 0 on no matches,
    # so the fallback appends a second one and breaks the arithmetic.

    # Count interfaces with IPv6
    local iface_count
    iface_count=$(ip -6 addr show 2>/dev/null | grep -c "inet6" || true)
    iface_count="${iface_count:-0}"
    stats+="interfaces:$iface_count;"

    # Count global addresses
    local global_count
    global_count=$(ip -6 addr show scope global 2>/dev/null | grep -c "inet6" || true)
    global_count="${global_count:-0}"
    stats+="global:$global_count;"

    # Check if IPv6 forwarding is enabled
    local forward=$(_kernel_get_sysctl "net.ipv6.conf.all.forwarding")
    stats+="forwarding:${forward:-0};"

    # Check for IPv6 default route
    if ip -6 route show default 2>/dev/null | grep -q "default"; then
        stats+="default_route:yes"
    else
        stats+="default_route:no"
    fi

    echo "$stats"
}

# Check for IPv6-specific security issues
_kernel_ipv6_check_security() {
    local issues=()

    # 1. Check if IPv6 is enabled but not secured
    if _kernel_ipv6_enabled; then
        # Router Advertisements are a MITM vector, except on an RA/SLAAC host
        # where accept_ra=1 is what keeps the default route (as for net.*).
        local accept_ra=$(_kernel_get_sysctl "net.ipv6.conf.all.accept_ra")
        if [[ "$accept_ra" == "1" ]] && ! _kernel_ipv6_uses_ra; then
            issues+=("accept_ra_enabled")
        fi

        # Check if forwarding is unexpectedly enabled
        local forward=$(_kernel_get_sysctl "net.ipv6.conf.all.forwarding")
        if [[ "$forward" == "1" ]] && ! _kernel_ip_forward_needed; then
            issues+=("forwarding_enabled")
        fi

        # Check privacy extensions
        local tempaddr=$(_kernel_get_sysctl "net.ipv6.conf.all.use_tempaddr")
        if [[ "$tempaddr" != "2" ]]; then
            issues+=("privacy_extensions_weak")
        fi

        # Check accept_redirects
        local redirects=$(_kernel_get_sysctl "net.ipv6.conf.all.accept_redirects")
        if [[ "$redirects" == "1" ]]; then
            issues+=("accept_redirects_enabled")
        fi
    fi

    echo "${issues[*]}"
}

# How many IPv6 issues pass: none on a host that uses IPv6, up to two on one
# that has it enabled but idle. $1 is yes/no (in use), $2 the issue count.
_kernel_ipv6_issues_ok() {
    if [[ "$1" == "yes" ]]; then
        (( $2 == 0 ))
    else
        (( $2 <= 2 ))
    fi
}

# Pass condition of _kernel_audit_ipv6 (IPv6 disabled passes outright).
_kernel_ipv6_secure() {
    _kernel_ipv6_enabled || return 0
    local in_use count
    in_use=$(_kernel_ipv6_in_use && echo "yes" || echo "no")
    count=$(wc -w <<< "$(_kernel_ipv6_check_security)")
    _kernel_ipv6_issues_ok "$in_use" "$count"
}

# IPv6 firewall state for the audit: filtered | unfiltered | unknown. The
# backend is fw_backend's answer, so this check and the ufw module agree.
_kernel_ipv6_firewall_check() {
    local rc=0
    fw_ipv6_filtered || rc=$?
    case "$rc" in
        0) echo "filtered" ;;
        1) echo "unfiltered" ;;
        *) echo "unknown" ;;
    esac
}

# Check core dump settings
_kernel_check_core_dump() {
    local issues=()

    # Check fs.suid_dumpable
    local suid_dump
    suid_dump=$(_kernel_get_sysctl "fs.suid_dumpable")
    if [[ "$suid_dump" != "0" ]]; then
        issues+=("suid_dumpable=$suid_dump")
    fi

    # Check limits.conf for core limits
    if [[ -f "$KERNEL_LIMITS_CONF" ]]; then
        if ! grep -qE "^\*\s+(soft|hard)\s+core\s+0" "$KERNEL_LIMITS_CONF" 2>/dev/null; then
            issues+=("no_core_limit")
        fi
    fi

    # Storage=none may live in the main coredump.conf OR a drop-in, which is
    # where the fix writes it and how systemd merges. Read BOTH, or the audit
    # keeps flagging a host the fix already handled.
    if [[ -f "$KERNEL_COREDUMP_CONF" || -d "$KERNEL_COREDUMP_D" ]]; then
        if ! grep -rqsE "^[[:space:]]*Storage=none" \
                "$KERNEL_COREDUMP_CONF" "$KERNEL_COREDUMP_D/" 2>/dev/null; then
            issues+=("systemd_coredump")
        fi
    fi

    echo "${issues[*]}"
}

# Display text for _kernel_check_core_dump's tokens. The tokens stay as they
# are because the fix's postcondition tests that output for emptiness.
_kernel_core_issue_text() {
    local tok out=() joined
    for tok in $1; do
        case "$tok" in
            no_core_limit|systemd_coredump) out+=("$(i18n "kernel.core_issue_$tok")") ;;
            *) out+=("$tok") ;;
        esac
    done
    printf -v joined '%s; ' "${out[@]}"
    echo "${joined%; }"
}

# The pass condition of _kernel_audit_core_dump: nothing left unrestricted.
_kernel_core_dump_restricted() {
    [[ -z "$(_kernel_check_core_dump)" ]]
}

# --- Kernel Audit ---

kernel_audit() {
    local module="kernel"

    # Check if running in a container first
    local container_type
    container_type=$(_kernel_is_container)
    if [[ -n "$container_type" ]]; then
        print_item "$(i18n 'kernel.check_container')"
        check_emit "kernel.container_detected" low failed \
            title="$(i18n 'kernel.container_detected' "type=$container_type")" \
            desc="$(i18n 'kernel.container_limitations')"
        print_info "$(i18n 'kernel.container_detected' "type=$container_type")"
        print_info "$(i18n 'kernel.container_limitations')"
    fi

    # Check ASLR
    print_item "$(i18n 'kernel.check_aslr')"
    _kernel_audit_aslr

    # Check network security parameters
    print_item "$(i18n 'kernel.check_network_params')"
    _kernel_audit_network_params

    # Check IPv6 security (dedicated section)
    print_item "$(i18n 'kernel.check_ipv6')"
    _kernel_audit_ipv6

    # Check kernel security parameters
    print_item "$(i18n 'kernel.check_kernel_params')"
    _kernel_audit_kernel_params

    # Check core dump settings
    print_item "$(i18n 'kernel.check_core_dump')"
    _kernel_audit_core_dump

    # Check rarely-used network protocol modules (Lynis NETW-3200)
    print_item "$(i18n 'kernel.check_unused_protocols')"
    _kernel_audit_unused_protocols

    print_item "$(i18n 'kernel.check_boot_params')"
    _kernel_audit_boot_params
}

# Are the rarely-used protocol modules blacklisted? dccp/sctp/rds/tipc ship
# enabled but are almost never needed on a server.
_kernel_audit_unused_protocols() {
    local protocols=("dccp" "sctp" "rds" "tipc")
    local unblocked=()
    local search_paths=(/etc/modprobe.d /usr/lib/modprobe.d /run/modprobe.d /lib/modprobe.d)
    local existing=()
    local p
    for p in "${search_paths[@]}"; do
        [[ -d "$p" ]] && existing+=("$p")
    done

    local proto
    for proto in "${protocols[@]}"; do
        local blocked=0
        if (( ${#existing[@]} > 0 )); then
            # Match: `install <proto> /bin/(true|false)` or `blacklist <proto>`
            if grep -rqsE "^[[:space:]]*(install[[:space:]]+${proto}[[:space:]]+/bin/(true|false)|blacklist[[:space:]]+${proto})([[:space:]]|$)" "${existing[@]}"; then
                blocked=1
            fi
        fi
        (( blocked == 0 )) && unblocked+=("$proto")
    done

    if (( ${#unblocked[@]} > 0 )); then
        local list="${unblocked[*]}"
        check_emit "kernel.unused_protocols_unblocked" low failed \
            title="$(i18n 'kernel.unused_protocols_unblocked' "count=${#unblocked[@]}")" \
            desc="$(i18n 'kernel.unused_protocols_unblocked_desc' "list=$list")" \
            suggestion="$(i18n 'kernel.unused_protocols_unblocked_suggestion')"
        print_severity "low" "$(i18n 'kernel.unused_protocols_unblocked' "count=${#unblocked[@]}")"
    else
        check_emit "kernel.unused_protocols_blocked" low passed \
            desc="$(i18n 'kernel.unused_protocols_blocked_desc' "protocols=${protocols[*]}")"
        print_ok "$(i18n 'kernel.unused_protocols_blocked')"
    fi
}

# --- IPv6 Audit Function ---

_kernel_audit_ipv6() {
    # Check if IPv6 is enabled
    if ! _kernel_ipv6_enabled; then
        check_emit "kernel.ipv6_disabled" low passed \
            desc="$(i18n 'kernel.ipv6_disabled_desc')"
        print_ok "$(i18n 'kernel.ipv6_disabled')"
        return
    fi

    # IPv6 is enabled - check if it's actively used
    local ipv6_stats=$(_kernel_ipv6_get_stats)
    local ipv6_in_use=$(_kernel_ipv6_in_use && echo "yes" || echo "no")
    local ipv6_issues=$(_kernel_ipv6_check_security)
    local ipv6_fw=$(_kernel_ipv6_firewall_check)

    # Report IPv6 status
    if [[ "$ipv6_in_use" == "yes" ]]; then
        # IPv6 is actively used
        local issue_count=$(echo "$ipv6_issues" | wc -w)

        if ! _kernel_ipv6_issues_ok yes "$issue_count"; then
            local tok ipv6_text=""
            for tok in $ipv6_issues; do
                ipv6_text+="$(i18n "kernel.ipv6_issue_$tok"); "
            done
            check_emit "kernel.ipv6_insecure" low failed \
                title="$(i18n 'kernel.ipv6_insecure' "count=$issue_count")" \
                desc="$(i18n 'kernel.ipv6_insecure_desc' "ipv6_issues=${ipv6_text%; }")" \
                suggestion="$(i18n 'kernel.fix_ipv6')" \
                fix="kernel.harden_ipv6"
            print_severity "low" "$(i18n 'kernel.ipv6_insecure' "count=$issue_count")"
        else
            check_emit "kernel.ipv6_secure" low passed \
                desc="$(i18n 'kernel.ipv6_secure_desc')"
            print_ok "$(i18n 'kernel.ipv6_secure')"
        fi
    else
        # IPv6 enabled but not actively used
        local issue_count=$(echo "$ipv6_issues" | wc -w)

        if ! _kernel_ipv6_issues_ok no "$issue_count"; then
            check_emit "kernel.ipv6_unused_insecure" low failed \
                desc="$(i18n 'kernel.ipv6_unused_insecure_desc')" \
                suggestion="$(i18n 'kernel.ipv6_unused_insecure_suggestion')" \
                fix="kernel.harden_ipv6"
            print_severity "low" "$(i18n 'kernel.ipv6_unused_insecure')"
        else
            check_emit "kernel.ipv6_enabled_unused" low passed \
                desc="$(i18n 'kernel.ipv6_enabled_unused_desc')"
            print_ok "$(i18n 'kernel.ipv6_enabled_unused')"
        fi
    fi

    # Check IPv6 firewall consistency (only if IPv6 is in use)
    if [[ "$ipv6_in_use" == "yes" ]]; then
        case "$ipv6_fw" in
            unfiltered)
                check_emit "kernel.ipv6_firewall_missing" medium failed \
                    desc="$(i18n 'kernel.ipv6_firewall_missing_desc')" \
                    suggestion="$(i18n 'kernel.ipv6_firewall_missing_suggestion')"
                print_severity "medium" "$(i18n 'kernel.ipv6_firewall_missing')"
                ;;
            filtered)
                check_emit "kernel.ipv6_firewall_ok" low passed \
                    desc="$(i18n 'kernel.ipv6_firewall_ok_desc')"
                print_ok "$(i18n 'kernel.ipv6_firewall_ok')"
                ;;
            unknown)
                check_emit "kernel.ipv6_firewall_unreadable" low failed \
                    desc="$(i18n 'kernel.ipv6_firewall_unreadable_desc')"
                print_severity "low" "$(i18n 'kernel.ipv6_firewall_unreadable')"
                ;;
        esac
    fi
}

_kernel_audit_aslr() {
    local aslr_status
    aslr_status=$(_kernel_check_aslr)

    case "$aslr_status" in
        full)
            check_emit "kernel.aslr_full" low passed \
                title="$(i18n 'kernel.aslr_enabled')" \
                desc="$(i18n 'kernel.aslr_full_desc')"
            print_ok "$(i18n 'kernel.aslr_enabled') (full)"
            ;;
        partial)
            check_emit "kernel.aslr_partial" low failed \
                desc="$(i18n 'kernel.aslr_partial_desc')" \
                suggestion="$(i18n 'kernel.fix_aslr')" \
                fix="kernel.enable_aslr"
            print_severity "low" "$(i18n 'kernel.aslr_partial')"
            ;;
        disabled)
            check_emit "kernel.aslr_disabled" medium failed \
                desc="$(i18n 'kernel.aslr_disabled_desc')" \
                suggestion="$(i18n 'kernel.fix_aslr')" \
                fix="kernel.enable_aslr"
            print_severity "medium" "$(i18n 'kernel.aslr_disabled')"
            ;;
        *)
            check_emit "kernel.aslr_unknown" low failed
            print_severity "low" "$(i18n 'kernel.aslr_unknown')"
            ;;
    esac
}

# The two param scopes. The audits and the fixes both scan through these, so
# a param is never audited in one scope and fixed in another.
KERNEL_NET_SCOPE='^net\.'
KERNEL_SYS_SCOPE='^(kernel\.|fs\.|dev\.)'

# One line per KERNEL_SECURITY_PARAMS entry in scope $1 (a regex), after the
# forwarding-host and RA-host exceptions: "ok - <param>", "bad <severity>
# <param> <expected> <actual>", "na - <param>" (unreadable) or "ra - <param>".
_kernel_param_scan() {
    local scope="$1" entry param rest expected severity actual rc host_uses_ra=""
    for entry in "${KERNEL_SECURITY_PARAMS[@]}"; do
        param="${entry%%:*}"
        rest="${entry#*:}"
        expected="${rest%%:*}"
        rest="${rest#*:}"
        severity="${rest%%:*}"
        [[ "$param" =~ $scope ]] || continue

        # IP forwarding is needed for Docker/LXC/Tailscale/WG/k3s/...
        if [[ "$param" == "net.ipv4.ip_forward" ]] && _kernel_ip_forward_needed; then
            continue
        fi

        # On a forwarding host rp_filter=2 (loose) is correct — strict mode
        # drops the asymmetric-return packets those workloads produce.
        # rp_filter=0 is still flagged: it permits spoofed source addresses.
        if [[ "$param" =~ ^net\.ipv4\.conf\.(all|default)\.rp_filter$ ]] \
           && _kernel_ip_forward_needed \
           && [[ "$(_kernel_get_sysctl "$param" 2>/dev/null)" == "2" ]]; then
            continue
        fi

        # On a SLAAC host accept_ra=1 / autoconf=1 are the CORRECT values:
        # disabling them drops the IPv6 default route, so no fix may act on them.
        if _kernel_param_is_ra_dependent "$param"; then
            if [[ -z "$host_uses_ra" ]]; then
                host_uses_ra=no
                _kernel_ipv6_uses_ra && host_uses_ra=yes
            fi
            if [[ "$host_uses_ra" == "yes" ]]; then
                echo "ra - $param"
                continue
            fi
        fi

        rc=0
        actual=$(_kernel_check_param "$param" "$expected") || rc=$?
        case "$rc" in
            0) echo "ok - $param" ;;
            1) echo "bad $severity $param $expected $actual" ;;
            *) echo "na - $param" ;;
        esac
    done
    return 0
}

# Pass conditions of the two param checks. The network one also needs one
# param read: reading none is network_params_unreadable, not a pass.
_kernel_network_params_ok() {
    local scan
    scan=$(_kernel_param_scan "$KERNEL_NET_SCOPE")
    ! grep -q '^bad ' <<<"$scan" && grep -q '^ok ' <<<"$scan"
}

_kernel_kernel_params_ok() {
    ! grep -q '^bad ' <<<"$(_kernel_param_scan "$KERNEL_SYS_SCOPE")"
}

_kernel_audit_network_params() {
    local issues_high=()
    local issues_medium=()
    local issues_low=()
    local passed=0
    local scan kind sev param expected actual

    scan=$(_kernel_param_scan "$KERNEL_NET_SCOPE")
    while read -r kind sev param expected actual; do
        case "$kind" in
            ok) passed=$((passed + 1)) ;;
            bad)
                case "$sev" in
                    high)   issues_high+=("$param=$actual $(i18n 'kernel.f_expected' "want=$expected")") ;;
                    medium) issues_medium+=("$param=$actual") ;;
                    low)    issues_low+=("$param=$actual") ;;
                esac
                ;;
        esac
    done <<<"$scan"

    local total_issues=$((${#issues_high[@]} + ${#issues_medium[@]} + ${#issues_low[@]}))

    # Severity is capped ONE tier below the parameter's weight, so the
    # *_high / *_medium check_ids name the source group, not the severity.
    # `desc` MUST list EVERY offending parameter, never a truncated head.
    if [[ ${#issues_high[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_high[@]}" | tr '\n' '; ')
        check_emit "kernel.network_params_high" medium failed \
            title="$(i18n 'kernel.network_params_insecure' "count=${#issues_high[@]}")" \
            desc="$(i18n 'kernel.network_params_high_desc' "list=$issue_list")" \
            suggestion="$(i18n 'kernel.fix_network_params')" \
            fix="kernel.harden_network"
        print_severity "medium" "$(i18n 'kernel.network_params_insecure' "count=${#issues_high[@]}")"
    fi

    # Medium and low report together, because the fix applies every net.*
    # param regardless of tier. A tier with no emit branch still counts
    # toward total_issues and suppresses the OK branch.
    local issues_weak=("${issues_medium[@]}" "${issues_low[@]}")
    if [[ ${#issues_weak[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_weak[@]}" | tr '\n' '; ')
        check_emit "kernel.network_params_medium" low failed \
            title="$(i18n 'kernel.network_params_weak' "count=${#issues_weak[@]}")" \
            desc="$(i18n 'kernel.network_params_medium_desc' "list=$issue_list")" \
            suggestion="$(i18n 'kernel.fix_network_params')" \
            fix="kernel.harden_network"
        print_severity "low" "$(i18n 'kernel.network_params_weak' "count=${#issues_weak[@]}")"
    fi

    if [[ $total_issues -eq 0 ]]; then
        # Zero issues from reading ZERO parameters is not a pass — it is a
        # /proc/sys we could not ask. failed + info, unscored, same pattern
        # as update.check_failed.
        if (( passed == 0 )); then
            check_emit "kernel.network_params_unreadable" low failed \
                desc="$(i18n 'kernel.network_params_unreadable_desc')"
            print_severity "low" "$(i18n 'kernel.network_params_unreadable')"
            return 0
        fi
        check_emit "kernel.network_params_ok" low passed \
            desc="$(i18n 'kernel.network_params_ok_desc' "passed=$passed")"
        print_ok "$(i18n 'kernel.network_params_ok')"
    fi
}

_kernel_audit_kernel_params() {
    local issues_high=()
    local issues_medium=()
    local issues_low=()
    local unavailable=()
    local passed=0
    local scan kind sev param expected actual

    # Check if we're in a container
    local in_container=false
    if _kernel_is_container &>/dev/null; then
        in_container=true
    fi

    # Unavailable params are common in containers; they are logged, not scored.
    scan=$(_kernel_param_scan "$KERNEL_SYS_SCOPE")
    while read -r kind sev param expected actual; do
        case "$kind" in
            ok) passed=$((passed + 1)) ;;
            na) unavailable+=("$param") ;;
            bad)
                case "$sev" in
                    high)   issues_high+=("$param=$actual $(i18n 'kernel.f_expected' "want=$expected")") ;;
                    medium) issues_medium+=("$param=$actual") ;;
                    low)    issues_low+=("$param=$actual") ;;
                esac
                ;;
        esac
    done <<<"$scan"

    local total_issues=$((${#issues_high[@]} + ${#issues_medium[@]} + ${#issues_low[@]}))

    # Report any high-severity kernel params separately. (Currently none in
    # KERNEL_SECURITY_PARAMS are tagged high — ASLR has its own check — so
    # this branch is dormant; kept for forward-compat if a high param is added.)
    if [[ ${#issues_high[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_high[@]}" | tr '\n' '; ')
        check_emit "kernel.kernel_params_high" medium failed \
            title="$(i18n 'kernel.kernel_params_critical' "count=${#issues_high[@]}")" \
            desc="$(i18n 'kernel.kernel_params_high_desc' "list=$issue_list")" \
            suggestion="$(i18n 'kernel.fix_kernel_params')" \
            fix="kernel.harden_kernel"
        print_severity "medium" "$(i18n 'kernel.kernel_params_critical' "count=${#issues_high[@]}")"
    fi

    # Report medium AND low tiers together (see _kernel_audit_network_params for
    # the rationale): the low tier had no emit branch yet counted toward
    # total_issues, so low-only deviations went completely silent.
    local issues_weak=("${issues_medium[@]}" "${issues_low[@]}")
    if [[ ${#issues_weak[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues_weak[@]}" | tr '\n' '; ')
        check_emit "kernel.kernel_params_weak" low failed \
            title="$(i18n 'kernel.kernel_params_weak' "count=${#issues_weak[@]}")" \
            desc="$(i18n 'kernel.kernel_params_weak_desc' "list=$issue_list")" \
            suggestion="$(i18n 'kernel.fix_kernel_params')" \
            fix="kernel.harden_kernel"
        print_severity "low" "$(i18n 'kernel.kernel_params_weak' "count=${#issues_weak[@]}")"
    fi

    # Report unavailable parameters (info only, not penalized)
    if [[ ${#unavailable[@]} -gt 0 ]] && [[ "$in_container" == true ]]; then
        local unavail_list=$(printf '%s ' "${unavailable[@]}")
        log_debug "Unavailable kernel params (container): $unavail_list"
    fi

    if [[ $total_issues -eq 0 ]]; then
        check_emit "kernel.kernel_params_ok" low passed \
            desc="$(i18n 'kernel.kernel_params_ok_desc' "passed=$passed")"
        print_ok "$(i18n 'kernel.kernel_params_ok')"
    fi
}

_kernel_audit_core_dump() {
    local issues
    issues=$(_kernel_check_core_dump)

    if [[ -z "$issues" ]]; then
        check_emit "kernel.core_dump_ok" low passed \
            title="$(i18n 'kernel.core_dump_disabled')" \
            desc="$(i18n 'kernel.core_dump_ok_desc')"
        print_ok "$(i18n 'kernel.core_dump_disabled')"
    else
        check_emit "kernel.core_dump_enabled" low failed \
            desc="$(i18n 'kernel.core_dump_enabled_desc' "issues=$(_kernel_core_issue_text "$issues")")" \
            suggestion="$(i18n 'kernel.fix_core_dump')" \
            fix="kernel.disable_core_dump"
        print_severity "low" "$(i18n 'kernel.core_dump_enabled')"
    fi
}

# --- Boot-time sysctl ---

# The sysctl.d files systemd-sysctl applies at boot, one path per line in the
# order it applies them: by file name, C collation. A masked name comes out as
# its /dev/null link, which reads empty.
_kernel_boot_sysctl_files() {
    local -A owner=()
    local dir f name
    for dir in "$SYSCTL_D" "${KERNEL_SYSCTL_BOOT_DIRS[@]}"; do
        for f in "$dir"/*.conf; do
            [[ -e "$f" || -L "$f" ]] && [[ ! -d "$f" ]] || continue
            name="${f##*/}"
            [[ -n "${owner[$name]:-}" ]] || owner[$name]="$f"
        done
    done
    (( ${#owner[@]} > 0 )) || return 0
    printf '%s\n' "${!owner[@]}" | LC_ALL=C sort | while IFS= read -r name; do
        printf '%s\n' "${owner[$name]}"
    done
}

# 1 when this systemd-sysctl expands glob keys (systemd 245 and later), else 0.
# An unreadable version counts as 1: every supported host but RHEL 8 (239) is.
_kernel_sysctl_globs() {
    local ver
    ver=$(systemctl --version 2>/dev/null | awk 'NR == 1 { print $2 }') || true
    if [[ "$ver" =~ ^[0-9]+$ ]] && (( ver < 245 )); then
        echo 0
    else
        echo 1
    fi
}

# For each parameter on stdin, "<param>\t<value>\t<file:line>": the value
# (first word) systemd-sysctl leaves it at after files $2...; no line when none
# sets it. $1 is _kernel_sysctl_globs.
_kernel_boot_values() {
    local globs="$1"
    shift
    # A re-assignment with a different value moves the key to the end, as do
    # globs in that order; an explicit key, or `-key` with no `=`, is never
    # matched by a glob. Keys compare in slash form, where * stops at a slash.
    KERNEL_BOOT_TARGETS="$(cat)" KERNEL_BOOT_GLOBS="$globs" awk '
        function strip(s) { sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s }
        function isglob(k) { return index(k, "*") || index(k, "?") || index(k, "[") }
        function norm(k,   i, c, out, first) {
            for (i = 1; i <= length(k); i++) {
                c = substr(k, i, 1)
                if (c == "." || c == "/") { first = c; break }
            }
            if (first == ".") {
                out = ""
                for (i = 1; i <= length(k); i++) {
                    c = substr(k, i, 1)
                    out = out (c == "." ? "/" : c == "/" ? "." : c)
                }
                k = out
            }
            gsub(/\/+/, "/", k); sub(/^\//, "", k); sub(/\/$/, "", k)
            return k
        }
        function glob2re(p,   i, j, c, re, cls) {
            re = "^"
            for (i = 1; i <= length(p); i++) {
                c = substr(p, i, 1)
                if (c == "*") re = re "[^/]*"
                else if (c == "?") re = re "[^/]"
                else if (c == "[" && (j = index(substr(p, i + 1), "]")) > 1) {
                    cls = substr(p, i + 1, j - 1)
                    if (substr(cls, 1, 1) == "!") cls = "^" substr(cls, 2)
                    re = re "[" cls "]"
                    i += j
                }
                else if (index("\\.^$+(){}|[]", c)) re = re "\\" c
                else re = re c
            }
            return re "$"
        }
        BEGIN { globs = ENVIRON["KERNEL_BOOT_GLOBS"] + 0 }
        {
            line = strip($0)
            if (line == "" || index("#;", substr(line, 1, 1))) next
            eq = index(line, "=")
            if (eq) {
                k = substr(line, 1, eq - 1); v = strip(substr(line, eq + 1)); hasv = 1
                if (substr(k, 1, 1) == "-") k = substr(k, 2)
            } else {
                if (substr(line, 1, 1) != "-" || !globs) next
                k = substr(line, 2); v = ""; hasv = 0
            }
            k = norm(strip(k))
            if (!globs && isglob(k)) next
            if ((k in seq) && has[k] == hasv && val[k] == v) next
            seq[k] = ++n; val[k] = v; has[k] = hasv; at[k] = FILENAME ":" FNR
        }
        END {
            nt = split(ENVIRON["KERNEL_BOOT_TARGETS"], t, "\n")
            for (i = 1; i <= nt; i++) {
                if (t[i] == "") continue
                key = norm(t[i]); hit = ""
                if (key in seq) {
                    if (has[key]) hit = key
                } else {
                    best = 0
                    for (g in seq)
                        if (has[g] && isglob(g) && seq[g] > best && key ~ glob2re(g)) { best = seq[g]; hit = g }
                }
                if (hit == "") continue
                split(val[hit], w, /[ \t]+/)
                if (w[1] != "") printf "%s\t%s\t%s\n", t[i], w[1], at[hit]
            }
        }' /dev/null "$@"
}

# Do the hardened runtime values survive a reboot? Only parameters that pass now
# are compared, against the audit's own expected values. A parameter no sysctl.d
# file sets keeps the kernel default, which cannot be read: listed, not judged.
_kernel_audit_boot_params() {
    local -a params=() expects=()
    local kind param
    while read -r kind _ param _; do
        [[ "$kind" == "ok" ]] || continue
        params+=("$param")
        expects+=("$(_kernel_param_expected "$param")")
    done <<<"$(_kernel_param_scan "$KERNEL_NET_SCOPE"; _kernel_param_scan "$KERNEL_SYS_SCOPE")"
    if _kernel_aslr_full; then
        params+=("kernel.randomize_va_space")
        expects+=("2")
    fi
    (( ${#params[@]} > 0 )) || return 0

    local -a files=() unreadable=()
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        [[ -r "$f" ]] || unreadable+=("$f")
        files+=("$f")
    done < <(_kernel_boot_sysctl_files)
    if (( ${#unreadable[@]} > 0 )); then
        check_emit "kernel.boot_params_unreadable" low failed \
            desc="$(i18n 'kernel.boot_params_unreadable_desc' "files=${unreadable[*]}")"
        print_severity "low" "$(i18n 'kernel.boot_params_unreadable')"
        return 0
    fi

    local targets globs value where
    local -A boot_value=() boot_at=() conf_at=()
    targets=$(printf '%s\n' "${params[@]}")
    globs=$(_kernel_sysctl_globs)
    while IFS=$'\t' read -r param value where; do
        boot_value[$param]="$value"
        boot_at[$param]="$where"
    done < <(_kernel_boot_values "$globs" "${files[@]}" <<<"$targets")

    # Where nothing in sysctl.d links SYSCTL_CONF (stock Debian 13, Ubuntu
    # 26.04), `sysctl -p` applies a setting written there and boot does not.
    if [[ -f "$SYSCTL_CONF" && -r "$SYSCTL_CONF" ]]; then
        local real linked=0
        real=$(readlink -f "$SYSCTL_CONF")
        for f in "${files[@]}"; do
            [[ "$(readlink -f "$f")" == "$real" ]] && { linked=1; break; }
        done
        if (( ! linked )); then
            while IFS=$'\t' read -r param value where; do
                conf_at[$param]="$where"
            done < <(_kernel_boot_values 0 "$SYSCTL_CONF" <<<"$targets")
        fi
    fi

    local -a findings=() unpersisted=()
    local i
    for i in "${!params[@]}"; do
        param="${params[$i]}"
        if [[ -n "${boot_value[$param]+x}" ]]; then
            _kernel_value_meets "${boot_value[$param]}" "${expects[$i]}" ||
                findings+=("$(i18n 'kernel.boot_params_weaker_item' "param=$param" \
                    "value=${boot_value[$param]}" "where=${boot_at[$param]}")")
        elif [[ -n "${conf_at[$param]+x}" ]]; then
            findings+=("$(i18n 'kernel.boot_params_ignored_item' "param=$param" \
                "where=${conf_at[$param]}")")
        else
            unpersisted+=("$param")
        fi
    done

    local note="" joined
    if (( ${#unpersisted[@]} > 0 )); then
        printf -v joined '%s, ' "${unpersisted[@]}"
        note=$(i18n 'kernel.boot_params_unset_note' "list=${joined%, }")
    fi
    if (( ${#findings[@]} > 0 )); then
        printf -v joined '%s; ' "${findings[@]}"
        check_emit "kernel.boot_params_revert" low failed \
            title="$(i18n 'kernel.boot_params_revert' "count=${#findings[@]}")" \
            desc="$(i18n 'kernel.boot_params_revert_desc' "list=${joined%; }" "unset=$note")" \
            suggestion="$(i18n 'kernel.boot_params_revert_suggestion')"
        print_severity "low" "$(i18n 'kernel.boot_params_revert' "count=${#findings[@]}")"
    else
        check_emit "kernel.boot_params_ok" low passed \
            desc="$(i18n 'kernel.boot_params_ok_desc' \
                "checked=$(( ${#params[@]} - ${#unpersisted[@]} ))" "unset=$note")"
        print_ok "$(i18n 'kernel.boot_params_ok')"
    fi
}

# --- Kernel Fix Functions ---

kernel_fix() {
    local fix_id="$1"

    case "$fix_id" in
        kernel.enable_aslr)
            _kernel_fix_aslr
            ;;
        kernel.harden_network)
            _kernel_fix_network_params
            ;;
        kernel.harden_kernel)
            _kernel_fix_kernel_params
            ;;
        kernel.harden_ipv6)
            _kernel_fix_ipv6
            ;;
        kernel.disable_core_dump)
            _kernel_fix_core_dump
            ;;
        *)
            log_error "Unknown kernel fix: $fix_id"
            return 1
            ;;
    esac
}

# --- IPv6 Fix Function ---

# True when the IPv6 default route comes from Router Advertisements, OR when
# that cannot be determined. Fail-safe: an unprobeable host is assumed to be
# on RA, so the caller SKIPS accept_ra rather than cutting IPv6.
_kernel_ipv6_uses_ra() {
    command -v ip >/dev/null 2>&1 || return 0

    # "The probe failed" and "the probe says no RA route" MUST stay apart:
    # piping straight into grep collapses them, and an `ip` that cannot answer
    # then reads as a statically configured host.
    local routes
    routes=$(ip -6 route show default 2>/dev/null) || return 0

    grep -q 'proto ra' <<<"$routes"
}

# The IPv6 params that would tear down a SLAAC default route if disabled.
# EVERY path that writes accept_ra must consult this — one unguarded path is
# enough to re-introduce the lockout.
_kernel_param_is_ra_dependent() {
    case "$1" in
        net.ipv6.conf.*.accept_ra|\
        net.ipv6.conf.*.accept_ra_defrtr|\
        net.ipv6.conf.*.accept_ra_pinfo|\
        net.ipv6.conf.*.accept_ra_rtr_pref|\
        net.ipv6.conf.*.autoconf|\
        net.ipv6.conf.*.max_addresses|\
        net.ipv6.conf.*.dad_transmits)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

_kernel_fix_ipv6() {
    print_info "$(i18n 'kernel.hardening_ipv6')"

    # Always-safe params: these harden IPv6 without changing how the host
    # obtains its address or default route.
    local ipv6_params=(
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_source_route=0"
        "net.ipv6.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.use_tempaddr=2"
        "net.ipv6.conf.default.use_tempaddr=2"
    )

    # RA-disabling params remove the SLAAC default route and global address,
    # so apply them ONLY on a host that does not rely on RA.
    if _kernel_ipv6_uses_ra; then
        print_warn "$(i18n 'kernel.ipv6_ra_skipped')"
        log_warn "kernel.harden_ipv6: host uses RA/SLAAC for its IPv6 default route; skipping accept_ra=0 to preserve connectivity"
    else
        ipv6_params+=(
            "net.ipv6.conf.all.accept_ra=0"
            "net.ipv6.conf.default.accept_ra=0"
        )
    fi

    local fixed=0
    local persist_failed=0

    for setting in "${ipv6_params[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        # A parameter counts as fixed only when runtime AND persistence
        # both landed — a runtime-only success evaporates on reboot.
        if sysctl -w "$param=$value" 2>/dev/null; then
            if _kernel_write_sysctl "$param" "$value"; then
                ((fixed++)) || true
            else
                ((persist_failed++)) || true
            fi
        fi
    done

    # Reload once after the batch; _kernel_write_sysctl no longer reloads
    # per-call (previously: N params = N reloads).
    ((fixed > 0)) && _kernel_reload_sysctl_dropin

    if (( persist_failed > 0 )); then
        print_error "$(i18n 'kernel.persist_failed' "count=$persist_failed")"
        return 1
    fi
    if [[ "$fixed" -gt 0 ]]; then
        print_ok "$(i18n 'kernel.ipv6_hardened' "count=$fixed")"
        return 0
    else
        print_warn "$(i18n 'kernel.ipv6_harden_failed')"
        return 1
    fi
}

_kernel_fix_aslr() {
    print_info "$(i18n 'kernel.enabling_aslr')"

    # Fire-and-forget: FIX_VERIFY re-reads the runtime value afterwards.
    sysctl -w kernel.randomize_va_space=2 2>/dev/null || true

    # A failed persist is a failed fix: a runtime-only success reverts to
    # weak ASLR on reboot with a "completed" entry in ok.json.
    if ! _kernel_write_sysctl "kernel.randomize_va_space" "2"; then
        print_error "$(i18n 'kernel.persist_failed' "count=1")"
        return 1
    fi
    _kernel_reload_sysctl_dropin
    return 0
}

_kernel_fix_network_params() {
    print_info "$(i18n 'kernel.hardening_network')"

    # Exactly the params the audit flags: same scan, same exceptions. Two passes,
    # because writing ip_forward resets every per-interface setting to its host
    # default — a param that was fine before can be wrong after the first pass.
    local params_to_set=() ra_skipped=false kind param expected setting value pass
    local applied=0 apply_failed=0
    for pass in 1 2; do
        params_to_set=()
        while read -r kind _ param expected _; do
            case "$kind" in
                bad) params_to_set+=("$param=$(_kernel_param_target "$expected")") ;;
                ra)  ra_skipped=true ;;
            esac
        done <<<"$(_kernel_param_scan "$KERNEL_NET_SCOPE")"
        (( ${#params_to_set[@]} > 0 )) || break

        # Counted, never assumed: fix bodies run with errexit off, so a bare
        # failing write would fall through into "hardened N".
        for setting in "${params_to_set[@]}"; do
            param="${setting%%=*}"
            value="${setting#*=}"
            if sysctl -w "$param=$value" 2>/dev/null && \
               _kernel_write_sysctl "$param" "$value"; then
                ((applied++)) || true
            else
                ((apply_failed++)) || true
            fi
        done
        (( apply_failed == 0 )) || break
    done

    [[ "$ra_skipped" == "true" ]] && print_warn "$(i18n 'kernel.ipv6_ra_skipped')"

    if (( applied == 0 && apply_failed == 0 )); then
        print_ok "$(i18n 'kernel.network_already_hardened')"
        return 0
    fi

    ((applied > 0)) && _kernel_reload_sysctl_dropin

    if (( apply_failed > 0 )); then
        print_error "$(i18n 'kernel.persist_failed' "count=$apply_failed")"
        return 1
    fi
    print_ok "$(i18n 'kernel.network_hardened' "count=$applied")"
    return 0
}

_kernel_fix_kernel_params() {
    print_info "$(i18n 'kernel.hardening_kernel')"

    local params_to_set=() kind param expected
    while read -r kind _ param expected _; do
        [[ "$kind" == "bad" ]] && params_to_set+=("$param=$(_kernel_param_target "$expected")")
    done <<<"$(_kernel_param_scan "$KERNEL_SYS_SCOPE")"

    if [[ ${#params_to_set[@]} -eq 0 ]]; then
        print_ok "$(i18n 'kernel.kernel_already_hardened')"
        return 0
    fi

    # Apply and persist — same counted pattern (and rationale) as
    # _kernel_fix_network_params above.
    local applied=0 apply_failed=0
    for setting in "${params_to_set[@]}"; do
        local param="${setting%%=*}"
        local value="${setting#*=}"

        if sysctl -w "$param=$value" 2>/dev/null && \
           _kernel_write_sysctl "$param" "$value"; then
            ((applied++)) || true
        else
            ((apply_failed++)) || true
        fi
    done

    ((applied > 0)) && _kernel_reload_sysctl_dropin

    if (( apply_failed > 0 )); then
        print_error "$(i18n 'kernel.persist_failed' "count=$apply_failed")"
        return 1
    fi
    print_ok "$(i18n 'kernel.kernel_hardened' "count=$applied")"
    return 0
}

_kernel_fix_core_dump() {
    print_info "$(i18n 'kernel.disabling_core_dump')"

    # Disable via sysctl. The persist status is checked because the
    # postcondition below reads the RUNTIME value, which `sysctl -w` just set:
    # a drop-in that never got written would pass it and revert at reboot.
    sysctl -w fs.suid_dumpable=0 2>/dev/null
    _kernel_write_sysctl "fs.suid_dumpable" "0" || return 1
    _kernel_reload_sysctl_dropin

    # PAM reads limits.conf on every login, so append through the atomic
    # writer: a partial line is a config error on every later login.
    if [[ -f "$KERNEL_LIMITS_CONF" ]]; then
        if ! grep -qE "^\*\s+hard\s+core\s+0" "$KERNEL_LIMITS_CONF"; then
            backup_file "$KERNEL_LIMITS_CONF" >/dev/null || return 1
            local limits_content
            limits_content=$(cat "$KERNEL_LIMITS_CONF")
            write_file_atomic "$KERNEL_LIMITS_CONF" \
                "${limits_content}"$'\n'"* hard core 0"$'\n'
        fi
    fi

    # The condition MUST mirror the audit's exactly: requiring the drop-in
    # directory while the audit accepts either path means the fix writes
    # nothing on a stock Debian host and claims success anyway.
    if [[ -f "$KERNEL_COREDUMP_CONF" || -d "$KERNEL_COREDUMP_D" ]]; then
        mkdir -p "$KERNEL_COREDUMP_D"
        backup_file "$KERNEL_COREDUMP_DROPIN" >/dev/null || return 1
        write_file_atomic "$KERNEL_COREDUMP_DROPIN" '[Coredump]
Storage=none
ProcessSizeMax=0'
    fi

    # Postcondition is the audit's own predicate, so this reports what was
    # achieved rather than what was attempted.
    local remaining
    remaining=$(_kernel_check_core_dump)
    if [[ -z "$remaining" ]]; then
        print_ok "$(i18n 'kernel.core_dump_disabled')"
        return 0
    fi

    print_warn "$(i18n 'kernel.core_dump_partial' "issues=$(_kernel_core_issue_text "$remaining")")"
    log_warn "kernel.disable_core_dump: still unrestricted after fix: $remaining"
    return 1
}


# Persist one sysctl. Each call rewrites the whole drop-in so the header
# appears once and an existing entry is replaced rather than duplicated.
# Does NOT reload — loop callers reload once after the loop.
_kernel_write_sysctl() {
    local param="$1"
    local value="$2"

    mkdir -p "$SYSCTL_D"

    # Strip previous header/blank lines AND any existing entry for this
    # param, leaving only clean `key = value` lines to replay.
    local existing=""
    if [[ -f "$VPSSEC_SYSCTL_CONF" ]]; then
        local param_re="${param//./\\.}"
        existing=$(grep -vE '^[[:space:]]*(#|$)' "$VPSSEC_SYSCTL_CONF" 2>/dev/null \
                   | grep -vE "^${param_re}[[:space:]]*=" || true)
    fi
    # UNCONDITIONAL: backup_file also records an absent path as fix-created,
    # which is the only thing that lets a rollback DELETE this drop-in.
    backup_file "$VPSSEC_SYSCTL_CONF" >/dev/null || return 1

    # Build the full drop-in and write it atomically — never a partial file:
    # this is persisted hardening replayed on every boot. write_file_atomic
    # sets 0644 for a new file and preserves the mode of an existing one.
    local content
    content="# vpssec kernel hardening configuration"$'\n'
    content+="# Generated: $(date -Iseconds)"$'\n'
    content+=$'\n'
    if [[ -n "$existing" ]]; then
        content+="$existing"$'\n'
    fi
    content+="$param = $value"

    write_file_atomic "$VPSSEC_SYSCTL_CONF" "$content"
}

# Reload the drop-in so persisted values take effect now, at the priority
# they will have after reboot. Silently a no-op where /proc/sys is read-only.
_kernel_reload_sysctl_dropin() {
    sysctl -p "$VPSSEC_SYSCTL_CONF" >/dev/null 2>&1 || true
}
