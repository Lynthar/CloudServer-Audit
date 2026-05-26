#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# UFW firewall module
# Copyright (c) 2024

# ==============================================================================
# Firewall Helper Functions
# ==============================================================================

# Check if UFW is installed
_ufw_installed() {
    check_command ufw
}

# Check if UFW is enabled
_ufw_enabled() {
    ufw status 2>/dev/null | grep -q "Status: active"
}

# Check if iptables has rules (beyond default)
#
# `grep -c` and `wc -l` always print an integer to stdout (0 on no
# matches / empty input); use `|| true` to swallow the exit-1-on-zero
# behavior of grep -c without ALSO appending a second "0" — the old
# `|| echo 0` produced the literal "0\n0" and tripped `[[ -gt ]]`
# with "syntax error in expression" on hosts where iptables existed
# but had no ACCEPT/DROP/REJECT lines.
_iptables_has_rules() {
    local rule_count
    rule_count=$(iptables -L -n 2>/dev/null | grep -cE "^(ACCEPT|DROP|REJECT)" || true)
    [[ "${rule_count:-0}" -gt 3 ]]  # More than default policy rules
}

# Check if nftables is active
_nftables_active() {
    if check_command nft; then
        local table_count
        table_count=$(nft list tables 2>/dev/null | wc -l || true)
        [[ "${table_count:-0}" -gt 0 ]]
    else
        return 1
    fi
}

# Check if firewalld is running
_firewalld_active() {
    systemctl is-active --quiet firewalld 2>/dev/null
}

# Detect active firewall type
# Returns: ufw, iptables, nftables, firewalld, or none
_detect_firewall() {
    if _ufw_enabled; then
        echo "ufw"
    elif _firewalld_active; then
        echo "firewalld"
    elif _nftables_active; then
        echo "nftables"
    elif _iptables_has_rules; then
        echo "iptables"
    else
        echo "none"
    fi
}

# Get UFW default incoming policy
_ufw_get_default_incoming() {
    ufw status verbose 2>/dev/null | grep "Default:" | grep -oP 'incoming\s+\K\w+'
}

# Get UFW default outgoing policy
_ufw_get_default_outgoing() {
    ufw status verbose 2>/dev/null | grep "Default:" | grep -oP 'outgoing\s+\K\w+'
}

# Check if SSH port is allowed.
# UFW emits a separate "22/tcp (v6) ALLOW ..." line for the IPv6 rule;
# the pattern has to accept an optional " (v6)" segment between the
# port spec and ALLOW or the v6-only case reports a false negative.
# Accept LIMIT as well as ALLOW: `ufw limit ssh` is the rate-limited
# variant (recommended for SSH against brute force) and used to be
# misreported as "no SSH rule", which then routed users to fix_allow_ssh
# — silently downgrading their LIMIT to a plain ALLOW.
_ufw_ssh_allowed() {
    local ssh_port=$(get_ssh_port)
    ufw status 2>/dev/null | grep -qE "^${ssh_port}(/tcp)?([[:space:]]+\(v6\))?[[:space:]]+(ALLOW|LIMIT)"
}

# Get current UFW rules
_ufw_get_rules() {
    ufw status numbered 2>/dev/null
}

# Check if a port is allowed
_ufw_port_allowed() {
    local port="$1"
    ufw status 2>/dev/null | grep -qE "^${port}(/tcp)?\s+ALLOW"
}

# Pure-data variant of _ufw_get_ipv6_setting for tests. $1 is the text
# of /etc/default/ufw. Returns "yes" or "no". Defaults to "yes" (the
# UFW package default since ~2014).
_ufw_parse_ipv6_setting() {
    local val
    val=$(awk -F= '
        /^IPV6=/ {
            v = $2
            gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", v)
            print tolower(v)
            exit
        }
    ' <<<"$1")
    echo "${val:-yes}"
}

_ufw_get_ipv6_setting() {
    local text=""
    [[ -f /etc/default/ufw ]] && text=$(cat /etc/default/ufw 2>/dev/null)
    _ufw_parse_ipv6_setting "$text"
}

# Pure-data variant. Returns 0 if input contains a global-scope inet6
# entry (output of `ip -6 addr show scope global`).
_host_has_global_ipv6_from_text() {
    grep -qE 'inet6[[:space:]]+[0-9a-fA-F:]+/[0-9]+.*scope[[:space:]]+global' <<<"$1"
}

_host_has_global_ipv6() {
    command -v ip >/dev/null 2>&1 || return 1
    local out
    out=$(ip -6 addr show scope global 2>/dev/null)
    _host_has_global_ipv6_from_text "$out"
}

# Detect overly permissive rules (from Anywhere to sensitive ports)
# Returns: list of problematic rules
_ufw_find_permissive_rules() {
    local issues=()

    # Sensitive ports that shouldn't be open to the world
    local sensitive_ports=(
        "3306:MySQL"
        "5432:PostgreSQL"
        "6379:Redis"
        "27017:MongoDB"
        "11211:Memcached"
        "5672:RabbitMQ"
        "9200:Elasticsearch"
        "2375:Docker"
        "2376:Docker TLS"
        "8080:HTTP Proxy"
        "23:Telnet"
        "21:FTP"
        "1433:MSSQL"
        "3389:RDP"
        "5900:VNC"
    )

    # Get UFW status
    local ufw_output
    ufw_output=$(ufw status 2>/dev/null)

    # Check for sensitive ports open to Anywhere
    for entry in "${sensitive_ports[@]}"; do
        local port="${entry%%:*}"
        local service="${entry#*:}"

        # Check if this port is ALLOW from Anywhere
        if echo "$ufw_output" | grep -qE "^${port}(/tcp)?\s+ALLOW\s+(IN\s+)?Anywhere"; then
            issues+=("$port ($service) open to Anywhere")
        fi
        if echo "$ufw_output" | grep -qE "^${port}/udp\s+ALLOW\s+(IN\s+)?Anywhere"; then
            issues+=("$port/udp ($service) open to Anywhere")
        fi
    done

    # Check for overly broad rules (allow all from specific IP with no port)
    # This is less critical but worth noting
    while read -r line; do
        if echo "$line" | grep -qE "ALLOW\s+IN\s+Anywhere\s*$" && ! echo "$line" | grep -qE "^(22|80|443)"; then
            # Non-standard port open to anywhere
            local rule_port=$(echo "$line" | awk '{print $1}')
            if [[ -n "$rule_port" && ! " ${sensitive_ports[*]%%:*} " =~ " ${rule_port%%/*} " ]]; then
                # Only flag if not already in sensitive_ports and not common web ports
                case "$rule_port" in
                    22|80|443|22/tcp|80/tcp|443/tcp) ;;
                    *)
                        issues+=("$rule_port open to Anywhere (review if needed)")
                        ;;
                esac
            fi
        fi
    done <<< "$ufw_output"

    printf '%s\n' "${issues[@]}"
}

# ==============================================================================
# UFW Audit
# ==============================================================================

ufw_audit() {
    local module="ufw"

    # First, detect what firewall is active
    print_item "$(i18n 'ufw.check_firewall_status')"
    local active_fw
    if declare -f fw_backend >/dev/null 2>&1; then
        active_fw=$(fw_backend)
    else
        active_fw=$(_detect_firewall)
    fi

    case "$active_fw" in
        ufw)
            local check=$(create_check_json \
                "ufw.firewall_active" \
                "ufw" \
                "low" \
                "passed" \
                "$(i18n 'ufw.firewall_active' "type=UFW")" \
                "" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'ufw.firewall_active' "type=UFW")"
            ;;
        firewalld)
            local check=$(create_check_json \
                "ufw.firewall_active" \
                "ufw" \
                "low" \
                "passed" \
                "$(i18n 'ufw.firewall_active' "type=firewalld")" \
                "$(i18n 'ufw.other_firewall_note')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'ufw.firewall_active' "type=firewalld")"
            # Skip UFW-specific checks
            return
            ;;
        nftables)
            local check=$(create_check_json \
                "ufw.firewall_active" \
                "ufw" \
                "low" \
                "passed" \
                "$(i18n 'ufw.firewall_active' "type=nftables")" \
                "$(i18n 'ufw.other_firewall_note')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'ufw.firewall_active' "type=nftables")"
            # Lynis FIRE-4540 cross-check: "firewall active" via kernel
            # module is necessary but not sufficient — an empty ruleset
            # is functionally equivalent to no firewall. Surface that.
            _ufw_audit_ruleset_empty "nftables"
            return
            ;;
        iptables)
            local check=$(create_check_json \
                "ufw.firewall_active" \
                "ufw" \
                "low" \
                "passed" \
                "$(i18n 'ufw.firewall_active' "type=iptables")" \
                "$(i18n 'ufw.other_firewall_note')" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'ufw.firewall_active' "type=iptables")"
            # Lynis FIRE-4512 cross-check (same rationale as nftables above).
            _ufw_audit_ruleset_empty "iptables"
            return
            ;;
        none)
            # No firewall active - this is a security issue. The remediation
            # hint is distro-aware: UFW is only the right front-end on
            # Debian/Ubuntu. RHEL ships firewalld and Arch typically uses
            # nftables, so steer those users away from "install UFW".
            local nf_suggestion
            if [[ "${VPSSEC_DISTRO_FAMILY:-debian}" == "debian" ]]; then
                nf_suggestion=$(i18n 'ufw.fix_install')
            else
                nf_suggestion=$(i18n 'ufw.fix_enable_firewall')
            fi
            local check=$(create_check_json \
                "ufw.no_firewall" \
                "ufw" \
                "medium" \
                "failed" \
                "$(i18n 'ufw.no_firewall')" \
                "$(i18n 'ufw.no_firewall_desc')" \
                "$nf_suggestion" \
                "ufw.install")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'ufw.no_firewall')"
            # Continue to check if UFW is installed but not enabled
            ;;
    esac

    # Check if UFW is installed
    print_item "$(i18n 'ufw.check_installed')"
    if ! _ufw_installed; then
        # "UFW not installed" is only actionable on Debian/Ubuntu, where
        # UFW is the standard front-end. On RHEL/Arch the active firewall
        # was already probed above; a "none" result has emitted the
        # high-severity no_firewall check, so recommending UFW here would
        # be both redundant and wrong for those distros.
        if [[ "${VPSSEC_DISTRO_FAMILY:-debian}" == "debian" ]]; then
            local check=$(create_check_json \
                "ufw.not_installed" \
                "ufw" \
                "low" \
                "failed" \
                "$(i18n 'ufw.not_installed')" \
                "$(i18n 'ufw.not_installed_desc')" \
                "$(i18n 'ufw.fix_install')" \
                "ufw.install")
            state_add_check "$check"
            print_severity "low" "$(i18n 'ufw.not_installed')"
        fi
        return
    fi
    print_ok "$(i18n 'ufw.ufw_installed')"

    # Check if UFW is enabled
    print_item "$(i18n 'ufw.check_enabled')"
    _ufw_audit_enabled

    # Check default policy
    print_item "$(i18n 'ufw.check_default_policy')"
    _ufw_audit_default_policy

    # Check SSH rule
    print_item "$(i18n 'ufw.check_ssh_rule')"
    _ufw_audit_ssh_rule

    # Check for permissive rules (only if UFW is enabled)
    if _ufw_enabled; then
        print_item "$(i18n 'ufw.check_permissive_rules')"
        _ufw_audit_permissive_rules

        # IPv6 consistency: IPV6=no in /etc/default/ufw + host has global
        # v6 = v6 packets bypass UFW entirely. Only meaningful when UFW
        # is the active firewall.
        print_item "$(i18n 'ufw.check_ipv6_consistency')"
        _ufw_audit_ipv6_consistency
    fi
}

# Decide whether the active (non-ufw/non-firewalld) backend actually
# enforces HOST INGRESS filtering. The previous version counted every
# rule in every chain, which reported a host as "firewalled" whenever a
# container runtime was present: Docker/podman populate FORWARD/NAT and
# custom chains (DOCKER, DOCKER-USER, ...) that filter container traffic
# but do NOT protect host-level services. On a modern iptables-nft host
# those rules even land in nftables, so fw_backend returns "nftables"
# and the ruleset looks busy while the host's INPUT path is wide open.
#
# Correct signal = the input hook: a host is protected if its input
# chain has at least one rule OR a default drop/reject policy (a
# default-drop input with no explicit rules is still enforcement — the
# old all-chains count flagged that secure case as "empty", a separate
# false positive this also fixes).
#
# Fail-safe: on any parse/query failure we return WITHOUT flagging, so
# we never raise a false "empty" alarm on a host we could not read.
_ufw_audit_ruleset_empty() {
    local backend="$1"
    local ingress_rules=0
    local default_drop=0

    case "$backend" in
        nftables)
            command -v nft >/dev/null 2>&1 || return 0
            local nft_out
            nft_out=$(nft --stateless list ruleset 2>/dev/null) || return 0
            [[ -z "$nft_out" ]] && return 0
            # Walk base chains; count rules only inside chains hooked to
            # `input`, and note a drop/reject policy on that hook. The
            # close-brace test requires a lone `}` so an inline anonymous
            # set (`tcp dport { 22, 80 } accept`) does not close the chain.
            # [ \t] (not [[:space:]]) keeps this portable to mawk.
            read -r ingress_rules default_drop <<<"$(awk '
                /^[ \t]*chain[ \t]/ { inchain=1; isinput=0; next }
                inchain && /^[ \t]*[}][ \t]*$/ { inchain=0; isinput=0; next }
                inchain && /hook[ \t]+input/ {
                    isinput=1
                    if ($0 ~ /policy[ \t]+(drop|reject)/) pol=1
                    next
                }
                inchain && isinput && $0 !~ /^[ \t]*$/ { r++ }
                END { print r+0, pol+0 }
            ' <<<"$nft_out")"
            ;;
        iptables)
            command -v iptables >/dev/null 2>&1 || return 0
            local pol
            pol=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT /{print $3; exit}')
            [[ "$pol" == "DROP" || "$pol" == "REJECT" ]] && default_drop=1
            # Count INPUT-chain rules only (host ingress); a jump to a
            # custom chain counts as a rule, so split firewalls still pass.
            ingress_rules=$(iptables -S INPUT 2>/dev/null | grep -cEv '^(-P|-N|$)' || true)
            ;;
        *)
            return 0
            ;;
    esac

    # Protected if the input hook drops by default or carries any rule.
    if (( default_drop == 1 )) || (( ingress_rules > 0 )); then
        return 0
    fi

    local check=$(create_check_json \
        "ufw.firewall_empty" \
        "ufw" \
        "medium" \
        "failed" \
        "$(i18n 'ufw.firewall_empty' "type=$backend" 2>/dev/null || echo "$backend active but host ingress is unfiltered")" \
        "$backend is active but the host ingress (input) chain has no rules and no default drop/reject policy; host services are unfiltered. Container runtimes add forwarding/NAT rules that do not protect the host." \
        "$(i18n 'ufw.fix_firewall_empty' 2>/dev/null || echo "Add input rules (or a default-deny input policy), or use a managed front-end like UFW/firewalld")" \
        "")
    state_add_check "$check"
    print_severity "medium" "$(i18n 'ufw.firewall_empty' "type=$backend" 2>/dev/null || echo "$backend active but host ingress unfiltered")"
}

_ufw_audit_enabled() {
    if _ufw_enabled; then
        local check=$(create_check_json \
            "ufw.enabled" \
            "ufw" \
            "low" \
            "passed" \
            "$(i18n 'ufw.enabled')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ufw.enabled')"
    else
        local check=$(create_check_json \
            "ufw.disabled" \
            "ufw" \
            "medium" \
            "failed" \
            "$(i18n 'ufw.disabled')" \
            "UFW is installed but not enabled" \
            "$(i18n 'ufw.fix_enable')" \
            "ufw.enable")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ufw.disabled')"
    fi
}

_ufw_audit_default_policy() {
    local incoming=$(_ufw_get_default_incoming)

    if [[ "${incoming,,}" == "deny" || "${incoming,,}" == "reject" ]]; then
        local check=$(create_check_json \
            "ufw.default_deny" \
            "ufw" \
            "low" \
            "passed" \
            "$(i18n 'ufw.default_incoming_deny')" \
            "Default incoming: $incoming" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ufw.default_incoming_deny')"
    elif [[ "${incoming,,}" == "allow" ]]; then
        local check=$(create_check_json \
            "ufw.default_accept" \
            "ufw" \
            "medium" \
            "failed" \
            "$(i18n 'ufw.default_incoming_accept')" \
            "Default incoming policy is ACCEPT" \
            "$(i18n 'ufw.fix_default_deny')" \
            "ufw.set_default_deny")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ufw.default_incoming_accept')"
    fi
}

_ufw_audit_ssh_rule() {
    local ssh_port=$(get_ssh_port)

    if _ufw_ssh_allowed; then
        local check=$(create_check_json \
            "ufw.ssh_allowed" \
            "ufw" \
            "low" \
            "passed" \
            "$(i18n 'ufw.ssh_rule_exists' "port=$ssh_port")" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ufw.ssh_rule_exists' "port=$ssh_port")"
    else
        local check=$(create_check_json \
            "ufw.no_ssh_rule" \
            "ufw" \
            "low" \
            "failed" \
            "$(i18n 'ufw.no_ssh_rule')" \
            "SSH port $ssh_port is not explicitly allowed" \
            "$(i18n 'ufw.fix_allow_ssh')" \
            "ufw.allow_ssh")
        state_add_check "$check"
        print_severity "low" "$(i18n 'ufw.no_ssh_rule')"
    fi
}

_ufw_audit_ipv6_consistency() {
    local ipv6_setting
    ipv6_setting=$(_ufw_get_ipv6_setting)

    if [[ "$ipv6_setting" == "yes" ]]; then
        local check=$(create_check_json \
            "ufw.ipv6_managed" \
            "ufw" \
            "low" \
            "passed" \
            "$(i18n 'ufw.ipv6_managed')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ufw.ipv6_managed')"
        return
    fi

    # IPV6=no — check whether the host actually has v6 connectivity.
    if _host_has_global_ipv6; then
        local check=$(create_check_json \
            "ufw.ipv6_bypass" \
            "ufw" \
            "medium" \
            "failed" \
            "$(i18n 'ufw.ipv6_bypass')" \
            "$(i18n 'ufw.ipv6_bypass_desc')" \
            "$(i18n 'ufw.fix_enable_ipv6')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ufw.ipv6_bypass')"
    else
        local check=$(create_check_json \
            "ufw.ipv6_no_traffic" \
            "ufw" \
            "info" \
            "passed" \
            "$(i18n 'ufw.ipv6_no_traffic')" \
            "" \
            "" \
            "")
        state_add_check "$check"
    fi
}

_ufw_audit_permissive_rules() {
    local issues
    issues=$(_ufw_find_permissive_rules)
    local issue_count=$(count_lines "$issues")

    if [[ -n "$issues" && "$issue_count" -gt 0 ]]; then
        local issue_list=""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            issue_list+="$issue; "
        done <<< "$issues"
        issue_list="${issue_list%; }"

        # Check severity - sensitive database ports are high risk
        local severity="medium"
        if echo "$issues" | grep -qE "(MySQL|PostgreSQL|Redis|MongoDB|Elasticsearch|Docker)"; then
            severity="high"
        fi

        local check=$(create_check_json \
            "ufw.permissive_rules" \
            "ufw" \
            "$severity" \
            "failed" \
            "$(i18n 'ufw.permissive_rules_found' "count=$issue_count")" \
            "$issue_list" \
            "$(i18n 'ufw.fix_restrict_rules')" \
            "ufw.review_rules")
        state_add_check "$check"
        print_severity "$severity" "$(i18n 'ufw.permissive_rules_found' "count=$issue_count")"
    else
        local check=$(create_check_json \
            "ufw.rules_ok" \
            "ufw" \
            "low" \
            "passed" \
            "$(i18n 'ufw.no_permissive_rules')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'ufw.no_permissive_rules')"
    fi
}

# ==============================================================================
# UFW Fix Functions
# ==============================================================================

ufw_fix() {
    local fix_id="$1"

    case "$fix_id" in
        ufw.install)
            _ufw_fix_install
            ;;
        ufw.enable)
            _ufw_fix_enable
            ;;
        ufw.set_default_deny)
            _ufw_fix_default_deny
            ;;
        ufw.allow_ssh)
            _ufw_fix_allow_ssh
            ;;
        ufw.review_rules)
            _ufw_fix_review_rules
            ;;
        *)
            log_error "Unknown UFW fix: $fix_id"
            return 1
            ;;
    esac
}

_ufw_fix_install() {
    print_info "$(i18n 'ufw.installing_ufw')"

    if apt-get update -qq && apt-get install -y ufw; then
        print_ok "$(i18n 'ufw.ufw_installed')"
        return 0
    else
        print_error "$(i18n 'ufw.ufw_install_failed')"
        return 1
    fi
}

_ufw_fix_enable() {
    local ssh_port=$(get_ssh_port)
    local current_ip=$(get_current_ssh_ip)

    # Safety: ensure SSH is allowed before enabling
    print_info "$(i18n 'ufw.fix_allow_ssh') (port $ssh_port)"

    # Allow SSH first
    ufw allow "$ssh_port/tcp" comment "SSH (vpssec)" 2>/dev/null

    # If we have current connection IP, whitelist it
    if [[ -n "$current_ip" ]]; then
        print_info "$(i18n 'ufw.current_ip_whitelisted' "ip=$current_ip")"
        ufw allow from "$current_ip" comment "Current session (vpssec temp)" 2>/dev/null
    fi

    # Critical confirmation
    print_msg ""
    print_warn "$(i18n 'ufw.current_rules')"
    ufw status 2>/dev/null | head -20

    if ! confirm_critical "$(i18n 'ufw.confirm_ufw_enable')"; then
        # Remove temporary rules if cancelled
        if [[ -n "$current_ip" ]]; then
            ufw delete allow from "$current_ip" 2>/dev/null
        fi
        return 1
    fi

    # Enable UFW
    print_info "$(i18n 'ufw.enabling_ufw')"
    if echo "y" | ufw enable; then
        print_ok "$(i18n 'ufw.ufw_enabled')"

        # Remove temporary IP whitelist (SSH rule should be enough)
        if [[ -n "$current_ip" ]]; then
            ufw delete allow from "$current_ip" 2>/dev/null
        fi

        return 0
    else
        print_error "$(i18n 'ufw.ufw_enable_failed')"
        return 1
    fi
}

_ufw_fix_default_deny() {
    local ssh_port=$(get_ssh_port)

    # Ensure SSH is allowed first
    if ! _ufw_ssh_allowed; then
        print_info "$(i18n 'ufw.adding_ssh_rule')"
        ufw allow "$ssh_port/tcp" comment "SSH (vpssec)" 2>/dev/null
    fi

    # Set default deny incoming
    if ufw default deny incoming; then
        print_ok "$(i18n 'ufw.default_deny_set')"

        # Set default allow outgoing (standard)
        ufw default allow outgoing 2>/dev/null

        return 0
    else
        print_error "$(i18n 'ufw.default_deny_failed')"
        return 1
    fi
}

_ufw_fix_allow_ssh() {
    local ssh_port=$(get_ssh_port)

    if ufw allow "$ssh_port/tcp" comment "SSH (vpssec)"; then
        print_ok "$(i18n 'ufw.rule_added' "rule=${ssh_port}/tcp ALLOW")"
        return 0
    else
        print_error "$(i18n 'ufw.ssh_rule_failed')"
        return 1
    fi
}

_ufw_fix_review_rules() {
    print_warn "$(i18n 'ufw.review_rules_title' 2>/dev/null || echo 'Overly Permissive Firewall Rules Detected')"
    echo ""

    # Show current problematic rules
    local issues=$(_ufw_find_permissive_rules)
    if [[ -n "$issues" ]]; then
        echo "$(i18n 'ufw.problematic_rules' 2>/dev/null || echo 'Problematic rules found'):"
        echo ""
        while IFS= read -r issue; do
            [[ -z "$issue" ]] && continue
            echo "  ⚠️  $issue"
        done <<< "$issues"
        echo ""
    fi

    echo "$(i18n 'ufw.recommendations' 2>/dev/null || echo 'Recommendations'):"
    echo ""
    echo "  1. $(i18n 'ufw.rec_restrict_source' 2>/dev/null || echo 'Restrict source IPs for database/internal services'):"
    echo "     ufw delete allow 3306"
    echo "     ufw allow from 10.0.0.0/8 to any port 3306 comment 'MySQL internal'"
    echo ""
    echo "  2. $(i18n 'ufw.rec_use_localhost' 2>/dev/null || echo 'Use localhost binding for database services'):"
    echo "     Configure MySQL/PostgreSQL/Redis to bind to 127.0.0.1"
    echo ""
    echo "  3. $(i18n 'ufw.rec_use_vpn' 2>/dev/null || echo 'Use VPN or SSH tunnel for remote access'):"
    echo "     ssh -L 3306:localhost:3306 user@server"
    echo ""
    echo "  4. $(i18n 'ufw.rec_review_numbered' 2>/dev/null || echo 'Review and delete unnecessary rules'):"
    echo "     ufw status numbered"
    echo "     ufw delete <rule_number>"
    echo ""

    return 1  # Return 1 since this is informational only
}

# ==============================================================================
# UFW Utility Functions for Other Modules
# ==============================================================================

# Allow a port (can be called from other modules)
ufw_allow_port() {
    local port="$1"
    local proto="${2:-tcp}"
    local comment="${3:-vpssec}"

    if _ufw_enabled; then
        ufw allow "$port/$proto" comment "$comment" 2>/dev/null
    fi
}

# Allow from specific IP
ufw_allow_from() {
    local ip="$1"
    local port="${2:-}"
    local comment="${3:-vpssec}"

    if _ufw_enabled; then
        if [[ -n "$port" ]]; then
            ufw allow from "$ip" to any port "$port" comment "$comment" 2>/dev/null
        else
            ufw allow from "$ip" comment "$comment" 2>/dev/null
        fi
    fi
}
