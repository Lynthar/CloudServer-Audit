#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# UFW firewall module
# Copyright (c) 2024

# ==============================================================================
# UFW Helper Functions
# ==============================================================================

# Check if UFW is installed
_ufw_installed() {
    check_command ufw
}

# Check if UFW is enabled
_ufw_enabled() {
    ufw status 2>/dev/null | grep -q "Status: active"
}

# Get UFW default incoming policy
_ufw_get_default_incoming() {
    ufw status verbose 2>/dev/null | grep "Default:" | grep -oP 'incoming\s+\K\w+'
}

# Get UFW default outgoing policy
_ufw_get_default_outgoing() {
    ufw status verbose 2>/dev/null | grep "Default:" | grep -oP 'outgoing\s+\K\w+'
}

# Check if SSH port is allowed
_ufw_ssh_allowed() {
    local ssh_port=$(get_ssh_port)
    ufw status 2>/dev/null | grep -qE "^${ssh_port}(/tcp)?\s+ALLOW"
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

    # Check if UFW is installed
    print_item "$(i18n 'ufw.check_installed')"
    if ! _ufw_installed; then
        local check=$(create_check_json \
            "ufw.not_installed" \
            "ufw" \
            "medium" \
            "failed" \
            "$(i18n 'ufw.not_installed')" \
            "UFW firewall is not installed" \
            "$(i18n 'ufw.fix_install')" \
            "ufw.install")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ufw.not_installed')"
        return
    fi
    print_ok "UFW installed"

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
    fi
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
            "high" \
            "failed" \
            "$(i18n 'ufw.disabled')" \
            "UFW is installed but not enabled" \
            "$(i18n 'ufw.fix_enable')" \
            "ufw.enable")
        state_add_check "$check"
        print_severity "high" "$(i18n 'ufw.disabled')"
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
            "high" \
            "failed" \
            "$(i18n 'ufw.default_incoming_accept')" \
            "Default incoming policy is ACCEPT" \
            "$(i18n 'ufw.fix_default_deny')" \
            "ufw.set_default_deny")
        state_add_check "$check"
        print_severity "high" "$(i18n 'ufw.default_incoming_accept')"
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
            "medium" \
            "failed" \
            "$(i18n 'ufw.no_ssh_rule')" \
            "SSH port $ssh_port is not explicitly allowed" \
            "$(i18n 'ufw.fix_allow_ssh')" \
            "ufw.allow_ssh")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'ufw.no_ssh_rule')"
    fi
}

_ufw_audit_permissive_rules() {
    local issues
    issues=$(_ufw_find_permissive_rules)
    local issue_count=$(echo "$issues" | grep -c . 2>/dev/null || echo 0)

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
        print_severity "$severity" "Overly permissive firewall rules: $issue_count"
    else
        local check=$(create_check_json \
            "ufw.rules_ok" \
            "ufw" \
            "low" \
            "passed" \
            "$(i18n 'ufw.no_permissive_rules')" \
            "No sensitive ports open to the world" \
            "" \
            "")
        state_add_check "$check"
        print_ok "No overly permissive firewall rules detected"
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
    print_info "Installing UFW..."

    if apt-get update -qq && apt-get install -y ufw; then
        print_ok "UFW installed successfully"
        return 0
    else
        print_error "Failed to install UFW"
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
    print_warn "Current rules before enabling:"
    ufw status 2>/dev/null | head -20

    if ! confirm_critical "$(i18n 'ufw.confirm_ufw_enable')"; then
        # Remove temporary rules if cancelled
        if [[ -n "$current_ip" ]]; then
            ufw delete allow from "$current_ip" 2>/dev/null
        fi
        return 1
    fi

    # Enable UFW
    print_info "Enabling UFW..."
    if echo "y" | ufw enable; then
        print_ok "$(i18n 'ufw.ufw_enabled')"

        # Remove temporary IP whitelist (SSH rule should be enough)
        if [[ -n "$current_ip" ]]; then
            ufw delete allow from "$current_ip" 2>/dev/null
        fi

        return 0
    else
        print_error "Failed to enable UFW"
        return 1
    fi
}

_ufw_fix_default_deny() {
    local ssh_port=$(get_ssh_port)

    # Ensure SSH is allowed first
    if ! _ufw_ssh_allowed; then
        print_info "Adding SSH rule before changing default policy..."
        ufw allow "$ssh_port/tcp" comment "SSH (vpssec)" 2>/dev/null
    fi

    # Set default deny incoming
    if ufw default deny incoming; then
        print_ok "Default incoming policy set to deny"

        # Set default allow outgoing (standard)
        ufw default allow outgoing 2>/dev/null

        return 0
    else
        print_error "Failed to set default policy"
        return 1
    fi
}

_ufw_fix_allow_ssh() {
    local ssh_port=$(get_ssh_port)

    if ufw allow "$ssh_port/tcp" comment "SSH (vpssec)"; then
        print_ok "$(i18n 'ufw.rule_added' "rule=${ssh_port}/tcp ALLOW")"
        return 0
    else
        print_error "Failed to add SSH rule"
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
