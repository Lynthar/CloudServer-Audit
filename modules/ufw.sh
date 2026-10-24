#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# UFW firewall module
# Copyright (c) 2024

# --- Firewall Helper Functions ---

# Check if UFW is installed
_ufw_installed() {
    check_command ufw
}

# LC_ALL=C is load-bearing on every ufw parse here: ufw gettext-translates
# "Status: active", and a translated locale makes an active UFW read as
# inactive, after which every UFW-specific check is silently skipped.
_ufw_enabled() {
    LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"
}

# UFW default incoming/outgoing policy. The verbose line reads
# "Default: deny (incoming), ...", so the policy word PRECEDES the paren —
# parse backwards from "(incoming)". LC_ALL=C: ufw translates "Default:".
_ufw_get_default_incoming() {
    LC_ALL=C ufw status verbose 2>/dev/null | grep "Default:" | grep -oP '\w+(?=\s*\(incoming\))'
}

# Pass condition of the default-policy check: incoming deny or reject. $1 is
# the policy already read; omitted, ufw is asked.
_ufw_default_deny() {
    local incoming="${1-$(_ufw_get_default_incoming)}"
    [[ "${incoming,,}" == "deny" || "${incoming,,}" == "reject" ]]
}

# Get UFW default outgoing policy
_ufw_get_default_outgoing() {
    LC_ALL=C ufw status verbose 2>/dev/null | grep "Default:" | grep -oP '\w+(?=\s*\(outgoing\))'
}

# ufw's own rule store. Its `### tuple ###` lines hold every added rule
# whether or not ufw is active, with app profiles already resolved to ports;
# `ufw status` lists nothing while inactive.
UFW_USER_RULES="/etc/ufw/user.rules"
UFW_USER6_RULES="/etc/ufw/user6.rules"

# Is TCP port $1 let in by an inbound ALLOW/LIMIT rule? Never OUT, routed or
# DENY: outbound read as inbound is a lockout. $2 "any" (default) counts rules
# confined to an interface or source; "open" only rules from anywhere.
_ufw_admits_port() {
    local port="$1" scope="${2:-any}" f
    local -a files=()
    for f in "$UFW_USER_RULES" "$UFW_USER6_RULES"; do
        [[ -r "$f" ]] && files+=("$f")
    done
    (( ${#files[@]} > 0 )) || return 1
    awk -v p="$port" -v scope="$scope" '
        function wild(a) { return a == "0.0.0.0/0" || a == "::/0" }
        $1 == "###" && $2 == "tuple" && $3 == "###" {
            n = NF
            if ($n ~ /^comment=/) n--
            if ($4 != "allow" && $4 != "limit") next
            if ($n !~ /^in(_|$)/) next
            if ($5 != "tcp" && $5 != "any") next
            if (scope == "open" && ($n != "in" || !wild($7) || !wild($9))) next
            if ($6 == "any") { hit = 1; exit }
            k = split($6, items, ",")
            for (i = 1; i <= k; i++) {
                if (split(items[i], r, ":") == 2) {
                    if (p + 0 >= r[1] + 0 && p + 0 <= r[2] + 0) { hit = 1; exit }
                } else if (items[i] + 0 == p + 0) { hit = 1; exit }
            }
        }
        END { exit !hit }
    ' "${files[@]}"
}

# Pass condition of the SSH rule check, and FIX_VERIFY's: every port sshd
# listens on is admitted inbound by some rule.
_ufw_ssh_allowed() {
    local port
    while read -r port; do
        _ufw_admits_port "$port" || return 1
    done < <(get_ssh_ports)
    return 0
}

# Every SSH port no rule opens to anywhere, one per line: the ports enable and
# set_default_deny must add before the policy turns to deny. A LIMIT rule
# already covers its port, so it is kept rather than rewritten into ALLOW.
_ufw_ssh_ports_unopened() {
    local port
    while read -r port; do
        _ufw_admits_port "$port" open || echo "$port"
    done < <(get_ssh_ports)
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

# What app profile $1 opens, as ufw resolved it into its rule store: one
# "<ports>[/<proto>]" per inbound ALLOW/LIMIT tuple naming it (ufw writes a
# space in the name as %20). Nothing when no tuple names it.
_ufw_app_ports() {
    local f
    local -a files=()
    for f in "$UFW_USER_RULES" "$UFW_USER6_RULES"; do
        [[ -r "$f" ]] && files+=("$f")
    done
    (( ${#files[@]} > 0 )) || return 0
    APP="$1" awk '
        $1 == "###" && $2 == "tuple" && $3 == "###" {
            n = NF
            if ($n ~ /^comment=/) n--
            if (n < 12 || ($4 != "allow" && $4 != "limit") || $n !~ /^in(_|$)/) next
            app = $10
            gsub(/%20/, " ", app)
            if (app != ENVIRON["APP"]) next
            p = $6 (($5 == "any") ? "" : "/" $5)
            if (!(p in seen)) { seen[p] = 1; print p }
        }
    ' "${files[@]}"
}

# Is every port in the "<ports>[/<proto>]" lines of $2 in the space-padded list
# $1? A range is never in it.
_ufw_ports_expected() {
    local ok="$1" t list p
    while read -r t; do
        list="${t%%/*}"
        for p in ${list//,/ }; do
            [[ "$ok" == *" $p "* ]] || return 1
        done
    done <<<"$2"
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

    # Get UFW status (LC_ALL=C: ufw translates "Anywhere"/"ALLOW" under a
    # non-C locale, which would defeat the matches below).
    local ufw_output
    ufw_output=$(LC_ALL=C ufw status 2>/dev/null)

    # Check for sensitive ports open to Anywhere
    for entry in "${sensitive_ports[@]}"; do
        local port="${entry%%:*}"
        local service="${entry#*:}"

        # ALLOW or LIMIT from Anywhere: a rate limit still lets the world in.
        if echo "$ufw_output" | grep -qE "^${port}(/tcp)?\s+(ALLOW|LIMIT)\s+(IN\s+)?Anywhere"; then
            issues+=("$(i18n 'ufw.f_open_anywhere' "port=$port ($service)")")
        fi
        if echo "$ufw_output" | grep -qE "^${port}/udp\s+(ALLOW|LIMIT)\s+(IN\s+)?Anywhere"; then
            issues+=("$(i18n 'ufw.f_open_anywhere' "port=$port/udp ($service)")")
        fi
    done

    # Any other inbound ALLOW/LIMIT from anywhere is listed for review by the port
    # it ends in, an app profile by the ports ufw resolved it to. Not SSH (each
    # port sshd listens on) or web; not interface-bound rules or "(v6)" copies.
    local open_ok=" 22 80 443 $(get_ssh_ports | tr '\n' ' ')"
    local line to tok ports
    while IFS= read -r line; do
        # Without its comment: one reading "ALLOW Anywhere" would be matched instead.
        line="${line%%#*}"
        [[ "$line" =~ ^(.*[^[:space:]])[[:space:]]+(ALLOW|LIMIT)[[:space:]]+(IN[[:space:]]+)?Anywhere ]] || continue
        to="${BASH_REMATCH[1]}"
        [[ "$to" == *" on "* || "$to" == *" (v6)" ]] && continue
        tok="${to##* }"
        if [[ "$tok" =~ ^[0-9][0-9,:]*(/(tcp|udp))?$ ]]; then
            [[ "$open_ok" == *" ${tok%%/*} "* ]] && continue
            [[ " ${sensitive_ports[*]%%:*} " == *" ${tok%%/*} "* ]] && continue
        else
            # An app profile, or every port (Anywhere, one address): what the rule
            # store resolves it to decides; anything unresolved is listed by name.
            ports=$(_ufw_app_ports "$to")
            if [[ -n "$ports" ]]; then
                _ufw_ports_expected "$open_ok" "$ports" && continue
                tok="$to ($(paste -sd' ' - <<<"$ports"))"
            else
                tok="$to"
            fi
        fi
        issues+=("$(i18n 'ufw.f_open_anywhere_review' "port=$tok")")
    done <<< "$ufw_output"

    printf '%s\n' "${issues[@]}"
}

# --- UFW Audit ---

ufw_audit() {
    local module="ufw"

    # First, detect what firewall is active
    print_item "$(i18n 'ufw.check_firewall_status')"
    local active_fw
    active_fw=$(fw_backend) || active_fw="unknown"

    case "$active_fw" in
        ufw)
            check_emit "ufw.firewall_active" low passed \
                title="$(i18n 'ufw.firewall_active' "type=UFW")"
            print_ok "$(i18n 'ufw.firewall_active' "type=UFW")"
            ;;
        firewalld)
            check_emit "ufw.firewall_active" low passed \
                title="$(i18n 'ufw.firewall_active' "type=firewalld")" \
                desc="$(i18n 'ufw.other_firewall_note')"
            print_ok "$(i18n 'ufw.firewall_active' "type=firewalld")"
            # Skip UFW-specific checks
            return
            ;;
        nftables)
            check_emit "ufw.firewall_active" low passed \
                title="$(i18n 'ufw.firewall_active' "type=nftables")" \
                desc="$(i18n 'ufw.other_firewall_note')"
            print_ok "$(i18n 'ufw.firewall_active' "type=nftables")"
            return
            ;;
        iptables)
            check_emit "ufw.firewall_active" low passed \
                title="$(i18n 'ufw.firewall_active' "type=iptables")" \
                desc="$(i18n 'ufw.other_firewall_note')"
            print_ok "$(i18n 'ufw.firewall_active' "type=iptables")"
            return
            ;;
        none)
            # One fact, one finding, carried by the id whose fix resolves it:
            # ufw.disabled when UFW is installed (below), ufw.not_installed on
            # Debian/Ubuntu, else ufw.no_firewall, with no UFW fix to offer.
            if ! _ufw_installed; then
                if [[ "${VPSSEC_DISTRO_FAMILY:-debian}" == "debian" ]]; then
                    check_emit "ufw.not_installed" medium failed \
                        desc="$(i18n 'ufw.not_installed_desc')" \
                        suggestion="$(i18n 'ufw.fix_install')" \
                        fix="ufw.install"
                    print_severity "medium" "$(i18n 'ufw.not_installed')"
                else
                    check_emit "ufw.no_firewall" medium failed \
                        desc="$(i18n 'ufw.no_firewall_desc')" \
                        suggestion="$(i18n 'ufw.fix_enable_firewall')"
                    print_severity "medium" "$(i18n 'ufw.no_firewall')"
                fi
                return
            fi
            ;;
        unknown)
            # A status query failed: nothing is claimed, UFW's own state included.
            check_emit "ufw.firewall_unknown" low failed \
                desc="$(i18n 'ufw.firewall_unknown_desc')"
            print_severity "low" "$(i18n 'ufw.firewall_unknown')"
            return
            ;;
    esac

    # Only an installed UFW gets here: active, or installed with nothing active.
    print_item "$(i18n 'ufw.check_installed')"
    print_ok "$(i18n 'ufw.ufw_installed')"

    # Check if UFW is enabled
    print_item "$(i18n 'ufw.check_enabled')"
    _ufw_audit_enabled

    # Check default policy
    print_item "$(i18n 'ufw.check_default_policy')"
    _ufw_audit_default_policy

    # Rule checks only while UFW is enabled: an inactive `ufw status` lists no
    # rules at all. ufw.disabled carries that host, and ufw.enable allows every
    # sshd port before it enables, so no rule finding is lost.
    if _ufw_enabled; then
        print_item "$(i18n 'ufw.check_ssh_rule')"
        _ufw_audit_ssh_rule

        print_item "$(i18n 'ufw.check_permissive_rules')"
        _ufw_audit_permissive_rules

        # IPv6 consistency: IPV6=no in /etc/default/ufw + host has global
        # v6 = v6 packets bypass UFW entirely. Only meaningful when UFW
        # is the active firewall.
        print_item "$(i18n 'ufw.check_ipv6_consistency')"
        _ufw_audit_ipv6_consistency
    fi
}


_ufw_audit_enabled() {
    if _ufw_enabled; then
        check_emit "ufw.enabled" low passed
        print_ok "$(i18n 'ufw.enabled')"
    else
        check_emit "ufw.disabled" medium failed \
            desc="$(i18n 'ufw.disabled_desc')" \
            suggestion="$(i18n 'ufw.fix_enable')" \
            fix="ufw.enable"
        print_severity "medium" "$(i18n 'ufw.disabled')"
    fi
}

_ufw_audit_default_policy() {
    local incoming=$(_ufw_get_default_incoming)

    if _ufw_default_deny "$incoming"; then
        check_emit "ufw.default_deny" low passed \
            title="$(i18n 'ufw.default_incoming_deny')" \
            desc="$(i18n 'ufw.default_deny_desc' "incoming=$incoming")"
        print_ok "$(i18n 'ufw.default_incoming_deny')"
    elif [[ "${incoming,,}" == "allow" ]]; then
        check_emit "ufw.default_accept" medium failed \
            title="$(i18n 'ufw.default_incoming_accept')" \
            desc="$(i18n 'ufw.default_accept_desc')" \
            suggestion="$(i18n 'ufw.fix_default_deny')" \
            fix="ufw.set_default_deny"
        print_severity "medium" "$(i18n 'ufw.default_incoming_accept')"
    fi
}

_ufw_audit_ssh_rule() {
    local ssh_port
    ssh_port=$(get_ssh_ports | paste -sd, -)

    if _ufw_ssh_allowed; then
        check_emit "ufw.ssh_allowed" low passed \
            title="$(i18n 'ufw.ssh_rule_exists' "port=$ssh_port")"
        print_ok "$(i18n 'ufw.ssh_rule_exists' "port=$ssh_port")"
    else
        check_emit "ufw.no_ssh_rule" low failed \
            desc="$(i18n 'ufw.no_ssh_rule_desc' "ssh_port=$ssh_port")" \
            suggestion="$(i18n 'ufw.fix_allow_ssh')" \
            fix="ufw.allow_ssh"
        print_severity "low" "$(i18n 'ufw.no_ssh_rule')"
    fi
}

_ufw_audit_ipv6_consistency() {
    local ipv6_setting
    ipv6_setting=$(_ufw_get_ipv6_setting)

    if [[ "$ipv6_setting" == "yes" ]]; then
        check_emit "ufw.ipv6_managed" low passed
        print_ok "$(i18n 'ufw.ipv6_managed')"
        return
    fi

    # IPV6=no — check whether the host actually has v6 connectivity.
    if _host_has_global_ipv6; then
        check_emit "ufw.ipv6_bypass" medium failed \
            desc="$(i18n 'ufw.ipv6_bypass_desc')" \
            suggestion="$(i18n 'ufw.fix_enable_ipv6')"
        print_severity "medium" "$(i18n 'ufw.ipv6_bypass')"
    else
        check_emit "ufw.ipv6_no_traffic" info passed
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

        check_emit "ufw.permissive_rules" "$severity" failed \
            title="$(i18n 'ufw.permissive_rules_found' "count=$issue_count")" \
            desc="$issue_list" \
            suggestion="$(i18n 'ufw.fix_restrict_rules')"
        print_severity "$severity" "$(i18n 'ufw.permissive_rules_found' "count=$issue_count")"
    else
        check_emit "ufw.rules_ok" low passed \
            title="$(i18n 'ufw.no_permissive_rules')"
        print_ok "$(i18n 'ufw.no_permissive_rules')"
    fi
}

# --- UFW Fix Functions ---

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
        *)
            log_error "Unknown UFW fix: $fix_id"
            return 1
            ;;
    esac
}

_ufw_fix_install() {
    print_info "$(i18n 'ufw.installing_ufw')"

    apt_refresh_index
    if apt_install ufw; then
        print_ok "$(i18n 'ufw.ufw_installed')"
        record_undo ufw.install "apt purge ufw"
        return 0
    else
        print_error "$(i18n 'ufw.ufw_install_failed')"
        return 1
    fi
}

# Add `ufw allow <port>/tcp` for each port on stdin, appending the matching
# delete command to the array named $1. Fails on the first rule ufw refuses.
_ufw_allow_ssh_ports() {
    local -n _undo=$1
    local p
    while read -r p; do
        [[ -n "$p" ]] || continue
        if ! ufw allow "$p/tcp" comment "SSH (vpssec)" >/dev/null; then
            print_error "$(i18n 'ufw.ssh_rule_failed')"
            return 1
        fi
        print_ok "$(i18n 'ufw.rule_added' "rule=${p}/tcp ALLOW")"
        _undo+=("ufw delete allow $p/tcp")
    done
}

_ufw_fix_enable() {
    local current_ip=$(get_current_ssh_ip)
    local -a undo=()

    # Every sshd port without a rule open to anywhere: enabling with
    # default-deny and a missing rule locks the operator out. Any failure MUST
    # abort before the firewall comes up.
    if ! _ufw_allow_ssh_ports undo < <(_ufw_ssh_ports_unopened); then
        _ufw_run_undo "${undo[@]}"
        return 1
    fi

    # Second safety net behind the port rules above. Its failure does not
    # abort, but claiming the rule exists when it does not would mislead.
    if [[ -n "$current_ip" ]]; then
        if ufw allow from "$current_ip" comment "Current session (vpssec rescue)" >/dev/null 2>&1; then
            print_info "$(i18n 'ufw.current_ip_whitelisted' "ip=$current_ip")"
            undo+=("ufw delete allow from $current_ip")
        else
            # Said on the terminal: it is part of what is being confirmed.
            tty_warn "$(i18n 'ufw.rescue_rule_failed' "ip=$current_ip")"
            current_ip=""
        fi
    else
        # No source address (tmux, mosh, no utmp entry): no rescue rule, said
        # before the question, since it is part of what is being confirmed.
        tty_warn "$(i18n 'ufw.operator_ip_unknown')"
    fi

    # The rules about to be enforced are what the confirmation is about.
    tty_say ""
    tty_warn "$(i18n 'ufw.current_rules')"
    LC_ALL=C ufw show added 2>/dev/null | head -20 | tty_out

    if ! confirm_critical "$(i18n 'ufw.confirm_ufw_enable')"; then
        _ufw_run_undo "${undo[@]}"
        return 1
    fi

    print_info "$(i18n 'ufw.enabling_ufw')"
    if echo "y" | ufw enable >/dev/null; then
        print_ok "$(i18n 'ufw.ufw_enabled')"

        # NEVER auto-delete the rescue rule: if the port rule does not cover
        # the live connection, removing it is the lockout. Tell the operator
        # to remove it after a fresh login is confirmed.
        if [[ -n "$current_ip" ]]; then
            print_warn "$(i18n 'ufw.rescue_rule_kept' "ip=$current_ip")"
        fi
        record_undo ufw.enable "$(undo_join "ufw disable" "${undo[@]}")"
        return 0
    else
        print_error "$(i18n 'ufw.ufw_enable_failed')"
        return 1
    fi
}

# Run the undo commands of rules this fix added (a declined or failed fix
# leaves ufw as it found it).
_ufw_run_undo() {
    local cmd
    for cmd in "$@"; do
        # Word splitting is intended: each entry is a plain ufw argv.
        # shellcheck disable=SC2086
        $cmd >/dev/null 2>&1 || log_warn "ufw cleanup failed: $cmd"
    done
}

_ufw_fix_default_deny() {
    local old_in old_out
    old_in=$(_ufw_get_default_incoming)
    old_out=$(_ufw_get_default_outgoing)
    local -a undo=()

    # Every sshd port must be open to anywhere before flipping to deny-all, or
    # the policy cuts the next login. Abort on any failure BEFORE the flip.
    if ! _ufw_allow_ssh_ports undo < <(_ufw_ssh_ports_unopened); then
        _ufw_run_undo "${undo[@]}"
        return 1
    fi

    # Set default deny incoming
    if ufw default deny incoming >/dev/null; then
        print_ok "$(i18n 'ufw.default_deny_set')"

        # Set default allow outgoing (standard)
        ufw default allow outgoing >/dev/null 2>&1 || true

        local -a revert=()
        [[ -n "$old_in" ]] && revert+=("ufw default ${old_in,,} incoming")
        [[ -n "$old_out" && "${old_out,,}" != "allow" ]] && revert+=("ufw default ${old_out,,} outgoing")
        record_undo ufw.set_default_deny "$(undo_join "${revert[@]}" "${undo[@]}")"
        return 0
    else
        print_error "$(i18n 'ufw.default_deny_failed')"
        _ufw_run_undo "${undo[@]}"
        return 1
    fi
}

_ufw_fix_allow_ssh() {
    # Only the ports no rule admits yet: SSH already confined to a VPN
    # interface or an admin address must not gain a rule open to anywhere.
    local -a undo=()
    local p missing=""
    while read -r p; do
        _ufw_admits_port "$p" || missing+="$p"$'\n'
    done < <(get_ssh_ports)
    [[ -n "$missing" ]] || return 0

    if ! _ufw_allow_ssh_ports undo <<<"$missing"; then
        _ufw_run_undo "${undo[@]}"
        return 1
    fi
    record_undo ufw.allow_ssh "$(undo_join "${undo[@]}")"
    return 0
}

# --- UFW Utility Functions for Other Modules ---

