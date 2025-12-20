#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Cloud environment and monitoring agent detection module
# Copyright (c) 2024
#
# This module detects:
# - Cloud provider (if identifiable)
# - Known cloud vendor monitoring agents
# - Generic monitoring/agent processes
# - Suspicious background agents
#
# All checks are informational - no automatic modifications

# ==============================================================================
# Known Cloud Vendor Agents Database
# ==============================================================================

# Format: process_name|service_name|vendor|description|can_disable
declare -a KNOWN_CLOUD_AGENTS=(
    # Alibaba Cloud
    "AliYunDun|aegis|阿里云|安骑士/云安全中心|yes"
    "AliYunDunMonitor|aegis|阿里云|安骑士监控|yes"
    "AliYunDunUpdate|aegis|阿里云|安骑士更新|yes"
    "aliyun-service|aliyun|阿里云|阿里云服务|yes"
    "cloudmonitor|cloudmonitor|阿里云|云监控插件|yes"
    "China China China China China China China China China China China China China China China China China China China China China China China China China China China China|China China China China China China China China China China China China China China China China China China China China China China China China China China China China|阿里云|China China China China China China China China China China China China China China China China China China China China China China China China China China China China|yes"

    # Tencent Cloud
    "YDService|YDService|腾讯云|云镜主机安全|yes"
    "YDLive|YDService|腾讯云|云镜实时防护|yes"
    "tat_agent|tat_agent|腾讯云|自动化助手|yes"
    "sgagent|sgagent|腾讯云|安全组件|yes"
    "barad_agent|barad_agent|腾讯云|监控组件|yes"

    # Huawei Cloud
    "telescope|telescope|华为云|云监控Agent|yes"
    "hostguard|hostguard|华为云|主机安全|yes"
    "uniagent|uniagent|华为云|统一Agent|yes"

    # AWS
    "amazon-ssm-agent|amazon-ssm-agent|AWS|Systems Manager Agent|optional"
    "amazon-cloudwatch-agent|amazon-cloudwatch-agent|AWS|CloudWatch Agent|optional"

    # Azure
    "waagent|walinuxagent|Azure|Linux VM Agent|no"
    "WaLinuxAgent|walinuxagent|Azure|Linux VM Agent|no"
    "OMSAgentForLinux|omsagent|Azure|Log Analytics Agent|yes"

    # Google Cloud
    "google_guest_agent|google-guest-agent|GCP|Guest Agent|optional"
    "google_osconfig_agent|google-osconfig-agent|GCP|OS Config Agent|optional"

    # DigitalOcean
    "do-agent|do-agent|DigitalOcean|Monitoring Agent|yes"

    # Vultr
    "vultr-helper|vultr-helper|Vultr|Helper Agent|yes"

    # Linode
    "linode-cli|linode-cli|Linode|CLI Tool|yes"
    "longview|longview|Linode|Monitoring Agent|yes"

    # Oracle Cloud
    "oracle-cloud-agent|oracle-cloud-agent|Oracle Cloud|Cloud Agent|optional"

    # Generic/Common monitoring tools
    "zabbix_agentd|zabbix-agent|Generic|Zabbix Agent|optional"
    "node_exporter|prometheus-node-exporter|Generic|Prometheus Exporter|optional"
    "telegraf|telegraf|Generic|Telegraf Agent|optional"
    "collectd|collectd|Generic|Collectd|optional"
    "netdata|netdata|Generic|Netdata Monitoring|optional"
    "datadog-agent|datadog-agent|Generic|Datadog Agent|optional"
    "newrelic-infra|newrelic-infra|Generic|New Relic Agent|optional"
)

# Suspicious process name patterns (regex)
declare -a SUSPICIOUS_AGENT_PATTERNS=(
    ".*[Aa]gent.*"
    ".*[Mm]onitor.*"
    ".*[Gg]uard.*"
    ".*[Ww]atcher.*"
    ".*[Cc]ollector.*"
    ".*[Tt]elemetry.*"
    ".*[Ss]py.*"
    ".*[Tt]racker.*"
)

# Known safe system processes (to exclude from suspicious detection)
declare -a SAFE_SYSTEM_PROCESSES=(
    "gpg-agent"
    "ssh-agent"
    "dbus-daemon"
    "polkitd"
    "packagekitd"
    "systemd-journald"
    "systemd-logind"
    "systemd-networkd"
    "systemd-resolved"
    "systemd-timesyncd"
    "systemd-udevd"
    "udisksd"
    "accounts-daemon"
    "avahi-daemon"
    "ModemManager"
    "NetworkManager"
    "wpa_supplicant"
    "cupsd"
    "cron"
    "atd"
    "rsyslogd"
    "sshd"
    "nginx"
    "apache2"
    "httpd"
    "mysqld"
    "postgres"
    "redis-server"
    "mongod"
    "docker"
    "containerd"
)

# ==============================================================================
# Detection Functions
# ==============================================================================

# Detect cloud provider from system info
_detect_cloud_provider() {
    local provider="unknown"

    # Check DMI/SMBIOS info
    if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
        local vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
        case "$vendor" in
            *"Alibaba"*)     provider="alibaba" ;;
            *"Tencent"*)     provider="tencent" ;;
            *"HUAWEI"*)      provider="huawei" ;;
            *"Amazon"*)      provider="aws" ;;
            *"Microsoft"*)   provider="azure" ;;
            *"Google"*)      provider="gcp" ;;
            *"DigitalOcean"*) provider="digitalocean" ;;
            *"Vultr"*)       provider="vultr" ;;
            *"Linode"*)      provider="linode" ;;
            *"Oracle"*)      provider="oracle" ;;
            *"Hetzner"*)     provider="hetzner" ;;
            *"OVH"*)         provider="ovh" ;;
            *"Scaleway"*)    provider="scaleway" ;;
        esac
    fi

    # Check product name if vendor didn't match
    if [[ "$provider" == "unknown" && -r /sys/class/dmi/id/product_name ]]; then
        local product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        case "$product" in
            *"Alibaba"*|*"ECS"*)  provider="alibaba" ;;
            *"CVM"*)              provider="tencent" ;;
            *"HVM"*)              provider="aws" ;;
            *"Virtual Machine"*) provider="azure" ;;
            *"Google"*)          provider="gcp" ;;
            *"Droplet"*)         provider="digitalocean" ;;
        esac
    fi

    # Check for cloud-init datasource
    if [[ "$provider" == "unknown" && -f /run/cloud-init/ds-identify.log ]]; then
        local ds=$(grep -oP 'datasource: \K\w+' /run/cloud-init/ds-identify.log 2>/dev/null | head -1)
        case "$ds" in
            "Ec2")          provider="aws" ;;
            "Azure")        provider="azure" ;;
            "GCE")          provider="gcp" ;;
            "DigitalOcean") provider="digitalocean" ;;
            "Vultr")        provider="vultr" ;;
            "Hetzner")      provider="hetzner" ;;
            "AliYun")       provider="alibaba" ;;
        esac
    fi

    # Check metadata endpoints (careful - some may not respond)
    if [[ "$provider" == "unknown" ]]; then
        # AWS/Alibaba metadata
        if curl -s --connect-timeout 1 -m 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
            if curl -s --connect-timeout 1 -m 2 http://100.100.100.200/latest/meta-data/ &>/dev/null; then
                provider="alibaba"
            else
                provider="aws"
            fi
        # Azure metadata
        elif curl -s --connect-timeout 1 -m 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
            provider="azure"
        # GCP metadata
        elif curl -s --connect-timeout 1 -m 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
            provider="gcp"
        fi
    fi

    echo "$provider"
}

# Get provider display name
_get_provider_name() {
    local provider="$1"
    case "$provider" in
        alibaba)      echo "阿里云 (Alibaba Cloud)" ;;
        tencent)      echo "腾讯云 (Tencent Cloud)" ;;
        huawei)       echo "华为云 (Huawei Cloud)" ;;
        aws)          echo "AWS (Amazon Web Services)" ;;
        azure)        echo "Microsoft Azure" ;;
        gcp)          echo "Google Cloud Platform" ;;
        digitalocean) echo "DigitalOcean" ;;
        vultr)        echo "Vultr" ;;
        linode)       echo "Linode (Akamai)" ;;
        oracle)       echo "Oracle Cloud" ;;
        hetzner)      echo "Hetzner" ;;
        ovh)          echo "OVH" ;;
        scaleway)     echo "Scaleway" ;;
        unknown)      echo "$(i18n 'common.unknown' 2>/dev/null || echo 'Unknown')" ;;
        *)            echo "$provider" ;;
    esac
}

# Check if a process is in the safe list
_is_safe_process() {
    local proc="$1"
    for safe in "${SAFE_SYSTEM_PROCESSES[@]}"; do
        [[ "$proc" == "$safe" ]] && return 0
    done
    return 1
}

# Find running monitoring agents from known list
_find_known_agents() {
    local found=()

    for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r proc_name service_name vendor desc can_disable <<< "$entry"

        # Check if process is running
        if pgrep -x "$proc_name" &>/dev/null; then
            found+=("$proc_name|$service_name|$vendor|$desc|$can_disable|running")
        # Check if service exists
        elif systemctl is-active "$service_name" &>/dev/null 2>&1; then
            found+=("$proc_name|$service_name|$vendor|$desc|$can_disable|service")
        fi
    done

    printf '%s\n' "${found[@]}"
}

# Find suspicious agent-like processes
_find_suspicious_agents() {
    local suspicious=()

    # Get all running processes
    local procs=$(ps -eo comm= 2>/dev/null | sort -u)

    while read -r proc; do
        [[ -z "$proc" ]] && continue

        # Skip known safe processes
        _is_safe_process "$proc" && continue

        # Skip if it's a known cloud agent (already detected)
        local is_known=false
        for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
            local known_proc="${entry%%|*}"
            [[ "$proc" == "$known_proc" ]] && is_known=true && break
        done
        [[ "$is_known" == "true" ]] && continue

        # Check against suspicious patterns
        for pattern in "${SUSPICIOUS_AGENT_PATTERNS[@]}"; do
            if [[ "$proc" =~ $pattern ]]; then
                # Get more info about the process
                local pid=$(pgrep -x "$proc" 2>/dev/null | head -1)
                local cmdline=""
                local user=""
                if [[ -n "$pid" ]]; then
                    cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | head -c 200)
                    user=$(ps -o user= -p "$pid" 2>/dev/null)
                fi
                suspicious+=("$proc|$pid|$user|$cmdline")
                break
            fi
        done
    done <<< "$procs"

    printf '%s\n' "${suspicious[@]}"
}

# ==============================================================================
# Audit Functions
# ==============================================================================

cloud_audit() {
    log_info "Running cloud environment audit"

    # 1. Detect cloud provider
    local provider=$(_detect_cloud_provider)
    local provider_name=$(_get_provider_name "$provider")

    local check_json
    if [[ "$provider" != "unknown" ]]; then
        check_json=$(cat <<EOF
{
    "id": "cloud.provider_detected",
    "check_id": "cloud.provider_detected",
    "module": "cloud",
    "title": "$(i18n 'cloud.provider_detected' 2>/dev/null || echo 'Cloud Provider Detected'): $provider_name",
    "desc": "$(i18n 'cloud.provider_info' 2>/dev/null || echo 'Running on cloud infrastructure')",
    "status": "passed",
    "severity": "info"
}
EOF
)
    else
        check_json=$(cat <<EOF
{
    "id": "cloud.provider_unknown",
    "check_id": "cloud.provider_unknown",
    "module": "cloud",
    "title": "$(i18n 'cloud.provider_unknown' 2>/dev/null || echo 'Cloud Provider Unknown')",
    "desc": "$(i18n 'cloud.provider_unknown_desc' 2>/dev/null || echo 'Could not detect cloud provider, may be bare metal or unrecognized VPS')",
    "status": "passed",
    "severity": "info"
}
EOF
)
    fi
    state_add_check "$check_json"

    # 2. Find known cloud agents
    local known_agents=$(_find_known_agents)
    local agent_count=$(echo "$known_agents" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$known_agents" && "$agent_count" -gt 0 ]]; then
        # Build agent list for display
        local agent_list=""
        local agent_details=""
        while IFS='|' read -r proc_name service_name vendor desc can_disable status; do
            [[ -z "$proc_name" ]] && continue
            agent_list+="$proc_name ($vendor), "
            agent_details+="$proc_name: $desc [$vendor]\\n"
        done <<< "$known_agents"
        agent_list="${agent_list%, }"

        local severity="medium"
        # Lower severity if all agents are from detected provider
        if [[ "$provider" != "unknown" ]]; then
            local all_from_provider=true
            while IFS='|' read -r proc_name service_name vendor desc can_disable status; do
                [[ -z "$proc_name" ]] && continue
                case "$provider" in
                    alibaba) [[ "$vendor" != "阿里云" ]] && all_from_provider=false ;;
                    tencent) [[ "$vendor" != "腾讯云" ]] && all_from_provider=false ;;
                    huawei)  [[ "$vendor" != "华为云" ]] && all_from_provider=false ;;
                    aws)     [[ "$vendor" != "AWS" ]] && all_from_provider=false ;;
                    azure)   [[ "$vendor" != "Azure" ]] && all_from_provider=false ;;
                    gcp)     [[ "$vendor" != "GCP" ]] && all_from_provider=false ;;
                esac
            done <<< "$known_agents"
            [[ "$all_from_provider" == "true" ]] && severity="low"
        fi

        check_json=$(cat <<EOF
{
    "id": "cloud.agents_found",
    "check_id": "cloud.agents_found",
    "module": "cloud",
    "title": "$(i18n 'cloud.agents_found' 2>/dev/null || echo 'Cloud Monitoring Agents Found'): $agent_count",
    "desc": "$agent_list",
    "status": "failed",
    "severity": "$severity",
    "suggestion": "$(i18n 'cloud.review_agents' 2>/dev/null || echo 'Review if these agents are needed, disable if not required')",
    "fix_id": "cloud.agents_found"
}
EOF
)
    else
        check_json=$(cat <<EOF
{
    "id": "cloud.no_known_agents",
    "check_id": "cloud.no_known_agents",
    "module": "cloud",
    "title": "$(i18n 'cloud.no_known_agents' 2>/dev/null || echo 'No Known Cloud Agents')",
    "desc": "$(i18n 'cloud.no_known_agents_desc' 2>/dev/null || echo 'No known cloud vendor monitoring agents detected')",
    "status": "passed",
    "severity": "info"
}
EOF
)
    fi
    state_add_check "$check_json"

    # 3. Find suspicious agent-like processes (strict level only)
    local suspicious=$(_find_suspicious_agents)
    local suspicious_count=$(echo "$suspicious" | grep -c '|' 2>/dev/null || echo 0)

    if [[ -n "$suspicious" && "$suspicious_count" -gt 0 ]]; then
        local proc_list=""
        while IFS='|' read -r proc pid user cmdline; do
            [[ -z "$proc" ]] && continue
            proc_list+="$proc (pid:$pid, user:$user), "
        done <<< "$suspicious"
        proc_list="${proc_list%, }"

        check_json=$(cat <<EOF
{
    "id": "cloud.suspicious_agents",
    "check_id": "cloud.suspicious_agents",
    "module": "cloud",
    "title": "$(i18n 'cloud.suspicious_agents' 2>/dev/null || echo 'Suspicious Agent Processes'): $suspicious_count",
    "desc": "$proc_list",
    "status": "failed",
    "severity": "low",
    "suggestion": "$(i18n 'cloud.review_suspicious' 2>/dev/null || echo 'Review these processes - may be legitimate monitoring or unwanted software')",
    "fix_id": "cloud.suspicious_agents"
}
EOF
)
        state_add_check "$check_json"
    fi

    return 0
}

# ==============================================================================
# Fix Functions (Alert Only - No Auto Fix)
# ==============================================================================

cloud_fix() {
    local fix_id="$1"

    case "$fix_id" in
        cloud.agents_found)
            print_warn "$(i18n 'cloud.manual_review' 2>/dev/null || echo 'Manual review required')"
            echo ""
            echo "$(i18n 'cloud.agents_info' 2>/dev/null || echo 'Detected monitoring agents'):"
            echo ""

            local known_agents=$(_find_known_agents)
            while IFS='|' read -r proc_name service_name vendor desc can_disable status; do
                [[ -z "$proc_name" ]] && continue
                echo "  • $proc_name"
                echo "    $(i18n 'common.info' 2>/dev/null || echo 'Info'): $desc"
                echo "    $(i18n 'cloud.vendor' 2>/dev/null || echo 'Vendor'): $vendor"
                echo "    $(i18n 'cloud.service' 2>/dev/null || echo 'Service'): $service_name"
                if [[ "$can_disable" == "yes" ]]; then
                    echo "    $(i18n 'cloud.can_disable' 2>/dev/null || echo 'Can disable'): systemctl disable --now $service_name"
                elif [[ "$can_disable" == "no" ]]; then
                    echo "    $(i18n 'cloud.required' 2>/dev/null || echo 'Required'): $(i18n 'cloud.do_not_disable' 2>/dev/null || echo 'Do not disable - required for cloud functionality')"
                else
                    echo "    $(i18n 'cloud.optional' 2>/dev/null || echo 'Optional'): $(i18n 'cloud.review_before_disable' 2>/dev/null || echo 'Review before disabling')"
                fi
                echo ""
            done

            return 1  # Alert only, no auto-fix
            ;;

        cloud.suspicious_agents)
            print_warn "$(i18n 'cloud.manual_review' 2>/dev/null || echo 'Manual review required')"
            echo ""
            echo "$(i18n 'cloud.suspicious_info' 2>/dev/null || echo 'Suspicious processes found'):"
            echo ""

            local suspicious=$(_find_suspicious_agents)
            while IFS='|' read -r proc pid user cmdline; do
                [[ -z "$proc" ]] && continue
                echo "  • $proc (PID: $pid)"
                echo "    User: $user"
                echo "    Command: ${cmdline:0:100}..."
                echo "    $(i18n 'cloud.investigate' 2>/dev/null || echo 'Investigate'): ps aux | grep $proc"
                echo ""
            done

            return 1  # Alert only, no auto-fix
            ;;

        *)
            log_warn "Unknown fix_id: $fix_id"
            return 1
            ;;
    esac
}
