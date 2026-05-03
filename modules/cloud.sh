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
declare -ga KNOWN_CLOUD_AGENTS=(
    # Alibaba Cloud
    "AliYunDun|aegis|阿里云|安骑士/云安全中心|yes"
    "AliYunDunMonitor|aegis|阿里云|安骑士监控|yes"
    "AliYunDunUpdate|aegis|阿里云|安骑士更新|yes"
    "aliyun-service|aliyun|阿里云|阿里云服务|yes"
    "cloudmonitor|cloudmonitor|阿里云|云监控插件|yes"

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
declare -ga SUSPICIOUS_AGENT_PATTERNS=(
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
declare -ga SAFE_SYSTEM_PROCESSES=(
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
    # Virtualization guest tools — most VPS providers ship one of these
    # by default and several superficially match SUSPICIOUS_AGENT_PATTERNS
    # (notably spice-vdagent → `.*[Aa]gent.*`). qemu-ga is included as
    # belt-and-suspenders even though its comm doesn't currently match.
    "qemu-ga"
    "spice-vdagent"
    "spice-vdagentd"
    "vmtoolsd"
    "VBoxService"
    "VBoxClient"
    "xe-daemon"
    "hv_kvp_daemon"
    "hv_vss_daemon"
    "hv_fcopy_daemon"
)

# ==============================================================================
# Detection Functions
# ==============================================================================

# Detect cloud provider from system info.
#
# Detection order — earlier signals are stronger and cheaper than
# later ones, and we deliberately exhaust every offline signal before
# touching the network:
#
#   1. DMI vendor / board_vendor / bios_vendor            (offline,
#                                                          authoritative
#                                                          when the
#                                                          hypervisor
#                                                          stamps it)
#   2. DMI product_name                                   (offline)
#   3. DMI product_uuid prefix                            (offline; AWS
#                                                          EC2 UUIDs
#                                                          start "ec2"
#                                                          on Xen)
#   4. cloud-init datasource (ds-identify.log,
#      /var/lib/cloud/data/datasource, /run/cloud-init/cloud-id,
#      /etc/cloud/cloud.cfg.d/*)                          (offline)
#   5. Provider-specific files (/etc/digitalocean,
#      /sys/firmware/qemu_fw_cfg/by_name/opt/io.systemd.credentials/...)
#                                                          (offline)
#   6. Provider-specific NETWORK metadata endpoints       (the only
#                                                          probes that
#                                                          go on the
#                                                          wire — and
#                                                          we order
#                                                          them so
#                                                          provider-
#                                                          unique IPs
#                                                          are tried
#                                                          BEFORE
#                                                          shared
#                                                          169.254.169.254)
#   7. Shared 169.254.169.254 IMDSv2/v1 — disambiguated by parsing the
#      placement/region or instance-id payload (Tencent and several
#      other providers offer EC2-compatible IMDS at the same IP, so a
#      bare 200 here is NOT enough to call it AWS).
_detect_cloud_provider() {
    local provider="unknown"

    # ---------- 1. DMI sys_vendor ----------
    if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
        local vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
        case "$vendor" in
            *"Alibaba"*)     provider="alibaba" ;;
            *"Tencent"*)     provider="tencent" ;;
            *"HUAWEI"*|*"Huawei"*) provider="huawei" ;;
            *"Amazon"*)      provider="aws" ;;
            *"Microsoft"*)   provider="azure" ;;
            *"Google"*)      provider="gcp" ;;
            *"DigitalOcean"*) provider="digitalocean" ;;
            *"Vultr"*|*"Choopa"*) provider="vultr" ;;
            *"Linode"*|*"Akamai"*) provider="linode" ;;
            *"Oracle"*|*"OracleCloud"*) provider="oracle" ;;
            *"Hetzner"*)     provider="hetzner" ;;
            *"OVH"*)         provider="ovh" ;;
            *"Scaleway"*|*"Online"*) provider="scaleway" ;;
        esac
    fi

    # ---------- 2. DMI product_name ----------
    if [[ "$provider" == "unknown" && -r /sys/class/dmi/id/product_name ]]; then
        local product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        case "$product" in
            *"Alibaba"*|*"Aliyun"*|*"ECS"*)  provider="alibaba" ;;
            *"CVM"*|*"Tencent"*)             provider="tencent" ;;
            *"HVM domU"*|*"HVM"*)            provider="aws" ;;
            *"Virtual Machine"*)             provider="azure" ;;
            *"Google Compute Engine"*)       provider="gcp" ;;
            *"Droplet"*)                     provider="digitalocean" ;;
            *"Standard PC (Q35"*) ;;  # very generic — KVM default, do not classify
            *"OracleCloud"*)                 provider="oracle" ;;
            *"VirtualBox"*) ;;        # local dev — leave as unknown
        esac
    fi

    # ---------- 2b. board_vendor / bios_vendor (rare; some providers
    # only stamp these). Only consult if still unknown.
    if [[ "$provider" == "unknown" ]]; then
        local extra
        for extra in /sys/class/dmi/id/board_vendor /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/chassis_vendor; do
            [[ -r "$extra" ]] || continue
            local val=$(cat "$extra" 2>/dev/null)
            case "$val" in
                *"Tencent"*)     provider="tencent"; break ;;
                *"Alibaba"*)     provider="alibaba"; break ;;
                *"Amazon"*)      provider="aws"; break ;;
                *"DigitalOcean"*) provider="digitalocean"; break ;;
                *"Hetzner"*)     provider="hetzner"; break ;;
                *"Oracle"*)      provider="oracle"; break ;;
            esac
        done
    fi

    # ---------- 3. product_uuid prefix ----------
    # AWS EC2 (Xen) instances have product_uuid starting with "EC2";
    # Nitro instances are random. Useful as a tiebreaker when DMI
    # vendor is generic (e.g., bare "Xen").
    if [[ "$provider" == "unknown" && -r /sys/class/dmi/id/product_uuid ]]; then
        # Read may fail with EACCES for non-root; ignore quietly.
        local uuid=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null | tr 'A-Z' 'a-z')
        if [[ "$uuid" == ec2* ]]; then
            provider="aws"
        fi
    fi

    # ---------- 4. cloud-init datasource ----------
    if [[ "$provider" == "unknown" ]]; then
        local ds=""

        # Preferred: cloud-init's resolved cloud-id (single token).
        if [[ -r /run/cloud-init/cloud-id ]]; then
            ds=$(head -n1 /run/cloud-init/cloud-id 2>/dev/null | tr -d '[:space:]')
        fi

        # Next: ds-identify.log (multi-line; first datasource: line wins).
        if [[ -z "$ds" && -f /run/cloud-init/ds-identify.log ]]; then
            ds=$(grep -oP 'datasource: \K\w+' /run/cloud-init/ds-identify.log 2>/dev/null | head -1)
        fi

        # Persisted datasource (survives reboot, set by cloud-init init).
        if [[ -z "$ds" && -r /var/lib/cloud/data/datasource ]]; then
            ds=$(head -n1 /var/lib/cloud/data/datasource 2>/dev/null | awk -F': ' '{print $1}')
        fi

        # /etc/cloud/cloud.cfg.d/ drop-ins. Vendors ship distinct names;
        # we look at filenames rather than parse the YAML.
        if [[ -z "$ds" && -d /etc/cloud/cloud.cfg.d ]]; then
            local f
            for f in /etc/cloud/cloud.cfg.d/*.cfg; do
                [[ -f "$f" ]] || continue
                case "$f" in
                    *aliyun*|*alicloud*) ds="AliYun"; break ;;
                    *tencent*|*qcloud*)  ds="Tencent"; break ;;
                    *digitalocean*)      ds="DigitalOcean"; break ;;
                    *hetzner*)           ds="Hetzner"; break ;;
                    *vultr*)             ds="Vultr"; break ;;
                    *oracle*)            ds="Oracle"; break ;;
                esac
            done
        fi

        case "$ds" in
            "Ec2"|"aws"|"AWS")                   provider="aws" ;;
            "Azure"|"azure")                     provider="azure" ;;
            "GCE"|"gce"|"gcp")                   provider="gcp" ;;
            "DigitalOcean"|"digitalocean")       provider="digitalocean" ;;
            "Vultr"|"vultr")                     provider="vultr" ;;
            "Hetzner"|"hetzner"|"hcloud")        provider="hetzner" ;;
            "AliYun"|"aliyun"|"alibaba")         provider="alibaba" ;;
            "Tencent"|"tencent")                 provider="tencent" ;;
            "Oracle"|"oracle"|"oci")             provider="oracle" ;;
            "Linode"|"linode")                   provider="linode" ;;
            "Scaleway"|"scaleway")               provider="scaleway" ;;
            "OpenStack"|"openstack")
                # OVH and several Chinese clouds use OpenStack — stays
                # unknown unless one of the offline signals above
                # already pinned it.
                ;;
        esac
    fi

    # ---------- 5. Provider-specific files ----------
    if [[ "$provider" == "unknown" ]]; then
        if [[ -e /etc/digitalocean ]] || [[ -e /var/lib/digitalocean ]]; then
            provider="digitalocean"
        elif [[ -e /etc/hetzner-build ]] || [[ -e /var/lib/hetzner ]]; then
            provider="hetzner"
        elif [[ -e /etc/oracle-cloud-agent ]] || [[ -d /etc/oci-hostname.conf ]]; then
            provider="oracle"
        fi
    fi

    # ---------- 6. Provider-specific NETWORK endpoints ----------
    # These IPs are unique to one provider, so a 200 here is conclusive.
    # Do these BEFORE the shared 169.254.169.254 fallback so we don't
    # misclassify Tencent/OCI/etc. as AWS.
    if [[ "$provider" == "unknown" ]]; then
        # Tencent Cloud has its own metadata service at metadata.tencentyun.com
        # (the canonical name used in Tencent's documentation), AND mirrors
        # an EC2-compatible service at 169.254.169.254. Hitting the
        # tencent-specific name first avoids the EC2-compat misclassification.
        if curl -fs --connect-timeout 1 -m 2 \
            http://metadata.tencentyun.com/latest/meta-data/ >/dev/null 2>&1; then
            provider="tencent"
        # Alibaba IMDS at its dedicated 100.100.100.200.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://100.100.100.200/latest/meta-data/ >/dev/null 2>&1; then
            provider="alibaba"
        # Oracle Cloud (OCI) IMDS — distinct path /opc/v2/instance/.
        elif curl -fs --connect-timeout 1 -m 2 \
            -H "Authorization: Bearer Oracle" \
            http://169.254.169.254/opc/v2/instance/ >/dev/null 2>&1; then
            provider="oracle"
        # Hetzner Cloud IMDS — distinct path /hetzner/v1/metadata.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://169.254.169.254/hetzner/v1/metadata/ >/dev/null 2>&1; then
            provider="hetzner"
        # DigitalOcean IMDS — distinct path /metadata/v1/.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://169.254.169.254/metadata/v1/id >/dev/null 2>&1; then
            provider="digitalocean"
        # Vultr IMDS — distinct path /v1.json.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://169.254.169.254/v1.json >/dev/null 2>&1; then
            provider="vultr"
        fi
    fi

    # ---------- 7. Shared 169.254.169.254 IMDS (ambiguous IP) ----------
    # AWS, Tencent, Huawei and several others all serve EC2-compatible
    # endpoints at this IP. A bare 200 is not enough; we have to read
    # the placement/region or instance-id and compare against known
    # provider patterns.
    if [[ "$provider" == "unknown" ]]; then
        local _imds_body=""

        # IMDSv2 token-required path (AWS/Tencent both support this).
        local _aws_token
        _aws_token=$(curl -fs -X PUT --connect-timeout 1 -m 2 \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
            http://169.254.169.254/latest/api/token 2>/dev/null) || true
        if [[ -n "$_aws_token" ]]; then
            _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                -H "X-aws-ec2-metadata-token: $_aws_token" \
                http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null) || true
            if [[ -z "$_imds_body" ]]; then
                # Fallback to instance-id; AWS Nitro IDs start with "i-"
                # (Tencent uses "ins-").
                _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                    -H "X-aws-ec2-metadata-token: $_aws_token" \
                    http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null) || true
            fi
        fi

        # IMDSv1 fallback (rare on AWS post-2024; common on Tencent /
        # several local cloud appliances).
        if [[ -z "$_imds_body" ]]; then
            _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null) || true
            if [[ -z "$_imds_body" ]]; then
                _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                    http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null) || true
            fi
        fi

        if [[ -n "$_imds_body" ]]; then
            # Disambiguate. Strip whitespace; lower-case for region match.
            local _b=$(printf '%s' "$_imds_body" | tr -d '[:space:]' | tr 'A-Z' 'a-z')
            case "$_b" in
                # Tencent regions: ap-* (overlaps with AWS Asia-Pacific)
                # plus eu-frankfurt, na-* — but the real giveaway is the
                # instance-id prefix "ins-".
                ins-*)                provider="tencent" ;;
                # AWS Nitro / Xen instance IDs.
                i-*)                  provider="aws" ;;
                # AWS region tokens look like us-east-1 / eu-west-2; they
                # always have a single trailing digit. Tencent's
                # eu-frankfurt has no trailing digit, ap-guangzhou ditto.
                *-[0-9])              provider="aws" ;;
                ap-guangzhou|ap-shanghai|ap-beijing|ap-chengdu|ap-chongqing|ap-nanjing|ap-hongkong|ap-singapore|ap-bangkok|ap-jakarta|ap-mumbai|ap-seoul|ap-tokyo|na-siliconvalley|na-ashburn|na-toronto|sa-saopaulo|eu-frankfurt|eu-moscow)
                                       provider="tencent" ;;
                cn-north-*|cn-east-*|cn-south-*)
                                       provider="huawei" ;;
                *)
                    # Last resort: we got *something* from 169.254.169.254
                    # with the EC2 path shape; fall back to AWS but flag
                    # via the ambiguous return.
                    provider="aws-or-compatible"
                    ;;
            esac
        else
            # Try Azure (header-required path) and GCP (header + path).
            if curl -fs --connect-timeout 1 -m 2 -H "Metadata: true" \
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
                >/dev/null 2>&1; then
                provider="azure"
            elif curl -fs --connect-timeout 1 -m 2 \
                -H "Metadata-Flavor: Google" \
                http://169.254.169.254/computeMetadata/v1/ >/dev/null 2>&1; then
                provider="gcp"
            fi
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
        aws-or-compatible) echo "EC2-compatible IMDS (provider unconfirmed)" ;;
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
                    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 200)
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
        check_json=$(create_check_json \
            "cloud.provider_detected" \
            "cloud" \
            "info" \
            "passed" \
            "$(i18n 'cloud.provider_detected' 2>/dev/null || echo 'Cloud Provider Detected'): $provider_name" \
            "$(i18n 'cloud.provider_info' 2>/dev/null || echo 'Running on cloud infrastructure')" \
            "" \
            "")
    else
        check_json=$(create_check_json \
            "cloud.provider_unknown" \
            "cloud" \
            "info" \
            "passed" \
            "$(i18n 'cloud.provider_unknown' 2>/dev/null || echo 'Cloud Provider Unknown')" \
            "$(i18n 'cloud.provider_unknown_desc' 2>/dev/null || echo 'Could not detect cloud provider, may be bare metal or unrecognized VPS')" \
            "" \
            "")
    fi
    state_add_check "$check_json"

    # 2. Find known cloud agents
    local known_agents=$(_find_known_agents)
    local agent_count=$(count_lines "$known_agents" '|')

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

        check_json=$(create_check_json \
            "cloud.agents_found" \
            "cloud" \
            "$severity" \
            "failed" \
            "$(i18n 'cloud.agents_found' 2>/dev/null || echo 'Cloud Monitoring Agents Found'): $agent_count" \
            "$agent_list" \
            "$(i18n 'cloud.review_agents' 2>/dev/null || echo 'Review if these agents are needed, disable if not required')" \
            "cloud.agents_found")
    else
        check_json=$(create_check_json \
            "cloud.no_known_agents" \
            "cloud" \
            "info" \
            "passed" \
            "$(i18n 'cloud.no_known_agents' 2>/dev/null || echo 'No Known Cloud Agents')" \
            "$(i18n 'cloud.no_known_agents_desc' 2>/dev/null || echo 'No known cloud vendor monitoring agents detected')" \
            "" \
            "")
    fi
    state_add_check "$check_json"

    # 3. Find suspicious agent-like processes (strict level only)
    local suspicious=$(_find_suspicious_agents)
    local suspicious_count=$(count_lines "$suspicious" '|')

    if [[ -n "$suspicious" && "$suspicious_count" -gt 0 ]]; then
        local proc_list=""
        while IFS='|' read -r proc pid user cmdline; do
            [[ -z "$proc" ]] && continue
            proc_list+="$proc (pid:$pid, user:$user), "
        done <<< "$suspicious"
        proc_list="${proc_list%, }"

        check_json=$(create_check_json \
            "cloud.suspicious_agents" \
            "cloud" \
            "low" \
            "failed" \
            "$(i18n 'cloud.suspicious_agents' 2>/dev/null || echo 'Suspicious Agent Processes'): $suspicious_count" \
            "$proc_list" \
            "$(i18n 'cloud.review_suspicious' 2>/dev/null || echo 'Review these processes - may be legitimate monitoring or unwanted software')" \
            "cloud.suspicious_agents")
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
