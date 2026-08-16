#!/usr/bin/env bash
# Cloud environment and monitoring-agent detection.
# Every check here is informational; nothing is modified.

# --- Known Cloud Vendor Agents Database ---

# Format: process_name|service_name|vendor_key|desc_key|can_disable
# Columns 3 and 4 are i18n KEY SUFFIXES, never display text: they render at
# the point of display. The vendor column shares the provider id space.
declare -ga KNOWN_CLOUD_AGENTS=(
    # Alibaba Cloud
    "AliYunDun|aegis|alibaba|aliyundun|yes"
    "AliYunDunMonitor|aegis|alibaba|aliyundun_monitor|yes"
    "AliYunDunUpdate|aegis|alibaba|aliyundun_update|yes"
    "aliyun-service|aliyun|alibaba|aliyun_service|yes"
    "cloudmonitor|cloudmonitor|alibaba|cloudmonitor|yes"

    # Tencent Cloud
    "YDService|YDService|tencent|ydservice|yes"
    "YDLive|YDService|tencent|ydlive|yes"
    "tat_agent|tat_agent|tencent|tat_agent|yes"
    "sgagent|sgagent|tencent|sgagent|yes"
    "barad_agent|barad_agent|tencent|barad_agent|yes"

    # Huawei Cloud
    "telescope|telescope|huawei|telescope|yes"
    "hostguard|hostguard|huawei|hostguard|yes"
    "uniagent|uniagent|huawei|uniagent|yes"

    # AWS
    "amazon-ssm-agent|amazon-ssm-agent|aws|ssm|optional"
    "amazon-cloudwatch-agent|amazon-cloudwatch-agent|aws|cloudwatch|optional"

    # Azure
    "waagent|walinuxagent|azure|walinuxagent|no"
    "WaLinuxAgent|walinuxagent|azure|walinuxagent|no"
    "OMSAgentForLinux|omsagent|azure|omsagent|yes"

    # Google Cloud
    "google_guest_agent|google-guest-agent|gcp|google_guest|optional"
    "google_osconfig_agent|google-osconfig-agent|gcp|google_osconfig|optional"

    # DigitalOcean
    "do-agent|do-agent|digitalocean|do_agent|yes"

    # Vultr
    "vultr-helper|vultr-helper|vultr|vultr_helper|yes"

    # Linode
    "linode-cli|linode-cli|linode|linode_cli|yes"
    "longview|longview|linode|longview|yes"

    # Oracle Cloud
    "oracle-cloud-agent|oracle-cloud-agent|oracle|oracle_agent|optional"

    # Generic/Common monitoring tools
    "zabbix_agentd|zabbix-agent|generic|zabbix|optional"
    "node_exporter|prometheus-node-exporter|generic|node_exporter|optional"
    "telegraf|telegraf|generic|telegraf|optional"
    "collectd|collectd|generic|collectd|optional"
    "netdata|netdata|generic|netdata|optional"
    "datadog-agent|datadog-agent|generic|datadog|optional"
    "newrelic-infra|newrelic-infra|generic|newrelic|optional"
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
    # Virtualization guest tools: shipped by default on most VPS providers,
    # and several superficially match the suspicious-agent patterns.
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

# --- Detection Functions ---

# Map an EC2-compatible IMDS payload — a placement/region string or an
# instance-id — onto a provider name. Pure: no network, no globals, so the
# disambiguation rules below are directly regression-testable.
_cloud_provider_from_imds() {
    # Strip whitespace; lower-case for region match.
    local _b
    _b=$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')

    case "$_b" in
        # Tencent regions: ap-* (overlaps with AWS Asia-Pacific) plus
        # eu-frankfurt, na-* — but the real giveaway is the instance-id
        # prefix "ins-".
        ins-*)                echo "tencent" ;;
        # AWS Nitro / Xen instance IDs.
        i-*)                  echo "aws" ;;
        # AWS China (Ningxia). cn-northwest-* exists only on AWS, and it has
        # to be matched before the Huawei cn-* shapes below, which would
        # otherwise claim it.
        cn-northwest-*)       echo "aws" ;;
        # Huawei-EXCLUSIVE shapes, and they MUST precede the generic
        # `*-[0-9])` AWS rule: every Huawei region also ends in a digit, so
        # that rule matches first and this branch becomes unreachable.
        cn-east-*|cn-south*|la-north-*|la-south-*|ru-northwest-*|na-mexico-*)
                              echo "huawei" ;;
        # A TRUE collision: both AWS Beijing and Huawei use cn-north-1 and
        # the region string cannot separate them. Keeping AWS trades no
        # misdetection for another; every other cn-north-* is Huawei-only.
        cn-north-1)           echo "aws" ;;
        cn-north-*)           echo "huawei" ;;
        # AWS region tokens always carry a single trailing digit, which
        # Tencent's eu-frankfurt and ap-guangzhou do not. The shapes shared
        # with Huawei stay AWS for the same reason as cn-north-1.
        *-[0-9])              echo "aws" ;;
        ap-guangzhou|ap-shanghai|ap-beijing|ap-chengdu|ap-chongqing|ap-nanjing|ap-hongkong|ap-singapore|ap-bangkok|ap-jakarta|ap-mumbai|ap-seoul|ap-tokyo|na-siliconvalley|na-ashburn|na-toronto|sa-saopaulo|eu-frankfurt|eu-moscow)
                              echo "tencent" ;;
        # Last resort: we got *something* from 169.254.169.254 with the EC2
        # path shape; fall back to AWS but flag via the ambiguous return.
        *)                    echo "aws-or-compatible" ;;
    esac
}

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
            *"Oracle"*)      provider="oracle" ;;
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

    # --- 3. product_uuid prefix: EC2 on Xen, random on Nitro. A tiebreaker
    # for when the DMI vendor is generic. ---
    if [[ "$provider" == "unknown" && -r /sys/class/dmi/id/product_uuid ]]; then
        # Read may fail with EACCES for non-root; ignore quietly.
        local uuid=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null | tr '[:upper:]' '[:lower:]')
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

    # --- 6. Provider-specific NETWORK endpoints. Unique per provider, so a
    # 200 is conclusive — and they MUST precede the shared 169.254.169.254
    # fallback, or an EC2-compatible mirror reads as AWS. ---
    if [[ "$provider" == "unknown" ]]; then
        # Tencent serves its own metadata name AND mirrors an EC2-compatible
        # service at the shared IP, so the specific name is tried first.
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

    # --- 7. Shared 169.254.169.254, which several providers all answer.
    # A bare 200 is NOT enough: the region or instance-id payload has to be
    # read and matched. ---
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
            provider=$(_cloud_provider_from_imds "$_imds_body")
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

# Provider display name. The names live in i18n, never as literals here —
# the provider ids below are the machine-side identity and never move.
_get_provider_name() {
    local provider="$1"
    case "$provider" in
        alibaba|tencent|huawei|aws|azure|gcp|digitalocean|vultr|linode|oracle|hetzner|ovh|scaleway)
            i18n "cloud.provider_name_${provider}" ;;
        aws-or-compatible)
            # Not a key on its own line only because of the dash.
            i18n 'cloud.provider_name_aws_compatible' ;;
        unknown)      echo "$(i18n 'common.unknown' 2>/dev/null || echo 'Unknown')" ;;
        *)            echo "$provider" ;;
    esac
}

# Render an agent's vendor column (a stable key) for display.
_cloud_vendor_name() {
    i18n "cloud.vendor_${1}"
}

# Render an agent's description column (a stable key) for display.
_cloud_agent_desc() {
    i18n "cloud.agent_${1}"
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

    # The vendor/desc keys travel unresolved: resolving here bakes the active
    # language into the data, and anything matching on vendor downstream would
    # then be matching a translated string.
    for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r proc_name service_name vendor_key desc_key can_disable <<< "$entry"

        # Check if process is running
        if pgrep -x "$proc_name" &>/dev/null; then
            found+=("$proc_name|$service_name|$vendor_key|$desc_key|$can_disable|running")
        # Check if service exists
        elif systemctl is-active "$service_name" &>/dev/null 2>&1; then
            found+=("$proc_name|$service_name|$vendor_key|$desc_key|$can_disable|service")
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

# --- IMDS helpers. Three rules hold throughout this section: NEVER log or
# echo a response body (they carry credentials), keep the timeouts at 1-2s so
# non-cloud hosts fail fast, and run only for tier1/tier2 providers. ---

# Capture only HTTP status (3-digit, or "000" on connection failure).
_cloud_imds_curl_status() {
    local url="$1"; shift
    curl -sS --max-time 1 --connect-timeout 1 \
        -o /dev/null -w '%{http_code}' \
        "$@" "$url" 2>/dev/null
}

# Fetch user-data via the detected provider's endpoint. Returns body
# on stdout; empty when unavailable. Decodes base64 only where the
# provider's API contract requires it (Azure customData).
_cloud_imds_get_user_data() {
    local provider; provider=$(vpssec_cloud_provider)
    local body=""
    case "$provider" in
        aws)
            # Prefer IMDSv2; fall back to v1 only if v2 unavailable.
            local token
            token=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
                -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
                --max-time 1 --connect-timeout 1 2>/dev/null)
            if [[ -n "$token" ]]; then
                body=$(curl -sS --max-time 2 --connect-timeout 1 \
                    -H "X-aws-ec2-metadata-token: $token" \
                    "http://169.254.169.254/latest/user-data" 2>/dev/null)
            fi
            [[ -z "$body" ]] && body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://169.254.169.254/latest/user-data" 2>/dev/null)
            ;;
        alibaba)
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://100.100.100.200/latest/user-data" 2>/dev/null)
            [[ -z "$body" ]] && body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://169.254.169.254/latest/user-data" 2>/dev/null)
            ;;
        azure)
            # customData is base64-encoded per Azure API contract.
            local enc
            enc=$(curl -sS --max-time 2 --connect-timeout 1 -H "Metadata: true" \
                "http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-01-01&format=text" \
                2>/dev/null)
            [[ -n "$enc" ]] && body=$(printf '%s' "$enc" | base64 -d 2>/dev/null)
            ;;
        gcp)
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                -H "Metadata-Flavor: Google" \
                "http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data" 2>/dev/null)
            ;;
        digitalocean)
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://169.254.169.254/metadata/v1/user-data" 2>/dev/null)
            ;;
        hetzner)
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://169.254.169.254/hetzner/v1/userdata" 2>/dev/null)
            ;;
        vultr|linode)
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://169.254.169.254/v1/user-data" 2>/dev/null)
            ;;
        tencent)
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://metadata.tencentyun.com/latest/user-data" 2>/dev/null)
            ;;
        huawei|ovh)
            # Both are OpenStack-based; user-data lives at the standard
            # OpenStack metadata path (plaintext).
            body=$(curl -sS --max-time 2 --connect-timeout 1 \
                "http://169.254.169.254/openstack/latest/user_data" 2>/dev/null)
            ;;
        oracle)
            # OCI: base64-encoded user_data behind the mandatory v2 auth header.
            local enc
            enc=$(curl -sS --max-time 2 --connect-timeout 1 \
                -H "Authorization: Bearer Oracle" \
                "http://169.254.169.254/opc/v2/instance/metadata/user_data" 2>/dev/null)
            [[ -n "$enc" ]] && body=$(printf '%s' "$enc" | base64 -d 2>/dev/null)
            ;;
        scaleway)
            # Scaleway serves user_data only to a privileged source port, so
            # one is bound. --local-port fails closed on a curl without it.
            body=$(curl -sS --max-time 2 --connect-timeout 1 --local-port 1-1023 \
                "http://169.254.42.42/user_data" 2>/dev/null)
            ;;
    esac
    printf '%s' "$body"
}

# Backwards-compat thin wrapper. The actual scanner lives in
# core/common.sh (_vpssec_scan_secrets_in_content) so docker.sh and
# any future module can reuse the same pattern set.
_cloud_imds_scan_secrets() {
    _vpssec_scan_secrets_in_content "$1"
}

# True if any host-firewall rule MENTIONS an IMDS IP — a weak signal, since
# telling a blocking rule from a logging one needs full ruleset parsing.
# The finding must be worded as "mentions", never "restricted".
_cloud_imds_firewall_restricted() {
    local imds_ips=("169.254.169.254" "100.100.100.200")
    local ip re
    for ip in "${imds_ips[@]}"; do
        re="${ip//./\\.}"
        if command -v iptables-save >/dev/null 2>&1 \
           && iptables-save 2>/dev/null | grep -q "$re"; then
            return 0
        fi
        if command -v ip6tables-save >/dev/null 2>&1 \
           && ip6tables-save 2>/dev/null | grep -q "$re"; then
            return 0
        fi
        if command -v nft >/dev/null 2>&1 \
           && nft list ruleset 2>/dev/null | grep -q "$re"; then
            return 0
        fi
    done
    return 1
}

# Lightweight container check (cloud.sh shouldn't depend on kernel.sh
# being loaded). Skips host-firewall checks in containers since the
# container can't see the host's nftables.
_cloud_imds_in_container() {
    [[ -f /.dockerenv ]] && return 0
    [[ -f /run/.containerenv ]] && return 0
    if [[ -r /proc/1/cgroup ]]; then
        grep -qE '/(docker|kubepods|libpod|containerd|lxc)/' /proc/1/cgroup 2>/dev/null \
            && return 0
    fi
    return 1
}

# Main IMDS audit orchestrator. Silent no-op on unknown tier.
_cloud_audit_imds() {
    local tier; tier=$(vpssec_cloud_tier)
    [[ "$tier" == "unknown" ]] && return 0
    command -v curl >/dev/null 2>&1 || return 0

    local provider; provider=$(vpssec_cloud_provider)
    local check

    # 1. AWS-specific: IMDSv1 still open?
    if [[ "$provider" == "aws" ]]; then
        local v1_status v2_token
        v1_status=$(_cloud_imds_curl_status "http://169.254.169.254/latest/meta-data/")
        v2_token=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
            --max-time 1 --connect-timeout 1 2>/dev/null)

        if [[ "$v1_status" == "200" ]]; then
            check=$(create_check_json \
                "cloud.imds_v1_enabled" \
                "cloud" \
                "medium" \
                "failed" \
                "$(i18n 'cloud.imds_v1_enabled' 2>/dev/null || echo 'AWS IMDSv1 is enabled (HttpTokens=optional)')" \
                "GET /latest/meta-data/ returned 200 with no session token — IMDSv1 reachable, exposes IAM role credentials to SSRF (Capital One pattern)" \
                "$(i18n 'cloud.fix_imds_v1' 2>/dev/null || echo 'Run: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required')" \
                "")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'cloud.imds_v1_enabled' 2>/dev/null || echo 'AWS IMDSv1 is enabled')"
        elif [[ "$v1_status" == "401" && -n "$v2_token" ]]; then
            check=$(create_check_json \
                "cloud.imds_v2_only" \
                "cloud" \
                "info" \
                "passed" \
                "$(i18n 'cloud.imds_v2_only' 2>/dev/null || echo 'AWS IMDSv2 enforced (HttpTokens=required)')" \
                "" "" "")
            state_add_check "$check"
            print_ok "$(i18n 'cloud.imds_v2_only' 2>/dev/null || echo 'AWS IMDSv2 enforced')"
        fi
    fi

    # 2. Alibaba-specific: security hardening mode enforced?
    if [[ "$provider" == "alibaba" ]]; then
        local ali_status
        ali_status=$(_cloud_imds_curl_status "http://100.100.100.200/latest/meta-data/")
        [[ "$ali_status" != "200" ]] && ali_status=$(_cloud_imds_curl_status "http://169.254.169.254/latest/meta-data/")

        if [[ "$ali_status" == "200" ]]; then
            check=$(create_check_json \
                "cloud.imds_alibaba_normal_mode" \
                "cloud" \
                "medium" \
                "failed" \
                "$(i18n 'cloud.imds_alibaba_normal_mode' 2>/dev/null || echo 'Alibaba Cloud IMDS accepts token-free reads (normal mode)')" \
                "Metadata reachable without a session token; Alibaba recommends Security Hardening Mode" \
                "$(i18n 'cloud.fix_imds_alibaba' 2>/dev/null || echo 'Enable security hardening mode in the ECS console under instance metadata options')" \
                "")
            state_add_check "$check"
            print_severity "medium" "$(i18n 'cloud.imds_alibaba_normal_mode' 2>/dev/null || echo 'Alibaba IMDS in normal mode')"
        elif [[ "$ali_status" == "403" || "$ali_status" == "401" ]]; then
            check=$(create_check_json \
                "cloud.imds_alibaba_hardened" \
                "cloud" \
                "info" \
                "passed" \
                "$(i18n 'cloud.imds_alibaba_hardened' 2>/dev/null || echo 'Alibaba Cloud IMDS security hardening enabled')" \
                "" "" "")
            state_add_check "$check"
            print_ok "$(i18n 'cloud.imds_alibaba_hardened' 2>/dev/null || echo 'Alibaba IMDS hardened')"
        fi
    fi

    # 3. user-data secret scan (universal across tier1 + tier2).
    local user_data; user_data=$(_cloud_imds_get_user_data)
    if [[ -n "$user_data" ]]; then
        local hits; hits=$(_cloud_imds_scan_secrets "$user_data")
        hits="${hits% }"
        if [[ -n "$hits" ]]; then
            # NEVER log user_data body — only kinds + counts.
            log_info "user-data secret hits (kinds): $hits"
            check=$(create_check_json \
                "cloud.user_data_leaked_secrets" \
                "cloud" \
                "high" \
                "failed" \
                "$(i18n 'cloud.user_data_leaked_secrets' 2>/dev/null || echo 'Embedded credentials detected in instance user-data')" \
                "Pattern matches: $hits (kinds + counts only; raw values withheld). cloud-init user-data is readable by every process on this host — rotate the exposed credentials and remove them from user-data" \
                "$(i18n 'cloud.fix_user_data_secrets' 2>/dev/null || echo 'Rotate the exposed credentials immediately; pass secrets via the cloud providers secret store rather than user-data')" \
                "")
            state_add_check "$check"
            print_severity "high" "$(i18n 'cloud.user_data_leaked_secrets' 2>/dev/null || echo 'Secrets in user-data'): $hits"
        else
            check=$(create_check_json \
                "cloud.user_data_clean" \
                "cloud" \
                "info" \
                "passed" \
                "$(i18n 'cloud.user_data_clean' 2>/dev/null || echo 'user-data scanned, no embedded credential patterns')" \
                "" "" "")
            state_add_check "$check"
            print_ok "$(i18n 'cloud.user_data_clean' 2>/dev/null || echo 'user-data clean')"
        fi
    fi

    # 4. Defense-in-depth: host firewall rule referencing IMDS IPs?
    # Skip in containers (no view of host nftables).
    if ! _cloud_imds_in_container; then
        if _cloud_imds_firewall_restricted; then
            check=$(create_check_json \
                "cloud.imds_restricted" \
                "cloud" \
                "info" \
                "passed" \
                "$(i18n 'cloud.imds_restricted' 2>/dev/null || echo 'Host firewall has rule(s) referencing IMDS address')" \
                "" "" "")
            state_add_check "$check"
            print_ok "$(i18n 'cloud.imds_restricted' 2>/dev/null || echo 'IMDS firewall restriction present')"
        else
            check=$(create_check_json \
                "cloud.imds_unrestricted" \
                "cloud" \
                "low" \
                "failed" \
                "$(i18n 'cloud.imds_unrestricted' 2>/dev/null || echo 'No host-firewall restriction on IMDS access')" \
                "iptables/nftables has no rule mentioning 169.254.169.254 or 100.100.100.200 — defense-in-depth recommends restricting IMDS to specific users (e.g. iptables -m owner --uid-owner root)" \
                "$(i18n 'cloud.fix_imds_firewall' 2>/dev/null || echo 'Consider blocking IMDS at the host firewall for non-root users')" \
                "")
            state_add_check "$check"
            print_severity "low" "$(i18n 'cloud.imds_unrestricted' 2>/dev/null || echo 'No firewall restriction on IMDS')"
        fi
    fi
}

# --- Audit Functions ---

cloud_audit() {
    log_info "Running cloud environment audit"

    # The public getter, so the result caches into VPSSEC_CLOUD_PROVIDER and
    # every later module reads it without rerunning DMI inspection.
    local provider=$(vpssec_cloud_provider)
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
        # Build agent list for display. The vendor key renders here, at the
        # edge, so the title follows --lang.
        local agent_list=""
        while IFS='|' read -r proc_name service_name vendor_key desc_key can_disable status; do
            [[ -z "$proc_name" ]] && continue
            agent_list+="$proc_name ($(_cloud_vendor_name "$vendor_key")), "
        done <<< "$known_agents"
        agent_list="${agent_list%, }"

        # Vendor agents are inventory, not exposure, so low on every host.
        # There is deliberately no foreign-vendor escalation: it must arrive
        # with a test that can observe the severity actually moving.
        local severity="low"

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

    # 4. IMDS posture audit (tier1 + tier2 only; silent on independent VPS).
    _cloud_audit_imds

    return 0
}

# --- Fix Functions (Alert Only - No Auto Fix) ---

cloud_fix() {
    local fix_id="$1"

    case "$fix_id" in
        cloud.agents_found)
            print_warn "$(i18n 'cloud.manual_review' 2>/dev/null || echo 'Manual review required')"
            echo ""
            echo "$(i18n 'cloud.agents_info' 2>/dev/null || echo 'Detected monitoring agents'):"
            echo ""

            local known_agents=$(_find_known_agents)
            # Feed the loop from the data, not stdin: a bare `while read` here
            # reads the process's stdin (in guide mode, the remaining plan), so
            # it must be redirected from $known_agents explicitly.
            while IFS='|' read -r proc_name service_name vendor_key desc_key can_disable status; do
                [[ -z "$proc_name" ]] && continue
                echo "  • $proc_name"
                echo "    $(i18n 'common.info' 2>/dev/null || echo 'Info'): $(_cloud_agent_desc "$desc_key")"
                echo "    $(i18n 'cloud.vendor' 2>/dev/null || echo 'Vendor'): $(_cloud_vendor_name "$vendor_key")"
                echo "    $(i18n 'cloud.service' 2>/dev/null || echo 'Service'): $service_name"
                if [[ "$can_disable" == "yes" ]]; then
                    echo "    $(i18n 'cloud.can_disable' 2>/dev/null || echo 'Can disable'): systemctl disable --now $service_name"
                elif [[ "$can_disable" == "no" ]]; then
                    echo "    $(i18n 'cloud.required' 2>/dev/null || echo 'Required'): $(i18n 'cloud.do_not_disable' 2>/dev/null || echo 'Do not disable - required for cloud functionality')"
                else
                    echo "    $(i18n 'cloud.optional' 2>/dev/null || echo 'Optional'): $(i18n 'cloud.review_before_disable' 2>/dev/null || echo 'Review before disabling')"
                fi
                echo ""
            done <<< "$known_agents"

            return 1  # Alert only, no auto-fix
            ;;

        cloud.suspicious_agents)
            print_warn "$(i18n 'cloud.manual_review' 2>/dev/null || echo 'Manual review required')"
            echo ""
            echo "$(i18n 'cloud.suspicious_info' 2>/dev/null || echo 'Suspicious processes found'):"
            echo ""

            local suspicious=$(_find_suspicious_agents)
            # Redirect from the data, not stdin (see cloud.agents_found above).
            while IFS='|' read -r proc pid user cmdline; do
                [[ -z "$proc" ]] && continue
                echo "  • $proc (PID: $pid)"
                echo "    User: $user"
                echo "    Command: ${cmdline:0:100}..."
                echo "    $(i18n 'cloud.investigate' 2>/dev/null || echo 'Investigate'): ps aux | grep $proc"
                echo ""
            done <<< "$suspicious"

            return 1  # Alert only, no auto-fix
            ;;

        *)
            log_warn "Unknown fix_id: $fix_id"
            return 1
            ;;
    esac
}
