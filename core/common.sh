#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core common functions and utilities
# Copyright (c) 2024

set -euo pipefail

# ==============================================================================
# Global Variables
# ==============================================================================

VPSSEC_VERSION="1.0.0"
VPSSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VPSSEC_CORE="${VPSSEC_ROOT}/core"
VPSSEC_MODULES="${VPSSEC_ROOT}/modules"
VPSSEC_STATE="${VPSSEC_ROOT}/state"
VPSSEC_REPORTS="${VPSSEC_ROOT}/reports"
VPSSEC_BACKUPS="${VPSSEC_ROOT}/backups"
VPSSEC_LOGS="${VPSSEC_ROOT}/logs"
VPSSEC_TEMPLATES="${VPSSEC_ROOT}/templates"

# Default settings
VPSSEC_LANG="${VPSSEC_LANG:-zh_CN}"
VPSSEC_COLOR="${VPSSEC_COLOR:-1}"
VPSSEC_JSON_ONLY="${VPSSEC_JSON_ONLY:-0}"
VPSSEC_YES="${VPSSEC_YES:-0}"
VPSSEC_DEBUG="${VPSSEC_DEBUG:-0}"
VPSSEC_QUIET_SCAN="${VPSSEC_QUIET_SCAN:-0}"  # Suppress detailed output during scanning

# Runtime state. Use `declare -g` so these arrays stay global even when
# common.sh is sourced from inside a function (e.g. from a bats test
# helper); without -g, bash's default "declare-inside-function = local"
# rule would hide them from any caller. In the production load path
# (vpssec entry script sources common.sh at top level) -g is a no-op.
declare -gA VPSSEC_I18N=()
declare -ga VPSSEC_CHECKS=()
declare -ga VPSSEC_FIXES=()

# Cloud-detection cache. Populated lazily on first call to
# vpssec_cloud_provider() and vpssec_cloud_tier(). The detection itself
# lives in modules/cloud.sh (`_detect_cloud_provider`) — these getters
# delegate to it when available and fall back to "unknown" when cloud.sh
# isn't loaded (e.g. running `vpssec audit --include=users` alone), so
# any module can call them without depending on module load order.
declare -g VPSSEC_CLOUD_PROVIDER=""
declare -g VPSSEC_CLOUD_TIER=""

# Returns one of:
#   aws | azure | gcp | alibaba | tencent | huawei | oracle
#   | digitalocean | vultr | linode | hetzner | ovh | scaleway
#   | unknown
vpssec_cloud_provider() {
    if [[ -n "$VPSSEC_CLOUD_PROVIDER" ]]; then
        echo "$VPSSEC_CLOUD_PROVIDER"
        return
    fi
    if declare -f _detect_cloud_provider >/dev/null 2>&1; then
        VPSSEC_CLOUD_PROVIDER=$(_detect_cloud_provider)
    else
        VPSSEC_CLOUD_PROVIDER="unknown"
    fi
    echo "$VPSSEC_CLOUD_PROVIDER"
}

# Coarse provider tier — used by modules that need to vary behavior
# based on "what kind of cloud" rather than which exact vendor:
#   tier1 — full-stack public cloud, IAM/RAM credentials live in IMDS
#           (AWS, Azure, GCP, Alibaba, Tencent, Huawei, Oracle).
#           IMDSv1-vs-v2 distinction is meaningful; SSRF -> credential
#           theft is the headline threat.
#   tier2 — managed VPS with a link-local IMDS but no IAM credentials.
#           user-data (bootstrap script) is the primary exposed asset.
#           (DigitalOcean, Vultr, Linode/Akamai, Hetzner Cloud, OVH
#           Public Cloud, Scaleway.)
#   unknown — independent / smaller VPS providers (RackNerd, HostHatch,
#             GreenCloud, netcup classic, Spartan, ...) or local
#             KVM/VirtualBox/bare-metal. Typically no network IMDS;
#             cloud-init via NoCloud / ConfigDrive (filesystem seed).
vpssec_cloud_tier() {
    if [[ -n "$VPSSEC_CLOUD_TIER" ]]; then
        echo "$VPSSEC_CLOUD_TIER"
        return
    fi
    case "$(vpssec_cloud_provider)" in
        aws|azure|gcp|alibaba|tencent|huawei|oracle)
            VPSSEC_CLOUD_TIER="tier1" ;;
        digitalocean|vultr|linode|hetzner|ovh|scaleway)
            VPSSEC_CLOUD_TIER="tier2" ;;
        *)
            VPSSEC_CLOUD_TIER="unknown" ;;
    esac
    echo "$VPSSEC_CLOUD_TIER"
}

# Scan a content string for KNOWN-FORMAT credentials. Used by both
# cloud.sh (IMDS user-data scan) and docker.sh (container env var
# scan); kept here to avoid maintaining two copies of the same
# pattern set.
#
# Output: "<kind>(<n>) <kind>(<n>) ..." — kinds + counts only, NEVER
# the matched values. Patterns are deliberately specific (vendor-
# mandated prefixes, PEM headers, JWT structure) so FP rate stays
# near zero. Generic markers like PASSWORD= / SECRET= are NOT
# matched: they're legitimate in many bootstrap scripts and
# container environment variables (MYSQL_ROOT_PASSWORD, etc.).
_vpssec_scan_secrets_in_content() {
    local content="$1"
    [[ -z "$content" ]] && return 0
    local found=() n

    # PEM private keys (any flavor).
    n=$(grep -cE -- '-----BEGIN[[:space:]]+(RSA|OPENSSH|EC|DSA|ENCRYPTED|PGP)?[[:space:]]?PRIVATE[[:space:]]+KEY-----' \
        <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("private_key(x$n)")

    # AWS access key IDs (AKIA = long-lived user; ASIA = temporary session).
    n=$(grep -cE '(AKIA|ASIA)[0-9A-Z]{16}' <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("aws_access_key(x$n)")

    # AWS secret access key (after canonical variable name).
    n=$(grep -cE 'aws_secret_access_key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+=]{40}' \
        <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("aws_secret_key(x$n)")

    # GitHub tokens (vendor-strict 2021+ prefix: ghp_, ghs_, gho_, ghu_).
    n=$(grep -cE 'gh[posu]_[A-Za-z0-9]{36}' <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("github_token(x$n)")

    # GitLab PAT.
    n=$(grep -cE 'glpat-[A-Za-z0-9_-]{20}' <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("gitlab_token(x$n)")

    # Slack tokens.
    n=$(grep -cE 'xox[bpoasr]-[0-9A-Za-z-]{10,}' <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("slack_token(x$n)")

    # JWT (a.b.c with base64url-format segments starting with eyJ).
    n=$(grep -cE 'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
        <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("jwt(x$n)")

    # Stripe live keys.
    n=$(grep -cE 'sk_live_[0-9a-zA-Z]{24,}' <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("stripe_live_key(x$n)")

    printf '%s ' "${found[@]}"
}

# ==============================================================================
# Color and Formatting
# ==============================================================================

# Color codes
if [[ "${VPSSEC_COLOR}" == "1" ]] && [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[0;37m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    MAGENTA=''
    CYAN=''
    WHITE=''
    BOLD=''
    DIM=''
    NC=''
fi

# Status symbols
SYM_OK="✓"
SYM_FAIL="✗"
SYM_WARN="⚠"
SYM_INFO="ℹ"
SYM_ARROW="→"
SYM_BULLET="•"

# Severity indicators
SEV_HIGH="${RED}●${NC}"
SEV_MEDIUM="${YELLOW}●${NC}"
SEV_LOW="${BLUE}●${NC}"
SEV_SAFE="${GREEN}●${NC}"

# ==============================================================================
# Logging Functions
# ==============================================================================

_log_file="${VPSSEC_LOGS}/vpssec.log"

log_init() {
    mkdir -p "${VPSSEC_LOGS}"
    echo "=== vpssec session started at $(date -Iseconds) ===" >> "${_log_file}"
}

log_debug() {
    if [[ "${VPSSEC_DEBUG:-0}" == "1" ]]; then
        echo "[DEBUG] $(date -Iseconds) $*" >> "${_log_file}" 2>/dev/null || true
    fi
}

log_info() {
    echo "[INFO] $(date -Iseconds) $*" >> "${_log_file}" 2>/dev/null || true
}

log_warn() {
    echo "[WARN] $(date -Iseconds) $*" >> "${_log_file}" 2>/dev/null || true
}

log_error() {
    echo "[ERROR] $(date -Iseconds) $*" >> "${_log_file}" 2>/dev/null || true
}

# ==============================================================================
# Output Functions
# ==============================================================================

print_msg() {
    [[ "${VPSSEC_JSON_ONLY}" == "1" ]] && return
    echo -e "$*"
}

print_info() {
    # Skip if in quiet scan mode
    [[ "${VPSSEC_QUIET_SCAN:-0}" == "1" ]] && return 0
    print_msg "${BLUE}${SYM_INFO}${NC} $*"
}

print_ok() {
    # Skip if in quiet scan mode
    [[ "${VPSSEC_QUIET_SCAN:-0}" == "1" ]] && return 0
    print_msg "${GREEN}${SYM_OK}${NC} $*"
}

print_warn() {
    # Skip if in quiet scan mode
    [[ "${VPSSEC_QUIET_SCAN:-0}" == "1" ]] && return 0
    print_msg "${YELLOW}${SYM_WARN}${NC} $*"
}

print_error() {
    print_msg "${RED}${SYM_FAIL}${NC} $*"
}

print_header() {
    local title="$1"
    local width="${2:-60}"
    # Use printf's repeat trick rather than `tr ' ' '─'`. `tr` is
    # byte-oriented and on some GNU coreutils versions (Debian 13's
    # included) replacing a single-byte space with a multi-byte UTF-8
    # char produces mojibake (users saw strings of `㣢`). The format
    # `─%.0s` prints `─` once per positional argument.
    local line
    line=$(printf '─%.0s' $(seq 1 "$width"))
    print_msg ""
    print_msg "${BOLD}${line}${NC}"
    print_msg "${BOLD}  $title${NC}"
    print_msg "${BOLD}${line}${NC}"
}

print_subheader() {
    # Skip if in quiet scan mode
    [[ "${VPSSEC_QUIET_SCAN:-0}" == "1" ]] && return 0
    print_msg ""
    print_msg "${BOLD}${CYAN}▶ $*${NC}"
}

print_item() {
    # Skip if in quiet scan mode
    [[ "${VPSSEC_QUIET_SCAN:-0}" == "1" ]] && return 0
    print_msg "  ${DIM}${SYM_BULLET}${NC} $*"
}

print_severity() {
    # Skip if in quiet scan mode
    [[ "${VPSSEC_QUIET_SCAN:-0}" == "1" ]] && return 0
    local severity="$1"
    local text="$2"
    case "$severity" in
        high)   print_msg "  ${SEV_HIGH} ${RED}$text${NC}" ;;
        medium) print_msg "  ${SEV_MEDIUM} ${YELLOW}$text${NC}" ;;
        low)    print_msg "  ${SEV_LOW} ${BLUE}$text${NC}" ;;
        safe|passed) print_msg "  ${SEV_SAFE} ${GREEN}$text${NC}" ;;
        *)      print_msg "  ${SYM_BULLET} $text" ;;
    esac
}

# Progress bar
print_progress() {
    local current="$1"
    local total="$2"
    local width="${3:-40}"

    # Defensive: every real caller passes a positive total (audit_all
    # always includes the preflight/cloud/timezone context modules, so
    # total >= 3), but a future caller or a pathological --include=
    # value could land here with total=0. Without this guard the
    # `current * 100 / total` arithmetic aborts under `set -e` and
    # kills the whole run.
    if (( total <= 0 )); then
        return 0
    fi

    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    local bar="${GREEN}"
    for ((i=0; i<filled; i++)); do bar+="█"; done
    bar+="${DIM}"
    for ((i=0; i<empty; i++)); do bar+="░"; done
    bar+="${NC}"

    printf "\r  [%s] %3d%% " "$bar" "$percent"
}

# ==============================================================================
# i18n Functions
# ==============================================================================

i18n_load() {
    local lang="${1:-$VPSSEC_LANG}"
    local i18n_file="${VPSSEC_CORE}/i18n/${lang}.json"

    if [[ ! -f "$i18n_file" ]]; then
        log_warn "Language file not found: $i18n_file, falling back to en_US"
        i18n_file="${VPSSEC_CORE}/i18n/en_US.json"
    fi

    if ! command -v jq &>/dev/null; then
        log_error "jq is required for i18n support"
        return 1
    fi

    # Load all translations into associative array
    while IFS='=' read -r key value; do
        VPSSEC_I18N["$key"]="$value"
    done < <(jq -r 'paths(scalars) as $p | "\($p | join("."))=\(getpath($p))"' "$i18n_file")

    log_debug "Loaded ${#VPSSEC_I18N[@]} i18n entries from $lang"
}

# Get translated string with optional variable substitution
# Usage: i18n "ssh.password_auth_enabled" or i18n "preflight.dep_missing" "dep=jq"
i18n() {
    local key="$1"
    shift
    local text="${VPSSEC_I18N[$key]:-$key}"

    # Variable substitution
    for arg in "$@"; do
        local var="${arg%%=*}"
        local val="${arg#*=}"
        text="${text//\{$var\}/$val}"
    done

    echo "$text"
}

# ==============================================================================
# System Detection Functions
# ==============================================================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

detect_os_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${VERSION_ID:-unknown}"
    else
        echo "unknown"
    fi
}

detect_os_codename() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${VERSION_CODENAME:-unknown}"
    else
        echo "unknown"
    fi
}

detect_virtualization() {
    if command -v systemd-detect-virt &>/dev/null; then
        systemd-detect-virt 2>/dev/null || echo "none"
    elif [[ -f /proc/1/cgroup ]]; then
        if grep -q docker /proc/1/cgroup 2>/dev/null; then
            echo "docker"
        elif grep -q lxc /proc/1/cgroup 2>/dev/null; then
            echo "lxc"
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

is_debian_based() {
    local os=$(detect_os)
    [[ "$os" == "debian" || "$os" == "ubuntu" ]]
}

is_supported_os() {
    local os=$(detect_os)
    local version=$(detect_os_version)

    case "$os" in
        debian)
            [[ "$version" == "12" || "$version" == "13" ]]
            ;;
        ubuntu)
            [[ "$version" == "22.04" || "$version" == "24.04" || "$version" == "26.04" ]]
            ;;
        *)
            # RHEL family (Rocky/Alma/CentOS Stream) and Arch: the
            # read-only audit is distro-aware via core/distro.sh and has
            # been validated on real hosts. Match the detected family so
            # ID_LIKE downstreams resolve without enumerating every ID.
            # Automated fixes are NOT ported — guide_mode gates on
            # is_debian_based() separately.
            case "${VPSSEC_DISTRO_FAMILY:-unknown}" in
                rhel)
                    local major="${version%%.*}"
                    [[ "$major" == "8" || "$major" == "9" || "$major" == "10" ]]
                    ;;
                arch)
                    return 0
                    ;;
                *)
                    return 1
                    ;;
            esac
            ;;
    esac
}

# ==============================================================================
# Dependency Check Functions
# ==============================================================================

check_root() {
    [[ "$(id -u)" == "0" ]]
}

check_command() {
    command -v "$1" &>/dev/null
}

check_required_deps() {
    local missing=()
    local deps=(jq ss systemctl sed awk tar grep)

    for dep in "${deps[@]}"; do
        if ! check_command "$dep"; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "${missing[*]}"
        return 1
    fi
    return 0
}

check_optional_deps() {
    local missing=()
    local deps=(whiptail dialog ufw nginx docker)

    for dep in "${deps[@]}"; do
        if ! check_command "$dep"; then
            missing+=("$dep")
        fi
    done

    echo "${missing[*]}"
}

# ==============================================================================
# Input Validation Functions
# ==============================================================================

# Validate that a path is safe (no path traversal)
validate_path() {
    local path="$1"
    local base_dir="${2:-}"

    # Check for null or empty
    [[ -z "$path" ]] && return 1

    # Check for path traversal attempts
    if [[ "$path" =~ \.\. ]] || [[ "$path" =~ ^[[:space:]] ]] || [[ "$path" =~ [[:space:]]$ ]]; then
        log_warn "Potentially unsafe path detected: $path"
        return 1
    fi

    # If base_dir is specified, ensure path is under it
    if [[ -n "$base_dir" ]]; then
        local resolved_path
        resolved_path=$(realpath -m "$path" 2>/dev/null) || return 1
        local resolved_base
        resolved_base=$(realpath -m "$base_dir" 2>/dev/null) || return 1

        # Require the path to BE the base or sit under "base/". A bare
        # "$resolved_base"* prefix match would accept a sibling whose name
        # merely starts with the base (e.g. base=/a/backups would accept
        # /a/backups-evil/x) — a prefix-escape in a security primitive.
        if [[ "$resolved_path" != "$resolved_base" && "$resolved_path" != "$resolved_base"/* ]]; then
            log_warn "Path $path is not under base directory $base_dir"
            return 1
        fi
    fi

    return 0
}

# Validate that input matches expected pattern
validate_input() {
    local input="$1"
    local pattern="$2"
    local max_length="${3:-1024}"

    # Check length
    if [[ ${#input} -gt $max_length ]]; then
        return 1
    fi

    # Check pattern
    if [[ -n "$pattern" ]] && [[ ! "$input" =~ $pattern ]]; then
        return 1
    fi

    return 0
}

# Validate port number
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]
}

# Validate IP address (basic check)
validate_ip() {
    local ip="$1"
    # IPv4 basic validation
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    # IPv6 basic validation (simplified)
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]; then
        return 0
    fi
    return 1
}

# ==============================================================================
# File Operations (Safe)
# ==============================================================================

# Create a timestamped backup of a file
backup_file() {
    local file="$1"

    # Validate input path
    if ! validate_path "$file"; then
        log_error "Invalid path for backup: $file"
        return 1
    fi

    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${VPSSEC_BACKUPS}/${timestamp}"

    # Create backup directory with secure permissions
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"

    if [[ -f "$file" ]]; then
        local relative_path="${file#/}"
        local backup_path="${backup_dir}/${relative_path}"

        # Validate the constructed backup path
        if ! validate_path "$backup_path" "$VPSSEC_BACKUPS"; then
            log_error "Unsafe backup path: $backup_path"
            return 1
        fi

        mkdir -p "$(dirname "$backup_path")"
        cp -p "$file" "$backup_path"
        chmod 600 "$backup_path"
        log_info "Backed up: $file -> $backup_path"
        echo "$backup_path"
    fi
}

# Write file atomically (write to temp, then mv)
write_file_atomic() {
    local target="$1"
    local content="$2"

    # Validate target path
    if ! validate_path "$target"; then
        log_error "Invalid target path: $target"
        return 1
    fi

    local temp_file
    local target_dir
    target_dir=$(dirname "$target")

    # Ensure target directory exists
    mkdir -p "$target_dir"

    # Create temp file in the same directory for atomic mv
    temp_file=$(mktemp "${target_dir}/.vpssec.XXXXXX") || {
        log_error "Failed to create temp file in $target_dir"
        return 1
    }

    # Set secure permissions initially
    chmod 600 "$temp_file"

    # Refuse empty content: typically indicates an upstream command
    # substitution that failed silently and would otherwise clobber
    # the target file with nothing.
    if [[ -z "$content" ]]; then
        rm -f "$temp_file"
        log_error "write_file_atomic: refusing empty content for $target"
        return 1
    fi

    # Write content
    if ! printf '%s' "$content" > "$temp_file"; then
        rm -f "$temp_file"
        log_error "Failed to write content to temp file"
        return 1
    fi

    # Set appropriate permissions (copy from target or default to 644)
    if [[ -f "$target" ]]; then
        chmod --reference="$target" "$temp_file" 2>/dev/null || chmod 644 "$temp_file"
    else
        chmod 644 "$temp_file"
    fi

    if mv -f "$temp_file" "$target"; then
        log_info "Atomically wrote: $target"
        return 0
    else
        rm -f "$temp_file"
        log_error "Failed to write: $target"
        return 1
    fi
}

# Write drop-in configuration
write_dropin() {
    local base_dir="$1"
    local filename="$2"
    local content="$3"
    local dropin_dir="${base_dir}.d"

    mkdir -p "$dropin_dir"
    local target="${dropin_dir}/${filename}"

    backup_file "$target" 2>/dev/null || true
    write_file_atomic "$target" "$content"
}

# ==============================================================================
# Service Operations
# ==============================================================================

service_exists() {
    systemctl list-unit-files "${1}.service" &>/dev/null
}

service_is_active() {
    systemctl is-active --quiet "$1"
}

service_is_enabled() {
    systemctl is-enabled --quiet "$1"
}

service_reload() {
    local service="$1"
    log_info "Reloading service: $service"
    systemctl reload "$service"
}

service_restart() {
    local service="$1"
    log_info "Restarting service: $service"
    systemctl restart "$service"
}

# ==============================================================================
# Network Utilities
# ==============================================================================

get_current_ssh_ip() {
    # Get the IP from SSH_CONNECTION or SSH_CLIENT
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        echo "${SSH_CONNECTION%% *}"
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        echo "${SSH_CLIENT%% *}"
    else
        echo ""
    fi
}

get_ssh_port() {
    # Effective SSH port. Prefer `sshd -T` because it resolves both
    # Include directives and the /etc/ssh/sshd_config.d/ drop-in
    # directory the way sshd actually loads them; on Debian 12+ a
    # cloud-init drop-in commonly overrides Port=, and grepping only
    # the main sshd_config produces a stale answer (downstream callers
    # in fail2ban / ufw then whitelist the wrong port).
    local port=""
    if command -v sshd &>/dev/null; then
        # sshd -T outputs lowercase directives, one per line.
        port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
    fi
    if [[ -z "$port" ]]; then
        # Fallback when sshd -T is unavailable (no openssh-server, or
        # config syntax error): scan main file plus drop-ins, taking
        # the last occurrence (sshd uses first-wins across the merged
        # file, but for the fallback we accept the simpler last-wins
        # since the common case is a single Port= line anywhere).
        port=$(grep -hE "^[[:space:]]*Port[[:space:]]+" \
            /etc/ssh/sshd_config \
            /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
            tail -1 | awk '{print $2}')
    fi
    echo "${port:-22}"
}

get_listening_ports() {
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -oE '[0-9]+$' | sort -nu
}

check_port_open() {
    local port="$1"
    ss -tln | grep -q ":${port}\s"
}

# ==============================================================================
# Counting helpers
# ==============================================================================

# Count lines in $1, or lines matching pattern $2 if given.
#
# Replaces the repeated idiom
#     n=$(echo "$x" | grep -c . 2>/dev/null || echo 0)
# which was broken for empty input: `grep -c .` prints "0" and exits 1
# when there are zero matches, so the `|| echo 0` fallback ran too and
# appended a SECOND "0", yielding the literal two-line string "0\n0".
# Bash arithmetic (`(( n > 0 ))`) then aborted with "syntax error in
# expression" and, under `set -e`, killed the audit mid-scan.
count_lines() {
    local input="$1"
    local pattern="${2:-.}"
    [[ -z "$input" ]] && { echo 0; return 0; }
    local n
    n=$(printf '%s\n' "$input" | grep -c -- "$pattern" 2>/dev/null) || n=0
    # grep -c always prints an integer, but be defensive in case the
    # pipeline above fails for an unrelated reason.
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}

# Count the public keys in an authorized_keys file.
#
# A "key" is a non-comment, non-blank line whose key-type token (ssh-*,
# ecdsa-*, sk-* for FIDO) appears at the start of the line or after the
# optional options prefix (e.g. `from="..." ssh-ed25519 AAAA...`). Comment
# lines (leading `#`, INCLUDING a rotated-out `# ssh-ed25519 ...`) are skipped
# so a commented-out key is never counted as usable — the inline grep that
# ssh.sh and users.sh used previously matched `# ssh-...` (the `#`-then-space
# let `[[:space:]]ssh-` hit) and could report a key when only a comment
# remained, risking a password-auth lockout / a false audit. awk (not
# `grep -c ... || echo 0`) avoids the "0\n0" zero-match pitfall noted above.
count_authorized_keys() {
    local file="$1"
    [[ -f "$file" ]] || { echo 0; return 0; }
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /(^|[[:space:]])(ssh-|ecdsa-|sk-)/ { c++ }
        END { print c + 0 }
    ' "$file" 2>/dev/null || echo 0
}

# ==============================================================================
# JSON Utilities
# ==============================================================================

# Create a check result JSON.
#
# Uses jq (already a hard dependency) to serialise, so every JSON control
# character including \r, \b, \f and the full U+0000..U+001F range is
# escaped correctly. A hand-rolled `json_escape` helper used to live here
# too, but after JSON-R1 migrated every producer to this function and
# `jq -n --arg`, it had zero callers — removed to avoid re-introducing a
# weaker escape path by accident.
create_check_json() {
    local id="$1"
    local module="$2"
    local severity="$3"
    local status="$4"
    local title="$5"
    local desc="${6:-}"
    local suggestion="${7:-}"
    local fix_id="${8:-}"

    # `module` became a reserved word in jq 1.7.0 (the modules feature),
    # and a stock Linux 1.7.0 build (Debian trixie, Ubuntu 24.04+)
    # rejects BOTH:
    #   - unquoted shorthand keys      `{module: ...}`
    #   - variables named `$module`    via `--arg module ...`
    # The macOS/Apple jq build is more permissive and accepts both, so
    # this only blew up in production. Fix is twofold: quote every JSON
    # key as a string (defense in depth against future jq keywords),
    # AND rename the bash-side `--arg module` to `--arg mod` so the
    # injected jq variable is `$mod`, not `$module`.
    jq -n \
        --arg id        "$id" \
        --arg mod       "$module" \
        --arg severity  "$severity" \
        --arg status    "$status" \
        --arg title     "$title" \
        --arg desc      "$desc" \
        --arg suggestion "$suggestion" \
        --arg fix_id    "$fix_id" \
        '{"id": $id, "module": $mod, "severity": $severity, "status": $status,
          "title": $title, "desc": $desc, "suggestion": $suggestion, "fix_id": $fix_id}'
}

# ==============================================================================
# User Interaction
# ==============================================================================

confirm() {
    local prompt="$1"
    local default="${2:-n}"

    if [[ "${VPSSEC_YES}" == "1" ]]; then
        return 0
    fi

    local yn
    local prompt_text
    if [[ "$default" == "y" ]]; then
        prompt_text="$prompt [Y/n] > "
    else
        prompt_text="$prompt [y/N] > "
    fi

    # Always print prompt first (works even if tty read fails)
    echo -n "$prompt_text"

    # Read from /dev/tty to handle curl|bash piped execution
    if ! read -r yn </dev/tty 2>/dev/null; then
        echo ""  # Newline after failed read
        yn="$default"
    fi
    yn="${yn:-$default}"

    [[ "${yn,,}" == "y" || "${yn,,}" == "yes" ]]
}

# Strict confirm for critical operations (never auto-yes)
confirm_critical() {
    local prompt="$1"
    local yn

    print_warn "$(i18n 'common.warning'): $prompt"

    # Always print prompt first
    echo -n "$(i18n 'common.confirm') [yes/NO] > "

    # For critical operations, we MUST get user confirmation
    # If /dev/tty is not available, return failure (do not proceed)
    if ! read -r yn </dev/tty 2>/dev/null; then
        echo ""
        print_error "$(i18n 'error.cannot_read_critical')"
        return 1
    fi

    [[ "${yn,,}" == "yes" ]]
}

# ==============================================================================
# Filesystem-walk Helpers (shared across modules)
# ==============================================================================

# Paths to prune from filesystem-walk scans.
#
# `find -xdev` already skips anything not on the root filesystem, so
# kernel/proc/sys/run/snap-squashfs mounts are handled automatically.
# This list is for trees that DO live on the root filesystem but would
# either swamp the audit with container-image content or take so long
# to traverse that the run hangs:
#   - /var/lib/docker        : overlay2/<sha>/diff/* contains thousands
#                              of files inherited from Docker images,
#                              including legitimate-inside-the-image
#                              SUID binaries that would be flagged as
#                              host-level anomalies
#   - /var/lib/containerd    : same as above, for containerd
#   - /var/lib/containers    : podman / buildah image storage
#   - /var/lib/lxd           : LXD container rootfs cache
#   - /var/lib/lxcfs         : LXC fuse layer
#   - /var/lib/snapd         : snap state + image cache (huge)
#   - /snap                  : snap mount point (squashfs is on its
#                              own fs and -xdev skips, but if root is
#                              a single fs the directory entries
#                              themselves can confuse find on some
#                              kernels — prune defensively)
declare -ga _FS_PRUNE_PATHS=(
    /var/lib/docker
    /var/lib/containerd
    /var/lib/containers
    /var/lib/lxd
    /var/lib/lxcfs
    /var/lib/snapd
    /snap
)

# Hard timeout for any single filesystem walk. Defaults to 60 seconds;
# operators with very large filesystems can override at audit time:
#     VPSSEC_FS_TIMEOUT=300 sudo ./vpssec audit
# A scan that hits the timeout returns whatever output it has gathered
# so far; the audit continues and a warning is logged. Better to
# report partial findings than to hang an audit indefinitely.
_FS_FIND_TIMEOUT="${VPSSEC_FS_TIMEOUT:-60}"

# Build the prune-args portion of a find expression from
# _FS_PRUNE_PATHS. Each path becomes `-path P -prune -o`. Caller
# concatenates the result before its `-type ... -print0` portion:
#
#     local prune_args=()
#     _fs_build_prune_args prune_args
#     find / -xdev "${prune_args[@]}" -type f -perm -4000 -print0 ...
#
# The single source of truth (the array above) keeps every walking
# helper from drifting out of sync — three filesystem.sh scans used to
# omit container prunes entirely, so world-writable / no-owner walks
# flagged Docker image content as host findings.
_fs_build_prune_args() {
    local -n _out=$1
    _out=()
    local p
    for p in "${_FS_PRUNE_PATHS[@]}"; do
        _out+=( -path "$p" -prune -o )
    done
}

# Run a find invocation under a hard timeout. Output is forwarded to
# stdout (so callers can wire it into a process substitution feeding
# `while read`). On timeout (exit 124) we log a warning but return 0
# so the audit doesn't bail; partial output already reached the
# consumer. Caller is responsible for the rest of the find arguments.
#
# `timeout` is part of GNU coreutils, present by default on every
# supported distro (Debian/Ubuntu/RHEL/Rocky/Alma). The graceful
# fallback below is for niche environments — minimal containers,
# macOS dev shells running tests — where coreutils may be absent;
# the audit still runs, just without the safety net.
_fs_run_find() {
    local label="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$_FS_FIND_TIMEOUT" "$@"
        local rc=$?
        if (( rc == 124 )); then
            log_warn "filesystem scan '${label}' timed out after ${_FS_FIND_TIMEOUT}s; results truncated. Set VPSSEC_FS_TIMEOUT=N to extend."
        fi
    else
        log_debug "timeout(1) unavailable; running '${label}' scan without time bound"
        "$@"
    fi
    return 0
}

# ==============================================================================
# Initialization
# ==============================================================================

# Language selection menu (called before i18n is loaded)
select_language() {
    # Skip if already specified via --lang or environment
    if [[ -n "${VPSSEC_LANG_SET:-}" ]]; then
        return 0
    fi

    # Check if we can read from terminal (handle curl|bash piped execution)
    if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
        # No terminal available, use default
        return 0
    fi

    echo ""
    echo "┌─────────────────────────────────────────┐"
    echo "│     vpssec - VPS Security Audit         │"
    echo "├─────────────────────────────────────────┤"
    echo "│  Select language / 选择语言:            │"
    echo "│                                         │"
    echo "│  [1] English                            │"
    echo "│  [2] 简体中文                           │"
    echo "│                                         │"
    echo "└─────────────────────────────────────────┘"
    echo ""

    local choice
    # Always print prompt first
    echo -n "Enter choice / 输入选项 [1-2] (default: 2) > "

    # Read from /dev/tty to handle curl|bash piped execution
    if ! read -r choice </dev/tty 2>/dev/null; then
        echo ""
        choice="2"  # Default to Chinese
    fi

    case "${choice:-2}" in
        1)
            VPSSEC_LANG="en_US"
            ;;
        2|*)
            VPSSEC_LANG="zh_CN"
            ;;
    esac

    export VPSSEC_LANG
    export VPSSEC_LANG_SET=1
}

# Mode selection menu (called before i18n is loaded)
# Returns: sets VPSSEC_MODE global variable
select_mode() {
    # Skip if already specified via command line
    if [[ -n "${VPSSEC_MODE_SET:-}" ]]; then
        return 0
    fi

    # Check if we can read from terminal
    if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
        # No terminal available, use default (audit)
        VPSSEC_MODE="audit"
        export VPSSEC_MODE
        return 0
    fi

    # Bilingual mode selection
    local title_en="Select mode"
    local title_zh="选择模式"
    local audit_en="Security Audit (read-only scan)"
    local audit_zh="安全审计 (只读扫描)"
    local guide_en="Hardening Guide (interactive fix)"
    local guide_zh="加固向导 (交互式修复)"

    if [[ "${VPSSEC_LANG:-zh_CN}" == "en_US" ]]; then
        echo ""
        echo "┌─────────────────────────────────────────┐"
        echo "│  ${title_en}:                              │"
        echo "│                                         │"
        echo "│  [1] ${audit_en}      │"
        echo "│  [2] ${guide_en}    │"
        echo "│                                         │"
        echo "└─────────────────────────────────────────┘"
    else
        echo ""
        echo "┌─────────────────────────────────────────┐"
        echo "│  ${title_zh}:                              │"
        echo "│                                         │"
        echo "│  [1] ${audit_zh}                  │"
        echo "│  [2] ${guide_zh}              │"
        echo "│                                         │"
        echo "└─────────────────────────────────────────┘"
    fi
    echo ""

    local choice
    local prompt_en="Enter choice [1-2] (default: 1) > "
    local prompt_zh="输入选择 [1-2] (默认: 1) > "

    # Always print prompt first
    if [[ "${VPSSEC_LANG:-zh_CN}" == "en_US" ]]; then
        echo -n "$prompt_en"
    else
        echo -n "$prompt_zh"
    fi

    # Read from /dev/tty, fall back to default if read fails
    if ! read -r choice </dev/tty 2>/dev/null; then
        echo ""
        choice="1"  # Default to audit
    fi

    case "${choice:-1}" in
        2)
            VPSSEC_MODE="guide"
            ;;
        1|*)
            VPSSEC_MODE="audit"
            ;;
    esac

    export VPSSEC_MODE
    export VPSSEC_MODE_SET=1
}

# Module selection menu
# Returns: sets VPSSEC_INCLUDE global variable
select_modules() {
    # Skip if already specified via command line
    if [[ -n "${VPSSEC_INCLUDE:-}" ]]; then
        return 0
    fi

    # Check if we can read from terminal
    if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
        # No terminal available, run all modules
        VPSSEC_INCLUDE=""
        export VPSSEC_INCLUDE
        return 0
    fi

    # Module categories with descriptions
    # Format: category_id:en_name:zh_name:modules
    local -a categories=(
        "access:Access Control:访问控制:users,ssh"
        "network:Network Security:网络安全:ufw,fail2ban"
        "system:System Hardening:系统加固:update,kernel,filesystem,baseline"
        "services:Service Security:服务安全:docker,nginx,cloudflared,webapp"
        "security:Security Scanning:安全扫描:malware"
        "ops:Operations:运维合规:logging,backup,alerts"
    )

    local is_en=0
    [[ "${VPSSEC_LANG:-zh_CN}" == "en_US" ]] && is_en=1

    echo ""
    if [[ $is_en -eq 1 ]]; then
        echo "┌──────────────────────────────────────────────────────────┐"
        echo "│  Select modules to check:                                │"
        echo "│                                                          │"
        echo "│  [0] All modules (recommended)                           │"
    else
        echo "┌──────────────────────────────────────────────────────────┐"
        echo "│  选择要检查的模块:                                       │"
        echo "│                                                          │"
        echo "│  [0] 全部模块 (推荐)                                     │"
    fi

    local idx=1
    for cat in "${categories[@]}"; do
        IFS=':' read -r cat_id en_name zh_name modules <<< "$cat"
        if [[ $is_en -eq 1 ]]; then
            printf "│  [%d] %-20s %-34s│\n" "$idx" "$en_name" "($modules)"
        else
            printf "│  [%d] %-18s %-36s│\n" "$idx" "$zh_name" "($modules)"
        fi
        ((idx++))
    done

    echo "│                                                          │"
    echo "└──────────────────────────────────────────────────────────┘"
    echo ""

    local prompt_en="Enter choices (space-separated, e.g., 1 2 3) [default: 0] > "
    local prompt_zh="输入选择 (空格分隔，如 1 2 3) [默认: 0] > "

    if [[ $is_en -eq 1 ]]; then
        echo -n "$prompt_en"
    else
        echo -n "$prompt_zh"
    fi

    local choice
    if ! read -r choice </dev/tty 2>/dev/null; then
        echo ""
        choice="0"
    fi

    # Default to all modules
    if [[ -z "$choice" || "$choice" == "0" ]]; then
        VPSSEC_INCLUDE=""
        export VPSSEC_INCLUDE
        return 0
    fi

    # Parse selected categories and build module list. Warn on any
    # token outside the valid 1-6 range so users who typed a typo
    # (e.g. "1 9 2") know their input was partially discarded rather
    # than silently dropped.
    local selected_modules=""
    for num in $choice; do
        if [[ "$num" =~ ^[1-6]$ ]]; then
            local cat_idx=$((num - 1))
            IFS=':' read -r _ _ _ modules <<< "${categories[$cat_idx]}"
            if [[ -n "$selected_modules" ]]; then
                selected_modules="${selected_modules},${modules}"
            else
                selected_modules="$modules"
            fi
        else
            if [[ $is_en -eq 1 ]]; then
                echo "  [WARN] Ignoring invalid selection: ${num}" >&2
            else
                echo "  [警告] 忽略无效选项：${num}" >&2
            fi
        fi
    done

    # Always include preflight, cloud, timezone for context
    if [[ -n "$selected_modules" ]]; then
        selected_modules="preflight,cloud,timezone,${selected_modules}"
    fi

    VPSSEC_INCLUDE="$selected_modules"
    export VPSSEC_INCLUDE
}

vpssec_init() {
    # Create necessary directories with secure permissions
    mkdir -p "${VPSSEC_STATE}" "${VPSSEC_REPORTS}" "${VPSSEC_BACKUPS}" "${VPSSEC_LOGS}" "${VPSSEC_TEMPLATES}"

    # Set secure permissions on sensitive directories
    chmod 700 "${VPSSEC_STATE}" "${VPSSEC_BACKUPS}"
    chmod 750 "${VPSSEC_REPORTS}" "${VPSSEC_LOGS}"
    chmod 755 "${VPSSEC_TEMPLATES}"

    # Initialize logging
    log_init

    # Load i18n
    i18n_load "${VPSSEC_LANG}"

    # Acquire a single-instance lock for any mutating command. Two
    # concurrent `vpssec audit` runs would race on state/checks.json
    # (state_init truncates it at the start of each run), and
    # `vpssec guide` running alongside could apply fixes from a stale
    # plan. `status` is read-only and is allowed to coexist.
    #
    # The lock is held by fd 200 for the lifetime of the shell; the
    # OS releases it automatically when this process exits, so there
    # is no stale-lock cleanup to worry about. The lock file's
    # contents (the holder PID) are advisory — used only to make the
    # collision message actionable.
    if [[ "${VPSSEC_MODE:-}" != "status" ]]; then
        local _run_lock="${VPSSEC_STATE}/.run.lock"
        # shellcheck disable=SC2093
        exec 200>"$_run_lock"
        if ! flock -n 200; then
            local _other_pid
            _other_pid=$(cat "$_run_lock" 2>/dev/null || true)
            if [[ -n "$_other_pid" ]]; then
                print_error "Another vpssec instance is already running (PID ${_other_pid})."
            else
                print_error "Another vpssec instance is already running."
            fi
            print_msg "If this is wrong (e.g. a previous run was killed), remove ${_run_lock} and retry."
            exit 1
        fi
        # Record our PID for the next caller's diagnostics.
        echo $$ >&200
    fi

    log_info "vpssec initialized (version: ${VPSSEC_VERSION}, lang: ${VPSSEC_LANG})"
}
