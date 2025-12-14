#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core common functions and utilities
# Copyright (c) 2024

set -euo pipefail

# ==============================================================================
# Global Variables
# ==============================================================================

VPSSEC_VERSION="0.1.0"
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

# Runtime state
declare -A VPSSEC_I18N=()
declare -a VPSSEC_CHECKS=()
declare -a VPSSEC_FIXES=()

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
    local line=$(printf '%*s' "$width" | tr ' ' '─')
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
            [[ "$version" == "22.04" || "$version" == "24.04" ]]
            ;;
        *)
            return 1
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

        if [[ "$resolved_path" != "$resolved_base"* ]]; then
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
    local port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
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
# JSON Utilities
# ==============================================================================

json_escape() {
    local text="$1"
    # Escape special characters for JSON
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\n'/\\n}"
    text="${text//$'\t'/\\t}"
    echo "$text"
}

# Create a check result JSON
create_check_json() {
    local id="$1"
    local module="$2"
    local severity="$3"
    local status="$4"
    local title="$5"
    local desc="${6:-}"
    local suggestion="${7:-}"
    local fix_id="${8:-}"

    cat <<EOF
{
  "id": "$(json_escape "$id")",
  "module": "$(json_escape "$module")",
  "severity": "$(json_escape "$severity")",
  "status": "$(json_escape "$status")",
  "title": "$(json_escape "$title")",
  "desc": "$(json_escape "$desc")",
  "suggestion": "$(json_escape "$suggestion")",
  "fix_id": "$(json_escape "$fix_id")"
}
EOF
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

    log_info "vpssec initialized (version: ${VPSSEC_VERSION}, lang: ${VPSSEC_LANG})"
}
