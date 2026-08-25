#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core common functions and utilities
# Copyright (c) 2024

set -euo pipefail

# --- Global Variables ---

VPSSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# VERSION is the only source of the version string; release.yml refuses a tag
# that disagrees with it. Guard with -r: the shell reports a failed `<`
# redirection itself, so `2>/dev/null` on the substitution would not catch it.
VPSSEC_VERSION=""
if [[ -r "${VPSSEC_ROOT}/VERSION" ]]; then
    VPSSEC_VERSION="$(tr -d '[:space:]' < "${VPSSEC_ROOT}/VERSION")"
fi
# Report "unknown" rather than an empty string: a blank version field in a
# report reads as "not applicable" instead of "this file was not shipped".
[[ "$VPSSEC_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || VPSSEC_VERSION="unknown"
VPSSEC_CORE="${VPSSEC_ROOT}/core"
VPSSEC_MODULES="${VPSSEC_ROOT}/modules"
VPSSEC_STATE="${VPSSEC_ROOT}/state"
VPSSEC_REPORTS="${VPSSEC_ROOT}/reports"
VPSSEC_BACKUPS="${VPSSEC_ROOT}/backups"
# Set by backup_create_session for the duration of a plan, so every backup_file
# call lands in one directory. Empty = standalone per-call timestamped backups.
VPSSEC_BACKUP_SESSION=""
VPSSEC_LOGS="${VPSSEC_ROOT}/logs"
VPSSEC_TEMPLATES="${VPSSEC_ROOT}/templates"
# Upstream identity, used only to look up the newest release tag.
VPSSEC_REPO="${VPSSEC_REPO:-Lynthar/CloudServer-Audit}"

# Default settings
VPSSEC_LANG="${VPSSEC_LANG:-zh_CN}"
VPSSEC_COLOR="${VPSSEC_COLOR:-1}"
VPSSEC_JSON_ONLY="${VPSSEC_JSON_ONLY:-0}"
VPSSEC_YES="${VPSSEC_YES:-0}"
VPSSEC_DEBUG="${VPSSEC_DEBUG:-0}"
VPSSEC_QUIET_SCAN="${VPSSEC_QUIET_SCAN:-0}"  # Suppress detailed output during scanning

# -g keeps these global when common.sh is sourced from inside a function
# (bats helpers); a no-op on the top-level production load path.
declare -gA VPSSEC_I18N=()
declare -ga VPSSEC_CHECKS=()
declare -ga VPSSEC_FIXES=()

# Lazily filled by the getters below, which delegate to cloud.sh's
# _detect_cloud_provider when loaded and return "unknown" when it is not.
# Any module may call them regardless of module load order.
declare -g VPSSEC_CLOUD_PROVIDER=""
declare -g VPSSEC_CLOUD_TIER=""

# One of: aws azure gcp alibaba tencent huawei oracle digitalocean
# vultr linode hetzner ovh scaleway unknown
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

# Coarse tier for modules that vary on "what kind of cloud", not which vendor:
# tier1 = IAM credentials in IMDS, tier2 = link-local IMDS without them,
# unknown = no network IMDS. Membership and rationale: see the design notes.
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

# Scan for known-format credentials. Shared by cloud.sh and docker.sh.
# Emits "<kind>(<n>) ..." — kinds and counts only, NEVER matched values.
# Generic PASSWORD=/SECRET= markers are deliberately not matched.
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

    # GitHub fine-grained PAT (2022+): github_pat_<base62>_<base62>, a distinct
    # prefix the classic gh[posu]_ pattern above does not cover.
    n=$(grep -cE 'github_pat_[A-Za-z0-9_]{22,}' <<<"$content" 2>/dev/null) || n=0
    (( n > 0 )) && found+=("github_pat(x$n)")

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

# --- Color and Formatting ---

# NO_COLOR (no-color.org) and TERM=dumb both force the plain palette,
# with the same effect as --no-color.
if [[ -n "${NO_COLOR:-}" || "${TERM:-}" == "dumb" ]]; then
    VPSSEC_COLOR=0
fi
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

# --- Logging Functions ---

_log_file="${VPSSEC_LOGS}/vpssec.log"

log_init() {
    mkdir -p "${VPSSEC_LOGS}"
    echo "=== vpssec session started at $(date -Iseconds) ===" >> "${_log_file}"
}

# 2>/dev/null comes FIRST in every redirect list below: bash applies them
# left to right, so the other order leaks the append error to the caller.
log_debug() {
    if [[ "${VPSSEC_DEBUG:-0}" == "1" ]]; then
        echo "[DEBUG] $(date -Iseconds) $*" 2>/dev/null >> "${_log_file}" || true
    fi
}

log_info() {
    echo "[INFO] $(date -Iseconds) $*" 2>/dev/null >> "${_log_file}" || true
}

log_warn() {
    echo "[WARN] $(date -Iseconds) $*" 2>/dev/null >> "${_log_file}" || true
}

log_error() {
    echo "[ERROR] $(date -Iseconds) $*" 2>/dev/null >> "${_log_file}" || true
}

# --- Output Functions ---

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
    # printf, not `tr ' ' '─'`: tr is byte-oriented and mangles the
    # multi-byte char on some coreutils builds. `─%.0s` prints once per arg.
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

    # Same reason as engine.sh's _progress: this writes to stdout with
    # printf (it needs \r and no trailing newline), so it must repeat
    # print_msg's --json-only guard or it corrupts the JSON document.
    [[ "${VPSSEC_JSON_ONLY:-0}" == "1" ]] && return 0

    # total=0 would abort the percentage arithmetic under set -e.
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

# --- Text Width Helpers (terminal cells, CJK-aware) ---

# Strip ANSI codes before measuring width. Pure bash, no sed fork.
# Two forms are stripped: the literal "\033[...m" text (the colour vars are
# single-quoted) and a real ESC byte, in case a caller pre-expanded it.
_strip_ansi() {
    local s="$1"
    s="${s//\\033\[[0-9;]*m/}"
    s="${s//$'\033'\[[0-9;]*m/}"
    printf '%s\n' "$s"
}

# DISPLAY width in terminal cells: CJK forms are 2 cells but one code point,
# so ${#str} is wrong for padding. Decodes UTF-8 in pure bash and applies the
# East_Asian_Width W/F ranges, so the answer holds under any locale.
_display_width() {
    local s="$1"
    s="${s//\\033\[[0-9;]*m/}"
    s="${s//$'\033'\[[0-9;]*m/}"
    [[ -z "$s" ]] && { echo 0; return; }

    # Byte-wise indexing: force the C locale for the ${#s} / ${s:i:1}
    # expansions below. `local` restores the caller's value on return.
    local LC_ALL=C
    local -i n=${#s} i=0 b cp extra w=0 k
    while (( i < n )); do
        printf -v b '%d' "'${s:i:1}"
        (( b < 0 )) && b+=256          # some builds report high bytes signed
        if   (( b < 0x80 )); then cp=$b;              extra=0
        elif (( b < 0xC0 )); then cp=0xFFFD;          extra=0   # stray continuation
        elif (( b < 0xE0 )); then cp=$(( b & 0x1F )); extra=1
        elif (( b < 0xF0 )); then cp=$(( b & 0x0F )); extra=2
        else                      cp=$(( b & 0x07 )); extra=3
        fi
        for (( k=1; k<=extra && i+k<n; k++ )); do
            printf -v b '%d' "'${s:i+k:1}"
            (( b < 0 )) && b+=256
            cp=$(( (cp << 6) | (b & 0x3F) ))
        done
        i=$(( i + extra + 1 ))

        # W/F -> 2 cells, everything else 1. U+2500-U+27BF (─ ✓ ●) is
        # Ambiguous/Narrow and deliberately falls through to 1.
        if (( cp >= 0x1100 && (
                cp <= 0x115F
             || cp == 0x2329 || cp == 0x232A
             || (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F)
             || (cp >= 0xA960 && cp <= 0xA97F)
             || (cp >= 0xAC00 && cp <= 0xD7A3)
             || (cp >= 0xF900 && cp <= 0xFAFF)
             || (cp >= 0xFE10 && cp <= 0xFE19)
             || (cp >= 0xFE30 && cp <= 0xFE6F)
             || (cp >= 0xFF00 && cp <= 0xFF60)
             || (cp >= 0xFFE0 && cp <= 0xFFE6)
             || (cp >= 0x17000 && cp <= 0x18AFF)
             || (cp >= 0x1F300 && cp <= 0x1F64F)
             || (cp >= 0x1F900 && cp <= 0x1F9FF)
             || (cp >= 0x20000 && cp <= 0x3FFFD) ) )); then
            w+=2
        else
            w+=1
        fi
    done
    echo "$w"
}

# Pad $1 with spaces to $2 display cells (no-op if already wider).
pad_to_width() {
    local text="$1"
    local target="$2"
    local -i pad=$(( target - $(_display_width "$text") ))
    if (( pad > 0 )); then
        printf '%s%*s' "$text" "$pad" ''
    else
        printf '%s' "$text"
    fi
}

# Truncate $1 to at most $2 display cells, appending "…" when it had to
# cut. Bash slicing is code-point based, so shrink in a loop and
# re-measure rather than computing an index.
truncate_to_width() {
    local text="$1"
    local target="$2"
    if (( $(_display_width "$text") <= target )); then
        printf '%s' "$text"
        return
    fi
    while [[ -n "$text" ]] && (( $(_display_width "$text") > target - 1 )); do
        text="${text:0:-1}"
    done
    printf '%s…' "$text"
}

# --- Menu Box Drawing: every box renders from one interior width, measured
# in display cells, so CJK labels cannot make a border ragged. ---

_MENU_BOX_WIDTH=70   # interior cells, between the two vertical borders

_menu_box_top()    { printf '┌%s┐\n' "$(printf '─%.0s' $(seq 1 $_MENU_BOX_WIDTH))"; }
_menu_box_bottom() { printf '└%s┘\n' "$(printf '─%.0s' $(seq 1 $_MENU_BOX_WIDTH))"; }
_menu_box_sep()    { printf '├%s┤\n' "$(printf '─%.0s' $(seq 1 $_MENU_BOX_WIDTH))"; }
_menu_box_blank()  { printf '│%*s│\n' "$_MENU_BOX_WIDTH" ''; }

# One content row, indented two cells and padded to the interior width.
_menu_box_row() {
    printf '│%s│\n' "$(pad_to_width "  $1" "$_MENU_BOX_WIDTH")"
}

# --- i18n Functions ---

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

# Newest release tag, or empty. Never fails the caller and never blocks long:
# a status command that errors because GitHub is unreachable is worse than one
# that says nothing about updates.
_vpssec_latest_release_tag() {
    command -v curl &>/dev/null || return 0
    command -v jq &>/dev/null || return 0
    curl -fsSL --connect-timeout 3 --max-time 5 \
        "https://api.github.com/repos/${VPSSEC_REPO}/releases/latest" 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true
}

# True when $2 is strictly newer than $1 under version sort. Returns false
# rather than guessing when `sort -V` is unavailable — a wrong "update
# available" is worse than a missing one.
_vpssec_version_lt() {
    [[ "$1" != "$2" ]] || return 1
    printf '%s\n' 1.0.0 1.0.1 | sort -V >/dev/null 2>&1 || return 1
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]
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

# --- System Detection Functions ---

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
            # Audit is distro-aware here; fixes are NOT ported.
            # guide_mode gates on is_debian_based() separately.
            case "${VPSSEC_DISTRO_FAMILY:-unknown}" in
                rhel)
                    local major="${version%%.*}"
                    [[ "$major" == "8" || "$major" == "9" || "$major" == "10" ]]
                    ;;
                arch)
                    return 0
                    ;;
                debian)
                    # Derivatives (Mint, Pop!_OS, Kali, Armbian, Raspbian).
                    # No version test: they number their own releases.
                    # Does NOT widen fix mode — is_debian_based() stays an allowlist.
                    return 0
                    ;;
                *)
                    return 1
                    ;;
            esac
            ;;
    esac
}

# --- Dependency Check Functions ---

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

# --- Input Validation Functions ---

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

        # Must BE the base or sit under "base/". A bare prefix match would
        # accept a sibling like /a/backups-evil for base /a/backups.
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

# Feeds security-relevant sinks (ufw source scoping for the SSH rescue rule),
# so it validates structure, not just shape.
validate_ip() {
    local ip="$1"

    # IPv4: four dot-separated octets, each 0-255.
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        local octet
        for octet in "${BASH_REMATCH[@]:1}"; do
            # 10# guards against leading zeros being read as octal.
            (( 10#$octet <= 255 )) || return 1
        done
        return 0
    fi

    # Hex groups of 1-4 digits, at most one '::', group count consistent with
    # 128 bits. Zone IDs and embedded IPv4 tails are deliberately rejected —
    # every caller feeds this to a firewall rule that wants the plain form.
    if [[ "$ip" == *:* && "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
        [[ "$ip" == *":::"* ]] && return 1
        local compressed="${ip//::/}"
        local double_colons=$(( (${#ip} - ${#compressed}) / 2 ))
        (( double_colons > 1 )) && return 1

        # Count hex groups (split on ':', ignore empties from '::').
        local -a parts
        IFS=':' read -ra parts <<<"$ip"
        local groups=0 part
        for part in "${parts[@]}"; do
            [[ -z "$part" ]] && continue
            [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
            ((groups++))
        done
        if (( double_colons == 1 )); then
            (( groups >= 1 && groups <= 7 )) && return 0
        else
            # No '::' — must be the full 8 groups, and no stray edge colon.
            [[ "$ip" != :* && "$ip" != *: ]] || return 1
            (( groups == 8 )) && return 0
        fi
        return 1
    fi

    return 1
}

# --- File Operations (Safe) ---

# Per-session manifest of files a fix CREATED. backup_restore deletes the
# listed paths on rollback and excludes this file from the restore walk.
VPSSEC_CREATED_MANIFEST=".vpssec_created"

# Per-directory manifest of each backed-up file's ORIGINAL mode, one
# "<mode> <path>" per line. Needed because backup_file chmods its copy to 600
# and cp -p would otherwise restore that mode (see the design notes).
VPSSEC_MODES_MANIFEST=".vpssec_modes"

# True if $1 already has a mode recorded in manifest $2. Compared with
# grep -qxF on the path column: /etc paths can contain regex metacharacters.
_backup_mode_recorded() {
    local path="$1" manifest="$2"
    [[ -f "$manifest" ]] || return 1
    cut -d' ' -f2- "$manifest" 2>/dev/null | grep -qxF "$path"
}

# Record $1's current mode into backup directory $2, once. First write wins:
# it must describe the pre-plan state, not a fix's own intermediate.
backup_track_mode() {
    local path="$1" backup_dir="$2"
    [[ -n "$backup_dir" ]] || return 0
    local manifest="${backup_dir}/${VPSSEC_MODES_MANIFEST}"
    _backup_mode_recorded "$path" "$manifest" && return 0

    local mode
    mode=$(stat -c '%a' "$path" 2>/dev/null) || return 0
    [[ "$mode" =~ ^[0-7]+$ ]] || return 0

    printf '%s %s\n' "$mode" "$path" >> "$manifest" || return 0
    chmod 600 "$manifest" 2>/dev/null || true
}

# True if $1 is already recorded as created this session.
backup_is_tracked_created() {
    local path="$1"
    [[ -n "${VPSSEC_BACKUP_SESSION:-}" ]] || return 1
    local manifest="${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}"
    [[ -f "$manifest" ]] && grep -qxF "$path" "$manifest" 2>/dev/null
}

# Record that a fix is about to CREATE $path, so rollback DELETES it.
# No-op outside a plan backup session. Without this a first-run drop-in has
# no backup entry at all and survives the rollback.
backup_track_created() {
    local path="$1"
    [[ -n "${VPSSEC_BACKUP_SESSION:-}" ]] || return 0
    validate_path "$path" || return 1
    mkdir -p "$VPSSEC_BACKUP_SESSION" 2>/dev/null || true
    chmod 700 "$VPSSEC_BACKUP_SESSION" 2>/dev/null || true
    if ! backup_is_tracked_created "$path"; then
        # Checked: this manifest is the only thing that lets a rollback delete
        # the file the caller is about to create, so a failed append must not
        # be reported as a successful registration.
        echo "$path" >> "${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}" 2>/dev/null || return 1
        chmod 600 "${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}" 2>/dev/null || true
    fi
}

backup_file() {
    local file="$1"

    # Every failure below reports on STDERR: stdout carries the backup path,
    # so a message written there would be captured by `bak=$(backup_file ...)`
    # instead of reaching the operator.
    if ! validate_path "$file"; then
        log_error "Invalid path for backup: $file"
        print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
        return 1
    fi

    # Inside a plan session every fix backs up into one directory, so rollback
    # restores the whole plan. Standalone callers get a timestamped one.
    local backup_dir
    if [[ -n "${VPSSEC_BACKUP_SESSION:-}" ]]; then
        backup_dir="$VPSSEC_BACKUP_SESSION"
    else
        local timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        backup_dir="${VPSSEC_BACKUPS}/${timestamp}"
    fi

    # Create backup directory with secure permissions
    if ! mkdir -p "$backup_dir"; then
        log_error "Backup failed (mkdir): $backup_dir"
        print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
        return 1
    fi
    chmod 700 "$backup_dir"

    if [[ -f "$file" ]]; then
        local relative_path="${file#/}"
        local backup_path="${backup_dir}/${relative_path}"

        # Validate the constructed backup path
        if ! validate_path "$backup_path" "$VPSSEC_BACKUPS"; then
            log_error "Unsafe backup path: $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi

        # First write wins within a session: keep the pre-plan original rather
        # than a fix's own intermediate. Standalone callers still overwrite,
        # since each already gets its own timestamped directory.
        if [[ -n "${VPSSEC_BACKUP_SESSION:-}" && -e "$backup_path" ]]; then
            log_info "Backup already present this session, keeping original: $backup_path"
            echo "$backup_path"
            return 0
        fi

        # Already tracked as created this session, so the file is ours: do not
        # snapshot a fix's own half-written output as the "original".
        # Rollback deletes tracked-created files; leave it untouched here.
        if backup_is_tracked_created "$file"; then
            return 0
        fi

        # Before the copy is taken and re-permissioned, so the manifest holds
        # the file's own mode rather than the snapshot's 600.
        backup_track_mode "$file" "$backup_dir"

        # Every step is checked: this runs inside fix bodies where errexit is
        # off, so an unchecked failure would return rc 0 and a path to a
        # snapshot that does not exist.
        if ! mkdir -p "$(dirname "$backup_path")"; then
            log_error "Backup failed (mkdir): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
        if ! cp -p "$file" "$backup_path"; then
            rm -f "$backup_path" 2>/dev/null || true
            log_error "Backup failed (cp): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
        chmod 600 "$backup_path" 2>/dev/null || \
            log_warn "Could not chmod 600 backup copy: $backup_path"
        log_info "Backed up: $file -> $backup_path"
        echo "$backup_path"
    else
        # File does not exist yet: the caller is about to CREATE it. Record it so
        # a rollback can delete it (session only; standalone callers have nothing
        # to roll back to). Echo nothing — there is no backup path.
        if ! backup_track_created "$file"; then
            log_error "Backup failed (created manifest): $file"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
        return 0
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
        # mktemp created the temp as root, so without this the rename would
        # silently re-own a non-root target. Best effort; failure is logged.
        chown --reference="$target" "$temp_file" 2>/dev/null || \
            log_warn "write_file_atomic: could not preserve ownership of $target"
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

# --- Service Operations ---

# --- Network Utilities ---

get_current_ssh_ip() {
    # Get the IP from SSH_CONNECTION or SSH_CLIENT
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        echo "${SSH_CONNECTION%% *}"
        return
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        echo "${SSH_CLIENT%% *}"
        return
    fi

    # sudo's env_reset strips SSH_CONNECTION/SSH_CLIENT, so recover the source
    # from utmp via `who am i` (sudo does not rewrite utmp). Accepted only as an
    # IP literal — a hostname is unusable as a `ufw allow from` source.
    local from
    from=$(LC_ALL=C who am i 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p')
    if [[ -n "$from" ]] && validate_ip "$from" >/dev/null 2>&1; then
        echo "$from"
        return
    fi

    echo ""
}

get_ssh_port() {
    # `sshd -T` first: it resolves Include and the sshd_config.d drop-ins the
    # way sshd loads them, and a cloud-init drop-in commonly overrides Port=.
    local port=""
    if command -v sshd &>/dev/null; then
        # sshd -T outputs lowercase directives, one per line.
        port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
    fi
    if [[ -z "$port" ]]; then
        # Fallback: scan main file plus drop-ins, last occurrence wins.
        # sshd itself is first-wins; the common case is a single Port= line.
        port=$(grep -hE "^[[:space:]]*Port[[:space:]]+" \
            /etc/ssh/sshd_config \
            /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
            tail -1 | awk '{print $2}')
    fi
    echo "${port:-22}"
}

# ALL configured SSH ports, deduped and ascending. Firewall fixes MUST open
# every port this returns — get_ssh_port gives only the first, and a
# default-deny flip would cut off an operator on any other one.
get_ssh_ports() {
    local ports=""
    if command -v sshd &>/dev/null; then
        ports=$(sshd -T 2>/dev/null | awk '/^port /{print $2}')
    fi
    if [[ -z "$ports" ]]; then
        ports=$(grep -hE "^[[:space:]]*Port[[:space:]]+" \
            /etc/ssh/sshd_config \
            /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}')
    fi
    [[ -z "$ports" ]] && ports=22
    # $ports is newline-separated (awk print per Port line); quoting keeps that
    # exact output while satisfying shellcheck SC2086.
    printf '%s\n' "$ports" | sort -nu
}

get_listening_ports() {
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -oE '[0-9]+$' | sort -nu
}

# --- Counting helpers ---

# Count lines in $1, or lines matching pattern $2. Use this instead of
# `grep -c . || echo 0`, which yields the two-line string "0\n0" on empty
# input and then aborts bash arithmetic under set -e.
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

# Count usable public keys: a non-comment, non-blank line whose key-type token
# starts the line or follows an options prefix. Commented-out keys must never
# count — reporting one that is not usable risks a password-auth lockout.
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

# --- JSON Utilities ---

# Create a check result JSON. Serialised by jq so the full U+0000..U+001F
# range is escaped correctly; do not hand-roll an escape path here.
create_check_json() {
    local id="$1"
    local module="$2"
    local severity="$3"
    local status="$4"
    local title="$5"
    local desc="${6:-}"
    local suggestion="${7:-}"
    local fix_id="${8:-}"

    # `module` is a reserved word in jq 1.7.0+, so every JSON key is quoted
    # and the bash-side arg is named `mod`. Keep both: stock Linux jq rejects
    # `{module: ...}` and `--arg module` while the macOS build accepts them.
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

# --- User Interaction ---

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
    if ! read -r yn 2>/dev/null </dev/tty; then
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
    if ! read -r yn 2>/dev/null </dev/tty; then
        echo ""
        print_error "$(i18n 'error.cannot_read_critical')"
        return 1
    fi

    [[ "${yn,,}" == "yes" ]]
}

# --- Filesystem-walk Helpers (shared across modules) ---

# Container and snap trees to prune from filesystem walks. They live on the
# root filesystem, so -xdev does not skip them, and their image content would
# be reported as host-level findings. Per-path notes: see the design notes.
declare -ga _FS_PRUNE_PATHS=(
    /var/lib/docker
    /var/lib/containerd
    /var/lib/containers
    /var/lib/lxd
    /var/lib/lxcfs
    /var/lib/snapd
    /snap
)

# Hard timeout per filesystem walk; override with VPSSEC_FS_TIMEOUT=<seconds>.
# A timed-out scan returns its partial output and logs a warning.
_FS_FIND_TIMEOUT="${VPSSEC_FS_TIMEOUT:-60}"

# Build `-path P -prune -o` args from _FS_PRUNE_PATHS into the named array.
# Every filesystem walk MUST go through this, or it will report container
# image content as host findings.
_fs_build_prune_args() {
    local -n _out=$1
    _out=()
    local p
    for p in "${_FS_PRUNE_PATHS[@]}"; do
        _out+=( -path "$p" -prune -o )
    done
}

# Run find under a hard timeout, forwarding output to stdout. Timeout (124)
# logs a warning and returns 0 so the audit continues on partial output.
# The no-timeout fallback is for environments without GNU coreutils.
_fs_run_find() {
    local label="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        # `|| rc=$?` makes this a tested expression: errexit is active in the
        # process-substitution subshell, so a bare failing timeout would abort
        # before the warning could log.
        local rc=0
        timeout "$_FS_FIND_TIMEOUT" "$@" || rc=$?
        if (( rc == 124 )); then
            log_warn "filesystem scan '${label}' timed out after ${_FS_FIND_TIMEOUT}s; results truncated. Set VPSSEC_FS_TIMEOUT=N to extend."
        fi
    else
        log_debug "timeout(1) unavailable; running '${label}' scan without time bound"
        "$@"
    fi
    return 0
}

# --- Initialization ---

# True when this process can actually read an interactive answer. Probes a
# real open: under cron or a systemd unit /dev/tty exists but open(2) fails
# with ENXIO, so testing for the device node answers the wrong question.
_tty_readable() {
    [[ -t 0 ]] && return 0
    (exec 3</dev/tty) 2>/dev/null
}

# True when the caller asked for a non-interactive run. --yes and --json-only
# both count: on a real TTY they must still skip the menus and take the
# documented defaults, not just when no terminal exists.
_noninteractive() {
    [[ "${VPSSEC_YES:-0}" == "1" || "${VPSSEC_JSON_ONLY:-0}" == "1" ]]
}

# Language selection menu (called before i18n is loaded)
select_language() {
    # Skip if already specified via --lang or environment
    if [[ -n "${VPSSEC_LANG_SET:-}" ]]; then
        return 0
    fi

    # Non-interactive run, or no terminal to read from: keep the default.
    if _noninteractive || ! _tty_readable; then
        return 0
    fi

    echo ""
    _menu_box_top
    _menu_box_row "  vpssec - VPS Security Audit"
    _menu_box_sep
    _menu_box_row "Select language / 选择语言:"
    _menu_box_blank
    _menu_box_row "[1] English"
    _menu_box_row "[2] 简体中文"
    _menu_box_blank
    _menu_box_bottom
    echo ""

    local choice
    # Always print prompt first
    echo -n "Enter choice / 输入选项 [1-2] (default: 2) > "

    # Read from /dev/tty to handle curl|bash piped execution
    if ! read -r choice 2>/dev/null </dev/tty; then
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

    # Non-interactive run, or no terminal to read from: default to the
    # read-only audit. Never silently escalate to `guide`, which mutates.
    if _noninteractive || ! _tty_readable; then
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

    local title audit_label guide_label
    if [[ "${VPSSEC_LANG:-zh_CN}" == "en_US" ]]; then
        title="$title_en"; audit_label="$audit_en"; guide_label="$guide_en"
    else
        title="$title_zh"; audit_label="$audit_zh"; guide_label="$guide_zh"
    fi

    echo ""
    _menu_box_top
    _menu_box_row "${title}:"
    _menu_box_blank
    _menu_box_row "[1] ${audit_label}"
    _menu_box_row "[2] ${guide_label}"
    _menu_box_blank
    _menu_box_bottom
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
    if ! read -r choice 2>/dev/null </dev/tty; then
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

    # Non-interactive run, or no terminal to read from: run all modules.
    if _noninteractive || ! _tty_readable; then
        VPSSEC_INCLUDE=""
        export VPSSEC_INCLUDE
        return 0
    fi

    # Format: category_id:en_name:zh_name:modules
    # Every selectable module must appear in exactly ONE category or it is
    # unreachable from this menu. preflight is excluded: it always runs.
    local -a categories=(
        "access:Access Control:访问控制:users,ssh"
        "network:Network Security:网络安全:ufw,fail2ban,networking"
        "system:System Hardening:系统加固:update,kernel,filesystem,baseline"
        "services:Service Security:服务安全:docker,nginx,cloudflared,webapp"
        "security:Security Scanning:安全扫描:malware,cloud"
        "ops:Operations:运维合规:logging,backup,alerts,scheduling,timezone"
    )

    local is_en=0
    [[ "${VPSSEC_LANG:-zh_CN}" == "en_US" ]] && is_en=1

    # "[N] " + name + module columns, all measured in DISPLAY cells.
    # printf "%-18s" counts bytes and mispads every CJK row.
    local name_w=18
    [[ $is_en -eq 1 ]] && name_w=20
    local mods_w=$(( _MENU_BOX_WIDTH - 2 - 4 - name_w ))

    echo ""
    _menu_box_top
    if [[ $is_en -eq 1 ]]; then
        _menu_box_row "Select modules to check:"
        _menu_box_blank
        _menu_box_row "[0] All modules (recommended)"
    else
        _menu_box_row "选择要检查的模块:"
        _menu_box_blank
        _menu_box_row "[0] 全部模块 (推荐)"
    fi

    local idx=1
    for cat in "${categories[@]}"; do
        IFS=':' read -r cat_id en_name zh_name modules <<< "$cat"
        local label
        if [[ $is_en -eq 1 ]]; then
            label="$en_name"
        else
            label="$zh_name"
        fi
        _menu_box_row "[${idx}] $(pad_to_width "$label" "$name_w")$(truncate_to_width "($modules)" "$mods_w")"
        ((idx++))
    done

    _menu_box_blank
    _menu_box_bottom
    echo ""

    local prompt_en="Enter choices (space-separated, e.g., 1 2 3) [default: 0] > "
    local prompt_zh="输入选择 (空格分隔，如 1 2 3) [默认: 0] > "

    if [[ $is_en -eq 1 ]]; then
        echo -n "$prompt_en"
    else
        echo -n "$prompt_zh"
    fi

    local choice
    if ! read -r choice 2>/dev/null </dev/tty; then
        echo ""
        choice="0"
    fi

    # Default to all modules
    if [[ -z "$choice" || "$choice" == "0" ]]; then
        VPSSEC_INCLUDE=""
        export VPSSEC_INCLUDE
        return 0
    fi

    # Out-of-range tokens warn rather than being silently dropped.
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
    # status is read-only and documented as not needing root, so it gets a
    # read-only init: i18n only. The mkdir/chmod below would abort under set -e
    # for a non-root user on a root-owned install.
    if [[ "${VPSSEC_MODE:-}" == "status" ]]; then
        i18n_load "${VPSSEC_LANG}"
        log_info "vpssec initialized read-only for status (version: ${VPSSEC_VERSION})"
        return 0
    fi

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

    # Single-instance lock for any mutating command; status may coexist.
    # Held by fd 200 for the life of the shell and released by the OS on exit,
    # so there is no stale-lock cleanup. The stored PID is advisory.
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
            # Never advise removing the lock file: reaching here means a LIVE
            # holder, and a fresh inode would let two mutating runs coexist.
            print_msg "Wait for it to finish, or stop it: kill ${_other_pid:-<pid>}"
            exit 1
        fi
        # Record our PID for the next caller's diagnostics.
        echo $$ >&200
    fi

    log_info "vpssec initialized (version: ${VPSSEC_VERSION}, lang: ${VPSSEC_LANG})"
}
