#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Core common functions and utilities
# Copyright (c) 2024

set -euo pipefail

# ==============================================================================
# Global Variables
# ==============================================================================

VPSSEC_VERSION="1.2.0"
VPSSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VPSSEC_CORE="${VPSSEC_ROOT}/core"
VPSSEC_MODULES="${VPSSEC_ROOT}/modules"
VPSSEC_STATE="${VPSSEC_ROOT}/state"
VPSSEC_REPORTS="${VPSSEC_ROOT}/reports"
VPSSEC_BACKUPS="${VPSSEC_ROOT}/backups"
# Active backup session directory. When non-empty (set by backup_create_session
# at the start of execute_plan), backup_file writes every backup of that plan
# into this one directory so a rollback can restore the whole plan. Empty means
# standalone per-call timestamped backups.
VPSSEC_BACKUP_SESSION=""
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

# ==============================================================================
# Color and Formatting
# ==============================================================================

# Color codes.
# NO_COLOR (https://no-color.org: any non-empty value disables color) and
# TERM=dumb (a terminal that renders escapes as garbage) both force the
# plain palette — same effect as --no-color, no flag needed.
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

# ==============================================================================
# Logging Functions
# ==============================================================================

_log_file="${VPSSEC_LOGS}/vpssec.log"

log_init() {
    mkdir -p "${VPSSEC_LOGS}"
    echo "=== vpssec session started at $(date -Iseconds) ===" >> "${_log_file}"
}

# The 2>/dev/null comes FIRST in each redirect list on purpose: bash
# processes redirections left to right, so with `>> file 2>/dev/null` a
# failing append (log dir missing) prints its "No such file or directory"
# BEFORE stderr is redirected — every log call then leaks a line onto the
# caller's stderr, which run/bats and --json-only consumers see as output.
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

    # Same reason as engine.sh's _progress: this writes to stdout with
    # printf (it needs \r and no trailing newline), so it must repeat
    # print_msg's --json-only guard or it corrupts the JSON document.
    [[ "${VPSSEC_JSON_ONLY:-0}" == "1" ]] && return 0

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
# Text Width Helpers (terminal cells, CJK-aware)
# ==============================================================================

# Strip ANSI escape codes before measuring visible width.
#
# Pure bash — no `echo -e | sed` pipeline. Two reasons: this runs
# several times per rendered line (report_print_details calls it ~3×
# per check via _display_width, so an 89-check audit forked sed
# hundreds of times), and `echo -e` also expanded backslash escapes
# that happened to sit inside a check title, corrupting it.
#
# Two forms are stripped because the colour variables above are LITERAL
# strings (RED='\033[0;31m', single-quoted) that only become real
# escapes when the final `echo -e` prints them:
#   1. the literal "\033[...m" text
#   2. a real ESC byte, in case a caller pre-expanded it
_strip_ansi() {
    local s="$1"
    s="${s//\\033\[[0-9;]*m/}"
    s="${s//$'\033'\[[0-9;]*m/}"
    printf '%s\n' "$s"
}

# DISPLAY width (terminal cells) of a string after stripping ANSI codes.
#
# CJK Han / kana / fullwidth forms render as 2 cells each, but bash
# `${#str}` counts code points: "✓ 操作系统支持" is 8 code points and
# 14 cells. Padding with the wrong number made the report's `│`
# separator zigzag on CJK-heavy rows, and made the module-selection
# menu's right border walk off the box entirely.
#
# Implementation: decode the UTF-8 byte stream in pure bash and apply
# the East_Asian_Width W/F ranges (Markus Kuhn's wcwidth table). No
# subprocess at all.
#
# This replaced a python3 fork per call. The fork was the single
# largest cost in report_print_details, which calls this ~3× per check
# (title measure, truncation loop, column padding) — an 89-check audit
# paid ~250 interpreter startups purely to count columns. It also made
# alignment silently depend on whether python3 happened to be present.
#
# Decoding the bytes ourselves (rather than indexing characters) keeps
# the answer correct regardless of the ambient locale: under LC_ALL=C
# bash would hand back single bytes and every CJK glyph would measure
# 3 instead of 2.
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

        # East_Asian_Width == W or F -> 2 cells, everything else 1.
        # U+2500-U+27BF (box drawing ─, dingbats ✓, geometric ●)
        # deliberately fall through to 1: they are Ambiguous/Narrow and
        # render single-width in the terminals vpssec targets.
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

# ==============================================================================
# Menu Box Drawing
# ==============================================================================
#
# The language / mode / module menus used to be hand-padded string
# literals ("│  [2] 简体中文                           │"). Every CJK
# label made the trailing space count wrong, so the right border of all
# three boxes was ragged, and the module menu's longest row
# ("运维合规 (logging,backup,alerts,scheduling,timezone)") overflowed
# it outright. Rendering from a single interior width fixes all of them
# and makes adding a row a one-liner.

_MENU_BOX_WIDTH=70   # interior cells, between the two vertical borders

_menu_box_top()    { printf '┌%s┐\n' "$(printf '─%.0s' $(seq 1 $_MENU_BOX_WIDTH))"; }
_menu_box_bottom() { printf '└%s┘\n' "$(printf '─%.0s' $(seq 1 $_MENU_BOX_WIDTH))"; }
_menu_box_sep()    { printf '├%s┤\n' "$(printf '─%.0s' $(seq 1 $_MENU_BOX_WIDTH))"; }
_menu_box_blank()  { printf '│%*s│\n' "$_MENU_BOX_WIDTH" ''; }

# One content row, indented two cells and padded to the interior width.
_menu_box_row() {
    printf '│%s│\n' "$(pad_to_width "  $1" "$_MENU_BOX_WIDTH")"
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
                debian)
                    # A Debian/Ubuntu derivative whose own ID is not in the
                    # list above: Mint, Pop!_OS, Kali, Armbian, Raspbian. The
                    # RHEL and Arch derivatives were already handled by family
                    # while their own main platform's were not, so a Mint host
                    # got the "unsupported OS" prompt (default no) at the entry
                    # point and a failed preflight check — for a distro whose
                    # every distro.sh primitive resolves correctly.
                    #
                    # No version test: derivatives number their own releases
                    # (Mint 21 is Ubuntu 22.04 underneath), so matching against
                    # the upstream numbers would reject every one of them.
                    #
                    # This does NOT widen fix mode. guide_mode gates on
                    # is_debian_based(), which stays an ID allowlist.
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

# Validate IP address. This feeds security-relevant sinks (ufw source
# scoping for the SSH rescue rule), so it must reject junk, not just match
# a shape: the old checks accepted 999.999.999.999 (no octet bounds) and
# "::::" (any hex-and-colon soup counted as IPv6).
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

    # IPv6, structurally: hex groups of 1-4 digits separated by ':', at most
    # one '::' (and no ':::'), and the group count consistent with 128 bits —
    # exactly 8 groups without '::', at most 7 with it. Zone IDs, embedded
    # IPv4 tails and other exotica are deliberately not accepted: every
    # caller feeds the value to a firewall rule where plain form is what
    # works.
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

# ==============================================================================
# File Operations (Safe)
# ==============================================================================

# Create a timestamped backup of a file
# Name of the per-session manifest listing files that fixes CREATED (had no
# prior version). Lives at the top of the backup session dir. backup_restore
# deletes the listed paths on rollback, and excludes this file from the
# restore walk.
VPSSEC_CREATED_MANIFEST=".vpssec_created"

# Name of the per-backup-directory manifest recording each backed-up file's
# ORIGINAL mode, one "<mode> <path>" line per file.
#
# It exists because two correct decisions combine into a wrong result:
# backup_file chmods its own copy to 600 so a snapshot of /etc/shadow is not
# left readable, and backup_restore restores with `cp -p`, which takes the
# mode from that copy. So a rollback used to reset every restored file to
# 600 while reporting full success. Harmless on root-read config
# (sshd_config, nginx.conf), but filesystem.fix_sensitive_perms backs up
# /etc/passwd and /etc/group — at 600 those break name lookups for every
# non-root process, leaving the host worse off than before the fix OR after
# it. Verified against the real primitives: 666 -> fix -> rollback gave 600.
VPSSEC_MODES_MANIFEST=".vpssec_modes"

# True if $1 already has a mode recorded in the manifest $2.
#
# The path is compared with `grep -qxF` on the path column rather than a
# regex over the whole line: an /etc path can contain regex metacharacters,
# and `cut -d' ' -f2-` keeps paths containing spaces intact because the mode
# is the only field that can never hold one.
_backup_mode_recorded() {
    local path="$1" manifest="$2"
    [[ -f "$manifest" ]] || return 1
    cut -d' ' -f2- "$manifest" 2>/dev/null | grep -qxF "$path"
}

# Record $1's current mode into $2 (a backup directory), once.
#
# First write wins, for the same reason backup_file's snapshot does: both
# must describe the pre-plan state. A fix that backs the same file up once
# per parameter would otherwise record the mode of its own intermediate.
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

# Record that a fix is about to CREATE $path (it does not exist yet), so a
# rollback DELETES it. No-op outside a plan backup session. This closes the
# rollback gap where backup_file — which only snapshots files that already
# exist — left a first-run drop-in (e.g. the kernel sysctl hardening file) with
# no backup entry, so "rollback" restored nothing and the file survived to
# re-apply its (possibly network-breaking) values on the next boot.
backup_track_created() {
    local path="$1"
    [[ -n "${VPSSEC_BACKUP_SESSION:-}" ]] || return 0
    validate_path "$path" || return 0
    mkdir -p "$VPSSEC_BACKUP_SESSION" 2>/dev/null || true
    chmod 700 "$VPSSEC_BACKUP_SESSION" 2>/dev/null || true
    if ! backup_is_tracked_created "$path"; then
        echo "$path" >> "${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}"
        chmod 600 "${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}" 2>/dev/null || true
    fi
}

backup_file() {
    local file="$1"

    # Validate input path
    if ! validate_path "$file"; then
        log_error "Invalid path for backup: $file"
        return 1
    fi

    # When a backup session is active (set by backup_create_session at the
    # start of execute_plan), every fix in the plan backs up into that ONE
    # directory, so a rollback restores the whole plan rather than only the
    # files touched in the last wall-clock second. Standalone callers get a
    # per-call timestamped directory, as before.
    local backup_dir
    if [[ -n "${VPSSEC_BACKUP_SESSION:-}" ]]; then
        backup_dir="$VPSSEC_BACKUP_SESSION"
    else
        local timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        backup_dir="${VPSSEC_BACKUPS}/${timestamp}"
    fi

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

        # First-write-wins WITHIN a backup session: if this file was already
        # backed up earlier in the same plan, keep that copy (the pre-plan
        # original) rather than overwriting it. A fix that re-backs-up the
        # same file once per item — e.g. kernel.sh writing the sysctl drop-in
        # per parameter — would otherwise leave only the N-1th intermediate as
        # the "backup", so a rollback would restore a still-mostly-hardened
        # file instead of the original (breaking the whole-plan rollback
        # contract). Standalone (no session) keeps its prior overwrite
        # behavior: each call already gets its own timestamped directory.
        if [[ -n "${VPSSEC_BACKUP_SESSION:-}" && -e "$backup_path" ]]; then
            log_info "Backup already present this session, keeping original: $backup_path"
            echo "$backup_path"
            return 0
        fi

        # If we already recorded this path as CREATED this session, it is ours —
        # do not snapshot an intermediate copy. A fix that writes the same file
        # once per parameter (kernel.sh's sysctl drop-in) would otherwise, on the
        # 2nd+ call, back up its own half-written output as the "original", so a
        # rollback would restore that instead of deleting the file. Rollback
        # deletes tracked-created files; leave it untouched here.
        if backup_is_tracked_created "$file"; then
            return 0
        fi

        # Record the mode BEFORE the copy is taken and re-permissioned, so
        # what lands in the manifest is the file's own mode rather than the
        # 600 the snapshot gets. See VPSSEC_MODES_MANIFEST for why the
        # rollback cannot recover it from the copy.
        backup_track_mode "$file" "$backup_dir"

        # Every step checked. This function runs inside fix bodies where
        # errexit is off (execute_fix calls fixes in an `if`), so an
        # unchecked failing cp used to fall through to the success log and
        # `echo` below — the caller got rc 0 and a "backup path" for a
        # backup that does not exist, and the fix proceeded with no way
        # back. A backup that could not be taken must be a loud failure.
        if ! mkdir -p "$(dirname "$backup_path")"; then
            log_error "Backup failed (mkdir): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")"
            return 1
        fi
        if ! cp -p "$file" "$backup_path"; then
            rm -f "$backup_path" 2>/dev/null || true
            log_error "Backup failed (cp): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")"
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
        backup_track_created "$file"
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
        # Preserve ownership too: mktemp created the temp as the invoking
        # user (root), so without this the rename silently re-owned any
        # non-root-owned target to root:root. Best effort — as non-root
        # (test runs) chown fails and the warning is the honest record.
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

# ==============================================================================
# Service Operations
# ==============================================================================

# ==============================================================================
# Network Utilities
# ==============================================================================

get_current_ssh_ip() {
    # Get the IP from SSH_CONNECTION or SSH_CLIENT
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        echo "${SSH_CONNECTION%% *}"
        return
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        echo "${SSH_CLIENT%% *}"
        return
    fi

    # Fallback: sudo's default env_reset STRIPS SSH_CONNECTION/SSH_CLIENT, which
    # is exactly how the documented `sudo ./vpssec guide` runs — so above we get
    # nothing and every caller that scopes a firewall rule to "the operator's
    # IP" would otherwise fall back to a world-open rule or no rescue rule at
    # all. Recover the source address from utmp via `who am i` (sudo does not
    # rewrite utmp): its last field is "(host)". Accept it only when it is an IP
    # literal — a reverse-resolved hostname or a blank/local login is not usable
    # as a `ufw allow from` source, and guessing wrong is worse than empty.
    local from
    from=$(LC_ALL=C who am i 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p')
    if [[ -n "$from" ]] && validate_ip "$from" >/dev/null 2>&1; then
        echo "$from"
        return
    fi

    echo ""
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

# ALL SSH ports sshd is configured to listen on (deduped, ascending). sshd can
# bind several `Port` lines; get_ssh_port returns only the first, so a firewall
# fix that allows just that one and then flips to default-deny cuts the operator
# off if they are on a different sshd port. Firewall fixes should open every
# port this returns, not just the first.
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
        # Capture the status via `|| rc=$?` rather than a bare call + `$?`.
        # This function runs inside a process-substitution subshell where
        # errexit is active; a bare failing `timeout` (exit 124 on timeout,
        # or the tool's own non-zero) would abort the subshell before the
        # warning could log — silently presenting truncated scan results as
        # complete. The `|| rc=$?` makes the failure a tested expression.
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

# ==============================================================================
# Initialization
# ==============================================================================

# True when this process can actually read an interactive answer.
#
# The old guard was `[[ ! -t 0 ]] && [[ ! -e /dev/tty ]]`, which asks
# whether the DEVICE NODE EXISTS. Under cron, a systemd unit or a
# daemonised CI runner /dev/tty exists but open(2) fails with ENXIO
# (no controlling terminal), so the guard passed, the menu printed,
# and the read below failed — leaking bash's own "No such device or
# address" to stderr on the way. Probing an actual open answers the
# question that matters.
_tty_readable() {
    [[ -t 0 ]] && return 0
    (exec 3</dev/tty) 2>/dev/null
}

# True when the caller asked for a non-interactive run.
#
# `--yes` documents itself as "auto-confirm non-critical prompts" and
# `--json-only` is for CI, yet neither suppressed the language / mode /
# module menus: `vpssec audit --yes` on a real TTY parked on the module
# selector forever, because the guard above only looked at whether a
# terminal existed, never at whether the user wanted to be asked. Both
# flags now select the documented defaults (Chinese-or-$VPSSEC_LANG,
# audit, all modules) and move on.
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

    # Module categories with descriptions
    # Format: category_id:en_name:zh_name:modules
    # Every selectable module must appear in exactly one category, or it becomes
    # unreachable from this menu (only "all modules" / --include= could pick it).
    # networking, cloud, scheduling and timezone were previously omitted.
    # preflight is intentionally excluded: it is a foundational pre-check that
    # always runs, not an opt-in module.
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

    # Column layout inside the box: "[N] " (4 cells) + name column +
    # module column, all measured in DISPLAY cells. The old code padded
    # with `printf "%-18s"`, which counts BYTES — every CJK glyph (3
    # bytes, 2 cells) over-counted by one, so the right border walked
    # left on every Chinese row, and "运维合规 (logging,backup,alerts,
    # scheduling,timezone)" burst through it entirely.
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
    # `status` is documented as not needing root, and it only READS. The
    # mkdir/chmod/log-append below all fail for a non-root user on a
    # root-owned install (and abort under set -e before status_mode ever
    # runs), so the read-only command gets a read-only init: i18n and
    # nothing else.
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
            # No "remove the lock file" advice here, on purpose. flock is
            # released by the kernel the instant the holder exits — a killed
            # run never blocks this branch. The only way to get here is a
            # LIVE process holding the lock, and deleting the file then
            # lets a new run recreate it on a fresh inode and take a "lock"
            # the first process isn't holding: two mutating runs at once,
            # exactly what the lock exists to prevent.
            print_msg "Wait for it to finish, or stop it: kill ${_other_pid:-<pid>}"
            exit 1
        fi
        # Record our PID for the next caller's diagnostics.
        echo $$ >&200
    fi

    log_info "vpssec initialized (version: ${VPSSEC_VERSION}, lang: ${VPSSEC_LANG})"
}
