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

# Default settings. A VPSSEC_LANG from the environment answers the language
# menu, as --lang does.
if [[ -n "${VPSSEC_LANG:-}" ]]; then
    VPSSEC_LANG_SET=1
fi
VPSSEC_LANG="${VPSSEC_LANG:-zh_CN}"
VPSSEC_COLOR="${VPSSEC_COLOR:-1}"
VPSSEC_JSON_ONLY="${VPSSEC_JSON_ONLY:-0}"
VPSSEC_YES="${VPSSEC_YES:-0}"
VPSSEC_DEBUG="${VPSSEC_DEBUG:-0}"
VPSSEC_QUIET_SCAN="${VPSSEC_QUIET_SCAN:-0}"  # Suppress detailed output during scanning

# -g keeps it global when common.sh is sourced from inside a function
# (bats helpers); a no-op on the top-level production load path.
declare -gA VPSSEC_I18N=()

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
# unknown = no network IMDS. aws-or-compatible is tier1: an EC2-shaped IMDS answered.
vpssec_cloud_tier() {
    if [[ -n "$VPSSEC_CLOUD_TIER" ]]; then
        echo "$VPSSEC_CLOUD_TIER"
        return
    fi
    case "$(vpssec_cloud_provider)" in
        aws|aws-or-compatible|azure|gcp|alibaba|tencent|huawei|oracle)
            VPSSEC_CLOUD_TIER="tier1" ;;
        digitalocean|vultr|linode|hetzner|ovh|scaleway)
            VPSSEC_CLOUD_TIER="tier2" ;;
        *)
            VPSSEC_CLOUD_TIER="unknown" ;;
    esac
    echo "$VPSSEC_CLOUD_TIER"
}

# Known-format credentials, one "<kind> <grep flags> <ERE>" each. Vendor-fixed
# prefixes and PEM headers only, for near-zero false positives: generic
# PASSWORD= / SECRET= markers are deliberately absent.
declare -ga _VPSSEC_SECRET_PATTERNS=(
    # PEM keys of any flavor, and PGP's armor, whose header ends "KEY BLOCK".
    'private_key -E -----BEGIN[[:space:]]+(RSA|OPENSSH|EC|DSA|ENCRYPTED|PGP)?[[:space:]]?PRIVATE[[:space:]]+KEY([[:space:]]+BLOCK)?-----'
    # AKIA = long-lived user key, ASIA = temporary session key.
    'aws_access_key -E (AKIA|ASIA)[0-9A-Z]{16}'
    # After its variable name, as env (=), YAML (:) or JSON ("...": "...").
    "aws_secret_key -iE aws_secret_access_key[\"']?[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9/+=]{40}"
    # The AccessKey ID, whose length after LTAI has varied over the years.
    'alibaba_access_key -E LTAI[A-Za-z0-9]{12,}'
    'tencent_secret_id -E AKID[A-Za-z0-9]{32}'
    # Personal access, OAuth and refresh tokens.
    'digitalocean_token -E do[opr]_v1_[a-f0-9]{64}'
    # Classic tokens (2021+ prefixes) and fine-grained PATs (2022+).
    'github_token -E gh[posu]_[A-Za-z0-9]{36}'
    'github_pat -E github_pat_[A-Za-z0-9_]{22,}'
    'gitlab_token -E glpat-[A-Za-z0-9_-]{20}'
    'slack_token -E xox[bpoasr]-[0-9A-Za-z-]{10,}'
    # a.b.c with base64url segments, the first two JSON objects (eyJ).
    'jwt -E eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    'stripe_live_key -E sk_live_[0-9a-zA-Z]{24,}'
)

# Scan for those credentials. Shared by cloud.sh and docker.sh.
# Emits "<kind>(x<n>) ..." — kinds and counts only, NEVER matched values.
_vpssec_scan_secrets_in_content() {
    local content="$1"
    [[ -z "$content" ]] && return 0
    local found=() entry kind flags re n
    for entry in "${_VPSSEC_SECRET_PATTERNS[@]}"; do
        read -r kind flags re <<<"$entry"
        # Occurrences, not lines: two keys on one line are two keys.
        n=$(grep -o "$flags" -- "$re" <<<"$content" 2>/dev/null | wc -l) || n=0
        (( n > 0 )) && found+=("${kind}(x$n)")
    done

    printf '%s ' "${found[@]}"
}

# --- Color and Formatting ---

# NO_COLOR (no-color.org) and TERM=dumb both force the plain palette,
# with the same effect as --no-color.
if [[ -n "${NO_COLOR:-}" || "${TERM:-}" == "dumb" ]]; then
    VPSSEC_COLOR=0
fi
# Real ESC bytes, not "\033" text: the output helpers print with %s, so that a
# backslash the operator typed stays literal, and %s shows "\033" as text.
if [[ "${VPSSEC_COLOR}" == "1" ]] && [[ -t 1 ]]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    MAGENTA=$'\033[0;35m'
    CYAN=$'\033[0;36m'
    WHITE=$'\033[0;37m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    NC=$'\033[0m' # No Color
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

# Control bytes (all but tab and newline) and DEL, each with its visible \xHH
# form. Host data reaches the reports and the log, which are read with cat and
# tail: a raw ESC there rewrites the reader's screen and can hide a line.
declare -ga _VPSSEC_CTRL_BYTES=() _VPSSEC_CTRL_SHOWN=()
for _ctrl_n in {1..8} {11..31} 127; do
    printf -v _ctrl_shown '\\x%02x' "$_ctrl_n"
    printf -v _ctrl_byte '%b' "$_ctrl_shown"
    _VPSSEC_CTRL_SHOWN+=("$_ctrl_shown")
    _VPSSEC_CTRL_BYTES+=("$_ctrl_byte")
done
unset _ctrl_n _ctrl_shown _ctrl_byte

# Rewrite those bytes in the variable named $1 as visible text, in place.
_ctrl_visible_var() {
    local -n _cvv_ref="$1"
    [[ "$_cvv_ref" == *[[:cntrl:]]* ]] || return 0
    local i
    for i in "${!_VPSSEC_CTRL_BYTES[@]}"; do
        _cvv_ref="${_cvv_ref//"${_VPSSEC_CTRL_BYTES[i]}"/"${_VPSSEC_CTRL_SHOWN[i]}"}"
    done
}

# 2>/dev/null comes FIRST in the redirect list: bash applies them left to
# right, so the other order leaks the append error to the caller.
_log_write() {
    local level="$1" msg="$2"
    _ctrl_visible_var msg
    echo "[$level] $(date -Iseconds) $msg" 2>/dev/null >> "${_log_file}" || true
}

log_debug() {
    if [[ "${VPSSEC_DEBUG:-0}" == "1" ]]; then
        _log_write DEBUG "$*"
    fi
}

log_info() {
    _log_write INFO "$*"
}

log_warn() {
    _log_write WARN "$*"
}

log_error() {
    _log_write ERROR "$*"
}

# --- Output Functions ---

print_msg() {
    [[ "${VPSSEC_JSON_ONLY}" == "1" ]] && return
    printf '%s\n' "$*"
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

# Under --json-only an error goes to stderr instead of vanishing: stdout is
# reserved for the JSON document, and a swallowed error leaves no trace.
print_error() {
    if [[ "${VPSSEC_JSON_ONLY}" == "1" ]]; then
        printf '%s\n' "${RED}${SYM_FAIL}${NC} $*" >&2
        return 0
    fi
    print_msg "${RED}${SYM_FAIL}${NC} $*"
}

# Questions, menus and every note a question depends on (a rescue port, the
# rules about to be enforced) go to the terminal, else stderr, never gated by
# --json-only or quiet scan: an unseen safety note cannot be acted on.
_VPSSEC_TTY=/dev/tty
tty_say() {
    if [[ "${1:-}" == "-n" ]]; then
        shift
        printf '%s' "$*" | tty_out
    else
        printf '%s\n' "$*" | tty_out
    fi
}

# stdin, verbatim, to the same place: data such as a plan or a rule list.
tty_out() {
    if { : >"$_VPSSEC_TTY"; } 2>/dev/null; then
        cat >"$_VPSSEC_TTY"
    else
        cat >&2
    fi
}

tty_warn() {
    tty_say "${YELLOW}${SYM_WARN}${NC} $*"
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

# --- Text Width Helpers (terminal cells, CJK-aware) ---

# One colour code: a real ESC byte, as the colour vars hold, or its literal
# "\033[...m" spelling. A regex, not a glob: in a glob `[0-9;]*m` runs to the
# LAST "m" in the string and takes the visible text with it.
_VPSSEC_ANSI_RE='(\\033|'$'\033'')\[[0-9;]*m'

# Remove every colour code from the variable named $1, in place (no fork).
_ansi_strip_var() {
    local -n _asv_ref="$1"
    while [[ "$_asv_ref" =~ $_VPSSEC_ANSI_RE ]]; do
        _asv_ref="${_asv_ref/"${BASH_REMATCH[0]}"/}"
    done
}

# DISPLAY width in terminal cells: CJK forms are 2 cells but one code point,
# so ${#str} is wrong for padding. Decodes UTF-8 in pure bash and applies the
# East_Asian_Width W/F ranges, so the answer holds under any locale.
_display_width() {
    local s="$1"
    _ansi_strip_var s
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

# Drop the last code point of the variable named $1, in place. Byte-wise
# under any locale: bash slices by bytes in the C locale, which an SSH
# session often has, and half a CJK character is not UTF-8 any more.
_drop_last_char_var() {
    local -n _dlc_ref="$1"
    local LC_ALL=C
    local -i b
    while [[ -n "$_dlc_ref" ]]; do
        printf -v b '%d' "'${_dlc_ref: -1}"
        (( b < 0 )) && b+=256
        _dlc_ref="${_dlc_ref:0:-1}"
        (( b >= 0x80 && b < 0xC0 )) || break
    done
}

# Truncate $1 to at most $2 display cells, appending "…" when it had to
# cut. Shrinks a code point at a time and re-measures: a cell count is
# not an index.
truncate_to_width() {
    local text="$1"
    local target="$2"
    if (( $(_display_width "$text") <= target )); then
        printf '%s' "$text"
        return
    fi
    while [[ -n "$text" ]] && (( $(_display_width "$text") > target - 1 )); do
        _drop_last_char_var text
    done
    printf '%s…' "$text"
}

# $1 as lines of at most $2 display cells, broken between code points
# (walked byte-wise, as above); a single character wider than $2 still
# gets a line of its own.
wrap_to_width() {
    local text="$1" line="" ch
    local -i target="$2" w=0 cw i n len b
    if (( $(_display_width "$text") <= target )); then
        printf '%s\n' "$text"
        return
    fi
    local LC_ALL=C
    n=${#text}
    for (( i = 0; i < n; i += len )); do
        printf -v b '%d' "'${text:i:1}"
        (( b < 0 )) && b+=256
        # The lead byte gives the sequence length; a stray continuation byte is one.
        if (( b >= 0xF0 )); then len=4; elif (( b >= 0xE0 )); then len=3
        elif (( b >= 0xC0 )); then len=2; else len=1; fi
        ch="${text:i:len}"
        cw=$(_display_width "$ch")
        if (( w > 0 && w + cw > target )); then
            printf '%s\n' "$line"
            line="" w=0
        fi
        line+="$ch"
        w+=cw
    done
    printf '%s\n' "$line"
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
        # Quoted: bash 5.2+ otherwise expands & in $val to the matched {var}.
        text="${text//\{$var\}/"$val"}"
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
        # It prints "none" AND exits 1 on bare metal, so the exit status cannot
        # pick the fallback; an empty answer is a failed query, not "none".
        local virt
        virt=$(systemd-detect-virt 2>/dev/null) || true
        echo "${virt:-unknown}"
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

# The /proc detect_container reads; tests point it at a fake one.
DETECT_PROC_DIR="/proc"

# The container type (openvz, lxc, docker, nspawn, container) when vpssec runs
# inside one, else nothing and 1. Kernel parameters and the MAC policy there
# belong to the host kernel, which nothing inside the container can change.
detect_container() {
    # systemd's rule: an OpenVZ host node has /proc/bc as well, and is no container.
    if [[ -d "$DETECT_PROC_DIR/vz" && ! -d "$DETECT_PROC_DIR/bc" ]]; then
        echo "openvz"
        return 0
    fi
    if grep -qa "lxc" "$DETECT_PROC_DIR/1/cgroup" 2>/dev/null; then
        echo "lxc"
        return 0
    fi
    if [[ -f /.dockerenv ]] || grep -qa "docker" "$DETECT_PROC_DIR/1/cgroup" 2>/dev/null; then
        echo "docker"
        return 0
    fi
    if grep -qa "machine.slice" "$DETECT_PROC_DIR/1/cgroup" 2>/dev/null; then
        echo "nspawn"
        return 0
    fi
    if grep -qa "container=" "$DETECT_PROC_DIR/1/environ" 2>/dev/null; then
        echo "container"
        return 0
    fi
    return 1
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
    local deps=(jq ss systemctl sed awk tar grep curl)

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
# "<mode> <path>" per line. backup_file chmods its copy to 600 and cp -p keeps
# that, so without it a rollback leaves /etc/passwd at 600 and breaks lookups.
VPSSEC_MODES_MANIFEST=".vpssec_modes"

# Scratch name of a copy still being written, at the session root. Never a
# restore candidate: it may be a fragment left by a killed backup.
VPSSEC_PARTIAL_PREFIX=".vpssec_partial."

# True if $1 already has a mode recorded in manifest $2. Compared with
# grep -qxF on the path column: /etc paths can contain regex metacharacters.
_backup_mode_recorded() {
    local path="$1" manifest="$2"
    [[ -f "$manifest" ]] || return 1
    cut -d' ' -f2- "$manifest" 2>/dev/null | grep -qxF "$path"
}

# Record $1's current mode into backup directory $2, once; 1 when it cannot be
# recorded. First write wins: it must describe the pre-plan state, not a fix's
# own intermediate. Without the entry a rollback leaves the copy's 600 in place.
backup_track_mode() {
    local path="$1" backup_dir="$2"
    [[ -n "$backup_dir" ]] || return 0
    local manifest="${backup_dir}/${VPSSEC_MODES_MANIFEST}"
    _backup_mode_recorded "$path" "$manifest" && return 0

    local mode
    mode=$(stat -c '%a' "$path" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1

    printf '%s %s\n' "$mode" "$path" 2>/dev/null >> "$manifest" || return 1
    chmod 600 "$manifest" 2>/dev/null || true
}

# Create backup directory $1 (700) with an empty created-files manifest. Every
# backup directory has one, so a rollback can tell a deleted manifest, which
# would leave the plan's new files behind unnoticed, from "nothing was created".
_backup_dir_open() {
    local dir="$1" manifest="$1/$VPSSEC_CREATED_MANIFEST"
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" || return 1
    [[ -e "$manifest" ]] && return 0
    : > "$manifest" && chmod 600 "$manifest"
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
    _backup_dir_open "$VPSSEC_BACKUP_SESSION" 2>/dev/null || return 1
    if ! backup_is_tracked_created "$path"; then
        # Checked: this manifest is the only thing that lets a rollback delete
        # the file the caller is about to create, so a failed append must not
        # be reported as a successful registration.
        echo "$path" >> "${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}" 2>/dev/null || return 1
        chmod 600 "${VPSSEC_BACKUP_SESSION}/${VPSSEC_CREATED_MANIFEST}" 2>/dev/null || true
    fi
}

# mkdir -p for a fix: each directory it is about to create is recorded first as
# "<dir>/", and a rollback removes it again if left empty. A fix MUST create its
# directories with this, or a rollback leaves them behind.
backup_mkdir() {
    local dir="${1%/}" d
    local -a missing=()
    [[ -d "$dir" ]] && return 0
    d="$dir"
    while [[ -n "$d" && ! -e "$d" ]]; do
        missing=("$d" ${missing[@]+"${missing[@]}"})
        d="${d%/*}"
    done
    for d in ${missing[@]+"${missing[@]}"}; do
        backup_track_created "$d/" || return 1
    done
    mkdir -p "$dir"
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

    # A working symlink is backed up as its target, which is what a write
    # through it changes: snapshotting it under the link's name with the link's
    # mode 777 restored a world-writable regular file in place of the link.
    if [[ -L "$file" && -e "$file" ]]; then
        local link="$file"
        if ! file=$(readlink -f "$link") || ! validate_path "$file"; then
            log_error "Backup failed (cannot resolve symlink): $link"
            print_error "$(i18n 'backup.snapshot_failed' "file=$link")" >&2
            return 1
        fi
        log_info "Backing up symlink target: $link -> $file"
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

    if ! _backup_dir_open "$backup_dir"; then
        log_error "Backup failed (mkdir): $backup_dir"
        print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
        return 1
    fi

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

        # Every step is checked: this runs inside fix bodies where errexit is
        # off, so an unchecked failure would return rc 0 and a path to a
        # snapshot that does not exist.
        if ! mkdir -p "$(dirname "$backup_path")"; then
            log_error "Backup failed (mkdir): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
        # Copied under a scratch name, renamed when complete: a copy cut short
        # by a kill must not sit at the final name, where the next backup keeps
        # it as the original and a rollback writes it back over the file.
        local partial
        if ! partial=$(mktemp "${backup_dir}/${VPSSEC_PARTIAL_PREFIX}XXXXXX") \
            || ! cp -p "$file" "$partial"; then
            [[ -n "${partial:-}" ]] && rm -f "$partial" 2>/dev/null
            log_error "Backup failed (cp): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
        chmod 600 "$partial" 2>/dev/null || \
            log_warn "Could not chmod 600 backup copy: $backup_path"
        if ! mv -f "$partial" "$backup_path"; then
            rm -f "$partial" 2>/dev/null
            log_error "Backup failed (rename): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
        # A copy whose mode went unrecorded would come back as 600: withdraw it.
        if ! backup_track_mode "$file" "$backup_dir"; then
            rm -f "$backup_path" 2>/dev/null
            log_error "Backup failed (mode manifest): $file -> $backup_path"
            print_error "$(i18n 'backup.snapshot_failed' "file=$file")" >&2
            return 1
        fi
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

    # Write THROUGH a working symlink, keeping the link: the rename below would
    # otherwise replace it with a regular file. A dangling link has no target,
    # so it is replaced — the nginx catchall's self-repair depends on that.
    if [[ -L "$target" && -e "$target" ]]; then
        local link="$target"
        if ! target=$(readlink -f "$link") || ! validate_path "$target"; then
            log_error "write_file_atomic: cannot resolve symlink $link"
            return 1
        fi
    fi

    local temp_file
    local target_dir
    target_dir=$(dirname "$target")

    # Ensure target directory exists
    backup_mkdir "$target_dir" || { log_error "write_file_atomic: cannot create $target_dir"; return 1; }

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

    # -T: a directory at $target is an error, not a place to move the file into.
    if mv -fT "$temp_file" "$target"; then
        log_info "Atomically wrote: $target"
        return 0
    else
        rm -f "$temp_file"
        log_error "Failed to write: $target"
        return 1
    fi
}

# Write a generated template from stdin to PATH in vpssec's own templates tree,
# then chmod MODE (verbatim; `+x` leaves umask in charge of read). Reports and
# returns 1 when either fails: a bare `cat >` says "generated" on a full disk.
write_template() {
    local path="$1" mode="${2:-}"
    if ! mkdir -p "${path%/*}" || ! cat > "$path"; then
        print_error "$(i18n 'common.template_write_failed' "path=$path")"
        return 1
    fi
    if [[ -n "$mode" ]] && ! chmod "$mode" "$path"; then
        print_error "$(i18n 'common.template_write_failed' "path=$path")"
        return 1
    fi
    print_item "$(i18n 'common.template_created' "name=${path##*/}")"
}

# --- Service Operations ---

# Refresh the apt index before a fix installs a package: an empty or stale
# cache cannot locate it. Never let it gate the install — one broken
# third-party repo fails the refresh while the package is still installable.
apt_refresh_index() {
    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
}

# Install packages $@ with apt, returning its status. Its output goes to the log,
# not into the guide, so no prompt may wait there unseen: stdin is /dev/null and
# dpkg keeps a changed conffile. On failure apt's last lines go to stderr.
apt_install() {
    local out rc=0
    out=$(DEBIAN_FRONTEND=noninteractive apt-get \
              -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
              install -y "$@" </dev/null 2>&1) || rc=$?
    log_info "apt-get install -y $* exited $rc:"$'\n'"$out"
    (( rc == 0 )) || tail -n 5 <<<"$out" >&2
    return "$rc"
}

# Apply changed fail2ban configuration to the running server. A plain reload
# leaves a jail whose banaction was renamed with NO action (fail2ban 1.0, 1.1);
# --restart restarts the affected jails in-process, bans restored from its db.
fail2ban_reload_jails() {
    fail2ban-client reload --restart >/dev/null 2>&1
}

# Rollback restores files only. A fix that changes anything else — a service,
# a package, a firewall rule, a symlink — passes the exact command that undoes
# it: printed now, and logged, because it may be needed days later.
record_undo() {
    local fix_id="$1" cmd="$2"
    [[ -n "$cmd" ]] || return 0
    print_info "$(i18n 'backup.undo_hint' "cmd=$cmd")"
    log_info "Undo for $fix_id: $cmd"
}

# Join undo commands into one line the operator can paste; empties skipped.
undo_join() {
    local out="" cmd
    for cmd in "$@"; do
        [[ -n "$cmd" ]] && out+="${out:+ && }$cmd"
    done
    printf '%s' "$out"
}

# Read BEFORE a fix enables and starts unit $1: the command that returns it to
# its present state afterwards, or nothing when it is already enabled and up.
service_undo_cmd() {
    local unit="$1" enabled=0 active=0
    systemctl is-enabled --quiet "$unit" 2>/dev/null && enabled=1
    systemctl is-active --quiet "$unit" 2>/dev/null && active=1
    if (( !enabled && !active )); then
        echo "systemctl disable --now $unit"
    elif (( !enabled )); then
        echo "systemctl disable $unit"
    elif (( !active )); then
        echo "systemctl stop $unit"
    fi
    return 0
}

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

# ALL ports sshd accepts connections on, deduped and ascending; firewall fixes
# MUST open every one. An active ssh.socket hands sshd its listeners and sshd
# binds none of its own, so the socket's ports beat what sshd -T says.
get_ssh_ports() {
    local ports dump="" unit
    # An inactive unit still prints its Listen lines: only an active one counts.
    ports=$(for unit in ssh.socket sshd.socket; do
                systemctl is-active --quiet "$unit" 2>/dev/null || continue
                systemctl show -p Listen --value "$unit" 2>/dev/null || true
            done | awk '$2 == "(Stream)" && $1 ~ /:[0-9]+$/ { n = split($1, a, ":"); print a[n] }')
    if [[ -z "$ports" ]] && command -v sshd &>/dev/null; then
        # One listenaddress line per bound address; `ListenAddress host:port`
        # overrides Port, so these lines, not the port lines, are the truth.
        dump=$(sshd -T 2>/dev/null) || dump=""
        ports=$(awk '$1 == "listenaddress" { n = split($2, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }' <<<"$dump")
    fi
    if [[ -z "$ports" ]]; then
        # sshd could not answer: Port lines plus explicit ListenAddress ports
        # from the files. A superset at worst, which only opens a spare rule.
        ports=$(grep -hiE "^[[:space:]]*(Port|ListenAddress)[[:space:]]+" \
            /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '
            tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print $2 }
            tolower($1) == "listenaddress" && $2 ~ /:[0-9]+$/ { n = split($2, a, ":"); print a[n] }' \
            || true)
    fi
    [[ -z "$ports" ]] && ports=22
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

# sshd's effective configuration for a connection as user $1 (default: one no
# Match User block names), Match blocks applied; addr=none never matches Match
# Address. Plain -T where -C is rejected. Returns 1 when sshd cannot answer.
sshd_effective_config() {
    local dump
    if dump=$(sshd -T -C "user=${1:-doesnotexist},host=none,addr=none" 2>/dev/null) && [[ -n "$dump" ]]; then
        printf '%s\n' "$dump"
        return 0
    fi
    dump=$(sshd -T 2>/dev/null) && [[ -n "$dump" ]] || return 1
    printf '%s\n' "$dump"
}

# The key files sshd reads for user $1, its Match blocks applied: %h, %u and %%
# expanded, relative paths under the home, one absolute path per line. None for
# "AuthorizedKeysFile none" or an unknown home; sshd's default when it cannot answer.
sshd_authorized_keys_files() {
    local user="$1" home dump akf tok path
    local -a toks=()
    home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6) || home=""
    [[ -n "$home" ]] || return 0
    # Captured, then read: a pipe into an awk that exits early would SIGPIPE sshd.
    dump=$(sshd_effective_config "$user") || dump=""
    akf=$(awk 'tolower($1) == "authorizedkeysfile" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' <<<"$dump")
    [[ -n "$akf" ]] || akf=".ssh/authorized_keys .ssh/authorized_keys2"
    [[ "${akf,,}" == none ]] && return 0
    read -ra toks <<<"$akf"
    for tok in "${toks[@]}"; do
        path="${tok//%%/$'\x01'}"   # protect literal %% before %h/%u
        path="${path//%h/"$home"}"
        path="${path//%u/"$user"}"
        path="${path//$'\x01'/%}"
        [[ "$path" != /* ]] && path="$home/$path"
        printf '%s\n' "$path"
    done
}

# Larger key files are not read: any local user can make one big enough to
# stall a root audit, and a real one is a few KB.
AUTHKEYS_MAX_BYTES=1048576

# Usable public keys in $1: non-comment lines with a key-type token at the start
# or after an options prefix (counting a commented-out key risks a lockout). A
# file not regular or over AUTHKEYS_MAX_BYTES is not read: prints 0, returns 2.
count_authorized_keys() {
    local file="$1" size
    [[ -e "$file" ]] || { echo 0; return 0; }
    size=$(stat -L -c %s -- "$file" 2>/dev/null) || size=""
    if [[ ! -f "$file" || ! "$size" =~ ^[0-9]+$ ]] || (( size > AUTHKEYS_MAX_BYTES )); then
        echo 0
        return 2
    fi
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /(^|[[:space:]])(ssh-|ecdsa-|sk-)/ { c++ }
        END { print c + 0 }
    ' "$file" 2>/dev/null || echo 0
}

# sshd's StrictModes check of user $1's key file $2: the file, then each directory
# up to the home (or /), owned by root or the user and not group/world-writable.
# Prints the first refused component as "path<TAB>mode<TAB>owner"; 1 = accepted.
strictmodes_refused_path() {
    local user="$1" pw uid home path st owner mode gid name
    [[ -e "$2" ]] || return 1
    pw=$(getent passwd "$user" 2>/dev/null) || return 1
    IFS=: read -r _ _ uid _ _ home _ <<<"$pw"
    path=$(readlink -f -- "$2") || return 1
    home=$(readlink -f -- "$home" 2>/dev/null) || home=""
    while :; do
        st=$(stat -L -c '%u %a %g %U' -- "$path" 2>/dev/null) || st="? 0 ? ?"
        read -r owner mode gid name <<<"$st"
        if [[ "$owner" != 0 && "$owner" != "$uid" ]] || (( 8#$mode & 8#002 )) \
           || { (( 8#$mode & 8#020 )) && ! _strictmodes_private_group "$gid" "$user"; }; then
            printf '%s\t%s\t%s\n' "$path" "$mode" "$name"
            return 0
        fi
        [[ "$path" == "$home" || "$path" == / ]] && return 1
        path="${path%/*}"
        path="${path:-/}"
    done
}

# Debian's OpenSSH also lets group $1 write a key path when the group's only
# member, primary or supplementary, is user $2: a private user group.
_strictmodes_private_group() {
    [[ "${VPSSEC_DISTRO_FAMILY:-}" == debian ]] || return 1
    local members primaries
    members=$(getent group "$1" 2>/dev/null | cut -d: -f4) || members=""
    primaries=$(getent passwd 2>/dev/null \
        | awk -F: -v g="$1" '$4 == g && !s[$1]++ { printf "%s%s", (n++ ? "," : ""), $1 }') || primaries=""
    [[ -n "$members$primaries" && "${members:-$2}" == "$2" && "${primaries:-$2}" == "$2" ]]
}

# --- Privileged accounts ---
# The one answer to "who can become root through sudo": the users audit, the
# ssh audit and the ssh lockout gates must agree, or a gate clears a lockout.

SUDOERS_FILE="/etc/sudoers"

# True for a sudoers.d drop-in that sudo IGNORES: @includedir skips any name
# containing '.' or ending in '~'. Reading those reports grants sudo never gives.
_sudoers_dropin_ignored() {
    local base="${1##*/}"
    [[ "$base" == *.* || "$base" == *'~' ]]
}

# The lines sudo reads, as "<file><TAB><line>", with @include / @includedir
# (and the older #include forms) expanded where they stand: rule order decides
# which grant wins, and a file sudo never includes grants nothing.
_sudoers_lines() {
    # sudo reads an @includedir in byte order (strcmp) and the last grant read
    # decides, so the glob below must not sort by the caller's locale.
    local LC_ALL=C
    local file="$1" depth="${2:-0}" line target f
    (( depth < 8 )) && [[ -r "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*[@#]include(dir)?[[:space:]]+\"?([^\"]*[^\"[:space:]])\"?[[:space:]]*$ ]]; then
            target="${BASH_REMATCH[2]}"
            [[ "$target" == /* ]] || target="${file%/*}/$target"
            if [[ -z "${BASH_REMATCH[1]}" ]]; then
                _sudoers_lines "$target" $((depth + 1))
                continue
            fi
            for f in "$target"/*; do
                [[ -f "$f" ]] || continue
                _sudoers_dropin_ignored "$f" && continue
                _sudoers_lines "$f" $((depth + 1))
            done
        else
            printf '%s\t%s\n' "$file" "$line"
        fi
    done < "$file"
}

# sudoers as tab-separated records in sudo's reading order; "-" stands for an
# empty field, which read's IFS would swallow. G file who N|P|- text: all
# commands as root; T file who text: NOPASSWD; D file g|u|r|c who 0|1 text.
_sudoers_records() {
    _sudoers_lines "$SUDOERS_FILE" | LC_ALL=C awk '
        function norm(s) { gsub(/[ \t]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }
        function tight(s) {
            gsub(/ ?, ?/, ",", s); gsub(/ ?: ?/, ":", s); gsub(/ ?= ?/, "=", s)
            gsub(/\( /, "(", s); gsub(/ \)/, ")", s)
            return s
        }
        # "#" opens a comment unless a digit follows: "#1001" is a uid.
        function uncomment(s,   i) {
            for (i = 1; i <= length(s); i++)
                if (substr(s, i, 1) == "#" && substr(s, i + 1, 1) !~ /[0-9]/)
                    return substr(s, 1, i - 1)
            return s
        }
        # Principals of a user or runas list ($2 is the alias kind), aliases
        # expanded; a negated alias negates every member.
        function principals(list, kind, depth,   n, it, i, neg, sub_, out, m, j, t) {
            if (depth > 16) return ""
            n = split(list, it, ",")
            out = ""
            for (i = 1; i <= n; i++) {
                neg = 0
                while (substr(it[i], 1, 1) == "!") { neg = !neg; it[i] = substr(it[i], 2) }
                if (it[i] == "") continue
                if ((kind, it[i]) in ALIAS) {
                    sub_ = principals(ALIAS[kind, it[i]], kind, depth + 1)
                    m = split(sub_, t, ",")
                    for (j = 1; j <= m; j++) {
                        if (neg) t[j] = (substr(t[j], 1, 1) == "+" ? "-" : "+") substr(t[j], 2)
                        out = out (out == "" ? "" : ",") t[j]
                    }
                } else {
                    out = out (out == "" ? "" : ",") (neg ? "-" : "+") it[i]
                }
            }
            return out
        }
        function cmnd_full(c, depth,   n, it, i) {
            if (c == "ALL") return 1
            if (depth > 16 || !(("C", c) in ALIAS)) return 0
            n = split(ALIAS["C", c], it, ",")
            for (i = 1; i <= n; i++)
                if (substr(it[i], 1, 1) != "!" && cmnd_full(it[i], depth + 1)) return 1
            return 0
        }
        # No Runas_Spec runs as root; "(:grp)" runs as the invoking user.
        function runas_root(r,   u, p, n, it, i) {
            if (r == "\001") return 1
            u = r; p = index(r, ":")
            if (p) u = substr(r, 1, p - 1)
            n = split(principals(u, "R", 0), it, ",")
            for (i = 1; i <= n; i++)
                if (it[i] == "+ALL" || it[i] == "+root" || it[i] == "+#0") return 1
            return 0
        }
        # Comma split that keeps a Runas_Spec "(a, b : c)" whole.
        function specs(s, out,   n, d, i, c, cur) {
            n = 0; d = 0; cur = ""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "(") d++
                else if (c == ")") d--
                if (c == "," && d == 0) { out[++n] = cur; cur = "" } else cur = cur c
            }
            out[++n] = cur
            return n
        }
        BEGIN {
            SEP = "\034"
            split("NOPASSWD PASSWD NOEXEC EXEC SETENV NOSETENV LOG_INPUT NOLOG_INPUT LOG_OUTPUT NOLOG_OUTPUT MAIL NOMAIL FOLLOW NOFOLLOW INTERCEPT NOINTERCEPT", k, " ")
            for (i in k) TAG[k[i]] = 1
            split("User_Alias U Runas_Alias R Host_Alias H Cmnd_Alias C Cmd_Alias C", k, " ")
            for (i = 1; i < 10; i += 2) KIND[k[i]] = k[i + 1]
        }
        {
            t = index($0, "\t"); file = substr($0, 1, t - 1)
            line = uncomment(substr($0, t + 1))
            if (held != "" && hfile == file) line = held " " line
            held = ""
            sub(/[ \t]+$/, "", line)
            for (nb = 0; substr(line, length(line) - nb, 1) == "\\"; nb++) ;
            if (nb % 2) { held = substr(line, 1, length(line) - 1); hfile = file; next }
            disp = norm(line); s = tight(disp)
            if (s == "") next
            sp = index(s, " "); word = sp ? substr(s, 1, sp - 1) : s
            if (word in KIND) {
                na = split(substr(s, sp + 1), a, ":")
                for (i = 1; i <= na; i++) {
                    eq = index(a[i], "=")
                    if (eq) ALIAS[KIND[word], substr(a[i], 1, eq - 1)] = substr(a[i], eq + 1)
                }
                next
            }
            if (s ~ /^Defaults([:@>!]|( |$))/) {
                c = substr(s, 9, 1); cls = "g"; bind = ""; rest = substr(s, 10)
                if (c == ":" || c == "@" || c == ">" || c == "!") {
                    p = index(rest, " "); if (!p) next
                    bind = substr(rest, 1, p - 1); rest = substr(rest, p + 1)
                    cls = (c == ":") ? "u" : (c == ">") ? "r" : (c == "!") ? "c" : "g"
                }
                np = split(rest, ps, ",")
                for (i = 1; i <= np; i++)
                    if (ps[i] == "authenticate" || ps[i] == "!authenticate")
                        rec[++n] = "D" SEP file SEP cls SEP bind SEP (ps[i] == "authenticate") SEP disp
                next
            }
            if (!sp) next
            r = substr(s, sp + 1); eq = index(r, "=")
            if (!eq) next
            rec[++n] = "R" SEP file SEP word SEP substr(r, eq + 1) SEP disp
        }
        END {
            for (i = 1; i <= n; i++) {
                split(rec[i], f, SEP)
                if (f[1] == "D") {
                    b = f[4]
                    if (f[3] == "u") b = principals(b, "U", 0)
                    else if (f[3] == "r") b = principals(b, "R", 0)
                    print "D\t" f[2] "\t" f[3] "\t" (b == "" ? "-" : b) "\t" f[5] "\t" f[6]
                    continue
                }
                runas = "\001"; auth = "-"; anyn = 0; full = 0; fauth = "-"
                m = specs(f[4], sp_)
                for (j = 1; j <= m; j++) {
                    c = sp_[j]; sub(/^ /, "", c)
                    if (substr(c, 1, 1) == "(") {
                        q = index(c, ")"); if (!q) break
                        runas = substr(c, 2, q - 2); c = substr(c, q + 1); sub(/^ /, "", c)
                    }
                    while (match(c, /^[A-Z_]+=[^ ]* /)) c = substr(c, RLENGTH + 1)
                    while (match(c, /^[A-Z_]+:/) && (substr(c, 1, RLENGTH - 1) in TAG)) {
                        tg = substr(c, 1, RLENGTH - 1)
                        if (tg == "NOPASSWD") auth = "N"; else if (tg == "PASSWD") auth = "P"
                        c = substr(c, RLENGTH + 1); sub(/^ /, "", c)
                    }
                    if (auth == "N") anyn = 1
                    if (cmnd_full(c, 0) && runas_root(runas)) { full = 1; fauth = auth }
                }
                pr = principals(f[3], "U", 0); if (pr == "") pr = "-"
                if (full) print "G\t" f[2] "\t" pr "\t" fauth "\t" f[5]
                if (anyn) print "T\t" f[2] "\t" pr "\t" f[5]
            }
        }'
}

# Pure-data variant of _group_all_members, for tests.
# $1: a getent-group line (`name:x:gid:m1,m2`); $2: getent-passwd content.
_group_all_members_from_streams() {
    local group_line="$1"
    local passwd_text="$2"

    local name pwd gid secondary
    IFS=: read -r name pwd gid secondary <<<"$group_line"

    if [[ -n "$secondary" ]]; then
        echo "$secondary" | tr ',' '\n'
    fi
    if [[ -n "$gid" ]]; then
        awk -F: -v g="$gid" '$4 == g {print $1}' <<<"$passwd_text"
    fi
}

# All users in a group: the 4th-field secondary members PLUS everyone whose
# primary GID matches. Omitting the latter loses `useradd -g sudo bob`.
_group_all_members() {
    local group="$1"
    local group_line passwd
    group_line=$(getent group "$group" 2>/dev/null) || return 0
    passwd=$(getent passwd 2>/dev/null)
    _group_all_members_from_streams "$group_line" "$passwd"
}

# Accounts a principal ("who") list names: "+x" adds and "-x" removes, x a
# user, #uid, %group, %#gid or ALL, aliases already expanded. Names that are
# not accounts drop out.
_sudoers_accounts() {
    local item name n
    local -a items=() names=()
    local -A add=() del=()
    IFS=, read -ra items <<<"$1"
    for item in "${items[@]}"; do
        name="${item:1}" names=()
        case "$name" in
            ALL) mapfile -t names < <(getent passwd 2>/dev/null | cut -d: -f1) ;;
            %:*|+*|'') ;;
            %\#*)
                n=$(getent group "${name#%#}" 2>/dev/null | cut -d: -f1)
                [[ -n "$n" ]] && mapfile -t names < <(_group_all_members "$n") ;;
            %*) mapfile -t names < <(_group_all_members "${name#%}") ;;
            \#*) mapfile -t names < <(getent passwd "${name#\#}" 2>/dev/null | cut -d: -f1) ;;
            *) getent passwd "$name" >/dev/null 2>&1 && names=("$name") ;;
        esac
        for n in "${names[@]}"; do
            [[ -n "$n" ]] || continue
            if [[ "${item:0:1}" == "-" ]]; then del[$n]=1; else add[$n]=1; fi
        done
    done
    for n in "${!add[@]}"; do
        [[ -n "${del[$n]:-}" ]] || echo "$n"
    done
}

# True when sudo asks account $1 for a password where no tag says: the
# authenticate Defaults in sudo's order, generic, then per-user, then per-runas
# for root; later lines of a class win. $2 is _sudoers_records' output.
_sudoers_authenticates() {
    local acct="$1" recs="$2" val=1 cls kind c b v accts
    for cls in g u r; do
        while IFS=$'\t' read -r kind _ c b v _; do
            [[ "$kind" == D && "$c" == "$cls" ]] || continue
            if [[ "$cls" == u ]]; then
                accts=$(_sudoers_accounts "$b")
                grep -qxF -- "$acct" <<<"$accts" || continue
            elif [[ "$cls" == r && ",$b," != *",+ALL,"* && ",$b," != *",+root,"* && ",$b," != *",+#0,"* ]]; then
                continue
            fi
            val="$v"
        done <<<"$recs"
    done
    (( val == 1 ))
}

# Every account holding a grant of all commands as root, as "<account> <0|1>",
# 1 when no password is asked. The last such grant naming the account decides,
# as in sudo; one without a PASSWD/NOPASSWD tag takes the authenticate Defaults.
_sudo_admin_grants() {
    local recs kind prins auth acct
    local -A last=()
    recs=$(_sudoers_records)
    while IFS=$'\t' read -r kind _ prins auth _; do
        [[ "$kind" == G ]] || continue
        while IFS= read -r acct; do
            last[$acct]="$auth"
        done < <(_sudoers_accounts "$prins")
    done <<<"$recs"
    for acct in "${!last[@]}"; do
        auth="${last[$acct]}"
        if [[ "$auth" == - ]]; then
            auth=N
            _sudoers_authenticates "$acct" "$recs" && auth=P
        fi
        if [[ "$auth" == N ]]; then echo "$acct 1"; else echo "$acct 0"; fi
    done
}

# Accounts that can become root through sudo, root included; one per line.
sudo_admin_users() {
    _sudo_admin_grants | cut -d' ' -f1 | sort -u
}

# True when $1 holds a full grant that needs no password.
sudo_nopasswd_admin() {
    local grants
    grants=$(_sudo_admin_grants)
    grep -qxF "$1 1" <<<"$grants"
}

# --- nginx configuration: one reading shared by the nginx and webapp modules ---
# Two modules with two answers to "is nginx here" and "what does it say" told
# the same host opposite things; both now ask these.

# The binary alone, as the engine's module gate does: `nginx -T` finds its own
# configuration, so a build whose config is not under /etc/nginx is still nginx.
nginx_present() {
    check_command nginx
}

# The resolved config (`nginx -T`) into NGINX_DUMP, once; call it in this shell,
# never in $(...). Returns 1 when the config fails nginx -t (first emerg line in
# NGINX_DUMP_ERROR): report that and skip, never grade the files nginx refuses.
NGINX_DUMP=""
NGINX_DUMP_ERROR=""
_NGINX_DUMP_STATE=""
nginx_dump_load() {
    case "$_NGINX_DUMP_STATE" in
        ok) return 0 ;;
        failed) return 1 ;;
    esac
    if NGINX_DUMP=$(nginx -T 2>/dev/null) && [[ -n "$NGINX_DUMP" ]]; then
        _NGINX_DUMP_STATE=ok
        return 0
    fi
    NGINX_DUMP=""
    NGINX_DUMP_ERROR=$(nginx -t 2>&1 | awk '/\[(emerg|alert|crit)\]/ { print; exit }') || true
    _NGINX_DUMP_STATE=failed
    return 1
}

# After rewriting the config and before reading it again: the cache hands back the old one.
nginx_dump_reset() {
    NGINX_DUMP=""
    NGINX_DUMP_ERROR=""
    _NGINX_DUMP_STATE=""
}

# `nginx -T` text on stdin -> "<server id>\t<context>\t<name>\t<args>" per directive,
# includes inlined where they occur. Server ids count server{} blocks from 1 (0 = none),
# context reads "http/server/...", args are space-joined and unquoted.
nginx_statements() {
    # -T prints each file once, under "# configuration file <path>:", in the order
    # nginx first read it; relative includes resolve against the main file's dir.
    LC_ALL=C awk '
        /^# configuration file .*:$/ {
            hdr = 1
            cur = ++nfiles
            order[cur] = substr($0, 22, length($0) - 22)
            next
        }
        {
            if (!cur) { cur = ++nfiles; order[cur] = "" }
            L[cur, ++nl[cur]] = $0
        }
        END {
            if (!nfiles) exit
            confdir = order[1]
            sub(/\/[^\/]*$/, "", confdir)
            depth = 0; sids[0] = 0; nserver = 0
            run(1)
        }
        function glob_re(p,   r, i, n, c, inb) {
            r = "^"; n = length(p); inb = 0
            for (i = 1; i <= n; i++) {
                c = substr(p, i, 1)
                if (inb) { r = r c; if (c == "]") inb = 0; continue }
                if (c == "*") r = r "[^/]*"
                else if (c == "?") r = r "[^/]"
                else if (c == "[") { inb = 1; if (substr(p, i + 1, 1) == "!") { r = r "[^"; i++ } else r = r "[" }
                else if (index("\\.^$+(){}|", c)) r = r "\\" c
                else r = r c
            }
            return r "$"
        }
        function include(pat,   re, f) {
            if (substr(pat, 1, 1) != "/") pat = confdir "/" pat
            re = glob_re(pat)
            for (f = 1; f <= nfiles; f++)
                if (!active[f] && order[f] ~ re) run(f)
        }
        function statement(toks, nt,   i, args, ctx) {
            if (nt == 0) return
            if (toks[1] == "include" && hdr) {
                for (i = 2; i <= nt; i++) include(toks[i])
                return
            }
            args = ""
            for (i = 2; i <= nt; i++) args = args (i > 2 ? " " : "") toks[i]
            ctx = ""
            for (i = 1; i <= depth; i++) ctx = ctx (i > 1 ? "/" : "") names[i]
            print sids[depth] "\t" ctx "\t" toks[1] "\t" args
        }
        # nginx tokenizing: `#` starts a comment only between tokens, quotes group
        # (backslash escapes inside them), and `${` opens a variable, not a block.
        function run(f,   k, i, n, c, line, tok, intok, inq, esc, invar, nt, toks) {
            active[f] = 1
            nt = 0; tok = ""; intok = 0; inq = ""; esc = 0; invar = 0
            for (k = 1; k <= nl[f]; k++) {
                line = L[f, k]; n = length(line)
                for (i = 1; i <= n; i++) {
                    c = substr(line, i, 1)
                    if (inq != "") {
                        if (esc) { tok = tok c; esc = 0; continue }
                        if (c == "\\") { esc = 1; continue }
                        if (c == inq) { inq = ""; toks[++nt] = tok; tok = ""; intok = 0; continue }
                        tok = tok c
                        continue
                    }
                    if (c == "#" && !intok) break
                    if (invar) { tok = tok c; if (c == "}") invar = 0; continue }
                    if (c == " " || c == "\t" || c == "\r") {
                        if (intok) { toks[++nt] = tok; tok = ""; intok = 0 }
                        continue
                    }
                    if (c == ";") {
                        if (intok) { toks[++nt] = tok; tok = ""; intok = 0 }
                        statement(toks, nt); nt = 0
                        continue
                    }
                    if (c == "{") {
                        if (intok && substr(tok, length(tok)) == "$") { tok = tok c; invar = 1; continue }
                        if (intok) { toks[++nt] = tok; tok = ""; intok = 0 }
                        depth++
                        names[depth] = (nt > 0 ? toks[1] : "")
                        sids[depth] = (names[depth] == "server") ? ++nserver : sids[depth - 1]
                        nt = 0
                        continue
                    }
                    if (c == "}") {
                        if (intok) { tok = ""; intok = 0 }
                        nt = 0
                        if (depth > 0) depth--
                        continue
                    }
                    if ((c == "\"" || c == "\047") && !intok) { inq = c; intok = 1; tok = ""; continue }
                    tok = tok c; intok = 1
                }
                if (inq != "") tok = tok "\n"
                else if (intok) { toks[++nt] = tok; tok = ""; intok = 0 }
            }
            active[f] = 0
        }
    '
}

# --- JSON Utilities ---

# Create a check result JSON. Serialised by jq so the full U+0000..U+001F
# range is escaped correctly; do not hand-roll an escape path here.
create_check_json() {
    # Fields reach jq on stdin, NUL-separated, never as --arg: an argv string is
    # capped at 128 KiB, past which jq fails and the check vanishes. END keeps
    # jq 1.6 from dropping trailing empty fields; keys are quoted (jq 1.7 `module`).
    { printf '%s\0' "$1" "$2" "$3" "$4" "$5" "${6:-}" "${7:-}" "${8:-}"; printf 'END'; } |
        jq -Rs 'split("\u0000")
            | {"id": .[0], "module": .[1], "severity": .[2], "status": .[3],
               "title": .[4], "desc": .[5], "suggestion": .[6], "fix_id": .[7]}'
}

# Emit one check: module is the id prefix, severity high|medium|low|info, status
# passed|failed, title defaults to i18n "$id"; key=value args, an unknown key drops it.
# A check that cannot be recorded marks its module incomplete and still returns 0.
check_emit() {
    local id="$1" severity="$2" status="$3"
    shift 3
    local title="" desc="" suggestion="" fix="" kv
    for kv in "$@"; do
        case "${kv%%=*}" in
            title)      title="${kv#*=}" ;;
            desc)       desc="${kv#*=}" ;;
            suggestion) suggestion="${kv#*=}" ;;
            fix)        fix="${kv#*=}" ;;
            *) log_error "check_emit $id: unknown field '${kv%%=*}'"; return 1 ;;
        esac
    done
    [[ -n "$title" ]] || title=$(i18n "$id")
    _ctrl_visible_var title
    _ctrl_visible_var desc
    _ctrl_visible_var suggestion
    # Every renderer buckets on these values; one outside them used to vanish
    # from the Markdown or show as a low failure in the terminal.
    local json
    if [[ "$severity" =~ ^(high|medium|low|info)$ && "$status" =~ ^(passed|failed)$ ]] \
        && json=$(create_check_json "$id" "${id%%.*}" "$severity" "$status" \
            "$title" "$desc" "$suggestion" "$fix") && state_add_check "$json"; then
        return 0
    fi
    log_error "check_emit $id: the check could not be recorded ($severity/$status)"
    # An _internal record reports a failure that is already recorded.
    [[ "${id%%.*}" == "_internal" ]] || _module_record_failure "${id%%.*}" "emit"
    return 0  # engine.sh emits under errexit, where 1 would kill the whole run
}

# --- User Interaction ---

# Set when the operator ANSWERED no to confirm or confirm_critical, as opposed to
# nobody being there to ask. execute_fix resets it and reads it to tell a fix
# the operator declined (skipped) from one that failed.
_VPSSEC_DECLINED=0

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

    # Printed before the read, so it shows even when the read then fails.
    tty_say -n "$prompt_text"

    # Read from /dev/tty to handle curl|bash piped execution
    local answered=1
    if ! read -r yn 2>/dev/null </dev/tty; then
        tty_say ""
        yn="$default"
        answered=0
    fi
    yn="${yn:-$default}"

    [[ "${yn,,}" == "y" || "${yn,,}" == "yes" ]] && return 0
    (( answered )) && _VPSSEC_DECLINED=1
    return 1
}

# Seconds confirm_critical waits for an answer. Bounded because the rescue sshd
# (root + password) stays up while it waits, and a session that dropped silently
# would otherwise keep it up for the TCP keepalive's two hours.
VPSSEC_CONFIRM_TIMEOUT=300

# Strict confirm for critical operations: never auto-yes. No terminal, or no
# answer within VPSSEC_CONFIRM_TIMEOUT, is a NO.
confirm_critical() {
    local prompt="$1"
    local yn rc=0

    tty_warn "$(i18n 'common.warning'): $prompt"
    tty_say -n "$(i18n 'common.confirm') [yes/NO] > "

    read -r -t "$VPSSEC_CONFIRM_TIMEOUT" yn 2>/dev/null </dev/tty || rc=$?
    if (( rc != 0 )); then
        tty_say ""
        if (( rc > 128 )); then
            tty_say "${RED}${SYM_FAIL}${NC} $(i18n 'error.confirm_timeout' "seconds=$VPSSEC_CONFIRM_TIMEOUT")"
        else
            tty_say "${RED}${SYM_FAIL}${NC} $(i18n 'error.cannot_read_critical')"
        fi
        return 1
    fi

    [[ "${yn,,}" == "yes" ]] && return 0
    _VPSSEC_DECLINED=1
    return 1
}

# --- Filesystem-walk Helpers (shared across modules) ---

# Container and snap trees to prune from filesystem walks. They live on the
# root filesystem, so -xdev does not skip them, and their image content (SUID
# binaries legitimate inside an image) would be reported as host findings.
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
_FS_FIND_TIMEOUT="${VPSSEC_FS_TIMEOUT:-60}"

# A whole number of seconds above 0. Checked at startup: a value timeout(1)
# rejects would skip every walk, and 0 would remove the bound altogether.
fs_timeout_valid() {
    [[ "$_FS_FIND_TIMEOUT" =~ ^[1-9][0-9]*$ ]]
}

# Record a walk ends with when it was cut short or never ran. No record a walk
# prints ends in "/", so a suffix match cannot hit a real path, and it also
# swallows the unterminated record a killed walk leaves behind.
_FS_WALK_CUT="vpssec:walk-cut-short/"

# Labels of the walks the running audit saw cut short; each module resets it.
_FS_CUT_WALKS=()

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

# Run a walk under the hard timeout, forwarding its output. A walk that timed
# out (124) or never ran (125-127) ends with the NUL-terminated _FS_WALK_CUT
# record, so its partial output cannot be read as "nothing found".
_fs_run_find() {
    local label="$1"
    shift
    # `|| rc=$?`: errexit is on in the process-substitution subshell this runs
    # in, and a bare failing walk would exit before the record is written.
    local rc=0
    if command -v timeout >/dev/null 2>&1; then
        timeout "$_FS_FIND_TIMEOUT" "$@" || rc=$?
    else
        log_debug "timeout(1) unavailable; running '${label}' scan without time bound"
        "$@" || rc=$?
    fi
    case "$rc" in
        124) log_warn "filesystem scan '${label}' timed out after ${_FS_FIND_TIMEOUT}s; results truncated. Set VPSSEC_FS_TIMEOUT=N to extend." ;;
        125|126|127) log_warn "filesystem scan '${label}' did not run (exit ${rc})" ;;
        *) return 0 ;;
    esac
    printf '%s\0' "$_FS_WALK_CUT"
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
    # Skip if already specified via --lang or the VPSSEC_LANG environment variable
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

    # Non-interactive run, no terminal to read from, or the one-line runner
    # (which refuses guide): default to the read-only audit. Never silently
    # escalate to `guide`, which mutates.
    if _noninteractive || ! _tty_readable || [[ -n "${VPSSEC_ONESHOT:-}" ]]; then
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

    # rollback and status use no modules; a menu here would consume the answer
    # meant for rollback's own confirmation prompt.
    case "${VPSSEC_MODE:-}" in
        rollback|status) return 0 ;;
    esac

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
        # Opened for append: truncating before the lock is won erases the
        # holder's PID, and the conflict message below loses it.
        # shellcheck disable=SC2093
        exec 200>>"$_run_lock"
        if ! flock -n 200; then
            local _other_pid _msg
            _other_pid=$(cat "$_run_lock" 2>/dev/null || true)
            if [[ -n "$_other_pid" ]]; then
                _msg=$(i18n 'error.already_running_pid' "pid=$_other_pid")
            else
                _msg=$(i18n 'error.already_running')
            fi
            # Never advise removing the lock file: reaching here means a LIVE
            # holder, and a fresh inode would let two mutating runs coexist.
            _msg+=$'\n'"  $(i18n 'error.already_running_hint' "pid=${_other_pid:-<pid>}")"
            # One call, so the hint follows the error to stderr under --json-only.
            print_error "$_msg"
            exit 1
        fi
        # Our PID for the next caller's diagnostics. Same inode, so the lock
        # held through fd 200 is unaffected by the truncation.
        echo $$ > "$_run_lock"
    fi

    log_info "vpssec initialized (version: ${VPSSEC_VERSION}, lang: ${VPSSEC_LANG})"
}
