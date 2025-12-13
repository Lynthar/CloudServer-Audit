#!/bin/bash
# vpssec - VPS Security Check & Hardening Tool
# One-line runner: curl -fsSL https://raw.githubusercontent.com/Lynthar/server-audit/main/run.sh | sudo bash
#
# Options:
#   curl ... | sudo bash -s -- audit          # Run audit only (default)
#   curl ... | sudo bash -s -- guide          # Interactive hardening
#   curl ... | sudo bash -s -- --lang=en_US   # English output

set -euo pipefail

# Configuration
VPSSEC_REPO="Lynthar/server-audit"
VPSSEC_BRANCH="main"
VPSSEC_TMP="/tmp/vpssec-$$"
VPSSEC_URL="https://raw.githubusercontent.com/${VPSSEC_REPO}/${VPSSEC_BRANCH}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    echo -e "${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           vpssec - VPS Security Check & Hardening             ║"
    echo "║                     https://github.com/${VPSSEC_REPO}             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check requirements
check_requirements() {
    # Check root
    if [[ "$(id -u)" != "0" ]]; then
        print_error "This script must be run as root"
        echo "Usage: curl -fsSL ${VPSSEC_URL}/run.sh | sudo bash"
        exit 1
    fi

    # Check required commands
    local missing=()
    for cmd in curl jq tar; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_warn "Installing missing dependencies: ${missing[*]}"
        apt-get update -qq 2>/dev/null || yum update -q 2>/dev/null || true
        apt-get install -y "${missing[@]}" 2>/dev/null || yum install -y "${missing[@]}" 2>/dev/null || {
            print_error "Failed to install dependencies: ${missing[*]}"
            exit 1
        }
    fi
}

# Download vpssec
download_vpssec() {
    print_info "Downloading vpssec..."

    mkdir -p "$VPSSEC_TMP"
    cd "$VPSSEC_TMP"

    # Download as tarball
    local tarball_url="https://github.com/${VPSSEC_REPO}/archive/refs/heads/${VPSSEC_BRANCH}.tar.gz"

    if curl -fsSL "$tarball_url" | tar -xz --strip-components=1; then
        print_ok "Downloaded successfully"
        chmod +x vpssec
    else
        print_error "Failed to download vpssec"
        exit 1
    fi
}

# Cleanup
cleanup() {
    if [[ -d "$VPSSEC_TMP" ]]; then
        rm -rf "$VPSSEC_TMP"
    fi
}

# Main
main() {
    print_banner

    # Parse arguments
    local mode="audit"
    local args=()

    for arg in "$@"; do
        case "$arg" in
            audit|guide|status)
                mode="$arg"
                ;;
            *)
                args+=("$arg")
                ;;
        esac
    done

    check_requirements
    download_vpssec

    # Set trap for cleanup
    trap cleanup EXIT

    # Run vpssec
    print_info "Running vpssec $mode..."
    echo ""

    ./vpssec "$mode" "${args[@]}"

    # Keep reports if generated
    if [[ -d "reports" ]] && [[ "$(ls -A reports 2>/dev/null)" ]]; then
        local report_dest="/tmp/vpssec-report-$(date +%Y%m%d-%H%M%S)"
        cp -r reports "$report_dest"
        echo ""
        print_info "Reports saved to: $report_dest"
    fi
}

main "$@"
