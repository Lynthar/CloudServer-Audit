#!/bin/bash
# vpssec installer script
# Usage: curl -fsSL https://raw.githubusercontent.com/repo/vpssec/main/install.sh | bash

set -euo pipefail

# Configuration
VPSSEC_VERSION="${VPSSEC_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vpssec}"
BIN_LINK="/usr/local/bin/vpssec"
GITHUB_REPO="${GITHUB_REPO:-Lynthar/server-audit}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if running as root
check_root() {
    if [[ "$(id -u)" != "0" ]]; then
        print_error "This script must be run as root"
        echo "Please run: sudo bash install.sh"
        exit 1
    fi
}

# Check system requirements
check_system() {
    print_info "Checking system requirements..."

    # Check OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu)
                print_ok "Supported OS: $PRETTY_NAME"
                ;;
            *)
                print_warn "Untested OS: $PRETTY_NAME (may work)"
                ;;
        esac
    else
        print_warn "Cannot detect OS"
    fi

    # Check required commands
    local missing=()
    for cmd in bash jq curl tar; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_warn "Missing dependencies: ${missing[*]}"
        print_info "Installing dependencies..."
        apt-get update -qq
        apt-get install -y "${missing[@]}"
    fi

    print_ok "System requirements satisfied"
}

# Download and install vpssec
install_vpssec() {
    print_info "Installing vpssec to $INSTALL_DIR..."

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Download from GitHub
    if [[ "$VPSSEC_VERSION" == "latest" ]]; then
        print_info "Downloading latest version from GitHub..."

        # Clone or download
        if command -v git &>/dev/null; then
            if [[ -d "$INSTALL_DIR/.git" ]]; then
                print_info "Updating existing installation..."
                cd "$INSTALL_DIR"
                git pull origin main
            else
                rm -rf "$INSTALL_DIR"
                git clone "https://github.com/${GITHUB_REPO}.git" "$INSTALL_DIR"
            fi
        else
            # Download as tarball
            local tarball_url="https://github.com/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"
            print_info "Downloading from $tarball_url"
            curl -fsSL "$tarball_url" | tar -xz -C /tmp
            rm -rf "$INSTALL_DIR"
            mv /tmp/server-audit-main "$INSTALL_DIR"
        fi
    else
        # Download specific version
        local tarball_url="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${VPSSEC_VERSION}.tar.gz"
        print_info "Downloading version $VPSSEC_VERSION..."
        curl -fsSL "$tarball_url" | tar -xz -C /tmp
        rm -rf "$INSTALL_DIR"
        mv "/tmp/server-audit-${VPSSEC_VERSION}" "$INSTALL_DIR"
    fi

    # Make executable
    chmod +x "$INSTALL_DIR/vpssec"

    # Create symlink
    ln -sf "$INSTALL_DIR/vpssec" "$BIN_LINK"

    # Create required directories
    mkdir -p "$INSTALL_DIR"/{state,reports,backups,logs,templates}

    print_ok "vpssec installed to $INSTALL_DIR"
}

# Create uninstall script
create_uninstaller() {
    cat > "$INSTALL_DIR/uninstall.sh" <<'EOF'
#!/bin/bash
# vpssec uninstaller

set -euo pipefail

echo "Uninstalling vpssec..."

# Remove symlink
rm -f /usr/local/bin/vpssec

# Remove installation directory
rm -rf /opt/vpssec

# Optionally remove state/backups (ask user)
read -rp "Remove state and backups? [y/N] " remove_data
if [[ "${remove_data,,}" == "y" ]]; then
    rm -rf /var/lib/vpssec
fi

echo "vpssec uninstalled"
EOF
    chmod +x "$INSTALL_DIR/uninstall.sh"
}

# Post-install setup
post_install() {
    print_info "Running post-install setup..."

    # Verify installation
    if "$BIN_LINK" --version &>/dev/null; then
        print_ok "Installation verified"
    else
        print_error "Installation verification failed"
        exit 1
    fi

    # Show version
    local version=$("$BIN_LINK" --version 2>/dev/null || echo "unknown")
    print_ok "Installed: $version"
}

# Print usage instructions
print_usage() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  vpssec installation complete!"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Quick start:"
    echo ""
    echo "    # Run security audit"
    echo "    sudo vpssec audit"
    echo ""
    echo "    # Interactive hardening"
    echo "    sudo vpssec guide"
    echo ""
    echo "    # Show help"
    echo "    vpssec --help"
    echo ""
    echo "  Uninstall:"
    echo "    sudo $INSTALL_DIR/uninstall.sh"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# Main installation flow
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           vpssec - VPS Security Check & Hardening             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    check_root
    check_system
    install_vpssec
    create_uninstaller
    post_install
    print_usage
}

# Run main
main "$@"
