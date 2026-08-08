#!/bin/bash
# vpssec installer script
# Usage: curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | bash

set -euo pipefail

# Configuration
VPSSEC_VERSION="${VPSSEC_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vpssec}"
BIN_LINK="/usr/local/bin/vpssec"
GITHUB_REPO="${GITHUB_REPO:-Lynthar/CloudServer-Audit}"

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

# Safely remove install directory (validate path first)
safe_remove_install_dir() {
    # Only allow removal if path is non-empty and looks like a vpssec install path
    if [[ -z "$INSTALL_DIR" ]]; then
        print_error "INSTALL_DIR is empty, refusing to remove"
        return 1
    fi
    # Must be under /opt/ or /var/lib/ (typical install locations)
    if [[ ! "$INSTALL_DIR" =~ ^/(opt|var/lib)/[a-zA-Z0-9_-]+$ ]]; then
        print_error "INSTALL_DIR path '$INSTALL_DIR' is not a safe location"
        return 1
    fi
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
    fi
}

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
                safe_remove_install_dir
                git clone "https://github.com/${GITHUB_REPO}.git" "$INSTALL_DIR"
            fi
        else
            # Download as tarball. GitHub tarballs extract to "<repo>-<branch>",
            # so the top-level dir here must match the repo name, not a stale
            # pre-rename guess.
            local tarball_url="https://github.com/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"
            local repo_name="${GITHUB_REPO##*/}"
            print_info "Downloading from $tarball_url"
            curl -fsSL "$tarball_url" | tar -xz -C /tmp
            safe_remove_install_dir
            mv "/tmp/${repo_name}-main" "$INSTALL_DIR"
        fi
    else
        # Download specific version
        local tarball_url="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${VPSSEC_VERSION}.tar.gz"
        local repo_name="${GITHUB_REPO##*/}"
        print_info "Downloading version $VPSSEC_VERSION..."
        curl -fsSL "$tarball_url" | tar -xz -C /tmp
        safe_remove_install_dir
        mv "/tmp/${repo_name}-${VPSSEC_VERSION}" "$INSTALL_DIR"
    fi

    # Create required directories
    mkdir -p "$INSTALL_DIR"/{state,reports,backups,logs,templates}

    # NOTE: chmod +x and the /usr/local/bin symlink are intentionally NOT
    # done here. They run in post_install, AFTER verify_integrity has
    # confirmed the extracted tree matches the manifest — otherwise a
    # tamper detected by the integrity check would already have left a live,
    # executable vpssec in PATH (reachable via `sudo vpssec`).
    print_ok "vpssec extracted to $INSTALL_DIR (pending integrity check)"
}

# Create uninstall script
#
# The paths are BAKED IN with %q rather than written as literals. The old
# version hardcoded `/opt/vpssec`, so `INSTALL_DIR=/srv/vpssec ./install.sh`
# produced an uninstaller that deleted a directory it had never installed to
# (someone else's copy, or nothing) and left the real install in place.
#
# It also asked "Remove state and backups?" one line AFTER `rm -rf` had
# already taken them: state and backups live under $INSTALL_DIR, not under
# the /var/lib/vpssec that prompt offered to delete — a path nothing in this
# codebase uses. So the question could not be honoured in either direction,
# and every uninstall silently destroyed the backups `vpssec rollback`
# restores from. It is now asked first and actually acted on.
create_uninstaller() {
    {
        printf '#!/bin/bash\n'
        printf '# vpssec uninstaller — generated by install.sh at install time.\n'
        printf '# The two paths below are the ones this installation actually used.\n\n'
        printf 'INSTALL_DIR=%q\n' "$INSTALL_DIR"
        printf 'BIN_LINK=%q\n' "$BIN_LINK"
        cat <<'EOF'

set -euo pipefail

# Same allowlist as install.sh's safe_remove_install_dir. Duplicated on
# purpose: this script has to stand alone after install.sh is gone, and it
# is the only thing between a mis-baked INSTALL_DIR and `rm -rf /`.
if [[ -z "$INSTALL_DIR" ]] || \
   [[ ! "$INSTALL_DIR" =~ ^/(opt|var/lib)/[a-zA-Z0-9_-]+$ ]]; then
    echo "Refusing to remove '$INSTALL_DIR': not a recognised vpssec install path." >&2
    echo "Remove it by hand if that is really where vpssec lives." >&2
    exit 1
fi

echo "Uninstalling vpssec from $INSTALL_DIR ..."

# Ask BEFORE removing anything. state/ holds the completed-fix history and
# backups/ is what `vpssec rollback` restores from, so the default on any
# non-interactive run is to KEEP them.
purge="${VPSSEC_UNINSTALL_PURGE:-}"
if [[ -z "$purge" ]]; then
    reply=""
    if read -rp "Also remove state and backups? [y/N] " reply 2>/dev/null </dev/tty; then
        :
    else
        # No terminal (piped, cron, CI): keep the data rather than guess.
        reply="n"
    fi
    [[ "${reply,,}" == "y" ]] && purge=1 || purge=0
fi

if [[ "$purge" != "1" ]]; then
    keep_dir="${INSTALL_DIR}.data-kept"
    mkdir -p "$keep_dir"
    for d in state backups; do
        if [[ -d "$INSTALL_DIR/$d" ]]; then
            rm -rf "${keep_dir:?}/$d"
            mv "$INSTALL_DIR/$d" "$keep_dir/$d"
        fi
    done
    echo "Kept state and backups in $keep_dir"
fi

rm -f "$BIN_LINK"
rm -rf "${INSTALL_DIR:?}"

echo "vpssec uninstalled"
EOF
    } > "$INSTALL_DIR/uninstall.sh"
    chmod +x "$INSTALL_DIR/uninstall.sh"
}

# Verify the integrity of every runtime-critical file against the
# checked-in manifest. The manifest covers entry script, core/,
# modules/, and the install/run scripts; tests, docs, README and
# friends are excluded.
#
# Threat model: this is defense-in-depth, NOT a substitute for
# release signing. TLS-protected GitHub clone/tarball + a manifest
# that ships in the same archive only catches partial or corrupted
# extraction, not deliberate compromise of the upstream repository
# (an attacker who can rewrite repo files can also rewrite the
# manifest). Real supply-chain assurance requires verifying the
# manifest itself against a signed release tag — that's a separate
# effort.
#
# Behaviour:
#   - manifest absent  → log a warning and continue (tolerates
#                        installs from older revisions before this
#                        infrastructure existed, and `git clone`
#                        from a fork or branch that hasn't run the
#                        manifest generator).
#   - manifest present and verifies → log OK, continue.
#   - manifest present but mismatch → abort install with exit 1.
verify_integrity() {
    local manifest="$INSTALL_DIR/manifest.sha256"

    if [[ ! -f "$manifest" ]]; then
        print_warn "Integrity manifest not present at $manifest; skipping check"
        return 0
    fi

    # `sha256sum -c` reads paths relative to the current directory.
    # cd into the install root so the manifest's "modules/foo.sh"
    # resolves correctly. --quiet suppresses the per-file "OK"
    # spam on success but still prints failed lines.
    print_info "Verifying file integrity against manifest.sha256..."
    if ( cd "$INSTALL_DIR" && sha256sum --quiet -c manifest.sha256 ); then
        print_ok "Integrity check passed (manifest matches)"
    else
        print_error "Integrity check FAILED — installation may be corrupted or tampered with"
        print_error "If you trust this source, re-run after deleting $INSTALL_DIR; otherwise inspect the failed files above"
        exit 1
    fi
}

# Post-install setup
post_install() {
    print_info "Running post-install setup..."

    # Expose the binary ONLY now — main() runs verify_integrity before this,
    # so the integrity check has already passed. Making it executable and
    # symlinking it into PATH here (rather than in install_vpssec) means a
    # failed integrity check leaves nothing executable in /usr/local/bin.
    chmod +x "$INSTALL_DIR/vpssec"
    ln -sf "$INSTALL_DIR/vpssec" "$BIN_LINK"

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
    verify_integrity
    create_uninstaller
    post_install
    print_usage
}

# Run main
main "$@"
