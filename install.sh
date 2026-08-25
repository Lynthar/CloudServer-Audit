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

# state/ holds the completed-fix history and backups/ is what `vpssec
# rollback` restores from — the uninstaller's default is to KEEP them, and a
# reinstall over an existing directory must honour the same contract.
INSTALL_DATA_STASH=""

# Move state/ and backups/ into a fresh sibling directory before the install
# tree is removed. The stash lives next to INSTALL_DIR (root-only parent,
# same filesystem), never under /tmp.
stash_data_dirs() {
    local d
    for d in state backups; do
        [[ -d "$INSTALL_DIR/$d" ]] || continue
        if [[ -z "$INSTALL_DATA_STASH" ]]; then
            INSTALL_DATA_STASH=$(mktemp -d "${INSTALL_DIR}.upgrade-XXXXXX") \
                || { print_error "Cannot create a stash for state/backups — aborting before anything is removed"; exit 1; }
        fi
        mv "$INSTALL_DIR/$d" "$INSTALL_DATA_STASH/$d" \
            || { print_error "Cannot stash $d — aborting before anything is removed"; exit 1; }
    done
    # if-form, not `[[ ]] &&`: under set -e a fresh install (no data dirs)
    # must not turn the empty-stash status into an installer abort.
    if [[ -n "$INSTALL_DATA_STASH" ]]; then
        print_info "Preserving existing state/ and backups/ across the reinstall"
    fi
}

# Move the stashed data into the freshly-installed tree and drop the stash.
restore_data_dirs() {
    [[ -n "$INSTALL_DATA_STASH" ]] || return 0
    local d
    for d in state backups; do
        [[ -d "$INSTALL_DATA_STASH/$d" ]] || continue
        rm -rf "${INSTALL_DIR:?}/$d"
        mv "$INSTALL_DATA_STASH/$d" "$INSTALL_DIR/$d" \
            || print_error "Could not restore $d — it remains at $INSTALL_DATA_STASH/$d"
    done
    if rmdir "$INSTALL_DATA_STASH" 2>/dev/null; then
        INSTALL_DATA_STASH=""
    else
        # A restore above failed: keep the stash (the EXIT notice names it)
        # and fail the install loudly instead of reporting success.
        return 1
    fi
}

# If the installer dies between stash and restore, a silent orphan directory
# is as bad as deletion — say where the data went.
_stash_notice() {
    if [[ -n "$INSTALL_DATA_STASH" && -d "$INSTALL_DATA_STASH" ]]; then
        print_warn "Install did not finish — your state/backups are preserved at: $INSTALL_DATA_STASH"
    fi
}
trap _stash_notice EXIT

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
        # Inside the removal primitive, not at its call sites: every current
        # and future removal path preserves the data automatically.
        stash_data_dirs
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
                print_warn "OS: $PRETTY_NAME — vpssec's audit supports Debian/Ubuntu/RHEL-family/Arch;"
                print_warn "hardening (guide/rollback) stays Debian/Ubuntu-only."
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
        # set -e is on: a failing install aborts here with the real error
        # visible, instead of exit 127 later mid-install.
        if command -v apt-get &>/dev/null; then
            apt-get update -qq || true
            apt-get install -y "${missing[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y "${missing[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y "${missing[@]}"
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm --needed "${missing[@]}"
        elif command -v zypper &>/dev/null; then
            zypper --non-interactive install "${missing[@]}"
        else
            print_error "No supported package manager — install these manually, then re-run: ${missing[*]}"
            exit 1
        fi
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
            # GitHub tarballs extract to "<repo>-<branch>", so this tracks
            # the repo name. Extracted into a fresh mktemp dir, never bare
            # /tmp — a predictable path is a local user's foothold.
            local tarball_url="https://github.com/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"
            local repo_name="${GITHUB_REPO##*/}"
            local staging
            staging=$(mktemp -d) || { print_error "mktemp failed"; exit 1; }
            chmod 700 "$staging"
            print_info "Downloading from $tarball_url"
            curl -fsSL "$tarball_url" | tar -xz -C "$staging"
            safe_remove_install_dir
            mv "${staging}/${repo_name}-main" "$INSTALL_DIR"
            rm -rf "$staging"
        fi
    else
        # Download specific version (same mktemp staging as the latest path).
        local tarball_url="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${VPSSEC_VERSION}.tar.gz"
        local repo_name="${GITHUB_REPO##*/}"
        local staging
        staging=$(mktemp -d) || { print_error "mktemp failed"; exit 1; }
        chmod 700 "$staging"
        print_info "Downloading version $VPSSEC_VERSION..."
        curl -fsSL "$tarball_url" | tar -xz -C "$staging"
        safe_remove_install_dir
        mv "${staging}/${repo_name}-${VPSSEC_VERSION}" "$INSTALL_DIR"
        rm -rf "$staging"
    fi

    # Create required directories
    mkdir -p "$INSTALL_DIR"/{state,reports,backups,logs,templates}

    # chmod +x and the symlink belong in post_install, AFTER verify_integrity:
    # otherwise a detected tamper has already left an executable in PATH.
    print_ok "vpssec extracted to $INSTALL_DIR (pending integrity check)"
}

# Create the uninstall script. Paths are baked in with %q, not written as
# literals, so a non-default INSTALL_DIR uninstalls itself. State and backups
# live under INSTALL_DIR, so the prompt about them must come BEFORE rm -rf.
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

# Verify runtime files against the manifest: absent = warn, verifies =
# continue, mismatch = abort. Defence in depth only — the manifest ships in
# the same archive, so it catches partial extraction, not a bad upstream.
verify_integrity() {
    local manifest="$INSTALL_DIR/manifest.sha256"

    if [[ ! -f "$manifest" ]]; then
        print_warn "Integrity manifest not present at $manifest; skipping check"
        return 0
    fi

    # sha256sum -c reads paths relative to cwd, so cd into the install root.
    # --quiet hides per-file OK lines but still prints failures.
    print_info "Verifying file integrity against manifest.sha256..."
    if ( cd "$INSTALL_DIR" && sha256sum --quiet -c manifest.sha256 ); then
        print_ok "Integrity check passed (manifest matches)"
    else
        print_error "Integrity check FAILED — installation may be corrupted or tampered with"
        print_error "If you trust this source, re-run after deleting $INSTALL_DIR; otherwise inspect the failed files above"
        # On an UPDATE the pre-existing symlink already points into the
        # replaced tree (the tarball ships vpssec executable) — leave no
        # entry point to an install that just failed verification.
        if [[ "$(readlink -f "$BIN_LINK" 2>/dev/null)" == "$INSTALL_DIR"/* ]]; then
            rm -f "$BIN_LINK"
            print_warn "Removed $BIN_LINK — it pointed into the failed install"
        fi
        exit 1
    fi
}

# Post-install setup
post_install() {
    print_info "Running post-install setup..."

    # Exposed only now, after verify_integrity has passed, so a failed
    # integrity check leaves nothing executable in /usr/local/bin.
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
    # After verify_integrity: a failed check exits with the data still in the
    # stash (reported by the EXIT notice), so "delete $INSTALL_DIR and re-run"
    # cannot take the state/backups with it.
    restore_data_dirs
    create_uninstaller
    post_install
    print_usage
}

# Run main
main "$@"
