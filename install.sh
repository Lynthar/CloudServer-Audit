#!/bin/bash
# Persistent installer for a sigstore-verified release, run as root. VPSSEC_VERSION
# pins a tag and takes `v1.2.0` or `1.2.0` (default: newest release, never a
# branch); VPSSEC_NO_VERIFY=1 skips cosign verification entirely.

set -euo pipefail

# Configuration
VPSSEC_VERSION="${VPSSEC_VERSION:-latest}"
VPSSEC_NO_VERIFY="${VPSSEC_NO_VERIFY:-0}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vpssec}"
BIN_LINK="/usr/local/bin/vpssec"
GITHUB_REPO="${GITHUB_REPO:-Lynthar/CloudServer-Audit}"

# The identity must name this repo's release workflow at EXACTLY the tag being
# installed. A looser any-v*-tag match would accept a signed asset from another
# release re-uploaded under this version's URL — a signed downgrade.
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Pinned cosign for the package-manager-fallback path; the hash is verified
# before dpkg or install sees the file. cosign-bump.yml rewrites these in
# run.sh AND here weekly, and hard-fails if either stops matching.
COSIGN_PIN_VERSION="3.1.3"
# .deb assets — Debian/Ubuntu (installed via dpkg)
COSIGN_PIN_SHA256_AMD64="75357d96161da4d06d37c4b2831fa6978483cdce661999e5951b586f9ee1d710"
COSIGN_PIN_SHA256_ARM64="cfa1a4ef37201be3086bb68f7d5f6e51dd497f28cdfa5bd990fbdffa92557cf8"
# static binaries — RHEL/Arch and any other non-dpkg distro
COSIGN_PIN_SHA256_BIN_AMD64="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_PIN_SHA256_BIN_ARM64="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"

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

# Download staging, cleared on every exit path so a failed verification never
# leaves an unverified tarball behind.
VPSSEC_STAGING=""

# If the installer dies between stash and restore, a silent orphan directory
# is as bad as deletion — say where the data went.
_install_cleanup() {
    if [[ -n "$VPSSEC_STAGING" && -d "$VPSSEC_STAGING" ]]; then
        rm -rf "$VPSSEC_STAGING"
    fi
    # if-form throughout: a failing test as the trap's last command would
    # overwrite the script's real exit status.
    if [[ -n "$INSTALL_DATA_STASH" && -d "$INSTALL_DATA_STASH" ]]; then
        print_warn "Install did not finish — your state/backups are preserved at: $INSTALL_DATA_STASH"
    fi
}
trap _install_cleanup EXIT

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

# Installs a pinned, SHA256-verified cosign asset: .deb via dpkg on Debian,
# static binary into /usr/local/bin elsewhere. The hash is always checked
# BEFORE the asset is installed or executed.
install_cosign_pinned() {
    local arch arch_sfx want_deb_hash want_bin_hash
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch_sfx="amd64"; want_deb_hash="$COSIGN_PIN_SHA256_AMD64"; want_bin_hash="$COSIGN_PIN_SHA256_BIN_AMD64" ;;
        aarch64) arch_sfx="arm64"; want_deb_hash="$COSIGN_PIN_SHA256_ARM64"; want_bin_hash="$COSIGN_PIN_SHA256_BIN_ARM64" ;;
        *)
            print_error "No pinned cosign for architecture: $arch"
            return 1
            ;;
    esac

    local base_url="https://github.com/sigstore/cosign/releases/download/v${COSIGN_PIN_VERSION}"
    print_warn "cosign not in package manager — installing pinned v${COSIGN_PIN_VERSION} from sigstore GitHub release"
    print_warn "  trust root for cosign shifts from distro archive to github.com (same as install.sh itself)"

    # Fresh 0700 mktemp dir. A hash check catches tampered content only
    # afterwards — the overwrite has already happened.
    local cosign_tmp
    cosign_tmp=$(mktemp -d) || {
        print_error "mktemp failed for cosign download"
        return 1
    }
    chmod 700 "$cosign_tmp"
    # Self-clearing RETURN trap: fires once on any return path, then unsets
    # itself. Cannot be forgotten when a new path is added.
    # shellcheck disable=SC2064  # expand now: cosign_tmp is a local
    trap "rm -rf '$cosign_tmp'; trap - RETURN" RETURN

    if command -v dpkg &>/dev/null; then
        # Debian/Ubuntu: pinned .deb. Hash-check before dpkg so a compromised
        # sigstore can't run a malicious maintainer script.
        local deb_file="${cosign_tmp}/cosign_${COSIGN_PIN_VERSION}_${arch_sfx}.deb"
        if ! curl -fsSL "${base_url}/cosign_${COSIGN_PIN_VERSION}_${arch_sfx}.deb" -o "$deb_file"; then
            print_error "Download failed: cosign_${COSIGN_PIN_VERSION}_${arch_sfx}.deb"
            return 1
        fi
        local got_hash
        got_hash=$(sha256sum "$deb_file" | awk '{print $1}')
        if [[ "$got_hash" != "$want_deb_hash" ]]; then
            print_error "cosign .deb SHA256 mismatch — refusing to install"
            print_error "  expected: $want_deb_hash"
            print_error "  got:      $got_hash"
            return 1
        fi
        print_ok "cosign .deb hash verified"
        if ! dpkg -i "$deb_file" >/dev/null 2>&1; then
            print_error "dpkg -i failed for $deb_file"
            return 1
        fi
    else
        # RHEL/Arch / anything without dpkg: pinned static binary. Same trust
        # trade-off; hash is checked before the file is executable or run.
        local bin_file="${cosign_tmp}/cosign-linux-${arch_sfx}"
        if ! curl -fsSL "${base_url}/cosign-linux-${arch_sfx}" -o "$bin_file"; then
            print_error "Download failed: cosign-linux-${arch_sfx}"
            return 1
        fi
        local got_hash
        got_hash=$(sha256sum "$bin_file" | awk '{print $1}')
        if [[ "$got_hash" != "$want_bin_hash" ]]; then
            print_error "cosign binary SHA256 mismatch — refusing to install"
            print_error "  expected: $want_bin_hash"
            print_error "  got:      $got_hash"
            return 1
        fi
        print_ok "cosign binary hash verified"
        if ! install -Dm0755 "$bin_file" /usr/local/bin/cosign 2>/dev/null; then
            print_error "failed to install cosign to /usr/local/bin"
            return 1
        fi
        # Make sure the freshly-installed binary is reachable for the
        # verify-blob call below even if /usr/local/bin wasn't on PATH.
        export PATH="/usr/local/bin:${PATH}"
    fi

    if ! command -v cosign &>/dev/null; then
        print_error "cosign installed but not on PATH"
        return 1
    fi
    print_ok "cosign v${COSIGN_PIN_VERSION} installed"
}

ensure_cosign() {
    if [[ "$VPSSEC_NO_VERIFY" == "1" ]]; then
        return 0
    fi
    command -v cosign &>/dev/null && return 0

    print_info "Installing cosign for signature verification..."
    if apt-get install -y cosign >/dev/null 2>&1; then
        return 0
    fi
    # apt has nothing (Debian, older Ubuntu, RHEL-family). Try the pinned
    # sigstore asset before giving up.
    if install_cosign_pinned; then
        return 0
    fi
    print_error "cosign is required to verify the release signature."
    echo ""
    echo "  Manual install :  https://docs.sigstore.dev/cosign/system_config/installation/"
    echo "  Skip verify    :  re-run with  VPSSEC_NO_VERIFY=1  (not recommended)"
    exit 1
}

# Reject any tag that is not a clean vX.Y.Z[.-suffix] before it reaches a
# download URL or local filename. Defence in depth: the tarball is still
# cosign-verified, but this stops a root-owned curl -o being steered.
_validate_version_tag() {
    local tag="$1"
    if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]]; then
        print_error "Refusing suspicious release tag: '$tag'"
        exit 1
    fi
}

# Normalise to the tag form used by the release assets. Both `1.2.0` and
# `v1.2.0` are accepted so the two entry points take the same input.
resolve_version() {
    if [[ "$VPSSEC_VERSION" != "latest" ]]; then
        [[ "$VPSSEC_VERSION" == v* ]] || VPSSEC_VERSION="v${VPSSEC_VERSION}"
        _validate_version_tag "$VPSSEC_VERSION"
        return 0
    fi
    print_info "Resolving latest release..."
    VPSSEC_VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
        | jq -r '.tag_name // empty')
    if [[ -z "$VPSSEC_VERSION" ]]; then
        print_error "Could not resolve latest release tag from GitHub API"
        exit 1
    fi
    _validate_version_tag "$VPSSEC_VERSION"
}

# Download and install vpssec
install_vpssec() {
    local ver_tag="$VPSSEC_VERSION"
    local ver="${ver_tag#v}"
    local archive="vpssec-${ver}.tar.gz"
    local base="https://github.com/${GITHUB_REPO}/releases/download/${ver_tag}"

    print_info "Installing vpssec ${ver_tag} to $INSTALL_DIR..."

    # 0700 staging, never a predictable path: a local user who pre-creates it
    # receives root's download. Cleared by the EXIT trap on every path.
    VPSSEC_STAGING=$(mktemp -d) || { print_error "mktemp failed"; exit 1; }
    chmod 700 "$VPSSEC_STAGING"

    print_info "Downloading ${archive}..."
    curl -fsSL "${base}/${archive}" -o "${VPSSEC_STAGING}/${archive}" \
        || { print_error "Download failed: ${base}/${archive}"; exit 1; }

    if [[ "$VPSSEC_NO_VERIFY" == "1" ]]; then
        print_warn "VPSSEC_NO_VERIFY=1 — skipping signature verification"
    else
        curl -fsSL "${base}/${archive}.sig.json" -o "${VPSSEC_STAGING}/${archive}.sig.json" \
            || { print_error "Signature download failed"; exit 1; }
        print_info "Verifying signature (sigstore keyless)..."
        # Exact-match identity: the signing cert must name this repo's release
        # workflow at the tag being installed, not just any v* tag.
        local want_identity="https://github.com/${GITHUB_REPO}/.github/workflows/release.yml@refs/tags/${ver_tag}"
        if cosign verify-blob \
            --bundle "${VPSSEC_STAGING}/${archive}.sig.json" \
            --certificate-identity "$want_identity" \
            --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
            "${VPSSEC_STAGING}/${archive}" >/dev/null 2>&1; then
            print_ok "Signature verified (signer = ${GITHUB_REPO} release workflow @ ${ver_tag})"
        else
            print_error "Signature verification FAILED — refusing to install."
            print_error "If the signer URL changed, check this install.sh against the latest copy."
            exit 1
        fi
    fi

    # The release tarball carries a single vpssec-<ver>/ top level.
    print_info "Extracting..."
    tar -xz -f "${VPSSEC_STAGING}/${archive}" -C "$VPSSEC_STAGING" \
        || { print_error "Extract failed"; exit 1; }
    if [[ ! -d "${VPSSEC_STAGING}/vpssec-${ver}" ]]; then
        print_error "Release tarball did not contain vpssec-${ver}/ — refusing to install"
        exit 1
    fi

    # Only now is the existing install touched: everything above can fail
    # without costing the operator a working installation.
    mkdir -p "$(dirname "$INSTALL_DIR")"
    safe_remove_install_dir
    mv "${VPSSEC_STAGING}/vpssec-${ver}" "$INSTALL_DIR"

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

# Manifest check: absent = warn, verifies = continue, mismatch = abort. The
# upstream check is the cosign signature above; this catches damage after it —
# partial extraction, a truncated move, a missing VERSION.
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

    # The tag was resolved from the releases API, so a mismatch here means the
    # tarball's VERSION disagrees with the tag it was published under.
    if [[ "$version" != *"${VPSSEC_VERSION#v}"* ]]; then
        print_warn "Installed tree reports '$version' but was published as ${VPSSEC_VERSION} — report this upstream"
    fi
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
    resolve_version
    ensure_cosign
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
