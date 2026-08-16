#!/bin/bash
# One-line runner with a sigstore-verified release. Args after `-s --` are
# passed to vpssec. VPSSEC_VERSION pins a release tag (default "latest");
# VPSSEC_NO_VERIFY=1 skips cosign verification entirely.

set -euo pipefail

VPSSEC_REPO="Lynthar/CloudServer-Audit"
VPSSEC_VERSION="${VPSSEC_VERSION:-latest}"
VPSSEC_NO_VERIFY="${VPSSEC_NO_VERIFY:-0}"
# A root-owned `mktemp -d` (0700). Never a predictable /tmp path: $$ is a
# small integer, and a pre-planted symlink turns root's curl -o into an
# arbitrary-file overwrite.
VPSSEC_TMP=""

# Only signatures issued to THIS repo's release workflow at a v* tag pass.
# The cosign cert embeds the workflow URL and OIDC issuer; verify-blob
# enforces the match.
COSIGN_IDENTITY_REGEX="^https://github\.com/${VPSSEC_REPO}/\.github/workflows/release\.yml@refs/tags/v.+$"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Pinned cosign for the apt-fallback path. The hash is verified before dpkg
# ever sees the .deb. Bump VERSION and the per-arch hashes together —
# cosign-bump.yml does this weekly. Moves independently of release.yml.
COSIGN_PIN_VERSION="3.1.3"
# .deb assets — Debian/Ubuntu (installed via dpkg)
COSIGN_PIN_SHA256_AMD64="75357d96161da4d06d37c4b2831fa6978483cdce661999e5951b586f9ee1d710"
COSIGN_PIN_SHA256_ARM64="cfa1a4ef37201be3086bb68f7d5f6e51dd497f28cdfa5bd990fbdffa92557cf8"
# static binaries — RHEL/Arch and any other non-dpkg distro
COSIGN_PIN_SHA256_BIN_AMD64="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_PIN_SHA256_BIN_ARM64="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    local title="vpssec - VPS Security Check & Hardening"
    local url="https://github.com/${VPSSEC_REPO}"
    local width=63
    echo -e "${BOLD}"
    printf '╔%s╗\n' "$(printf '═%.0s' $(seq 1 "$width"))"
    printf '║%*s%s%*s║\n' $(( (width - ${#title}) / 2 )) "" "$title" $(( width - ${#title} - (width - ${#title}) / 2 )) ""
    printf '║%*s%s%*s║\n' $(( (width - ${#url}) / 2 )) "" "$url" $(( width - ${#url} - (width - ${#url}) / 2 )) ""
    printf '╚%s╝\n' "$(printf '═%.0s' $(seq 1 "$width"))"
    echo -e "${NC}"
}

print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Root, basic tools, and cosign unless verification is opted out.
# `apt install cosign` is best-effort; install_cosign_pinned() is the
# fallback. Architectures with no pinned hash bail with instructions.
install_cosign_pinned() {
    # Installs a pinned, SHA256-verified cosign asset: .deb via dpkg on
    # Debian, static binary into /usr/local/bin elsewhere. The hash is always
    # checked BEFORE the asset is installed or executed.
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
    print_warn "  trust root for cosign shifts from distro archive to github.com (same as run.sh itself)"

    # Fresh 0700 mktemp dir, like the tarball path. A hash check catches
    # tampered content only afterwards — the overwrite has already happened.
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
        # Debian/Ubuntu: pinned .deb. Hash-check before dpkg so a
        # compromised sigstore can't run a malicious maintainer script.
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
        # RHEL/Arch / anything without dpkg: pinned static binary. Same
        # trust trade-off; hash is checked before the file is made
        # executable or run.
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

check_requirements() {
    if [[ "$(id -u)" != "0" ]]; then
        print_error "This script must be run as root"
        echo "Usage: curl -fsSL https://raw.githubusercontent.com/${VPSSEC_REPO}/main/run.sh | sudo bash"
        exit 1
    fi

    local missing=()
    for cmd in curl jq tar; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if (( ${#missing[@]} > 0 )); then
        print_warn "Installing missing dependencies: ${missing[*]}"
        # Refresh package metadata only — NOT `yum update` (which upgrades
        # every package, or stalls on a y/N prompt with no tty). makecache is
        # the metadata-only equivalent on both yum and dnf.
        apt-get update -qq 2>/dev/null || yum -q makecache 2>/dev/null || dnf -q makecache 2>/dev/null || true
        apt-get install -y "${missing[@]}" 2>/dev/null \
            || yum install -y "${missing[@]}" 2>/dev/null \
            || { print_error "Failed to install: ${missing[*]}"; exit 1; }
    fi

    if [[ "$VPSSEC_NO_VERIFY" == "1" ]]; then
        return 0
    fi

    if ! command -v cosign &>/dev/null; then
        print_info "Installing cosign for signature verification..."
        if ! apt-get install -y cosign 2>/dev/null; then
            # apt has nothing (Debian, older Ubuntu, RHEL-family). Try
            # the pinned sigstore .deb fallback before giving up.
            if ! install_cosign_pinned; then
                print_error "cosign is required to verify the release signature."
                echo ""
                echo "  Manual install :  https://docs.sigstore.dev/cosign/system_config/installation/"
                echo "  Skip verify    :  re-run with  VPSSEC_NO_VERIFY=1  (not recommended)"
                exit 1
            fi
        fi
    fi
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

resolve_version() {
    if [[ "$VPSSEC_VERSION" != "latest" ]]; then
        _validate_version_tag "$VPSSEC_VERSION"
        return 0
    fi
    print_info "Resolving latest release..."
    VPSSEC_VERSION=$(curl -fsSL "https://api.github.com/repos/${VPSSEC_REPO}/releases/latest" \
        | jq -r '.tag_name // empty')
    if [[ -z "$VPSSEC_VERSION" ]]; then
        print_error "Could not resolve latest release tag from GitHub API"
        exit 1
    fi
    _validate_version_tag "$VPSSEC_VERSION"
}

# Download tarball and signature bundle, verify against the pinned cosign
# identity, then extract. Anything but a fully passing verify aborts.
download_and_verify() {
    local ver_tag="$VPSSEC_VERSION"
    local ver="${ver_tag#v}"
    local archive="vpssec-${ver}.tar.gz"
    local base="https://github.com/${VPSSEC_REPO}/releases/download/${ver_tag}"

    # Create a root-owned, 0700, unguessable temp dir. The name still starts
    # with /tmp/vpssec- so the cleanup() trap's path guard matches it.
    VPSSEC_TMP=$(mktemp -d "/tmp/vpssec-XXXXXX") \
        || { print_error "Failed to create temporary directory"; exit 1; }
    cd "$VPSSEC_TMP" || { print_error "Failed to enter $VPSSEC_TMP"; exit 1; }

    print_info "Downloading vpssec ${ver_tag}..."
    curl -fsSL "${base}/${archive}" -o "$archive" \
        || { print_error "Download failed: ${base}/${archive}"; exit 1; }

    if [[ "$VPSSEC_NO_VERIFY" == "1" ]]; then
        print_warn "VPSSEC_NO_VERIFY=1 — skipping signature verification"
    else
        curl -fsSL "${base}/${archive}.sig.json" -o "${archive}.sig.json" \
            || { print_error "Signature download failed"; exit 1; }
        print_info "Verifying signature (sigstore keyless)..."
        if cosign verify-blob \
            --bundle "${archive}.sig.json" \
            --certificate-identity-regexp "$COSIGN_IDENTITY_REGEX" \
            --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
            "$archive" >/dev/null 2>&1; then
            print_ok "Signature verified (signer = ${VPSSEC_REPO} release workflow @ ${ver_tag})"
        else
            print_error "Signature verification FAILED — refusing to run."
            print_error "If the signer URL changed, check this run.sh against the latest copy."
            exit 1
        fi
    fi

    print_info "Extracting..."
    tar -xz --strip-components=1 -f "$archive"
    chmod +x vpssec
}

cleanup() {
    if [[ -n "$VPSSEC_TMP" ]] && [[ "$VPSSEC_TMP" =~ ^/tmp/vpssec- ]] && [[ -d "$VPSSEC_TMP" ]]; then
        rm -rf "$VPSSEC_TMP"
    fi
}

main() {
    print_banner

    local mode=""
    local args=()
    for arg in "$@"; do
        case "$arg" in
            audit|guide|rollback|status) mode="$arg" ;;
            *) args+=("$arg") ;;
        esac
    done

    # Installed BEFORE anything creates the temp dir, so an early failure
    # cannot leak a directory holding an unverified tarball.
    trap cleanup EXIT

    check_requirements
    resolve_version
    download_and_verify

    if [[ -n "$mode" ]]; then
        print_info "Running vpssec $mode..."
        echo ""
        if (( ${#args[@]} > 0 )); then
            ./vpssec "$mode" "${args[@]}"
        else
            ./vpssec "$mode"
        fi
    else
        print_info "Starting vpssec..."
        echo ""
        if (( ${#args[@]} > 0 )); then
            ./vpssec "${args[@]}"
        else
            ./vpssec
        fi
    fi

    if [[ -d "reports" ]] && [[ "$(ls -A reports 2>/dev/null)" ]]; then
        local report_dest="/tmp/vpssec-report-$(date +%Y%m%d-%H%M%S)"
        cp -r reports "$report_dest"
        echo ""
        print_info "Reports saved to: $report_dest"
    fi
}

main "$@"
