#!/bin/bash
# vpssec - VPS Security Check & Hardening Tool
# One-line runner with sigstore-verified release:
#   curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
#
# Usage:
#   curl ... | sudo bash                          # interactive (audit/guide menu)
#   curl ... | sudo bash -s -- audit              # direct audit
#   curl ... | sudo bash -s -- guide              # direct guide
#   curl ... | sudo bash -s -- --lang=en_US       # English UI
#
# Environment overrides:
#   VPSSEC_VERSION    pin to a specific release (e.g. "v0.0.9"); default "latest"
#   VPSSEC_NO_VERIFY  set to 1 to skip cosign verification (NOT recommended)

set -euo pipefail

VPSSEC_REPO="Lynthar/CloudServer-Audit"
VPSSEC_VERSION="${VPSSEC_VERSION:-latest}"
VPSSEC_NO_VERIFY="${VPSSEC_NO_VERIFY:-0}"
VPSSEC_TMP="/tmp/vpssec-$$"

# Sigstore identity check: only signatures issued to THIS repo's
# release workflow at a v* tag are accepted. The cosign cert embeds
# the workflow URL + OIDC issuer; cosign verify-blob enforces the
# match. A compromised upstream cannot forge a passing signature
# without also compromising sigstore's Fulcio CA + Rekor log.
COSIGN_IDENTITY_REGEX="^https://github\.com/${VPSSEC_REPO}/\.github/workflows/release\.yml@refs/tags/v.+$"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Pinned cosign for the apt-fallback install path (Debian, etc.). The
# SHA256 below is verified locally before dpkg ever sees the .deb, so a
# future compromise of the sigstore release pipeline still can't ship a
# tampered cosign through this script — the hash check fails first.
# Bump both VERSION and the per-arch hashes together; the bump workflow
# at .github/workflows/cosign-bump.yml automates this weekly.
# cosign v3.x verifies bundles signed by older v2.x cosign (sigstore
# bundle verification is backwards compatible across majors), so this
# pin can move independently of release.yml's signer pin.
COSIGN_PIN_VERSION="3.0.6"
COSIGN_PIN_SHA256_AMD64="e16e8eb815f8b1b3cee3e678874393c286f19dd59e9ac5da95e428f970ef00f3"
COSIGN_PIN_SHA256_ARM64="93f382c7476e3effabff8a2c3561239381d55dc2b21b2ccbeaf70e460acfeaaa"

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

# Root + basic tools + cosign (unless verification is opted-out). We
# best-effort `apt install cosign` since Ubuntu 22.04+ ships it in
# universe. If apt has nothing (typical Debian), we fall back to a
# pinned + SHA256-verified .deb from sigstore's GitHub release — see
# install_cosign_pinned() for the trust-model trade-off. Architectures
# without a pinned hash, or any other dpkg failure, still bail with
# manual-install instructions.
install_cosign_pinned() {
    # Fallback used when apt has no cosign package. Resolves uname -m
    # to a sigstore .deb arch suffix, downloads the pinned release
    # asset, verifies it against the SHA256 baked into this script,
    # then dpkg-installs. We deliberately do the hash check BEFORE
    # dpkg so a compromised sigstore can't run a malicious maintainer
    # script via package install. Returns non-zero on any failure.
    if ! command -v dpkg &>/dev/null; then
        print_error "dpkg not available — pinned cosign fallback is dpkg-only"
        return 1
    fi

    local arch deb_arch want_hash
    arch=$(uname -m)
    case "$arch" in
        x86_64)  deb_arch="amd64"; want_hash="$COSIGN_PIN_SHA256_AMD64" ;;
        aarch64) deb_arch="arm64"; want_hash="$COSIGN_PIN_SHA256_ARM64" ;;
        *)
            print_error "No pinned cosign .deb for architecture: $arch"
            return 1
            ;;
    esac

    local deb_file="/tmp/cosign_${COSIGN_PIN_VERSION}_${deb_arch}.$$.deb"
    local deb_url="https://github.com/sigstore/cosign/releases/download/v${COSIGN_PIN_VERSION}/cosign_${COSIGN_PIN_VERSION}_${deb_arch}.deb"

    print_warn "cosign not in apt — installing pinned v${COSIGN_PIN_VERSION} from sigstore GitHub release"
    print_warn "  trust root for cosign shifts from distro archive to github.com (same as run.sh itself)"

    if ! curl -fsSL "$deb_url" -o "$deb_file"; then
        print_error "Download failed: $deb_url"
        rm -f "$deb_file"
        return 1
    fi

    local got_hash
    got_hash=$(sha256sum "$deb_file" | awk '{print $1}')
    if [[ "$got_hash" != "$want_hash" ]]; then
        print_error "cosign .deb SHA256 mismatch — refusing to install"
        print_error "  expected: $want_hash"
        print_error "  got:      $got_hash"
        rm -f "$deb_file"
        return 1
    fi
    print_ok "cosign .deb hash verified"

    if ! dpkg -i "$deb_file" >/dev/null 2>&1; then
        print_error "dpkg -i failed for $deb_file"
        rm -f "$deb_file"
        return 1
    fi
    rm -f "$deb_file"

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
        apt-get update -qq 2>/dev/null || yum update -q 2>/dev/null || true
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

# Resolve "latest" to a concrete tag via the GitHub API. This is the
# latest *published* release (matches what shows on the Releases page),
# not the highest git tag.
resolve_version() {
    if [[ "$VPSSEC_VERSION" != "latest" ]]; then
        return 0
    fi
    print_info "Resolving latest release..."
    VPSSEC_VERSION=$(curl -fsSL "https://api.github.com/repos/${VPSSEC_REPO}/releases/latest" \
        | jq -r '.tag_name // empty')
    if [[ -z "$VPSSEC_VERSION" ]]; then
        print_error "Could not resolve latest release tag from GitHub API"
        exit 1
    fi
}

# Download tarball + signature bundle from the release, verify against
# the pinned cosign identity, then extract. Anything other than a
# fully-passing verify aborts (unless VPSSEC_NO_VERIFY=1, in which
# case verification is skipped entirely and the signature isn't even
# downloaded).
download_and_verify() {
    local ver_tag="$VPSSEC_VERSION"
    local ver="${ver_tag#v}"
    local archive="vpssec-${ver}.tar.gz"
    local base="https://github.com/${VPSSEC_REPO}/releases/download/${ver_tag}"

    mkdir -p "$VPSSEC_TMP"
    cd "$VPSSEC_TMP"

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

    check_requirements
    resolve_version
    download_and_verify

    trap cleanup EXIT

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
