#!/usr/bin/env bats
# install.sh must reach the same trust root as run.sh: a release asset whose
# cosign signature does not verify is never installed, and a failed verification
# must not cost the operator the installation they already had.

load helpers.bash

setup() {
    _vpssec_load

    local src
    src="$(_vpssec_repo_root)/install.sh"
    eval "$(awk '/^_validate_version_tag\(\)/,/^}/' "$src")"
    eval "$(awk '/^resolve_version\(\)/,/^}/'      "$src")"
    eval "$(awk '/^ensure_cosign\(\)/,/^}/'        "$src")"
    eval "$(awk '/^install_vpssec\(\)/,/^}/'       "$src")"

    print_info()  { echo "[INFO] $*"; }
    print_ok()    { echo "[OK] $*"; }
    print_warn()  { echo "[WARN] $*"; }
    print_error() { echo "[ERROR] $*"; }

    GITHUB_REPO="Lynthar/CloudServer-Audit"
    COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
    VPSSEC_NO_VERIFY=0
    VPSSEC_STAGING=""
    INSTALL_DIR="$BATS_TEST_TMPDIR/opt-vpssec"

    # A spy, not the real thing: the point of most tests here is that the
    # existing tree is never reached, and the real allowlist refuses every
    # bats-writable path anyway.
    REMOVE_CALLED="$BATS_TEST_TMPDIR/remove-was-called"
    safe_remove_install_dir() { : > "$REMOVE_CALLED"; rm -rf "$INSTALL_DIR"; }
}

@test "_validate_version_tag accepts release tags and their suffixed forms" {
    for tag in v1.2.0 v10.0.1 v1.2.0-rc1 v1.2.0.1; do
        run _validate_version_tag "$tag"
        [ "$status" -eq 0 ]
    done
}

@test "_validate_version_tag refuses anything that could steer a download" {
    for tag in main ../../etc v1.2 'v1.2.0;id' 'v1.2.0 x' '' 'v1.2.0/../..'; do
        run _validate_version_tag "$tag"
        [ "$status" -ne 0 ]
        [[ "$output" == *"Refusing suspicious release tag"* ]]
    done
}

@test "resolve_version normalises a bare version to the tag form" {
    VPSSEC_VERSION="1.2.0"
    resolve_version
    [ "$VPSSEC_VERSION" = "v1.2.0" ]
}

@test "resolve_version leaves an already-tagged version alone" {
    VPSSEC_VERSION="v1.2.0"
    resolve_version
    [ "$VPSSEC_VERSION" = "v1.2.0" ]
}

@test "resolve_version refuses a branch name rather than resolving it" {
    VPSSEC_VERSION="main"
    run resolve_version
    [ "$status" -ne 0 ]
}

@test "ensure_cosign installs nothing when verification is opted out" {
    VPSSEC_NO_VERIFY=1
    # PATH is emptied, not prepended to: the very next line of ensure_cosign is
    # `command -v cosign && return 0`, so on a host that HAS cosign this test
    # passes whether the opt-out short-circuit works or not. Mutation testing
    # caught exactly that, on a container something else had installed it into.
    mkdir -p "$BATS_TEST_TMPDIR/nobin"

    # Reaching a package manager at all is the failure being asserted.
    apt-get() { echo "apt-get must not run" >&2; return 1; }
    install_cosign_pinned() { echo "pinned fallback must not run" >&2; return 1; }

    # Scoped to this call: bats' own teardown needs a working PATH.
    local saved="$PATH"
    PATH="$BATS_TEST_TMPDIR/nobin"
    run ensure_cosign
    PATH="$saved"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "a failed signature aborts without touching the existing installation" {
    mkdir -p "$INSTALL_DIR/state"
    printf 'precious\n' > "$INSTALL_DIR/state/ok.json"

    curl() { : > "${*: -1}"; }               # produce empty files, succeed
    cosign() { return 1; }                   # verification fails
    # tar must SUCCEED here. With a failing tar, "verification aborted" and
    # "verification only warned, then the next step failed" give the same status,
    # message and untouched directory — no assertion can tell them apart.
    tar() { mkdir -p "${VPSSEC_STAGING}/vpssec-1.2.0"; }
    export -f curl cosign tar 2>/dev/null || true

    VPSSEC_VERSION="v1.2.0"
    run install_vpssec
    [ "$status" -ne 0 ]
    [[ "$output" == *"Signature verification FAILED"* ]]

    [ ! -f "$REMOVE_CALLED" ]
    [ "$(cat "$INSTALL_DIR/state/ok.json")" = "precious" ]
}

@test "a failed download aborts before the signature step and before removal" {
    mkdir -p "$INSTALL_DIR/state"
    printf 'precious\n' > "$INSTALL_DIR/state/ok.json"

    curl() { return 22; }
    cosign() { echo "cosign must not run" >&2; return 0; }
    export -f curl cosign 2>/dev/null || true

    VPSSEC_VERSION="v1.2.0"
    run install_vpssec
    [ "$status" -ne 0 ]
    [[ "$output" == *"Download failed"* ]]

    [ ! -f "$REMOVE_CALLED" ]
    [ "$(cat "$INSTALL_DIR/state/ok.json")" = "precious" ]
}

@test "a tarball without the expected top level is refused, not installed" {
    mkdir -p "$INSTALL_DIR/state"
    printf 'precious\n' > "$INSTALL_DIR/state/ok.json"

    curl() { : > "${*: -1}"; }
    cosign() { return 0; }
    # Extracts cleanly but yields some other directory — the shape a
    # re-pointed release asset would have.
    tar() { mkdir -p "${VPSSEC_STAGING}/something-else"; }
    export -f curl cosign tar 2>/dev/null || true

    VPSSEC_VERSION="v1.2.0"
    run install_vpssec
    [ "$status" -ne 0 ]
    [[ "$output" == *"did not contain vpssec-1.2.0/"* ]]

    [ ! -f "$REMOVE_CALLED" ]
    [ "$(cat "$INSTALL_DIR/state/ok.json")" = "precious" ]
}

@test "verification is skipped only when explicitly opted out" {
    mkdir -p "$INSTALL_DIR"

    curl() { : > "${*: -1}"; }
    cosign() { echo "cosign must not run" >&2; return 1; }
    tar() { mkdir -p "${VPSSEC_STAGING}/vpssec-1.2.0"; }
    export -f curl cosign tar 2>/dev/null || true

    VPSSEC_NO_VERIFY=1
    VPSSEC_VERSION="v1.2.0"
    run install_vpssec
    [ "$status" -eq 0 ]
    [[ "$output" == *"skipping signature verification"* ]]
    [ -f "$REMOVE_CALLED" ]
}

@test "the install tree is replaced only after extraction succeeds" {
    # Source-text guard for the ordering the tests above exercise: every
    # failure path must return before safe_remove_install_dir, so that call
    # has to sit after the verify and the extract in the file.
    local src verify_line extract_line remove_line
    src="$(_vpssec_repo_root)/install.sh"
    verify_line=$(grep -n 'cosign verify-blob' "$src" | head -1 | cut -d: -f1)
    extract_line=$(grep -n 'did not contain vpssec-' "$src" | head -1 | cut -d: -f1)
    remove_line=$(grep -n '^ *safe_remove_install_dir$' "$src" | head -1 | cut -d: -f1)

    [ -n "$verify_line" ] && [ -n "$extract_line" ] && [ -n "$remove_line" ]
    [ "$remove_line" -gt "$verify_line" ]
    [ "$remove_line" -gt "$extract_line" ]
}
