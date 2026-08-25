#!/usr/bin/env bats
# VERSION is the only source of the version string. If it stops being readable
# or stops being covered by the manifest, every report quietly says "unknown"
# instead of failing, which is the harder kind of wrong to notice.

load helpers.bash

setup() {
    _vpssec_load
    REPO="$(_vpssec_repo_root)"
}

@test "VERSION exists and holds a bare version string" {
    [ -f "$REPO/VERSION" ]
    run tr -d '[:space:]' < "$REPO/VERSION"
    [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]]
}

@test "VPSSEC_VERSION is taken from VERSION, not hardcoded" {
    [ "$VPSSEC_VERSION" = "$(tr -d '[:space:]' < "$REPO/VERSION")" ]
    [ "$VPSSEC_VERSION" != "unknown" ]
}

@test "no version literal is left in the sources that read it" {
    # A second copy would drift silently: the release gate only compares the
    # tag against VERSION, so a stale literal elsewhere would survive it.
    run grep -rn 'VPSSEC_VERSION="[0-9]' "$REPO/core" "$REPO/vpssec"
    [ "$status" -ne 0 ]
}

@test "a missing VERSION degrades to unknown without writing to stderr" {
    # The `<` redirection is reported by the shell itself, so a guard is
    # required — `2>/dev/null` on the substitution does not suppress it.
    local work="$BATS_TEST_TMPDIR/tree"
    mkdir -p "$work/core"
    cp "$REPO/core/common.sh" "$work/core/common.sh"

    run bash -c "source '$work/core/common.sh' 2>'$BATS_TEST_TMPDIR/err'; echo \$VPSSEC_VERSION"
    [ "$output" = "unknown" ]
    [ ! -s "$BATS_TEST_TMPDIR/err" ]
}

@test "VERSION is covered by the integrity manifest" {
    # This is what turns a missing VERSION into an install-time abort rather
    # than a runtime "unknown": sha256sum -c fails on a listed missing file.
    run grep -qE '[[:space:]]VERSION$' "$REPO/manifest.sha256"
    [ "$status" -eq 0 ]
}
