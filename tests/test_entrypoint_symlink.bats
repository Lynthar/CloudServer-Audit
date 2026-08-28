#!/usr/bin/env bats
# install.sh puts a symlink at /usr/local/bin/vpssec and then self-checks with
# `"$BIN_LINK" --version`. If the entry point cannot find core/ through a link,
# that check fails, the installer exits 1, and the installed command is dead.

load helpers.bash

setup() {
    REPO="$(_vpssec_repo_root)"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
}

# The baseline: without it, a red test below could mean "the tree is broken"
# rather than "the link is not resolved", and the suite would misreport.
@test "entrypoint: direct invocation reports a version" {
    run "$REPO/vpssec" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(tr -d '[:space:]' < "$REPO/VERSION")"* ]]
}

@test "entrypoint: works through a symlink whose directory has no core/" {
    # This is the installed shape. $BIN holds only the link, so an unresolved
    # dirname sends the first source to $BIN/core/ and nothing else runs.
    ln -s "$REPO/vpssec" "$BIN/vpssec"
    [ ! -d "$BIN/core" ]

    run "$BIN/vpssec" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(tr -d '[:space:]' < "$REPO/VERSION")"* ]]
}

@test "entrypoint: works through a symlink that points at another symlink" {
    # Pins full resolution rather than one hop: a packager may link into a
    # link, and a single readlink would stop at the first one and still miss.
    ln -s "$REPO/vpssec" "$BIN/first"
    ln -s "$BIN/first" "$BIN/second"

    run "$BIN/second" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(tr -d '[:space:]' < "$REPO/VERSION")"* ]]
}

@test "entrypoint: works through a symlink whose target is written relatively" {
    # ln -s does not canonicalise its target; a relative one resolves against
    # the link's own directory, which is not the caller's working directory.
    ln -s "$(realpath --relative-to="$BIN" "$REPO/vpssec")" "$BIN/relative"

    run "$BIN/relative" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(tr -d '[:space:]' < "$REPO/VERSION")"* ]]
}

@test "entrypoint: the symlink install.sh creates is the shape tested above" {
    # Binds these tests to the installer: if install.sh stops creating a plain
    # symlink, they keep passing while guarding a shape nothing produces.
    run grep -n 'ln -sf "\$INSTALL_DIR/vpssec" "\$BIN_LINK"' "$REPO/install.sh"
    [ "$status" -eq 0 ]
}
