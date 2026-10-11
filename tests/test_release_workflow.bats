#!/usr/bin/env bats
# release.yml's publishing step must never replace a signed asset already
# published under a tag. It runs here as written, against a stub gh.

load helpers.bash

setup() {
    export GH_LOG="$BATS_TEST_TMPDIR/gh-calls"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    # GH_RELEASE: present | missing | unreachable. GH_ASSETS: names already on it.
    cat > "$BATS_TEST_TMPDIR/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_LOG"
[[ "$1 $2" == "release view" ]] || exit 0
case "$GH_RELEASE" in
    missing)     echo "release not found" >&2; exit 1 ;;
    unreachable) echo 'Get "https://api.github.com/repos/x/y/releases/tags/v9.8.7": EOF' >&2; exit 1 ;;
esac
[[ " $* " == *" --json "* ]] && printf '%s\n' $GH_ASSETS
exit 0
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/gh"
    : > "$GH_LOG"
}

# The step's `run: |` block, de-indented, with the build step's output wired in.
_publish_step() {
    awk '
        /^      - name: Create or update release with assets$/ { s = 1; next }
        s && /^        run: \|$/ { r = 1; next }
        r && /^      - / { exit }
        r { sub(/^          /, ""); print }
    ' "$(_vpssec_repo_root)/.github/workflows/release.yml" \
        | sed 's/\${{ steps\.build\.outputs\.archive }}/${ARCHIVE_NAME}/'
}

_run_publish() {
    local script
    script=$(_publish_step)
    [[ "$script" == *"gh release upload"* ]] || { echo "publishing step not found"; return 99; }
    run env PATH="$BATS_TEST_TMPDIR/bin:$PATH" GITHUB_REF_NAME=v9.8.7 \
        ARCHIVE_NAME=vpssec-9.8.7.tar.gz bash -c "$script"
}

@test "a release that cannot be read is not published to" {
    export GH_RELEASE=unreachable GH_ASSETS=""
    _run_publish
    [ "$status" -eq 1 ]
    [[ "$output" == *"::error::"*"EOF"* ]]
    _vpssec_refute grep -qE '^release (create|upload)' "$GH_LOG"
}

@test "a release that already carries the signed tarball is refused" {
    export GH_RELEASE=present GH_ASSETS="vpssec-9.8.7.tar.gz vpssec-9.8.7.tar.gz.sha256"
    _run_publish
    [ "$status" -eq 1 ]
    [[ "$output" == *"already has vpssec-9.8.7.tar.gz"* ]]
    _vpssec_refute grep -qE '^release (create|upload)' "$GH_LOG"
}

@test "a first run creates the release and uploads the signed assets" {
    export GH_RELEASE=missing GH_ASSETS=""
    _run_publish
    [ "$status" -eq 0 ]
    grep -qx 'release create v9.8.7 --title v9.8.7 --generate-notes' "$GH_LOG"
    grep -qx 'release upload v9.8.7 vpssec-9.8.7.tar.gz vpssec-9.8.7.tar.gz.sha256 vpssec-9.8.7.tar.gz.sig.json --clobber' "$GH_LOG"
}

@test "a re-run before the tarball landed reuses the release and finishes the upload" {
    export GH_RELEASE=present GH_ASSETS="vpssec-9.8.7.tar.gz.sha256"
    _run_publish
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q '^release create' "$GH_LOG"
    grep -q '^release upload v9.8.7 vpssec-9.8.7.tar.gz ' "$GH_LOG"
}
