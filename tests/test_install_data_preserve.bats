#!/usr/bin/env bats
#
# A reinstall over an existing directory must not destroy state/ and
# backups/: the uninstaller's default is to KEEP them, and the upgrade path
# honours the same contract via stash_data_dirs/restore_data_dirs.
#
# The stash pair is extracted and exercised alone: safe_remove_install_dir's
# allowlist refuses every bats-writable path by design, so its stash-then-rm
# ordering is pinned on the source text instead.

load helpers.bash

setup() {
    _vpssec_load

    eval "$(awk '/^stash_data_dirs\(\)/,/^}/' "$(_vpssec_repo_root)/install.sh")"
    eval "$(awk '/^restore_data_dirs\(\)/,/^}/' "$(_vpssec_repo_root)/install.sh")"

    INSTALL_DATA_STASH=""
    INSTALL_DIR="$BATS_TEST_TMPDIR/opt-vpssec"
    mkdir -p "$INSTALL_DIR/state" "$INSTALL_DIR/backups/20260101_000000"
    printf 'precious-state\n'  > "$INSTALL_DIR/state/ok.json"
    printf 'precious-backup\n' > "$INSTALL_DIR/backups/20260101_000000/etc-file"
}

@test "stash+restore round-trips state and backups across a tree replacement" {
    stash_data_dirs
    [ -n "$INSTALL_DATA_STASH" ]

    local stash="$INSTALL_DATA_STASH"
    rm -rf "$INSTALL_DIR"                                          # what safe_remove does
    mkdir -p "$INSTALL_DIR"/{state,reports,backups,logs,templates} # the fresh tree

    restore_data_dirs
    [ "$(cat "$INSTALL_DIR/state/ok.json")" = "precious-state" ]
    [ "$(cat "$INSTALL_DIR/backups/20260101_000000/etc-file")" = "precious-backup" ]
    [ ! -d "$stash" ]
}

@test "a fresh install with no data dirs stashes nothing and does not fail" {
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    stash_data_dirs
    [ -z "$INSTALL_DATA_STASH" ]
    restore_data_dirs
}

@test "only the uninstaller's kept set survives: reports are not carried over" {
    mkdir -p "$INSTALL_DIR/reports"
    printf 'old-report\n' > "$INSTALL_DIR/reports/summary.json"

    stash_data_dirs
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"/{state,reports,backups,logs,templates}
    restore_data_dirs

    [ ! -f "$INSTALL_DIR/reports/summary.json" ]
    [ "$(cat "$INSTALL_DIR/state/ok.json")" = "precious-state" ]
}

@test "safe_remove_install_dir stashes before it removes (source order)" {
    local src
    src=$(awk '/^safe_remove_install_dir\(\)/,/^}/' "$(_vpssec_repo_root)/install.sh")
    local stash_line rm_line
    stash_line=$(grep -n 'stash_data_dirs' <<<"$src" | head -1 | cut -d: -f1)
    rm_line=$(grep -n 'rm -rf "\$INSTALL_DIR"' <<<"$src" | head -1 | cut -d: -f1)
    [ -n "$stash_line" ]
    [ -n "$rm_line" ]
    [ "$stash_line" -lt "$rm_line" ]
}
