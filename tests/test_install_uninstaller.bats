#!/usr/bin/env bats
#
# Tests for the uninstaller install.sh generates.
#
# Three defects motivate this file, all in one 20-line heredoc:
#
#   1. `rm -rf /opt/vpssec` was a LITERAL while INSTALL_DIR is configurable,
#      so `INSTALL_DIR=/srv/vpssec ./install.sh` produced an uninstaller that
#      deleted a directory it had never installed to — someone else's copy,
#      or nothing — and left the real install in place.
#   2. It asked "Remove state and backups?" one line AFTER `rm -rf` had
#      already taken them. state/ and backups/ live under $INSTALL_DIR, not
#      under the /var/lib/vpssec that prompt offered to delete — a path
#      nothing in this codebase uses (it was the only occurrence in the whole
#      repo). So the question could not be honoured either way, and every
#      uninstall silently destroyed the backups `vpssec rollback` restores
#      from while appearing to ask first.
#   3. install.sh guards its own `rm -rf` with safe_remove_install_dir's
#      allowlist; the script it GENERATED had no guard at all. Making the
#      path configurable without adding one would have been strictly worse
#      than the bug being fixed.
#
# What this suite can and cannot reach: the allowlist only accepts
# /opt/<name> and /var/lib/<name>, so every path bats can write to is
# refused by design. The refusal paths and the generated text are covered
# here; the destructive success paths (data kept, data purged) need real
# allowlisted directories and live in tests/uninstall/run.sh, which is
# root-and-throwaway-container only, exactly like tests/mutation/.

load helpers.bash

setup() {
    _vpssec_load

    # Pull just the generator out of install.sh — it depends on nothing else
    # in that file.
    eval "$(awk '/^create_uninstaller\(\)/,/^}/' "$(_vpssec_repo_root)/install.sh")"

    fake="$BATS_TEST_TMPDIR/fakeinstall"
    mkdir -p "$fake/state" "$fake/backups"
    printf 'precious\n' > "$fake/state/ok.json"
    printf 'precious\n' > "$fake/backups/marker"

    BIN_LINK="$BATS_TEST_TMPDIR/bin-vpssec"
    : > "$BIN_LINK"
}

# ---- what gets generated ---------------------------------------------

@test "uninstaller: both paths are baked in, not hardcoded" {
    INSTALL_DIR="$fake" create_uninstaller
    grep -qxF "INSTALL_DIR=$fake" "$fake/uninstall.sh"
    # BIN_LINK too: it is a constant in install.sh today, which is exactly
    # how INSTALL_DIR's literal survived for as long as it did.
    grep -qxF "BIN_LINK=$BIN_LINK" "$fake/uninstall.sh"
}

@test "uninstaller: no /opt/vpssec literal survives for a different install dir" {
    # The whole of defect 1: the old script said /opt/vpssec no matter where
    # it had been installed.
    INSTALL_DIR="$fake" create_uninstaller
    _vpssec_refute grep -q '/opt/vpssec' "$fake/uninstall.sh"
}

@test "uninstaller: the dead /var/lib/vpssec path is gone" {
    # It was the only occurrence in the repo and nothing ever wrote there,
    # so offering to delete it was the visible half of defect 2.
    INSTALL_DIR="$fake" create_uninstaller
    _vpssec_refute grep -q '/var/lib/vpssec' "$fake/uninstall.sh"
}

@test "uninstaller: it carries the allowlist guard" {
    INSTALL_DIR="$fake" create_uninstaller
    grep -q 'opt|var/lib' "$fake/uninstall.sh"
}

@test "uninstaller: it asks about the data BEFORE removing anything" {
    # Defect 2 in the form a diff can check: the prompt must not appear
    # after the rm.
    INSTALL_DIR="$fake" create_uninstaller
    local ask_line rm_line
    ask_line=$(grep -n 'Also remove state and backups' "$fake/uninstall.sh" | head -1 | cut -d: -f1)
    rm_line=$(grep -n '^rm -rf' "$fake/uninstall.sh" | head -1 | cut -d: -f1)
    [ -n "$ask_line" ]
    [ -n "$rm_line" ]
    [ "$ask_line" -lt "$rm_line" ]
}

@test "uninstaller: the generated script is valid bash" {
    INSTALL_DIR="$fake" create_uninstaller
    bash -n "$fake/uninstall.sh"
}

@test "uninstaller: it is executable" {
    INSTALL_DIR="$fake" create_uninstaller
    [ -x "$fake/uninstall.sh" ]
}

# ---- the guard actually refuses --------------------------------------

@test "uninstaller: an install dir outside the allowlist is refused" {
    INSTALL_DIR="$fake" create_uninstaller

    run bash "$fake/uninstall.sh" </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"not a recognised vpssec install path"* ]]
}

@test "uninstaller: a refused run deletes nothing at all" {
    INSTALL_DIR="$fake" create_uninstaller

    run bash "$fake/uninstall.sh" </dev/null
    [ "$status" -ne 0 ]
    [ "$(cat "$fake/state/ok.json")" = "precious" ]
    [ "$(cat "$fake/backups/marker")" = "precious" ]
    [ -e "$BIN_LINK" ]
}

@test "uninstaller: shell metacharacters in the path are quoted, never executed" {
    # If the path were interpolated raw instead of through %q, the generated
    # `INSTALL_DIR=...; rm -rf <canary>` line would run the rm the moment the
    # uninstaller starts — before any guard could refuse.
    local canary="$BATS_TEST_TMPDIR/canary"
    mkdir -p "$canary"
    printf 'alive\n' > "$canary/marker"

    local hostile="$BATS_TEST_TMPDIR/x; rm -rf $canary"
    mkdir -p "$hostile"
    INSTALL_DIR="$hostile" create_uninstaller

    run bash "$hostile/uninstall.sh" </dev/null
    [ "$status" -ne 0 ]
    [ "$(cat "$canary/marker")" = "alive" ]
}

@test "uninstaller: an empty install dir is refused" {
    INSTALL_DIR="$fake" create_uninstaller
    # Re-bake an empty value the way an unset env var would.
    sed -i "s|^INSTALL_DIR=.*|INSTALL_DIR=''|" "$fake/uninstall.sh"

    run bash "$fake/uninstall.sh" </dev/null
    [ "$status" -ne 0 ]
    [ "$(cat "$fake/state/ok.json")" = "precious" ]
}
