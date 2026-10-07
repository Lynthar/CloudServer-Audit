#!/usr/bin/env bats
# run.sh deletes its whole tree on exit, and a fix's backups land in that tree.
# So guide and rollback must be refused here — running them would change /etc
# and destroy the only means of undoing it in the same command.

load helpers.bash

setup() {
    _vpssec_load

    local src
    src="$(_vpssec_repo_root)/run.sh"
    eval "$(awk '/^_refuse_stateful_mode\(\)/,/^}/' "$src")"

    print_error() { echo "[ERROR] $*"; }
    VPSSEC_REPO="Lynthar/CloudServer-Audit"
}

@test "guide is refused, and not with the code that means a wrong host" {
    run _refuse_stateful_mode guide
    # 4 is "this HOST cannot be hardened"; automation must not read one as the
    # other, and 0 would read as "hardening completed".
    [ "$status" -eq 2 ]
    [[ "$output" == *"not available through the one-line runner"* ]]
}

@test "rollback is refused too: a fresh tree has no backups to restore from" {
    run _refuse_stateful_mode rollback
    [ "$status" -eq 2 ]
}

@test "the refusal names the way forward, not just the refusal" {
    run _refuse_stateful_mode guide
    [[ "$output" == *"install.sh"* ]]
    [[ "$output" == *"sudo vpssec guide"* ]]
}

@test "audit, status and no mode word pass the pre-download check" {
    # No mode word is decided downstream, by vpssec itself — see the tests below.
    for m in audit status ""; do
        run _refuse_stateful_mode "$m"
        [ "$status" -eq 0 ]
        [ -z "$output" ]
    done
}

@test "the refusal happens before anything is downloaded" {
    # Refusing after the download would still be correct, but it would fetch a
    # release only to decline to use it — and on a slow link that reads as a
    # hang rather than a refusal.
    local src refuse_line download_line
    src="$(_vpssec_repo_root)/run.sh"
    refuse_line=$(grep -n '^ *_refuse_stateful_mode "\$mode"$' "$src" | head -1 | cut -d: -f1)
    download_line=$(grep -n '^ *download_and_verify$' "$src" | head -1 | cut -d: -f1)

    [ -n "$refuse_line" ] && [ -n "$download_line" ]
    [ "$refuse_line" -lt "$download_line" ]
}

# ---- refusing on the mode vpssec settles on, not the words run.sh saw ----
# A bare `curl … | sudo bash` reaches guide through the mode menu, and an
# environment can set VPSSEC_MODE; neither puts a mode word on run.sh's line.

@test "with no mode word the runner still marks the run one-shot for vpssec" {
    local src work
    src="$(_vpssec_repo_root)/run.sh"
    work="$BATS_TEST_TMPDIR/tree"
    mkdir -p "$work"
    eval "$(awk '/^main\(\)/,/^}/' "$src")"
    print_banner() { :; }; print_info() { :; }; cleanup() { :; }
    check_requirements() { :; }; resolve_version() { :; }; download_and_verify() { :; }
    printf '#!/bin/sh\necho "marker=${VPSSEC_ONESHOT:-} args=$*"\n' > "$work/vpssec"
    chmod +x "$work/vpssec"

    cd "$work"
    run main
    [ "$status" -eq 0 ]
    [[ "$output" == *"marker=1 args="* ]]
}

@test "vpssec refuses guide and rollback under the marker, however the mode was set" {
    [ "$(id -u)" = "0" ] || skip "the root check runs first and exits 1 for non-root"
    local m
    for m in guide rollback; do
        # --fix with an id nothing offers: were the gate missing, guide would audit and exit 1.
        run env VPSSEC_ONESHOT=1 VPSSEC_MODE="$m" VPSSEC_MODE_SET=1 \
            "$(_vpssec_repo_root)/vpssec" --lang=en_US --include=ssh --fix=oneshot.none --yes
        [ "$status" -eq 2 ]
        [[ "$output" == *"not available through the one-line runner"* ]]
        [[ "$output" == *"sudo vpssec $m"* ]]
    done
}

@test "the mode menu is not offered under the marker, even with a terminal" {
    _tty_readable() { return 0; }
    _noninteractive() { return 1; }
    unset VPSSEC_MODE VPSSEC_MODE_SET
    export VPSSEC_ONESHOT=1

    select_mode > "$BATS_TEST_TMPDIR/menu" </dev/null
    [ "$VPSSEC_MODE" = "audit" ]
    ! grep -q 'Hardening Guide' "$BATS_TEST_TMPDIR/menu"
}
