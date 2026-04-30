# Shared bats helpers for vpssec unit tests.
#
# Sourced by every test file in this directory. Responsible for:
#   - Locating the project root regardless of where bats was invoked from
#   - Providing per-test isolated state / log / backup directories so
#     functions that touch the filesystem don't pollute the dev tree
#   - Sourcing the production code under test
#
# Tests should call _vpssec_load to bring the production functions into
# scope after setting any per-test environment overrides.

_vpssec_repo_root() {
    # tests/ lives directly under the repo root. BATS_TEST_DIRNAME points
    # at the directory of the currently-running .bats file.
    cd "$BATS_TEST_DIRNAME/.." && pwd
}

_vpssec_isolate_dirs() {
    # Per-test scratch directories. BATS_TEST_TMPDIR is unique per test
    # and cleaned up automatically by bats.
    export VPSSEC_STATE="$BATS_TEST_TMPDIR/state"
    export VPSSEC_REPORTS="$BATS_TEST_TMPDIR/reports"
    export VPSSEC_BACKUPS="$BATS_TEST_TMPDIR/backups"
    export VPSSEC_LOGS="$BATS_TEST_TMPDIR/logs"
    export VPSSEC_TEMPLATES="$BATS_TEST_TMPDIR/templates"
    mkdir -p "$VPSSEC_STATE" "$VPSSEC_REPORTS" "$VPSSEC_BACKUPS" \
             "$VPSSEC_LOGS" "$VPSSEC_TEMPLATES"
}

# Source production code. Pass extra files as args to layer additional
# sources (state.sh, security_levels.sh) on top of common.sh.
#
#   _vpssec_load                                # common.sh only
#   _vpssec_load core/state.sh                  # common.sh + state.sh
#   _vpssec_load core/security_levels.sh        # common.sh + security_levels.sh
_vpssec_load() {
    local root
    root=$(_vpssec_repo_root)

    # Force English / no-color first; common.sh respects these via
    # the `${VAR:-default}` defaults at its config-vars block.
    export VPSSEC_LANG=en_US
    export VPSSEC_COLOR=0
    export VPSSEC_JSON_ONLY=0
    export VPSSEC_QUIET_SCAN=1   # silence print_* during tests

    # common.sh sets `set -euo pipefail` at top. That's already what
    # tests expect; bats's `run` isolates the failure semantics.
    # shellcheck source=/dev/null
    source "$root/core/common.sh"

    # common.sh hard-codes path vars from VPSSEC_ROOT (no `:-`). We
    # need test-isolated paths instead, so override AFTER sourcing.
    # state.sh and other consumers re-derive STATE_*_FILE from these
    # at their own source time, so the order matters: paths first,
    # then layered files.
    _vpssec_isolate_dirs

    local extra
    for extra in "$@"; do
        # shellcheck source=/dev/null
        source "$root/$extra"
    done
}

# Skip the current test if the host doesn't ship GNU realpath.
# vpssec is documented as Linux-only; on macOS dev machines we still
# want most tests to pass, so paths-related ones use this guard.
_vpssec_require_gnu_realpath() {
    if ! realpath -m / >/dev/null 2>&1; then
        skip "GNU realpath (-m) not available on this host"
    fi
}
