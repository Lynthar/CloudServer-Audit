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

# ==============================================================================
# Fixture for testing *_fix_* functions
# ==============================================================================
#
# The fix functions are the most dangerous code in the project — they are
# the part that actually rewrites /etc — and were also the least covered:
# of 56 fix implementations only 6 were referenced by any test. They resist
# the plain `_vpssec_load` treatment for two reasons:
#
#   1. they shell out to apt-get / systemctl / docker / nginx / sshd, none
#      of which may run for real in a test; and
#   2. they write to absolute paths under /etc.
#
# The two helpers below address exactly those. Nothing here mocks vpssec's
# own functions — `backup_file`, `write_file_atomic` and friends run for
# real against a redirected tree, so a test still exercises the atomic
# write, the backup session and the created-file manifest.
#
# Typical use:
#
#     setup() {
#         _vpssec_load
#         source "$(_vpssec_repo_root)/modules/logging.sh"
#         etc=$(_vpssec_fake_etc)
#         LOGROTATE_CONF="$etc/logrotate.conf"      # module path var
#         _vpssec_stub apt-get 100                  # make the install fail
#     }
#
#     @test "install failure is propagated" {
#         run _logging_fix_setup_logrotate
#         [ "$status" -eq 1 ]
#         [ ! -f "$LOGROTATE_CONF" ]
#     }

# Directory holding this test's command stubs.
_vpssec_stub_dir() {
    printf '%s\n' "$BATS_TEST_TMPDIR/stubbin"
}

# Create the stub directory, put it FIRST on PATH, and reset the call log.
# Idempotent: calling it again keeps existing stubs and log entries.
_vpssec_stub_init() {
    local dir
    dir=$(_vpssec_stub_dir)
    mkdir -p "$dir"
    export VPSSEC_STUB_LOG="$BATS_TEST_TMPDIR/stub-calls.log"
    [[ -f "$VPSSEC_STUB_LOG" ]] || : > "$VPSSEC_STUB_LOG"
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) export PATH="$dir:$PATH" ;;
    esac
}

# Stub COMMAND with a fixed exit status and optional stdout.
#
#   _vpssec_stub systemctl            # succeeds, prints nothing
#   _vpssec_stub apt-get 100          # exits 100
#   _vpssec_stub docker 0 false       # exits 0, prints "false"
#
# `command -v COMMAND` also starts succeeding, which is how tests steer
# the `check_command` guards inside the fixes.
_vpssec_stub() {
    local cmd="$1" rc="${2:-0}" out="${3:-}"
    _vpssec_stub_init
    {
        printf '#!/usr/bin/env bash\n'
        printf 'printf "%%s %%s\\n" %q "$*" >> %q\n' "$cmd" "$VPSSEC_STUB_LOG"
        [[ -n "$out" ]] && printf 'printf "%%s\\n" %q\n' "$out"
        printf 'exit %d\n' "$rc"
    } > "$(_vpssec_stub_dir)/$cmd"
    chmod +x "$(_vpssec_stub_dir)/$cmd"
}

# Stub COMMAND with an arbitrary body read from stdin, for the cases where
# the answer depends on argv (`docker info --format ...` vs `docker ps`).
# Call logging is prepended for you; the body sees the original "$@".
#
#     _vpssec_stub_script docker <<'SH'
#     case "$*" in
#         *LiveRestoreEnabled*) echo false ;;
#         *) echo "" ;;
#     esac
#     SH
_vpssec_stub_script() {
    local cmd="$1"
    _vpssec_stub_init
    {
        printf '#!/usr/bin/env bash\n'
        printf 'printf "%%s %%s\\n" %q "$*" >> %q\n' "$cmd" "$VPSSEC_STUB_LOG"
        cat
    } > "$(_vpssec_stub_dir)/$cmd"
    chmod +x "$(_vpssec_stub_dir)/$cmd"
}

# All recorded stub invocations, one "<cmd> <argv>" line per call.
_vpssec_stub_calls() {
    cat "${VPSSEC_STUB_LOG:-/dev/null}" 2>/dev/null || true
}

# True if COMMAND ran. With a second argument, true only if some
# invocation's argv matched that extended regex — use it to assert
# intent ("apt-get install ran") rather than mere invocation.
_vpssec_stub_called() {
    local cmd="$1" pattern="${2:-}"
    [[ -f "${VPSSEC_STUB_LOG:-}" ]] || return 1
    if [[ -n "$pattern" ]]; then
        grep -qE "^${cmd} .*${pattern}" "$VPSSEC_STUB_LOG"
    else
        grep -qE "^${cmd}( |$)" "$VPSSEC_STUB_LOG"
    fi
}

# Per-test stand-in for /etc. Echoes its path; the caller points the
# module's own path variables at it (LOGROTATE_CONF, DOCKER_DAEMON_JSON,
# ...). Kept separate from _vpssec_isolate_dirs because those are vpssec's
# OWN directories, whereas this is the system tree a fix writes into.
_vpssec_fake_etc() {
    local dir="$BATS_TEST_TMPDIR/etc"
    mkdir -p "$dir"
    printf '%s\n' "$dir"
}

# Assert that COMMAND fails. Use this instead of `! command`.
#
# Bash exempts a command preceded by `!` from errexit and the ERR trap,
# which is how bats detects a failed assertion. So `! command` only ends
# the test when it happens to be the LAST statement in the test body —
# anywhere else a failed assertion is silently discarded and the test
# passes vacuously. Mutation testing caught one such assertion in the ufw
# suite; the same shape was present in five other files.
#
#     _vpssec_refute _vpssec_stub_called ufw 'enable'
#     _vpssec_refute grep -q accept_ra "$VPSSEC_SYSCTL_CONF"
_vpssec_refute() {
    if "$@"; then
        printf 'expected to fail but succeeded: %s\n' "$*" >&2
        return 1
    fi
    return 0
}

# Open a backup session rooted in the per-test backups dir, so a fix's
# backup_file calls land somewhere assertable and the created-file
# manifest (.vpssec_created) is exercised the way execute_plan does it.
#
# SETS $VPSSEC_BACKUP_SESSION — call it plainly, never as `s=$(...)`.
# Command substitution runs it in a subshell where the export dies with
# the subshell, and the fix under test then silently records nothing.
_vpssec_begin_backup_session() {
    VPSSEC_BACKUP_SESSION="${VPSSEC_BACKUPS}/test_session"
    mkdir -p "$VPSSEC_BACKUP_SESSION"
    export VPSSEC_BACKUP_SESSION
}
