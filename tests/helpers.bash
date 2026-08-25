# Shared bats helpers, sourced by every test file here: locates the repo root,
# gives each test isolated state/log/backup directories, and sources the
# production code. Set per-test environment overrides before _vpssec_load.

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

# Source production code; extra args layer more files (core/state.sh,
# core/security_levels.sh) on top of common.sh. Export any environment
# override BEFORE calling this — common.sh reads them at source time.
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

    # common.sh hard-codes path vars from VPSSEC_ROOT (no `:-`), so isolation
    # must come AFTER sourcing it and BEFORE the layered files, which re-derive
    # STATE_*_FILE from these at their own source time.
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

# Fixture for *_fix_* functions: they shell out to apt-get/systemctl/docker and
# write absolute /etc paths, so tests stub the commands and redirect the
# module's path variables. Never mock backup_file or write_file_atomic.

# The real chmod, resolved before any stub can shadow it. The helpers below
# chmod +x every stub they write, so routing `chmod` through a stub is
# self-defeating: bash skips the non-executable stub and runs the real one.
_VPSSEC_REAL_CHMOD="$(command -v chmod || echo /bin/chmod)"

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
    # Drop bash's command hash table: prepending to PATH does NOT redirect a
    # command already resolved in this shell, so a stub written after the test
    # ran that command never fires and the test passes against the real one.
    hash -r 2>/dev/null || true
}

# Stub COMMAND with a fixed exit status and optional stdout, e.g.
# `_vpssec_stub apt-get 100` or `_vpssec_stub docker 0 false`. `command -v`
# also starts succeeding — that is how tests steer check_command guards.
_vpssec_stub() {
    local cmd="$1" rc="${2:-0}" out="${3:-}"
    _vpssec_stub_init
    {
        printf '#!/usr/bin/env bash\n'
        printf 'printf "%%s %%s\\n" %q "$*" >> %q\n' "$cmd" "$VPSSEC_STUB_LOG"
        [[ -n "$out" ]] && printf 'printf "%%s\\n" %q\n' "$out"
        printf 'exit %d\n' "$rc"
    } > "$(_vpssec_stub_dir)/$cmd"
    "$_VPSSEC_REAL_CHMOD" +x "$(_vpssec_stub_dir)/$cmd"
}

# Stub COMMAND with a body read from stdin, for when the answer depends on
# argv (`docker info --format ...` vs `docker ps`). Call logging is prepended
# for you; the body sees the original "$@".
_vpssec_stub_script() {
    local cmd="$1"
    _vpssec_stub_init
    {
        printf '#!/usr/bin/env bash\n'
        printf 'printf "%%s %%s\\n" %q "$*" >> %q\n' "$cmd" "$VPSSEC_STUB_LOG"
        cat
    } > "$(_vpssec_stub_dir)/$cmd"
    "$_VPSSEC_REAL_CHMOD" +x "$(_vpssec_stub_dir)/$cmd"
}

# Make `check_command NAME` answer "not installed" whatever the host ships;
# call it AFTER _vpssec_load, which defines the real one. Stubbing does the
# OPPOSITE — it puts a binary on PATH, so check_command starts succeeding.
#
# A test relying on genuine absence instead asserts what the container ships,
# and stops covering its branch the moment it runs somewhere that has the
# binary. Stub the binary alongside this, so "never called" refutes something.
declare -gA _VPSSEC_ABSENT_CMDS=()
_vpssec_absent_command() {
    _VPSSEC_ABSENT_CMDS["$1"]="${2:-}"

    check_command() {
        local marker
        if [[ -n "${_VPSSEC_ABSENT_CMDS[$1]+set}" ]]; then
            # A FILE, not a closure: closing over a `local` captures the NAME,
            # out of scope by call time, so `set -u` aborts the guard — which
            # no "it refused" assertion can tell apart from a real refusal.
            marker="${_VPSSEC_ABSENT_CMDS[$1]}"
            # No marker: absent for good. With one: absent until it appears,
            # after which the normal PATH lookup (i.e. the stub) answers.
            [[ -n "$marker" && -e "$marker" ]] || return 1
        fi
        command -v "$1" &>/dev/null
    }
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

# Per-test stand-in for /etc; the caller points the module's own path variables
# at it. Separate from _vpssec_isolate_dirs, which isolates vpssec's OWN
# directories rather than the system tree a fix writes into.
_vpssec_fake_etc() {
    local dir="$BATS_TEST_TMPDIR/etc"
    mkdir -p "$dir"
    printf '%s\n' "$dir"
}

# The created-file contract. `.vpssec_created` is the ONLY thing backup_restore
# consults when deciding what a rollback deletes, so a fix that creates a file
# without registering it leaves it behind after the operator undid the plan.

# Every regular file and symlink under DIR, one "<type> <path>" line each.
# `find -printf` would be shorter but is GNU-only; this stays portable to the
# macOS dev checkout where much of the suite still runs.
_vpssec_tree_snapshot() {
    local dir="$1"
    {
        find "$dir" -type f -print 2>/dev/null | sed 's|^|f |'
        find "$dir" -type l -print 2>/dev/null | sed 's|^|l |'
    } | sort
}

# Assert, for everything that appeared under DIR since SNAPSHOT, that regular
# files are tracked and symlinks are NOT — backup_restore skips a tracked
# symlink and drags its return code to 2, reporting a partial restore.
#
# This asserts the OUTCOME, not the call shape: whatever appeared on disk must
# match the manifest, whichever primitive wrote it. A grep for the calling
# idiom can only prove one spelling is gone, never that the defect is.
_vpssec_assert_created_contract() {
    local dir="$1" before="$2" rc=0
    local manifest="${VPSSEC_BACKUP_SESSION:-/nonexistent}/${VPSSEC_CREATED_MANIFEST:-.vpssec_created}"
    local after kind path
    after=$(_vpssec_tree_snapshot "$dir")

    while read -r kind path; do
        [[ -n "${path:-}" ]] || continue
        case "$kind" in
            f)
                if ! grep -qxF "$path" "$manifest" 2>/dev/null; then
                    printf 'created but not tracked in %s: %s\n' \
                        "$VPSSEC_CREATED_MANIFEST" "$path" >&2
                    rc=1
                fi
                ;;
            l)
                if grep -qxF "$path" "$manifest" 2>/dev/null; then
                    printf 'symlink must not be tracked (rollback skips it and returns 2): %s\n' \
                        "$path" >&2
                    rc=1
                fi
                ;;
        esac
    done < <(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))

    return "$rc"
}

# Assert that COMMAND fails. Use this instead of `! command`: bash exempts a
# `!`-prefixed command from errexit and the ERR trap, so `! command` only ends
# the test as the LAST statement — anywhere else it passes vacuously.
_vpssec_refute() {
    if "$@"; then
        printf 'expected to fail but succeeded: %s\n' "$*" >&2
        return 1
    fi
    return 0
}

# Open a backup session in the per-test backups dir so a fix's backup_file
# calls land somewhere assertable and .vpssec_created is exercised the way
# execute_plan does it.
#
# SETS $VPSSEC_BACKUP_SESSION — call it plainly, never as `s=$(...)`: command
# substitution runs it in a subshell, the export dies there, and the fix under
# test then silently records nothing.
#
# The YYYYMMDD_HHMMSS name is required, not cosmetic: backup_restore refuses
# any other timestamp shape, so a differently-named session can be written but
# never rolled back. Pass VPSSEC_TEST_BACKUP_SESSION_TS to backup_restore.
VPSSEC_TEST_BACKUP_SESSION_TS="20260101_000000"
_vpssec_begin_backup_session() {
    VPSSEC_BACKUP_SESSION="${VPSSEC_BACKUPS}/${VPSSEC_TEST_BACKUP_SESSION_TS}"
    mkdir -p "$VPSSEC_BACKUP_SESSION"
    export VPSSEC_BACKUP_SESSION
}
