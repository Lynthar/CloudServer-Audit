#!/usr/bin/env bats
# --json-only reserves stdout for the JSON document. A question, and the note
# it depends on (a rescue port, the rules about to be enforced), must still
# reach the operator's terminal, and must never land in that document.

load helpers.bash
bats_require_minimum_version 1.5.0

setup() {
    _vpssec_load
    command -v script >/dev/null || skip "script(1) not installed"
}

# Run $1 (bash, after common.sh is sourced with --json-only on) on a real
# terminal whose input stays open and silent. Prints the terminal transcript,
# then "stdout=[...]" holding only what the snippet wrote to stdout.
_on_terminal() {
    cat > "$BATS_TEST_TMPDIR/probe.sh" <<SH
VPSSEC_JSON_ONLY=1
source "$(_vpssec_repo_root)/core/common.sh"
_log_file=/dev/null
VPSSEC_CONFIRM_TIMEOUT=1
out=\$( $1 ) || true
echo "stdout=[\$out]"
SH
    bash -c "sleep 3 | script -qec 'bash $BATS_TEST_TMPDIR/probe.sh' /dev/null"
}

@test "confirm_critical under --json-only: the warning reaches the terminal, stdout stays empty" {
    run _on_terminal 'confirm_critical "rescue on port 2222"'
    [[ "$output" == *"rescue on port 2222"* ]]
    [[ "$output" == *"[yes/NO]"* ]]
    [[ "$output" == *"stdout=[]"* ]]
}

@test "confirm under --json-only without --yes: the question reaches the terminal, not stdout" {
    run _on_terminal 'confirm "Continue anyway?"'
    [[ "$output" == *"Continue anyway?"* ]]
    [[ "$output" == *"stdout=[]"* ]]
}

@test "print_error under --json-only goes to stderr, not nowhere and not stdout" {
    VPSSEC_JSON_ONLY=1
    run --separate-stderr print_error "boom"
    [ -z "$output" ]
    [[ "$stderr" == *boom* ]]
}
