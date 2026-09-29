#!/usr/bin/env bats
# run.sh and install.sh verify a release the same way. An unreachable sigstore
# and a tampered file fail cosign with the same status, so a failure is retried
# and the final one shows cosign's own error rather than a guessed cause.

load helpers.bash

setup() {
    _vpssec_load

    COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
    CALLS="$BATS_TEST_TMPDIR/cosign-calls"
    SLEEPS="$BATS_TEST_TMPDIR/sleeps"

    print_warn()  { echo "[WARN] $*"; }
    print_error() { echo "[ERROR] $*"; }
    sleep() { echo x >> "$SLEEPS"; }
}

_load_from() {
    eval "$(awk '/^_verify_release_signature\(\)/,/^}/' "$(_vpssec_repo_root)/$1")"
    rm -f "$CALLS" "$SLEEPS"
}

_count() {
    [ -f "$1" ] || { echo 0; return; }
    wc -l < "$1" | tr -d ' '
}

# Fails the first $FAILS calls the way cosign does — a TUF warning, then the
# real error last — plus a stdout line, and passes after that. FAILS is a
# global: the stub runs after this function has returned.
_cosign_fails_first() {
    FAILS="$1"
    cosign() {
        echo x >> "$CALLS"
        local n; n=$(_count "$CALLS")
        (( n > FAILS )) && return 0
        echo "WARNING: Could not fetch trusted_root.json from the TUF repository" >&2
        echo "error during command execution: none of the expected identities matched (call $n)" >&2
        echo "stdout-noise"
        return 1
    }
}

@test "a verification that passes at once says nothing and tries once" {
    _cosign_fails_first 0
    for f in run.sh install.sh; do
        _load_from "$f"
        run _verify_release_signature a.tar.gz a.tar.gz.sig.json id
        [ "$status" -eq 0 ]
        [ -z "$output" ]
        [ "$(_count "$CALLS")" -eq 1 ]
    done
}

@test "a transient failure is retried and the release is then accepted" {
    _cosign_fails_first 2
    for f in run.sh install.sh; do
        _load_from "$f"
        run _verify_release_signature a.tar.gz a.tar.gz.sig.json id
        [ "$status" -eq 0 ]
        [ "$(_count "$CALLS")" -eq 3 ]
        [[ "$output" == *"attempt 1 of 3"* ]]
        [[ "$output" == *"attempt 2 of 3"* ]]
    done
}

@test "a persistent failure is refused after three attempts, with no wait after the last" {
    _cosign_fails_first 99
    for f in run.sh install.sh; do
        _load_from "$f"
        run _verify_release_signature a.tar.gz a.tar.gz.sig.json id
        [ "$status" -eq 1 ]
        [ "$(_count "$CALLS")" -eq 3 ]
        [ "$(_count "$SLEEPS")" -eq 2 ]
        [[ "$output" == *"Could not verify the release signature — refusing to"* ]]
    done
}

@test "the refusal quotes cosign's final error line and nothing else it printed" {
    _cosign_fails_first 99
    for f in run.sh install.sh; do
        _load_from "$f"
        run _verify_release_signature a.tar.gz a.tar.gz.sig.json id
        [ "$status" -eq 1 ]
        [[ "$output" == *"cosign: error during command execution: none of the expected identities matched (call 3)"* ]]
        # The TUF warning appears even when the real failure is an identity
        # mismatch, so quoting it under the "unreachable" hint would mislead.
        [[ "$output" != *"trusted_root.json"* ]]
        [[ "$output" != *"stdout-noise"* ]]
    done
}
