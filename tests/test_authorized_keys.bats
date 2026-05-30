#!/usr/bin/env bats
#
# Tests for count_authorized_keys (core/common.sh), the shared helper that both
# the SSH module (lockout precondition) and the users module (key audit) use.
#
# The contract that matters for safety: a COMMENTED-OUT key (`# ssh-ed25519 …`,
# e.g. a rotated-out key left as a note) must NOT count as a usable key — the
# previous inline grep matched it because `#`-then-space let `[[:space:]]ssh-`
# hit, which could let _ssh_fix_disable_password_auth cut off password auth and
# lock the user out, and made the users audit over-report.

load helpers

setup() {
    _vpssec_load
    AK="$BATS_TEST_TMPDIR/authorized_keys"
}

@test "count_authorized_keys: a normal ssh-ed25519 key counts as 1" {
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1 user@host\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "1" ]
}

@test "count_authorized_keys: ssh-rsa key counts" {
    printf 'ssh-rsa AAAAB3NzaC1yc2E user@host\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "1" ]
}

@test "count_authorized_keys: ecdsa key counts (missed by the old ^ssh- check)" {
    printf 'ecdsa-sha2-nistp256 AAAAE2VjZHNh user@host\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "1" ]
}

@test "count_authorized_keys: sk- FIDO key counts" {
    printf 'sk-ssh-ed25519@openssh.com AAAAGnNr user@host\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "1" ]
}

@test "count_authorized_keys: options-prefixed key counts" {
    printf 'from="10.0.0.1",no-pty ssh-ed25519 AAAAC3Nz user@host\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "1" ]
}

@test "count_authorized_keys: a commented-out key does NOT count (the bug)" {
    printf '# ssh-ed25519 AAAAC3NzaC1lZDI1 rotated-out 2026-04\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "0" ]
}

@test "count_authorized_keys: a plain comment does not count" {
    printf '# keys rotated 2026-04, none active\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "0" ]
}

@test "count_authorized_keys: comment + one real key counts as 1" {
    printf '# old key removed\nssh-ed25519 AAAAC3NzaC1lZDI1 user@host\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "1" ]
}

@test "count_authorized_keys: multiple keys count correctly" {
    printf 'ssh-ed25519 AAAAaaa a@h\nssh-rsa AAAAbbb b@h\necdsa-sha2-nistp256 AAAAccc c@h\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "3" ]
}

@test "count_authorized_keys: empty file is 0 (not 0\\n0)" {
    : > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "0" ]
    [ "${#lines[@]}" -eq 1 ]
}

@test "count_authorized_keys: blank/whitespace-only lines do not count" {
    printf '   \n\n\t\n' > "$AK"
    run count_authorized_keys "$AK"
    [ "$output" = "0" ]
}

@test "count_authorized_keys: missing file is 0" {
    run count_authorized_keys "$BATS_TEST_TMPDIR/does-not-exist"
    [ "$status" -eq 0 ]
    [ "$output" = "0" ]
}
