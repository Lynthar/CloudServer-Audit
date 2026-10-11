#!/usr/bin/env bats
# The PATH vpssec runs its commands with. cron starts jobs with /usr/bin:/bin,
# where sysctl, sshd, ufw and nft are absent, and every check that asks for one
# read "not installed". The sbin directories are appended; nothing is reordered.

load helpers.bash

# Run the real entry script with PATH=$1 (after a probe directory) and print the
# PATH its first command saw: a `tr` stand-in that records it, then runs tr.
_path_seen_by_vpssec() {
    local probe="$BATS_TEST_TMPDIR/probe" log="$BATS_TEST_TMPDIR/path.log" real_tr
    real_tr=$(command -v tr)
    mkdir -p "$probe"
    printf '#!/bin/sh\nprintf "%%s\\n" "$PATH" >> %q\nexec %q "$@"\n' "$log" "$real_tr" > "$probe/tr"
    chmod +x "$probe/tr"
    env PATH="$probe:$1" bash "$(_vpssec_repo_root)/vpssec" --version >/dev/null
    head -1 "$log"
}

@test "PATH: cron's /usr/bin:/bin gains the sbin directories, at the end" {
    run _path_seen_by_vpssec "/usr/bin:/bin"
    [ "$status" -eq 0 ]
    [ "$output" = "$BATS_TEST_TMPDIR/probe:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin" ]
}

@test "PATH: directories already there keep their place and are not repeated" {
    run _path_seen_by_vpssec "/sbin:/usr/bin:/bin:/usr/sbin"
    [ "$status" -eq 0 ]
    [ "$output" = "$BATS_TEST_TMPDIR/probe:/sbin:/usr/bin:/bin:/usr/sbin:/usr/local/sbin" ]
}

@test "PATH: a full PATH is left exactly as it was" {
    local full="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    run _path_seen_by_vpssec "$full"
    [ "$status" -eq 0 ]
    [ "$output" = "$BATS_TEST_TMPDIR/probe:$full" ]
}
