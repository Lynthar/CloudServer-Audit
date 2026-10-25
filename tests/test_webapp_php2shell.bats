#!/usr/bin/env bats
# The php2shell note: which PHP versions are upstream-unfixed, and what the
# unscored finding tells the operator to check, since a distribution may have
# backported the fix under the old version number.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    VPSSEC_PKG_MGR=apt
    _UPLOAD_PROGRESS=""
    _webapp_get_php_config() { [[ "$1" == session.upload_progress.enabled ]] && echo "$_UPLOAD_PROGRESS"; }
    file_package_verified() { echo php8.3-fpm; }
}

_desc() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$STATE_CHECKS_FILE"
}

# A php-fpm whose -v reports version $1, as the only PHP: the host's own
# (GitHub's Ubuntu runner ships one) would otherwise join the note.
_fpm_reports() {
    _vpssec_stub_script php-fpm <<SH
[[ "\$1" == -v ]] && echo "PHP $1 (fpm-fcgi) (built: Oct 21 2026 10:00:00)"
exit 0
SH
    _webapp_php_bins() { echo "$(_vpssec_stub_dir)/php-fpm"; }
}

@test "both the CLI and FPM on PATH are candidate PHP binaries" {
    _vpssec_stub_script php <<<'exit 0'
    _vpssec_stub_script php-fpm <<<'exit 0'
    run _webapp_php_bins
    [[ "$output" == *"$(_vpssec_stub_dir)/php"$'\n'* ]]
    [[ "$output" == *"$(_vpssec_stub_dir)/php-fpm"* ]]
}

@test "versions: every release before its branch's fix is affected, the fix and later are not" {
    local v wrong=""
    for v in 8.2.34 8.3.35 8.4.26 8.5.11 8.1.33 8.0.30 7.4.33 8.1.2-1ubuntu2.22 8.6.0RC3 8.6.0beta2; do
        _webapp_php2shell_affected "$v" || wrong+="[$v not affected] "
    done
    for v in 8.2.35 8.3.36 8.4.27 8.5.12 8.5.13 8.3.36-1+deb13u1 8.6.0RC4 8.6.0 8.7.1; do
        _webapp_php2shell_affected "$v" && wrong+="[$v affected] "
    done
    _webapp_php2shell_affected "not-a-version" && wrong+="[garbage affected] "
    [ -z "$wrong" ] || { echo "$wrong"; false; }
}

@test "an affected PHP is one unscored note naming the binary, its version and the changelog to read" {
    _fpm_reports 8.3.6
    _webapp_audit_php2shell
    run jq -r '.[] | select(.id == "webapp.php2shell") | "\(.status) \(.severity)"' "$STATE_CHECKS_FILE"
    [ "$output" = "failed info" ]
    [ "${CHECK_SCORE_CATEGORY[webapp.php2shell]}" = "info" ]
    [[ "$(_desc webapp.php2shell)" == *"php-fpm 8.3.6."* ]]
    [[ "$(_desc webapp.php2shell)" == *"zgrep -E 'CVE-2026-10961[89]' /usr/share/doc/php8.3-fpm/changelog.Debian.gz"* ]]
}

@test "a fixed PHP gets no note" {
    _fpm_reports 8.3.36
    _webapp_audit_php2shell
    [ -z "$(_desc webapp.php2shell)" ]
}

@test "a branch with no official release is said to have none" {
    _fpm_reports 8.1.2-1ubuntu2.22
    _webapp_audit_php2shell
    [[ "$(_desc webapp.php2shell)" == *"8.1.2-1ubuntu2.22 (no official fix on this branch)"* ]]
}

@test "the stopgap reads on when unset, PHP's default, and off when set to 0" {
    _fpm_reports 8.4.20
    _webapp_audit_php2shell
    [[ "$(_desc webapp.php2shell)" == *"the known path: on, PHP's default."* ]]

    state_init
    _UPLOAD_PROGRESS=0
    _webapp_audit_php2shell
    [[ "$(_desc webapp.php2shell)" == *"the known path: off."* ]]
}

@test "without a distribution changelog the version number is the answer" {
    # Arch builds upstream releases, and an unverified binary has no package to read.
    VPSSEC_PKG_MGR=pacman
    _fpm_reports 8.4.20
    _webapp_audit_php2shell
    [[ "$(_desc webapp.php2shell)" == *"the version number is the answer"* ]]

    state_init
    VPSSEC_PKG_MGR=apt
    file_package_verified() { return 1; }
    _webapp_audit_php2shell
    [[ "$(_desc webapp.php2shell)" == *"the version number is the answer"* ]]
}

@test "rpm hosts are told the rpm changelog query" {
    VPSSEC_PKG_MGR=dnf
    file_package_verified() { echo php-fpm; }
    _fpm_reports 8.3.19
    _webapp_audit_php2shell
    [[ "$(_desc webapp.php2shell)" == *"rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'"* ]]
}
