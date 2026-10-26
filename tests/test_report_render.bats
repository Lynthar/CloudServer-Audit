#!/usr/bin/env bats
# The reports people read say what summary.json says: every check lands somewhere,
# an unfinished scan says so before the score, advice runs on this host, each
# finding says whether it is scored, and host data carries no control bytes.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh core/engine.sh core/report.sh
    i18n_load en_US
    state_init
    md="$BATS_TEST_TMPDIR/summary.md"
}

_on_debian() { VPSSEC_DISTRO_FAMILY=debian; is_debian_based() { return 0; }; }
_on_rocky()  { VPSSEC_DISTRO_FAMILY=rhel;   is_debian_based() { return 1; }; }

_add() { state_add_check "$(create_check_json "$@")"; }

# The lines of Markdown section "## $1", up to the next "## " heading.
_md_section_text() {
    awk -v h="## $1" '$0 == h {f=1; next} f && /^## / {exit} f' "$md"
}

# ---- every check lands somewhere ------------------------------------------------

@test "markdown: a crashed module is stated before the score, not dropped" {
    _add backup.ok backup low passed "Backup ok" "" "" ""
    _add _internal.module_failed _internal low failed "Module backup did not complete" \
        "backup_audit returned 1" "" ""
    report_generate_markdown "$md" >/dev/null
    local block_line score_line
    block_line=$(grep -n '^## Incomplete scan' "$md" | cut -d: -f1)
    score_line=$(grep -n 'Security Score' "$md" | cut -d: -f1)
    [ -n "$block_line" ] && (( block_line < score_line ))
    grep -q 'Module backup did not complete' "$md"
}

@test "markdown: a failure of severity info is listed with the lows it is counted in" {
    # webapp.other_webserver (caddy and friends) was counted as low and shown nowhere.
    _add webapp.other_webserver webapp info failed "Other web server: caddy" "" "" ""
    _add ssh.weak_algorithms ssh low failed "Weak algorithms" "" "" ""
    report_generate_markdown "$md" >/dev/null
    _md_section_text 'Low Severity Issues' | grep -q 'Other web server: caddy'
    local counted listed
    counted=$(grep -F 'Low Severity Issues |' "$md" | grep -oE '[0-9]+ \|$' | tr -dc 0-9)
    listed=$(_md_section_text 'Low Severity Issues' | grep -c '^#### ')
    [ "$counted" = "$listed" ]
}

@test "markdown: a finding without a desc, a suggestion or a fix gets no empty label" {
    # update.updates_available has no desc when none of the updates is a security one.
    _add update.updates_available update low failed "9 updates available" "" "Apply pending updates" ""
    _add networking.public_listeners_present networking medium failed "4 listeners" "tcp/8443" "" ""
    report_generate_markdown "$md" >/dev/null
    _vpssec_refute grep -qE '^- \*\*(Info|Recommendations|Fix ID)\*\*: *$' "$md"
    grep -Fqx -- '- **Recommendations**: Apply pending updates' "$md"
    grep -Fqx -- '- **Info**: tcp/8443' "$md"
    grep -Fqx -- '- **Fix ID**: N/A' "$md"
}

@test "terminal: a crashed module is stated above the score, an info failure drawn as low" {
    VPSSEC_QUIET_SCAN=0
    _add _internal.module_failed _internal low failed "Module backup did not complete" "" "" ""
    _add webapp.other_webserver webapp info failed "Other web server: caddy" "" "" ""
    run report_print_details
    grep -q '○ Other web server: caddy' <<<"$output"
    run report_print_summary
    local block_line score_line
    block_line=$(grep -n 'Incomplete scan' <<<"$output" | cut -d: -f1)
    score_line=$(grep -n 'Security Score' <<<"$output" | cut -d: -f1)
    [ -n "$block_line" ] && (( block_line < score_line ))
    grep -q 'Module backup did not complete' <<<"$output"
}

@test "check_emit: a status outside passed|failed is not recorded and marks the module" {
    # kernel.container_detected was emitted with status "info": in no bucket,
    # absent from the Markdown, drawn in the terminal as a low failure.
    check_emit kernel.container_detected low info desc="container"
    [ "$(jq length "$STATE_CHECKS_FILE")" = "0" ]
    [[ " ${VPSSEC_MODULES_FAILED[*]} " == *" kernel "* ]]
}

# ---- runnable advice ---------------------------------------------------------------

@test "next steps: an audit-only distro is not told to run guide or rollback" {
    _on_rocky
    _add users.uid0 users high failed "Extra UID 0" "" "" "users.review"
    mkdir -p "$VPSSEC_BACKUPS/20260501_120000"
    report_generate_markdown "$md" >/dev/null
    _vpssec_refute grep -q 'vpssec guide' "$md"
    _vpssec_refute grep -q 'vpssec rollback' "$md"
    grep -q 'audit-only: apply each finding' "$md"
}

@test "next steps: rollback is offered only when this install holds a backup" {
    _on_debian
    _add users.uid0 users high failed "Extra UID 0" "" "" "users.review"
    report_generate_markdown "$md" >/dev/null
    grep -q 'vpssec guide --include=users' "$md"
    _vpssec_refute grep -q 'vpssec rollback' "$md"

    mkdir -p "$VPSSEC_BACKUPS/20260501_120000"
    report_generate_markdown "$md" >/dev/null
    grep -q 'vpssec rollback' "$md"
}

@test "next steps: a one-line run is told to install vpssec before running guide" {
    _on_debian
    _add users.uid0 users high failed "Extra UID 0" "" "" "users.review"
    VPSSEC_ONESHOT=1 report_generate_markdown "$md" >/dev/null
    local install guide
    install=$(grep -n '/main/install.sh | sudo bash$' "$md" | cut -d: -f1)
    guide=$(grep -n 'vpssec guide --include=users' "$md" | cut -d: -f1)
    [ -n "$install" ] && (( install < guide ))
}

@test "terminal: the partial-score line names the modules that ran, not the raw flag" {
    VPSSEC_QUIET_SCAN=0
    _add ssh.ok ssh low passed "ok" "" "" ""
    module_get_enabled() { printf '%s\n' preflight cloud timezone ssh; }
    VPSSEC_EXCLUDE=malware
    run report_print_summary
    _vpssec_refute grep -q '\[all\]' <<<"$output"
    grep -q '\[preflight,cloud,timezone,ssh\]' <<<"$output"
}

# ---- scored or not, at the finding ----------------------------------------------------

@test "json: each check says whether it is scored" {
    _add ssh.password_auth_enabled ssh high failed "Password auth" "" "" ""
    _add users.faillog_disabled users low failed "Faillog off" "" "" ""
    report_generate_json "$BATS_TEST_TMPDIR/summary.json" >/dev/null
    jq -e '.checks[] | select(.id == "ssh.password_auth_enabled") | .scored == true' \
        "$BATS_TEST_TMPDIR/summary.json"
    jq -e '.checks[] | select(.id == "users.faillog_disabled") | .scored == false' \
        "$BATS_TEST_TMPDIR/summary.json"
}

@test "markdown: an unscored finding is marked at its heading; the table lists severities only" {
    _add ssh.password_auth_enabled ssh high failed "Password auth" "" "" ""
    _add users.faillog_disabled users low failed "Faillog off" "" "" ""
    report_generate_markdown "$md" >/dev/null
    grep -qx '#### Faillog off _(not scored)_' "$md"
    grep -qx '#### Password auth' "$md"
    grep -q '^| Severity | Count |$' "$md"
    _vpssec_refute grep -q 'Advisory' "$md"
}

# ---- control bytes ----------------------------------------------------------------

@test "check_emit: control bytes in host data reach the report and log as visible text" {
    # A file name holding ESC ] 0; ... BEL or ESC [2K rewrote the screen of
    # whoever ran cat on summary.md or tail on the log.
    local evil=$'/tmp/x\033]0;owned\a\033[2K\rgone'
    check_emit filesystem.suid_unusual low failed desc="$evil"
    log_warn "found $evil"
    report_generate_markdown "$md" >/dev/null
    _vpssec_refute grep -q $'[\033\a\r]' "$md"
    grep -qF '/tmp/x\x1b]0;owned\x07\x1b[2K\x0dgone' "$md"
    _vpssec_refute grep -q $'[\033\a\r]' "$VPSSEC_LOGS/vpssec.log"
}

# ---- colour codes and column width ------------------------------------------------------

@test "terminal: a long CJK title is cut between characters under the C locale too" {
    # bash slices by bytes there, and half a character is not UTF-8 any more.
    command -v iconv >/dev/null || skip "iconv not installed"
    local LC_ALL=C
    _add users.mm users low failed "密码策略过弱：最短长度、复杂度与历史记录都没有按建议配置，账户容易被猜中" "" "" ""
    COLUMNS=100 run report_print_details
    [ "$status" -eq 0 ]
    [[ "$output" == *"密码策略过弱"*".."* ]]
    iconv -f UTF-8 -t UTF-8 <<<"$output" >/dev/null
}

@test "width: colour codes count as nothing, the text around them as itself" {
    [ "$(_display_width '\033[1m\033[0;36mEnvironment Preflight\033[0m')" = "21" ]
    [ "$(_display_width '  \033[0;32m✓\033[0m Kernel param missing')" = "24" ]
    [ "$(_display_width $'\033[0;31mmmm\033[0m')" = "3" ]
}

@test "terminal: with colour on, the two columns keep one separator column" {
    # The glob stripped from the first colour code to the last "m", so each row
    # was measured short and the │ wandered across eight columns.
    BOLD='\033[1m' CYAN='\033[0;36m' GREEN='\033[0;32m' BLUE='\033[0;34m' NC='\033[0m' DIM='\033[2m'
    _add users.ok users low passed "No empty passwords" "" "" ""
    _add users.mm users low failed "Umask too permissive" "" "" ""
    _add ssh.ok ssh low passed "Pubkey enabled" "" "" ""
    _add ssh.mm ssh low failed "MaxAuthTries high" "" "" ""
    COLUMNS=100 run report_print_details
    # Measured after stripping the colour codes, so the measure is not the
    # function under test: plain text with one-cell glyphs only.
    local line cols=()
    while IFS= read -r line; do
        [[ "$line" == *│* ]] && cols+=("$(_display_width "${line%%│*}")")
    done < <(sed 's/\x1b\[[0-9;]*m//g' <<<"$output")
    (( ${#cols[@]} >= 3 ))
    [ "$(printf '%s\n' "${cols[@]}" | sort -u | wc -l)" -eq 1 ]
}
