#!/usr/bin/env bats
# Regression tests for the alerts fix: the interactivity gate and every write
# whose status must not be discarded. These fixes write into vpssec's own
# state/templates trees, never /etc, and the generated artifacts stay inert.

load helpers.bash

setup() {
    _vpssec_load
    # Without this, i18n echoes the KEY, and a grep for the key name passes
    # whether or not the string exists in either language file.
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/alerts.sh"

    # Most assertions here are on printed messages; helpers.bash silences
    # print_* by default.
    VPSSEC_QUIET_SCAN=0

    # ALERTS_CONFIG_FILE / ALERTS_TEMPLATES_DIR are derived from VPSSEC_STATE
    # and VPSSEC_TEMPLATES at source time, and _vpssec_load has already pointed
    # both at this test's tmpdir.

    # A fix that reached for the real system would have to go through one of
    # these; stub them so "never called" is a real refutation.
    _vpssec_stub systemctl
    _vpssec_stub crontab

    etc=$(_vpssec_fake_etc)

    # Neither flag set unless a test says so.
    VPSSEC_YES=0
    VPSSEC_JSON_ONLY=0
}

# ---- the interactivity gate -----------------------------------------

@test "should_prompt: a readable terminal and no --yes prompts" {
    # The test that kills a reversion to `[[ -t 0 ]]`: stdin is not a terminal
    # under bats, so the old gate answers "do not prompt" here while the
    # correct one answers "prompt".
    _tty_readable() { return 0; }

    _alerts_should_prompt
}

@test "should_prompt: --yes refuses even when a terminal is readable" {
    _tty_readable() { return 0; }
    VPSSEC_YES=1

    _vpssec_refute _alerts_should_prompt
}

@test "should_prompt: --json-only refuses even when a terminal is readable" {
    _tty_readable() { return 0; }
    VPSSEC_JSON_ONLY=1

    _vpssec_refute _alerts_should_prompt
}

@test "should_prompt: no readable terminal refuses even without --yes" {
    _tty_readable() { return 1; }

    _vpssec_refute _alerts_should_prompt
}

@test "setup_config: the non-interactive path writes the template and never prompts" {
    _alerts_should_prompt() { return 1; }

    run _alerts_fix_setup_config
    [ "$status" -eq 0 ]
    # The template wording, not the "saved" wording — they are the two
    # branches' only externally visible difference.
    [[ "$output" == *"Alert configuration template created"* ]]
    [[ "$output" == *"Edit the file to add your webhook URL"* ]]
    _vpssec_refute grep -q "Alert configuration saved" <<<"$output"
}

@test "setup_config: the non-interactive template has empty webhook and email" {
    _alerts_should_prompt() { return 1; }

    run _alerts_fix_setup_config
    [ "$status" -eq 0 ]
    jq -e '.webhook_url == ""' "$ALERTS_CONFIG_FILE"
    jq -e '.email == ""' "$ALERTS_CONFIG_FILE"
    jq -e '.throttle_minutes == 5' "$ALERTS_CONFIG_FILE"
    jq -e '.events.ssh_login_failure == true' "$ALERTS_CONFIG_FILE"
}

# ---- the config write -----------------------------------------------

@test "alerts_fix: an unknown fix_id fails rather than silently doing nothing" {
    run alerts_fix alerts.not_a_real_fix
    [ "$status" -eq 1 ]
}

@test "setup_config: an existing permissive alerts.json is tightened to 0600" {
    # The trailing chmod is not redundant with the umask around the write:
    # the umask only governs a file being created, and this one already
    # exists at 0644 from an older vpssec.
    _alerts_should_prompt() { return 1; }
    printf '{}\n' > "$ALERTS_CONFIG_FILE"
    chmod 644 "$ALERTS_CONFIG_FILE"

    run _alerts_fix_setup_config
    [ "$status" -eq 0 ]
    [ "$(stat -c '%a' "$ALERTS_CONFIG_FILE")" = "600" ]
}

@test "setup_config: alerts.json is created 0600" {
    # It holds webhook URLs and bot tokens. The umask dance around the write
    # is what keeps it from being world-readable for the instant before the
    # trailing chmod.
    _alerts_should_prompt() { return 1; }

    run _alerts_fix_setup_config
    [ "$status" -eq 0 ]
    [ "$(stat -c '%a' "$ALERTS_CONFIG_FILE")" = "600" ]
}

@test "setup_config: an uncreatable state directory is reported as such" {
    _alerts_should_prompt() { return 1; }
    # dirname() of the config is now under a regular file, so mkdir -p fails.
    printf 'blocker\n' > "$BATS_TEST_TMPDIR/blocker"
    ALERTS_CONFIG_FILE="$BATS_TEST_TMPDIR/blocker/sub/alerts.json"

    run _alerts_fix_setup_config
    [ "$status" -eq 1 ]
    # Specifically the directory message: asserting the generic write failure
    # would pass with the mkdir guard deleted, because the write below fails too
    # and prints that one — the two guards would be indistinguishable.
    [[ "$output" == *"Could not create the directory for the alert configuration"* ]]
}

@test "setup_config: a failed config write is reported, not reported as saved" {
    _alerts_should_prompt() { return 1; }
    # The config path is a directory, so the redirection fails while its
    # parent exists and mkdir -p succeeds.
    mkdir -p "$ALERTS_CONFIG_FILE"

    run _alerts_fix_setup_config
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the alert configuration"* ]]
    _vpssec_refute grep -q "Alert configuration saved" <<<"$output"
    _vpssec_refute grep -q "Alert configuration template created" <<<"$output"
}

@test "setup_config: a failing jq is reported rather than writing a truncated config" {
    _alerts_should_prompt() { return 1; }
    _vpssec_stub jq 1

    run _alerts_fix_setup_config
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the alert configuration"* ]]
    # The old code redirected jq's output straight at the file, so a failure
    # left an empty alerts.json behind. Nothing should have been created.
    _vpssec_refute test -f "$ALERTS_CONFIG_FILE"
}

@test "setup_config: a failure to generate the hooks fails the whole fix" {
    # The config on its own is not a configured alert channel — it names
    # scripts that would not exist.
    _alerts_should_prompt() { return 1; }
    _alerts_fix_generate_templates() { return 1; }

    run _alerts_fix_setup_config
    [ "$status" -eq 1 ]
}

# ---- the generated hooks --------------------------------------------

@test "generate_templates: all five artifacts are written" {
    run _alerts_fix_generate_templates
    [ "$status" -eq 0 ]
    [ -f "$ALERTS_TEMPLATES_DIR/alert-lib.sh" ]
    [ -f "$ALERTS_TEMPLATES_DIR/ssh-login-monitor.sh" ]
    [ -f "$ALERTS_TEMPLATES_DIR/ufw-monitor.sh" ]
    [ -f "$ALERTS_TEMPLATES_DIR/service-monitor.sh" ]
    [ -f "$ALERTS_TEMPLATES_DIR/README.md" ]
}

@test "generate_templates: the four scripts are executable and the README is not" {
    run _alerts_fix_generate_templates
    [ "$status" -eq 0 ]
    [ -x "$ALERTS_TEMPLATES_DIR/alert-lib.sh" ]
    [ -x "$ALERTS_TEMPLATES_DIR/ssh-login-monitor.sh" ]
    [ -x "$ALERTS_TEMPLATES_DIR/ufw-monitor.sh" ]
    [ -x "$ALERTS_TEMPLATES_DIR/service-monitor.sh" ]
    _vpssec_refute test -x "$ALERTS_TEMPLATES_DIR/README.md"
}

@test "generate_templates: the generated hooks point at this installation, not /var/lib/vpssec" {
    # The load-bearing assertion of the sed pass. The heredocs carry a
    # /var/lib/vpssec literal so the quoted bodies do not expand $WEBHOOK_URL; if
    # the rewrite does not happen, sourcing alert-lib.sh fails and no alert fires.
    run _alerts_fix_generate_templates
    [ "$status" -eq 0 ]

    grep -q "${VPSSEC_STATE}/alerts.json" "$ALERTS_TEMPLATES_DIR/alert-lib.sh"
    grep -q "${VPSSEC_TEMPLATES}/alerts/alert-lib.sh" "$ALERTS_TEMPLATES_DIR/ssh-login-monitor.sh"
    _vpssec_refute grep -rq '/var/lib/vpssec/' "$ALERTS_TEMPLATES_DIR"
}

@test "generate_templates: an uncreatable templates directory is reported" {
    printf 'blocker\n' > "$BATS_TEST_TMPDIR/blocker"
    ALERTS_TEMPLATES_DIR="$BATS_TEST_TMPDIR/blocker/alerts"

    run _alerts_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not create the alert templates directory"* ]]
}

@test "generate_templates: a failed hook write is reported and stops the run" {
    mkdir -p "$ALERTS_TEMPLATES_DIR/alert-lib.sh"

    run _alerts_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the alert hook script"* ]]
    # It failed on the first artifact, so the rest were never attempted and
    # the success line was never printed.
    _vpssec_refute test -f "$ALERTS_TEMPLATES_DIR/ssh-login-monitor.sh"
    _vpssec_refute grep -q "Alert templates generated in" <<<"$output"
}

@test "generate_templates: a failed write of ANY of the five artifacts fails the fix" {
    # Every write needs its own status check, and a suite that only ever fails
    # the FIRST artifact pins only the first one — dropping the check from the
    # third or fourth would then change nothing observable.
    local artifact
    for artifact in alert-lib.sh ssh-login-monitor.sh ufw-monitor.sh \
                    service-monitor.sh README.md; do
        # A fresh tree per artifact, so an earlier iteration's leftovers
        # cannot satisfy a later one.
        ALERTS_TEMPLATES_DIR="$BATS_TEST_TMPDIR/tpl-$artifact"
        mkdir -p "$ALERTS_TEMPLATES_DIR/$artifact"

        run _alerts_fix_generate_templates
        echo "artifact under test: $artifact"   # shown by bats on failure
        [ "$status" -eq 1 ]
        [[ "$output" == *"Could not write the alert hook script"* ]]
        _vpssec_refute grep -q "Alert templates generated in" <<<"$output"
    done
}

@test "generate_templates: a failed chmod is reported, not left as a non-executable hook" {
    _vpssec_stub chmod 1

    run _alerts_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not write the alert hook script"* ]]
}

@test "generate_templates: a failed path rewrite is reported rather than swallowed" {
    # This used to be `2>/dev/null || true`, which discarded precisely the
    # failure that makes every generated alert a no-op.
    _vpssec_stub sed 1

    run _alerts_fix_generate_templates
    [ "$status" -eq 1 ]
    [[ "$output" == *"would never fire as written"* ]]
    _vpssec_refute grep -q "Alert templates generated in" <<<"$output"
}

# ---- the artifacts stay inert ---------------------------------------

@test "generate_templates: nothing is installed, only written under the templates dir" {
    # The whole contract of this module: it produces artifacts the operator
    # installs by hand. It must not enable a unit, add a crontab entry or
    # touch the system tree.
    run _alerts_fix_generate_templates
    [ "$status" -eq 0 ]

    _vpssec_refute _vpssec_stub_called systemctl
    _vpssec_refute _vpssec_stub_called crontab
    [ -z "$(ls -A "$etc")" ]
}

@test "setup_config: nothing is registered for rollback" {
    # These artifacts live in vpssec's own trees, so backup_file must NOT be
    # called on them — a path recorded in .vpssec_created would make a
    # rollback delete part of vpssec's own state.
    _alerts_should_prompt() { return 1; }
    _vpssec_begin_backup_session

    run _alerts_fix_setup_config
    [ "$status" -eq 0 ]
    _vpssec_refute test -f "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}
