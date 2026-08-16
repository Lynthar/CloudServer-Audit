#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Alert hooks module - webhook and email notifications
# Copyright (c) 2024

# --- Alert Configuration ---

ALERTS_CONFIG_FILE="${VPSSEC_STATE}/alerts.json"
ALERTS_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/alerts"

# --- Alert Helper Functions ---

_alerts_config_exists() {
    [[ -f "$ALERTS_CONFIG_FILE" ]]
}

_alerts_get_webhook_url() {
    if _alerts_config_exists; then
        jq -r '.webhook_url // empty' "$ALERTS_CONFIG_FILE" 2>/dev/null
    fi
}

_alerts_get_email() {
    if _alerts_config_exists; then
        jq -r '.email // empty' "$ALERTS_CONFIG_FILE" 2>/dev/null
    fi
}

_alerts_check_mail_configured() {
    check_command mail || check_command sendmail || check_command msmtp
}

_alerts_check_curl() {
    check_command curl
}

# Is there somebody to ask for a webhook URL? Both predicates are required:
# a readable /dev/tty (the prompts do not read stdin) AND no --yes /
# --json-only, or an automated run parks on the prompt forever.
_alerts_should_prompt() {
    ! _noninteractive && _tty_readable
}

# --- Alert Audit ---

alerts_audit() {
    local module="alerts"

    # Check alert configuration
    print_item "$(i18n 'alerts.check_config')"
    _alerts_audit_config

    # Check notification capabilities
    print_item "$(i18n 'alerts.check_capabilities')"
    _alerts_audit_capabilities
}

_alerts_audit_config() {
    if _alerts_config_exists; then
        local webhook=$(_alerts_get_webhook_url)
        local email=$(_alerts_get_email)

        local configured=0
        [[ -n "$webhook" ]] && { ((configured++)) || true; }
        [[ -n "$email" ]] && { ((configured++)) || true; }

        if ((configured > 0)); then
            # PRESENCE only, never the values: a webhook URL and an email
            # address are bearer secrets, and this text lands in every report
            # format plus the copy run.sh leaves in /tmp.
            local webhook_status="no" email_status="no"
            [[ -n "$webhook" ]] && webhook_status="yes"
            [[ -n "$email" ]] && email_status="yes"
            local check=$(create_check_json \
                "alerts.configured" \
                "alerts" \
                "low" \
                "passed" \
                "$(i18n 'alerts.configured')" \
                "$(i18n 'alerts.config_status' "webhook=$webhook_status" "email=$email_status")" \
                "" \
                "")
            state_add_check "$check"
            print_ok "$(i18n 'alerts.configured')"
        else
            local check=$(create_check_json \
                "alerts.not_configured" \
                "alerts" \
                "low" \
                "failed" \
                "$(i18n 'alerts.not_configured')" \
                "$(i18n 'alerts.no_webhook_email')" \
                "$(i18n 'alerts.fix_configure')" \
                "alerts.setup_config")
            state_add_check "$check"
            print_severity "low" "$(i18n 'alerts.not_configured')"
        fi
    else
        local check=$(create_check_json \
            "alerts.no_config" \
            "alerts" \
            "low" \
            "failed" \
            "$(i18n 'alerts.config_not_found')" \
            "$(i18n 'alerts.config_not_found_desc')" \
            "$(i18n 'alerts.fix_setup')" \
            "alerts.setup_config")
        state_add_check "$check"
        print_severity "low" "$(i18n 'alerts.config_not_found')"
    fi
}

_alerts_audit_capabilities() {
    local capabilities=()

    if _alerts_check_curl; then
        capabilities+=("webhook")
    fi

    if _alerts_check_mail_configured; then
        capabilities+=("email")
    fi

    if [[ ${#capabilities[@]} -gt 0 ]]; then
        local caps_list="${capabilities[*]}"
        local check=$(create_check_json \
            "alerts.capabilities_ok" \
            "alerts" \
            "low" \
            "passed" \
            "$(i18n 'alerts.capabilities_available')" \
            "$(i18n 'alerts.capabilities_list' "types=$caps_list")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'alerts.capabilities' "types=$caps_list")"
    else
        local check=$(create_check_json \
            "alerts.no_capabilities" \
            "alerts" \
            "low" \
            "failed" \
            "$(i18n 'alerts.no_capabilities')" \
            "$(i18n 'alerts.no_capabilities_desc')" \
            "$(i18n 'alerts.fix_install_curl')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'alerts.no_capabilities')"
    fi
}

# --- Alert Fix Functions ---

alerts_fix() {
    local fix_id="$1"

    case "$fix_id" in
        alerts.setup_config)
            _alerts_fix_setup_config
            ;;
        # No generate_templates case: nothing emits that fix_id. The function
        # itself is alive — setup_config calls it as its last step.
        *)
            log_warn "Alerts fix not implemented: $fix_id"
            return 1
            ;;
    esac
}

_alerts_fix_setup_config() {
    print_info "$(i18n 'alerts.setting_up')"

    # Its own message, not the write failure's: an uncreatable directory and
    # an unwritable file need different things from the operator, and sharing
    # one string leaves nothing able to tell the two guards apart.
    local _config_dir
    _config_dir=$(dirname "$ALERTS_CONFIG_FILE")
    if ! mkdir -p "$_config_dir"; then
        print_error "$(i18n 'alerts.state_dir_failed' "path=$_config_dir")"
        return 1
    fi

    # Ask only when there is somebody to ask — see _alerts_should_prompt.
    local webhook_url="" email="" interactive=0
    if _alerts_should_prompt; then
        interactive=1

        print_msg ""
        print_msg "$(i18n 'alerts.configure_prompt')"
        print_msg ""

        read -rp "Webhook URL (Slack-compatible; Discord: append /slack. Leave empty to skip): " webhook_url </dev/tty
        read -rp "Email address (leave empty to skip): " email </dev/tty
    fi

    # Built with jq -n --arg, never heredoc interpolation: a URL containing
    # a quote or backslash produces malformed JSON that breaks the downstream
    # read. Both paths share this builder; the template is it with empty values.
    local config_json
    if ! config_json=$(jq -n \
        --arg webhook "$webhook_url" \
        --arg email   "$email" \
        '{
            webhook_url: $webhook,
            email: $email,
            events: {
                ssh_login_failure: true,
                firewall_change: true,
                service_restart: true,
                security_audit: true
            },
            throttle_minutes: 5
        }'); then
        print_error "$(i18n 'alerts.config_write_failed' "path=$ALERTS_CONFIG_FILE")"
        return 1
    fi

    # alerts.json holds webhook URLs and tokens; create it 0600 so it
    # retains its restrictive mode even if someone `cp`s it elsewhere.
    # The parent state dir is 700 (state_init), but don't rely on that.
    local _prev_umask wrote=0
    _prev_umask=$(umask)
    umask 077
    printf '%s\n' "$config_json" > "$ALERTS_CONFIG_FILE" && wrote=1
    umask "$_prev_umask"

    # The redirection above is the whole write, and its status used to be
    # discarded: an unwritable state dir left the operator with "alert
    # configuration saved" and a fix the engine recorded as complete.
    if ((wrote == 0)); then
        print_error "$(i18n 'alerts.config_write_failed' "path=$ALERTS_CONFIG_FILE")"
        return 1
    fi

    # Belt-and-braces in case an existing file pre-dated this patch and
    # already has a permissive mode. chmod is idempotent.
    chmod 600 "$ALERTS_CONFIG_FILE" 2>/dev/null || true

    if ((interactive)); then
        print_ok "$(i18n 'alerts.config_saved')"
    else
        print_ok "$(i18n 'alerts.template_created' "path=$ALERTS_CONFIG_FILE")"
        print_info "$(i18n 'alerts.edit_template')"
    fi

    # The monitor scripts are the other half of this fix — a config pointing
    # at scripts that were never written is not a configured alert channel.
    _alerts_fix_generate_templates || return 1

    return 0
}

# Write one generated artifact from stdin, reporting when it could not be
# written — a bare `cat >` whose status is discarded ends in "generated" on a
# full disk. MODE goes to chmod verbatim; `+x` leaves umask in charge of read.
_alerts_write_template() {
    local name="$1" mode="${2:-}"
    local path="${ALERTS_TEMPLATES_DIR}/${name}"

    if ! cat > "$path"; then
        print_error "$(i18n 'alerts.hook_write_failed' "name=$name")"
        return 1
    fi

    if [[ -n "$mode" ]] && ! chmod "$mode" "$path"; then
        print_error "$(i18n 'alerts.hook_write_failed' "name=$name")"
        return 1
    fi

    print_item "$(i18n 'alerts.hook_created' "name=$name")"
}

_alerts_fix_generate_templates() {
    if ! mkdir -p "$ALERTS_TEMPLATES_DIR"; then
        print_error "$(i18n 'alerts.templates_dir_failed' "path=$ALERTS_TEMPLATES_DIR")"
        return 1
    fi

    print_info "$(i18n 'alerts.generating_hooks')"

    # Main alert function library
    _alerts_write_template alert-lib.sh +x <<'EOF' || return 1
#!/bin/bash
# vpssec Alert Library
# Source this file in your monitoring scripts

VPSSEC_ALERTS_CONFIG="/var/lib/vpssec/state/alerts.json"

# Load configuration
vpssec_alert_load_config() {
    if [[ -f "$VPSSEC_ALERTS_CONFIG" ]]; then
        WEBHOOK_URL=$(jq -r '.webhook_url // empty' "$VPSSEC_ALERTS_CONFIG")
        ALERT_EMAIL=$(jq -r '.email // empty' "$VPSSEC_ALERTS_CONFIG")
        THROTTLE_MINUTES=$(jq -r '.throttle_minutes // 5' "$VPSSEC_ALERTS_CONFIG")
    fi
}

# Send webhook notification. Returns non-zero when delivery failed, so the
# caller can decide whether to arm the throttle.
vpssec_alert_webhook() {
    local title="$1"
    local message="$2"
    local severity="${3:-info}"  # info, warning, critical

    [[ -z "$WEBHOOK_URL" ]] && return 1

    local color
    case "$severity" in
        critical) color="#FF0000" ;;
        warning)  color="#FFA500" ;;
        *)        color="#00FF00" ;;
    esac

    # Slack-compatible payload, built by jq so quotes/newlines/backslashes in
    # the message cannot break the JSON. The title routinely embeds a
    # USERNAME (the PAM hooks pass whatever the login attempt claimed), so a
    # hand-interpolated heredoc handed payload injection to anyone who types
    # a crafted name at an SSH prompt. jq is guaranteed present: vpssec
    # itself requires it and this library already uses it to load config.
    local payload
    payload=$(jq -n \
        --arg color "$color" \
        --arg title "$title" \
        --arg text  "$message" \
        --arg host  "$(hostname)" \
        --arg time  "$(date -Iseconds)" \
        '{attachments: [{color: $color, title: $title, text: $text,
          fields: [{title: "Host", value: $host, short: true},
                   {title: "Time", value: $time, short: true}]}]}') || return 1

    # --fail: a 4xx/5xx from the webhook endpoint is a delivery failure, not
    # a success with an error page; timeouts keep a dead endpoint from
    # hanging the monitoring cron.
    curl --fail -sS -X POST -H "Content-Type: application/json" \
        --connect-timeout 5 --max-time 15 \
        -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1
}

# Send email notification. Returns non-zero when no channel is configured
# or the mailer reported failure — see vpssec_alert for why that matters.
vpssec_alert_email() {
    local subject="$1"
    local body="$2"

    [[ -z "$ALERT_EMAIL" ]] && return 1

    local hostname=$(hostname)

    # Use printf with a literal format so backslash sequences in $body
    # (e.g. "\n" from command output, or an attacker-controlled message
    # field) are not re-interpreted by echo -e.
    if command -v mail &>/dev/null; then
        printf '%s\n\nHost: %s\nTime: %s\n' "$body" "$hostname" "$(date)" | \
            mail -s "[vpssec] $subject" "$ALERT_EMAIL"
    elif command -v msmtp &>/dev/null; then
        printf 'Subject: [vpssec] %s\n\n%s\n\nHost: %s\nTime: %s\n' \
            "$subject" "$body" "$hostname" "$(date)" | \
            msmtp "$ALERT_EMAIL"
    else
        return 1
    fi
}

# Main alert function
vpssec_alert() {
    local title="$1"
    local message="$2"
    local severity="${3:-info}"

    vpssec_alert_load_config

    # Throttle state lives in a protected directory rather than /tmp.
    # Under /tmp the filename was md5(title) — deterministic and world-
    # writable — which let any local user pre-create the file with a
    # future timestamp to silence specific alerts (e.g. "SSH login",
    # "High CPU"). A 700-mode directory under /var/lib prevents that.
    local throttle_dir="/var/lib/vpssec/state/alerts/throttle"
    mkdir -p "$throttle_dir" 2>/dev/null
    chmod 700 "$throttle_dir" 2>/dev/null

    local throttle_file="${throttle_dir}/$(echo "$title" | md5sum | cut -d' ' -f1)"
    if [[ -f "$throttle_file" ]]; then
        local last_alert=$(cat "$throttle_file")
        local now=$(date +%s)
        local diff=$((now - last_alert))
        local throttle_seconds=$((THROTTLE_MINUTES * 60))

        if ((diff < throttle_seconds)); then
            return 0  # Throttled
        fi
    fi

    # Send, then arm the throttle ONLY if something was actually delivered.
    # Stamping unconditionally meant one failed delivery (endpoint down,
    # curl timeout) silenced every retry of that same alert for the whole
    # throttle window — the alert that never arrived suppressed the ones
    # that could have.
    local delivered=1
    vpssec_alert_webhook "$title" "$message" "$severity" && delivered=0
    vpssec_alert_email "$title" "$message" && delivered=0

    if [[ "$delivered" -eq 0 ]]; then
        date +%s > "$throttle_file"
    fi
    return "$delivered"
}

# Initialize
vpssec_alert_load_config
EOF

    # SSH login monitor
    _alerts_write_template ssh-login-monitor.sh +x <<'EOF' || return 1
#!/bin/bash
# SSH Login Monitor - sends alerts on failed/successful logins
# Install: Copy to /usr/local/bin/ and add to /etc/pam.d/sshd

source /var/lib/vpssec/templates/alerts/alert-lib.sh

# Get login info from environment (PAM)
USER="${PAM_USER:-unknown}"
RHOST="${PAM_RHOST:-unknown}"
SERVICE="${PAM_SERVICE:-ssh}"
TYPE="${PAM_TYPE:-unknown}"

# Successful logins only. This hook is installed on the PAM *session*
# stack (see README), so open_session is the only event it will ever see.
# A previous version also carried an `auth` branch claiming to detect
# FAILED logins by testing PAM_AUTHTOK — doubly wrong: the session hook
# never receives auth events, and pam_exec does not expose the authtok
# without expose_authtok anyway, so the branch was unreachable theater.
# For failed-login alerting, watch the journal (sshd logs every failure)
# or use fail2ban, which this tool can set up.
case "$TYPE" in
    open_session)
        vpssec_alert "SSH Login: $USER" \
            "User '$USER' logged in from $RHOST" \
            "info"
        ;;
esac
EOF

    # Firewall change monitor
    _alerts_write_template ufw-monitor.sh +x <<'EOF' || return 1
#!/bin/bash
# UFW Change Monitor
# Run via inotifywait or periodically via cron

source /var/lib/vpssec/templates/alerts/alert-lib.sh

UFW_RULES_FILE="/etc/ufw/user.rules"
# State lives in a root-owned 0700 directory, NOT /tmp: this script runs as
# root from cron, and a fixed /tmp name let any local user pre-plant a
# symlink there — root's `echo >` then truncated whatever file the link
# pointed at.
STATE_DIR="/var/lib/vpssec/state/alerts"
HASH_FILE="${STATE_DIR}/ufw-rules.hash"
mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"

current_hash=$(md5sum "$UFW_RULES_FILE" 2>/dev/null | cut -d' ' -f1)
stored_hash=$(cat "$HASH_FILE" 2>/dev/null)

if [[ "$current_hash" != "$stored_hash" ]]; then
    vpssec_alert "Firewall Rules Changed" \
        "UFW rules have been modified. Review changes." \
        "warning"

    echo "$current_hash" > "$HASH_FILE"
fi
EOF

    # Service monitor
    _alerts_write_template service-monitor.sh +x <<'EOF' || return 1
#!/bin/bash
# Critical Service Monitor
# Run via cron: */5 * * * * /path/to/service-monitor.sh

source /var/lib/vpssec/templates/alerts/alert-lib.sh

SERVICES=(
    "ssh"
    "ufw"
    "docker"
    "nginx"
)

for service in "${SERVICES[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        if ! systemctl is-active --quiet "$service"; then
            vpssec_alert "Service Down: $service" \
                "Critical service '$service' is not running" \
                "critical"
        fi
    fi
done
EOF

    # Installation instructions
    _alerts_write_template README.md <<'EOF' || return 1
# vpssec Alert Hooks

## Setup

### 1. Configure alerts.json

Edit `/var/lib/vpssec/state/alerts.json`:

```json
{
  "webhook_url": "https://hooks.slack.com/services/xxx",
  "email": "admin@example.com",
  "events": {
    "ssh_login_failure": true,
    "firewall_change": true,
    "service_restart": true
  },
  "throttle_minutes": 5
}
```

### 2. Webhook URLs

The payload is **Slack-format JSON**. It works with:

- **Slack**: https://api.slack.com/messaging/webhooks
- **Discord**: create a webhook (Server Settings → Integrations → Webhooks)
  and append `/slack` to its URL — Discord translates Slack payloads on
  that endpoint.
- Anything else Slack-compatible (Mattermost, Rocket.Chat, ...).

Telegram is **not** supported by this payload: its Bot API expects
`chat_id`/`text` fields, not Slack attachments. Use a bridge or adapt
`vpssec_alert_webhook` if you need Telegram.

### 3. Install Monitors

**SSH Login Alerts (via PAM — successful logins only):**
```bash
# Add to /etc/pam.d/sshd:
session optional pam_exec.so /usr/local/bin/ssh-login-monitor.sh
```

For **failed** login alerting, use fail2ban (vpssec can set it up) or watch
the journal — PAM session hooks only fire on successful logins.

**Service Monitor (via cron):**
```bash
# Add to root crontab:
*/5 * * * * /var/lib/vpssec/templates/alerts/service-monitor.sh
```

**Firewall Monitor (via cron):**
```bash
*/10 * * * * /var/lib/vpssec/templates/alerts/ufw-monitor.sh
```

### 4. Test

```bash
source /var/lib/vpssec/templates/alerts/alert-lib.sh
vpssec_alert "Test Alert" "This is a test notification" "info"
```
EOF

    # Bake the RUNTIME paths in: the artifacts hold a /var/lib/vpssec literal
    # so the quoted heredocs stay unexpanded, but the real trees are elsewhere.
    # Without this every generated alert silently never fires.
    if ! find "$ALERTS_TEMPLATES_DIR" -type f -exec sed -i \
        -e "s|/var/lib/vpssec/templates|${VPSSEC_TEMPLATES}|g" \
        -e "s|/var/lib/vpssec/state|${VPSSEC_STATE}|g" \
        {} +; then
        print_error "$(i18n 'alerts.path_rewrite_failed' "path=$ALERTS_TEMPLATES_DIR")"
        return 1
    fi

    print_ok "$(i18n 'alerts.templates_generated' "path=$ALERTS_TEMPLATES_DIR")"

    return 0
}

# (vpssec_send_alert used to live here: a zero-caller near-duplicate of the
# generated alert-lib.sh template. Deleted per the unwired-API rule — the
# template library is the single implementation.)
