#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Alert hooks module - webhook and email notifications
# Copyright (c) 2024

# ==============================================================================
# Alert Configuration
# ==============================================================================

ALERTS_CONFIG_FILE="${VPSSEC_STATE}/alerts.json"
ALERTS_TEMPLATES_DIR="${VPSSEC_TEMPLATES}/alerts"

# ==============================================================================
# Alert Helper Functions
# ==============================================================================

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

# True when there is somebody to ask for a webhook URL.
#
# Extracted from _alerts_fix_setup_config so the decision is testable: the
# inline `[[ -t 0 ]]` it replaces could only ever be exercised by whatever
# stdin the test runner happened to supply, which is never a terminal — so
# no test could tell the old gate from the new one. It was wrong twice over
# anyway: it asks about stdin while the prompts read from /dev/tty, and it
# ignores --yes / --json-only, so `guide --yes` on a real terminal parked on
# "Webhook URL:" forever. Same pair of predicates as timezone.sh's menu.
_alerts_should_prompt() {
    ! _noninteractive && _tty_readable
}

# ==============================================================================
# Alert Audit
# ==============================================================================

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
            # Report only PRESENCE (yes/no), never the secret values. A
            # webhook URL (Slack/Discord/Telegram bot token) and an email
            # address are bearer secrets; the previous
            # `${var:+yes}${var:-no}` expansion silently expanded to
            # "yes<the-full-URL>" whenever the var was set, leaking the
            # secret into reports/summary.{md,json,sarif} (and the copy
            # run.sh drops in /tmp).
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

# ==============================================================================
# Alert Fix Functions
# ==============================================================================

alerts_fix() {
    local fix_id="$1"

    case "$fix_id" in
        alerts.setup_config)
            _alerts_fix_setup_config
            ;;
        # No alerts.generate_templates case: nothing emits that fix_id, so the
        # branch was unreachable. _alerts_fix_generate_templates is still very
        # much alive — _alerts_fix_setup_config calls it directly as its last
        # step.
        *)
            log_warn "Alerts fix not implemented: $fix_id"
            return 1
            ;;
    esac
}

_alerts_fix_setup_config() {
    print_info "$(i18n 'alerts.setting_up')"

    # Its own message rather than the write failure's: an uncreatable state
    # directory and an unwritable alerts.json need different things from the
    # operator, and sharing one string also made the two indistinguishable to
    # a test — dropping this guard entirely still produced the write failure's
    # message one step later, so nothing could tell the guards apart.
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

        read -rp "Webhook URL (Slack/Discord/Telegram, leave empty to skip): " webhook_url </dev/tty
        read -rp "Email address (leave empty to skip): " email </dev/tty
    fi

    # Build the JSON with `jq -n --arg` rather than heredoc-interpolating
    # `$webhook_url` / `$email` directly — a URL or address containing
    # `"` or `\` would otherwise produce malformed JSON and break
    # downstream `jq -r '.webhook_url'` reads in _alerts_get_webhook_url.
    # Both paths share one builder: the non-interactive template is just
    # this with both values empty.
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

# Write one generated artifact from stdin, and say so when it could not be
# written. Each of these was a bare `cat >` whose status the fix discarded,
# so a full disk or a read-only templates tree still ended in "alert hooks
# generated" and a return 0.
#
# MODE is passed to chmod verbatim; `+x` rather than an absolute mode so the
# caller's umask still decides who may read a generated script.
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

# Send webhook notification
vpssec_alert_webhook() {
    local title="$1"
    local message="$2"
    local severity="${3:-info}"  # info, warning, critical

    [[ -z "$WEBHOOK_URL" ]] && return 0

    local color
    case "$severity" in
        critical) color="#FF0000" ;;
        warning)  color="#FFA500" ;;
        *)        color="#00FF00" ;;
    esac

    local hostname=$(hostname)
    local timestamp=$(date -Iseconds)

    # Slack-compatible payload
    local payload=$(cat <<PAYLOAD
{
  "attachments": [{
    "color": "$color",
    "title": "$title",
    "text": "$message",
    "fields": [
      {"title": "Host", "value": "$hostname", "short": true},
      {"title": "Time", "value": "$timestamp", "short": true}
    ]
  }]
}
PAYLOAD
)

    curl -s -X POST -H "Content-Type: application/json" \
        -d "$payload" "$WEBHOOK_URL" &>/dev/null
}

# Send email notification
vpssec_alert_email() {
    local subject="$1"
    local body="$2"

    [[ -z "$ALERT_EMAIL" ]] && return 0

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

    # Send alerts
    vpssec_alert_webhook "$title" "$message" "$severity"
    vpssec_alert_email "$title" "$message"

    # Update throttle file
    date +%s > "$throttle_file"
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

case "$TYPE" in
    open_session)
        vpssec_alert "SSH Login: $USER" \
            "User '$USER' logged in from $RHOST" \
            "info"
        ;;
    auth)
        if [[ "${PAM_AUTHTOK:-}" == "" ]]; then
            vpssec_alert "SSH Login Failed: $USER" \
                "Failed login attempt for '$USER' from $RHOST" \
                "warning"
        fi
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
HASH_FILE="/tmp/vpssec-ufw-hash"

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

- **Slack**: https://api.slack.com/messaging/webhooks
- **Discord**: Server Settings → Integrations → Webhooks
- **Telegram**: Use BotFather to create bot, then use:
  `https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=`

### 3. Install Monitors

**SSH Login Alerts (via PAM):**
```bash
# Add to /etc/pam.d/sshd:
session optional pam_exec.so /usr/local/bin/ssh-login-monitor.sh
```

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

    # Bake the RUNTIME paths into the generated artifacts. They are authored
    # with a `/var/lib/vpssec/...` literal so the quoted heredocs don't expand
    # $WEBHOOK_URL / $1 etc., but vpssec actually keeps state and templates under
    # $VPSSEC_STATE / $VPSSEC_TEMPLATES (e.g. /opt/vpssec/... when installed) —
    # and install.sh even `rm -rf /var/lib/vpssec`. Without this rewrite the
    # generated monitors/cron/README point at a path that does not exist, so
    # `source .../alert-lib.sh` fails and every alert silently never fires. The
    # `state|templates` order matters (templates lives under neither, state is a
    # distinct tree), and | is a safe sed delimiter since paths contain /.
    #
    # The status is checked and stderr left visible on purpose: this used to be
    # `2>/dev/null || true`, which swallowed exactly the failure the paragraph
    # above describes as fatal. Artifacts that still point at /var/lib/vpssec
    # are artifacts whose every alert silently never fires, so shipping them
    # with a green "alert hooks generated" is worse than reporting the failure.
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

# ==============================================================================
# Alert Utility Functions (for use by other modules)
# ==============================================================================

# Send alert from vpssec operations
vpssec_send_alert() {
    local title="$1"
    local message="$2"
    local severity="${3:-info}"

    local webhook=$(_alerts_get_webhook_url)
    local email=$(_alerts_get_email)

    # Send webhook
    if [[ -n "$webhook" ]] && _alerts_check_curl; then
        local hostname=$(hostname)
        local color
        case "$severity" in
            critical) color="#FF0000" ;;
            warning)  color="#FFA500" ;;
            *)        color="#00FF00" ;;
        esac

        local payload=$(cat <<EOF
{
  "attachments": [{
    "color": "$color",
    "title": "$title",
    "text": "$message",
    "fields": [
      {"title": "Host", "value": "$hostname", "short": true},
      {"title": "Time", "value": "$(date -Iseconds)", "short": true}
    ]
  }]
}
EOF
)
        curl -s -X POST -H "Content-Type: application/json" \
            -d "$payload" "$webhook" &>/dev/null &
    fi

    # Send email (printf so backslash sequences inside $message aren't
    # re-interpreted, matching the template library's behaviour).
    if [[ -n "$email" ]] && _alerts_check_mail_configured; then
        printf '%s\n\nHost: %s\nTime: %s\n' "$message" "$(hostname)" "$(date)" | \
            mail -s "[vpssec] $title" "$email" 2>/dev/null &
    fi
}
