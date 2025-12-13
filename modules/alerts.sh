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

# ==============================================================================
# Alert Audit
# ==============================================================================

alerts_audit() {
    local module="alerts"

    # Check alert configuration
    print_item "Checking alert configuration..."
    _alerts_audit_config

    # Check notification capabilities
    print_item "Checking notification capabilities..."
    _alerts_audit_capabilities
}

_alerts_audit_config() {
    if _alerts_config_exists; then
        local webhook=$(_alerts_get_webhook_url)
        local email=$(_alerts_get_email)

        local configured=0
        [[ -n "$webhook" ]] && ((configured++))
        [[ -n "$email" ]] && ((configured++))

        if ((configured > 0)); then
            local check=$(create_check_json \
                "alerts.configured" \
                "alerts" \
                "low" \
                "passed" \
                "Alert notifications configured" \
                "Webhook: ${webhook:+yes}${webhook:-no}, Email: ${email:+yes}${email:-no}" \
                "" \
                "")
            state_add_check "$check"
            print_ok "Alert notifications configured"
        else
            local check=$(create_check_json \
                "alerts.not_configured" \
                "alerts" \
                "low" \
                "failed" \
                "Alert notifications not configured" \
                "No webhook or email configured" \
                "Configure alert notifications" \
                "alerts.setup_config")
            state_add_check "$check"
            print_severity "low" "Alert notifications not configured"
        fi
    else
        local check=$(create_check_json \
            "alerts.no_config" \
            "alerts" \
            "low" \
            "failed" \
            "Alert configuration not found" \
            "alerts.json not present" \
            "Set up alert configuration" \
            "alerts.setup_config")
        state_add_check "$check"
        print_severity "low" "Alert configuration not found"
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
        local check=$(create_check_json \
            "alerts.capabilities_ok" \
            "alerts" \
            "low" \
            "passed" \
            "Alert capabilities available" \
            "Available: ${capabilities[*]}" \
            "" \
            "")
        state_add_check "$check"
        print_ok "Alert capabilities: ${capabilities[*]}"
    else
        local check=$(create_check_json \
            "alerts.no_capabilities" \
            "alerts" \
            "low" \
            "failed" \
            "No alert capabilities available" \
            "Neither curl nor mail command available" \
            "Install curl for webhook support" \
            "")
        state_add_check "$check"
        print_severity "low" "No alert capabilities (install curl)"
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
        alerts.generate_templates)
            _alerts_fix_generate_templates
            ;;
        *)
            log_warn "Alerts fix not implemented: $fix_id"
            return 1
            ;;
    esac
}

_alerts_fix_setup_config() {
    print_info "Setting up alert configuration..."

    mkdir -p "$(dirname "$ALERTS_CONFIG_FILE")"

    # Interactive setup or generate template
    if [[ -t 0 ]]; then
        local webhook_url=""
        local email=""

        print_msg ""
        print_msg "Configure alert notifications:"
        print_msg ""

        read -rp "Webhook URL (Slack/Discord/Telegram, leave empty to skip): " webhook_url
        read -rp "Email address (leave empty to skip): " email

        cat > "$ALERTS_CONFIG_FILE" <<EOF
{
  "webhook_url": "${webhook_url}",
  "email": "${email}",
  "events": {
    "ssh_login_failure": true,
    "firewall_change": true,
    "service_restart": true,
    "security_audit": true
  },
  "throttle_minutes": 5
}
EOF

        print_ok "Alert configuration saved"
    else
        # Non-interactive: generate template
        cat > "$ALERTS_CONFIG_FILE" <<'EOF'
{
  "webhook_url": "",
  "email": "",
  "events": {
    "ssh_login_failure": true,
    "firewall_change": true,
    "service_restart": true,
    "security_audit": true
  },
  "throttle_minutes": 5
}
EOF
        print_ok "Alert configuration template created: $ALERTS_CONFIG_FILE"
        print_info "Edit the file to add your webhook URL and/or email"
    fi

    # Generate monitoring scripts
    _alerts_fix_generate_templates

    return 0
}

_alerts_fix_generate_templates() {
    mkdir -p "$ALERTS_TEMPLATES_DIR"

    print_info "Generating alert hook scripts..."

    # Main alert function library
    cat > "${ALERTS_TEMPLATES_DIR}/alert-lib.sh" <<'EOF'
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

    if command -v mail &>/dev/null; then
        echo -e "$body\n\nHost: $hostname\nTime: $(date)" | \
            mail -s "[vpssec] $subject" "$ALERT_EMAIL"
    elif command -v msmtp &>/dev/null; then
        echo -e "Subject: [vpssec] $subject\n\n$body\n\nHost: $hostname\nTime: $(date)" | \
            msmtp "$ALERT_EMAIL"
    fi
}

# Main alert function
vpssec_alert() {
    local title="$1"
    local message="$2"
    local severity="${3:-info}"

    vpssec_alert_load_config

    # Check throttling
    local throttle_file="/tmp/vpssec-alert-$(echo "$title" | md5sum | cut -d' ' -f1)"
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

    chmod +x "${ALERTS_TEMPLATES_DIR}/alert-lib.sh"
    print_item "Created: alert-lib.sh"

    # SSH login monitor
    cat > "${ALERTS_TEMPLATES_DIR}/ssh-login-monitor.sh" <<'EOF'
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

    chmod +x "${ALERTS_TEMPLATES_DIR}/ssh-login-monitor.sh"
    print_item "Created: ssh-login-monitor.sh"

    # Firewall change monitor
    cat > "${ALERTS_TEMPLATES_DIR}/ufw-monitor.sh" <<'EOF'
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

    chmod +x "${ALERTS_TEMPLATES_DIR}/ufw-monitor.sh"
    print_item "Created: ufw-monitor.sh"

    # Service monitor
    cat > "${ALERTS_TEMPLATES_DIR}/service-monitor.sh" <<'EOF'
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

    chmod +x "${ALERTS_TEMPLATES_DIR}/service-monitor.sh"
    print_item "Created: service-monitor.sh"

    # Installation instructions
    cat > "${ALERTS_TEMPLATES_DIR}/README.md" <<'EOF'
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

    print_item "Created: README.md"
    print_ok "Alert templates generated in: $ALERTS_TEMPLATES_DIR"

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

    # Send email
    if [[ -n "$email" ]] && _alerts_check_mail_configured; then
        echo -e "$message\n\nHost: $(hostname)\nTime: $(date)" | \
            mail -s "[vpssec] $title" "$email" 2>/dev/null &
    fi
}
