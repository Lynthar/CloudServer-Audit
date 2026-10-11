#!/usr/bin/env bats
# An alerts.json that does not parse is not "not configured": that reading
# offered setup_config, which then overwrote the operator's webhook with an
# empty template. It is reported on its own, with no fix attached.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh modules/alerts.sh
    i18n_load en_US
    state_init
}

_config_check() {
    _alerts_audit_config
    jq -r '.[] | "\(.id) \(.status) fix=\(.fix_id // "")"' "$VPSSEC_STATE/checks.json"
}

@test "a hand edit that broke the JSON is reported as unreadable, with no fix offered" {
    printf '{"webhook_url": "https://hooks.example.invalid/x",}\n' > "$ALERTS_CONFIG_FILE"
    [ "$(_config_check)" = "alerts.config_invalid failed fix=" ]
    [ "$(jq -r '.[0].desc' "$VPSSEC_STATE/checks.json")" = \
      "$ALERTS_CONFIG_FILE is not a JSON object; vpssec will not overwrite it" ]
}

@test "valid JSON that is not an object is unreadable too" {
    printf '[]\n' > "$ALERTS_CONFIG_FILE"
    [ "$(_config_check)" = "alerts.config_invalid failed fix=" ]
}

@test "a valid config without webhook or email is not configured, and offers the fix" {
    printf '{"webhook_url": "", "email": ""}\n' > "$ALERTS_CONFIG_FILE"
    [ "$(_config_check)" = "alerts.not_configured failed fix=alerts.setup_config" ]
}
