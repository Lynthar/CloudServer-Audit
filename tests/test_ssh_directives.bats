#!/usr/bin/env bats
# Golden record of the twelve sshd directive checks: the id, desc, suggestion
# and fix_id each emits in its pass and fail state, and the terminal line
# beside it. Changing a row here is a deliberate change of output.

load helpers.bash

# stem|directive|default|expect|pass_input|fail_input|pass_id|fail_id|suggestion|fix|pass_desc|shown|default_state
# suggestion "-" = ssh.suggest_set_directive with directive/expect; pass_desc
# "directive" = "<directive>=<value>", "-" = empty; shown = when " (value)" follows.
SSH_GOLD=(
    "x11_forwarding|X11Forwarding|no|no|No|yes|ssh.x11_forwarding_disabled|ssh.x11_forwarding_enabled|ssh.x11_forwarding_enabled_suggestion|ssh.disable_x11_forwarding|-|none|passed"
    "allow_tcp_forwarding|AllowTcpForwarding|yes|no|NO|yes|ssh.allow_tcp_forwarding_disabled|ssh.allow_tcp_forwarding_enabled|-|-|directive|none|failed"
    "client_alive|ClientAliveCountMax|3|2|2|3|ssh.client_alive_ok|ssh.client_alive_high|-|-|directive|both|failed"
    "log_level|LogLevel|INFO|VERBOSE|verbose|INFO|ssh.log_level_ok|ssh.log_level_low|-|-|directive|fail|failed"
    "max_sessions|MaxSessions|10|4|4|10|ssh.max_sessions_ok|ssh.max_sessions_high|-|-|directive|both|failed"
    "tcp_keepalive|TCPKeepAlive|yes|no|no|Yes|ssh.tcp_keepalive_disabled|ssh.tcp_keepalive_enabled|ssh.tcp_keepalive_enabled_suggestion|-|directive|none|failed"
    "agent_forwarding|AllowAgentForwarding|yes|no|no|yes|ssh.agent_forwarding_disabled|ssh.agent_forwarding_enabled|-|-|directive|none|failed"
    "ignore_rhosts|IgnoreRhosts|yes|yes|YES|no|ssh.ignore_rhosts_ok|ssh.ignore_rhosts_disabled|-|-|directive|none|passed"
    "strict_modes|StrictModes|yes|yes|yes|no|ssh.strict_modes_ok|ssh.strict_modes_disabled|-|-|directive|none|passed"
    "permit_user_env|PermitUserEnvironment|no|no|no|yes|ssh.permit_user_env_disabled|ssh.permit_user_env_enabled|-|-|directive|none|passed"
    "permit_tunnel|PermitTunnel|no|no|no|point-to-point|ssh.permit_tunnel_disabled|ssh.permit_tunnel_enabled|-|-|directive|none|passed"
    "gateway_ports|GatewayPorts|no|no|no|clientspecified|ssh.gateway_ports_disabled|ssh.gateway_ports_enabled|-|-|directive|none|passed"
)

# The checks ssh_audit runs before, between and after the directive block;
# stubbed to nothing so only their headline lines appear in the output.
SSH_OTHER_BEFORE=(password_auth root_login pubkey_auth admin_user empty_password max_auth_tries login_grace_time)
SSH_OTHER_AFTER=(algorithms access_control port)

setup() {
    _vpssec_load core/security_levels.sh core/state.sh
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    export VPSSEC_QUIET_SCAN=0
    declare -gA SSH_STUB=()
    _ssh_get_config() { printf '%s\n' "${SSH_STUB[$1]-$2}"; }
    local fn
    for fn in _ssh_audit_password_auth _ssh_audit_root_login _ssh_audit_pubkey \
              _ssh_audit_admin_user _ssh_audit_empty_password _ssh_audit_max_auth_tries \
              _ssh_audit_login_grace_time _ssh_audit_algorithms _ssh_audit_access_control \
              _ssh_audit_port; do
        eval "$fn() { :; }"
    done
}

# Feed every directive its pass ($1=pass), fail ($1=fail) or default ($1=default) input.
_stub_all() {
    local row stem directive default expect pass_in fail_in rest
    for row in "${SSH_GOLD[@]}"; do
        IFS='|' read -r stem directive default expect pass_in fail_in rest <<< "$row"
        case "$1" in
            pass)    SSH_STUB[$directive]="$pass_in" ;;
            fail)    SSH_STUB[$directive]="$fail_in" ;;
            default) ;;
        esac
    done
}

# Expected checks.json rows (TSV) and terminal lines for the current stub,
# given each directive's outcome as "$1" (passed/failed/default).
_expected() {
    local mode="$1" row stem directive default expect pass_in fail_in pass_id fail_id sugg fix pass_desc shown default_state
    local val state id desc suggestion fix_id suffix k
    EXPECTED_CHECKS=(); EXPECTED_LINES=()
    for k in "${SSH_OTHER_BEFORE[@]}"; do EXPECTED_LINES+=("  • $(i18n "ssh.check_$k")"); done
    for row in "${SSH_GOLD[@]}"; do
        IFS='|' read -r stem directive default expect pass_in fail_in pass_id fail_id sugg fix pass_desc shown default_state <<< "$row"
        val="${SSH_STUB[$directive]-$default}"
        case "$mode" in
            passed|failed) state="$mode" ;;
            default)       state="$default_state" ;;
        esac
        suffix=""
        [[ "$shown" == both || ( "$shown" == fail && "$state" == failed ) ]] && suffix=" ($val)"
        if [[ "$state" == passed ]]; then
            id="$pass_id"; desc=""; suggestion=""; fix_id=""
            [[ "$pass_desc" == directive ]] && desc="${directive}=${val}"
            EXPECTED_LINES+=("  • $(i18n "ssh.check_$stem")" "✓ $(i18n "$pass_id")$suffix")
        else
            id="$fail_id"; desc=$(i18n "${fail_id}_desc" "val=$val")
            if [[ "$sugg" == - ]]; then
                suggestion=$(i18n 'ssh.suggest_set_directive' "directive=$directive" "value=$expect")
            else
                suggestion=$(i18n "$sugg")
            fi
            fix_id="${fix/#-/}"
            EXPECTED_LINES+=("  • $(i18n "ssh.check_$stem")" "  ● $(i18n "$fail_id")$suffix")
        fi
        EXPECTED_CHECKS+=("$(printf '%s\t' "$id" ssh low "$state" "$(i18n "$id")" "$desc" "$suggestion")$fix_id")
    done
    for k in "${SSH_OTHER_AFTER[@]}"; do EXPECTED_LINES+=("  • $(i18n "ssh.check_$k")"); done
}

_assert_golden() {
    run ssh_audit
    [ "$status" -eq 0 ]
    diff <(printf '%s\n' "${EXPECTED_LINES[@]}") <(printf '%s\n' "$output")
    diff <(printf '%s\n' "${EXPECTED_CHECKS[@]}") \
         <(jq -r '.[] | [.id, .module, .severity, .status, .title, .desc, .suggestion, .fix_id] | @tsv' "$STATE_CHECKS_FILE")
}

@test "ssh directives: every check passes on its hardened value, case-insensitively" {
    _stub_all pass
    _expected passed
    _assert_golden
}

@test "ssh directives: every check fails on its permissive value with the directive's suggestion" {
    _stub_all fail
    _expected failed
    _assert_golden
}

@test "ssh directives: sshd's defaults pass six checks and fail six" {
    _stub_all default
    _expected default
    _assert_golden
}

@test "ssh directives: a non-numeric ClientAliveCountMax or MaxSessions fails, never aborts" {
    _stub_all pass
    SSH_STUB[ClientAliveCountMax]="abc"
    SSH_STUB[MaxSessions]="4x"
    _expected passed
    # Only the two numeric checks flip; rebuild their rows and lines by hand.
    local i
    for i in "${!EXPECTED_CHECKS[@]}"; do
        case "${EXPECTED_CHECKS[$i]}" in
            "ssh.client_alive_ok"*) EXPECTED_CHECKS[$i]="$(printf '%s\t' ssh.client_alive_high ssh low failed "$(i18n ssh.client_alive_high)" "$(i18n ssh.client_alive_high_desc val=abc)" "$(i18n ssh.suggest_set_directive directive=ClientAliveCountMax value=2)")" ;;
            "ssh.max_sessions_ok"*) EXPECTED_CHECKS[$i]="$(printf '%s\t' ssh.max_sessions_high ssh low failed "$(i18n ssh.max_sessions_high)" "$(i18n ssh.max_sessions_high_desc val=4x)" "$(i18n ssh.suggest_set_directive directive=MaxSessions value=4)")" ;;
        esac
    done
    for i in "${!EXPECTED_LINES[@]}"; do
        case "${EXPECTED_LINES[$i]}" in
            "✓ $(i18n ssh.client_alive_ok)"*) EXPECTED_LINES[$i]="  ● $(i18n ssh.client_alive_high) (abc)" ;;
            "✓ $(i18n ssh.max_sessions_ok)"*) EXPECTED_LINES[$i]="  ● $(i18n ssh.max_sessions_high) (4x)" ;;
        esac
    done
    _assert_golden
}

@test "ssh directives: every id in the golden table is a scored check" {
    local row rest pass_id fail_id
    for row in "${SSH_GOLD[@]}"; do
        IFS='|' read -r _ _ _ _ _ _ pass_id fail_id rest <<< "$row"
        [ -n "${CHECK_SCORE_CATEGORY[$pass_id]:-}" ]
        [ -n "${CHECK_SCORE_CATEGORY[$fail_id]:-}" ]
    done
}
