#!/usr/bin/env bats
# "A failed query is not a clean result." An audit that cannot answer must report
# the non-observation (failed + info-category, unscored) or fail loudly — never
# fold it into the green path as "no updates" or "0 failed logins".

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
}

# ---- update ------------------------------------------------------------

@test "update: query failure emits update.check_failed, not no_updates" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { return 1; }
    pkg_security_update_count() { return 1; }

    _update_audit_available

    run jq -r '.[] | select(.id == "update.check_failed") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "update.no_updates") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

@test "update: a real zero still passes as no_updates" {
    source "$(_vpssec_repo_root)/modules/update.sh"
    pkg_update_count() { echo 0; }
    pkg_security_update_count() { echo 0; }

    _update_audit_available

    run jq -r '.[] | select(.id == "update.no_updates") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "passed" ]
}

# ---- logging -----------------------------------------------------------

@test "logging: journalctl failure emits journal_unreadable, not ssh_logs_ok" {
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _vpssec_stub journalctl 1

    _logging_audit_ssh_logs

    run jq -r '.[] | select(.id == "logging.journal_unreadable") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "logging.ssh_logs_ok") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

@test "logging: working journalctl with zero failures still passes" {
    source "$(_vpssec_repo_root)/modules/logging.sh"
    _vpssec_stub journalctl 0 ""

    _logging_audit_ssh_logs

    run jq -r '.[] | select(.id == "logging.ssh_logs_ok") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "passed" ]
}

# ---- kernel ------------------------------------------------------------

@test "kernel: zero readable sysctls emits network_params_unreadable, not OK" {
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    _kernel_get_sysctl() { echo ""; }
    _kernel_ipv6_uses_ra() { return 1; }
    _kernel_ip_forward_needed() { return 1; }

    # `run`, not a bare call: the production engine dispatches audits inside
    # an `if` (errexit suppressed), and this function relies on that — an
    # assignment from rc-2 _kernel_check_param aborts it under bare set -e.
    run _kernel_audit_network_params

    run jq -r '.[] | select(.id == "kernel.network_params_unreadable") | .status' \
        "$VPSSEC_STATE/checks.json"
    [ "$output" = "failed" ]
    run jq -r '.[] | select(.id == "kernel.network_params_ok") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

# ---- networking: specific-public binds --------------------------------

@test "networking: dangerous service on a specific PUBLIC address is flagged" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _net_list_listeners() {
        printf 'tcp\tv4\t203.0.113.10\t3306\tmysqld\n'
        printf 'tcp\tv4\t192.168.1.5\t3306\tmysqld\n'
    }

    _net_audit_listeners

    run jq -r '.[] | select(.id == "networking.exposed_dangerous_ports") | .desc' \
        "$VPSSEC_STATE/checks.json"
    [[ "$output" == *"3306@203.0.113.10"* ]]
    # The RFC1918 bind must NOT appear — operator context required there.
    _vpssec_refute grep -q "192.168.1.5" <<<"$output"
}

@test "networking: private-only specific binds still produce no exposure finding" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _net_list_listeners() {
        printf 'tcp\tv4\t10.0.0.5\t3306\tmysqld\n'
    }

    _net_audit_listeners

    run jq -r '.[] | select(.id == "networking.exposed_dangerous_ports") | .id' \
        "$VPSSEC_STATE/checks.json"
    [ -z "$output" ]
}

@test "networking: public/private address classifier boundaries" {
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _net_specific_addr_is_public v4 203.0.113.10
    _net_specific_addr_is_public v6 2001:db8::1
    _vpssec_refute _net_specific_addr_is_public v4 10.1.2.3
    _vpssec_refute _net_specific_addr_is_public v4 172.16.0.1
    # 172.32.x is PUBLIC (outside 172.16/12) — the boundary must not overreach
    _net_specific_addr_is_public v4 172.32.0.1
    _vpssec_refute _net_specific_addr_is_public v4 192.168.9.9
    _vpssec_refute _net_specific_addr_is_public v4 100.64.0.1
    _vpssec_refute _net_specific_addr_is_public v4 169.254.1.1
    _vpssec_refute _net_specific_addr_is_public v6 fe80::1
    _vpssec_refute _net_specific_addr_is_public v6 fd00::1
}

# ---- backup_file failure propagation -----------------------------------

@test "backup_file: cp failure returns 1 and echoes no path" {
    _vpssec_begin_backup_session
    local target="$BATS_TEST_TMPDIR/etcfile"
    echo "content" > "$target"
    _vpssec_stub cp 1

    run backup_file "$target"
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q "$VPSSEC_BACKUP_SESSION" <<<"$output"
}

@test "backup_restore: uncopyable entry counts as skipped, not restored" {
    # Occupy the restore DESTINATION's parent position with a regular file,
    # so `mkdir -p` fails for root and non-root alike (root ignores mode
    # bits, but a file where a directory must go stops everyone).
    local blockdir="$BATS_TEST_TMPDIR/blockdir"
    echo "i am a file, not a directory" > "$blockdir"

    local ts="$VPSSEC_TEST_BACKUP_SESSION_TS"
    local bdir="$VPSSEC_BACKUPS/$ts"
    mkdir -p "$bdir$blockdir"
    echo "old content" > "$bdir$blockdir/target"

    run backup_restore "$ts"
    # Nothing restored, one skip -> rc 1 and the "0 restored" error path.
    [ "$status" -eq 1 ]
}
