#!/usr/bin/env bats
# cloudflared.setup_service installs and starts a systemd unit; rollback, which
# restores files, cannot remove it, so the fix logs the command that does.

load helpers.bash

setup() {
    _vpssec_load
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloudflared.sh"
    CLOUDFLARED_CONFIG="$BATS_TEST_TMPDIR/config.yml"
    : > "$CLOUDFLARED_CONFIG"
    _vpssec_stub systemctl
    _vpssec_stub cloudflared
}

@test "setup_service: the installed service is logged with the command that removes it" {
    run _cloudflared_fix_setup_service
    [ "$status" -eq 0 ]
    _vpssec_stub_called cloudflared 'service install'
    grep -q 'Undo for cloudflared.setup_service: cloudflared service uninstall' "$VPSSEC_LOGS/vpssec.log"
}

@test "setup_service: nothing is claimed when the service does not start" {
    _vpssec_stub systemctl 1

    run _cloudflared_fix_setup_service
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q 'Undo for cloudflared' "$VPSSEC_LOGS/vpssec.log"
}
