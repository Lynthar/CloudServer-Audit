#!/usr/bin/env bats
# What the fail2ban audit says about the SSH jail. A jail that is loaded but
# cannot ban still reports "Currently banned: N", so "loaded" alone is no pass.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"
    _f2b_service_active() { return 0; }
    _f2b_ssh_jail_enabled() { return 0; }
    _f2b_get_maxretry() { echo 3; }
}

_checks() { jq -r '[.[] | "\(.id) \(.status) \(.fix_id)"] | join(",")' "$VPSSEC_STATE/checks.json"; }

@test "audit: a jail that bans passes as enabled" {
    _f2b_ssh_jail_bans() { return 0; }
    _f2b_audit_ssh_jail
    [ "$(_checks)" = "fail2ban.ssh_jail_enabled passed " ]
}

@test "audit: a jail that bans no one is a finding, with the fix that repairs it" {
    # Left by a reload across a banaction rename (no action), or by an iptables
    # action on an nftables-only host — vpssec's own fix produced both.
    _f2b_ssh_jail_bans() { return 1; }
    _f2b_audit_ssh_jail
    [ "$(_checks)" = "fail2ban.ssh_jail_not_banning failed fail2ban.configure_ssh_jail" ]
    [ "${CHECK_SCORE_CATEGORY[fail2ban.ssh_jail_not_banning]}" = "recommended" ]
}
