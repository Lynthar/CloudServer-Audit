#!/usr/bin/env bats
# The names of the drop-ins the fixes write are load-bearing: each tool merges
# its directory in name order, and the name decides whether ours wins. Read as
# the modules ship them — the fix suites point these paths at temp files.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh
    local m
    for m in ssh kernel update fail2ban; do
        # shellcheck source=/dev/null
        source "$(_vpssec_repo_root)/modules/$m.sh"
    done
}

@test "sshd: the hardening drop-in is read first, because sshd keeps the first value" {
    # Include sshd_config.d/*.conf sits above the operator's lines, and a later
    # cloud-init 50- file would otherwise win; the glob only matches *.conf.
    local LC_ALL=C
    [ "$(dirname "$SSH_HARDENING_DROPIN")" = /etc/ssh/sshd_config.d ]
    [[ "$SSH_HARDENING_DROPIN" == *.conf ]]
    [[ "$(basename "$SSH_HARDENING_DROPIN")" < "01" ]]
}

@test "sysctl: the hardening drop-in is applied last, because a later value wins" {
    # Debian 12 links /etc/sysctl.conf in as 99-sysctl.conf; ours must sort after it.
    local LC_ALL=C
    [ "$(dirname "$VPSSEC_SYSCTL_CONF")" = /etc/sysctl.d ]
    [[ "$VPSSEC_SYSCTL_CONF" == *.conf ]]
    [[ "$(basename "$VPSSEC_SYSCTL_CONF")" > "99-sysctl.conf" ]]
}

@test "apt: the unattended-upgrades drop-in is read after 50unattended-upgrades" {
    # Its #clear has to come after the list it clears. apt skips a part named
    # outside [A-Za-z0-9_.-] or with an extension other than .conf.
    local LC_ALL=C name
    name=$(basename "$UPDATE_UU_DROPIN")
    [ "$(dirname "$UPDATE_UU_DROPIN")" = /etc/apt/apt.conf.d ]
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]]
    [[ "$name" != *.* || "$name" == *.conf ]]
    [[ "$name" > "50unattended-upgrades" ]]
}

@test "fail2ban: the jail drop-in is a .local in jail.d" {
    # jail.d outranks the operator's jail.local, and within jail.d the .local
    # tier outranks the distro's defaults-debian.conf; the prefix does not.
    [ "$(dirname "$F2B_DROPIN")" = /etc/fail2ban/jail.d ]
    [[ "$F2B_DROPIN" == *.local ]]
}
