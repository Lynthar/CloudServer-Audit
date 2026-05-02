#!/usr/bin/env bats
#
# Regression tests for _f2b_has_custom_config. The original
# implementation accepted ANY *.conf in jail.d/ as evidence of custom
# tuning, so the Debian/Ubuntu shipped `defaults-debian.conf` (just
# `[sshd] enabled=true`) made every fresh install pass the
# "custom_config" check while still running stock 5-retry / 10-min
# defaults.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"

    # Redirect both config locations to per-test scratch dirs so the
    # test never touches the host /etc/fail2ban tree.
    F2B_JAIL_LOCAL="$BATS_TEST_TMPDIR/jail.local"
    F2B_JAIL_D="$BATS_TEST_TMPDIR/jail.d"
    mkdir -p "$F2B_JAIL_D"
}

@test "no jail.local and empty jail.d → not custom" {
    run _f2b_has_custom_config
    [ "$status" -eq 1 ]
}

@test "only defaults-debian.conf in jail.d → not custom (regression)" {
    # The shipped Debian/Ubuntu file. Used to make every fresh install
    # pass the custom-config check.
    cat >"$F2B_JAIL_D/defaults-debian.conf" <<'EOF'
[sshd]
enabled = true
EOF
    run _f2b_has_custom_config
    [ "$status" -eq 1 ]
}

@test "operator-added jail.d file alongside defaults-debian.conf → custom" {
    cat >"$F2B_JAIL_D/defaults-debian.conf" <<'EOF'
[sshd]
enabled = true
EOF
    cat >"$F2B_JAIL_D/99-operator.conf" <<'EOF'
[sshd]
maxretry = 3
bantime = 3600
EOF
    run _f2b_has_custom_config
    [ "$status" -eq 0 ]
}

@test "non-empty jail.local → custom" {
    cat >"$F2B_JAIL_LOCAL" <<'EOF'
[DEFAULT]
maxretry = 3
EOF
    run _f2b_has_custom_config
    [ "$status" -eq 0 ]
}

@test "jail.local with only comments and whitespace → not custom" {
    cat >"$F2B_JAIL_LOCAL" <<'EOF'
# vim: set ft=ini :
# placeholder, edit me later

EOF
    run _f2b_has_custom_config
    [ "$status" -eq 1 ]
}

@test "jail.local empty + jail.d with operator file → custom" {
    : >"$F2B_JAIL_LOCAL"
    cat >"$F2B_JAIL_D/sshd.local" <<'EOF'
[sshd]
maxretry = 3
EOF
    # sshd.local is in jail.d/ but doesn't end in .conf — current glob
    # matches *.conf only, so this should not by itself flip custom.
    # Add a real .conf to confirm.
    run _f2b_has_custom_config
    [ "$status" -eq 1 ]

    cat >"$F2B_JAIL_D/operator.conf" <<'EOF'
[sshd]
maxretry = 3
EOF
    run _f2b_has_custom_config
    [ "$status" -eq 0 ]
}
