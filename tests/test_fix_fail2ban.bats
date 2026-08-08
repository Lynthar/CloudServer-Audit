#!/usr/bin/env bats
#
# Coverage for fail2ban's four fixes. Until this file existed the module was
# the only one in the project with selectable fixes and no test touching any
# of them — `ls tests/*fail2ban*.bats` matched test_fail2ban_custom.bats and
# made it look covered, but that suite exercises _f2b_has_custom_config, an
# AUDIT-side predicate. Same name-collision failure mode the backup module hit
# from the other direction; read what a matched suite sources.
#
# What the fixes now have to get right, and what each was getting wrong:
#
#   1. configure_ssh_jail wrote the whole of /etc/fail2ban/jail.local, which is
#      the operator's file. It now writes jail.d/99-vpssec-sshd.local, so a
#      hand-written multi-jail or ignoreip config survives. What makes the
#      drop-in take effect was measured against a real fail2ban-client, not
#      assumed: jail.d beats jail.local, and within jail.d the *.local tier
#      beats the *.conf tier. The `99-` prefix does none of that work — in byte
#      order it sorts before `defaults-`.
#   2. backup_file sat under an `[[ -f ]]` guard. Its other job is recording an
#      ABSENT path in .vpssec_created, the only thing that lets a rollback
#      delete a fix-created file — and the drop-in never exists beforehand, so
#      nothing was recorded and `vpssec rollback` left this tool's jail config
#      live. Eighth instance of that defect; it hid from the closing grep
#      because the guard and the call were on separate lines.
#   3. Three audit-side readers globbed only jail.d/*.conf, so they could not
#      see the .local the fix had just written: on the file-fallback path the
#      fix would succeed and the next audit would report "using default
#      configuration only". Verified against a real fail2ban-client that both
#      suffixes are read and that [DEFAULT] in a drop-in takes effect.
#   4. install auto-configured whenever jail.local was absent. The question that
#      matters is whether the OPERATOR configured anything, which is what
#      _f2b_has_custom_config answers — and it deliberately ignores the distro's
#      shipped defaults-debian.conf, so a fresh install still gets configured.
#
# The assertions are deliberately about behaviour — what lands on disk, what a
# rollback deletes — not about which core function the fix calls, so they stay
# valid through any later change to the backup API.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    export TMPDIR="$BATS_TEST_TMPDIR"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"

    etc=$(_vpssec_fake_etc)
    mkdir -p "$etc/fail2ban/jail.d"
    F2B_CONFIG="$etc/fail2ban/fail2ban.conf"
    F2B_JAIL_LOCAL="$etc/fail2ban/jail.local"
    F2B_JAIL_D="$etc/fail2ban/jail.d"
    F2B_DROPIN="$etc/fail2ban/jail.d/99-vpssec-sshd.local"
    # The fix sleeps to let fail2ban load the jail. 0 here; the production
    # default stays 2.
    F2B_RELOAD_SETTLE=0

    # A host where everything the fix shells out to succeeds. Individual tests
    # re-stub what they need to fail. Stubbing also makes the fix's own
    # `command -v fail2ban-client` guard see the client as present.
    _vpssec_stub systemctl
    _vpssec_stub apt-get
    _vpssec_stub fail2ban-client
    # `port 2222` because get_ssh_port reads `sshd -T` first and falls back to
    # grepping the real /etc/ssh/sshd_config — an unstubbed sshd would let the
    # test host decide what lands in the drop-in.
    _vpssec_stub sshd 0 'port 2222'
}

# The postcondition (_f2b_ssh_jail_enabled) needs the client to answer for the
# sshd jail AND the service to be active. Both go through stubs.
_f2b_jail_comes_up() {
    _vpssec_stub_script fail2ban-client <<'SH'
case "$*" in
    "status sshd") exit 0 ;;
    -t)            exit 0 ;;
    *)             exit 0 ;;
esac
SH
}

_f2b_jail_stays_down() {
    _vpssec_stub_script fail2ban-client <<'SH'
case "$*" in
    "status sshd") exit 1 ;;
    "status ssh")  exit 1 ;;
    -t)            exit 0 ;;
    *)             exit 0 ;;
esac
SH
}

_f2b_config_test_fails() {
    _vpssec_stub_script fail2ban-client <<'SH'
case "$*" in
    -t) exit 1 ;;
    *)  exit 0 ;;
esac
SH
}

# ==============================================================================
# configure_ssh_jail — where the drop-in lands
# ==============================================================================

@test "configure: writes the jail.d drop-in, not jail.local" {
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    [ -f "$F2B_DROPIN" ]
    _vpssec_refute test -e "$F2B_JAIL_LOCAL"
}

@test "configure: an operator's hand-written jail.local survives byte for byte" {
    # The whole point of the drop-in. Before this change the fix replaced this
    # file wholesale and the operator's other jails went with it.
    cat > "$F2B_JAIL_LOCAL" <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 198.51.100.9

[postfix]
enabled = true
EOF
    local before
    before=$(sha256sum < "$F2B_JAIL_LOCAL")

    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    [ "$(sha256sum < "$F2B_JAIL_LOCAL")" = "$before" ]
}

@test "configure: the drop-in lands in jail.d and is a .local" {
    # Both halves are load-bearing, and measurement (see the module header)
    # rather than convention decides them: jail.d is what beats the operator's
    # jail.local, and the *.local tier is what beats the distro's own
    # jail.d/defaults-debian.conf. Renaming it to .conf would lose the second
    # while looking harmless.
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    [ "$(dirname "$F2B_DROPIN")" = "$F2B_JAIL_D" ]
    [[ "$F2B_DROPIN" == *.local ]]
    [ -f "$F2B_DROPIN" ]
}

@test "configure: the drop-in carries the sshd jail and the hardened values" {
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^\[sshd\]' "$F2B_DROPIN"
    grep -qE '^enabled = true' "$F2B_DROPIN"
    grep -qE '^maxretry = 3' "$F2B_DROPIN"
}

@test "configure: loopback is always in ignoreip" {
    # maxretry=3 over a 10-minute window means three fat-fingered passwords
    # ban the source. Without this the tool's own jail can lock the operator
    # out of the box it just hardened.
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^ignoreip = .*127\.0\.0\.1/8' "$F2B_DROPIN"
    grep -qE '^ignoreip = .*::1' "$F2B_DROPIN"
}

@test "configure: the operator's current SSH source address is whitelisted" {
    export SSH_CONNECTION="203.0.113.44 51234 10.0.0.5 22"
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^ignoreip = .*203\.0\.113\.44' "$F2B_DROPIN"
}

@test "configure: the jail watches the port sshd actually listens on" {
    # Hardcoding 22 gives a jail that watches a port nothing connects to, on
    # exactly the hosts that moved SSH off 22 to cut the noise.
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^port = 2222' "$F2B_DROPIN"
}

@test "configure: a failed write is reported as a failure" {
    # The parent of the target is a regular file, so write_file_atomic's mkdir
    # and mktemp both fail. Nothing must report success off the back of that.
    printf 'not a directory\n' > "$etc/fail2ban/blocked"
    F2B_DROPIN="$etc/fail2ban/blocked/99-vpssec-sshd.local"
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "configure: the systemd backend is only chosen when fail2ban can read the journal" {
    # journald running and journalctl working say nothing about whether
    # fail2ban can use the systemd backend — that needs the python3-systemd
    # module, which Debian only Recommends. Getting this wrong makes fail2ban
    # fail to initialize the jail at all. Measured against a real fail2ban.
    _vpssec_stub systemctl          # journald active
    _vpssec_stub journalctl
    _vpssec_stub python3 1          # `import systemd.journal` fails
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    _vpssec_refute grep -qE '^backend = systemd' "$F2B_DROPIN"
}

@test "configure: the systemd backend is chosen when the module is there" {
    _vpssec_stub systemctl
    _vpssec_stub journalctl
    _vpssec_stub python3 0
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^backend = systemd' "$F2B_DROPIN"
}

@test "configure: the detected banaction is what gets written" {
    # A hardcoded iptables-multiport silently no-ops on an nftables host:
    # fail2ban loads the jail and reports it active while every ban fails.
    _vpssec_stub_script ufw <<'SH'
echo "Status: active"
SH
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^banaction = ufw' "$F2B_DROPIN"
    grep -qE '^banaction_allports = ufw' "$F2B_DROPIN"
}

# ==============================================================================
# configure_ssh_jail — the rollback contract
# ==============================================================================

@test "configure: a created drop-in is recorded so rollback can delete it" {
    _vpssec_begin_backup_session
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    [ -f "$F2B_DROPIN" ]
    grep -qxF "$F2B_DROPIN" "$VPSSEC_BACKUP_SESSION/.vpssec_created"
}

@test "configure: rolling the session back removes the drop-in" {
    # The end-to-end version of the assertion above, and the one the operator
    # actually cares about: `vpssec rollback` used to leave this tool's jail
    # configuration live on a host whose owner had asked to undo it.
    _vpssec_begin_backup_session
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    [ -f "$F2B_DROPIN" ]

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "configure: an existing drop-in is snapshotted, and rollback restores it" {
    _vpssec_begin_backup_session
    printf '%s\n' '# operator edited this' > "$F2B_DROPIN"

    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'operator edited this' "$F2B_DROPIN"

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    grep -q 'operator edited this' "$F2B_DROPIN"
}

# ==============================================================================
# configure_ssh_jail — failure paths
# ==============================================================================

@test "configure: a failed config test removes the drop-in it just created" {
    _f2b_config_test_fails
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "configure: a failed config test restores the previous drop-in" {
    printf '%s\n' '# previous drop-in' > "$F2B_DROPIN"
    _f2b_config_test_fails
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    grep -q 'previous drop-in' "$F2B_DROPIN"
}

@test "configure: a pre-existing drop-in is never deleted when there is no backup to restore" {
    # No backup session and backup_file's standalone copy unavailable: the
    # cleanup must leave a file it cannot put back, not remove it.
    printf '%s\n' '# precious' > "$F2B_DROPIN"
    _f2b_config_test_fails
    export VPSSEC_BACKUPS=/proc/vpssec-cannot-write-here
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    [ -f "$F2B_DROPIN" ]
}

@test "configure: a jail that never comes up is reported as a failure" {
    _f2b_jail_stays_down
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
}

@test "configure: a jail that never comes up gets the drop-in taken back out" {
    # Found by running the fix against a real fail2ban, not by any stub. A
    # drop-in that passes `fail2ban-client -t` can still make fail2ban fail to
    # initialize the jail at runtime, and then the host has NO sshd jail — the
    # distro's own went with ours. Reporting the failure is not enough; a
    # hardening fix must not leave the box less protected than it found it.
    _f2b_jail_stays_down
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "configure: a previous drop-in is put back when the jail does not come up" {
    printf '%s\n' '# the config that was working' > "$F2B_DROPIN"
    _vpssec_begin_backup_session
    _f2b_jail_stays_down
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    grep -q 'the config that was working' "$F2B_DROPIN"
}

@test "configure: a down service does not cost us a validated drop-in" {
    # The other side of the rule above. A missing jail on a host where
    # fail2ban is not running says nothing about our drop-in, and deleting a
    # file that already passed validation throws away correct work — install
    # on a service that is slow to start is exactly this case.
    _vpssec_stub systemctl 3          # is-active fails: service down
    _f2b_jail_stays_down
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    [ -f "$F2B_DROPIN" ]
}

@test "configure: the reported failure names the postcondition, not the write" {
    VPSSEC_QUIET_SCAN=0
    _f2b_jail_stays_down
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    [[ "$output" == *"Failed to configure SSH jail"* ]]
}

@test "configure: a legacy vpssec-written jail.local is called out as superseded" {
    # Otherwise the host carries two vpssec configs and nothing on screen says
    # which one is in effect.
    VPSSEC_QUIET_SCAN=0
    printf '%s\n' '# vpssec fail2ban configuration' 'maxretry = 9' > "$F2B_JAIL_LOCAL"
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    [[ "$output" == *"written by an earlier version"* ]]
}

@test "configure: an operator's jail.local is not called ours" {
    VPSSEC_QUIET_SCAN=0
    printf '%s\n' '[postfix]' 'enabled = true' > "$F2B_JAIL_LOCAL"
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'written by an earlier version' <<<"$output"
}

# ==============================================================================
# enable_ssh_jail — the other entry point into the same fix
# ==============================================================================

@test "enable_ssh_jail: writes the same drop-in configure does" {
    _f2b_jail_comes_up
    run _f2b_fix_enable_ssh_jail
    [ "$status" -eq 0 ]
    grep -qE '^\[sshd\]' "$F2B_DROPIN"
}

@test "enable_ssh_jail: propagates the failure rather than reporting success" {
    _f2b_jail_stays_down
    run _f2b_fix_enable_ssh_jail
    [ "$status" -eq 1 ]
}

# ==============================================================================
# enable_service
# ==============================================================================

@test "enable_service: enables at boot as well as starting" {
    # Starting without enabling gives a host that is protected until its next
    # reboot and silently unprotected afterwards.
    _vpssec_stub systemctl
    run _f2b_fix_enable_service
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'enable fail2ban'
    _vpssec_stub_called systemctl 'start fail2ban'
}

@test "enable_service: a service that does not come up is a failure" {
    _vpssec_stub_script systemctl <<'SH'
case "$*" in
    *is-active*) exit 3 ;;
    *)           exit 0 ;;
esac
SH
    run _f2b_fix_enable_service
    [ "$status" -eq 1 ]
}

# ==============================================================================
# install
# ==============================================================================

@test "install: a failing apt-get is not reported as success" {
    _vpssec_stub apt-get 100
    run _f2b_fix_install
    [ "$status" -eq 1 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "install: configures the jail on a host with no operator tuning" {
    _f2b_jail_comes_up
    run _f2b_fix_install
    [ "$status" -eq 0 ]
    [ -f "$F2B_DROPIN" ]
}

@test "install: the distro's own defaults-debian.conf does not count as tuning" {
    # It ships with the package and carries no real tuning, so a fresh install
    # must still get configured. This is the regression that made every fresh
    # install report a custom config while running stock defaults.
    printf '%s\n' '[sshd]' 'enabled = true' > "$F2B_JAIL_D/defaults-debian.conf"
    _f2b_jail_comes_up
    run _f2b_fix_install
    [ "$status" -eq 0 ]
    [ -f "$F2B_DROPIN" ]
}

@test "install: an operator's jail.local stops it from configuring unasked" {
    # install is FIX_SAFE, auto-applied with no confirm; configure_ssh_jail is
    # CONFIRM-class because its drop-in overrides the operator's values. Running
    # it transitively from install would bypass that gate.
    printf '%s\n' '[postfix]' 'enabled = true' > "$F2B_JAIL_LOCAL"
    _f2b_jail_comes_up
    run _f2b_fix_install
    [ "$status" -eq 0 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "install: an operator's own jail.d file also stops it" {
    # The old gate asked only about jail.local, so a host tuned entirely
    # through jail.d got configured without confirmation.
    printf '%s\n' '[sshd]' 'maxretry = 10' > "$F2B_JAIL_D/50-operator.local"
    _f2b_jail_comes_up
    run _f2b_fix_install
    [ "$status" -eq 0 ]
    _vpssec_refute test -e "$F2B_DROPIN"
}

@test "install: a jail that fails to configure fails the install" {
    _f2b_jail_stays_down
    run _f2b_fix_install
    [ "$status" -eq 1 ]
}

@test "install: a service that fails to start fails the install" {
    _vpssec_stub_script systemctl <<'SH'
case "$*" in
    *is-active*) exit 3 ;;
    *)           exit 0 ;;
esac
SH
    run _f2b_fix_install
    [ "$status" -eq 1 ]
}

@test "install: a service that failed to start still fails it once the jail comes up" {
    # The test above cannot pin enable_service's return value. Both it and
    # configure_ssh_jail's postcondition consult `systemctl is-active`, so a
    # stub answering uniformly makes them fail together — discarding
    # enable_service's status then looks harmless because configure fails
    # anyway, and the mutation survives. Split them with a service that is
    # down when enable_service looks and up by the time configure does, which
    # is also the real "slow to start" case.
    local marker="$BATS_TEST_TMPDIR/f2b-came-up"
    _vpssec_stub_script systemctl <<SH
case "\$*" in
    *is-active*)
        [[ -e "$marker" ]] && exit 0
        : > "$marker"
        exit 3
        ;;
    *) exit 0 ;;
esac
SH
    _f2b_jail_comes_up
    run _f2b_fix_install
    [ "$status" -eq 1 ]
    # ...and the failure is enable_service's alone: configure did its job.
    [ -f "$F2B_DROPIN" ]
}

# ==============================================================================
# The audit must be able to see what the fix wrote
# ==============================================================================
#
# These three readers globbed jail.d/*.conf only. The drop-in is a .local, so
# the fix succeeded and the next audit contradicted it.

@test "audit: the drop-in counts as custom config" {
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    run _f2b_has_custom_config
    [ "$status" -eq 0 ]
}

@test "audit: maxretry is read back out of the drop-in" {
    # The file fallback, i.e. the path taken whenever fail2ban-client cannot
    # answer. Default is 5, and the drop-in sets 3 — so a reader that cannot
    # see the file returns the value the fix exists to change.
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    _vpssec_stub systemctl 3      # service inactive -> file fallback
    run _f2b_get_maxretry
    [ "$output" = "3" ]
}

@test "audit: bantime is read back out of the drop-in" {
    _f2b_jail_comes_up
    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 0 ]
    _vpssec_stub systemctl 3
    run _f2b_get_bantime
    [ "$output" = "1h" ]
}

@test "audit: a jail.d holding only the distro default is still not custom" {
    # Guards the widened glob from the other side: adding *.local must not
    # make the shipped defaults-debian.conf start counting.
    printf '%s\n' '[sshd]' 'enabled = true' > "$F2B_JAIL_D/defaults-debian.conf"
    run _f2b_has_custom_config
    [ "$status" -eq 1 ]
}
