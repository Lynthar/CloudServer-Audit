#!/usr/bin/env bats
# Coverage for fail2ban's four fixes. The assertions are deliberately about
# behaviour — what lands on disk, what a rollback deletes — not about which
# core function a fix calls, so they survive any change to the backup API.

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
    # Both halves are load-bearing, and measured against a real fail2ban-client:
    # jail.d beats the operator's jail.local, and within jail.d the *.local tier
    # beats the distro's defaults-debian.conf. Renaming to .conf loses the second.
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
    # journald running and journalctl working say nothing about whether fail2ban
    # can use the systemd backend — that needs python3-systemd, which Debian only
    # Recommends. Getting it wrong makes fail2ban fail to initialize the jail.
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
    # A drop-in that passes `fail2ban-client -t` can still make fail2ban fail to
    # initialize the jail at runtime, and then the host has NO sshd jail — the
    # distro's own went with ours. A hardening fix must not leave the box worse.
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
    # The other side of the rule above. A missing jail on a host where fail2ban
    # is not running says nothing about our drop-in, and deleting a file that
    # already passed validation throws away correct work.
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
    # enable_service and configure_ssh_jail both consult `systemctl is-active`, so
    # a uniformly answering stub makes them fail together and hides a discarded
    # enable_service status. Split them: down when one looks, up when the other does.
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

# The audit must be able to see what the fix wrote: these three readers must not
# glob jail.d/*.conf only, or the drop-in (a .local) is invisible and the next
# audit contradicts a fix that succeeded.

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

# ---- the backup contract ---------------------------------------------

@test "ssh jail: a backup that cannot be taken aborts the fix" {
    _vpssec_begin_backup_session
    printf '# existing\n' > "$F2B_DROPIN"
    _vpssec_stub cp 1

    run _f2b_fix_configure_ssh_jail
    [ "$status" -ne 0 ]
    [ "$(cat "$F2B_DROPIN")" = "# existing" ]
}

@test "configure: a drop-in this plan created is not removed when there is nothing to restore" {
    # backup_file returns 0 with NO path for a file already registered as
    # fix-created this session, so there is no snapshot to put back — and the
    # file must be left for the plan-level rollback rather than removed here.
    _vpssec_begin_backup_session
    printf '%s\n' '# created earlier in this plan' > "$F2B_DROPIN"
    printf '%s\n' "$F2B_DROPIN" > "$VPSSEC_BACKUP_SESSION/$VPSSEC_CREATED_MANIFEST"
    _f2b_jail_stays_down

    run _f2b_fix_configure_ssh_jail
    [ "$status" -eq 1 ]
    [ -f "$F2B_DROPIN" ]
}
