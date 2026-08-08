#!/usr/bin/env bats
#
# Coverage for baseline's four fixes. Nothing here was tested before, and
# these have the widest blast radius left in the tool: two of them enforce a
# MAC system and one stops services the operator may be relying on. All four
# are reachable from guide mode (three FIX_CONFIRM, one alert-only).
#
# Five defects motivated this file:
#
#   1. _baseline_fix_selinux_enforcing returned 0 after the persistence step
#      failed — an unexpected config layout printed an error, restored the
#      backup, and then fell through to `return 0`. The finding was recorded
#      as resolved on a host that comes back permissive at the next boot.
#   2. The same fix returned 0 when the config file did not exist at all
#      (Debian with selinux-utils installed), having made a runtime-only
#      change that dies at reboot.
#   3. It edited /etc/selinux/config in place with `sed -i`, i.e. the file
#      that decides how SELinux initialises at boot was rewritten
#      non-atomically, and its layout was only checked afterwards.
#   4. _baseline_fix_enable_apparmor swallowed the apt-get status, so a failed
#      install surfaced as "Failed to enable AppArmor" — pointing at the
#      service rather than at the transaction that actually failed.
#   5. _baseline_fix_disable_unused chained `disable && stop`, so a failed
#      disable skipped the stop and left the service both running and
#      enabled, while a failed stop hid a disable that had landed.
#
# The audit predicate they all rest on had a sixth: `systemctl is-enabled`
# exits 0 for `static` and `indirect` units, which `systemctl disable` cannot
# act on — it exits 0 and changes nothing. That combination is a finding whose
# fix reports success on every run while the next audit re-reports it.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/baseline.sh"

    # Without this, VPSSEC_I18N is empty and `i18n key` echoes the KEY. Every
    # assertion below that greps a message would then be matching the key name,
    # which passes whether or not the key exists in the language files — the
    # exact mistake i18n parity is meant to catch. Loading en_US makes those
    # assertions read the real strings, so a fix that prints an unregistered
    # key fails here rather than shipping "baseline.foo" to the operator.
    i18n_load en_US

    etc=$(_vpssec_fake_etc)
    export TMPDIR="$BATS_TEST_TMPDIR"

    BASELINE_SELINUX_CONFIG="$etc/selinux/config"
    BASELINE_SELINUX_FS_ENFORCE="$etc/sys/fs/selinux/enforce"
    mkdir -p "$etc/selinux" "$etc/sys/fs/selinux"

    _vpssec_stub systemctl
}

# ---- SELinux fixtures ------------------------------------------------
#
# setenforce and getenforce are modelled as the pair they are: `setenforce 1`
# flips the runtime mode and `getenforce` reports it. The marker file is what
# makes the fix's own postcondition observable — with a constant getenforce,
# every success assertion would pass on a fix that never called setenforce.

_selinux_present() {
    : > "$BASELINE_SELINUX_FS_ENFORCE"
    _vpssec_stub_script setenforce <<SH
[[ "\$1" == "1" ]] && : > "$BATS_TEST_TMPDIR/enforcing"
exit 0
SH
    _vpssec_stub_script getenforce <<SH
if [[ -f "$BATS_TEST_TMPDIR/enforcing" ]]; then echo Enforcing; else echo Permissive; fi
SH
}

# The stock layout, comments included: the explanatory block contains the
# string "SELINUX=" inside a comment, which is why the rewrite has to be
# anchored to the start of the line.
_permissive_config() {
    cat > "$BASELINE_SELINUX_CONFIG" <<'EOF'
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
SELINUX=permissive
# SELINUXTYPE= can take one of these values:
SELINUXTYPE=targeted
EOF
}

_config_mode() {
    stat -c '%a' "$BASELINE_SELINUX_CONFIG"
}

# ==============================================================================
# baseline.selinux_set_enforcing  (FIX_CONFIRM — rewrites the boot-mode file)
# ==============================================================================

@test "selinux: a host without setenforce fails instead of editing the config" {
    # The guard is answered here rather than by un-stubbing setenforce, because
    # "is the binary absent" must not depend on what the test host happens to
    # have installed — the tool ships for hosts both with and without
    # selinux-utils. setenforce IS stubbed, so the refutation below is real.
    _selinux_present
    _permissive_config
    _vpssec_absent_command setenforce

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called setenforce
    grep -q '^SELINUX=permissive$' "$BASELINE_SELINUX_CONFIG"
}

@test "selinux: a runtime flip that does not take is not reported as success" {
    # setenforce exits non-zero (SELinux disabled at boot cannot be enabled at
    # runtime). getenforce keeps answering Permissive, and the config must not
    # be rewritten to claim a mode the kernel is not in.
    _selinux_present
    _vpssec_stub setenforce 1
    _permissive_config

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 1 ]
    grep -q '^SELINUX=permissive$' "$BASELINE_SELINUX_CONFIG"
}

@test "selinux: the runtime mode is flipped and persisted" {
    _selinux_present
    _permissive_config

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 0 ]
    _vpssec_stub_called setenforce '1'
    grep -qx 'SELINUX=enforcing' "$BASELINE_SELINUX_CONFIG"
}

@test "selinux: unrelated config lines survive the rewrite" {
    # SELINUXTYPE is what decides which policy loads; losing it turns the next
    # boot into a relabel-everything event.
    _selinux_present
    _permissive_config

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 0 ]
    grep -qx 'SELINUXTYPE=targeted' "$BASELINE_SELINUX_CONFIG"
    grep -q '^# This file controls' "$BASELINE_SELINUX_CONFIG"
    # The commented "SELINUX= can take…" line is the one an unanchored
    # substitution would rewrite into "# SELINUX=enforcing", turning the
    # file's own documentation into a contradiction of itself.
    grep -q '^# SELINUX= can take one of these three values:$' "$BASELINE_SELINUX_CONFIG"
}

@test "selinux: exactly one SELINUX= line is left behind" {
    _selinux_present
    _permissive_config

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 0 ]
    [ "$(grep -c '^SELINUX=' "$BASELINE_SELINUX_CONFIG")" -eq 1 ]
}

@test "selinux: an already-enforcing config is left with one directive" {
    printf 'SELINUX=enforcing\nSELINUXTYPE=targeted\n' > "$BASELINE_SELINUX_CONFIG"
    _selinux_present

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 0 ]
    [ "$(grep -c '^SELINUX=' "$BASELINE_SELINUX_CONFIG")" -eq 1 ]
}

@test "selinux: the config is backed up before it is edited" {
    _permissive_config
    _selinux_present
    _vpssec_begin_backup_session

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 0 ]
    grep -qx 'SELINUX=permissive' "${VPSSEC_BACKUP_SESSION}${BASELINE_SELINUX_CONFIG}"
}

@test "selinux: the config's permissions are not widened" {
    # write_file_atomic copies the mode from the target it replaces. A 0600
    # config that came back 0644 would be a regression introduced by this fix.
    _permissive_config
    chmod 600 "$BASELINE_SELINUX_CONFIG"
    _selinux_present

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 0 ]
    [ "$(_config_mode)" = "600" ]
}

@test "selinux: an unexpected layout leaves the file untouched and fails" {
    # The regression: this used to sed -i first, notice the result had no
    # SELINUX=enforcing line, restore the backup — and return 0 anyway.
    _selinux_present
    printf '# a config with no SELINUX= line at all\nSELINUXTYPE=targeted\n' \
        > "$BASELINE_SELINUX_CONFIG"
    local before
    before=$(cat "$BASELINE_SELINUX_CONFIG")

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 1 ]
    [ "$(cat "$BASELINE_SELINUX_CONFIG")" = "$before" ]
}

@test "selinux: a missing config file is a manual step, not a success" {
    # Debian hosts can have selinux-utils (so setenforce works) with no
    # /etc/selinux/config at all. Returning 0 there recorded the finding as
    # resolved while the host reverts at the next boot.
    VPSSEC_QUIET_SCAN=0
    _selinux_present
    rm -f "$BASELINE_SELINUX_CONFIG"

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 1 ]
    [ ! -f "$BASELINE_SELINUX_CONFIG" ]
    grep -qi 'reboot' <<<"$output"
}

@test "selinux: a write the atomic writer refuses does not claim persistence" {
    # validate_path rejects a path containing '..', which is how the write is
    # made to fail here without mocking write_file_atomic — the real guard
    # chain runs. The live file must survive intact.
    _selinux_present
    _permissive_config
    BASELINE_SELINUX_CONFIG="$etc/selinux/../selinux/config"

    run _baseline_fix_selinux_enforcing
    [ "$status" -eq 1 ]
    grep -qx 'SELINUX=permissive' "$etc/selinux/config"
}

# ==============================================================================
# baseline.selinux_enable  (FIX_ALERT_ONLY — advice, deliberately inert)
# ==============================================================================

@test "selinux enable: the fix reports a manual step rather than success" {
    run _baseline_fix_selinux_enable
    [ "$status" -eq 1 ]
}

@test "selinux enable: the operator is told the steps and the reboot" {
    # This one cannot act: enabling SELinux needs a relabel and a reboot. The
    # printed steps are the entire deliverable, so they are what to pin.
    VPSSEC_QUIET_SCAN=0

    run _baseline_fix_selinux_enable
    [ "$status" -eq 1 ]
    grep -q 'SELINUX=enforcing' <<<"$output"
    grep -q 'SELINUXTYPE=targeted' <<<"$output"
    grep -qi 'reboot' <<<"$output"
}

# ==============================================================================
# baseline.enable_apparmor  (FIX_CONFIRM — installs, enables, starts)
# ==============================================================================

# The guard answers from a marker file, so "not installed" is a property of the
# test rather than of the host, and one test can cover the whole
# install -> enable -> effective lifecycle. The state lives in a file, not in a
# local: a nested function closing over a local captures the NAME, and by call
# time set -u aborts the gate — indistinguishable from the gate refusing.
_apparmor_absent() {
    rm -f "$BATS_TEST_TMPDIR/aa-installed"
    _vpssec_absent_command aa-status "$BATS_TEST_TMPDIR/aa-installed"
}

@test "apparmor: an install that fails is reported as an install failure" {
    # The regression: apt-get's status was discarded, so this path printed
    # "Failed to enable AppArmor" and the operator went looking at the service.
    VPSSEC_QUIET_SCAN=0
    _apparmor_absent
    _vpssec_stub apt-get 100

    run _baseline_fix_enable_apparmor
    [ "$status" -eq 1 ]
    _vpssec_stub_called apt-get 'install .*apparmor'
    # apparmor-utils appears only in the install-failure string, never in the
    # enable-failure one — this is what distinguishes the two messages.
    grep -q 'apparmor-utils' <<<"$output"
}

@test "apparmor: a failed install does not go on to touch the service" {
    _apparmor_absent
    _vpssec_stub apt-get 100

    run _baseline_fix_enable_apparmor
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called systemctl 'enable apparmor'
    _vpssec_refute _vpssec_stub_called systemctl 'start apparmor'
}

@test "apparmor: install, enable, start, and the profile becomes effective" {
    # The whole guide-mode path on a host with no AppArmor at all. apt-get
    # creates the marker check_command reads, so aa-status only becomes
    # available after the install actually ran.
    _apparmor_absent
    _vpssec_stub_script apt-get <<SH
: > "$BATS_TEST_TMPDIR/aa-installed"
exit 0
SH
    _vpssec_stub aa-status 0

    run _baseline_fix_enable_apparmor
    [ "$status" -eq 0 ]
    _vpssec_stub_called apt-get 'install .*apparmor'
    _vpssec_stub_called systemctl 'enable apparmor'
    _vpssec_stub_called systemctl 'start apparmor'
}

@test "apparmor: an already-installed AppArmor is not reinstalled" {
    _vpssec_stub aa-status 0
    _vpssec_stub apt-get 0

    run _baseline_fix_enable_apparmor
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called apt-get
}

@test "apparmor: a service that comes up disabled is reported as failure" {
    # aa-status is present (so the install is skipped) but --enabled says no:
    # a kernel without AppArmor support. The postcondition is the only thing
    # that catches this, since enable/start both succeeded.
    _vpssec_stub aa-status 1

    run _baseline_fix_enable_apparmor
    [ "$status" -eq 1 ]
}

@test "apparmor: a failing systemctl enable does not skip the start" {
    # enable is best-effort — the unit may be static, or already enabled — so
    # its failure is logged and the postcondition decides the outcome. What
    # must not happen is the failure taking the start attempt with it, which is
    # what chaining the two commands would do.
    _vpssec_stub_script systemctl <<'SH'
[[ "$1" == "enable" ]] && exit 1
exit 0
SH
    _vpssec_stub aa-status 0

    run _baseline_fix_enable_apparmor
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'start apparmor'
}

# ==============================================================================
# baseline.disable_unused  (FIX_CONFIRM — stops services the host may need)
# ==============================================================================

# systemctl that reports the named units as `enabled` and everything else as
# absent. $1 names a verb that fails ("none" for the happy path), so the
# disable and stop paths can be broken independently.
_systemctl_units() {
    local fail="$1"; shift
    _vpssec_stub_script systemctl <<SH
fail="$fail"
units="$*"
if [[ "\$1" == "is-enabled" ]]; then
    for u in \$units; do
        if [[ "\$u" == "\$2" ]]; then echo enabled; exit 0; fi
    done
    echo "Failed to get unit file state for \$2: No such file or directory" >&2
    exit 1
fi
if [[ "\$1" == "\$fail" ]]; then exit 1; fi
exit 0
SH
}

@test "unused services: each enabled service is disabled and stopped" {
    _systemctl_units none cups avahi-daemon

    run _baseline_fix_disable_unused
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'disable cups'
    _vpssec_stub_called systemctl 'stop cups'
    _vpssec_stub_called systemctl 'disable avahi-daemon'
    _vpssec_stub_called systemctl 'stop avahi-daemon'
}

@test "unused services: a host with nothing enabled changes nothing" {
    _systemctl_units none

    run _baseline_fix_disable_unused
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called systemctl 'disable'
    _vpssec_refute _vpssec_stub_called systemctl 'stop'
}

@test "unused services: a failed disable still stops the running service" {
    # The regression: `disable && stop` short-circuited, so the service that
    # could not be disabled was also left running until the next reboot — the
    # one moment at which it would have come back anyway.
    _systemctl_units disable cups

    run _baseline_fix_disable_unused
    [ "$status" -ne 0 ]
    _vpssec_stub_called systemctl 'stop cups'
}

@test "unused services: a failed stop is reported even though disable worked" {
    _systemctl_units stop cups

    run _baseline_fix_disable_unused
    [ "$status" -ne 0 ]
    _vpssec_stub_called systemctl 'disable cups'
}

@test "unused services: one failure does not stop the other services" {
    _systemctl_units disable cups avahi-daemon

    run _baseline_fix_disable_unused
    [ "$status" -ne 0 ]
    _vpssec_stub_called systemctl 'stop avahi-daemon'
}

@test "unused services: the operator is given the command that undoes this" {
    # `vpssec rollback` restores files; a disabled unit is invisible to it, so
    # this line is the only way back. It must name the services that were
    # actually disabled.
    VPSSEC_QUIET_SCAN=0
    _systemctl_units none cups avahi-daemon

    run _baseline_fix_disable_unused
    [ "$status" -eq 0 ]
    grep -q 'systemctl enable --now .*cups' <<<"$output"
    grep -q 'systemctl enable --now .*avahi-daemon' <<<"$output"
}

@test "unused services: nothing disabled means no revert hint" {
    VPSSEC_QUIET_SCAN=0
    _systemctl_units none

    run _baseline_fix_disable_unused
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q 'enable --now' <<<"$output"
}

# ==============================================================================
# The predicate all of the above rests on
# ==============================================================================

@test "unused services: a static unit is not offered for disabling" {
    # `systemctl is-enabled` exits 0 for a static unit, and `systemctl disable`
    # then exits 0 while changing nothing — so keying on the exit status
    # produced a finding whose fix succeeds forever and whose audit never
    # clears.
    _vpssec_stub_script systemctl <<'SH'
if [[ "$1" == "is-enabled" ]]; then
    case "$2" in
        cups) echo static; exit 0 ;;
        *) exit 1 ;;
    esac
fi
exit 0
SH

    run _baseline_get_unused_services
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "unused services: an indirect unit is not offered for disabling" {
    _vpssec_stub_script systemctl <<'SH'
if [[ "$1" == "is-enabled" ]]; then
    case "$2" in
        bluetooth) echo indirect; exit 0 ;;
        *) exit 1 ;;
    esac
fi
exit 0
SH

    run _baseline_get_unused_services
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "unused services: a SysV unit is read past systemctl's redirect notice" {
    # For an init script systemctl prints "…is not a native service,
    # redirecting to systemd-sysv-install" before the state word. Ubuntu's
    # apport is exactly this shape, and `disable` does work on it, so it must
    # not be dropped by the state matching.
    _vpssec_stub_script systemctl <<'SH'
if [[ "$1" == "is-enabled" ]]; then
    case "$2" in
        apport)
            echo "apport.service is not a native service, redirecting to systemd-sysv-install."
            echo "Executing: /lib/systemd/systemd-sysv-install is-enabled apport"
            echo enabled
            exit 0 ;;
        *) exit 1 ;;
    esac
fi
exit 0
SH

    run _baseline_get_unused_services
    [ "$status" -eq 0 ]
    [ "$output" = "apport" ]
}

@test "unused services: an enabled-runtime unit IS offered for disabling" {
    # `systemctl enable --runtime` leaves the unit enabled until the next boot,
    # and `disable` does clear it — so this one is actionable and must not be
    # filtered out along with static and indirect.
    _vpssec_stub_script systemctl <<'SH'
if [[ "$1" == "is-enabled" ]]; then
    case "$2" in
        cups) echo enabled-runtime; exit 0 ;;
        *) exit 1 ;;
    esac
fi
exit 0
SH

    run _baseline_get_unused_services
    [ "$status" -eq 0 ]
    [ "$output" = "cups" ]
}

@test "unused services: a masked unit is not offered for disabling" {
    _vpssec_stub_script systemctl <<'SH'
if [[ "$1" == "is-enabled" ]]; then
    case "$2" in
        cups) echo masked; exit 1 ;;
        *) exit 1 ;;
    esac
fi
exit 0
SH

    run _baseline_get_unused_services
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "baseline_fix: an unknown fix id fails instead of silently doing nothing" {
    run baseline_fix "baseline.not_a_real_fix"
    [ "$status" -eq 1 ]
}

@test "baseline_fix: a known fix id reaches its implementation" {
    # selinux_enable is the inert one, so routing can be proven without
    # touching the filesystem or any service.
    VPSSEC_QUIET_SCAN=0

    run baseline_fix "baseline.selinux_enable"
    [ "$status" -eq 1 ]
    grep -qi 'reboot' <<<"$output"
}
