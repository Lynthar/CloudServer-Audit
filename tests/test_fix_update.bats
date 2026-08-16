#!/usr/bin/env bats
#
# Coverage for update's three fixes, none of which had a test.
#
# What they write is the switch that turns on automatic package installation,
# which makes the rollback contract the interesting part:
#
#   1. Both backup_file calls were guarded by `[[ -f ]]`. backup_file's other
#      job is recording an ABSENT path in .vpssec_created, which is the only
#      thing that lets a rollback delete a file the fix created — and on a
#      first run, the common case for this fix, neither file exists. So an
#      operator who rolled the whole plan back still had a host installing
#      packages unattended. Sixth and seventh instance of that defect
#      (logging x2, webapp x3); this is where it mattered most.
#   2. write_file_atomic's status was not checked on 20auto-upgrades. The
#      postcondition reads the MERGED apt config, which another file can
#      satisfy, so a failed write could still be reported as success.
#   3. The module carried its own copy of the whole "is auto-update effective"
#      predicate, reachable only from the fix's postcondition, while the audit
#      asked core/distro.sh. They agreed, so nothing was broken — but the fix's
#      success gate and the finding it clears must not be two implementations.
#      Both now delegate to auto_update_status.
#
# apply_security is FIX_RISKY and installs packages, which a rollback cannot
# undo at all; the fix now says so and points at apt's history log.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh
    i18n_load en_US
    export TMPDIR="$BATS_TEST_TMPDIR"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/update.sh"

    etc=$(_vpssec_fake_etc)
    mkdir -p "$etc/apt/apt.conf.d"
    UPDATE_AUTO_UPGRADES_CONF="$etc/apt/apt.conf.d/20auto-upgrades"
    UPDATE_UU_DROPIN="$etc/apt/apt.conf.d/52vpssec-unattended-security"

    # distro.sh dispatches on this; these fixes are the apt ones.
    export VPSSEC_PKG_MGR=apt

    _vpssec_stub systemctl
    _vpssec_stub apt-get
    _vpssec_stub dpkg 0 ''
    # A host where automatic updates are already effective, so the fix's
    # postcondition passes unless a test says otherwise. apt-config is what
    # auto_update_status actually reads.
    _apt_config_effective
}

# ---- stubs -----------------------------------------------------------

# `apt-config dump` output that satisfies all three of auto_update_status's
# conditions. Written as a stub rather than a file because the audit reads the
# MERGED config, never the files the fix writes.
_apt_config_effective() {
    _vpssec_stub_script apt-config <<'SH'
cat <<'DUMP'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
DUMP
SH
}

_apt_config_periodic_off() {
    _vpssec_stub_script apt-config <<'SH'
cat <<'DUMP'
APT::Periodic::Unattended-Upgrade "0";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bookworm-security,label=Debian-Security";
DUMP
SH
}

_uu_installed()     { _vpssec_stub_script dpkg <<'SH'
echo "ii  unattended-upgrades  2.9.1  all  automatic installation of security upgrades"
SH
}
_uu_not_installed() { _vpssec_stub dpkg 0 ''; }

# ==============================================================================
# update.enable_unattended  (FIX_CONFIRM — turns on automatic installation)
# ==============================================================================

@test "enable: the periodic config is written with unattended-upgrade on" {
    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF 'APT::Periodic::Unattended-Upgrade "1";' "$UPDATE_AUTO_UPGRADES_CONF"
}

@test "enable: the drop-in clears inherited origins before setting its own" {
    # Without the #clear lines the distro's own Allowed-Origins stay active and
    # the "security only" promise is not kept.
    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF '#clear Unattended-Upgrade::Allowed-Origins;' "$UPDATE_UU_DROPIN"
    grep -qF '#clear Unattended-Upgrade::Origins-Pattern;' "$UPDATE_UU_DROPIN"
    grep -qF 'Unattended-Upgrade::Origins-Pattern {' "$UPDATE_UU_DROPIN"
}

@test "enable: the drop-in does not reboot the host on its own" {
    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF 'Unattended-Upgrade::Automatic-Reboot "false";' "$UPDATE_UU_DROPIN"
}

@test "enable: 50unattended-upgrades is left alone" {
    # It is a conffile carrying operator settings (Mail, Package-Blacklist).
    # The previous implementation overwrote it — and with a pattern that
    # matched nothing on Debian, so security updates silently stopped.
    printf '// operator settings\nUnattended-Upgrade::Mail "root";\n' \
        > "$etc/apt/apt.conf.d/50unattended-upgrades"

    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF 'Unattended-Upgrade::Mail "root";' "$etc/apt/apt.conf.d/50unattended-upgrades"
}

@test "enable: the drop-in sorts after 50, so it wins the merge" {
    # apt reads apt.conf.d in lexical order; a 52- prefix is the entire reason
    # the #clear above takes effect.
    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    [[ "$(basename "$UPDATE_UU_DROPIN")" > "50unattended-upgrades" ]]
}

@test "enable: Debian gets codename-based security origins" {
    _vpssec_stub_script lsb_release <<'SH'
echo Debian
SH
    detect_os() { echo debian; }

    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF 'label=Debian-Security' "$UPDATE_UU_DROPIN"
    _vpssec_refute grep -qF 'ESMApps' "$UPDATE_UU_DROPIN"
}

@test "enable: Ubuntu gets archive-based security origins including ESM" {
    # Ubuntu's security Suite IS <codename>-security, and ESM apps/infra are
    # separate archives; a Debian-shaped pattern matches neither.
    detect_os() { echo ubuntu; }

    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF 'archive=${distro_codename}-security' "$UPDATE_UU_DROPIN"
    grep -qF 'ESMApps' "$UPDATE_UU_DROPIN"
}

@test "enable: the periodic driver timer is enabled, not just the service" {
    # A masked apt-daily-upgrade.timer with the service enabled used to read as
    # "automatic updates on" while nothing ran on a schedule.
    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    _vpssec_stub_called systemctl 'enable --now apt-daily-upgrade.timer'
}

@test "enable: a first run records both created files so rollback deletes them" {
    # The regression. Neither file exists on a first run, and under the old
    # `[[ -f ]] && backup_file` guard nothing was recorded — so rolling back
    # the plan left the host installing packages unattended.
    _vpssec_begin_backup_session
    [ ! -f "$UPDATE_AUTO_UPGRADES_CONF" ]
    [ ! -f "$UPDATE_UU_DROPIN" ]

    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qxF "$UPDATE_AUTO_UPGRADES_CONF" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
    grep -qxF "$UPDATE_UU_DROPIN" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "enable: a rollback removes what a first run created" {
    _vpssec_begin_backup_session

    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    [ -f "$UPDATE_AUTO_UPGRADES_CONF" ]

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    [ ! -f "$UPDATE_AUTO_UPGRADES_CONF" ]
    [ ! -f "$UPDATE_UU_DROPIN" ]
}

@test "enable: an operator's existing 20auto-upgrades is backed up" {
    printf 'APT::Periodic::Unattended-Upgrade "0";\n' > "$UPDATE_AUTO_UPGRADES_CONF"
    _vpssec_begin_backup_session

    run _update_fix_enable_unattended
    [ "$status" -eq 0 ]
    grep -qF 'Unattended-Upgrade "0";' "${VPSSEC_BACKUP_SESSION}${UPDATE_AUTO_UPGRADES_CONF}"
}

@test "enable: a write the atomic writer refuses is reported, not ignored" {
    # A regular file where the parent directory belongs defeats both the
    # mkdir -p and the mktemp inside write_file_atomic. Not a '..' path any
    # more: backup_file validates the same path and would now abort the fix
    # before the write. The status was unchecked before, and the postcondition
    # reads the merged config — which this stubbed apt-config reports as
    # effective — so the fix would have claimed success.
    VPSSEC_QUIET_SCAN=0
    : > "$etc/apt/notadir"
    UPDATE_AUTO_UPGRADES_CONF="$etc/apt/notadir/20auto-upgrades"

    run _update_fix_enable_unattended
    [ "$status" -eq 1 ]
    grep -q 'automatic updates were not enabled' <<<"$output"
    [ ! -f "$etc/apt/apt.conf.d/20auto-upgrades" ]
}

@test "enable: a drop-in write that fails is reported too" {
    VPSSEC_QUIET_SCAN=0
    : > "$etc/apt/notadir"
    UPDATE_UU_DROPIN="$etc/apt/notadir/52vpssec-unattended-security"

    run _update_fix_enable_unattended
    [ "$status" -eq 1 ]
    grep -q 'security-only origins were not applied' <<<"$output"
}

@test "enable: a host the audit still calls ineffective is not a success" {
    # The postcondition is auto_update_status — the same question the audit
    # asks, so the fix cannot report success on a finding that stays open.
    _apt_config_periodic_off

    run _update_fix_enable_unattended
    [ "$status" -eq 1 ]
}

@test "enable: a masked timer alone fails the postcondition" {
    _vpssec_stub_script systemctl <<'SH'
[[ "$1" == "is-enabled" ]] && exit 1
exit 0
SH

    run _update_fix_enable_unattended
    [ "$status" -eq 1 ]
}

# ==============================================================================
# update.install_unattended  (FIX_CONFIRM — installs, then configures)
# ==============================================================================

@test "install: the package is installed and then configured" {
    run _update_fix_install_unattended
    [ "$status" -eq 0 ]
    _vpssec_stub_called apt-get 'install .*unattended-upgrades'
    grep -qF 'APT::Periodic::Unattended-Upgrade "1";' "$UPDATE_AUTO_UPGRADES_CONF"
}

@test "install: a failed install does not go on to write config" {
    _vpssec_stub apt-get 100

    run _update_fix_install_unattended
    [ "$status" -eq 1 ]
    [ ! -f "$UPDATE_AUTO_UPGRADES_CONF" ]
}

@test "install: a configure step that fails is propagated" {
    # install_unattended returns enable_unattended's status; a green install
    # with a red configure must not read as success.
    _apt_config_periodic_off

    run _update_fix_install_unattended
    [ "$status" -eq 1 ]
}

# ==============================================================================
# update.apply_security  (FIX_RISKY — installs packages; not undoable)
# ==============================================================================

@test "apply: unattended-upgrade is what applies the updates" {
    # Not `apt-get upgrade`, which would upgrade every package on the host.
    _uu_installed
    _vpssec_stub unattended-upgrade 0

    run _update_fix_apply_security
    [ "$status" -eq 0 ]
    _vpssec_stub_called unattended-upgrade
    _vpssec_refute _vpssec_stub_called apt-get 'upgrade'
}

@test "apply: a missing unattended-upgrades is installed first" {
    _uu_not_installed
    _vpssec_stub unattended-upgrade 0

    run _update_fix_apply_security
    [ "$status" -eq 0 ]
    _vpssec_stub_called apt-get 'install .*unattended-upgrades'
}

@test "apply: an install failure aborts instead of upgrading everything" {
    _uu_not_installed
    _vpssec_stub apt-get 100

    run _update_fix_apply_security
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called unattended-upgrade
}

@test "apply: a failed upgrade run is reported as failure" {
    _uu_installed
    _vpssec_stub unattended-upgrade 1

    run _update_fix_apply_security
    [ "$status" -eq 1 ]
}

@test "apply: the operator is told where to see what was upgraded" {
    # Rollback restores config files; installed packages are not files it
    # tracks, so apt's own history log is the only record of what changed.
    VPSSEC_QUIET_SCAN=0
    _uu_installed
    _vpssec_stub unattended-upgrade 0

    run _update_fix_apply_security
    [ "$status" -eq 0 ]
    grep -q '/var/log/apt/history.log' <<<"$output"
}

@test "apply: nothing is claimed about history when the run failed" {
    VPSSEC_QUIET_SCAN=0
    _uu_installed
    _vpssec_stub unattended-upgrade 1

    run _update_fix_apply_security
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q '/var/log/apt/history.log' <<<"$output"
}

# ==============================================================================
# The predicate the audit and the fix now share
# ==============================================================================

@test "predicate: the fix's success gate is the audit's own question" {
    # Both must be auto_update_status. If the module reintroduces a private
    # copy, this fails: the stub reports periodic off, which only a delegating
    # implementation sees.
    _apt_config_periodic_off
    run _update_unattended_enabled
    [ "$status" -eq 1 ]

    _apt_config_effective
    run _update_unattended_enabled
    [ "$status" -eq 0 ]
}

@test "predicate: installed-ness is also the audit's question" {
    _uu_not_installed
    run _update_unattended_installed
    [ "$status" -eq 1 ]

    _uu_installed
    run _update_unattended_installed
    [ "$status" -eq 0 ]
}

@test "predicate: installed-ness follows the package manager, not dpkg" {
    # The apt branch of auto_update_installed is byte-identical to the private
    # copy this module used to keep, so on an apt host the difference is
    # invisible — the delegation is only observable off apt. On a dnf host the
    # question is about dnf-automatic; answering it with `dpkg -l
    # unattended-upgrades` is how a module-local copy drifts from the audit.
    #
    # (The fix BODIES still run apt commands regardless of distro. That is
    # C5-#6 — fix_ids not gated by package manager — and is tracked there;
    # this test is about the predicate, not about making apply_security
    # portable.)
    export VPSSEC_PKG_MGR=dnf
    _uu_installed              # dpkg says unattended-upgrades is installed
    _vpssec_stub rpm 1         # ...but dnf-automatic is not

    run _update_unattended_installed
    [ "$status" -eq 1 ]
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "update_fix: an unknown fix id fails instead of silently doing nothing" {
    run update_fix "update.not_a_real_fix"
    [ "$status" -eq 1 ]
}

@test "update_fix: each known id reaches its implementation" {
    run update_fix "update.enable_unattended"
    [ "$status" -eq 0 ]
    grep -qF 'APT::Periodic::Unattended-Upgrade "1";' "$UPDATE_AUTO_UPGRADES_CONF"

    rm -f "$UPDATE_AUTO_UPGRADES_CONF"
    run update_fix "update.install_unattended"
    [ "$status" -eq 0 ]
    _vpssec_stub_called apt-get 'install'
}

# ---- the backup contract ---------------------------------------------

@test "unattended-upgrades: a backup that cannot be taken aborts the fix" {
    _vpssec_begin_backup_session
    printf 'original\n' > "$UPDATE_AUTO_UPGRADES_CONF"
    _vpssec_stub cp 1

    run _update_fix_enable_unattended
    [ "$status" -ne 0 ]
    [ "$(cat "$UPDATE_AUTO_UPGRADES_CONF")" = "original" ]
}
