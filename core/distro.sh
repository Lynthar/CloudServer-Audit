#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# core/distro.sh - distribution abstraction layer (READ-ONLY / audit subset)
#
# Mirrors the cloud-provider pattern (VPSSEC_CLOUD_PROVIDER/_TIER in
# core/common.sh): detect once, cache in declare -g globals, let any
# module reuse the value. The difference from cloud: distro detection
# must live in core/ (always sourced) and be populated EAGERLY at source
# time, because nearly every module needs it and is_supported_os /
# check_required_deps run before modules load. Detection is cheap
# (reads /etc/os-release + a few `command -v`), so no lazy getter or
# subshell pre-warm dance is required — the globals are set in the
# parent shell before any module's $(...) subshell forks.
#
# Two layers, as designed:
#   * cheap globals (VPSSEC_DISTRO_ID / _FAMILY / _PKG_MGR) for read-only
#     branching ("skip this on Arch"); _FAMILY is the analog of cloud
#     "tier" — modules branch on the family bucket, not the exact ID.
#   * a thin function interface (pkg_* / *_whitelist / *_paths) for
#     behavioural divergence, so modules call one fn instead of growing
#     scattered `case $ID` blocks.
#
# SCOPE: this is the audit (read-only) subset only. Every Debian/Ubuntu
# branch reproduces the current module behaviour verbatim, so wiring a
# module to call these instead of its inline logic is a no-op on
# Debian/Ubuntu. Fix-path primitives (pkg_install, fw_allow_port,
# auto_update_configure, sshd_binary_path, ...) are deliberately NOT
# here — they belong to the later guide-mode multi-distro effort.
#
# STATUS: defined but not yet consumed. Nothing calls these functions
# yet; sourcing this file does not change any audit result. Wiring the
# modules (update.sh, baseline.sh, logging.sh, filesystem.sh, users.sh)
# to call this layer is the next step, gated behind real-box validation
# on RHEL 9 / Rocky / Alma / CentOS Stream 9 / Arch.

# ==============================================================================
# Detection layer
# ==============================================================================

declare -g VPSSEC_DISTRO_ID=""      # raw /etc/os-release ID: debian|ubuntu|rocky|almalinux|centos|fedora|arch|...
declare -g VPSSEC_DISTRO_FAMILY=""  # debian|rhel|arch|suse|unknown  (the "tier"-style bucket)
declare -g VPSSEC_PKG_MGR=""        # apt|dnf|pacman|zypper|unknown

# Read a single /etc/os-release field without leaking its other
# variables into our shell (the file would otherwise define NAME,
# VERSION_ID, PRETTY_NAME, ... as globals). Indirect expansion ${!1}
# fetches the field named by $1.
_distro_osrelease_field() {
    [[ -r /etc/os-release ]] || return 0
    ( . /etc/os-release 2>/dev/null; printf '%s' "${!1:-}" )
}

# Map ID + ID_LIKE to a coarse family. ID is checked first, then each
# ID_LIKE token — this is what lets Rocky/Alma (ID=rocky, ID_LIKE="rhel
# centos fedora"), Manjaro/EndeavourOS (ID_LIKE=arch) and Mint
# (ID_LIKE="ubuntu debian") resolve correctly without enumerating every
# downstream.
_distro_family_from() {
    local id="$1" like="$2" tok
    for tok in "$id" $like; do
        case "$tok" in
            debian|ubuntu|linuxmint|raspbian|pop|devuan|kali)
                echo "debian"; return ;;
            rhel|fedora|centos|rocky|almalinux|ol|oracle|amzn|scientific)
                echo "rhel"; return ;;
            arch|manjaro|endeavouros|arcolinux|garuda)
                echo "arch"; return ;;
            suse|opensuse|opensuse-leap|opensuse-tumbleweed|sles|sled)
                echo "suse"; return ;;
        esac
    done
    echo "unknown"
}

# Package manager by tool presence (more robust than mapping from
# family — covers downstreams we didn't enumerate, and matches the
# convergence note in MULTI_DISTRO_SUPPORT.md §7).
_distro_pkg_mgr() {
    if   command -v apt-get >/dev/null 2>&1; then echo "apt"
    elif command -v dnf     >/dev/null 2>&1; then echo "dnf"
    elif command -v yum     >/dev/null 2>&1; then echo "dnf"   # yum == dnf-compatible CLI
    elif command -v pacman  >/dev/null 2>&1; then echo "pacman"
    elif command -v zypper  >/dev/null 2>&1; then echo "zypper"
    else echo "unknown"
    fi
}

# Populate the globals once. Idempotent and never returns non-zero, so
# it is safe to call at source time under `set -e`.
distro_detect() {
    [[ -n "$VPSSEC_DISTRO_FAMILY" ]] && return 0
    local id like
    id=$(_distro_osrelease_field ID)
    like=$(_distro_osrelease_field ID_LIKE)
    VPSSEC_DISTRO_ID="$id"
    VPSSEC_DISTRO_FAMILY="$(_distro_family_from "$id" "$like")"
    VPSSEC_PKG_MGR="$(_distro_pkg_mgr)"
    export VPSSEC_DISTRO_ID VPSSEC_DISTRO_FAMILY VPSSEC_PKG_MGR
    return 0
}

# ==============================================================================
# Package / update primitives
# ==============================================================================

# Is the native package database locked (an install/upgrade in flight)?
# Returns 0 = locked, 1 = not locked. Read-only.
pkg_manager_locked() {
    case "$VPSSEC_PKG_MGR" in
        apt)
            lsof /var/lib/dpkg/lock-frontend &>/dev/null || \
            lsof /var/lib/apt/lists/lock &>/dev/null || \
            lsof /var/cache/apt/archives/lock &>/dev/null
            ;;
        dnf)
            # dnf/rpm hold a transaction lock; a running dnf/yum/PackageKit
            # process is the reliable read-only signal (the lock file path
            # has moved across rpm versions).
            pgrep -x dnf >/dev/null 2>&1 || \
            pgrep -x yum >/dev/null 2>&1 || \
            pgrep -x packagekitd >/dev/null 2>&1
            ;;
        pacman)
            [[ -e /var/lib/pacman/db.lck ]]
            ;;
        *) return 1 ;;
    esac
}

# Count of pending (all) updates. Echoes an integer (0 on any error).
pkg_update_count() {
    local n out
    case "$VPSSEC_PKG_MGR" in
        apt)
            n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ') || true
            ;;
        dnf)
            # `check-update` exits 100 when updates exist; capture-then-count
            # so pipefail+set -e don't abort on the 100. One package per
            # line, "name.arch  version  repo" — NF>=3 filters headers.
            out=$(LC_ALL=C dnf -q check-update 2>/dev/null) || true
            n=$(awk 'NF>=3 && $1 !~ /^(Last|Obsoleting|Security|Loaded)/ {c++} END{print c+0}' <<<"$out")
            ;;
        pacman)
            # Read-only against the already-synced db (no network refresh).
            n=$(pacman -Qu 2>/dev/null | grep -c .) || true
            ;;
        *) n=0 ;;
    esac
    echo "${n:-0}"
}

# Count of pending SECURITY updates. Echoes an integer, or -1 where the
# distro has no security-update channel (Arch is rolling — callers must
# treat <0 as "not applicable" and not penalise/score it).
pkg_security_update_count() {
    local n out
    case "$VPSSEC_PKG_MGR" in
        apt)
            n=$(apt-get -s upgrade 2>/dev/null | grep -c 'security') || true
            ;;
        dnf)
            out=$(LC_ALL=C dnf -q updateinfo list security 2>/dev/null) || true
            n=$(grep -c . <<<"$out") || true
            ;;
        pacman)
            echo "-1"; return 0
            ;;
        *) n=0 ;;
    esac
    echo "${n:-0}"
}

# How many days since the package index was last refreshed, or empty if
# we cannot tell. Used as an "is the operator paying attention" signal.
pkg_index_age_days() {
    local marker="" mtime now age
    case "$VPSSEC_PKG_MGR" in
        apt)
            if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
                marker=/var/lib/apt/periodic/update-success-stamp
            elif [[ -d /var/lib/apt/lists ]]; then
                marker=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Packages*' 2>/dev/null | head -1)
            fi
            ;;
        dnf)
            # Newest cache metadata under the dnf cache tree.
            marker=$(find /var/cache/dnf -maxdepth 3 -name 'repomd.xml' 2>/dev/null | head -1)
            ;;
        pacman)
            [[ -d /var/lib/pacman/sync ]] && \
                marker=$(find /var/lib/pacman/sync -maxdepth 1 -type f -name '*.db' 2>/dev/null | head -1)
            ;;
    esac
    [[ -z "$marker" || ! -e "$marker" ]] && return 0
    mtime=$(stat -c %Y "$marker" 2>/dev/null || stat -f %m "$marker" 2>/dev/null)
    [[ -z "$mtime" ]] && return 0
    now=$(date +%s)
    age=$(( now - mtime )); (( age < 0 )) && age=0
    echo $(( age / 86400 ))
}

# Latest installed kernel-package version, in a form comparable to
# `uname -r`. Empty if the query tool is unavailable.
pkg_installed_kernel() {
    case "$VPSSEC_PKG_MGR" in
        apt)
            command -v dpkg-query >/dev/null 2>&1 || return 0
            dpkg-query -W -f='${Status}\t${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
                | awk -F'\t' '$1 == "install ok installed" {sub(/^linux-image-/, "", $2); print $2}' \
                | sort -V | tail -1
            ;;
        dnf)
            command -v rpm >/dev/null 2>&1 || return 0
            # `kernel-5.14.0-503.el9.x86_64` -> `5.14.0-503.el9.x86_64`,
            # which is exactly what `uname -r` reports on RHEL.
            rpm -q --last kernel 2>/dev/null | awk 'NR==1{sub(/^kernel-/,"",$1); print $1}'
            ;;
        pacman)
            command -v pacman >/dev/null 2>&1 || return 0
            pacman -Q linux 2>/dev/null | awk '{print $2}'
            ;;
        *) return 0 ;;
    esac
}

_distro_needrestart_kernel_pending() {
    local ksta
    ksta=$(awk -F': ' '/^NEEDRESTART-KSTA:/ {print $2; exit}' <<<"$1")
    [[ "$ksta" =~ ^[0-9]+$ ]] && (( ksta >= 2 ))
}

# True when the running kernel differs from the latest installed one.
_distro_running_kernel_outdated() {
    local running latest
    running="$(uname -r)"
    latest="$(pkg_installed_kernel)"
    [[ -z "$running" || -z "$latest" ]] && return 1
    if [[ "$VPSSEC_DISTRO_FAMILY" == "arch" ]]; then
        # `pacman -Q linux` -> 6.9.3.arch1-1 vs `uname -r` -> 6.9.3-arch1-1;
        # normalise separators before comparing (best-effort).
        running="${running//-/.}"; latest="${latest//-/.}"
    fi
    [[ "$running" != "$latest" ]]
}

# Does the system need a reboot? Returns 0 = reboot required.
pkg_reboot_required() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian)
            [[ -f /var/run/reboot-required ]] && return 0
            if command -v needrestart >/dev/null 2>&1; then
                local out
                if out=$(needrestart -k -b 2>/dev/null); then
                    _distro_needrestart_kernel_pending "$out" && return 0
                fi
            fi
            _distro_running_kernel_outdated
            ;;
        rhel)
            # `needs-restarting -r` (dnf-plugins-core, default-installed):
            # exit 0 = no reboot needed, 1 = reboot needed.
            if command -v needs-restarting >/dev/null 2>&1; then
                local rc=0
                needs-restarting -r >/dev/null 2>&1 || rc=$?
                [[ "$rc" -eq 1 ]] && return 0
            fi
            _distro_running_kernel_outdated
            ;;
        arch)
            _distro_running_kernel_outdated
            ;;
        *) return 1 ;;
    esac
}

# Is an unattended-update mechanism installed? 0 = yes.
auto_update_installed() {
    case "$VPSSEC_PKG_MGR" in
        apt)    dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii' ;;
        dnf)    rpm -q dnf-automatic &>/dev/null ;;
        pacman) return 1 ;;   # Arch has no native auto-update mechanism
        *)      return 1 ;;
    esac
}

# Effective auto-update state. Echoes one of
# ok|service_disabled|periodic_off|no_origins|unsupported|unknown;
# returns 0 iff "ok".
auto_update_status() {
    case "$VPSSEC_PKG_MGR" in
        apt)
            if ! systemctl is-enabled unattended-upgrades &>/dev/null; then
                echo "service_disabled"; return 1
            fi
            command -v apt-config >/dev/null 2>&1 || { echo "unknown"; return 1; }
            local dump per
            dump=$(apt-config dump 2>/dev/null) || { echo "unknown"; return 1; }
            per=$(awk -F'"' '/^APT::Periodic::Unattended-Upgrade /{print $2; exit}' <<<"$dump")
            [[ "$per" == "1" ]] || { echo "periodic_off"; return 1; }
            grep -qE '^Unattended-Upgrade::(Origins-Pattern|Allowed-Origins):: "[^"]+";' <<<"$dump" \
                || { echo "no_origins"; return 1; }
            echo "ok"; return 0
            ;;
        dnf)
            command -v systemctl >/dev/null 2>&1 || { echo "unknown"; return 1; }
            if ! systemctl is-enabled dnf-automatic.timer &>/dev/null; then
                echo "service_disabled"; return 1
            fi
            local conf=/etc/dnf/automatic.conf
            [[ -r "$conf" ]] || { echo "unknown"; return 1; }
            # apply_updates=yes is the switch from download-only to install.
            grep -qE '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*[Yy]es' "$conf" \
                || { echo "periodic_off"; return 1; }
            echo "ok"; return 0
            ;;
        pacman)
            echo "unsupported"; return 1   # rolling release; no security-only channel
            ;;
        *) echo "unknown"; return 1 ;;
    esac
}

# Is a specific package installed? 0 = installed, 1 = not installed,
# 2 = cannot determine (no query tool for this pkg manager).
pkg_is_installed() {
    local pkg="$1"
    case "$VPSSEC_PKG_MGR" in
        apt)
            command -v dpkg-query >/dev/null 2>&1 || return 2
            dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q '^install ok installed$'
            ;;
        dnf)
            command -v rpm >/dev/null 2>&1 || return 2
            rpm -q "$pkg" &>/dev/null
            ;;
        pacman)
            command -v pacman >/dev/null 2>&1 || return 2
            pacman -Q "$pkg" &>/dev/null
            ;;
        *) return 2 ;;
    esac
}

# Per-family package names for the "insecure legacy server" scan in
# baseline.sh (telnet/rsh/tftp/nis/...). The Debian list is taken
# verbatim from modules/baseline.sh; the RHEL/Arch lists are
# best-effort and should be confirmed against real boxes.
distro_insecure_packages() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian)
            echo "telnetd inetutils-telnetd telnet-server rsh-server rsh-redone-server inetutils-inetd openbsd-inetd xinetd fingerd nis ypbind ypserv tftpd tftpd-hpa atftpd talkd ntalkd rwhod"
            ;;
        rhel)
            echo "telnet-server rsh-server xinetd ypserv ypbind tftp-server talk-server finger-server rusers-server rwho"
            ;;
        arch)
            echo "inetutils xinetd rsh tftp-hpa"
            ;;
        *) echo "" ;;
    esac
}

# ==============================================================================
# Path / config-location primitives
# ==============================================================================

# syslog-style log files (under /var/log) to existence-check for the
# logrotate audit. RHEL/Arch route most logging through journald, so the
# list is short there.
distro_log_paths() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) echo "syslog auth.log dpkg.log" ;;
        rhel)   echo "messages secure dnf.rpm.log" ;;
        arch)   echo "pacman.log" ;;
        *)      echo "" ;;
    esac
}

# Per-user crontab spool directory.
cron_spool_dir() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) echo "/var/spool/cron/crontabs" ;;
        *)      echo "/var/spool/cron" ;;   # cronie (RHEL, Arch)
    esac
}

# Candidate GRUB config locations (newline-separated; caller existence-
# checks each). RHEL's real grub.cfg on a UEFI install lives under
# /boot/efi/EFI/<id>/, which the old single-path check missed.
grub_cfg_path() {
    local id="${VPSSEC_DISTRO_ID:-}"
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) printf '%s\n' /boot/grub/grub.cfg ;;
        rhel)   printf '%s\n' /boot/grub2/grub.cfg "/boot/efi/EFI/${id}/grub.cfg" ;;
        arch)   printf '%s\n' /boot/grub/grub.cfg ;;
        *)      printf '%s\n' /boot/grub/grub.cfg /boot/grub2/grub.cfg ;;
    esac
}

# PAM files that define the password stack (hash method / rounds).
pam_password_files() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) echo "/etc/pam.d/common-password" ;;
        *)      echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
    esac
}

# PAM files that define the session stack (pam_umask probe).
pam_session_files() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) echo "/etc/pam.d/common-session /etc/pam.d/common-session-noninteractive" ;;
        *)      echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
    esac
}

# Extra legitimate SUID binary paths beyond the cross-distro base
# whitelist in filesystem.sh. The base list is Debian-pathed; these are
# the RHEL/Arch locations that would otherwise be flagged as "suspicious
# SUID". Best-effort — refine against real boxes during validation.
distro_suid_whitelist() {
    case "$VPSSEC_DISTRO_FAMILY" in
        rhel)
            printf '%s\n' \
                /usr/libexec/openssh/ssh-keysign \
                /usr/libexec/dbus-1/dbus-daemon-launch-helper \
                /usr/libexec/polkit-1/polkit-agent-helper-1 \
                /usr/bin/fusermount /usr/bin/fusermount3 \
                /usr/sbin/mount.nfs /usr/sbin/grub2-set-bootflag
            ;;
        arch)
            printf '%s\n' \
                /usr/lib/ssh/ssh-keysign \
                /usr/lib/polkit-1/polkit-agent-helper-1 \
                /usr/lib/dbus-1.0/dbus-daemon-launch-helper \
                /usr/bin/fusermount /usr/bin/fusermount3 \
                /usr/bin/mount.nfs
            ;;
        *) : ;;   # Debian base list already covers these
    esac
}

# Extra legitimate SGID paths (util-linux / utempter locations differ).
distro_sgid_whitelist() {
    case "$VPSSEC_DISTRO_FAMILY" in
        rhel)
            printf '%s\n' \
                /usr/bin/unix_chkpwd \
                /usr/libexec/utempter/utempter \
                /usr/libexec/openssh/ssh-keysign \
                /usr/bin/write /usr/bin/wall /usr/bin/screen
            ;;
        arch)
            printf '%s\n' \
                /usr/bin/unix_chkpwd \
                /usr/lib/utempter/utempter \
                /usr/bin/write /usr/bin/wall
            ;;
        *) : ;;
    esac
}

# Extra legitimate file-capability entries ("path:cap_name").
distro_caps_whitelist() {
    case "$VPSSEC_DISTRO_FAMILY" in
        rhel)
            printf '%s\n' \
                /usr/bin/ping:cap_net_raw \
                /usr/sbin/suexec:cap_setuid,cap_setgid \
                /usr/bin/newgidmap:cap_setgid \
                /usr/bin/newuidmap:cap_setuid
            ;;
        arch)
            printf '%s\n' \
                /usr/bin/ping:cap_net_raw \
                /usr/bin/newgidmap:cap_setgid \
                /usr/bin/newuidmap:cap_setuid
            ;;
        *) : ;;
    esac
}

# ==============================================================================
# Eager init: populate the globals at source time (parent shell) so every
# module and subshell inherits them. Guarded so it can never abort the
# source under `set -e`.
# ==============================================================================
distro_detect || true
