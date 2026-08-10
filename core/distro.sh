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
# STATUS: consumed by the read-only audit path. Modules currently wired
# to this layer:
#   * ufw.sh        — fw_backend
#   * update.sh     — pkg_update_count / pkg_security_update_count /
#                     pkg_index_age_days / pkg_reboot_required /
#                     auto_update_installed / auto_update_status /
#                     pkg_manager_locked
#   * baseline.sh   — pkg_is_installed / distro_insecure_packages
#   * filesystem.sh — file_owned_by_package / distro_suid_whitelist /
#                     distro_sgid_whitelist / distro_caps_whitelist
#   * logging.sh    — distro_log_paths
# Defined but not yet wired to any caller (available for future audit
# wiring): fw_is_enabled, cron_spool_dir, grub_cfg_path,
# pam_password_files, pam_session_files. Validated on the RHEL 8/9/10
# family (Rocky/Alma/CentOS Stream) and Arch for the wired read paths;
# fix-path primitives remain out of scope (guide_mode gates on
# is_debian_based).

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

# Where the kernel publishes currently-held file locks. A variable rather
# than a literal so the predicate below is reachable from a test.
DISTRO_PROC_LOCKS="${DISTRO_PROC_LOCKS:-/proc/locks}"

# The apt lock files, in the order apt itself takes them.
DISTRO_APT_LOCK_FILES=(
    /var/lib/dpkg/lock-frontend
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
)

# Is a lock held on PATH? Echoes exactly one of: held / free / unknown.
#
# Primary source is /proc/locks, which needs no package installed at all —
# apt takes an flock on each of its lock files and the kernel publishes it
# as "MAJOR:MINOR:INODE" in field 5, hex major/minor and decimal inode.
# lsof is kept as a fallback for a host whose procfs is unreadable.
#
# Known blind spot, measured rather than assumed: /proc/locks omits any lock
# whose owning pid the kernel cannot resolve in the READER's pid namespace.
# A lock held only through an inherited descriptor whose original locker has
# exited is therefore invisible here even though it is genuinely held (a
# second flock is still refused). That does not affect the case this exists
# for — apt and dpkg hold their locks from a live process in our own
# namespace — but it is why the tests hold the lock from a live process
# rather than the `exec 9>f; flock -n 9` idiom, which silently proves
# nothing.
#
# The third answer is the point. This used to be three bare `lsof` calls
# ORed together: on a host without lsof each exits 127, the || chain yields
# 1, and the caller read that as "not locked" — so `update.apt_available`,
# a SCORED check, passed for something that was never looked at. vpssec's
# own verification container has no lsof, so that green line was in every
# smoke run. "I could not tell" must not be spelled the same as "no".
_pkg_lock_held() {
    local path="$1"

    # A lock file that does not exist cannot be held by anyone.
    [[ -e "$path" ]] || { printf 'free\n'; return 0; }

    if [[ -r "$DISTRO_PROC_LOCKS" ]]; then
        local dev ino major minor
        if dev=$(stat -c '%d' "$path" 2>/dev/null) && \
           ino=$(stat -c '%i' "$path" 2>/dev/null) && \
           [[ "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ ]]; then
            # glibc's st_dev encoding, which is what /proc/locks prints.
            major=$(( (dev >> 8) & 0xfff ))
            minor=$(( (dev & 0xff) | ((dev >> 12) & ~0xff) ))
            if grep -qE "[[:space:]]$(printf '%02x:%02x:%d' "$major" "$minor" "$ino")[[:space:]]" \
                    "$DISTRO_PROC_LOCKS" 2>/dev/null; then
                printf 'held\n'
            else
                printf 'free\n'
            fi
            return 0
        fi
    fi

    if check_command lsof; then
        if lsof "$path" &>/dev/null; then printf 'held\n'; else printf 'free\n'; fi
        return 0
    fi

    printf 'unknown\n'
}

# Is the native package database locked (an install/upgrade in flight)?
# Returns 0 = locked, 1 = not locked, **2 = could not determine**. Read-only.
# Callers must handle all three — see _pkg_lock_held for what the third one
# costs when it is collapsed into "not locked".
pkg_manager_locked() {
    case "$VPSSEC_PKG_MGR" in
        apt)
            local f state unknown=0
            for f in "${DISTRO_APT_LOCK_FILES[@]}"; do
                state=$(_pkg_lock_held "$f")
                # One held lock settles it; keep looking otherwise, since a
                # later file may be held even if this one was unreadable.
                [[ "$state" == "held" ]] && return 0
                [[ "$state" == "unknown" ]] && unknown=1
            done
            (( unknown )) && return 2
            return 1
            ;;
        dnf)
            # dnf/rpm hold a transaction lock; a running dnf/yum/PackageKit
            # process is the reliable read-only signal (the lock file path
            # has moved across rpm versions).
            #
            # Same trap as the apt branch: without pgrep every probe exits
            # 127 and the || chain says "not locked".
            check_command pgrep || return 2
            pgrep -x dnf >/dev/null 2>&1 || \
            pgrep -x yum >/dev/null 2>&1 || \
            pgrep -x packagekitd >/dev/null 2>&1
            ;;
        pacman)
            # The only branch that needs no external tool.
            [[ -e /var/lib/pacman/db.lck ]]
            ;;
        # An unrecognised package manager is "cannot determine", not "not
        # locked" — we have not looked at anything.
        *) return 2 ;;
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
            # check-update rc: 100 = updates available (list printed), 0 = none,
            # 1 = error. Capture in an `if` so pipefail/set -e don't abort on 100.
            # Count only real package lines: they start in column 0 (long-NEVRA
            # continuation lines are indented) and stop at the trailing
            # "Obsoleting Packages" section. NF>=3 = "name.arch  ver  repo".
            # -C (cacheonly): the audit is read-only and MUST NOT refresh the
            # repo metadata (network I/O, can stall on dead mirrors, and would
            # defeat pkg_index_age_days by touching the very cache it ages).
            # Counts come from the existing cache; a cold cache yields rc=1 → 0.
            local rc=0
            if out=$(LC_ALL=C dnf -q -C check-update 2>/dev/null); then rc=0; else rc=$?; fi
            if [[ "$rc" -eq 100 ]]; then
                n=$(awk '/^Obsoleting Packages/{exit} /^[^[:space:]]/ && NF>=3 {c++} END{print c+0}' <<<"$out")
            else
                n=0
            fi
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
            # Count only the install lines. `apt-get -s upgrade` prints both
            # an "Inst" and a "Conf" line per package, so a bare `grep -c
            # security` double-counted. Anchor on "^Inst " (mirrors the total
            # count) and require "security" to appear INSIDE the origin
            # parenthetical — case-insensitive, since Debian shows the origin
            # as "Debian-Security" while Ubuntu shows "<codename>-security" —
            # so a package merely NAMED *security* (its name precedes the "(")
            # is not miscounted.
            n=$(apt-get -s upgrade 2>/dev/null | grep -ciE '^Inst .*\(.*security') || true
            ;;
        dnf)
            # No dnf command cleanly yields "installed packages that have a
            # pending security update": `updateinfo list` enumerates EVERY
            # package named in an applicable security advisory (incl. ones not
            # installed or already current), and `repoquery --security` ignores
            # --security under dnf5. So this is an UPPER BOUND on real-box data
            # it can exceed the total update count. It IS a reliable
            # has-security-updates signal though (>0 iff any apply — verified
            # non-empty on dnf4 with security updates, 0 on dnf5 with none).
            # Callers: use as ">0?" only; clamp any displayed figure to the total.
            out=$(LC_ALL=C dnf -q -C updateinfo list --security --available 2>/dev/null) || true
            n=$(awk 'NF>=3 {print $NF}' <<<"$out" | sort -u | grep -c .) || true
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
            # Arch's kernel package name varies (linux / linux-lts / linux-zen /
            # linux-hardened), so don't query a fixed package. /usr/lib/modules/
            # lists every installed kernel's module dir, and the dir name matches
            # `uname -r` exactly (e.g. 6.18.31-1-lts) — newest = latest installed.
            [[ -d /usr/lib/modules ]] || return 0
            ls -1 /usr/lib/modules/ 2>/dev/null | sort -V | tail -1
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
    # All branches return a version in `uname -r` format (apt: linux-image
    # NEVRA; rhel: rpm -q --last kernel; arch: /usr/lib/modules dir name),
    # so a direct string compare is correct — no normalisation needed.
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

# Parse one answer out of a merged `apt-config dump`. Both are pure functions
# of their argument so they can be tested without an apt host, and they live
# here rather than in modules/update.sh because `auto_update_status` below is
# the single implementation of this predicate: the audit asks it for its
# verdict and the unattended-upgrades fix asks it whether it succeeded. There
# used to be a second copy of the whole three-step check inside the module,
# reachable only from the fix's postcondition — the two agreed, but an edit to
# either would have made the fix report success on a host the audit still
# flagged, which is the shape that has already bitten this project five times.
_auto_update_apt_periodic_from_dump() {
    local val
    val=$(awk -F'"' '/^APT::Periodic::Unattended-Upgrade /{print $2; exit}' <<<"$1")
    [[ "$val" == "1" ]]
}

# Match list elements (`Key:: "value";`) only; skip the empty-list anchor
# (`Key "";`), which apt emits for a cleared list and which used to read as
# "origins are configured".
_auto_update_apt_origins_from_dump() {
    grep -qE '^Unattended-Upgrade::(Origins-Pattern|Allowed-Origins):: "[^"]+";' <<<"$1"
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
            # apt-daily-upgrade.timer is the periodic driver; the
            # unattended-upgrades service only flushes at shutdown. Checking
            # the service let a masked timer read as enabled (false pass).
            # is-enabled returns 0 for enabled/static, non-zero for
            # masked/disabled — the correct gate.
            if ! systemctl is-enabled apt-daily-upgrade.timer &>/dev/null; then
                echo "service_disabled"; return 1
            fi
            command -v apt-config >/dev/null 2>&1 || { echo "unknown"; return 1; }
            local dump
            dump=$(apt-config dump 2>/dev/null) || { echo "unknown"; return 1; }
            _auto_update_apt_periodic_from_dump "$dump" || { echo "periodic_off"; return 1; }
            _auto_update_apt_origins_from_dump "$dump"  || { echo "no_origins"; return 1; }
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

# Does some installed package own this file? 0 = owned, 1 = not owned,
# 2 = cannot determine (no query tool / unknown pkg manager). Callers
# MUST invoke this in a tested context (`if` / `&&`) so a non-zero result
# from the query tool doesn't trip `set -e` inside the function body.
file_owned_by_package() {
    local path="$1"
    case "$VPSSEC_PKG_MGR" in
        apt)
            command -v dpkg-query >/dev/null 2>&1 || return 2
            dpkg-query -S "$path" &>/dev/null && return 0
            # usrmerge: dpkg records some files under the pre-merge path
            # (/bin, /sbin) and does NOT resolve the /bin -> /usr/bin
            # symlink, so `dpkg -S /usr/bin/foo` misses a file the db
            # stored as /bin/foo (and vice versa). Retry the aliased path
            # before concluding the binary is orphaned.
            local alt=""
            case "$path" in
                /usr/bin/*)  alt="/bin/${path#/usr/bin/}" ;;
                /usr/sbin/*) alt="/sbin/${path#/usr/sbin/}" ;;
                /bin/*)      alt="/usr/bin/${path#/bin/}" ;;
                /sbin/*)     alt="/usr/sbin/${path#/sbin/}" ;;
            esac
            [[ -n "$alt" ]] && dpkg-query -S "$alt" &>/dev/null && return 0
            return 1
            ;;
        dnf)
            command -v rpm >/dev/null 2>&1 || return 2
            rpm -qf "$path" &>/dev/null
            ;;
        pacman)
            command -v pacman >/dev/null 2>&1 || return 2
            pacman -Qo "$path" &>/dev/null
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
            echo "telnetd inetutils-telnetd telnet-server rsh-server rsh-redone-server fingerd nis ypbind ypserv tftpd tftpd-hpa atftpd talkd ntalkd rwhod"
            ;;
        rhel)
            echo "telnet-server rsh-server ypserv ypbind tftp-server talk-server finger-server rusers-server rwho"
            ;;
        arch)
            echo "rsh tftp-hpa"
            ;;
        *) echo "" ;;
    esac
}

# The command that would install / remove PACKAGES on this host, as advice
# printed to the operator. vpssec never runs these: hardening is Debian-only
# and installs there through the module's own apt calls.
#
# They exist because the audit was telling RHEL and Arch operators to run
# `apt install aide`. The audit supports those distros, so a suggestion that
# cannot run on the host it is shown to is the tool asserting something the
# operator can disprove in one command.
#
# Both return non-zero and print nothing when the package manager is unknown,
# rather than guessing — so callers must invoke them in a tested context and
# have something honest to say when there is no answer.
pkg_install_hint() {
    (( $# )) || return 1
    case "$VPSSEC_PKG_MGR" in
        apt)    echo "apt install $*" ;;
        dnf)    echo "dnf install $*" ;;
        pacman) echo "pacman -S $*" ;;
        zypper) echo "zypper install $*" ;;
        *)      return 1 ;;
    esac
}

pkg_remove_hint() {
    (( $# )) || return 1
    case "$VPSSEC_PKG_MGR" in
        # purge, not remove: leaving a disabled service's config behind is
        # what makes it come back on the next reinstall.
        apt)    echo "apt purge $*" ;;
        dnf)    echo "dnf remove $*" ;;
        pacman) echo "pacman -Rns $*" ;;
        zypper) echo "zypper remove $*" ;;
        *)      return 1 ;;
    esac
}

# Package names providing the given COMMANDS, for feeding to pkg_install_hint.
#
# A command name is not a package name, and the preflight suggestion was
# built as though it were: `apt install ss` fails on Debian too, because ss
# ships in iproute2. Only the commands vpssec actually requires are mapped;
# anything unrecognised passes through unchanged, which is right for the ones
# whose package shares their name (jq, sed, tar, grep).
distro_packages_for_commands() {
    local cmd pkg out=()
    for cmd in "$@"; do
        case "$cmd" in
            ss)
                # iproute on RHEL, iproute2 everywhere else.
                [[ "$VPSSEC_DISTRO_FAMILY" == "rhel" ]] && pkg=iproute || pkg=iproute2
                ;;
            systemctl) pkg=systemd ;;
            # mawk provides awk on Debian and gawk is available there too;
            # gawk is the one name that resolves on all four families.
            awk)       pkg=gawk ;;
            *)         pkg="$cmd" ;;
        esac
        out+=("$pkg")
    done
    printf '%s\n' "${out[*]}"
}

# The file-integrity package to recommend, or empty where there is none in
# the distribution's own repositories.
#
# AIDE is packaged by Debian and RHEL but lives in the AUR on Arch, so
# suggesting `pacman -S aide` there would replace one command that cannot run
# with another. An empty answer means "name the tools, do not name a command".
distro_integrity_package() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian|rhel|suse) echo "aide" ;;
        *)                echo "" ;;
    esac
}

# ==============================================================================
# Firewall primitives (read-only)
# ==============================================================================

# Active firewall backend: ufw|firewalld|nftables|iptables|none — same probe
# order as ufw.sh's _detect_firewall (which this is meant to replace). Probes
# are standard across distros; each is guarded with `command -v`.
fw_backend() {
    # LC_ALL=C: ufw gettext-translates "Status: active" under a non-C locale
    # (e.g. zh_CN "状态： 激活"); without it an active UFW is misdetected and
    # the probe falls through to "nftables" (ufw's chains make nft non-empty).
    if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "ufw"
    elif systemctl is-active --quiet firewalld 2>/dev/null; then
        echo "firewalld"
    elif command -v nft >/dev/null 2>&1 && [[ "$(nft list tables 2>/dev/null | wc -l)" -gt 0 ]]; then
        echo "nftables"
    elif command -v iptables >/dev/null 2>&1 && (( "$(iptables -L -n 2>/dev/null | grep -cE '^(ACCEPT|DROP|REJECT)' || true)" > 3 )); then
        echo "iptables"
    else
        echo "none"
    fi
}

# True iff a firewall backend is active.
fw_is_enabled() {
    [[ "$(fw_backend)" != "none" ]]
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
                /usr/sbin/mount.nfs /usr/sbin/grub2-set-bootflag \
                /usr/libexec/cockpit-session
            ;;
        arch)
            printf '%s\n' \
                /usr/lib/ssh/ssh-keysign \
                /usr/lib/polkit-1/polkit-agent-helper-1 \
                /usr/lib/dbus-daemon-launch-helper \
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
                /usr/bin/newuidmap:cap_setuid \
                /usr/libexec/sssd/*:cap_dac_read_search
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
