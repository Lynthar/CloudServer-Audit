#!/usr/bin/env bash
# Distribution abstraction for the READ-ONLY audit. Detected once at source
# time into VPSSEC_DISTRO_ID / _FAMILY / _PKG_MGR; modules branch on _FAMILY.
# Fix-path primitives are deliberately absent (see the design notes).

# --- Detection layer ---

declare -g VPSSEC_DISTRO_ID=""      # raw /etc/os-release ID: debian|ubuntu|rocky|almalinux|centos|fedora|arch|...
declare -g VPSSEC_DISTRO_FAMILY=""  # debian|rhel|arch|suse|unknown  (the "tier"-style bucket)
declare -g VPSSEC_PKG_MGR=""        # apt|dnf|pacman|zypper|unknown

# Read one /etc/os-release field without sourcing the file, which would
# define NAME, VERSION_ID, PRETTY_NAME and the rest as our globals.
_distro_osrelease_field() {
    [[ -r /etc/os-release ]] || return 0
    ( . /etc/os-release 2>/dev/null; printf '%s' "${!1:-}" )
}

# Map ID + ID_LIKE to a coarse family, ID first. This resolves Rocky/Alma,
# Manjaro and Mint without enumerating every downstream distro.
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

# Package manager by tool presence, not by mapping from family: family
# mapping is only correct for downstreams we enumerated, presence is also
# correct for the ones we didn't. Corollary: is_supported_os reduces to
# "a distro we have a backend for", so adding one means adding a backend
# here rather than another case arm elsewhere.
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

# --- Package / update primitives ---

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
# The third answer is the point — "I could not tell" must never be spelled
# the same as "no". Sources and blind spots: see the design notes.
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

# Is the package database locked? 0 = locked, 1 = not locked,
# 2 = could not determine. Callers MUST handle all three.
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
            # A running dnf/yum/PackageKit process is the reliable read-only
            # signal; the lock file path has moved across rpm versions.
            # pgrep is required, or every probe exits 127 and reads as free.
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

# Count of pending updates. Echoes an integer, or returns NON-ZERO AND PRINTS
# NOTHING when the query failed. Never conflate those: one digit cannot mean
# both "up to date" and "could not ask". Call in a tested context.
pkg_update_count() {
    local n out
    case "$VPSSEC_PKG_MGR" in
        apt)
            # Capture first: the query's own failure (exit 100 on broken
            # sources/lock) must be distinguishable from "zero Inst lines".
            out=$(apt-get -s upgrade 2>/dev/null) || return 1
            n=$(grep -c '^Inst ' <<<"$out") || n=0
            ;;
        dnf)
            # rc 100 = updates, 0 = none, else error; captured in an `if` so
            # set -e does not abort on 100. Only column-0 lines are packages.
            # -C is required: a read-only audit must not refresh metadata.
            local rc=0
            if out=$(LC_ALL=C dnf -q -C check-update 2>/dev/null); then rc=0; else rc=$?; fi
            case "$rc" in
                100) n=$(awk '/^Obsoleting Packages/{exit} /^[^[:space:]]/ && NF>=3 {c++} END{print c+0}' <<<"$out") ;;
                0)   n=0 ;;
                *)   return 1 ;;
            esac
            ;;
        pacman)
            # `pacman -Qu` exits 1 for BOTH "no updates" and errors; only
            # stderr tells them apart, so the streams are split.
            local err_file err
            err_file=$(mktemp) || return 1
            out=$(pacman -Qu 2>"$err_file") || true
            err=$(<"$err_file")
            rm -f "$err_file"
            [[ -n "$err" ]] && return 1
            n=$(grep -c . <<<"$out") || n=0
            ;;
        *) return 1 ;;
    esac
    echo "${n:-0}"
}

# Count of pending SECURITY updates, or -1 where the distro has no security
# channel (callers must treat <0 as not-applicable, never as zero).
# Non-zero with no output means the query failed.
pkg_security_update_count() {
    local n out
    case "$VPSSEC_PKG_MGR" in
        apt)
            # Anchored on "^Inst " because apt prints Inst and Conf per
            # package. "security" must appear inside the origin parenthetical,
            # so a package merely NAMED *security* is not counted.
            out=$(apt-get -s upgrade 2>/dev/null) || return 1
            n=$(grep -ciE '^Inst .*\(.*security' <<<"$out") || n=0
            ;;
        dnf)
            # UPPER BOUND, not a count: updateinfo lists every package named
            # in an applicable advisory, so on real hosts it can exceed the
            # total. Use as ">0?" only and clamp any displayed figure.
            out=$(LC_ALL=C dnf -q -C updateinfo list --security --available 2>/dev/null) || return 1
            n=$(awk 'NF>=3 {print $NF}' <<<"$out" | sort -u | grep -c .) || n=0
            ;;
        pacman)
            echo "-1"; return 0
            ;;
        *) return 1 ;;
    esac
    echo "${n:-0}"
}

# Newest mtime among the files a find yields; prints nothing when there are
# none. Callers ask when the LAST refresh happened, so `find | head -1` —
# whichever file enumeration surfaced first — is the wrong answer.
_distro_newest_mtime() {
    local newest="" f m
    while IFS= read -r f; do
        m=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null) || continue
        [[ "$m" =~ ^[0-9]+$ ]] || continue
        if [[ -z "$newest" ]] || (( m > newest )); then
            newest="$m"
        fi
    done < <("$@" 2>/dev/null)
    [[ -n "$newest" ]] && echo "$newest"
}

# How many days since the package index was last refreshed, or empty if
# we cannot tell. Used as an "is the operator paying attention" signal.
pkg_index_age_days() {
    local mtime="" now age
    case "$VPSSEC_PKG_MGR" in
        apt)
            if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
                mtime=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null) || mtime=""
            elif [[ -d /var/lib/apt/lists ]]; then
                mtime=$(_distro_newest_mtime find /var/lib/apt/lists -maxdepth 1 -type f -name '*Packages*')
            fi
            ;;
        dnf)
            # Newest cache metadata under the dnf cache tree.
            mtime=$(_distro_newest_mtime find /var/cache/dnf -maxdepth 3 -name 'repomd.xml')
            ;;
        pacman)
            [[ -d /var/lib/pacman/sync ]] && \
                mtime=$(_distro_newest_mtime find /var/lib/pacman/sync -maxdepth 1 -type f -name '*.db')
            ;;
    esac
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
            # Arch's kernel package name varies, so read /usr/lib/modules/
            # instead: each dir name matches `uname -r` exactly.
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

# Parse one answer out of a merged `apt-config dump`; pure functions of their
# argument, so they test without an apt host. auto_update_status below is the
# SINGLE implementation both the audit and the fix's postcondition must use.
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
            # The timer is the periodic driver; the service only flushes at
            # shutdown, so checking it lets a masked timer read as enabled.
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

# Does an installed package own this file? 0 = owned, 1 = not, 2 = cannot
# determine. Callers MUST invoke this in a tested context (`if` / `&&`).
file_owned_by_package() {
    local path="$1"
    case "$VPSSEC_PKG_MGR" in
        apt)
            command -v dpkg-query >/dev/null 2>&1 || return 2
            dpkg-query -S "$path" &>/dev/null && return 0
            # usrmerge: dpkg stores some files under the pre-merge path and
            # does not resolve /bin -> /usr/bin, so retry the aliased path
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

# Per-family package names for baseline.sh's insecure-legacy-server scan.
# The RHEL/Arch lists are best-effort and unconfirmed on real hosts.
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

# The command to SUGGEST to the operator; vpssec never runs these. Never
# write `apt install` into a suggestion: the audit supports three families.
# Returns non-zero and prints nothing when the manager is unknown.
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

# Package names for the given COMMANDS, to feed pkg_install_hint. A command
# name is not a package name — `apt install ss` fails on Debian too.
# Unmapped names pass through, which is right for jq, sed, tar and grep.
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

# The file-integrity package to recommend, or empty where the distro has
# none in its own repositories (AIDE is AUR-only on Arch).
# Empty means "name the tools, do not name a command".
distro_integrity_package() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian|rhel|suse) echo "aide" ;;
        *)                echo "" ;;
    esac
}

# --- Firewall primitives (read-only) ---

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

# --- Path / config-location primitives ---

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

# RHEL/Arch SUID paths beyond filesystem.sh's Debian-pathed base whitelist.
# Best-effort; refine against real hosts.
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

# Eager init: populate the globals at source time (parent shell) so every
# module and subshell inherits them. Guarded so it can never abort the
# source under `set -e`.
distro_detect || true
