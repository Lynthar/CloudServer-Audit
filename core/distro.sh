#!/usr/bin/env bash
# Distribution abstraction for the READ-ONLY audit. Detected once at source
# time into VPSSEC_DISTRO_ID / _FAMILY / _PKG_MGR; modules branch on _FAMILY.
# No fix-path primitives: fixes run on Debian/Ubuntu only and call apt directly.

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

# Is package manager $1's command installed? yum counts as dnf: same CLI.
_distro_pkg_tool_present() {
    case "$1" in
        apt) command -v apt-get >/dev/null 2>&1 ;;
        dnf) command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 ;;
        *)   command -v "$1" >/dev/null 2>&1 ;;
    esac
}

# Package manager for family $1: its own tool when present (Arch's repositories
# carry apt and dnf too), else the first tool present, which also covers
# downstreams nobody enumerated. A new distro needs a backend, not a case arm.
_distro_pkg_mgr() {
    local -a order=(apt dnf pacman zypper)
    case "$1" in
        rhel) order=(dnf apt pacman zypper) ;;
        arch) order=(pacman apt dnf zypper) ;;
        suse) order=(zypper apt dnf pacman) ;;
    esac
    local mgr
    for mgr in "${order[@]}"; do
        if _distro_pkg_tool_present "$mgr"; then
            echo "$mgr"
            return 0
        fi
    done
    echo "unknown"
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
    VPSSEC_PKG_MGR="$(_distro_pkg_mgr "$VPSSEC_DISTRO_FAMILY")"
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

# Is a lock held on PATH? Echoes held / free / unknown: /proc/locks, else lsof,
# and "unknown", never "free", when neither can answer. /proc/locks hides a lock
# whose holder process has exited (an inherited fd): test with a live holder.
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

# `apt upgrade`, simulated without writing (a bare -s rebuilds stale caches and
# overwrites eipp.log.xz). --with-new-pkgs: a kernel ABI bump is not kept back
# unseen. Only Inst lines with a [current version] are upgrades.
_distro_apt_simulate_upgrade() {
    apt-get -s -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
        -o Dir::Log::Planner=/dev/null upgrade --with-new-pkgs
}

# A cache-only dnf query (-C: a read-only audit must not refresh metadata),
# with dnf's own logs sent to a throwaway directory instead of /var/log.
# Returns dnf's status, so check-update's 100 ("updates exist") survives.
_distro_dnf_query() {
    local logdir rc=0
    logdir=$(mktemp -d) || return 1
    LC_ALL=C dnf -q -C --setopt=logdir="$logdir" "$@" || rc=$?
    rm -rf "$logdir"
    return "$rc"
}

# Packages `check-update [args]` lists, or non-zero when the query failed. Its
# rc 100 means "some" and is captured in an `if`, so set -e does not abort on
# it. Only column-0 lines are packages; "Obsoleting Packages" ends the list.
_distro_dnf_update_count() {
    local out rc=0
    if out=$(_distro_dnf_query check-update "$@" 2>/dev/null); then rc=0; else rc=$?; fi
    case "$rc" in
        100) awk '/^Obsoleting Packages/{exit} /^[^[:space:]]/ && NF>=3 {c++} END{print c+0}' <<<"$out" ;;
        0)   echo 0 ;;
        *)   return 1 ;;
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
            out=$(_distro_apt_simulate_upgrade 2>/dev/null) || return 1
            n=$(grep -c '^Inst [^ ]* \[' <<<"$out") || n=0
            ;;
        dnf)
            n=$(_distro_dnf_update_count) || return 1
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
            out=$(_distro_apt_simulate_upgrade 2>/dev/null) || return 1
            n=$(grep -ciE '^Inst [^ ]* \[.*\(.*security' <<<"$out") || n=0
            ;;
        dnf)
            # Installed packages with a pending security update. Not updateinfo:
            # it names every package in an applicable advisory, installed or not.
            n=$(_distro_dnf_update_count --security) || return 1
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

# Where apt keeps its index and apt-daily its success stamp. Variables rather
# than literals so the age predicate below is reachable from a test.
DISTRO_APT_LISTS="${DISTRO_APT_LISTS:-/var/lib/apt/lists}"
DISTRO_APT_STAMP="${DISTRO_APT_STAMP:-/var/lib/apt/periodic/update-success-stamp}"

# How many days since the package index was last refreshed, or empty if
# we cannot tell. Used as an "is the operator paying attention" signal.
pkg_index_age_days() {
    local mtime="" now age
    case "$VPSSEC_PKG_MGR" in
        apt)
            # The stamp is apt-daily's alone; a manual `apt-get update` refreshes
            # only lists/, where InRelease changes with every archive publish.
            mtime=$(_distro_newest_mtime find "$DISTRO_APT_STAMP" "$DISTRO_APT_LISTS" \
                -maxdepth 1 -type f \( -path "$DISTRO_APT_STAMP" \
                -o -name '*Release' -o -name '*Packages*' \))
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

# Where installed kernels and Ubuntu's reboot flag live. Variables rather than
# literals so the reboot answers below are reachable from a test.
DISTRO_MODULES_DIR="${DISTRO_MODULES_DIR:-/usr/lib/modules}"
DISTRO_REBOOT_FLAG="${DISTRO_REBOOT_FLAG:-/var/run/reboot-required}"

# Latest installed kernel-package version, in a form comparable to
# `uname -r`. Empty if the query tool is unavailable or no kernel is installed.
pkg_installed_kernel() {
    local out
    case "$VPSSEC_PKG_MGR" in
        apt)
            command -v dpkg-query >/dev/null 2>&1 || return 0
            dpkg-query -W -f='${Status}\t${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
                | awk -F'\t' '$1 == "install ok installed" {sub(/^linux-image-/, "", $2); print $2}' \
                | sort -V | tail -1
            ;;
        dnf)
            command -v rpm >/dev/null 2>&1 || return 0
            # "package kernel is not installed" goes to STDOUT, with rc 1, so
            # only a query that succeeded has a version in it.
            out=$(rpm -q --last kernel 2>/dev/null) || return 0
            # `kernel-5.14.0-503.el9.x86_64` -> `5.14.0-503.el9.x86_64`,
            # which is exactly what `uname -r` reports on RHEL.
            awk 'NR==1{sub(/^kernel-/,"",$1); print $1}' <<<"$out"
            ;;
        pacman)
            # Arch's kernel package name varies, so read the modules dir
            # instead: each dir name matches `uname -r` exactly.
            [[ -d "$DISTRO_MODULES_DIR" ]] || return 0
            ls -1 "$DISTRO_MODULES_DIR"/ 2>/dev/null | sort -V | tail -1
            ;;
        *) return 0 ;;
    esac
}

# needrestart's batch-mode kernel state: 0 = a newer kernel awaits a reboot
# (KSTA 2, ABI-compatible, or 3), 1 = the running kernel is the newest,
# 2 = no answer (KSTA 0 is needrestart's own detection failure).
_distro_needrestart_kernel_pending() {
    local ksta
    ksta=$(awk -F': ' '/^NEEDRESTART-KSTA:/ {print $2; exit}' <<<"$1")
    [[ "$ksta" =~ ^[0-9]+$ ]] || return 2
    (( ksta >= 2 )) && return 0
    (( ksta == 1 )) && return 1
    return 2
}

# Running kernel against the newest installed one: 0 = they differ (the change
# is printed), 1 = the same, 2 = nothing to compare with — no kernel package,
# as in a container, whose kernel belongs to the host.
_distro_kernel_reboot_check() {
    local running latest
    running=$(uname -r)
    latest=$(pkg_installed_kernel) || latest=""
    [[ -n "$running" && -n "$latest" ]] || return 2
    [[ "$running" == "$latest" ]] && return 1
    echo "kernel: $running → $latest"
}

# Ubuntu's reboot-required.pkgs, which each asking package appends to and nothing
# prunes: every name once, at its last request, without packages since removed.
_distro_reboot_flag_pkgs() {
    local p rc
    tac "$1" 2>/dev/null | awk 'NF && !seen[$0]++' | tac | while IFS= read -r p; do
        rc=0
        pkg_is_installed "$p" || rc=$?
        (( rc == 1 )) || printf '%s\n' "$p"
    done
}

# Does the host need a reboot? 0 = yes, reasons (packages, or the kernel change)
# on stdout one per line, possibly none; 1 = no; 2 = could not tell. Capture
# with `|| rc=$?`: under a bare `if`, "could not tell" reads as "no".
pkg_reboot_required() {
    local out rc=0
    case "$VPSSEC_DISTRO_FAMILY" in
        debian)
            # The flag comes with update-notifier-common (Ubuntu). Debian does
            # not ship it, so its absence alone proves nothing.
            if [[ -f "$DISTRO_REBOOT_FLAG" ]]; then
                _distro_reboot_flag_pkgs "$DISTRO_REBOOT_FLAG.pkgs"
                return 0
            fi
            if command -v needrestart >/dev/null 2>&1 && out=$(needrestart -k -b 2>/dev/null); then
                _distro_needrestart_kernel_pending "$out" || rc=$?
                if (( rc == 0 )); then
                    awk -F': ' '/^NEEDRESTART-KCUR:/ && !c {c=$2} /^NEEDRESTART-KEXP:/ && !e {e=$2}
                        END {if (c != "" && e != "" && c != e) print "kernel: " c " → " e}' <<<"$out"
                    return 0
                fi
                (( rc == 1 )) && return 1
            fi
            _distro_kernel_reboot_check
            ;;
        rhel)
            # Read the text, not the rc: dnf exits 1 both for "reboot required"
            # and for "No such command" when dnf-plugins-core is missing.
            out=$(_distro_dnf_query needs-restarting -r 2>/dev/null) || true
            if grep -q '^Reboot is required' <<<"$out"; then
                sed -n 's/^ *\* //p' <<<"$out"
                return 0
            fi
            grep -q '^Reboot should not be necessary' <<<"$out" && return 1
            _distro_kernel_reboot_check
            ;;
        arch)
            _distro_kernel_reboot_check
            ;;
        *) return 2 ;;
    esac
}

# Parse one answer out of a merged `apt-config dump`; pure functions of their
# argument, so they test without an apt host. auto_update_status below is the
# SINGLE implementation both the audit and the fix's postcondition must use.
_auto_update_apt_dump_value() {
    awk -F'"' -v key="$2 " 'index($0, key) == 1 {print $2; exit}' <<<"$1"
}

# An APT::Periodic interval as apt.systemd.daily reads it: "always", or days
# with an optional s/m/h/d suffix. Only a bare "0" is off; a word such as "yes"
# makes the script abort, so it is off too.
_auto_update_apt_interval_on() {
    [[ "$1" == "always" ]] || { [[ "$1" =~ ^[0-9]+[smhd]?$ ]] && [[ "$1" != "0" ]]; }
}

# The install half. APT::Periodic::Enable at numeric 0 stops apt.systemd.daily
# altogether, the refresh half included.
_auto_update_apt_periodic_from_dump() {
    local enable
    enable=$(_auto_update_apt_dump_value "$1" APT::Periodic::Enable)
    [[ "$enable" =~ ^[0-9]+$ ]] && (( 10#$enable == 0 )) && return 1
    _auto_update_apt_interval_on "$(_auto_update_apt_dump_value "$1" APT::Periodic::Unattended-Upgrade)"
}

# The refresh half, run by apt-daily.service; the install half never refreshes,
# so without it unattended-upgrade keeps reading the index of the last refresh.
_auto_update_apt_refresh_from_dump() {
    _auto_update_apt_interval_on "$(_auto_update_apt_dump_value "$1" APT::Periodic::Update-Package-Lists)"
}

# Match list elements (`Key:: "value";`) only; skip the empty-list anchor
# (`Key "";`), which apt emits for a cleared list and which used to read as
# "origins are configured".
_auto_update_apt_origins_from_dump() {
    grep -qE '^Unattended-Upgrade::(Origins-Pattern|Allowed-Origins):: "[^"]+";' <<<"$1"
}

# dnf-automatic's switch from download-only to install: libdnf reads a boolean
# as 1/yes/true/on, in any case. Pure, like the apt readers above.
_auto_update_dnf_applies() {
    local val
    val=$(awk -F= '/^[[:space:]]*apply_updates[[:space:]]*=/ {v=$2} END {print v}' <<<"$1")
    val=${val//[[:space:]]/}
    [[ "${val,,}" =~ ^(1|yes|true|on)$ ]]
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

DISTRO_DNF_AUTOMATIC_CONF="${DISTRO_DNF_AUTOMATIC_CONF:-/etc/dnf/automatic.conf}"

# Effective auto-update state. Echoes one of ok|service_disabled|
# refresh_disabled|periodic_off|no_origins|unsupported|unknown;
# returns 0 iff "ok".
auto_update_status() {
    case "$VPSSEC_PKG_MGR" in
        apt)
            # Timers, not services: the u-u service only flushes at shutdown.
            # apt-daily-upgrade installs; apt-daily refreshes the index it reads.
            if ! systemctl is-enabled apt-daily-upgrade.timer &>/dev/null; then
                echo "service_disabled"; return 1
            fi
            if ! systemctl is-enabled apt-daily.timer &>/dev/null; then
                echo "refresh_disabled"; return 1
            fi
            command -v apt-config >/dev/null 2>&1 || { echo "unknown"; return 1; }
            local dump
            dump=$(apt-config dump 2>/dev/null) || { echo "unknown"; return 1; }
            _auto_update_apt_periodic_from_dump "$dump" || { echo "periodic_off"; return 1; }
            _auto_update_apt_refresh_from_dump "$dump"  || { echo "refresh_disabled"; return 1; }
            _auto_update_apt_origins_from_dump "$dump"  || { echo "no_origins"; return 1; }
            echo "ok"; return 0
            ;;
        dnf)
            command -v systemctl >/dev/null 2>&1 || { echo "unknown"; return 1; }
            # The -install timer installs whatever automatic.conf says; the
            # plain one only when apply_updates is true.
            systemctl is-enabled dnf-automatic-install.timer &>/dev/null && { echo "ok"; return 0; }
            if ! systemctl is-enabled dnf-automatic.timer &>/dev/null; then
                echo "service_disabled"; return 1
            fi
            [[ -r "$DISTRO_DNF_AUTOMATIC_CONF" ]] || { echo "unknown"; return 1; }
            _auto_update_dnf_applies "$(<"$DISTRO_DNF_AUTOMATIC_CONF")" \
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

# The packages among $@ not installed now, one per line. "Cannot determine"
# counts as installed, so an undo hint never removes what the host already had.
pkg_missing() {
    local p rc
    for p in "$@"; do
        rc=0
        pkg_is_installed "$p" || rc=$?
        (( rc == 1 )) && echo "$p"
    done
    return 0
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

# Print the package owning the file PATH resolves to, if its content still
# matches that package's recorded sum: 0 = verified, 1 = not owned, modified or
# unsummed, 2 = cannot tell (no tool). Call it in a tested context.
file_package_verified() {
    local real out pkg cand sums want have alt="" db
    real=$(readlink -f -- "$1" 2>/dev/null) && [[ -f "$real" ]] || return 1
    case "$VPSSEC_PKG_MGR" in
        apt)
            command -v dpkg-query >/dev/null 2>&1 || return 2
            # readlink resolved /lib -> /usr/lib, while dpkg may hold the
            # pre-usrmerge spelling: ask for both.
            case "$real" in
                /usr/lib/*|/usr/lib64/*|/usr/bin/*|/usr/sbin/*) alt="${real#/usr}" ;;
            esac
            for cand in "$real" ${alt:+"$alt"}; do
                out=$(dpkg-query -S -- "$cand" 2>/dev/null) || continue
                pkg=$(P="$cand" awk -F': ' '$2 == ENVIRON["P"] && $1 !~ /^diversion by / {
                    sub(/,.*/, "", $1); print $1; exit }' <<<"$out")
                [[ -n "$pkg" ]] || continue
                # dpkg --verify prints nothing for a file it has no sum for, so
                # the sum is read and compared here: md5sums, or for a conffile
                # (anything under /etc a package ships) its Conffiles entry.
                sums=$(dpkg-query --control-show "$pkg" md5sums 2>/dev/null) || sums=""
                want=$(P="${cand#/}" awk 'substr($0, 35) == ENVIRON["P"] { print $1; exit }' <<<"$sums")
                if [[ -z "$want" ]]; then
                    sums=$(dpkg-query -W -f="\${Conffiles}\n" "$pkg" 2>/dev/null) || sums=""
                    want=$(P="$cand" awk '$1 == ENVIRON["P"] && length($2) == 32 { print $2; exit }' <<<"$sums")
                fi
                have=$(md5sum < "$real") || return 2
                [[ -n "$want" && "${have%% *}" == "$want" ]] || return 1
                echo "${pkg%%:*}"
                return 0
            done
            return 1
            ;;
        dnf)
            command -v rpm >/dev/null 2>&1 || return 2
            out=$(rpm -qf --qf '%{NAME}\n' -- "$real" 2>/dev/null) || return 1
            # rpm -V exits non-zero for any file of the package that differs,
            # so its verdict on this one is read from the output.
            sums=$(rpm -Vf -- "$real" 2>/dev/null) || true
            P="$real" awk '$NF == ENVIRON["P"] { bad = 1 } END { exit bad }' <<<"$sums" || return 1
            echo "${out%%$'\n'*}"
            ;;
        pacman)
            command -v pacman >/dev/null 2>&1 || return 2
            pkg=$(pacman -Qqo -- "$real" 2>/dev/null) || return 1
            pkg="${pkg%%$'\n'*}"
            out=$(pacman -Q -- "$pkg" 2>/dev/null) || return 1
            # The sum is read from the local database's mtree, as dpkg's md5sums
            # are: pacman -Qkk names only mismatches, so an unsummed file passes.
            db=$(pacman-conf DBPath 2>/dev/null) || db=/var/lib/pacman/
            sums=$(gzip -dc -- "${db%/}/local/${pkg}-${out#* }/mtree" 2>/dev/null) || return 1
            want=$(P="./${real#/}" awk '$1 == ENVIRON["P"] {
                for (i = 2; i <= NF; i++) if ($i ~ /^sha256digest=/) { print substr($i, 14); exit } }' <<<"$sums")
            have=$(sha256sum < "$real") || return 2
            [[ -n "$want" && "${have%% *}" == "$want" ]] || return 1
            echo "$pkg"
            ;;
        *) return 2 ;;
    esac
}

# A command that searches the changelog of installed package $1 for the
# extended regex $2; status 1 where packages carry no distribution changelog.
pkg_changelog_grep_hint() {
    case "$VPSSEC_PKG_MGR" in
        apt) echo "zgrep -E '$2' /usr/share/doc/$1/changelog.Debian.gz" ;;
        dnf) echo "rpm -q --changelog $1 | grep -E '$2'" ;;
        *) return 1 ;;
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

# Never `pacman -Sy` alone: Arch does not support partial upgrades.
pkg_refresh_hint() {
    case "$VPSSEC_PKG_MGR" in
        apt)    echo "apt-get update" ;;
        dnf)    echo "dnf makecache" ;;
        pacman) echo "pacman -Syu" ;;
        zypper) echo "zypper refresh" ;;
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
            ps|pgrep)
                case "$VPSSEC_DISTRO_FAMILY" in
                    rhel|arch) pkg=procps-ng ;;
                    *)         pkg=procps ;;
                esac
                ;;
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

DISTRO_UFW_DEFAULTS="${DISTRO_UFW_DEFAULTS:-/etc/default/ufw}"

# The file ufw hands to `sysctl -p` each time it starts or reloads: IPT_SYSCTL
# in its defaults, read as data rather than sourced. Empty when none is named.
fw_ufw_sysctl_file() {
    [[ -r "$DISTRO_UFW_DEFAULTS" ]] || return 0
    awk '/^[ \t]*IPT_SYSCTL=/ { v = substr($0, index($0, "=") + 1) }
         END { gsub(/^[ \t"\047]+|[ \t"\047]+$/, "", v); print v }' "$DISTRO_UFW_DEFAULTS"
}

# True when an nft input hook (ruleset on stdin) can drop: a drop/reject policy
# or verdict, a queue, or a jump into a chain; fail2ban, ufw (emptied while off)
# and tailscale chains are no firewall. $1 = ip6: only ip6/inet tables count.
_fw_nft_input_filters() {
    awk -v v6="${1:-}" '
        /^[ \t]*table[ \t]/ {
            f2b = ($0 ~ /[ \t]f2b-table[ \t]*[{]/)
            other = (v6 != "" && $2 != "inet" && $2 != "ip6")
            next
        }
        /^[ \t]*chain[ \t]/ { input = 0; next }
        /hook[ \t]+input/ {
            input = !f2b && !other
            if (input && $0 ~ /policy[ \t]+(drop|reject)/) f = 1
            next
        }
        /^[ \t]*[}][ \t]*$/ { input = 0; next }
        !input { next }
        /(jump|goto)[ \t]+(f2b-|ufw6?-|ts-)/ { next }
        tolower($0) ~ /(^|[^a-z_-])(drop|reject|queue|jump|goto)([^a-z_-]|$)/ { f = 1 }
        END { exit !f }
    '
}

# The same question, of `iptables -S INPUT` on stdin. A rule filters when its
# target can drop: DROP, REJECT, a queue, or a chain other than those above.
_fw_iptables_input_filters() {
    awk '
        /^-P INPUT (DROP|REJECT)/ { f = 1; next }
        !/^-A INPUT / { next }
        {
            t = ""
            for (i = 1; i < NF; i++) if ($i == "-j" || $i == "-g") t = $(i + 1)
            if (t == "" || t ~ /^(f2b-|ufw6?-|ts-)/) next
            if (t !~ /^(ACCEPT|RETURN|LOG|NFLOG|ULOG|MARK|CONNMARK|CT|TRACE|AUDIT|SET|CLASSIFY|TCPMSS)$/) f = 1
        }
        END { exit !f }
    '
}

# firewalld's own CLI ships with it; a seam of its own so tests decide it.
_fw_firewalld_installed() {
    command -v firewall-cmd >/dev/null 2>&1
}

# Active firewall backend: ufw|firewalld|nftables|iptables|none, first match in
# that order; nftables/iptables count only while their input hook filters. A
# failed query with nothing found returns 1 and prints nothing, never "none".
fw_backend() {
    local out failed=0
    # LC_ALL=C: ufw gettext-translates "Status: active" under a non-C locale
    # (e.g. zh_CN "状态： 激活"); without it an active UFW is misdetected and
    # the probe falls through to "nftables" (ufw's chains make nft non-empty).
    if command -v ufw >/dev/null 2>&1; then
        if out=$(LC_ALL=C ufw status 2>/dev/null); then
            grep -q "Status: active" <<<"$out" && { echo "ufw"; return 0; }
        else
            failed=1
        fi
    fi
    # is-active exits 3 for inactive, failed or absent units (4 per LSB): a
    # plain "no". Any other failure is a query that failed, which counts only
    # where firewalld is installed; elsewhere it would flag every container.
    local fwd_rc=0
    systemctl is-active --quiet firewalld 2>/dev/null || fwd_rc=$?
    (( fwd_rc == 0 )) && { echo "firewalld"; return 0; }
    if (( fwd_rc != 3 && fwd_rc != 4 )) && _fw_firewalld_installed; then
        failed=1
    fi
    if command -v nft >/dev/null 2>&1; then
        if out=$(nft list ruleset 2>/dev/null); then
            _fw_nft_input_filters <<<"$out" && { echo "nftables"; return 0; }
        else
            failed=1
        fi
    fi
    if command -v iptables >/dev/null 2>&1; then
        if out=$(iptables -S INPUT 2>/dev/null); then
            _fw_iptables_input_filters <<<"$out" && { echo "iptables"; return 0; }
        else
            failed=1
        fi
    fi
    (( failed == 0 )) || return 1
    echo "none"
}

# Is IPv6 input filtered: 0 yes, 1 no, 2 cannot tell. Built on fw_backend: ufw
# filters IPv6 only with IPV6=yes and firewalld covers both stacks; otherwise
# an ip6/inet input hook, or ip6tables' own INPUT chain, has to filter.
fw_ipv6_filtered() {
    local backend out failed=0
    backend=$(fw_backend) || return 2
    case "$backend" in
        ufw)
            [[ -r "$DISTRO_UFW_DEFAULTS" ]] || return 2
            grep -q '^IPV6=yes' "$DISTRO_UFW_DEFAULTS" && return 0
            return 1 ;;
        firewalld) return 0 ;;
    esac
    if command -v nft >/dev/null 2>&1; then
        if out=$(nft list ruleset 2>/dev/null); then
            _fw_nft_input_filters ip6 <<<"$out" && return 0
        else
            failed=1
        fi
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        if out=$(ip6tables -S INPUT 2>/dev/null); then
            _fw_iptables_input_filters <<<"$out" && return 0
        else
            failed=1
        fi
    fi
    (( failed == 0 )) || return 2
    return 1
}

# --- Path / config-location primitives ---

# syslog-style log files (under /var/log) to existence-check for the
# logrotate audit. RHEL/Arch route most logging through journald, so the
# list is short there.
distro_log_paths() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) echo "syslog auth.log dpkg.log" ;;
        rhel)   echo "messages secure" ;;
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

# PAM files where a session-stack pam_umask line can live (newline-separated;
# caller existence-checks each). RHEL ships it in postlogin and Arch in
# system-login, so a Debian-only list reads "not enabled" on both.
pam_session_files() {
    case "$VPSSEC_DISTRO_FAMILY" in
        debian) printf '%s\n' /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive ;;
        rhel)   printf '%s\n' /etc/pam.d/postlogin /etc/pam.d/system-auth /etc/pam.d/password-auth ;;
        arch)   printf '%s\n' /etc/pam.d/system-login ;;
        *)      printf '%s\n' /etc/pam.d/common-session /etc/pam.d/postlogin /etc/pam.d/system-login ;;
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
                /usr/libexec/utempter/utempter \
                /usr/libexec/openssh/ssh-keysign \
                /usr/bin/write /usr/bin/wall
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

# Extra legitimate file-capability entries, in FS_CAPS_WHITELIST's
# "path:caps:packages" form.
distro_caps_whitelist() {
    case "$VPSSEC_DISTRO_FAMILY" in
        rhel)
            printf '%s\n' \
                '/usr/sbin/mtr-packet:cap_net_raw:mtr' \
                '/usr/sbin/suexec:cap_setuid,cap_setgid:httpd-core|httpd' \
                '/usr/bin/newgidmap:cap_setgid:shadow-utils' \
                '/usr/bin/newuidmap:cap_setuid:shadow-utils' \
                '/usr/libexec/sssd/*:cap_dac_read_search:sssd-*' \
                '/usr/libexec/gstreamer-1.0/gst-ptp-helper:cap_net_admin,cap_net_bind_service,cap_sys_nice:gstreamer1'
            ;;
        arch)
            printf '%s\n' \
                '/usr/bin/mtr-packet:cap_net_bind_service,cap_net_raw:mtr' \
                '/usr/bin/newgidmap:cap_setgid:shadow' \
                '/usr/bin/newuidmap:cap_setuid:shadow' \
                '/usr/lib/gstreamer-1.0/gst-ptp-helper:cap_net_admin,cap_net_bind_service:gstreamer'
            ;;
        *) : ;;
    esac
}

# Eager init: populate the globals at source time (parent shell) so every
# module and subshell inherits them. Guarded so it can never abort the
# source under `set -e`.
distro_detect || true
