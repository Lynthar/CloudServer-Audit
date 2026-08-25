#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Filesystem security module - SUID/SGID, permissions, world-writable
# Copyright (c) 2024

# --- Filesystem Security Configuration ---

# Known legitimate SUID binaries (whitelist)
# These are standard system binaries that normally have SUID bit set
declare -ga FS_SUID_WHITELIST=(
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
    "/usr/bin/crontab"
    "/usr/bin/at"
    "/usr/bin/ping"
    "/usr/bin/ping6"
    "/usr/bin/ssh-agent"
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/bin/expiry"
    "/usr/bin/chage"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/libexec/polkit-agent-helper-1"
    "/usr/sbin/pam_timestamp_check"
    "/usr/*bin/unix_chkpwd"
    "/usr/bin/ksu"
    "/usr/sbin/mount.nfs"
    "/usr/sbin/mount.cifs"
    "/snap/snapd/*/usr/lib/snapd/snap-confine"
    # FUSE mount helpers (fuse2/fuse3) — SUID by design on Debian/Ubuntu
    "/usr/bin/fusermount"
    "/usr/bin/fusermount3"
    # snapd sandbox helper at the system path (the /snap/snapd/* entry above
    # only covers the in-snap copy); appears SUID on Ubuntu 24.04
    "/usr/lib/snapd/snap-confine"
    # polkit agent helper — Ubuntu 24.04 path (older: /usr/libexec or policykit-1)
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    # sudo-rs (Rust sudo) — default on Ubuntu 25.10+/26.04; ships under cargo/bin,
    # plus /usr/bin/sudo.ws from the transitional `sudo` package
    "/usr/lib/cargo/bin/sudo"
    "/usr/lib/cargo/bin/su"
    "/usr/bin/sudo.ws"
    # NTFS-3G FUSE mount helper
    "/usr/bin/ntfs-3g"
)

# Sensitive files and their expected modes. The backup-shadow files
# (/etc/shadow-, /etc/gshadow-) are here on purpose: they hold the same
# hashes as the originals and are a classic blind spot.
declare -gA FS_SENSITIVE_FILES=(
    # Account databases + their backup copies
    ["/etc/passwd"]="644"
    ["/etc/passwd-"]="644"
    ["/etc/shadow"]="640"
    ["/etc/shadow-"]="640"
    ["/etc/group"]="644"
    ["/etc/group-"]="644"
    ["/etc/gshadow"]="640"
    ["/etc/gshadow-"]="640"
    # SSH server config + host keys
    ["/etc/ssh/sshd_config"]="644"
    ["/etc/ssh/ssh_host_rsa_key"]="600"
    ["/etc/ssh/ssh_host_ecdsa_key"]="600"
    ["/etc/ssh/ssh_host_ed25519_key"]="600"
    # sudo + scheduled jobs. crontab(1) is setgid crontab and at(1) runs as
    # daemon: both need group or world read on these files, so only at.deny
    # (shipped root:daemon 640) may forbid world-read; the rest police write bits.
    ["/etc/sudoers"]="440"
    ["/etc/crontab"]="644"
    ["/etc/cron.allow"]="644"
    ["/etc/cron.deny"]="644"
    ["/etc/at.allow"]="644"
    ["/etc/at.deny"]="640"
    # TCP wrappers (public, read-only)
    ["/etc/hosts.allow"]="644"
    ["/etc/hosts.deny"]="644"
    # The risk here is WRITE access (it sets the kernel cmdline), not read:
    # grub.cfg is already world-readable via /proc/cmdline, and Debian ships
    # it 444. Expect 644 and flag only world/group-WRITABLE.
    ["/boot/grub/grub.cfg"]="644"
    ["/boot/grub2/grub.cfg"]="644"
    # Legacy r-* trust files: if present, lax perms are a remote-trust leak
    ["/root/.rhosts"]="600"
    ["/root/.shosts"]="600"
)

# Maximum number of items to report (to prevent huge output)
FS_MAX_REPORT_ITEMS=20

# Variables, not literals, for two reasons: the audit predicate and the fix
# must not be able to point at different files, and a fix with a hardcoded
# /etc path cannot be exercised against a scratch tree.
FS_LOGIN_DEFS="/etc/login.defs"
FS_PROFILE="/etc/profile"
# Files whose pam_umask line decides whether login.defs UMASK applies at
# session start at all.
declare -ga FS_PAM_SESSION_FILES=(
    "/etc/pam.d/common-session"
    "/etc/pam.d/common-session-noninteractive"
)
# Drop-in directories expanded by BOTH the audit and the permissions fix.
# FS_SENSITIVE_FILES cannot hold globs, so these are walked separately; the
# fix mirrors the audit's expected modes (sudoers.d 0440, sshd_config.d 0644).
FS_SUDOERS_D="/etc/sudoers.d"
FS_SSHD_CONFIG_D="/etc/ssh/sshd_config.d"

# The filesystem-walk helpers live in core/common.sh so webapp and malware
# can use them without filesystem.sh being in the include set.

# --- Filesystem Helper Functions ---

# Sanitize count value to ensure it's a single integer
# Handles cases where grep -c returns multiline output
_fs_sanitize_count() {
    local val="$1"
    val=$(echo "$val" | head -1)
    val="${val//[^0-9]/}"
    echo "${val:-0}"
}

# True when the package manager says PATH's on-disk MODE differs from what
# its package shipped. dpkg cannot verify modes, so on Debian this always
# returns "not tampered" and the explicit whitelists stay the guard.
_fs_pkg_mode_tampered() {
    local path="$1" out
    case "${VPSSEC_PKG_MGR:-}" in
        dnf|yum)
            command -v rpm >/dev/null 2>&1 || return 1
            # Field 1's 2nd char is 'M' on a mode mismatch. Captured FIRST:
            # rpm -V exits non-zero on any discrepancy, which under pipefail
            # would mask awk's verdict and always report "not tampered".
            out=$(rpm -Vf "$path" 2>/dev/null)
            awk -v p="$path" '
                $NF == p && substr($1,2,1) == "M" { t=1 }
                END { exit(t ? 0 : 1) }' <<<"$out"
            ;;
        pacman)
            command -v pacman >/dev/null 2>&1 || return 1
            local pkg
            pkg=$(pacman -Qoq -- "$path" 2>/dev/null) || return 1
            [[ -n "$pkg" ]] || return 1
            # Captured first for the same pipefail reason as rpm, and with
            # 2>&1: pacman emits the mismatch as a WARNING on stderr, so
            # discarding stderr makes this detection inert.
            out=$(pacman -Qkk -- "$pkg" 2>&1)
            grep -F -- "$path" <<<"$out" | grep -qi "permission"
            ;;
        *)
            return 1   # apt/dpkg cannot verify modes; treat as not tampered
            ;;
    esac
}

# Check if path is in whitelist (supports glob patterns)
_fs_is_whitelisted() {
    local path="$1"
    local pattern

    for pattern in "${FS_SUID_WHITELIST[@]}"; do
        # Support glob patterns with *
        if [[ "$path" == $pattern ]]; then
            return 0
        fi
    done
    # Distro-specific legit SUID paths (RHEL/Arch) from core/distro.sh.
    # The debian branch returns nothing, so this is a no-op on Debian/Ubuntu.
    if declare -f distro_suid_whitelist >/dev/null 2>&1; then
        while IFS= read -r pattern; do
            [[ -n "$pattern" && "$path" == $pattern ]] && return 0
        done < <(distro_suid_whitelist)
    fi
    # A package-owned SUID binary is distro-shipped — this replaced the
    # per-release whitelists. Ownership alone is NOT enough: the exemption is
    # refused wherever the manager can prove the mode was tampered.
    if declare -f file_owned_by_package >/dev/null 2>&1; then
        if file_owned_by_package "$path" && ! _fs_pkg_mode_tampered "$path"; then
            return 0
        fi
    fi
    return 1
}

# Find non-whitelisted SUID files. -xdev handles other filesystems; the
# prune list handles container-image storage on the root fs, whose overlay
# diffs ship legitimate SUID binaries.
_fs_find_suid_files() {
    local count=0
    local results=()

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        if ! _fs_is_whitelisted "$file"; then
            results+=("$file")
            ((count++)) || true
            # Limit output
            if ((count >= FS_MAX_REPORT_ITEMS)); then
                break
            fi
        fi
    done < <(_fs_run_find "suid" \
        find / -xdev "${prune_args[@]}" \
        -type f -perm -4000 -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find SGID files (excluding common ones)
_fs_find_sgid_files() {
    local count=0
    local results=()
    local sgid_whitelist=(
        "/usr/bin/wall"
        "/usr/bin/write"
        "/usr/bin/ssh-agent"
        "/usr/bin/expiry"
        "/usr/bin/chage"
        "/usr/bin/crontab"
        "/usr/sbin/unix_chkpwd"
        "/usr/sbin/pam_extrausers_chkpwd"
        "/usr/lib/*/utempter/utempter"
        "/usr/bin/groupmems"
    )

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        local skip=0
        for pattern in "${sgid_whitelist[@]}"; do
            # Unquoted RHS = glob match (e.g. /usr/lib/*/utempter/utempter across arches)
            if [[ "$file" == $pattern ]]; then
                skip=1
                break
            fi
        done

        # Distro-specific SGID paths (RHEL/Arch) from core/distro.sh
        if (( skip == 0 )) && declare -f distro_sgid_whitelist >/dev/null 2>&1; then
            while IFS= read -r pattern; do
                [[ -n "$pattern" && "$file" == $pattern ]] && { skip=1; break; }
            done < <(distro_sgid_whitelist)
        fi

        # Same rule as SUID: exempt a package-owned SGID binary UNLESS the
        # manager can prove the mode was tampered. dpkg cannot, so the
        # explicit whitelist guards Debian.
        if (( skip == 0 )) && declare -f file_owned_by_package >/dev/null 2>&1; then
            if file_owned_by_package "$file" && ! _fs_pkg_mode_tampered "$file"; then
                skip=1
            fi
        fi

        if ((skip == 0)); then
            results+=("$file")
            ((count++)) || true
            if ((count >= FS_MAX_REPORT_ITEMS)); then
                break
            fi
        fi
    done < <(_fs_run_find "sgid" \
        find / -xdev "${prune_args[@]}" \
        -type f -perm -2000 -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find world-writable files, excluding volatile mounts AND container
# storage — without the latter, image-internal files are flagged as host
# findings on any Docker host.
_fs_find_world_writable() {
    local count=0
    local results=()

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        results+=("$file")
        ((count++)) || true
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(_fs_run_find "world-writable" \
        find / -xdev "${prune_args[@]}" \
        -type f -perm -0002 \
        ! -path "/tmp/*" \
        ! -path "/var/tmp/*" \
        ! -path "/dev/*" \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        ! -path "/run/*" \
        -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find world-writable directories without sticky bit. Same prune
# fix as world-writable files.
_fs_find_world_writable_dirs() {
    local count=0
    local results=()

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' dir; do
        results+=("$dir")
        ((count++)) || true
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(_fs_run_find "world-writable-dirs" \
        find / -xdev "${prune_args[@]}" \
        -type d -perm -0002 ! -perm -1000 \
        ! -path "/tmp" \
        ! -path "/tmp/*" \
        ! -path "/var/tmp" \
        ! -path "/var/tmp/*" \
        ! -path "/dev/*" \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        ! -path "/run/*" \
        -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find files with no owner. Same container-prune fix: a host that
# pulls images often accumulates orphan-uid files inside Docker
# overlays that aren't host-level orphans.
_fs_find_no_owner() {
    local count=0
    local results=()

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        results+=("$file")
        ((count++)) || true
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(_fs_run_find "no-owner" \
        find / -xdev "${prune_args[@]}" \
        \( -nouser -o -nogroup \) \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Check a sensitive file's permissions AND ownership. Mode alone is not
# enough: /etc/shadow at 640 owned by nobody is as readable to the wrong
# party as a world-readable one.
_fs_check_sensitive_file() {
    local file="$1"
    local expected="$2"

    if [[ ! -f "$file" ]]; then
        return 0  # File doesn't exist, skip
    fi

    local actual owner group
    actual=$(stat -c "%a" "$file" 2>/dev/null)
    owner=$(stat -c "%U" "$file" 2>/dev/null)
    group=$(stat -c "%G" "$file" 2>/dev/null)

    if [[ -z "$actual" ]]; then
        return 1
    fi

    local problems=()

    # Bitmask, NEVER an arithmetic comparison: 0604 is numerically below
    # 0640 but grants world-read, so `>` silently passes mode 604 on
    # /etc/shadow. The test is `actual & ~expected`, masked to 12 bits.
    local actual_num=$((8#$actual))
    local expected_num=$((8#$expected))
    local extra_bits=$(( (actual_num & ~expected_num) & 07777 ))
    if (( extra_bits != 0 )); then
        problems+=("mode $actual (expected $expected)")
    fi

    # Ownership is only checked as root, the production condition: bats
    # fixtures own their own scratch files.
    if [[ "$(id -u)" == "0" ]]; then
        # Owner: every file in FS_SENSITIVE_FILES is root-owned on every
        # supported distro; anything else is drift worth surfacing.
        if [[ -n "$owner" && "$owner" != "root" ]]; then
            problems+=("owner $owner (expected root)")
        fi

        # Group only matters when it actually gets access bits AND is outside
        # what THIS file legitimately uses: root/shadow/ssh_keys anywhere;
        # daemon only on /etc/at.*, crontab only on /etc/cron* (setgid readers).
        if [[ -n "$group" ]] && (( actual_num & 070 )) ; then
            case "$group" in
                root|shadow|ssh_keys) : ;;
                daemon) [[ "$file" == /etc/at.* ]] || problems+=("group $group grants access") ;;
                crontab) [[ "$file" == /etc/cron* ]] || problems+=("group $group grants access") ;;
                *) problems+=("group $group grants access") ;;
            esac
        fi
    fi

    if (( ${#problems[@]} > 0 )); then
        local joined
        joined=$(IFS='; '; printf '%s' "${problems[*]}")
        echo "$file: $joined"
        return 1
    fi

    return 0
}

# Check /tmp mount options
_fs_check_tmp_mount() {
    local mount_opts
    mount_opts=$(findmnt -n -o OPTIONS /tmp 2>/dev/null)

    if [[ -z "$mount_opts" ]]; then
        echo "not_separate"
        return
    fi

    local issues=()

    if [[ ! "$mount_opts" =~ noexec ]]; then
        issues+=("noexec")
    fi

    if [[ ! "$mount_opts" =~ nosuid ]]; then
        issues+=("nosuid")
    fi

    if [[ ! "$mount_opts" =~ nodev ]]; then
        issues+=("nodev")
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        echo "missing:${issues[*]}"
    else
        echo "ok"
    fi
}

# Check umask setting
_fs_check_umask() {
    local umask_value

    # FIRST occurrence only: shadow's getdef keeps the first entry for a
    # duplicated name, and an unbounded grep concatenates both into "077 022".
    # awk, not `grep | head -1` — head's SIGPIPE becomes the exit status.
    if [[ -f "$FS_LOGIN_DEFS" ]]; then
        umask_value=$(awk '/^UMASK/ { print $2; exit }' "$FS_LOGIN_DEFS" 2>/dev/null)
    fi

    # Check /etc/profile. `tail -1` here rather than the first match, and the
    # asymmetry is deliberate: this is a shell script, so the last `umask`
    # command executed is the one in effect.
    if [[ -z "$umask_value" && -f "$FS_PROFILE" ]]; then
        umask_value=$(grep -E "^\s*umask" "$FS_PROFILE" 2>/dev/null | tail -1 | awk '{print $2}')
    fi

    echo "${umask_value:-022}"
}

# The audit's definition of an acceptable umask: world bits denied. Shared
# with _fs_fix_umask so the fix's postcondition cannot drift from the check
# that produced the finding.
_fs_umask_is_strict() {
    [[ "$1" =~ ^0[0-7][0-7]7$ ]]
}

# Returns "yes" or "no" — the value of USERGROUPS_ENAB in /etc/login.defs.
# Defaults to "yes" (the documented Debian/Ubuntu default) when the
# directive is absent, since that's how pam_umask actually behaves.
_fs_get_usergroups_enab() {
    local val=""
    if [[ -f "$FS_LOGIN_DEFS" ]]; then
        val=$(grep -E "^USERGROUPS_ENAB" "$FS_LOGIN_DEFS" 2>/dev/null | awk '{print tolower($2)}')
    fi
    echo "${val:-yes}"
}

# Apply the USERGROUPS_ENAB transformation to a configured umask, so the
# audit reports what actually applies at session start rather than the
# literal in login.defs. Args: <umask> <yes|no>. Echoes 4 digits.
_fs_compute_effective_umask() {
    local raw="$1"
    local usergroups="${2:-no}"

    [[ -z "$raw" ]] && raw="022"
    # Normalize — keep only octal digits, then pad/truncate to 4.
    raw="${raw//[^0-7]/}"
    while [[ ${#raw} -lt 4 ]]; do raw="0$raw"; done
    raw="${raw: -4}"

    if [[ "${usergroups,,}" == "yes" ]]; then
        # Group digit (pos 2) is replaced with owner digit (pos 1).
        echo "${raw:0:1}${raw:1:1}${raw:1:1}${raw:3:1}"
    else
        echo "$raw"
    fi
}

# Is pam_umask enabled in /etc/pam.d/common-session*? It is what makes the
# login.defs UMASK take effect at session start; without it only shell rc
# files influence umask.
_fs_check_pam_umask_enabled() {
    local f
    for f in "${FS_PAM_SESSION_FILES[@]}"; do
        [[ -f "$f" ]] || continue
        # Match "session ... pam_umask.so" while skipping commented lines.
        grep -qE '^[[:space:]]*session[[:space:]]+[^#]*pam_umask\.so' "$f" 2>/dev/null && return 0
    done
    return 1
}

# Legitimate cap-bearing binaries. The cap field is the COMPLETE allowed set
# and matching is subset-based, never substring: a contains-match exempts any
# capability stacked onto a whitelisted binary.
declare -ga FS_CAPS_WHITELIST=(
    "/usr/bin/ping:cap_net_raw"
    "/usr/bin/traceroute:cap_net_raw"
    "/usr/bin/mtr-packet:cap_net_raw"
    # arping/clockdiff swap between /usr/bin and /usr/sbin across distros (RHEL vs Debian) — glob both
    "/usr/*bin/arping:cap_net_raw"
    "/usr/*bin/clockdiff:cap_net_raw,cap_sys_nice"
    "/usr/bin/gnome-keyring-daemon:cap_ipc_lock"
    "/usr/bin/systemd-resolve:cap_net_bind_service"
    # snapd sandbox helper legitimately holds cap_sys_admin
    "/usr/lib/snapd/snap-confine:cap_sys_admin"
    # GStreamer PTP helper — Debian ships net_bind_service+net_admin, some
    # builds add sys_nice (multiarch path)
    "/usr/lib/*/gstreamer1.0/gstreamer-1.0/gst-ptp-helper:cap_net_admin,cap_net_bind_service,cap_sys_nice"
)

# True when every capability in the raw getcap value $1 appears in the
# comma-separated allowed list $2. Both getcap formats are handled:
# modern "cap_a,cap_b=ep" and legacy "cap_a+ep" (flag suffix stripped).
_fs_caps_subset_of() {
    local held="$1" allowed="$2"
    held="${held%%=*}"
    held="${held%%+*}"
    local cap
    local IFS=','
    for cap in $held; do
        cap="${cap// /}"
        [[ -z "$cap" ]] && continue
        [[ ",${allowed}," == *",${cap},"* ]] || return 1
    done
    return 0
}

# Dangerous capabilities that grant significant privileges
declare -ga FS_DANGEROUS_CAPS=(
    "cap_sys_admin"
    "cap_sys_ptrace"
    "cap_sys_module"
    "cap_sys_rawio"
    "cap_sys_boot"
    "cap_dac_override"
    "cap_dac_read_search"
    "cap_setuid"
    "cap_setgid"
    "cap_chown"
    "cap_fowner"
)

# Find files with capabilities set
_fs_find_caps_files() {
    local results=()
    local count=0

    # Check if getcap is available
    if ! command -v getcap &>/dev/null; then
        return
    fi

    # getcap output differs by libcap version: "path cap=ep" on 2.43+ and
    # "path = cap+ep" before it. Split on the first space, then strip a
    # leading "= " so both forms parse.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local file="${line%% *}"
        local caps="${line#* }"
        caps="${caps#= }"

        # getcap has no -xdev or -prune, so container and snap storage on the
        # root fs must be skipped explicitly, as the other walks do.
        local pruned=false pp
        for pp in "${_FS_PRUNE_PATHS[@]}"; do
            if [[ "$file" == "$pp" || "$file" == "$pp"/* ]]; then
                pruned=true
                break
            fi
        done
        [[ "$pruned" == true ]] && continue

        # Check if in whitelist. Subset semantics (see FS_CAPS_WHITELIST):
        # the file's WHOLE capability set must be covered by its entry.
        local whitelisted=false
        for entry in "${FS_CAPS_WHITELIST[@]}"; do
            local wl_file="${entry%%:*}"
            local wl_cap="${entry#*:}"
            # Unquoted $wl_file = glob match (handles multiarch /usr/lib/*/ paths)
            if [[ "$file" == $wl_file ]] && _fs_caps_subset_of "$caps" "$wl_cap"; then
                whitelisted=true
                break
            fi
        done

        # Distro-specific cap entries (RHEL/Arch) from core/distro.sh
        if [[ "$whitelisted" == false ]] && declare -f distro_caps_whitelist >/dev/null 2>&1; then
            local dentry
            while IFS= read -r dentry; do
                [[ -z "$dentry" ]] && continue
                if [[ "$file" == ${dentry%%:*} ]] && _fs_caps_subset_of "$caps" "${dentry#*:}"; then
                    whitelisted=true
                    break
                fi
            done < <(distro_caps_whitelist)
        fi

        if [[ "$whitelisted" == false ]]; then
            # Check if dangerous capability
            local is_dangerous=false
            for dangerous in "${FS_DANGEROUS_CAPS[@]}"; do
                if [[ "$caps" =~ $dangerous ]]; then
                    is_dangerous=true
                    break
                fi
            done

            if [[ "$is_dangerous" == true ]]; then
                results+=("DANGEROUS:$file:$caps")
            else
                results+=("$file:$caps")
            fi

            ((count++)) || true
            if ((count >= FS_MAX_REPORT_ITEMS)); then
                break
            fi
        fi
    done < <(_fs_run_find "caps" getcap -r / 2>/dev/null | grep -v "^$")

    printf '%s\n' "${results[@]}"
}

# Find suspicious cron entries
_fs_find_suspicious_cron() {
    local suspicious=()

    # Suspicious patterns in cron entries
    local patterns=(
        "curl.*\\|.*sh"
        "wget.*\\|.*sh"
        "base64.*-d"
        "/dev/tcp/"
        "nc\\s+-e"
        "ncat.*-e"
        "python.*-c.*import"
        "perl.*-e"
        "ruby.*-e"
        "\\\\x[0-9a-f]"
        "/tmp/\\."
    )

    # Check system crontabs
    local cron_dirs=(
        "/etc/cron.d"
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
    )

    # Check /etc/crontab
    if [[ -f /etc/crontab ]]; then
        for pattern in "${patterns[@]}"; do
            local matches=$(grep -iE "$pattern" /etc/crontab 2>/dev/null | head -2)
            if [[ -n "$matches" ]]; then
                suspicious+=("/etc/crontab: matches '$pattern'")
            fi
        done
    fi

    # Check cron directories
    for dir in "${cron_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        for file in "$dir"/*; do
            [[ -f "$file" ]] || continue
            for pattern in "${patterns[@]}"; do
                local matches=$(grep -iE "$pattern" "$file" 2>/dev/null | head -2)
                if [[ -n "$matches" ]]; then
                    suspicious+=("$file: matches '$pattern'")
                fi
            done
        done
    done

    # Check user crontabs
    if [[ -d /var/spool/cron/crontabs ]]; then
        for file in /var/spool/cron/crontabs/*; do
            [[ -f "$file" ]] || continue
            local username=$(basename "$file")
            for pattern in "${patterns[@]}"; do
                local matches=$(grep -iE "$pattern" "$file" 2>/dev/null | head -2)
                if [[ -n "$matches" ]]; then
                    suspicious+=("User $username crontab: matches '$pattern'")
                fi
            done
        done
    fi

    printf '%s\n' "${suspicious[@]}"
}

# Count user crontabs
_fs_count_user_crontabs() {
    local count=0
    if [[ -d /var/spool/cron/crontabs ]]; then
        count=$(ls -1 /var/spool/cron/crontabs 2>/dev/null | wc -l)
    fi
    echo "$count"
}

# --- Filesystem Audit ---

filesystem_audit() {
    local module="filesystem"

    # Check SUID files
    print_item "$(i18n 'filesystem.check_suid')"
    _fs_audit_suid

    # Check SGID files
    print_item "$(i18n 'filesystem.check_sgid')"
    _fs_audit_sgid

    # Check world-writable files
    print_item "$(i18n 'filesystem.check_world_writable')"
    _fs_audit_world_writable

    # Check files with no owner
    print_item "$(i18n 'filesystem.check_no_owner')"
    _fs_audit_no_owner

    # Check sensitive file permissions
    print_item "$(i18n 'filesystem.check_sensitive_perms')"
    _fs_audit_sensitive_perms

    # Check /tmp mount options
    print_item "$(i18n 'filesystem.check_tmp_mount')"
    _fs_audit_tmp_mount

    # Check umask
    print_item "$(i18n 'filesystem.check_umask')"
    _fs_audit_umask

    # Check files with capabilities (setcap)
    print_item "$(i18n 'filesystem.check_caps')"
    _fs_audit_caps

    # Check cron jobs for suspicious entries
    print_item "$(i18n 'filesystem.check_cron')"
    _fs_audit_cron
}

_fs_audit_suid() {
    local suid_files
    suid_files=$(_fs_find_suid_files)
    local count=$(_fs_sanitize_count "$(echo "$suid_files" | grep -c . 2>/dev/null)")

    if ((count > 0)); then
        local file_list=$(echo "$suid_files" | head -5 | tr '\n' ' ')
        local check=$(create_check_json \
            "filesystem.suspicious_suid" \
            "filesystem" \
            "medium" \
            "failed" \
            "$(i18n 'filesystem.suspicious_suid' "count=$count")" \
            "$(i18n 'filesystem.suspicious_suid_desc' "list=$file_list")" \
            "$(i18n 'filesystem.review_suid')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'filesystem.suspicious_suid' "count=$count")"
        log_info "Suspicious SUID files: $suid_files"
    else
        local check=$(create_check_json \
            "filesystem.suid_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.suid_ok')" \
            "$(i18n 'filesystem.suid_ok_desc')" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.suid_ok')"
    fi
}

_fs_audit_sgid() {
    local sgid_files
    sgid_files=$(_fs_find_sgid_files)
    local count=$(_fs_sanitize_count "$(echo "$sgid_files" | grep -c . 2>/dev/null)")

    if ((count > 0)); then
        local file_list=$(echo "$sgid_files" | head -5 | tr '\n' ' ')
        local check=$(create_check_json \
            "filesystem.suspicious_sgid" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.suspicious_sgid' "count=$count")" \
            "$(i18n 'filesystem.suspicious_sgid_desc' "list=$file_list")" \
            "$(i18n 'filesystem.review_sgid')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'filesystem.suspicious_sgid' "count=$count")"
    else
        local check=$(create_check_json \
            "filesystem.sgid_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.sgid_ok')" \
            "$(i18n 'filesystem.sgid_ok_desc')" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.sgid_ok')"
    fi
}

_fs_audit_world_writable() {
    local ww_files
    ww_files=$(_fs_find_world_writable)
    local count=$(_fs_sanitize_count "$(echo "$ww_files" | grep -c . 2>/dev/null)")

    local ww_dirs
    ww_dirs=$(_fs_find_world_writable_dirs)
    local dir_count=$(_fs_sanitize_count "$(echo "$ww_dirs" | grep -c . 2>/dev/null)")

    if ((count > 0 || dir_count > 0)); then
        local total=$((count + dir_count))
        local items=$(echo -e "$ww_files\n$ww_dirs" | head -5 | tr '\n' ' ')
        local check=$(create_check_json \
            "filesystem.world_writable" \
            "filesystem" \
            "medium" \
            "failed" \
            "$(i18n 'filesystem.world_writable' "count=$total")" \
            "$(i18n 'filesystem.world_writable_desc' "items=$items")" \
            "$(i18n 'filesystem.fix_world_writable')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'filesystem.world_writable' "count=$total")"
    else
        local check=$(create_check_json \
            "filesystem.no_world_writable" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.no_world_writable')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.no_world_writable')"
    fi
}

_fs_audit_no_owner() {
    local no_owner_files
    no_owner_files=$(_fs_find_no_owner)
    local count=$(_fs_sanitize_count "$(echo "$no_owner_files" | grep -c . 2>/dev/null)")

    if ((count > 0)); then
        local file_list=$(echo "$no_owner_files" | head -5 | tr '\n' ' ')
        local check=$(create_check_json \
            "filesystem.no_owner" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.no_owner' "count=$count")" \
            "$(i18n 'filesystem.no_owner_desc' "list=$file_list")" \
            "$(i18n 'filesystem.fix_no_owner')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'filesystem.no_owner' "count=$count")"
    else
        local check=$(create_check_json \
            "filesystem.owner_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.owner_ok')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.owner_ok')"
    fi
}

_fs_audit_sensitive_perms() {
    # Two buckets, one finding each, so the score reflects real exposure:
    # HIGH for direct priv-esc / credential-leak primitives (shadow, sudoers,
    # SSH host keys), MEDIUM for read-only exposure (passwd, group, configs).
    local high_issues=()
    local med_issues=()

    _fs_is_critical_perm_path() {
        case "$1" in
            # The rotated backups hold the SAME hashes as the live files,
            # so weak perms there are an equivalent leak primitive.
            /etc/shadow|/etc/shadow-|/etc/gshadow|/etc/gshadow-|/etc/sudoers) return 0 ;;
            /etc/sudoers.d/*) return 0 ;;
            /etc/ssh/ssh_host_*_key) return 0 ;;
            *) return 1 ;;
        esac
    }

    for file in "${!FS_SENSITIVE_FILES[@]}"; do
        local expected="${FS_SENSITIVE_FILES[$file]}"
        # RHEL ships host private keys as 640 root:ssh_keys, which is the
        # default rather than a slip. Accepted ONLY when the group really is
        # ssh_keys; 640 still forbids world bits. Debian and Arch keep 600.
        if [[ "$file" == /etc/ssh/ssh_host_*_key && "${VPSSEC_DISTRO_FAMILY:-debian}" == "rhel" && "$(stat -c '%G' "$file" 2>/dev/null)" == "ssh_keys" ]]; then
            expected="640"
        fi
        local result
        result=$(_fs_check_sensitive_file "$file" "$expected")
        if [[ -n "$result" ]]; then
            if _fs_is_critical_perm_path "$file"; then
                high_issues+=("$result")
            else
                med_issues+=("$result")
            fi
        fi
    done

    # Drop-in directories, expanded here because the static list cannot use
    # globs. Without this a 666 file in /etc/sudoers.d/ — a direct
    # privilege-escalation primitive — passes cleanly.
    local _drop
    for _drop in "$FS_SUDOERS_D"/*; do
        [[ -f "$_drop" ]] || continue
        local result
        result=$(_fs_check_sensitive_file "$_drop" "440")
        [[ -n "$result" ]] && high_issues+=("$result")
    done
    for _drop in "$FS_SSHD_CONFIG_D"/*; do
        [[ -f "$_drop" ]] || continue
        local result
        result=$(_fs_check_sensitive_file "$_drop" "644")
        [[ -n "$result" ]] && med_issues+=("$result")
    done

    local total=$(( ${#high_issues[@]} + ${#med_issues[@]} ))

    if (( total > 0 )); then
        if (( ${#high_issues[@]} > 0 )); then
            local issue_list=$(printf '%s\n' "${high_issues[@]}" | head -5 | tr '\n' ' ')
            local check=$(create_check_json \
                "filesystem.sensitive_perms_wrong" \
                "filesystem" \
                "high" \
                "failed" \
                "$(i18n 'filesystem.sensitive_perms_wrong' "count=${#high_issues[@]}")" \
                "$(i18n 'filesystem.sensitive_perms_wrong_desc' "list=$issue_list")" \
                "$(i18n 'filesystem.fix_sensitive_perms')" \
                "filesystem.fix_sensitive_perms")
            state_add_check "$check"
            print_severity "high" "$(i18n 'filesystem.sensitive_perms_wrong' "count=${#high_issues[@]}")"
        fi
        if (( ${#med_issues[@]} > 0 )); then
            local issue_list_m=$(printf '%s\n' "${med_issues[@]}" | head -5 | tr '\n' ' ')
            local check_m=$(create_check_json \
                "filesystem.sensitive_perms_wrong_minor" \
                "filesystem" \
                "low" \
                "failed" \
                "$(i18n 'filesystem.sensitive_perms_wrong_minor' "count=${#med_issues[@]}")" \
                "$(i18n 'filesystem.sensitive_perms_wrong_minor_desc' "list=$issue_list_m")" \
                "$(i18n 'filesystem.fix_sensitive_perms')" \
                "filesystem.fix_sensitive_perms")
            state_add_check "$check_m"
            print_severity "low" "$(i18n 'filesystem.sensitive_perms_wrong_minor' "count=${#med_issues[@]}")"
        fi
    else
        local check=$(create_check_json \
            "filesystem.sensitive_perms_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.sensitive_perms_ok')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.sensitive_perms_ok')"
    fi
}

_fs_audit_tmp_mount() {
    local tmp_status
    tmp_status=$(_fs_check_tmp_mount)

    if [[ "$tmp_status" == "ok" ]]; then
        local check=$(create_check_json \
            "filesystem.tmp_mount_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.tmp_mount_ok')" \
            "$(i18n 'filesystem.tmp_mount_ok_desc')" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.tmp_mount_ok')"
    elif [[ "$tmp_status" == "not_separate" ]]; then
        local check=$(create_check_json \
            "filesystem.tmp_not_separate" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.tmp_not_separate')" \
            "$(i18n 'filesystem.tmp_not_separate_desc')" \
            "$(i18n 'filesystem.tmp_not_separate_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'filesystem.tmp_not_separate')"
    else
        local missing="${tmp_status#missing:}"
        local check=$(create_check_json \
            "filesystem.tmp_mount_missing_opts" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.tmp_mount_missing_opts')" \
            "$(i18n 'filesystem.tmp_mount_missing_opts_desc' "missing=$missing")" \
            "$(i18n 'filesystem.tmp_mount_missing_opts_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "low" "/tmp missing mount options: $missing"
    fi
}

_fs_audit_umask() {
    local configured usergroups effective
    configured=$(_fs_check_umask)
    usergroups=$(_fs_get_usergroups_enab)
    effective=$(_fs_compute_effective_umask "$configured" "$usergroups")

    local pam_umask_on=0
    _fs_check_pam_umask_enabled && pam_umask_on=1

    # Severity keys on the EFFECTIVE umask, not the login.defs literal.
    # The wording qualifies two claims the operator could disprove by typing
    # `umask` (see the design notes), and compares NORMALISED values.
    local normalized
    normalized=$(_fs_compute_effective_umask "$configured" "no")

    local desc="configured=$configured"
    if (( pam_umask_on == 0 )); then
        desc="$desc$(i18n 'filesystem.umask_pam_not_applied')"
    elif [[ "$normalized" != "$effective" ]]; then
        desc="$desc$(i18n 'filesystem.umask_possibly_effective' "effective=$effective" "usergroups=$usergroups")"
    fi

    # OK = world denied (last digit = 7). Captures 027, 077, 007 (the
    # USERGROUPS-rewritten form), and any other strict variant.
    if _fs_umask_is_strict "$effective"; then
        local check=$(create_check_json \
            "filesystem.umask_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.umask_ok')" \
            "$desc" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.umask_ok') ($desc)"
    elif [[ "$effective" == "0022" || "$effective" == "0002" ]]; then
        local check=$(create_check_json \
            "filesystem.umask_default" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.umask_default')" \
            "$(i18n 'filesystem.umask_default_desc' "desc=$desc")" \
            "$(i18n 'filesystem.umask_default_suggestion')" \
            "filesystem.fix_umask")
        state_add_check "$check"
        print_severity "low" "$(i18n 'filesystem.umask_default') ($desc)"
    else
        local check=$(create_check_json \
            "filesystem.umask_weak" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.umask_weak')" \
            "$(i18n 'filesystem.umask_weak_desc' "desc=$desc")" \
            "$(i18n 'filesystem.umask_weak_suggestion')" \
            "filesystem.fix_umask")
        state_add_check "$check"
        print_severity "low" "Weak umask: $desc"
    fi

    # Informational: without pam_umask the login.defs UMASK may never apply
    # at session start. No fix offered — PAM stack edits are not auto-safe.
    if (( pam_umask_on == 0 )); then
        local pam_check
        pam_check=$(create_check_json \
            "filesystem.pam_umask_disabled" \
            "filesystem" \
            "info" \
            "passed" \
            "$(i18n 'filesystem.pam_umask_disabled')" \
            "$(i18n 'filesystem.pam_umask_disabled_desc')" \
            "" \
            "")
        state_add_check "$pam_check"
    fi
}

_fs_audit_caps() {
    # Check if getcap is available
    if ! command -v getcap &>/dev/null; then
        local check=$(create_check_json \
            "filesystem.caps_unavailable" \
            "filesystem" \
            "low" \
            "info" \
            "$(i18n 'filesystem.caps_unavailable')" \
            "$(i18n 'filesystem.caps_unavailable_desc')" \
            "" \
            "")
        state_add_check "$check"
        print_info "getcap not available (install libcap2-bin)"
        return
    fi

    local caps_files
    caps_files=$(_fs_find_caps_files)
    local total_count=$(_fs_sanitize_count "$(echo "$caps_files" | grep -c . 2>/dev/null)")
    local dangerous_count=$(_fs_sanitize_count "$(echo "$caps_files" | grep -c "^DANGEROUS:" 2>/dev/null)")

    if ((dangerous_count > 0)); then
        # Extract dangerous files list
        local dangerous_list=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ "$line" =~ ^DANGEROUS: ]]; then
                local file_info="${line#DANGEROUS:}"
                dangerous_list+="${file_info}; "
            fi
        done <<< "$caps_files"
        dangerous_list="${dangerous_list%; }"

        local check=$(create_check_json \
            "filesystem.dangerous_caps" \
            "filesystem" \
            "medium" \
            "failed" \
            "$(i18n 'filesystem.dangerous_caps' "count=$dangerous_count")" \
            "$(i18n 'filesystem.dangerous_caps_desc' "list=$dangerous_list")" \
            "$(i18n 'filesystem.review_caps')" \
            "filesystem.review_caps")
        state_add_check "$check"
        print_severity "medium" "Files with dangerous capabilities: $dangerous_count"
    elif ((total_count > 0)); then
        local caps_list=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^DANGEROUS: ]] && continue
            caps_list+="$line; "
        done <<< "$caps_files"
        caps_list="${caps_list%; }"

        local check=$(create_check_json \
            "filesystem.non_standard_caps" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.non_standard_caps' "count=$total_count")" \
            "$(i18n 'filesystem.non_standard_caps_desc' "list=$caps_list")" \
            "$(i18n 'filesystem.non_standard_caps_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "low" "Non-standard file capabilities: $total_count"
    else
        local check=$(create_check_json \
            "filesystem.caps_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.caps_ok')" \
            "" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.caps_ok')"
    fi
}

_fs_audit_cron() {
    local suspicious
    suspicious=$(_fs_find_suspicious_cron)
    local sus_count=$(_fs_sanitize_count "$(echo "$suspicious" | grep -c . 2>/dev/null)")

    local user_crontabs=$(_fs_count_user_crontabs)

    if ((sus_count > 0)); then
        local sus_list=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            sus_list+="$line; "
        done <<< "$suspicious"
        sus_list="${sus_list%; }"

        local check=$(create_check_json \
            "filesystem.suspicious_cron" \
            "filesystem" \
            "medium" \
            "failed" \
            "$(i18n 'filesystem.suspicious_cron' "count=$sus_count")" \
            "$sus_list" \
            "$(i18n 'filesystem.suspicious_cron_suggestion')" \
            "")
        state_add_check "$check"
        print_severity "medium" "Suspicious cron entries found: $sus_count"
    else
        local check=$(create_check_json \
            "filesystem.cron_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.cron_ok')" \
            "$(i18n 'filesystem.cron_ok_desc' "user_crontabs=$user_crontabs")" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.cron_ok')"
    fi
}

# --- Filesystem Fix Functions ---

filesystem_fix() {
    local fix_id="$1"

    case "$fix_id" in
        filesystem.fix_sensitive_perms)
            _fs_fix_sensitive_perms
            ;;
        filesystem.fix_umask)
            _fs_fix_umask
            ;;
        *)
            log_warn "Filesystem fix not implemented: $fix_id"
            print_warn "$(i18n 'filesystem.manual_review_required')"
            return 1
            ;;
    esac
}

_fs_fix_sensitive_perms() {
    print_info "$(i18n 'filesystem.fixing_perms')"

    local fixed=0
    local failed=0

    # Single inner loop reused for both the static FS_SENSITIVE_FILES
    # entries and the drop-in directories. Pulled into a helper so the
    # bitmask logic stays in one place.
    _fs_fix_one() {
        local file="$1"
        local expected="$2"
        [[ -f "$file" ]] || return 0

        local actual
        actual=$(stat -c "%a" "$file" 2>/dev/null)
        [[ -z "$actual" ]] && return 0
        local actual_num=$((8#$actual))
        local expected_num=$((8#$expected))

        # Same bitmask test as the audit side, so the fix cannot skip a file
        # the audit flagged: an arithmetic comparison misses 0604.
        local extra_bits=$(( (actual_num & ~expected_num) & 07777 ))
        if (( extra_bits != 0 )); then
            print_info "$(i18n 'filesystem.fixing_file' "file=$file" "from=$actual" "to=$expected")"
            # Back up before chmod so the prior mode can be restored on rollback
            # (cp -p preserves the mode). Counted, not just returned: the loops
            # below ignore this helper's status, so a bare return would be silent.
            if ! backup_file "$file" >/dev/null; then
                ((failed++)) || true
                return 1
            fi
            if chmod "$expected" "$file" 2>/dev/null; then
                ((fixed++)) || true
                print_ok "$(i18n 'filesystem.file_fixed' "file=$file")"
            else
                ((failed++)) || true
                print_error "$(i18n 'filesystem.file_fix_failed' "file=$file")"
            fi
        fi
    }

    for file in "${!FS_SENSITIVE_FILES[@]}"; do
        _fs_fix_one "$file" "${FS_SENSITIVE_FILES[$file]}"
    done

    # Mirrors the audit-side drop-in expansion — without it the fix is a
    # silent no-op for files the audit just flagged. sudoers.d is 0440,
    # sshd_config.d is 0644.
    local _drop
    for _drop in "$FS_SUDOERS_D"/*; do
        [[ -f "$_drop" ]] || continue
        _fs_fix_one "$_drop" "440"
    done
    for _drop in "$FS_SSHD_CONFIG_D"/*; do
        [[ -f "$_drop" ]] || continue
        _fs_fix_one "$_drop" "644"
    done

    unset -f _fs_fix_one

    if ((fixed > 0)); then
        print_ok "$(i18n 'filesystem.perms_fixed' "count=$fixed")"
    fi

    if ((failed > 0)); then
        print_error "$(i18n 'filesystem.perms_fix_failed' "count=$failed")"
        return 1
    fi

    return 0
}

_fs_fix_umask() {
    print_info "$(i18n 'filesystem.fixing_umask')"

    if [[ ! -f "$FS_LOGIN_DEFS" ]]; then
        print_error "$(i18n 'filesystem.login_defs_not_found')"
        return 1
    fi

    backup_file "$FS_LOGIN_DEFS" >/dev/null || return 1

    # Stage, validate, replace atomically. PAM reads login.defs at every
    # login, so a partial in-place rewrite is a login-time failure — and this
    # fix is FIX_SAFE, applied without asking.
    local staged
    if grep -qE '^UMASK' "$FS_LOGIN_DEFS"; then
        staged=$(sed 's/^UMASK.*/UMASK\t\t027/' "$FS_LOGIN_DEFS") || staged=""
    else
        staged=$(printf '%s\nUMASK\t\t027\n' "$(cat "$FS_LOGIN_DEFS")") || staged=""
    fi

    if ! grep -qE '^UMASK[[:space:]]+027$' <<<"$staged"; then
        print_error "$(i18n 'filesystem.umask_stage_failed' "file=$FS_LOGIN_DEFS")"
        return 1
    fi

    if ! write_file_atomic "$FS_LOGIN_DEFS" "$staged"; then
        print_error "$(i18n 'filesystem.umask_write_failed' "file=$FS_LOGIN_DEFS")"
        return 1
    fi

    # Postcondition: ask the audit's own question again. sed exits 0 having
    # matched nothing, so trusting the write reports a fixed host that the
    # next audit re-flags.
    local usergroups effective
    usergroups=$(_fs_get_usergroups_enab)
    effective=$(_fs_compute_effective_umask "$(_fs_check_umask)" "$usergroups")
    if ! _fs_umask_is_strict "$effective"; then
        print_error "$(i18n 'filesystem.umask_not_effective' "value=$effective")"
        return 1
    fi

    print_ok "$(i18n 'filesystem.umask_fixed')"

    # Surface the USERGROUPS_ENAB interaction: with the Debian default the
    # group bits mirror the owner bits, so 027 becomes an effective 007.
    # World access is still denied.
    if [[ "$usergroups" == "yes" ]]; then
        print_info "Note: USERGROUPS_ENAB=yes is in effect; pam_umask will apply 027 as effective 007 (group bits = owner bits). Set USERGROUPS_ENAB=no manually only if you intentionally use shared groups for file isolation."
    fi

    # Without pam_umask the value just written only reaches shell login
    # sessions — the difference between "hardened" and "hardened for
    # interactive bash users". No fix: PAM stack edits are not auto-safe.
    if ! _fs_check_pam_umask_enabled; then
        print_warn "$(i18n 'filesystem.umask_pam_missing')"
    fi

    return 0
}
