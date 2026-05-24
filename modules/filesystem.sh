#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Filesystem security module - SUID/SGID, permissions, world-writable
# Copyright (c) 2024

# ==============================================================================
# Filesystem Security Configuration
# ==============================================================================

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

# Sensitive files and their expected permissions
# Note: sshd_config is 644 on Debian/Ubuntu by default (no secrets stored)
# SSH private keys should be 600, public keys 644
# Backup-shadow files (/etc/shadow-, /etc/gshadow-, etc.) are checked
# alongside the originals — they hold the same secrets and are a
# classic blind spot (also missed by Lynis's default profile).
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
    # sudo + scheduled jobs
    ["/etc/sudoers"]="440"
    ["/etc/crontab"]="600"
    ["/etc/cron.allow"]="600"
    ["/etc/cron.deny"]="600"
    ["/etc/at.allow"]="600"
    ["/etc/at.deny"]="600"
    # TCP wrappers (public, read-only)
    ["/etc/hosts.allow"]="644"
    ["/etc/hosts.deny"]="644"
    # Boot loader config — write access here changes kernel cmdline
    ["/boot/grub/grub.cfg"]="600"
    ["/boot/grub2/grub.cfg"]="600"
    # Legacy r-* trust files: if present, lax perms are a remote-trust leak
    ["/root/.rhosts"]="600"
    ["/root/.shosts"]="600"
)

# Maximum number of items to report (to prevent huge output)
FS_MAX_REPORT_ITEMS=20

# Filesystem-walk infrastructure (_FS_PRUNE_PATHS, _FS_FIND_TIMEOUT,
# _fs_build_prune_args, _fs_run_find) lives in core/common.sh so any
# module — webapp's web-root scans, malware's path probes — can use it
# without depending on filesystem.sh being in the include set.

# ==============================================================================
# Filesystem Helper Functions
# ==============================================================================

# Sanitize count value to ensure it's a single integer
# Handles cases where grep -c returns multiline output
_fs_sanitize_count() {
    local val="$1"
    val=$(echo "$val" | head -1)
    val="${val//[^0-9]/}"
    echo "${val:-0}"
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
    # Package-ownership fallback: a SUID binary owned by an installed
    # package is distro-shipped and maintainer-vetted, not an anomaly —
    # this is what lets us stop hand-maintaining per-release path
    # whitelists. Orphaned (unowned) SUID files still fall through to a
    # finding. No-op when the pkg manager can't answer (non-zero rc).
    if declare -f file_owned_by_package >/dev/null 2>&1; then
        file_owned_by_package "$path" && return 0
    fi
    return 1
}

# Find SUID files (excluding whitelisted).
#
# `find / -xdev` already skips anything not on the root filesystem
# (NFS, separate /home, snap squashfs, tmpfs etc.). The prune list
# below additionally skips container-image storage that lives *on*
# the root filesystem — Docker overlay diffs ship legitimate SUID
# binaries that would get flagged as host-level anomalies otherwise.
_fs_find_suid_files() {
    local count=0
    local results=()

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        if ! _fs_is_whitelisted "$file"; then
            results+=("$file")
            ((count++))
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

        # Package-ownership fallback (same rationale as SUID): an SGID
        # binary owned by an installed package is distro-shipped, not an
        # anomaly. Orphaned ones still get reported.
        if (( skip == 0 )) && declare -f file_owned_by_package >/dev/null 2>&1; then
            file_owned_by_package "$file" && skip=1
        fi

        if ((skip == 0)); then
            results+=("$file")
            ((count++))
            if ((count >= FS_MAX_REPORT_ITEMS)); then
                break
            fi
        fi
    done < <(_fs_run_find "sgid" \
        find / -xdev "${prune_args[@]}" \
        -type f -perm -2000 -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find world-writable files. Excludes ephemeral/volatile mounts AND
# container storage — the latter were missing from the original
# implementation, so a busy Docker host saw image-internal files
# flagged as host-level world-writable issues.
_fs_find_world_writable() {
    local count=0
    local results=()

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        results+=("$file")
        ((count++))
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
        ((count++))
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(_fs_run_find "world-writable-dirs" \
        find / -xdev "${prune_args[@]}" \
        -type d -perm -0002 ! -perm -1000 \
        ! -path "/tmp" \
        ! -path "/var/tmp" \
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
        ((count++))
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

# Check sensitive file permissions
_fs_check_sensitive_file() {
    local file="$1"
    local expected="$2"

    if [[ ! -f "$file" ]]; then
        return 0  # File doesn't exist, skip
    fi

    local actual
    actual=$(stat -c "%a" "$file" 2>/dev/null)

    if [[ -z "$actual" ]]; then
        return 1
    fi

    # Check if permissions are too permissive (bitmask comparison).
    #
    # The previous arithmetic test `((actual_num > expected_num))` was
    # WRONG: 0604 < 0640 numerically, but 0604 grants world-read where
    # 0640 does not, so /etc/shadow at mode 604 silently passed this
    # audit. Likewise 0046 (38) < 0640 (416) but 0046 grants world-
    # write. The correct test is: does `actual` set any bit that
    # `expected` does not? — `actual & ~expected`. Mask to the low 12
    # bits so setuid/setgid/sticky in `actual` still flag (they are
    # legitimately surprising on these files), without false-flagging
    # ad-hoc high bits if stat ever printed them.
    local actual_num=$((8#$actual))
    local expected_num=$((8#$expected))
    local extra_bits=$(( (actual_num & ~expected_num) & 07777 ))

    if (( extra_bits != 0 )); then
        echo "$file:$actual:$expected"
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

    # Check /etc/login.defs
    if [[ -f /etc/login.defs ]]; then
        umask_value=$(grep -E "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')
    fi

    # Check /etc/profile
    if [[ -z "$umask_value" && -f /etc/profile ]]; then
        umask_value=$(grep -E "^\s*umask" /etc/profile 2>/dev/null | tail -1 | awk '{print $2}')
    fi

    echo "${umask_value:-022}"
}

# Returns "yes" or "no" — the value of USERGROUPS_ENAB in /etc/login.defs.
# Defaults to "yes" (the documented Debian/Ubuntu default) when the
# directive is absent, since that's how pam_umask actually behaves.
_fs_get_usergroups_enab() {
    local val=""
    if [[ -f /etc/login.defs ]]; then
        val=$(grep -E "^USERGROUPS_ENAB" /etc/login.defs 2>/dev/null | awk '{print tolower($2)}')
    fi
    echo "${val:-yes}"
}

# Apply the USERGROUPS_ENAB transformation to a configured umask. When
# USERGROUPS_ENAB=yes (Debian/Ubuntu default) and the user's uid equals
# their primary gid (the standard private-group convention), pam_umask
# rewrites the group mask bits to match the owner bits. So configured
# 027 becomes effective 007, and the audit lying about "027 is set"
# was the actual M15 user-facing bug.
#
# $1 = configured umask string (e.g. "027" or "0027")
# $2 = "yes"|"no" (USERGROUPS_ENAB)
# Echoes a 4-digit normalized effective umask.
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

# Returns 0 if pam_umask is enabled in /etc/pam.d/common-session*.
# pam_umask reading login.defs UMASK is what makes the configured
# value actually take effect at session start; without it, only shell
# rc files (/etc/profile, /etc/bash.bashrc) influence umask.
_fs_check_pam_umask_enabled() {
    local f
    for f in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
        [[ -f "$f" ]] || continue
        # Match "session ... pam_umask.so" while skipping commented lines.
        grep -qE '^[[:space:]]*session[[:space:]]+[^#]*pam_umask\.so' "$f" 2>/dev/null && return 0
    done
    return 1
}

# Known legitimate binaries with capabilities (whitelist)
declare -ga FS_CAPS_WHITELIST=(
    "/usr/bin/ping:cap_net_raw"
    "/usr/bin/traceroute:cap_net_raw"
    "/usr/bin/mtr-packet:cap_net_raw"
    # arping/clockdiff swap between /usr/bin and /usr/sbin across distros (RHEL vs Debian) — glob both
    "/usr/*bin/arping:cap_net_raw"
    "/usr/*bin/clockdiff:cap_net_raw"
    "/usr/bin/gnome-keyring-daemon:cap_ipc_lock"
    "/usr/bin/systemd-resolve:cap_net_bind_service"
    # snapd sandbox helper legitimately holds cap_sys_admin (+ others)
    "/usr/lib/snapd/snap-confine:cap_sys_admin"
    # GStreamer PTP helper — legit cap_net_admin/net_bind_service/sys_nice (multiarch path)
    "/usr/lib/*/gstreamer1.0/gstreamer-1.0/gst-ptp-helper:cap_net_admin"
)

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

    # Find all files with capabilities.
    # getcap output format varies by libcap version:
    #   modern (libcap >= 2.43):  "/usr/bin/ping cap_net_raw=ep"
    #   legacy:                   "/usr/bin/ping = cap_net_raw+ep"
    # Previously parsed only the legacy form, so on every modern Debian/
    # Ubuntu the whitelist match silently failed and every cap-bearing
    # binary got flagged. Split on the first space, then strip a leading
    # "= " to handle the legacy form too.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local file="${line%% *}"
        local caps="${line#* }"
        caps="${caps#= }"

        # Check if in whitelist
        local whitelisted=false
        for entry in "${FS_CAPS_WHITELIST[@]}"; do
            local wl_file="${entry%%:*}"
            local wl_cap="${entry#*:}"
            # Unquoted $wl_file = glob match (handles multiarch /usr/lib/*/ paths)
            if [[ "$file" == $wl_file && "$caps" =~ $wl_cap ]]; then
                whitelisted=true
                break
            fi
        done

        # Distro-specific cap entries (RHEL/Arch) from core/distro.sh
        if [[ "$whitelisted" == false ]] && declare -f distro_caps_whitelist >/dev/null 2>&1; then
            local dentry
            while IFS= read -r dentry; do
                [[ -z "$dentry" ]] && continue
                if [[ "$file" == ${dentry%%:*} && "$caps" =~ ${dentry#*:} ]]; then
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

            ((count++))
            if ((count >= FS_MAX_REPORT_ITEMS)); then
                break
            fi
        fi
    done < <(getcap -r / 2>/dev/null | grep -v "^$")

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

# ==============================================================================
# Filesystem Audit
# ==============================================================================

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
            "Files: $file_list" \
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
            "No unexpected SUID files found" \
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
            "Files: $file_list" \
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
            "No unexpected SGID files found" \
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
            "Items: $items" \
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
            "medium" \
            "failed" \
            "$(i18n 'filesystem.no_owner' "count=$count")" \
            "Files: $file_list" \
            "$(i18n 'filesystem.fix_no_owner')" \
            "")
        state_add_check "$check"
        print_severity "medium" "$(i18n 'filesystem.no_owner' "count=$count")"
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
    # Severity model: not every "wrong perms" finding is equal.
    #   * /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/*,
    #     SSH host private keys (ssh_host_*_key) → mistaken perms
    #     here are direct local-priv-esc / credential-leak
    #     primitives. Stay HIGH.
    #   * /etc/passwd, /etc/group, sshd_config, /etc/crontab, public
    #     hosts.allow/deny, sshd_config.d drop-ins → wrong perms are
    #     real but typically read-only exposure, not direct
    #     compromise. MEDIUM.
    # Emit one finding per bucket so the score reflects actual
    # exposure rather than counting a wrong-perm /etc/group as
    # equivalent to a 666 sudoers drop-in.
    local high_issues=()
    local med_issues=()

    _fs_is_critical_perm_path() {
        case "$1" in
            # /etc/shadow- and /etc/gshadow- are the rotated backups
            # written by passwd/usermod/etc. — they hold the *same*
            # password hashes as the live files, so weak perms there
            # are an equivalent credential-leak primitive.
            /etc/shadow|/etc/shadow-|/etc/gshadow|/etc/gshadow-|/etc/sudoers) return 0 ;;
            /etc/sudoers.d/*) return 0 ;;
            /etc/ssh/ssh_host_*_key) return 0 ;;
            *) return 1 ;;
        esac
    }

    for file in "${!FS_SENSITIVE_FILES[@]}"; do
        local expected="${FS_SENSITIVE_FILES[$file]}"
        # RHEL/Fedora package SSH host private keys as 640 root:ssh_keys
        # (the ssh-keysign helper and host-based auth need group read);
        # that is the shipped default, not a permission slip. Accept 640
        # for host keys only when the group really is ssh_keys — 640 still
        # forbids world/other bits, so a world-readable key is still
        # caught. Debian/Ubuntu/Arch keep the 600 expectation.
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

    # Drop-in directories. The static FS_SENSITIVE_FILES list cannot
    # use globs, so files dropped into /etc/sudoers.d/ or
    # /etc/ssh/sshd_config.d/ at install time (cloud-init, Ansible,
    # kubeadm, etc.) were not audited. A 666 file in /etc/sudoers.d/
    # is a direct privilege-escalation primitive yet was passing
    # cleanly. Same drop-in blindness pattern as the sshd_config.d
    # bug this whole audit pass was seeded by.
    local _drop
    for _drop in /etc/sudoers.d/*; do
        [[ -f "$_drop" ]] || continue
        local result
        result=$(_fs_check_sensitive_file "$_drop" "440")
        [[ -n "$result" ]] && high_issues+=("$result")
    done
    for _drop in /etc/ssh/sshd_config.d/*; do
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
                "Files with wrong permissions: $issue_list" \
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
                "medium" \
                "failed" \
                "$(i18n 'filesystem.sensitive_perms_wrong_minor' "count=${#med_issues[@]}")" \
                "Files with wrong permissions: $issue_list_m" \
                "$(i18n 'filesystem.fix_sensitive_perms')" \
                "filesystem.fix_sensitive_perms")
            state_add_check "$check_m"
            print_severity "medium" "$(i18n 'filesystem.sensitive_perms_wrong_minor' "count=${#med_issues[@]}")"
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
            "/tmp mounted with noexec,nosuid,nodev" \
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
            "/tmp is not a separate mount point" \
            "Consider using separate /tmp partition or tmpfs" \
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
            "Missing options: $missing" \
            "Add noexec,nosuid,nodev to /tmp mount" \
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

    # Severity is decided on the EFFECTIVE umask (what actually applies
    # at session start), not the literal value in login.defs. Otherwise
    # configured=027 + USERGROUPS_ENAB=yes (Debian default) reports "OK"
    # while real users get effective 007.
    local desc="configured=$configured"
    if [[ "$configured" != "$effective" ]]; then
        desc="$desc, effective=$effective (USERGROUPS_ENAB=$usergroups rewrites group bits)"
    fi

    # OK = world denied (last digit = 7). Captures 027, 077, 007 (the
    # USERGROUPS-rewritten form), and any other strict variant.
    if [[ "$effective" =~ ^0[0-7][0-7]7$ ]]; then
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
            "$desc (consider 027)" \
            "Set umask to 027 in /etc/login.defs" \
            "filesystem.fix_umask")
        state_add_check "$check"
        print_severity "low" "$(i18n 'filesystem.umask_default') ($desc)"
    else
        local check=$(create_check_json \
            "filesystem.umask_weak" \
            "filesystem" \
            "medium" \
            "failed" \
            "$(i18n 'filesystem.umask_weak')" \
            "$desc (too permissive)" \
            "Set umask to 027 or 077" \
            "filesystem.fix_umask")
        state_add_check "$check"
        print_severity "medium" "Weak umask: $desc"
    fi

    # pam_umask presence is informational — if absent, the UMASK setting
    # in login.defs may not be applied at session start (only via shell
    # rc files), so tell the user. No fix offered: PAM stack edits are
    # too sensitive to auto-modify.
    if ! _fs_check_pam_umask_enabled; then
        local pam_check
        pam_check=$(create_check_json \
            "filesystem.pam_umask_disabled" \
            "filesystem" \
            "info" \
            "passed" \
            "pam_umask not enabled in common-session" \
            "Without pam_umask, /etc/login.defs UMASK is only applied via shell rc files (/etc/profile etc), not at PAM session start" \
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
            "getcap not available" \
            "Install libcap2-bin to check file capabilities" \
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
            "high" \
            "failed" \
            "$(i18n 'filesystem.dangerous_caps' "count=$dangerous_count")" \
            "Dangerous capabilities: $dangerous_list" \
            "$(i18n 'filesystem.review_caps')" \
            "filesystem.review_caps")
        state_add_check "$check"
        print_severity "high" "Files with dangerous capabilities: $dangerous_count"
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
            "Files with capabilities: $caps_list" \
            "Review if these capabilities are needed" \
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
            "high" \
            "failed" \
            "$(i18n 'filesystem.suspicious_cron' "count=$sus_count")" \
            "$sus_list" \
            "Review cron entries for potential malware or backdoors" \
            "")
        state_add_check "$check"
        print_severity "high" "Suspicious cron entries found: $sus_count"
    else
        local check=$(create_check_json \
            "filesystem.cron_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.cron_ok')" \
            "User crontabs: $user_crontabs" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.cron_ok')"
    fi
}

# ==============================================================================
# Filesystem Fix Functions
# ==============================================================================

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

        # Same bitmask test as _fs_check_sensitive_file — chmod whenever
        # the file has any bit not in the expected mask. The original
        # arithmetic `((actual > expected))` failed to fix files like
        # /etc/shadow at 0604 (world-readable but numerically smaller
        # than the 0640 expected mask) — the audit reported the issue
        # via the bitmask check above, but the fix never ran.
        local extra_bits=$(( (actual_num & ~expected_num) & 07777 ))
        if (( extra_bits != 0 )); then
            print_info "$(i18n 'filesystem.fixing_file' "file=$file" "from=$actual" "to=$expected")"
            if chmod "$expected" "$file" 2>/dev/null; then
                ((fixed++))
                print_ok "$(i18n 'filesystem.file_fixed' "file=$file")"
            else
                ((failed++))
                print_error "$(i18n 'filesystem.file_fix_failed' "file=$file")"
            fi
        fi
    }

    for file in "${!FS_SENSITIVE_FILES[@]}"; do
        _fs_fix_one "$file" "${FS_SENSITIVE_FILES[$file]}"
    done

    # Mirror the audit-side drop-in expansion. /etc/sudoers.d/* should
    # be 0440 (matching the sudoers main file); /etc/ssh/sshd_config.d/*
    # should be 0644 (matching sshd_config). Without this, the fix
    # path is silently a no-op for files the audit just flagged.
    local _drop
    for _drop in /etc/sudoers.d/*; do
        [[ -f "$_drop" ]] || continue
        _fs_fix_one "$_drop" "440"
    done
    for _drop in /etc/ssh/sshd_config.d/*; do
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

    local login_defs="/etc/login.defs"

    if [[ -f "$login_defs" ]]; then
        backup_file "$login_defs"

        # Update UMASK in login.defs
        if grep -q "^UMASK" "$login_defs"; then
            sed -i 's/^UMASK.*/UMASK\t\t027/' "$login_defs"
        else
            echo "UMASK		027" >> "$login_defs"
        fi

        print_ok "$(i18n 'filesystem.umask_fixed')"

        # Surface the USERGROUPS_ENAB interaction so the operator isn't
        # surprised. With the Debian default (USERGROUPS_ENAB=yes +
        # private user groups), pam_umask rewrites 027 to effective 007
        # at session start. World access is still denied; the change
        # is just that group bits mirror owner bits — harmless on a
        # standard VPS where each user has their own private group.
        local usergroups
        usergroups=$(_fs_get_usergroups_enab)
        if [[ "$usergroups" == "yes" ]]; then
            print_info "Note: USERGROUPS_ENAB=yes is in effect; pam_umask will apply 027 as effective 007 (group bits = owner bits). Set USERGROUPS_ENAB=no manually only if you intentionally use shared groups for file isolation."
        fi
        return 0
    else
        print_error "$(i18n 'filesystem.login_defs_not_found')"
        return 1
    fi
}
