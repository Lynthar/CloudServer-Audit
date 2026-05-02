#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Filesystem security module - SUID/SGID, permissions, world-writable
# Copyright (c) 2024

# ==============================================================================
# Filesystem Security Configuration
# ==============================================================================

# Known legitimate SUID binaries (whitelist)
# These are standard system binaries that normally have SUID bit set
declare -a FS_SUID_WHITELIST=(
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
    "/usr/sbin/unix_chkpwd"
    "/usr/sbin/mount.nfs"
    "/usr/sbin/mount.cifs"
    "/snap/snapd/*/usr/lib/snapd/snap-confine"
)

# Sensitive files and their expected permissions
# Note: sshd_config is 644 on Debian/Ubuntu by default (no secrets stored)
# SSH private keys should be 600, public keys 644
declare -A FS_SENSITIVE_FILES=(
    ["/etc/passwd"]="644"
    ["/etc/shadow"]="640"
    ["/etc/group"]="644"
    ["/etc/gshadow"]="640"
    ["/etc/ssh/sshd_config"]="644"
    ["/etc/ssh/ssh_host_rsa_key"]="600"
    ["/etc/ssh/ssh_host_ecdsa_key"]="600"
    ["/etc/ssh/ssh_host_ed25519_key"]="600"
    ["/etc/crontab"]="600"
    ["/etc/sudoers"]="440"
    ["/etc/hosts.allow"]="644"
    ["/etc/hosts.deny"]="644"
)

# Maximum number of items to report (to prevent huge output)
FS_MAX_REPORT_ITEMS=20

# Paths to prune from filesystem-walk scans.
#
# `find -xdev` already skips anything not on the root filesystem, so
# kernel/proc/sys/run/snap-squashfs mounts are handled automatically.
# This list is for trees that DO live on the root filesystem but would
# either swamp the audit with container-image content or take so long
# to traverse that the run hangs:
#   - /var/lib/docker        : overlay2/<sha>/diff/* contains thousands
#                              of files inherited from Docker images,
#                              including legitimate-inside-the-image
#                              SUID binaries that would be flagged as
#                              host-level anomalies
#   - /var/lib/containerd    : same as above, for containerd
#   - /var/lib/containers    : podman / buildah image storage
#   - /var/lib/lxd           : LXD container rootfs cache
#   - /var/lib/lxcfs         : LXC fuse layer
#   - /var/lib/snapd         : snap state + image cache (huge)
#   - /snap                  : snap mount point (squashfs is on its
#                              own fs and -xdev skips, but if root is
#                              a single fs the directory entries
#                              themselves can confuse find on some
#                              kernels — prune defensively)
declare -ga _FS_PRUNE_PATHS=(
    /var/lib/docker
    /var/lib/containerd
    /var/lib/containers
    /var/lib/lxd
    /var/lib/lxcfs
    /var/lib/snapd
    /snap
)

# Hard timeout for any single filesystem walk. Defaults to 60 seconds;
# operators with very large filesystems can override at audit time:
#     VPSSEC_FS_TIMEOUT=300 sudo ./vpssec audit
# A scan that hits the timeout returns whatever output it has gathered
# so far; the audit continues and a warning is logged. Better to
# report partial findings than to hang an audit indefinitely.
_FS_FIND_TIMEOUT="${VPSSEC_FS_TIMEOUT:-60}"

# ==============================================================================
# Filesystem Helper Functions
# ==============================================================================

# Build the prune-args portion of a find expression from
# _FS_PRUNE_PATHS. Each path becomes `-path P -prune -o`. Caller
# concatenates the result before its `-type ... -print0` portion:
#
#     local prune_args=()
#     _fs_build_prune_args prune_args
#     find / -xdev "${prune_args[@]}" -type f -perm -4000 -print0 ...
#
# The single source of truth (the array above) keeps the five scans
# from drifting out of sync — three of them used to omit container
# prunes entirely, so world-writable / no-owner scans flagged Docker
# image content as host findings.
_fs_build_prune_args() {
    local -n _out=$1
    _out=()
    local p
    for p in "${_FS_PRUNE_PATHS[@]}"; do
        _out+=( -path "$p" -prune -o )
    done
}

# Run a find invocation under a hard timeout. Output is forwarded to
# stdout (so callers can wire it into a process substitution feeding
# `while read`). On timeout (exit 124) we log a warning but return 0
# so the audit doesn't bail; partial output already reached the
# consumer. Caller is responsible for the rest of the find arguments.
#
# `timeout` is part of GNU coreutils, present by default on every
# supported distro (Debian/Ubuntu/RHEL/Rocky/Alma). The graceful
# fallback below is for niche environments — minimal containers,
# macOS dev shells running tests — where coreutils may be absent;
# the audit still runs, just without the safety net.
_fs_run_find() {
    local label="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$_FS_FIND_TIMEOUT" "$@"
        local rc=$?
        if (( rc == 124 )); then
            log_warn "filesystem scan '${label}' timed out after ${_FS_FIND_TIMEOUT}s; results truncated. Set VPSSEC_FS_TIMEOUT=N to extend."
        fi
    else
        log_debug "timeout(1) unavailable; running '${label}' scan without time bound"
        "$@"
    fi
    return 0
}

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

    for pattern in "${FS_SUID_WHITELIST[@]}"; do
        # Support glob patterns with *
        if [[ "$path" == $pattern ]]; then
            return 0
        fi
    done
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
    )

    local prune_args=()
    _fs_build_prune_args prune_args

    while IFS= read -r -d '' file; do
        local skip=0
        for pattern in "${sgid_whitelist[@]}"; do
            if [[ "$file" == "$pattern" ]]; then
                skip=1
                break
            fi
        done

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

# Known legitimate binaries with capabilities (whitelist)
declare -a FS_CAPS_WHITELIST=(
    "/usr/bin/ping:cap_net_raw"
    "/usr/bin/traceroute:cap_net_raw"
    "/usr/bin/mtr-packet:cap_net_raw"
    "/usr/bin/arping:cap_net_raw"
    "/usr/sbin/clockdiff:cap_net_raw"
    "/usr/bin/gnome-keyring-daemon:cap_ipc_lock"
    "/usr/bin/systemd-resolve:cap_net_bind_service"
)

# Dangerous capabilities that grant significant privileges
declare -a FS_DANGEROUS_CAPS=(
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

    # Find all files with capabilities
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local file="${line%% =*}"
        local caps="${line#*= }"

        # Check if in whitelist
        local whitelisted=false
        for entry in "${FS_CAPS_WHITELIST[@]}"; do
            local wl_file="${entry%%:*}"
            local wl_cap="${entry#*:}"
            if [[ "$file" == "$wl_file" && "$caps" =~ $wl_cap ]]; then
                whitelisted=true
                break
            fi
        done

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
    local issues=()

    for file in "${!FS_SENSITIVE_FILES[@]}"; do
        local expected="${FS_SENSITIVE_FILES[$file]}"
        local result
        result=$(_fs_check_sensitive_file "$file" "$expected")
        if [[ -n "$result" ]]; then
            issues+=("$result")
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
        [[ -n "$result" ]] && issues+=("$result")
    done
    for _drop in /etc/ssh/sshd_config.d/*; do
        [[ -f "$_drop" ]] || continue
        local result
        result=$(_fs_check_sensitive_file "$_drop" "644")
        [[ -n "$result" ]] && issues+=("$result")
    done

    if [[ ${#issues[@]} -gt 0 ]]; then
        local issue_list=$(printf '%s\n' "${issues[@]}" | head -5 | tr '\n' ' ')
        local check=$(create_check_json \
            "filesystem.sensitive_perms_wrong" \
            "filesystem" \
            "high" \
            "failed" \
            "$(i18n 'filesystem.sensitive_perms_wrong' "count=${#issues[@]}")" \
            "Files with wrong permissions: $issue_list" \
            "$(i18n 'filesystem.fix_sensitive_perms')" \
            "filesystem.fix_sensitive_perms")
        state_add_check "$check"
        print_severity "high" "$(i18n 'filesystem.sensitive_perms_wrong' "count=${#issues[@]}")"
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
    local umask_value
    umask_value=$(_fs_check_umask)

    # umask 027 or 077 is recommended
    if [[ "$umask_value" == "027" || "$umask_value" == "077" ]]; then
        local check=$(create_check_json \
            "filesystem.umask_ok" \
            "filesystem" \
            "low" \
            "passed" \
            "$(i18n 'filesystem.umask_ok')" \
            "umask=$umask_value" \
            "" \
            "")
        state_add_check "$check"
        print_ok "$(i18n 'filesystem.umask_ok') ($umask_value)"
    elif [[ "$umask_value" == "022" ]]; then
        local check=$(create_check_json \
            "filesystem.umask_default" \
            "filesystem" \
            "low" \
            "failed" \
            "$(i18n 'filesystem.umask_default')" \
            "umask=$umask_value (default, consider 027)" \
            "Set umask to 027 in /etc/login.defs" \
            "")
        state_add_check "$check"
        print_severity "low" "$(i18n 'filesystem.umask_default') ($umask_value)"
    else
        local check=$(create_check_json \
            "filesystem.umask_weak" \
            "filesystem" \
            "medium" \
            "failed" \
            "$(i18n 'filesystem.umask_weak')" \
            "umask=$umask_value (too permissive)" \
            "Set umask to 027 or 077" \
            "filesystem.fix_umask")
        state_add_check "$check"
        print_severity "medium" "Weak umask: $umask_value"
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
        return 0
    else
        print_error "$(i18n 'filesystem.login_defs_not_found')"
        return 1
    fi
}
