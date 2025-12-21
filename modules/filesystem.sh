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

# ==============================================================================
# Filesystem Helper Functions
# ==============================================================================

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

# Find SUID files (excluding whitelisted)
_fs_find_suid_files() {
    local count=0
    local results=()

    while IFS= read -r -d '' file; do
        if ! _fs_is_whitelisted "$file"; then
            results+=("$file")
            ((count++))
            # Limit output
            if ((count >= FS_MAX_REPORT_ITEMS)); then
                break
            fi
        fi
    done < <(find / -xdev -type f -perm -4000 -print0 2>/dev/null)

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
    done < <(find / -xdev -type f -perm -2000 -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find world-writable files (excluding /tmp, /var/tmp, /dev)
_fs_find_world_writable() {
    local count=0
    local results=()

    while IFS= read -r -d '' file; do
        results+=("$file")
        ((count++))
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(find / -xdev -type f -perm -0002 \
        ! -path "/tmp/*" \
        ! -path "/var/tmp/*" \
        ! -path "/dev/*" \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        ! -path "/run/*" \
        -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find world-writable directories without sticky bit
_fs_find_world_writable_dirs() {
    local count=0
    local results=()

    while IFS= read -r -d '' dir; do
        results+=("$dir")
        ((count++))
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(find / -xdev -type d -perm -0002 ! -perm -1000 \
        ! -path "/tmp" \
        ! -path "/var/tmp" \
        ! -path "/dev/*" \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        ! -path "/run/*" \
        -print0 2>/dev/null)

    printf '%s\n' "${results[@]}"
}

# Find files with no owner
_fs_find_no_owner() {
    local count=0
    local results=()

    while IFS= read -r -d '' file; do
        results+=("$file")
        ((count++))
        if ((count >= FS_MAX_REPORT_ITEMS)); then
            break
        fi
    done < <(find / -xdev \( -nouser -o -nogroup \) \
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

    # Check if permissions are too permissive
    # Convert to octal numbers for comparison
    local actual_num=$((8#$actual))
    local expected_num=$((8#$expected))

    # If actual permissions are more permissive than expected
    if ((actual_num > expected_num)); then
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
}

_fs_audit_suid() {
    local suid_files
    suid_files=$(_fs_find_suid_files)
    local count=$(echo "$suid_files" | grep -c . 2>/dev/null || echo "0")

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
    local count=$(echo "$sgid_files" | grep -c . 2>/dev/null || echo "0")

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
    local count=$(echo "$ww_files" | grep -c . 2>/dev/null || echo "0")

    local ww_dirs
    ww_dirs=$(_fs_find_world_writable_dirs)
    local dir_count=$(echo "$ww_dirs" | grep -c . 2>/dev/null || echo "0")

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
    local count=$(echo "$no_owner_files" | grep -c . 2>/dev/null || echo "0")

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

    for file in "${!FS_SENSITIVE_FILES[@]}"; do
        local expected="${FS_SENSITIVE_FILES[$file]}"

        if [[ ! -f "$file" ]]; then
            continue
        fi

        local actual
        actual=$(stat -c "%a" "$file" 2>/dev/null)
        local actual_num=$((8#$actual))
        local expected_num=$((8#$expected))

        if ((actual_num > expected_num)); then
            print_info "Fixing $file: $actual -> $expected"
            if chmod "$expected" "$file" 2>/dev/null; then
                ((fixed++))
                print_ok "Fixed: $file"
            else
                ((failed++))
                print_error "Failed to fix: $file"
            fi
        fi
    done

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
