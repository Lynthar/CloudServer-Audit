#!/usr/bin/env bats
# Coverage for the kernel fixes that write sysctl drop-ins, limits.conf and the
# systemd-coredump drop-in. The RA/SLAAC guard on accept_ra=0 must hold on BOTH
# paths — harden_ipv6 and harden_network — or an IPv6-only VPS loses its route.

load helpers.bash

setup() {
    _vpssec_load
    etc=$(_vpssec_fake_etc)
    _kernel_source
    mkdir -p "$etc/security" "$etc/systemd"

    export TMPDIR="$BATS_TEST_TMPDIR"
    sysctl_store="$BATS_TEST_TMPDIR/sysctl"
    mkdir -p "$sysctl_store"

    _sysctl_stub
    _no_forwarding_daemons
}

# Source the module, then repoint its paths at the fake /etc. The param table
# is built at source time from the detected distro, so a test that changes
# VPSSEC_DISTRO_* re-sources through here — never directly, or /etc is live.
_kernel_source() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/kernel.sh"

    # VPSSEC_SYSCTL_CONF and KERNEL_COREDUMP_DROPIN are derived at source time,
    # so overriding only their parent directories would leave them on /etc.
    SYSCTL_D="$etc/sysctl.d"
    VPSSEC_SYSCTL_CONF="$SYSCTL_D/99-vpssec-hardening.conf"
    KERNEL_LIMITS_CONF="$etc/security/limits.conf"
    KERNEL_COREDUMP_CONF="$etc/systemd/coredump.conf"
    KERNEL_COREDUMP_D="$etc/systemd/coredump.conf.d"
    KERNEL_COREDUMP_DROPIN="$KERNEL_COREDUMP_D/99-vpssec.conf"
}

# Rebuild the param table as the module builds it on distro $1 (family $2).
_kernel_on() {
    VPSSEC_DISTRO_ID="$1"
    VPSSEC_DISTRO_FAMILY="$2"
    _kernel_source
}

# ---- stubs ----------------------------------------------------------

# A sysctl that remembers. One file per parameter (parameter names contain
# dots, never slashes), so `-w` then `-n` reads back the written value and
# the last write wins.
_sysctl_stub() {
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    -w) printf '%s\n' "\${2#*=}" > "\$store/\${2%%=*}" ;;
    -p) ;;
esac
exit 0
SH
}

# A sysctl whose runtime writes are refused — a container with a read-only
# /proc/sys. Reads still answer, so seeded values stay as they were.
_sysctl_readonly() {
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    *)  exit 1 ;;
esac
exit 0
SH
}

# Seed a parameter's current runtime value.
_sysctl_seed() { printf '%s\n' "$2" > "$sysctl_store/$1"; }

# True if the persisted drop-in carries "<param> = <value>".
_dropin_has() { grep -qxF "$1 = $2" "$VPSSEC_SYSCTL_CONF"; }

# The host's IPv6 default route comes from Router Advertisements.
_host_uses_ra() {
    _vpssec_stub_script ip <<'SH'
[[ "$*" == *"-6 route show default"* ]] &&
    echo "default via fe80::1 dev eth0 proto ra metric 1024"
exit 0
SH
}

# Static IPv6 configuration — no RA-installed route.
_host_static_ipv6() {
    _vpssec_stub_script ip <<'SH'
[[ "$*" == *"-6 route show default"* ]] &&
    echo "default via 2001:db8::1 dev eth0 metric 1024"
exit 0
SH
}

# `ip` is installed but cannot answer (no permission, no IPv6 support in
# the kernel, netlink refused). "Cannot probe" must be treated the same as
# "ip is missing": assume RA and leave the route alone.
_host_ipv6_unprobeable() {
    _vpssec_stub_script ip <<'SH'
exit 1
SH
}

_no_forwarding_daemons() {
    _vpssec_stub_script systemctl <<'SH'
exit 1
SH
}

# Something on this host legitimately routes (Docker, a VPN, a k8s node).
_forwarding_daemon_active() {
    _vpssec_stub_script systemctl <<'SH'
[[ "$*" == *"is-active"*docker* ]] && exit 0
exit 1
SH
}

# ==============================================================================
# The sysctl drop-in writer
# ==============================================================================

@test "sysctl drop-in: the parameter is persisted" {
    _kernel_write_sysctl "kernel.dmesg_restrict" "1"
    _dropin_has "kernel.dmesg_restrict" "1"
}

@test "sysctl drop-in: the header appears exactly once after several params" {
    _kernel_write_sysctl "kernel.dmesg_restrict" "1"
    _kernel_write_sysctl "kernel.kptr_restrict" "2"
    _kernel_write_sysctl "fs.protected_hardlinks" "1"

    [ "$(grep -c '^# vpssec kernel hardening configuration$' "$VPSSEC_SYSCTL_CONF")" -eq 1 ]
}

@test "sysctl drop-in: rewriting a parameter replaces it instead of duplicating" {
    _kernel_write_sysctl "kernel.sysrq" "176"
    _kernel_write_sysctl "kernel.sysrq" "0"

    [ "$(grep -c '^kernel\.sysrq = ' "$VPSSEC_SYSCTL_CONF")" -eq 1 ]
    _dropin_has "kernel.sysrq" "0"
}

@test "sysctl drop-in: writing one parameter keeps the others" {
    # The rewrite filters the existing file by an anchored regex built from
    # the parameter name. A parameter sharing a prefix with another must
    # survive its neighbour's write.
    _kernel_write_sysctl "fs.protected_hardlinks" "1"
    _kernel_write_sysctl "fs.protected_symlinks" "1"

    _dropin_has "fs.protected_hardlinks" "1"
    _dropin_has "fs.protected_symlinks" "1"
}

@test "sysctl drop-in: a pre-existing drop-in is backed up as it was before the plan" {
    # The writer rewrites the whole file once per parameter, so the backup
    # has to be first-write-wins: whichever parameter happens to be written
    # last must not end up defining what a rollback restores.
    mkdir -p "$SYSCTL_D"
    printf '# hand-written\nkernel.sysrq = 176\n' > "$VPSSEC_SYSCTL_CONF"
    _vpssec_begin_backup_session

    _kernel_write_sysctl "kernel.dmesg_restrict" "1"
    _kernel_write_sysctl "kernel.kptr_restrict" "2"

    local backup="${VPSSEC_BACKUP_SESSION}${VPSSEC_SYSCTL_CONF}"
    grep -qxF "kernel.sysrq = 176" "$backup"
    _vpssec_refute grep -q "dmesg_restrict\|kptr_restrict" "$backup"
}

@test "sysctl drop-in: a newly created drop-in is recorded so rollback deletes it" {
    _vpssec_begin_backup_session
    _kernel_write_sysctl "kernel.dmesg_restrict" "1"

    grep -qxF "$VPSSEC_SYSCTL_CONF" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "sysctl drop-in: no staging file is left behind" {
    _kernel_write_sysctl "kernel.dmesg_restrict" "1"

    run bash -c "ls $SYSCTL_D/.vpssec.* 2>/dev/null"
    [ -z "$output" ]
}

# ==============================================================================
# The RA/SLAAC guard — both paths that can apply accept_ra
# ==============================================================================

@test "harden_ipv6: accept_ra is left alone on a SLAAC host" {
    _host_uses_ra

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "accept_ra" "$VPSSEC_SYSCTL_CONF"
}

@test "harden_ipv6: the always-safe parameters are still applied on a SLAAC host" {
    # Skipping the RA parameters must not turn into skipping the fix.
    _host_uses_ra

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv6.conf.all.accept_redirects" "0"
    _dropin_has "net.ipv6.conf.all.use_tempaddr" "2"
}

@test "harden_ipv6: accept_ra is applied on a statically configured host" {
    _host_static_ipv6

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv6.conf.all.accept_ra" "0"
    _dropin_has "net.ipv6.conf.default.accept_ra" "0"
}

@test "harden_ipv6: an unprobeable host is treated as SLAAC, not as static" {
    # `ip` present but failing is "cannot determine", the same situation as
    # `ip` missing. Reading its failure as "no RA route" applied accept_ra=0
    # to exactly the hosts the guard exists to protect.
    _host_ipv6_unprobeable

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "accept_ra" "$VPSSEC_SYSCTL_CONF"
}

@test "harden_network: accept_ra is left alone on a SLAAC host" {
    # The regression: the guard used to live only in _kernel_fix_ipv6, so
    # the same parameter reached the wire unguarded through this fix id.
    _host_uses_ra
    _sysctl_seed "net.ipv6.conf.all.accept_ra" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "accept_ra" "$VPSSEC_SYSCTL_CONF"
}

@test "harden_network: accept_ra is applied on a statically configured host" {
    _host_static_ipv6
    _sysctl_seed "net.ipv6.conf.all.accept_ra" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv6.conf.all.accept_ra" "0"
}

# ==============================================================================
# IPv6 keys under all/default: only what reaches an interface, said honestly
# ==============================================================================

# An IPv6 stack in use, with every net.ipv6 setting the audit reads at $1.
_ipv6_in_use_at() {
    source "$(_vpssec_repo_root)/core/state.sh"
    state_init
    _kernel_ipv6_enabled() { return 0; }
    _kernel_ipv6_in_use() { return 0; }
    _kernel_ipv6_get_stats() { echo ""; }
    _kernel_ipv6_firewall_check() { echo "filtered"; }
    local key
    for key in accept_redirects accept_source_route accept_ra forwarding; do
        _sysctl_seed "net.ipv6.conf.all.$key" "$1"
    done
    _sysctl_seed "net.ipv6.conf.all.use_tempaddr" 2
}

@test "IPv6 keys that reach no interface, or do not exist, are neither read nor written" {
    # max_addresses, accept_ra_defrtr/pinfo/rtr_pref, autoconf and dad_transmits
    # were set under "all" only, which no interface reads; IPv6 has no send_redirects.
    _host_static_ipv6
    _ipv6_in_use_at 1

    _kernel_audit_network_params
    kernel_fix kernel.harden_network
    kernel_fix kernel.harden_ipv6

    local key
    for key in max_addresses accept_ra_defrtr accept_ra_pinfo accept_ra_rtr_pref \
               autoconf dad_transmits send_redirects; do
        _vpssec_refute grep -q "ipv6\.conf\.[a-z]*\.$key" "$VPSSEC_STUB_LOG"
        _vpssec_refute grep -q "ipv6\.conf\.[a-z]*\.$key" "$VPSSEC_SYSCTL_CONF"
    done
}

_emitted_field() {
    jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f] // ""' \
        "$VPSSEC_STATE/checks.json"
}

@test "the IPv6 and network results say existing interfaces such as eth0 are unchanged" {
    # all/default reach only interfaces created later, so neither a pass nor
    # the fix it suggests may read as covering eth0.
    _host_static_ipv6
    local lang
    for lang in en_US zh_CN; do
        i18n_load "$lang"
        _ipv6_in_use_at 0
        _sysctl_seed "net.ipv4.tcp_syncookies" 1
        _kernel_audit_ipv6
        _kernel_audit_network_params
        [[ "$(_emitted_field kernel.ipv6_secure desc)" == *eth0* ]]
        [[ "$(_emitted_field kernel.network_params_ok desc)" == *eth0* ]]

        _ipv6_in_use_at 1
        _sysctl_seed "net.ipv4.tcp_syncookies" 0
        _kernel_audit_ipv6
        _kernel_audit_network_params
        [[ "$(_emitted_field kernel.ipv6_insecure suggestion)" == *eth0* ]]
        [[ "$(_emitted_field kernel.network_params_high suggestion)" == *eth0* ]]
        [[ "$(_emitted_field kernel.network_params_medium suggestion)" == *eth0* ]]
    done
}

# ==============================================================================
# harden_network's host-role exceptions
# ==============================================================================

@test "harden_network: ip_forward is left enabled on a host that routes" {
    _host_static_ipv6
    _forwarding_daemon_active
    _sysctl_seed "net.ipv4.ip_forward" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "ip_forward" "$VPSSEC_SYSCTL_CONF"
}

@test "harden_network: ip_forward is disabled on a host that does not route" {
    _host_static_ipv6
    _sysctl_seed "net.ipv4.ip_forward" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv4.ip_forward" "0"
}

@test "harden_network: a param the ip_forward write resets is written back" {
    # The kernel resets per-interface settings to host defaults when
    # ip_forward changes; accept_redirects was fine before and 1 after.
    _host_static_ipv6
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    -w) printf '%s\n' "\${2#*=}" > "\$store/\${2%%=*}"
        [[ "\$2" == net.ipv4.ip_forward=* ]] && echo 1 > "\$store/net.ipv4.conf.all.accept_redirects" ;;
esac
exit 0
SH
    _sysctl_seed "net.ipv4.ip_forward" "1"
    _sysctl_seed "net.ipv4.conf.all.accept_redirects" "0"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    [ "$(cat "$sysctl_store/net.ipv4.conf.all.accept_redirects")" = "0" ]
    _dropin_has "net.ipv4.conf.all.accept_redirects" "0"
}

@test "harden_network: loose rp_filter is preserved on a forwarding host" {
    # rp_filter=2 is the correct setting on a router; forcing it back to
    # strict mode drops asymmetric-return traffic. The audit already makes
    # this exception, so the fix must not undo what the audit accepted.
    _host_static_ipv6
    _forwarding_daemon_active
    _sysctl_seed "net.ipv4.conf.all.rp_filter" "2"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "conf\.all\.rp_filter" "$VPSSEC_SYSCTL_CONF"
}

@test "harden_network: disabled rp_filter is hardened even on a forwarding host" {
    _host_static_ipv6
    _forwarding_daemon_active
    _sysctl_seed "net.ipv4.conf.all.rp_filter" "0"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv4.conf.all.rp_filter" "1"
}

# ==============================================================================
# The core-dump fix
# ==============================================================================

@test "core dump: the limits.conf entry is appended without losing the file" {
    printf '# /etc/security/limits.conf\n*  soft  nofile  1024\n# End of file\n' \
        > "$KERNEL_LIMITS_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    grep -qxF "*  soft  nofile  1024" "$KERNEL_LIMITS_CONF"
    grep -qxF "* hard core 0" "$KERNEL_LIMITS_CONF"
}

@test "core dump: the entry is not appended twice" {
    printf '# limits\n* hard core 0\n' > "$KERNEL_LIMITS_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ "$(grep -cxF "* hard core 0" "$KERNEL_LIMITS_CONF")" -eq 1 ]
}

@test "core dump: limits.conf is backed up before it is edited" {
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"
    _vpssec_begin_backup_session

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ -f "${VPSSEC_BACKUP_SESSION}${KERNEL_LIMITS_CONF}" ]
    _vpssec_refute grep -q "hard core 0" "${VPSSEC_BACKUP_SESSION}${KERNEL_LIMITS_CONF}"
}

@test "core dump: the systemd drop-in is written when only coredump.conf exists" {
    # Debian and Ubuntu ship /etc/systemd/coredump.conf and no coredump.conf.d,
    # so a fix that requires the directory writes nothing there while the audit,
    # which flags on either path, keeps reporting core dumps as unrestricted.
    printf '[Coredump]\n' > "$KERNEL_COREDUMP_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    grep -qxF "Storage=none" "$KERNEL_COREDUMP_DROPIN"
}

@test "core dump: the systemd drop-in is created as a rollback-removable file" {
    printf '[Coredump]\n' > "$KERNEL_COREDUMP_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"
    _vpssec_begin_backup_session

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    grep -qxF "$KERNEL_COREDUMP_DROPIN" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "core dump: no systemd drop-in on a host without systemd-coredump" {
    # Neither the main file nor the directory exists: the component is not
    # installed and the audit does not flag it. Writing config for it would
    # be litter.
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ ! -e "$KERNEL_COREDUMP_DROPIN" ]
}

@test "core dump: failure is reported when the runtime write is refused" {
    # A container with a read-only /proc/sys. suid_dumpable stays at 1, so
    # the next audit will still flag core dumps — the fix must say so
    # rather than printing a green line over it.
    _sysctl_seed "fs.suid_dumpable" "1"
    _sysctl_readonly

    run _kernel_fix_core_dump
    [ "$status" -eq 1 ]
}

@test "core dump: success is reported when every part took effect" {
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"
    printf '[Coredump]\n' > "$KERNEL_COREDUMP_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    run _kernel_check_core_dump
    [ -z "$output" ]
}

# ==============================================================================
# Thresholds: a stricter value than required is a pass, and is never lowered
# ==============================================================================

# Runtime value of one param in the stub, after whatever the fix wrote.
_runtime() { cat "$sysctl_store/$1"; }

@test "kernel params: stricter-than-required values pass and the fix leaves them" {
    _kernel_on ubuntu debian
    _sysctl_seed kernel.yama.ptrace_scope 3
    _sysctl_seed kernel.perf_event_paranoid 4
    _sysctl_seed kernel.unprivileged_bpf_disabled 2

    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"ok - kernel.yama.ptrace_scope"* ]]
    [[ "$output" == *"ok - kernel.perf_event_paranoid"* ]]
    [[ "$output" == *"ok - kernel.unprivileged_bpf_disabled"* ]]

    _kernel_fix_kernel_params
    [ "$(_runtime kernel.yama.ptrace_scope)" = 3 ]
    [ "$(_runtime kernel.perf_event_paranoid)" = 4 ]
    [ "$(_runtime kernel.unprivileged_bpf_disabled)" = 2 ]
}

@test "kernel params: a value below the minimum is raised to exactly the minimum" {
    _sysctl_seed kernel.yama.ptrace_scope 0
    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"bad medium kernel.yama.ptrace_scope >=1 0"* ]]

    _kernel_fix_kernel_params
    _dropin_has kernel.yama.ptrace_scope 1
    [ "$(_runtime kernel.yama.ptrace_scope)" = 1 ]
}

@test "kernel params: a value that is not a plain integer never meets a minimum" {
    # Bash arithmetic would read 0x10 as 16 — and evaluate any other text it was given.
    _sysctl_seed kernel.yama.ptrace_scope "0x10"
    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"bad medium kernel.yama.ptrace_scope >=1 0x10"* ]]
}

@test "perf_event_paranoid: on Ubuntu 3 is weak, because only 4 blocks unprivileged perf" {
    _kernel_on ubuntu debian
    _sysctl_seed kernel.perf_event_paranoid 3

    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"bad medium kernel.perf_event_paranoid >=4 3"* ]]
    _kernel_fix_kernel_params
    _dropin_has kernel.perf_event_paranoid 4
}

@test "perf_event_paranoid: Debian's default 3 already blocks it" {
    _kernel_on debian debian
    _sysctl_seed kernel.perf_event_paranoid 3
    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"ok - kernel.perf_event_paranoid"* ]]

    _sysctl_seed kernel.perf_event_paranoid 2
    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"bad medium kernel.perf_event_paranoid >=3 2"* ]]
}

@test "perf_event_paranoid: a mainline kernel's 2 is its strictest level" {
    _kernel_on rocky rhel
    _sysctl_seed kernel.perf_event_paranoid 2
    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"ok - kernel.perf_event_paranoid"* ]]
}

@test "unprivileged_bpf_disabled: the fix writes 2, not the value that locks until reboot" {
    _sysctl_seed kernel.unprivileged_bpf_disabled 0
    _kernel_fix_kernel_params
    _dropin_has kernel.unprivileged_bpf_disabled 2

    _sysctl_seed kernel.unprivileged_bpf_disabled 1
    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [[ "$output" == *"ok - kernel.unprivileged_bpf_disabled"* ]]
}

@test "tcp_timestamps: off is a deliberate choice, and only 2 is re-enabled to 1" {
    _sysctl_seed net.ipv4.tcp_timestamps 0
    run _kernel_param_scan "$KERNEL_NET_SCOPE"
    [[ "$output" == *"ok - net.ipv4.tcp_timestamps"* ]]

    _sysctl_seed net.ipv4.tcp_timestamps 2
    _kernel_fix_network_params
    _dropin_has net.ipv4.tcp_timestamps 1
}

# ==============================================================================
# Dispatch
# ==============================================================================

@test "kernel_fix: an unknown fix id fails instead of silently doing nothing" {
    run kernel_fix "kernel.not_a_real_fix"
    [ "$status" -eq 1 ]
}

# ---- the backup contract ---------------------------------------------

@test "sysctl drop-in: a backup that cannot be taken aborts the write" {
    _vpssec_begin_backup_session
    mkdir -p "$SYSCTL_D"
    printf '# existing\n' > "$VPSSEC_SYSCTL_CONF"
    _vpssec_stub cp 1

    run _kernel_write_sysctl "kernel.randomize_va_space" "2"
    [ "$status" -ne 0 ]
    [ "$(cat "$VPSSEC_SYSCTL_CONF")" = "# existing" ]
}
