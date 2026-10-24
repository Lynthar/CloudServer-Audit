#!/usr/bin/env bats
# Coverage for the kernel fixes that write sysctl drop-ins, the limits.d and
# systemd-coredump drop-ins. The RA/SLAAC guard on accept_ra=0 must hold on BOTH
# paths — harden_ipv6 and harden_network — or an IPv6-only VPS loses its route.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh
    # Not in a container unless a test says so: bats itself may run in one.
    detect_container() { return 1; }
    etc=$(_vpssec_fake_etc)
    _kernel_source
    mkdir -p "$etc/security" "$etc/systemd"
    DISTRO_UFW_DEFAULTS="$etc/default/ufw"

    export TMPDIR="$BATS_TEST_TMPDIR"
    sysctl_store="$BATS_TEST_TMPDIR/sysctl"
    mkdir -p "$sysctl_store"

    _sysctl_stub
    _no_forwarding_daemons
    # No link is systemd-networkd's unless a test says so, whatever the host runs.
    _vpssec_stub networkctl 1
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
    KERNEL_LIMITS_D="$etc/security/limits.d"
    KERNEL_LIMITS_DROPIN="$KERNEL_LIMITS_D/${KERNEL_LIMITS_DROPIN##*/}"
    KERNEL_COREDUMP_CONF="$etc/systemd/coredump.conf"
    KERNEL_COREDUMP_D="$etc/systemd/coredump.conf.d"
    KERNEL_COREDUMP_DROPIN="$KERNEL_COREDUMP_D/99-vpssec.conf"
    KERNEL_IPV4_CONF_DIR="$BATS_TEST_TMPDIR/ipv4-conf"
    KERNEL_IPV6_CONF_DIR="$BATS_TEST_TMPDIR/ipv6-conf"
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

# Runtime value of one param in the stub, after whatever the fix wrote.
_runtime() { cat "$sysctl_store/$1"; }

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
    [ "$status" -ne 0 ]
    [ -z "$output" ]
}

# ==============================================================================
# The RA/SLAAC guard — both paths that can apply accept_ra
# ==============================================================================

# default and eth0 with every IPv6 key the IPv6 check reads at its weak value.
_ipv6_all_weak() {
    _sysctl_seed net.ipv6.conf.default.accept_ra 1
    _sysctl_seed net.ipv6.conf.default.accept_redirects 1
    _sysctl_seed net.ipv6.conf.default.use_tempaddr 0
    _ipv6_iface eth0 accept_ra=1 accept_redirects=1 use_tempaddr=0 forwarding=0
}

@test "harden_ipv6: accept_ra is left alone on a SLAAC host, and the fix says so" {
    _messages_on
    _host_uses_ra
    _ipv6_all_weak

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "accept_ra" "$VPSSEC_SYSCTL_CONF"
    [ "$(_runtime net.ipv6.conf.eth0.accept_ra)" = 1 ]
    [[ "$output" == *"$(i18n 'kernel.ipv6_ra_skipped')"* ]]
}

@test "harden_ipv6: the always-safe parameters are still applied on a SLAAC host" {
    # Skipping the RA parameters must not turn into skipping the fix.
    _host_uses_ra
    _ipv6_all_weak

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv6.conf.default.accept_redirects" "0"
    _dropin_has "net.ipv6.conf.*.use_tempaddr" "2"
}

@test "harden_ipv6: accept_ra is applied on a statically configured host" {
    _host_static_ipv6
    _ipv6_all_weak

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv6.conf.default.accept_ra" "0"
    _dropin_has "net.ipv6.conf.*.accept_ra" "0"
}

@test "harden_ipv6: an unprobeable host is treated as SLAAC, not as static" {
    # `ip` present but failing is "cannot determine", the same situation as
    # `ip` missing. Reading its failure as "no RA route" applied accept_ra=0
    # to exactly the hosts the guard exists to protect.
    _host_ipv6_unprobeable
    _ipv6_all_weak

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "accept_ra" "$VPSSEC_SYSCTL_CONF"
}

# accept_ra belongs to the IPv6 check, not the network table. Listed there again,
# the scan's SLAAC guard must still keep harden_network off it.
_table_lists_accept_ra() {
    KERNEL_SECURITY_PARAMS+=("net.ipv6.conf.all.accept_ra:0:medium:IPv6 Router Advertisements")
}

@test "harden_network: an accept_ra the table lists is left alone on a SLAAC host" {
    # The regression: the guard used to live only in _kernel_fix_ipv6, so
    # the same parameter reached the wire unguarded through this fix id.
    _host_uses_ra
    _table_lists_accept_ra
    _sysctl_seed "net.ipv6.conf.all.accept_ra" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "accept_ra" "$VPSSEC_SYSCTL_CONF"
}

@test "harden_network: an accept_ra the table lists is applied on a static host" {
    _host_static_ipv6
    _table_lists_accept_ra
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

@test "an IPv6 redirect, RA or privacy setting is judged by the IPv6 check alone" {
    # Listed in the network table as well, one weak value failed two scored checks.
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 1
    _sysctl_seed "net.ipv6.conf.default.accept_redirects" 1
    _sysctl_seed "net.ipv6.conf.default.accept_ra" 1
    _sysctl_seed "net.ipv6.conf.default.use_tempaddr" 0
    _sysctl_seed "net.ipv4.tcp_syncookies" 0

    _kernel_audit_ipv6
    _kernel_audit_network_params
    [ -n "$(_emitted_field kernel.ipv6_insecure desc)" ]
    [ -n "$(_emitted_field kernel.network_params_high desc)" ]
    run jq -r '.[] | select(.id | startswith("kernel.network_params")) | .desc' \
        "$VPSSEC_STATE/checks.json"
    [ "$status" -eq 0 ]
    [[ "$output" == *"net.ipv4.tcp_syncookies=0"* ]]
    [[ "$output" != *accept_redirects* ]]
    [[ "$output" != *accept_ra* ]]
    [[ "$output" != *use_tempaddr* ]]
}

@test "an unused IPv6 with weak settings says which settings are weak" {
    # Its desc used to repeat the title word for word.
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 1
    _kernel_ipv6_in_use() { return 1; }
    _sysctl_seed "net.ipv6.conf.default.accept_redirects" 1
    _sysctl_seed "net.ipv6.conf.default.use_tempaddr" 0
    _kernel_audit_ipv6
    local desc
    desc=$(_emitted_field kernel.ipv6_unused_insecure desc)
    [[ "$desc" == *"$(i18n 'kernel.ipv6_issue_accept_redirects_enabled')"* ]]
    [[ "$desc" == *"$(i18n 'kernel.ipv6_issue_privacy_extensions_weak')"* ]]
}

# ==============================================================================
# IPv6 accept_ra / accept_redirects / use_tempaddr: each interface's own value
# ==============================================================================

# The kernel reads these per interface only (ipv6_accept_ra, rt6_do_redirect,
# manage_tempaddrs) and a write to "all" reaches none: default and all hardened.
_ipv6_defaults_hardened() {
    local scope
    for scope in all default; do
        _sysctl_seed "net.ipv6.conf.$scope.accept_ra" 0
        _sysctl_seed "net.ipv6.conf.$scope.accept_redirects" 0
        _sysctl_seed "net.ipv6.conf.$scope.use_tempaddr" 2
        _sysctl_seed "net.ipv6.conf.$scope.forwarding" 0
    done
}

# Interface $1 under the scanned conf directory, its keys given as key=value.
_ipv6_iface() {
    local name="$1" kv
    shift
    mkdir -p "$KERNEL_IPV6_CONF_DIR/$name"
    for kv in "$@"; do
        _sysctl_seed "net.ipv6.conf.$name.${kv%%=*}" "${kv#*=}"
    done
}

# systemd-networkd configures link $1 (networkctl list, systemd 249 to 257).
_networkd_configures() {
    _vpssec_stub networkctl 0 "  1 lo    loopback carrier  unmanaged
  2 $1 ether    routable configured"
}

@test "IPv6: an interface that takes redirects fails the check, with all and default hardened" {
    # A host up 315 days had ens18 at 1: all=0 never reached it.
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _ipv6_iface eth0 accept_ra=0 accept_redirects=1 use_tempaddr=2 forwarding=0
    _kernel_audit_ipv6
    [[ "$(_emitted_field kernel.ipv6_insecure desc)" == *"$(i18n 'kernel.ipv6_issue_accept_redirects_enabled')"*eth0* ]]
}

@test "IPv6: a forwarding interface takes no redirects, and RAs only at accept_ra=2" {
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _ipv6_iface eth0 accept_ra=1 accept_redirects=1 use_tempaddr=2 forwarding=1
    _kernel_audit_ipv6
    [ -n "$(_emitted_field kernel.ipv6_secure id)" ]

    _ipv6_in_use_at 0
    _ipv6_iface eth0 accept_ra=2
    _kernel_audit_ipv6
    [[ "$(_emitted_field kernel.ipv6_insecure desc)" == *"$(i18n 'kernel.ipv6_issue_accept_ra_enabled')"*eth0* ]]
}

@test "IPv6: loopback is not judged" {
    # Its accept_redirects is the kernel's 1 on every host.
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _ipv6_iface lo accept_ra=1 accept_redirects=1 use_tempaddr=-1 forwarding=0
    _kernel_audit_ipv6
    [ -n "$(_emitted_field kernel.ipv6_secure id)" ]
}

@test "IPv6: the default that new interfaces copy is judged as well" {
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _sysctl_seed net.ipv6.conf.default.use_tempaddr 0
    _ipv6_iface eth0 accept_ra=0 accept_redirects=0 use_tempaddr=2 forwarding=0
    _kernel_audit_ipv6
    [[ "$(_emitted_field kernel.ipv6_insecure desc)" == *"$(i18n 'kernel.ipv6_issue_privacy_extensions_weak')"*default* ]]
}

@test "IPv6: a link without privacy extensions (use_tempaddr -1) is no finding" {
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _ipv6_iface sit0 accept_ra=0 accept_redirects=0 use_tempaddr=-1 forwarding=0
    _kernel_audit_ipv6
    [ -n "$(_emitted_field kernel.ipv6_secure id)" ]
}

@test "IPv6: on a link systemd-networkd configures, RA and privacy are its own, listed unscored" {
    # networkd keeps the kernel's accept_ra at 0 and takes RAs itself, and writes
    # use_tempaddr from IPv6PrivacyExtensions=: no sysctl changes either there.
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _networkd_configures ens18
    _ipv6_iface ens18 accept_ra=0 accept_redirects=0 use_tempaddr=0 forwarding=0
    _kernel_audit_ipv6
    [ -n "$(_emitted_field kernel.ipv6_secure id)" ]
    [[ "$(_emitted_field kernel.ipv6_networkd_managed desc)" == *ens18* ]]
    [[ "$(_emitted_field kernel.ipv6_networkd_managed suggestion)" == *"accept-ra: false"* ]]
    source "$(_vpssec_repo_root)/core/security_levels.sh"
    [ "${CHECK_SCORE_CATEGORY[kernel.ipv6_networkd_managed]}" = info ]
}

@test "IPv6: a link networkd leaves alone is judged like any other" {
    i18n_load en_US
    _host_static_ipv6
    _ipv6_in_use_at 0
    _ipv6_defaults_hardened
    _networkd_configures ens18
    _ipv6_iface ens18 accept_ra=0 accept_redirects=0 use_tempaddr=2 forwarding=0
    _ipv6_iface eth1 accept_ra=0 accept_redirects=0 use_tempaddr=0 forwarding=0
    _kernel_audit_ipv6
    [[ "$(_emitted_field kernel.ipv6_insecure desc)" == *eth1* ]]
    [[ "$(_emitted_field kernel.ipv6_insecure desc)" != *ens18* ]]
}

@test "harden_ipv6: an interface's values are set now, and kept by one glob line each" {
    _host_static_ipv6
    _ipv6_defaults_hardened
    _ipv6_iface eth0 accept_ra=1 accept_redirects=1 use_tempaddr=0 forwarding=0

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    [ "$(_runtime net.ipv6.conf.eth0.accept_ra)" = 0 ]
    [ "$(_runtime net.ipv6.conf.eth0.accept_redirects)" = 0 ]
    [ "$(_runtime net.ipv6.conf.eth0.use_tempaddr)" = 2 ]
    _dropin_has "net.ipv6.conf.*.accept_ra" 0
    _dropin_has "net.ipv6.conf.*.accept_redirects" 0
    _dropin_has "net.ipv6.conf.*.use_tempaddr" 2
    _vpssec_refute grep -q 'ipv6\.conf\.eth0\.' "$VPSSEC_SYSCTL_CONF"
}

@test "harden_ipv6: an interface's old values are in the logged undo command" {
    _host_static_ipv6
    _ipv6_defaults_hardened
    _ipv6_iface eth0 accept_ra=0 accept_redirects=1 use_tempaddr=2 forwarding=0

    kernel_fix kernel.harden_ipv6 || true
    grep -q 'Undo for kernel.harden_ipv6: sysctl -w net.ipv6.conf.eth0.accept_redirects=1' \
        "$VPSSEC_LOGS/vpssec.log"
}

@test "harden_ipv6: networkd's RA and privacy are left to it, and the fix says where they live" {
    _messages_on
    _host_static_ipv6
    _ipv6_defaults_hardened
    _networkd_configures ens18
    _ipv6_iface ens18 accept_ra=0 accept_redirects=1 use_tempaddr=0 forwarding=0

    run _kernel_fix_ipv6
    [ "$status" -eq 0 ]
    [ "$(_runtime net.ipv6.conf.ens18.use_tempaddr)" = 0 ]
    [ "$(_runtime net.ipv6.conf.ens18.accept_redirects)" = 0 ]
    [[ "$output" == *"$(i18n 'kernel.ipv6_networkd_skipped' "links=ens18")"* ]]
}

@test "in a container the host's fs.suid_dumpable is listed with the host's parameters, unscored" {
    # The core-dump check leaves it to the host, and nothing else named it.
    source "$(_vpssec_repo_root)/core/state.sh"
    state_init
    i18n_load en_US
    detect_container() { echo docker; return 0; }
    _sysctl_seed fs.suid_dumpable 2
    _kernel_audit_kernel_params
    [[ "$(_emitted_field kernel.kernel_params_host_managed desc)" == *"fs.suid_dumpable=2"* ]]
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

@test "harden_network: sysctl's echo of each write stays out of the guide's terminal" {
    # sysctl -w prints "key = value" for every write: thirteen lines on a stock host.
    _messages_on
    _host_static_ipv6
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    -w) printf '%s\n' "\${2#*=}" > "\$store/\${2%%=*}"; echo "\${2%%=*} = \${2#*=}" ;;
esac
exit 0
SH
    _sysctl_seed net.ipv4.tcp_syncookies 0

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    [[ "$output" != *"net.ipv4.tcp_syncookies = 1"* ]]
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

@test "harden_network: disabled rp_filter is raised to loose, not strict, on a forwarding host" {
    # 0 permits spoofed sources; 1 would drop the asymmetric-return traffic
    # the forwarding is for, the very reason 2 is accepted there.
    _host_static_ipv6
    _forwarding_daemon_active
    _sysctl_seed "net.ipv4.conf.all.rp_filter" "0"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _dropin_has "net.ipv4.conf.all.rp_filter" "2"
    [ "$(_runtime net.ipv4.conf.all.rp_filter)" = 2 ]
}

@test "harden_network: strict rp_filter already chosen on a forwarding host is kept" {
    _host_static_ipv6
    _forwarding_daemon_active
    _sysctl_seed "net.ipv4.conf.all.rp_filter" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q "conf\.all\.rp_filter" "$VPSSEC_SYSCTL_CONF"
}

# ==============================================================================
# Interfaces: keys the kernel combines with conf.all by OR, or by the larger
# ==============================================================================

# Interface $1 exists, with its own keys as given: key=value ...
_iface() {
    local name="$1" kv
    shift
    mkdir -p "$KERNEL_IPV4_CONF_DIR/$name"
    for kv in "$@"; do
        _sysctl_seed "net.ipv4.conf.$name.${kv%%=*}" "${kv#*=}"
    done
}

# The network-parameter audit, its checks recorded for _emitted_field.
_audit_network() {
    source "$(_vpssec_repo_root)/core/state.sh"
    state_init
    _kernel_audit_network_params >/dev/null
}

@test "interfaces: an own accept_redirects=1 is flagged by name though all and default read 0" {
    # The kernel ORs it with conf.all where the interface does not forward, and
    # an interface made before the default was set keeps its old value.
    i18n_load en_US
    _host_static_ipv6
    _sysctl_seed net.ipv4.conf.all.accept_redirects 0
    _sysctl_seed net.ipv4.conf.default.accept_redirects 0
    _iface ens18 accept_redirects=1 forwarding=0

    _audit_network
    [[ "$(_emitted_field kernel.network_params_medium desc)" == *"net.ipv4.conf.ens18.accept_redirects=1"* ]]
}

@test "interfaces: accept_redirects on an interface that forwards is left to conf.all" {
    # There the kernel ANDs the two, so conf.all=0 already turns it off.
    _host_static_ipv6
    _sysctl_seed net.ipv4.conf.all.accept_redirects 0
    _iface docker0 accept_redirects=1 forwarding=1

    _kernel_network_params_ok
}

@test "interfaces: rp_filter is flagged where the interface's own value is the one in force" {
    # The kernel takes the larger of the two: systemd's 50-default.conf leaves
    # every interface at 2 (loose) whatever conf.all says; a 0 there changes nothing.
    i18n_load en_US
    _host_static_ipv6
    _sysctl_seed net.ipv4.conf.all.rp_filter 1
    _iface ens18 rp_filter=2
    _iface ens19 rp_filter=0

    _audit_network
    local desc
    desc=$(_emitted_field kernel.network_params_medium desc)
    [[ "$desc" == *"net.ipv4.conf.ens18.rp_filter=2"* ]]
    [[ "$desc" != *ens19* ]]

    # Stock Ubuntu: 2 on both. The interface's own 2 is in force there too.
    _sysctl_seed net.ipv4.conf.all.rp_filter 2
    _audit_network
    [[ "$(_emitted_field kernel.network_params_medium desc)" == *"net.ipv4.conf.ens18.rp_filter=2"* ]]
}

@test "interfaces: log_martians, the ANDed keys and lo are judged on conf.all alone" {
    # log_martians is ORed but wanted on, so all=1 covers every interface;
    # accept_source_route, bootp_relay and mc_forwarding are ANDed.
    i18n_load en_US
    _host_static_ipv6
    _sysctl_seed net.ipv4.conf.all.log_martians 1
    _sysctl_seed net.ipv4.conf.all.accept_source_route 0
    _sysctl_seed net.ipv4.conf.all.send_redirects 0
    _iface ens18 log_martians=0 accept_source_route=1 bootp_relay=1 mc_forwarding=1
    _iface lo send_redirects=1

    _audit_network
    [ "$(_emitted_field kernel.network_params_ok status)" = passed ]
}

@test "harden_network: an interface is set at runtime and kept by one glob, not by its name" {
    # udev applies a glob to each interface as it appears, whenever that is;
    # a name can change, and two interfaces need the same single line.
    _host_static_ipv6
    _sysctl_seed net.ipv4.conf.all.send_redirects 0
    _sysctl_seed net.ipv4.conf.all.rp_filter 1
    _iface ens18 send_redirects=1 rp_filter=2
    _iface ens19 send_redirects=1

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    [ "$(_runtime net.ipv4.conf.ens18.send_redirects)" = 0 ]
    [ "$(_runtime net.ipv4.conf.ens19.send_redirects)" = 0 ]
    [ "$(_runtime net.ipv4.conf.ens18.rp_filter)" = 1 ]
    [ "$(grep -cxF 'net.ipv4.conf.*.send_redirects = 0' "$VPSSEC_SYSCTL_CONF")" = 1 ]
    _dropin_has 'net.ipv4.conf.*.rp_filter' 1
    _vpssec_refute grep -q ens1 "$VPSSEC_SYSCTL_CONF"
    _kernel_network_params_ok
}

@test "undo: harden_network puts an interface's own value back" {
    _host_static_ipv6
    _sysctl_seed net.ipv4.conf.all.secure_redirects 0
    _iface ens18 secure_redirects=1

    _kernel_fix_network_params
    [ "$(_runtime net.ipv4.conf.ens18.secure_redirects)" = 0 ]

    _run_logged_undo kernel.harden_network
    [ "$(_runtime net.ipv4.conf.ens18.secure_redirects)" = 1 ]
}

# ==============================================================================
# ufw's sysctl file, which ufw applies after sysctl.d on every start and reload
# ==============================================================================

# ufw's defaults name file $1 as its IPT_SYSCTL, quoted as a shell file may
# quote it; the rest are that file's lines.
_ufw_sysctl() {
    local f="$1"
    shift
    mkdir -p "${DISTRO_UFW_DEFAULTS%/*}" "${f%/*}"
    printf 'IPV6=yes\nIPT_SYSCTL="%s"\n' "$f" > "$DISTRO_UFW_DEFAULTS"
    printf '%s\n' "$@" > "$f"
}

# The value `sysctl -p` on file $1 leaves key $2 at: the last line setting it,
# in either of the two forms sysctl reads.
_sysctl_p_value() {
    local line out=""
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*([^#=[:space:]]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        [[ "${BASH_REMATCH[1]//\//.}" == "$2" ]] && out="${BASH_REMATCH[2]}"
    done < "$1"
    printf '%s\n' "$out"
}

@test "harden_network: a weaker key in ufw's sysctl file is overridden there too" {
    # Otherwise the next `ufw reload`, or `ufw enable` later in the same plan,
    # puts the old value back. A key the file already agrees with is left alone.
    _host_static_ipv6
    local ufw_conf="$etc/ufw/sysctl.conf"
    _ufw_sysctl "$ufw_conf" \
        'net/ipv4/conf/all/accept_redirects=0' \
        'net/ipv4/conf/all/log_martians=0' \
        'net/ipv4/conf/default/log_martians=0'
    _sysctl_seed net.ipv4.conf.all.accept_redirects 1
    _sysctl_seed net.ipv4.conf.all.log_martians 0
    _sysctl_seed net.ipv4.conf.default.log_martians 0

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    [ "$(_sysctl_p_value "$ufw_conf" net.ipv4.conf.all.log_martians)" = 1 ]
    [ "$(_sysctl_p_value "$ufw_conf" net.ipv4.conf.default.log_martians)" = 1 ]
    [ "$(grep -c accept_redirects "$ufw_conf")" = 1 ]
    [ "$(head -1 "$ufw_conf")" = 'net/ipv4/conf/all/accept_redirects=0' ]
    _dropin_has net.ipv4.conf.all.log_martians 1
}

@test "harden_network: ufw's sysctl file is backed up before it changes, untouched when it agrees" {
    _host_static_ipv6
    local ufw_conf="$etc/ufw/sysctl.conf"
    _ufw_sysctl "$ufw_conf" 'net/ipv4/conf/all/log_martians=1'
    _sysctl_seed net.ipv4.conf.all.log_martians 0
    _vpssec_begin_backup_session

    _kernel_fix_network_params
    [ "$(cat "$ufw_conf")" = 'net/ipv4/conf/all/log_martians=1' ]
    [ ! -e "${VPSSEC_BACKUP_SESSION}${ufw_conf}" ]

    printf 'net/ipv4/conf/all/log_martians=0\n' > "$ufw_conf"
    _sysctl_seed net.ipv4.conf.all.log_martians 0
    _kernel_fix_network_params
    [ "$(cat "${VPSSEC_BACKUP_SESSION}${ufw_conf}")" = 'net/ipv4/conf/all/log_martians=0' ]
}

# ==============================================================================
# The core-dump fix
# ==============================================================================

@test "core dump: the hard limit goes into limits.d, limits.conf is not touched" {
    printf '# /etc/security/limits.conf\n*  soft  nofile  1024\n# End of file\n' \
        > "$KERNEL_LIMITS_CONF"
    local before
    before=$(cat "$KERNEL_LIMITS_CONF")
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ "$(cat "$KERNEL_LIMITS_CONF")" = "$before" ]
    grep -qxF "* hard core 0" "$KERNEL_LIMITS_DROPIN"
}

@test "core dump: a vendor limits.d file lifting the limit is overridden" {
    # Debian 13 ships this file (systemd package): any limit set in
    # limits.conf loses to it.
    mkdir -p "$KERNEL_LIMITS_D"
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"
    printf '*\tsoft\tcore\t0\n*\thard\tcore\tinfinity\n' \
        > "$KERNEL_LIMITS_D/10-coredump-debian.conf"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    run _kernel_check_core_dump
    [ -z "$output" ]
}

@test "core dump: a host with limits.d and no limits.conf gets the limit too" {
    # The audit flags either path, so the fix must write on either.
    mkdir -p "$KERNEL_LIMITS_D"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    grep -qxF "* hard core 0" "$KERNEL_LIMITS_DROPIN"
}

@test "core dump: no limits drop-in when the hard limit is already 0" {
    printf '# limits\n* hard core 0\n' > "$KERNEL_LIMITS_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ ! -e "$KERNEL_LIMITS_DROPIN" ]
}

@test "core dump: the limits drop-in is created as a rollback-removable file" {
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"
    _sysctl_seed "fs.suid_dumpable" "1"
    _vpssec_begin_backup_session

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    grep -qxF "$KERNEL_LIMITS_DROPIN" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
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

# ==============================================================================
# One check per key
# ==============================================================================

@test "fs.suid_dumpable is judged by the core-dump check alone" {
    # In the kernel-param table as well, Ubuntu's apport value (2) failed two
    # scored checks for one setting.
    _sysctl_seed fs.suid_dumpable 2

    run _kernel_param_scan "$KERNEL_SYS_SCOPE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"kernel.dmesg_restrict"* ]]
    [[ "$output" != *"suid_dumpable"* ]]
    run _kernel_check_core_dump
    [[ "$output" == *"suid_dumpable=2"* ]]
}

# ==============================================================================
# Who needs forwarding
# ==============================================================================

# `ip` answering only for links of type $1, with one such interface.
_host_has_link_type() {
    _vpssec_stub_script ip <<SH
[[ "\$*" == *"link show type $1"* ]] && echo "if0  UP  02:00:00:00:00:01"
exit 0
SH
}

@test "forwarding: an interface that forwarding serves counts, with no unit running" {
    # snap LXD and Docker, podman without a unit, CNI plugins and tun/tap VPNs
    # have no unit the list names; ip_forward=0 written there cuts them off.
    local type
    for type in bridge vxlan wireguard tun; do
        _host_has_link_type "$type"
        _kernel_ip_forward_needed || { echo "not needed with a $type link" >&2; return 1; }
    done
}

@test "forwarding: no such interface and no such unit means no forwarding role" {
    # A veth alone is no role either: inside a container eth0 is one.
    local type
    for type in dummy veth; do
        _host_has_link_type "$type"
        _vpssec_refute _kernel_ip_forward_needed
    done
}

@test "forwarding: a strongSwan gateway counts" {
    _host_has_link_type dummy
    _vpssec_stub_script systemctl <<'SH'
[[ "$*" == *"is-active"*strongswan-starter* ]] && exit 0
exit 1
SH
    _kernel_ip_forward_needed
}

@test "harden_network: ip_forward is left enabled on a host with a bridge and no unit" {
    _host_has_link_type bridge
    _sysctl_seed "net.ipv4.ip_forward" "1"

    run _kernel_fix_network_params
    [ "$status" -eq 0 ]
    [ "$(_runtime net.ipv4.ip_forward)" = 1 ]
    _vpssec_refute grep -q "ip_forward" "$VPSSEC_SYSCTL_CONF"
}

# ==============================================================================
# Core-dump limits as pam_limits reads them
# ==============================================================================

# fs.suid_dumpable restricted and no systemd-coredump, so only the limits decide.
_limits_only() { _sysctl_seed fs.suid_dumpable 0; mkdir -p "$KERNEL_LIMITS_D"; }

@test "core dump: a hard core 0 in limits.d is honoured" {
    # ansible-lockdown's CIS role writes limits.d/99_zero_core.conf.
    _limits_only
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"
    printf '*  hard  core  0\n' > "$KERNEL_LIMITS_D/99_zero_core.conf"

    run _kernel_check_core_dump
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "core dump: a soft core 0 alone caps nothing" {
    # Any process may raise its soft limit up to the hard one.
    _limits_only
    printf '* soft core 0\n' > "$KERNEL_LIMITS_CONF"

    run _kernel_check_core_dump
    [ "$output" = "no_core_limit" ]
}

@test "core dump: a limits.d file read later lifts the limit again" {
    _limits_only
    printf '* hard core 0\n' > "$KERNEL_LIMITS_CONF"
    printf '* hard core unlimited\n' > "$KERNEL_LIMITS_D/50-dev.conf"

    run _kernel_check_core_dump
    [ "$output" = "no_core_limit" ]

    printf '* - core 0\n' > "$KERNEL_LIMITS_D/90-cis.conf"
    run _kernel_check_core_dump
    [ -z "$output" ]
}

@test "core dump: the fix leaves limits.conf alone when limits.d already caps it" {
    _limits_only
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"
    printf '* hard core 0\n' > "$KERNEL_LIMITS_D/99_zero_core.conf"

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ "$(cat "$KERNEL_LIMITS_CONF")" = "# limits" ]
}

# ==============================================================================
# Runtime and persistence fail apart, and say which
# ==============================================================================

_messages_on() { i18n_load en_US; export VPSSEC_QUIET_SCAN=0; }

@test "harden_kernel: a refused runtime write is reported as refused, not unpersisted" {
    # A read-only /proc/sys changed nothing and wrote nothing; "failed to
    # persist ... would not survive a reboot" says the opposite.
    _messages_on
    _sysctl_seed kernel.dmesg_restrict 0
    _sysctl_readonly

    run _kernel_fix_kernel_params
    [ "$status" -eq 1 ]
    [[ "$output" == *"kernel refused 1 runtime sysctl write"* ]]
    [[ "$output" != *"Failed to persist"* ]]
}

@test "harden_ipv6: a refused write fails the fix instead of shrinking its count" {
    _messages_on
    _host_static_ipv6
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    -w) [[ "\$2" == *accept_redirects* ]] && exit 1
        printf '%s\n' "\${2#*=}" > "\$store/\${2%%=*}" ;;
esac
exit 0
SH

    _sysctl_seed net.ipv6.conf.default.accept_redirects 1
    _ipv6_iface eth0 accept_redirects=1 forwarding=0

    run _kernel_fix_ipv6
    [ "$status" -eq 1 ]
    [[ "$output" == *"kernel refused 2 runtime sysctl write"* ]]
    [[ "$output" != *"IPv6 parameters hardened"* ]]
}

@test "harden_network: a drop-in that cannot be written is reported as unpersisted" {
    _messages_on
    _host_static_ipv6
    _sysctl_seed net.ipv4.tcp_syncookies 0
    _kernel_write_sysctl() { return 1; }

    run _kernel_fix_network_params
    [ "$status" -eq 1 ]
    [[ "$output" == *"Failed to persist 1 sysctl value"* ]]
    [[ "$output" != *"refused"* ]]
    [ "$(_runtime net.ipv4.tcp_syncookies)" = 1 ]
}

# ==============================================================================
# The drop-in is never replayed
# ==============================================================================

# A sysctl whose -p applies every key = value of the file it is given.
_sysctl_replaying() {
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    -w) printf '%s\n' "\${2#*=}" > "\$store/\${2%%=*}" ;;
    -p) sed -nE 's/^([^#= ]+) *= *(.*)$/\1 \2/p' "\$2" | while read -r k v; do
            printf '%s\n' "\$v" > "\$store/\$k"
        done ;;
esac
exit 0
SH
}

@test "a kernel fix re-applies no key an earlier session left in the drop-in" {
    # Written before Docker was installed, ip_forward = 0 now cuts container
    # networking off the moment it is replayed — by even the SAFE enable_aslr.
    _sysctl_replaying
    mkdir -p "$SYSCTL_D"
    printf 'net.ipv4.ip_forward = 0\n' > "$VPSSEC_SYSCTL_CONF"
    _sysctl_seed net.ipv4.ip_forward 1
    _sysctl_seed kernel.randomize_va_space 0
    _sysctl_seed fs.suid_dumpable 2
    _sysctl_seed kernel.dmesg_restrict 0

    local fix
    for fix in enable_aslr disable_core_dump harden_kernel harden_ipv6; do
        _host_static_ipv6
        run kernel_fix "kernel.$fix"
        [ "$(_runtime net.ipv4.ip_forward)" = 1 ] || { echo "$fix replayed it" >&2; return 1; }
    done
    [ "$(_runtime kernel.randomize_va_space)" = 2 ]
}

# ==============================================================================
# The undo command: rollback restores the drop-in, not the runtime values
# ==============================================================================

# The undo command fix $1 logged, run against the stub.
_run_logged_undo() {
    local cmd
    cmd=$(sed -n "s/^.*Undo for $1: //p" "$VPSSEC_LOGS/vpssec.log" | tail -1)
    [ -n "$cmd" ] || { echo "no undo logged for $1" >&2; return 1; }
    bash -c "$cmd"
}

@test "undo: harden_network puts back the values from before it, ip_forward first" {
    # The second pass rewrites accept_redirects after the ip_forward write
    # reset it, so the value to restore is the one read before either pass.
    _host_static_ipv6
    _vpssec_stub_script sysctl <<SH
store="$sysctl_store"
case "\$1" in
    -n) cat "\$store/\$2" 2>/dev/null ;;
    -w) for kv in "\${@:2}"; do
            printf '%s\n' "\${kv#*=}" > "\$store/\${kv%%=*}"
            [[ "\$kv" == net.ipv4.ip_forward=* ]] && echo 1 > "\$store/net.ipv4.conf.all.accept_redirects"
        done ;;
esac
exit 0
SH
    _sysctl_seed net.ipv4.ip_forward 1
    _sysctl_seed net.ipv4.conf.all.accept_redirects 0
    _sysctl_seed net.ipv4.tcp_syncookies 0

    _kernel_fix_network_params
    [ "$(_runtime net.ipv4.ip_forward)" = 0 ]
    grep -q 'Undo for kernel.harden_network: sysctl -w net.ipv4.ip_forward=1 ' "$VPSSEC_LOGS/vpssec.log"

    _run_logged_undo kernel.harden_network
    [ "$(_runtime net.ipv4.ip_forward)" = 1 ]
    [ "$(_runtime net.ipv4.conf.all.accept_redirects)" = 0 ]
    [ "$(_runtime net.ipv4.tcp_syncookies)" = 0 ]
}

@test "undo: every other kernel fix logs the command that restores its values" {
    _host_static_ipv6
    local fix param before
    for fix in "enable_aslr kernel.randomize_va_space 1" \
               "harden_kernel kernel.kptr_restrict 0" \
               "harden_ipv6 net.ipv6.conf.default.accept_redirects 1" \
               "disable_core_dump fs.suid_dumpable 2"; do
        read -r fix param before <<<"$fix"
        _sysctl_seed "$param" "$before"
        kernel_fix "kernel.$fix" || true
        [ "$(_runtime "$param")" != "$before" ]
        _run_logged_undo "kernel.$fix"
        [ "$(_runtime "$param")" = "$before" ] || { echo "$fix: $param not restored" >&2; return 1; }
    done
}

@test "undo: a fix that changed no runtime value logs no command" {
    _sysctl_seed kernel.randomize_va_space 2
    _kernel_fix_aslr
    _vpssec_refute grep -q 'Undo for kernel.enable_aslr' "$VPSSEC_LOGS/vpssec.log"
}

# ==============================================================================
# Inside a container the kernel is the host's
# ==============================================================================

_in_container() { detect_container() { echo lxc; }; }

@test "container: weak kernel parameters are listed as the host's, scored nowhere, fixed by nothing" {
    i18n_load en_US
    source "$(_vpssec_repo_root)/core/state.sh"
    state_init
    _in_container
    _sysctl_seed kernel.kptr_restrict 1
    _sysctl_seed kernel.dmesg_restrict 1

    _kernel_audit_kernel_params
    [ -z "$(_emitted_field kernel.kernel_params_weak desc)" ]
    [ -z "$(_emitted_field kernel.kernel_params_ok desc)" ]
    [[ "$(_emitted_field kernel.kernel_params_host_managed desc)" == *"kernel.kptr_restrict=1"* ]]
    [ "$(_emitted_field kernel.kernel_params_host_managed fix_id)" = "" ]
    source "$(_vpssec_repo_root)/core/security_levels.sh"
    [ "${CHECK_SCORE_CATEGORY[kernel.kernel_params_host_managed]}" = "info" ]
}

# The checks a container audit emitted, as "id status fix_id".
_container_checks() {
    jq -r '.[] | "\(.id) \(.status) \(.fix_id)"' "$VPSSEC_STATE/checks.json"
}

@test "container: kernel parameters that all meet the mark are the host's too, scored neither way" {
    i18n_load en_US
    source "$(_vpssec_repo_root)/core/state.sh"
    state_init
    _in_container
    _sysctl_seed kernel.kptr_restrict 2

    _kernel_audit_kernel_params
    run _container_checks
    [ "$output" = "kernel.kernel_params_host_managed passed " ]
    [[ "$(_emitted_field kernel.kernel_params_host_managed desc)" == "1 parameters checked."* ]]
}

@test "container: ASLR is the host's, reported either way, scored neither way, fixed by nothing" {
    # sysctl -w randomize_va_space fails in an unprivileged container and
    # reaches the host from a privileged one; enable_aslr can only fail or overreach.
    i18n_load en_US
    source "$(_vpssec_repo_root)/core/state.sh"
    source "$(_vpssec_repo_root)/core/security_levels.sh"
    state_init
    _in_container

    _sysctl_seed kernel.randomize_va_space 2
    _kernel_audit_aslr
    _sysctl_seed kernel.randomize_va_space 0
    _kernel_audit_aslr
    rm "$sysctl_store/kernel.randomize_va_space"
    _kernel_audit_aslr

    run _container_checks
    [ "$output" = "kernel.aslr_host_managed passed 
kernel.aslr_host_managed failed 
kernel.aslr_unknown failed " ]
    [[ "$(_emitted_field kernel.aslr_host_managed desc)" == *"randomize_va_space=0"* ]]
    [ "${CHECK_SCORE_CATEGORY[kernel.aslr_host_managed]}" = "info" ]
}

@test "container: core dumps are judged and fixed without the host's suid_dumpable" {
    _in_container
    _sysctl_seed fs.suid_dumpable 2
    printf '# limits\n' > "$KERNEL_LIMITS_CONF"

    run _kernel_check_core_dump
    [ "$output" = "no_core_limit" ]

    run _kernel_fix_core_dump
    [ "$status" -eq 0 ]
    [ "$(_runtime fs.suid_dumpable)" = 2 ]
    _vpssec_refute grep -q "suid_dumpable" "$VPSSEC_SYSCTL_CONF"
}
