#!/usr/bin/env bats
# kernel.boot_params_*: does a hardened runtime value survive a reboot? The
# boot value is what systemd-sysctl makes of the sysctl.d files, read here from
# a fake tree laid out the way the real directories are.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/distro.sh
    i18n_load en_US
    etc=$(_vpssec_fake_etc)
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    SYSCTL_CONF="$etc/sysctl.conf"
    SYSCTL_D="$etc/sysctl.d"
    VPSSEC_SYSCTL_CONF="$SYSCTL_D/99-vpssec-hardening.conf"
    run_d="$BATS_TEST_TMPDIR/run/sysctl.d"
    local_d="$BATS_TEST_TMPDIR/usr/local/lib/sysctl.d"
    lib_d="$BATS_TEST_TMPDIR/usr/lib/sysctl.d"
    KERNEL_SYSCTL_BOOT_DIRS=("$run_d" "$local_d" "$lib_d")
    KERNEL_IPV4_CONF_DIR="$BATS_TEST_TMPDIR/ipv4-conf"
    DISTRO_UFW_DEFAULTS="$etc/default/ufw"
    mkdir -p "$SYSCTL_D" "$run_d" "$local_d" "$lib_d"

    # Data, not logic: the real scan and comparison run over this table.
    KERNEL_SECURITY_PARAMS=(
        "kernel.dmesg_restrict:1:medium:Restrict dmesg access"
        "kernel.yama.ptrace_scope:>=1:medium:Restrict ptrace"
        "kernel.unprivileged_bpf_disabled:2|1:medium:Disable unprivileged BPF"
        "net.ipv4.conf.all.rp_filter:1:medium:Reverse path filtering"
    )
    sysctl_store="$BATS_TEST_TMPDIR/sysctl"
    mkdir -p "$sysctl_store"
    _vpssec_stub_script sysctl <<SH
case "\$1" in
    -n) cat "$sysctl_store/\$2" 2>/dev/null ;;
    -w) printf '%s\n' "\${2#*=}" > "$sysctl_store/\${2%%=*}" ;;
esac
exit 0
SH
    _systemd_version 257
    _vpssec_stub ip 0
    # Every parameter passes at runtime unless a test says otherwise.
    _runtime kernel.dmesg_restrict 1
    _runtime kernel.yama.ptrace_scope 1
    _runtime kernel.unprivileged_bpf_disabled 2
    _runtime net.ipv4.conf.all.rp_filter 1
    _runtime kernel.randomize_va_space 2
}

_runtime() { printf '%s\n' "$2" > "$sysctl_store/$1"; }

# A systemctl that reports systemd version $1 and no active units.
_systemd_version() {
    _vpssec_stub_script systemctl <<SH
[[ "\$1" == --version ]] && { echo "systemd $1 (test)"; echo "+PAM"; exit 0; }
exit 1
SH
}

# Write file $1 with the remaining arguments as its lines.
_conf() {
    local f="$1"
    shift
    mkdir -p "${f%/*}"
    printf '%s\n' "$@" > "$f"
}

_status() {
    [[ -e "$VPSSEC_STATE/checks.json" ]] || return 0
    jq -r --arg id "$1" '.[] | select(.id == $id) | .status' "$VPSSEC_STATE/checks.json"
}

_desc() {
    jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

_audit() { _kernel_audit_boot_params >/dev/null; }

@test "a later file setting a weaker value is reported with its file and line" {
    _conf "$lib_d/10-distro.conf" "kernel.dmesg_restrict = 1"
    _conf "$SYSCTL_D/60-local.conf" "# tuning" "kernel.dmesg_restrict = 0"

    _audit

    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    [ -z "$(_status kernel.boot_params_ok)" ]
    _desc kernel.boot_params_revert | grep -qF \
        "kernel.dmesg_restrict is set to 0 at boot by $SYSCTL_D/60-local.conf:2"
}

@test "files apply in name order across directories, the last setting winning" {
    _conf "$SYSCTL_D/10-early.conf" "kernel.dmesg_restrict = 0"
    _conf "$lib_d/90-late.conf" "kernel.dmesg_restrict = 1"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    [ -z "$(_status kernel.boot_params_revert)" ]
}

@test "a name in /etc hides it in /usr/lib, /run hides /usr/local/lib, /dev/null masks" {
    _conf "$lib_d/50-hidden.conf" "kernel.dmesg_restrict = 0"
    _conf "$SYSCTL_D/50-hidden.conf" "kernel.dmesg_restrict = 1"
    _conf "$local_d/51-hidden.conf" "kernel.yama.ptrace_scope = 0"
    _conf "$run_d/51-hidden.conf" "kernel.yama.ptrace_scope = 2"
    _conf "$lib_d/52-masked.conf" "kernel.unprivileged_bpf_disabled = 0"
    ln -s /dev/null "$SYSCTL_D/52-masked.conf"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    # The masked file set nothing, so bpf is not set at boot at all.
    run _desc kernel.boot_params_ok
    [[ "$output" == *"is not judged:"*kernel.unprivileged_bpf_disabled* ]]
    [[ "$output" != *"not judged:"*ptrace_scope* ]]
}

@test "an explicit key beats a later glob, and a later glob beats an earlier one" {
    _conf "$lib_d/10-explicit.conf" "net.ipv4.conf.all.rp_filter = 1"
    _conf "$lib_d/90-glob.conf" "net.ipv4.conf.*.rp_filter = 2"

    _audit
    [ "$(_status kernel.boot_params_ok)" = "passed" ]

    rm "$lib_d/10-explicit.conf"
    _conf "$lib_d/10-glob.conf" "net.ipv4.conf.*.rp_filter = 1"
    rm -f "$VPSSEC_STATE/checks.json"
    _audit
    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    _desc kernel.boot_params_revert | grep -qF \
        "net.ipv4.conf.all.rp_filter is set to 2 at boot by $lib_d/90-glob.conf:1"
}

@test "-key with no = keeps a glob off that key" {
    _conf "$lib_d/50-default.conf" \
        "net.ipv4.conf.*.rp_filter = 2" "-net.ipv4.conf.all.rp_filter"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    _desc kernel.boot_params_ok | grep -qF "net.ipv4.conf.all.rp_filter"
}

@test "a glob * stops at a key separator, as glob(3) does on /proc/sys" {
    _conf "$lib_d/90-glob.conf" "net.ipv4.*.rp_filter = 2" "kernel/*_restrict = 0"

    _audit

    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    run _desc kernel.boot_params_revert
    [[ "$output" == *"kernel.dmesg_restrict is set to 0"* ]]
    [[ "$output" != *"rp_filter is set"* ]]
}

@test "systemd before 245 does not expand globs, so a glob sets nothing" {
    _systemd_version 239
    _conf "$lib_d/90-glob.conf" "net.ipv4.conf.*.rp_filter = 2"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    _desc kernel.boot_params_ok | grep -qF "net.ipv4.conf.all.rp_filter"
}

@test "boot values are judged as runtime ones: >=N floors and |-sets" {
    _conf "$lib_d/10-strict.conf" \
        "kernel.yama.ptrace_scope = 3" "kernel.unprivileged_bpf_disabled = 1"

    _audit
    [ "$(_status kernel.boot_params_ok)" = "passed" ]

    _conf "$lib_d/20-weak.conf" "kernel.unprivileged_bpf_disabled = 0"
    rm -f "$VPSSEC_STATE/checks.json"
    _audit
    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    _desc kernel.boot_params_revert | grep -qF "kernel.unprivileged_bpf_disabled is set to 0"
    run _desc kernel.boot_params_revert
    [ "$status" -eq 0 ]
    [[ "$output" != *ptrace_scope* ]]
}

@test "lines are read as systemd-sysctl reads them" {
    # Slash keys, a leading -, padding, ; comments and a trailing word.
    _conf "$lib_d/10-forms.conf" \
        "; kernel.dmesg_restrict = 0" \
        "  -kernel/dmesg_restrict=0  " \
        "kernel.yama.ptrace_scope = 1 # inline text"

    _audit

    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    run _desc kernel.boot_params_revert
    [[ "$output" == *"kernel.dmesg_restrict is set to 0 at boot by $lib_d/10-forms.conf:2"* ]]
    [[ "$output" != *ptrace_scope* ]]
}

@test "re-setting a key to the value it already has keeps its earlier place" {
    # systemd-sysctl keeps the first entry when the value repeats, so the glob
    # set in between still comes later and wins.
    _conf "$lib_d/10-a.conf" "net.ipv4.conf.*.rp_filter = 1"
    _conf "$lib_d/20-b.conf" "net.ipv4.conf.a*.rp_filter = 0"
    _conf "$lib_d/30-c.conf" "net.ipv4.conf.*.rp_filter = 1"

    _audit

    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    _desc kernel.boot_params_revert | grep -qF "set to 0 at boot by $lib_d/20-b.conf:1"
}

@test "/etc/sysctl.conf with no link from sysctl.d is reported as not read at boot" {
    _conf "$SYSCTL_CONF" "kernel.dmesg_restrict = 1"

    _audit
    [ "$(_status kernel.boot_params_revert)" = "failed" ]
    _desc kernel.boot_params_revert | grep -qF \
        "kernel.dmesg_restrict is set only in $SYSCTL_CONF:1, which systemd-sysctl does not read"

    ln -s ../sysctl.conf "$SYSCTL_D/99-sysctl.conf"
    rm -f "$VPSSEC_STATE/checks.json"
    _audit
    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    run _desc kernel.boot_params_ok
    [ "$status" -eq 0 ]
    [[ "$output" != *dmesg_restrict* ]]
}

@test "a linked /etc/sysctl.conf is read at boot even when a later -key drops its value" {
    _conf "$SYSCTL_CONF" "kernel.dmesg_restrict = 1"
    ln -s ../sysctl.conf "$SYSCTL_D/99-sysctl.conf"
    _conf "$SYSCTL_D/zz-drop.conf" "-kernel.dmesg_restrict"

    _audit

    # Not "only in /etc/sysctl.conf": boot read it, then the -key unset it.
    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    run _desc kernel.boot_params_ok
    [[ "$output" == *"is not judged:"*kernel.dmesg_restrict* ]]
}

@test "a parameter no file sets is listed and not judged" {
    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    _desc kernel.boot_params_ok | grep -qF "0 hardened parameters are set at boot"
    _desc kernel.boot_params_ok | grep -qF "kernel.dmesg_restrict, kernel.yama.ptrace_scope"
    _desc kernel.boot_params_ok | grep -qF "kernel.randomize_va_space"
}

@test "a parameter that already fails at runtime is left to the runtime check" {
    _runtime kernel.dmesg_restrict 0
    _conf "$lib_d/10-weak.conf" "kernel.dmesg_restrict = 0"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    run _desc kernel.boot_params_ok
    [ "$status" -eq 0 ]
    [[ "$output" != *dmesg_restrict* ]]
}

@test "full ASLR at runtime is compared too" {
    _conf "$lib_d/10-aslr.conf" "kernel.randomize_va_space = 1"

    _audit

    _desc kernel.boot_params_revert | grep -qF "kernel.randomize_va_space is set to 1"
}

@test "an unreadable sysctl.d file is reported instead of judged" {
    ln -s "$BATS_TEST_TMPDIR/gone" "$SYSCTL_D/70-dangling.conf"
    _conf "$lib_d/10-weak.conf" "kernel.dmesg_restrict = 0"

    _audit

    [ "$(_status kernel.boot_params_unreadable)" = "failed" ]
    [ -z "$(_status kernel.boot_params_revert)" ]
    _desc kernel.boot_params_unreadable | grep -qF "$SYSCTL_D/70-dangling.conf"
}

@test "nothing passing at runtime emits nothing" {
    rm "$sysctl_store"/*

    _audit

    [ ! -e "$VPSSEC_STATE/checks.json" ]
}

@test "the fix's drop-in keeps a value at boot; removing it is reported" {
    _runtime kernel.dmesg_restrict 0
    _conf "$lib_d/10-distro.conf" "kernel.dmesg_restrict = 0"
    _kernel_fix_kernel_params >/dev/null
    [ "$(cat "$sysctl_store/kernel.dmesg_restrict")" = "1" ]

    _audit
    [ "$(_status kernel.boot_params_ok)" = "passed" ]

    rm "$VPSSEC_SYSCTL_CONF"
    rm -f "$VPSSEC_STATE/checks.json"
    _audit
    _desc kernel.boot_params_revert | grep -qF \
        "kernel.dmesg_restrict is set to 0 at boot by $lib_d/10-distro.conf:1"
}

@test "the three ids are info: advice, never scored" {
    local id
    for id in kernel.boot_params_ok kernel.boot_params_revert kernel.boot_params_unreadable; do
        [ "${CHECK_SCORE_CATEGORY[$id]}" = "info" ]
    done
}

@test "the boot directories are systemd-sysctl's, in its precedence order" {
    # Tests repoint the array; this pins the value production uses.
    run bash -c 'source "$1/modules/kernel.sh"; printf "%s\n" "$SYSCTL_D" "${KERNEL_SYSCTL_BOOT_DIRS[@]}"' \
        _ "$(_vpssec_repo_root)"
    [ "$output" = "$(printf '%s\n' /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d \
        /usr/lib/sysctl.d /lib/sysctl.d)" ]
}

@test "a forwarding host's loose rp_filter is neither judged nor reported at boot" {
    # The scan skips rp_filter=2 there, so nothing may compare it with the
    # table's 1 either: systemd's 50-default.conf sets 2 at boot.
    _vpssec_stub_script systemctl <<'SH'
[[ "$1" == --version ]] && { echo "systemd 257 (test)"; exit 0; }
[[ "$*" == *"is-active"*docker* ]] && exit 0
exit 1
SH
    _runtime net.ipv4.conf.all.rp_filter 2
    _conf "$lib_d/50-default.conf" "net.ipv4.conf.*.rp_filter = 2" "kernel.dmesg_restrict = 1"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
    [ -z "$(_status kernel.boot_params_revert)" ]
}

# ufw is $1 ("active" or "inactive") and its defaults name file $2, holding the
# remaining lines, as the one it applies with `sysctl -p`.
_ufw_with() {
    local state="$1" f="$2"
    shift 2
    _conf "$f" "$@"
    _conf "$DISTRO_UFW_DEFAULTS" "IPV6=yes" "IPT_SYSCTL=$f"
    _vpssec_stub_script ufw <<SH
[[ "\$1" == status ]] && echo "Status: $state"
exit 0
SH
}

@test "an active ufw's sysctl file is applied after sysctl.d: a weaker value there is reported" {
    # ufw applies it on every start and reload; at boot nothing orders it
    # against systemd-sysctl, and on real hosts it lands later.
    _conf "$VPSSEC_SYSCTL_CONF" "net.ipv4.conf.all.rp_filter = 1"
    _ufw_with active "$etc/ufw/sysctl.conf" "# ufw" "net/ipv4/conf/all/rp_filter=0"

    _audit

    _desc kernel.boot_params_revert | grep -qF \
        "net.ipv4.conf.all.rp_filter is set to 0 by $etc/ufw/sysctl.conf:2, which ufw applies"
}

@test "an active ufw's sysctl file wins over a weaker sysctl.d value" {
    _conf "$lib_d/10-distro.conf" "net.ipv4.conf.all.rp_filter = 0"
    _ufw_with active "$etc/ufw/sysctl.conf" "net.ipv4.conf.all.rp_filter = 1"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
}

@test "an inactive ufw's sysctl file is not applied" {
    _conf "$VPSSEC_SYSCTL_CONF" "net.ipv4.conf.all.rp_filter = 1"
    _ufw_with inactive "$etc/ufw/sysctl.conf" "net/ipv4/conf/all/rp_filter=0"

    _audit

    [ "$(_status kernel.boot_params_ok)" = "passed" ]
}
