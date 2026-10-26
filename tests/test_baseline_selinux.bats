#!/usr/bin/env bats
# What the baseline audit says about SELinux: the denial count comes from the audit log
# whatever vpssec's stdin is, permissive carries it, and a RHEL host without MAC is sent
# back to SELinux, never offered the AppArmor fix its family does not ship.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/baseline.sh"
    detect_container() { return 1; }
    BASELINE_APPARMOR_DISABLE_DIR="$BATS_TEST_TMPDIR/no-disable-dir"
    BASELINE_AUDIT_LOG="$BATS_TEST_TMPDIR/no-audit.log"
    _vpssec_absent_command aa-status
    _vpssec_absent_command apparmor_status
}

# An ausearch that reads stdin when it is a pipe, as the real one does, and otherwise
# finds two denials in the log.
_ausearch_stub() {
    _vpssec_stub_script ausearch <<'SH'
if [[ -p /dev/stdin ]]; then cat >/dev/null; echo '<no matches>'; exit 1; fi
printf 'type=AVC msg=audit(1.1:1): avc:  denied  { read }\ntype=AVC msg=audit(1.1:2): avc:  denied  { read }\n'
SH
}

@test "denials are counted from the log when stdin is a pipe" {
    _ausearch_stub
    local count
    count=$(printf 'the rest of a piped script\n' | _baseline_selinux_denials_count)
    [ "$count" = "2" ]
}

@test "denials are counted from the log when stdin is /dev/null" {
    _ausearch_stub
    local count
    count=$(_baseline_selinux_denials_count </dev/null)
    [ "$count" = "2" ]
}

# ---- what the MAC audit reports ----------------------------------------------

# SELinux loaded and in mode $1, with $2 AVC records logged today.
_selinux_in() {
    BASELINE_SELINUX_FS_ENFORCE="$BATS_TEST_TMPDIR/enforce"
    : > "$BASELINE_SELINUX_FS_ENFORCE"
    _vpssec_stub getenforce 0 "$1"
    _vpssec_stub_script ausearch <<EOF
for ((i = 0; i < $2; i++)); do echo 'type=AVC msg=audit(1.0:1): avc:  denied  { read }'; done
EOF
}

_field_of() {
    jq -r --arg id "$1" ".[] | select(.id == \$id) | .$2" "$VPSSEC_STATE/checks.json"
}

@test "selinux: permissive carries the count of denials logged today" {
    _selinux_in Permissive 3

    _baseline_audit_mac
    run _field_of baseline.selinux_permissive desc
    [[ "$output" == *"denials logged today: 3"* ]]
}

@test "selinux: permissive says to review the denials before setenforce 1" {
    _selinux_in Permissive 0

    _baseline_audit_mac
    run _field_of baseline.selinux_permissive suggestion
    [[ "$output" == *"ausearch -m AVC"*"setenforce 1"* ]]
}

@test "selinux: a denial count it cannot read is said in the report's language" {
    i18n_load zh_CN
    _selinux_in Permissive 0
    _vpssec_absent_command ausearch

    _baseline_audit_mac
    run _field_of baseline.selinux_permissive desc
    [[ "$output" == *"未知"* ]]
    _vpssec_refute grep -q unknown <<<"$output"
}

@test "no MAC on RHEL: pointed back at SELinux, with no AppArmor fix offered" {
    VPSSEC_DISTRO_FAMILY=rhel
    BASELINE_SELINUX_FS_ENFORCE="$BATS_TEST_TMPDIR/no-selinux"

    _baseline_audit_mac
    run jq -r '.[] | "\(.id) [\(.fix_id)]"' "$VPSSEC_STATE/checks.json"
    [ "$output" = "baseline.no_mac_system []" ]
    run _field_of baseline.no_mac_system suggestion
    [[ "$output" == *"SELINUX=permissive"*"fixfiles -F onboot"* ]]
}

@test "no MAC on Debian: AppArmor is still the fix offered" {
    VPSSEC_DISTRO_FAMILY=debian
    BASELINE_SELINUX_FS_ENFORCE="$BATS_TEST_TMPDIR/no-selinux"

    _baseline_audit_mac
    run jq -r '.[] | "\(.id) [\(.fix_id)]"' "$VPSSEC_STATE/checks.json"
    [ "$output" = "baseline.no_mac_system [baseline.enable_apparmor]" ]
}
