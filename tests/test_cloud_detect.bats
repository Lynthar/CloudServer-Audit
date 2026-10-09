#!/usr/bin/env bats
# Which cloud this is, from DMI, cloud-init and the metadata service. A provider
# is named only on a signal that provider alone gives: OpenStack (Nova) answers
# the EC2 paths with i- ids, and every Xen or Hyper-V guest shares AWS's and
# Azure's generic DMI strings.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloud.sh"
    CLOUD_DMI_DIR="$BATS_TEST_TMPDIR/dmi"
    CLOUD_INIT_RUN_DIR="$BATS_TEST_TMPDIR/cloud-init"
    mkdir -p "$CLOUD_DMI_DIR" "$CLOUD_INIT_RUN_DIR"
    VPSSEC_CLOUD_PROVIDER="" VPSSEC_CLOUD_TIER=""
    # No agents and no services: only detection and IMDS speak.
    _vpssec_stub pgrep 1
    _vpssec_stub systemctl 1
    _vpssec_stub ps 0 "bash"
    _metadata ""
}

# DMI fields as name=value arguments.
_dmi() {
    local kv
    for kv in "$@"; do printf '%s\n' "${kv#*=}" > "$CLOUD_DMI_DIR/${kv%%=*}"; done
}

# A metadata service on 169.254.169.254: "nova" answers as OpenStack Nova does
# (EC2-compatible paths with an i-%08x id, no token or region, plus its own
# /openstack tree), "ec2" as EC2 with IMDSv1 open, "" not at all.
_metadata() {
    _vpssec_stub_script curl <<SH
kind="$1"
case "\$*" in
    *openstack/latest/meta_data.json*)
        [[ \$kind == nova ]] && { echo '{"uuid": "6f2b"}'; exit 0; } ;;
    *"-X PUT"*) [[ \$kind == ec2 ]] && { echo tok; exit 0; } ;;
    *placement/region*) [[ \$kind == ec2 ]] && { echo us-east-1; exit 0; } ;;
    *latest/meta-data/instance-id*)
        [[ \$kind == nova ]] && { echo i-0000041b; exit 0; }
        [[ \$kind == ec2 ]] && { echo i-0abc1234def567890; exit 0; } ;;
    *"%{http_code}"*latest/meta-data/) [[ -n \$kind ]] && { printf 200; exit 0; } ;;
esac
[[ \$kind == "" ]] && exit 7
exit 22
SH
}

_provider() {
    VPSSEC_CLOUD_PROVIDER=""
    _detect_cloud_provider
}

@test "OpenStack's default DMI: no provider, and no AWS IMDSv1 finding" {
    # Nova's SMBIOS defaults; the instance id comes back as i-0000041b.
    _dmi "sys_vendor=OpenStack Foundation" "product_name=OpenStack Nova" \
        "product_uuid=6f2b0c1e-0000-4000-8000-000000000000"
    _metadata nova

    [ "$(_provider)" = "unknown" ]
    _vpssec_refute _vpssec_stub_called curl
    cloud_audit >/dev/null
    run jq -r '[.[] | .id] | join(",")' "$VPSSEC_STATE/checks.json"
    [[ "$output" == *"cloud.provider_unknown"* ]]
    [[ "$output" != *"cloud.imds_v1_enabled"* ]]
}

@test "a vendor named offline on an OpenStack-built host stays named" {
    # Nova's default product name, but the board vendor says Tencent.
    _dmi "sys_vendor=QEMU" "product_name=OpenStack Nova" "board_vendor=Tencent Cloud"
    _metadata nova
    [ "$(_provider)" = "tencent" ]

    rm -f "$CLOUD_DMI_DIR/board_vendor"
    _dmi "product_uuid=EC2E1E2B-0000-4000-8000-000000000000"
    [ "$(_provider)" = "aws" ]
}

@test "cloud-init's openstack: no metadata guessing at all" {
    _dmi "sys_vendor=QEMU" "product_name=Standard PC (i440FX + PIIX, 1996)"
    echo openstack > "$CLOUD_INIT_RUN_DIR/cloud-id"
    _metadata nova

    [ "$(_provider)" = "unknown" ]
    _vpssec_refute _vpssec_stub_called curl
}

@test "a rebranded OpenStack with no offline signal: its /openstack tree outweighs the i- id" {
    _dmi "sys_vendor=QEMU" "product_name=Standard PC (i440FX + PIIX, 1996)"
    _metadata nova
    [ "$(_provider)" = "unknown" ]
}

@test "EC2's metadata without an /openstack tree is still AWS" {
    _dmi "sys_vendor=QEMU" "product_name=Standard PC (i440FX + PIIX, 1996)"
    _metadata ec2
    [ "$(_provider)" = "aws" ]
}

@test "a Hyper-V guest is not Azure without Azure's chassis asset tag" {
    _dmi "sys_vendor=Microsoft Corporation" "product_name=Virtual Machine" \
        "chassis_asset_tag=None"
    [ "$(_provider)" = "unknown" ]

    _dmi "chassis_asset_tag=7783-7084-3265-9085-8269-3286-77"
    [ "$(_provider)" = "azure" ]
}

@test "a Xen HVM guest is not AWS by its product name; EC2's uuid prefix is" {
    _dmi "sys_vendor=Xen" "product_name=HVM domU" \
        "product_uuid=4B3C9A10-0000-4000-8000-000000000000"
    [ "$(_provider)" = "unknown" ]

    _dmi "product_uuid=EC2E1E2B-0000-4000-8000-000000000000"
    [ "$(_provider)" = "aws" ]
}
