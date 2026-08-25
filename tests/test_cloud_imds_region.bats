#!/usr/bin/env bats
# Regression tests for _cloud_provider_from_imds. Region-string ordering is the
# whole subject: cn-northwest-* must stay ahead of the Huawei shapes, cn-north-1
# is a real AWS/Huawei collision, and the shared prefixes keep their AWS answer.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloud.sh"
}

_assert_provider() {
    local input="$1" expected="$2" actual
    actual=$(_cloud_provider_from_imds "$input")
    if [[ "$actual" != "$expected" ]]; then
        printf 'IMDS payload %-18s -> %s, expected %s\n' "$input" "$actual" "$expected" >&2
        return 1
    fi
}

# ---- the regression --------------------------------------------------

@test "IMDS: Huawei-only regions are Huawei, not AWS" {
    _assert_provider cn-north-4     huawei
    _assert_provider cn-north-9     huawei
    _assert_provider cn-north-11    huawei
    _assert_provider cn-east-2      huawei
    _assert_provider cn-east-3      huawei
    _assert_provider cn-south-1     huawei
    _assert_provider cn-southwest-2 huawei
    _assert_provider la-north-2     huawei
    _assert_provider la-south-2     huawei
    _assert_provider ru-northwest-2 huawei
    _assert_provider na-mexico-1    huawei
}

# ---- the two traps the reorder could have sprung ---------------------

@test "IMDS: AWS Ningxia is not swallowed by the Huawei cn-* shapes" {
    _assert_provider cn-northwest-1 aws
}

@test "IMDS: the cn-north-1 collision keeps its historical AWS answer" {
    # Both AWS Beijing and Huawei use this exact string. Whichever way it
    # resolves, someone is misdetected; changing it silently would move the
    # breakage rather than fix it, so pin the choice here.
    _assert_provider cn-north-1 aws
}

@test "IMDS: regions shared with Huawei stay AWS" {
    _assert_provider ap-southeast-1 aws
    _assert_provider af-south-1     aws
    _assert_provider me-east-1      aws
}

# ---- everything that was already right must stay right ---------------

@test "IMDS: instance-id prefixes win over any region shape" {
    _assert_provider i-0abc123def456 aws
    _assert_provider ins-abc123      tencent
}

@test "IMDS: ordinary AWS regions are AWS" {
    _assert_provider us-east-1  aws
    _assert_provider eu-west-2  aws
    _assert_provider sa-east-1  aws
    _assert_provider il-central-1 aws
}

@test "IMDS: Tencent's digit-less regions are Tencent" {
    _assert_provider ap-guangzhou     tencent
    _assert_provider eu-frankfurt     tencent
    _assert_provider na-ashburn       tencent
    _assert_provider na-siliconvalley tencent
    _assert_provider sa-saopaulo      tencent
}

@test "IMDS: an unrecognised payload is reported as ambiguous, not as AWS" {
    _assert_provider some-appliance aws-or-compatible
    _assert_provider ''             aws-or-compatible
}

# ---- payload hygiene -------------------------------------------------

@test "IMDS: case and surrounding whitespace do not change the answer" {
    _assert_provider 'CN-EAST-3'      huawei
    _assert_provider '  cn-east-3  '  huawei
    _assert_provider $'us-east-1\n'   aws
}
