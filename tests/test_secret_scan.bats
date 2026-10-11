#!/usr/bin/env bats
# The credential scanner that cloud user-data and container env share: which
# formats it knows, that it counts keys rather than lines, that it prints kinds
# and never values; and that the IMDS audit runs it wherever an IMDS answered.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
}

# Fake credentials are built at run time, so the source holds no token-shaped
# literal for a forge's push protection to flag. $1 repeated $2 times.
_rep() { printf "%${2}s" '' | tr ' ' "$1"; }

_scan() { _vpssec_scan_secrets_in_content "$1"; }

# ---- formats ----------------------------------------------------------------

@test "scan: a PGP private key block is a private key" {
    local key=$'-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----'
    [ "$(_scan "$key")" = "private_key(x1) " ]
}

@test "scan: a PEM private key still is one" {
    local key=$'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----'
    [ "$(_scan "$key")" = "private_key(x1) " ]
}

@test "scan: an AWS secret key in env, YAML and JSON form, in either case" {
    local s
    s=$(_rep K 40)
    [ "$(_scan "AWS_SECRET_ACCESS_KEY=$s")" = "aws_secret_key(x1) " ]
    [ "$(_scan "aws_secret_access_key: $s")" = "aws_secret_key(x1) " ]
    [ "$(_scan "{\"aws_secret_access_key\": \"$s\"}")" = "aws_secret_key(x1) " ]
    [ "$(_scan "aws_secret_access_key = $s")" = "aws_secret_key(x1) " ]
}

@test "scan: Alibaba, Tencent and DigitalOcean keys, the clouds this tool detects" {
    [ "$(_scan "ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI$(_rep a 20)")" = "alibaba_access_key(x1) " ]
    [ "$(_scan "shorter id LTAI$(_rep b 12)")" = "alibaba_access_key(x1) " ]
    [ "$(_scan "TENCENTCLOUD_SECRET_ID=AKID$(_rep c 32)")" = "tencent_secret_id(x1) " ]
    [ "$(_scan "DO_TOKEN=dop_v1_$(_rep f 64)")" = "digitalocean_token(x1) " ]
    [ "$(_scan "oauth doo_v1_$(_rep 0 64) refresh dor_v1_$(_rep 1 64)")" = "digitalocean_token(x2) " ]
}

@test "scan: generic password markers are not credentials" {
    run _scan 'MYSQL_ROOT_PASSWORD=hunter2 SECRET=abc'
    [ "$status" -eq 0 ]
    [ -z "${output// /}" ]
}

# ---- counting and silence ---------------------------------------------------

@test "scan: two keys on one line are two keys" {
    local a b
    a="AKIA$(_rep A 16)"
    b="ASIA$(_rep B 16)"
    [ "$(_scan "keys: $a,$b")" = "aws_access_key(x2) " ]
    [ "$(_scan "$a"$'\n'"$b")" = "aws_access_key(x2) " ]
}

@test "scan: the output names kinds, never a value" {
    local tencent="AKID$(_rep q 32)" ali="LTAI$(_rep r 20)"
    run _scan "$tencent $ali"
    [ "$status" -eq 0 ]
    [[ "$output" == *"tencent_secret_id(x1)"* && "$output" == *"alibaba_access_key(x1)"* ]]
    [[ "$output" != *"qqqq"* && "$output" != *"rrrr"* ]]
}

# ---- the IMDS audit ---------------------------------------------------------

@test "imds: an EC2-shaped IMDS no provider claims still has its user-data scanned" {
    # cloud.sh calls it aws-or-compatible; the tier map knew no such provider,
    # so the audit returned before asking for the user-data at all.
    source "$(_vpssec_repo_root)/modules/cloud.sh"
    VPSSEC_CLOUD_PROVIDER="aws-or-compatible"
    VPSSEC_CLOUD_TIER=""
    _cloud_imds_in_container() { return 0; }
    local key="AKIA$(_rep C 16)"
    _vpssec_stub_script curl <<SH
case "\$*" in
    *169.254.169.254/latest/user-data*) printf '#cloud-config\nruncmd: [echo %s]\n' "$key" ;;
    *) exit 7 ;;
esac
SH
    _cloud_audit_imds
    run jq -r '.[] | select(.id == "cloud.user_data_leaked_secrets") | .desc' "$STATE_CHECKS_FILE"
    [[ "$output" == *"aws_access_key(x1)"* ]]
    [[ "$output" != *"$key"* ]]
}
