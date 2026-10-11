#!/usr/bin/env bats
# What cloud_audit says about the agents it finds and the metadata service it
# asks. Every claim must match the host: an agent is found by the name the
# kernel gives it, and user-data is called clean only after it was read.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloud.sh"
    _vpssec_stub systemctl 3
}

_emitted() {
    jq -r '.[] | "\(.id) \(.status)"' "$VPSSEC_STATE/checks.json" 2>/dev/null
}

_field() {
    jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f] // ""' \
        "$VPSSEC_STATE/checks.json"
}

# ---- agents ------------------------------------------------------------

# The processes running, by comm. pgrep -x answers as procps-ng 4 does: it
# matches the comm, which the kernel cuts to 15 bytes, and a longer pattern
# matches nothing at all.
_procs() {
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/comms"
    _vpssec_stub_script pgrep <<SH
pat="\${*: -1}"
if (( \${#pat} > 15 )); then
    echo "pgrep: pattern that searches for process name longer than 15 characters will result in zero matches" >&2
    exit 1
fi
grep -nxF -- "\$pat" "$BATS_TEST_TMPDIR/comms" | cut -d: -f1 | grep .
SH
    _vpssec_stub_script ps <<SH
case "\$*" in
    "-eo comm=") cat "$BATS_TEST_TMPDIR/comms" ;;
    *) echo root ;;
esac
SH
    # Provider and tier disagree on purpose: tier unknown keeps the metadata
    # service out of these tests.
    VPSSEC_CLOUD_PROVIDER=aws
    VPSSEC_CLOUD_TIER=unknown
}

@test "agents: a name longer than the kernel's 15-byte comm is still found" {
    _procs amazon-ssm-agen amazon-cloudwat bash

    cloud_audit >/dev/null
    _emitted | grep -qx 'cloud.agents_found failed'
    [[ "$(_field cloud.agents_found desc)" == *"amazon-ssm-agent (AWS)"* ]]
    [[ "$(_field cloud.agents_found desc)" == *"amazon-cloudwatch-agent (AWS)"* ]]
}

@test "agents: a known agent's cut comm is not reported as suspicious" {
    _procs OMSAgentForLinu bash

    cloud_audit >/dev/null
    [[ "$(_field cloud.agents_found desc)" == *"OMSAgentForLinux (Azure)"* ]]
    _vpssec_refute grep -q 'cloud.suspicious_agents' <<<"$(_emitted)"
}

@test "agents: an unknown agent-like process is still suspicious" {
    # The twin of the test above: the suspicious scan itself still fires.
    _procs evil-agent bash

    cloud_audit >/dev/null
    _emitted | grep -qx 'cloud.suspicious_agents failed'
    [[ "$(_field cloud.suspicious_agents desc)" == "evil-agent (pid:1, user:root)" ]]
}

# systemctl with unit $1 active and no other. is-active succeeds when any unit
# named is active, one unit per argument.
_active_unit() {
    _vpssec_stub_script systemctl <<SH
[[ "\$1" == is-active ]] || exit 3
for unit in "\${@:2}"; do
    [[ "\$unit" == "$1" ]] && exit 0
done
exit 3
SH
}

@test "agents: the snap-packaged SSM agent is found by its service" {
    # Ubuntu's EC2 images ship SSM as a snap, whose unit has its own name.
    _procs bash
    _active_unit snap.amazon-ssm-agent.amazon-ssm-agent

    cloud_audit >/dev/null
    [ "$(_field cloud.agents_found title)" = "$(i18n cloud.agents_found): 1" ]
    [ "$(_field cloud.agents_found desc)" = "amazon-ssm-agent (AWS): Systems Manager Agent" ]
}

# The Azure agent runs as `python3 -u /usr/sbin/waagent -daemon`, so its comm
# is python3 and only its unit finds it: walinuxagent on Ubuntu, waagent on RHEL.
@test "agents: the Azure agent under Ubuntu's unit is listed once" {
    _procs python3 bash
    _active_unit walinuxagent

    cloud_audit >/dev/null
    [ "$(_field cloud.agents_found title)" = "$(i18n cloud.agents_found): 1" ]
    [ "$(_field cloud.agents_found desc)" = "waagent (Azure): Linux VM Agent" ]
}

@test "agents: the Azure agent under RHEL's unit is found" {
    _procs python3 bash
    _active_unit waagent

    cloud_audit >/dev/null
    [ "$(_field cloud.agents_found desc)" = "waagent (Azure): Linux VM Agent" ]
}

# ---- the metadata service ----------------------------------------------

# A DigitalOcean droplet: tier2, one user-data GET, no token dance. The
# firewall step, which runs only outside a container, reads empty rulesets.
_droplet() {
    VPSSEC_CLOUD_PROVIDER=digitalocean
    VPSSEC_CLOUD_TIER=tier2
    _vpssec_stub iptables-save 0
    _vpssec_stub ip6tables-save 0
    _vpssec_stub nft 0
}

# The metadata service answers user-data with the bytes of file $1, or with a
# 404 page when $1 is empty: curl -f turns that into rc 22 and no output.
_user_data() {
    _vpssec_stub_script curl <<SH
f=0
for a in "\$@"; do [[ "\$a" != --* && "\$a" == -*f* ]] && f=1; done
case "\$*" in
    *metadata/v1/user-data*)
        if [[ -n "$1" ]]; then cat "$1"; exit 0; fi
        (( f )) && exit 22
        echo '<html><head><title>404 Not Found</title></head></html>'
        exit 0 ;;
esac
exit 7
SH
}

_github_token() {
    printf 'ghp_%s' "$(printf 'a%.0s' {1..36})"
}

@test "imds: without curl the metadata checks are reported as not run" {
    _droplet
    _user_data ""
    _vpssec_absent_command curl

    _cloud_audit_imds >/dev/null
    _emitted | grep -qx 'cloud.imds_not_checked failed'
    [ "${CHECK_SCORE_CATEGORY[cloud.imds_not_checked]}" = "info" ]
}

@test "user-data: plain text without credentials is scanned clean" {
    printf '#cloud-config\npackages: [nginx]\n' > "$BATS_TEST_TMPDIR/ud"
    _droplet
    _user_data "$BATS_TEST_TMPDIR/ud"

    _cloud_audit_imds >/dev/null
    _emitted | grep -qx 'cloud.user_data_clean passed'
}

@test "user-data: an error page is not user-data, so nothing is said about it" {
    _droplet
    _user_data ""

    _cloud_audit_imds >/dev/null
    _vpssec_refute grep -q 'cloud.user_data' <<<"$(_emitted)"
}

@test "user-data: a gzip body is decompressed before the scan" {
    printf '#!/bin/sh\nexport GITHUB_TOKEN=%s\n' "$(_github_token)" \
        | gzip -c > "$BATS_TEST_TMPDIR/ud"
    _droplet
    _user_data "$BATS_TEST_TMPDIR/ud"

    _cloud_audit_imds >/dev/null 2>"$BATS_TEST_TMPDIR/err"
    _emitted | grep -qx 'cloud.user_data_leaked_secrets failed'
    [[ "$(_field cloud.user_data_leaked_secrets desc)" == *"github_token(x1)"* ]]
    [ ! -s "$BATS_TEST_TMPDIR/err" ]
}

@test "user-data: a gzip body that does not decompress is not called clean" {
    printf '\037\213\010garbage' > "$BATS_TEST_TMPDIR/ud"
    _droplet
    _user_data "$BATS_TEST_TMPDIR/ud"

    _cloud_audit_imds >/dev/null
    _emitted | grep -qx 'cloud.user_data_not_scanned failed'
    _vpssec_refute grep -q 'cloud.user_data_clean' <<<"$(_emitted)"
}

@test "user-data: a binary body is not called clean" {
    # An ELF header: no compression format gzip knows, NUL bytes inside.
    printf '\177ELF\002\001\001\000\000\000binary' > "$BATS_TEST_TMPDIR/ud"
    _droplet
    _user_data "$BATS_TEST_TMPDIR/ud"

    _cloud_audit_imds >/dev/null 2>"$BATS_TEST_TMPDIR/err"
    _emitted | grep -qx 'cloud.user_data_not_scanned failed'
    _vpssec_refute grep -q 'cloud.user_data_clean' <<<"$(_emitted)"
    [ ! -s "$BATS_TEST_TMPDIR/err" ]
}

# ---- the host firewall's view of the metadata service ------------------

# iptables-save prints a ruleset of ~1.5 MB; $1 is a rule placed near its top.
_big_ruleset() {
    {
        printf '*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n'
        [[ -n "$1" ]] && printf '%s\n' "$1"
        awk 'BEGIN { for (i = 0; i < 30000; i++)
            printf "-A INPUT -s 10.0.%d.%d/32 -p tcp -m tcp --dport 443 -j ACCEPT\n", int(i / 256) % 256, i % 256 }'
        printf 'COMMIT\n'
    } > "$BATS_TEST_TMPDIR/rules"
    _vpssec_stub_script iptables-save <<SH
cat "$BATS_TEST_TMPDIR/rules"
SH
    _vpssec_stub ip6tables-save 0
    _vpssec_stub nft 0
}

@test "imds firewall: a rule near the top of a large ruleset is seen" {
    # Large enough that a reader stopping at the first match leaves the
    # writer blocked on a full pipe.
    _big_ruleset '-A OUTPUT -d 169.254.169.254/32 -m owner ! --uid-owner 0 -j DROP'

    run _cloud_imds_firewall_restricted
    [ "$status" -eq 0 ]
}

@test "imds firewall: an nft rule on Alibaba's metadata address counts" {
    _vpssec_absent_command iptables-save
    _vpssec_absent_command ip6tables-save
    _vpssec_stub_script nft <<'SH'
printf 'table inet filter {\n\tchain output {\n\t\tip daddr 100.100.100.200 meta skuid != 0 drop\n\t}\n}\n'
SH

    run _cloud_imds_firewall_restricted
    [ "$status" -eq 0 ]
}

@test "imds firewall: a large ruleset without the address is not a restriction" {
    _big_ruleset ''

    run _cloud_imds_firewall_restricted
    [ "$status" -eq 1 ]
}
