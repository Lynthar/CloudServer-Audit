#!/usr/bin/env bats
#
# The cloud agent table must not print Chinese on an English report.
#
# KNOWN_CLOUD_AGENTS used to carry display text in its vendor and description
# columns, and half of it was Chinese ("阿里云", "安骑士/云安全中心"). Those
# strings were concatenated straight into the cloud.agents_found title and
# description, so `--lang=en_US` on an Alibaba host produced a check that read
#
#     Cloud Monitoring Agents Found: 3 | AliYunDun (阿里云), ...
#
# i18n key parity could never catch this: the keys were all present and in
# sync. The text simply was not going through i18n at all. The same held for
# _get_provider_name, which hard-coded "阿里云 (Alibaba Cloud)" into the
# provider_detected title.
#
# Both columns are stable machine keys now. The tests below pin the two things
# that can regress:
#
#   1. every key the table names exists in BOTH language files — a new agent
#      row with no translation fails here, and the failure lists the rows
#   2. the emitted check follows --lang, asserted on the check in checks.json
#      rather than on which branch ran
#
# The vendor column is load-bearing beyond display: it is the machine-side
# identity of the vendor. That is why _find_known_agents is pinned to emit
# keys, not rendered names — resolving early would put a translated string
# where later code expects an identifier.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/cloud.sh"
}

# Read a cloud.* key straight out of a language file. Deliberately not via
# the loaded VPSSEC_I18N array: only one language is loaded at a time, and
# the point of these tests is to check both files.
_i18n_raw() {
    local lang="$1" key="$2"
    jq -r --arg k "$key" '.cloud[$k] // empty' \
        "$(_vpssec_repo_root)/core/i18n/${lang}.json"
}

# Fail if a string carries any byte outside printable ASCII. LC_ALL=C keeps
# the bracket expression byte-oriented on GNU and BSD grep alike.
_assert_ascii_only() {
    if printf '%s' "$1" | LC_ALL=C grep -q '[^ -~]'; then
        printf 'expected ASCII-only, got: %s\n' "$1" >&2
        return 1
    fi
}

# Every provider id the module can produce, from both shapes that produce
# one: the assignments in _detect_cloud_provider and the echoes in
# _cloud_provider_from_imds.
_provider_ids() {
    local src
    src="$(_vpssec_repo_root)/modules/cloud.sh"
    {
        grep -oE 'provider="[a-z][a-z0-9-]*"' "$src" | sed -E 's/provider="(.*)"/\1/'
        awk '/^_cloud_provider_from_imds\(\)/,/^}/' "$src" |
            grep -oE 'echo "[a-z][a-z0-9-]*"' | sed -E 's/echo "(.*)"/\1/'
    } | sort -u
}

# ==============================================================================
# 1. The enumeration gate: no row may name a key that does not exist
# ==============================================================================

@test "cloud i18n: every agent row's vendor and desc keys exist in both languages" {
    # An empty table would make every assertion below pass without running.
    # The count is deliberately a floor, not the exact 32: adding an agent
    # should not have to touch this test, removing the table should.
    [ "${#KNOWN_CLOUD_AGENTS[@]}" -ge 30 ]

    local missing="" entry proc svc vendor_key desc_key lang
    for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r proc svc vendor_key desc_key _ <<< "$entry"
        for lang in en_US zh_CN; do
            [[ -n "$(_i18n_raw "$lang" "vendor_${vendor_key}")" ]] ||
                missing+="${lang}: cloud.vendor_${vendor_key} (row ${proc})"$'\n'
            [[ -n "$(_i18n_raw "$lang" "agent_${desc_key}")" ]] ||
                missing+="${lang}: cloud.agent_${desc_key} (row ${proc})"$'\n'
        done
    done

    if [[ -n "$missing" ]]; then
        printf 'agent rows naming keys that do not exist:\n%s' "$missing" >&2
        return 1
    fi
}

@test "cloud i18n: every provider id the module can return has a display name" {
    # _provider_ids scrapes the module source, so a reformat that breaks the
    # scrape would silently turn this test into a no-op that still passes.
    [ "$(_provider_ids | wc -l)" -ge 12 ]

    local missing="" id rendered
    while read -r id; do
        [[ -z "$id" || "$id" == "unknown" ]] && continue
        rendered=$(_get_provider_name "$id")
        # Two shapes of "nobody translated this". The catch-all arm of
        # _get_provider_name echoes the id back; a key that resolves to
        # nothing comes out of i18n as the key itself, which is not equal to
        # the id and would otherwise read as a successful translation.
        if [[ "$rendered" == "$id" || "$rendered" == cloud.* ]]; then
            missing+="${id} -> ${rendered}"$'\n'
        fi
    done < <(_provider_ids)

    if [[ -n "$missing" ]]; then
        printf 'provider ids with no cloud.provider_name_* key:\n%s' "$missing" >&2
        return 1
    fi
}

@test "cloud i18n: no vendor or agent key is left over from a deleted row" {
    # The other direction. Without it the guard is one-way: dropping an agent
    # row leaves its strings behind in both language files, where they read as
    # supported vendors nobody detects any more. Same reasoning as the
    # two-way check in test_fix_id_classification.bats.
    local used="" entry vendor_key desc_key key suffix orphans=""
    for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r _ _ vendor_key desc_key _ <<< "$entry"
        used+="vendor_${vendor_key}"$'\n'"agent_${desc_key}"$'\n'
    done

    while read -r key; do
        [[ -z "$key" ]] && continue
        grep -qxF "$key" <<< "$used" || orphans+="cloud.${key}"$'\n'
    done < <(jq -r '.cloud | keys[] | select(startswith("vendor_") or startswith("agent_"))' \
        "$(_vpssec_repo_root)/core/i18n/en_US.json")

    if [[ -n "$orphans" ]]; then
        printf 'keys no agent row names any more:\n%s' "$orphans" >&2
        return 1
    fi
}

@test "cloud i18n: the table carries keys, not display text" {
    # A row whose vendor column held "阿里云" or "AWS" would pass every other
    # test here while defeating the point: the column has to stay an
    # identifier that both languages resolve from.
    local entry proc vendor_key
    for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r proc _ vendor_key _ _ <<< "$entry"
        _assert_ascii_only "$vendor_key"
        if [[ ! "$vendor_key" =~ ^[a-z][a-z0-9_]*$ ]]; then
            printf 'row %s: vendor column %q is not a key\n' "$proc" "$vendor_key" >&2
            return 1
        fi
    done
}

# ==============================================================================
# 2. The rendered output follows --lang
# ==============================================================================

_stub_one_running_agent() {
    # AliYunDun running, nothing else; no services; a process table with
    # nothing that trips the suspicious-name patterns. All three are stubbed
    # so the assertions below do not depend on what the runner has.
    _vpssec_stub_script pgrep <<'SH'
case "$*" in
    *AliYunDun) exit 0 ;;
    *) exit 1 ;;
esac
SH
    _vpssec_stub systemctl 1
    _vpssec_stub ps 0 "bash"
    # Pre-seed the detection cache so cloud_audit neither reads DMI nor probes
    # 169.254.169.254. The pair is deliberately inconsistent — alibaba is a
    # tier1 provider — because "unknown" is what makes _cloud_audit_imds
    # return before its first curl. Nothing here reads the tier for anything
    # else; do not "correct" it to tier1 without stubbing curl.
    export VPSSEC_CLOUD_PROVIDER=alibaba
    export VPSSEC_CLOUD_TIER=unknown
}

_agents_found_desc() {
    jq -r '.[] | select(.id == "cloud.agents_found") | .desc' \
        "$VPSSEC_STATE/checks.json"
}

@test "cloud i18n: en_US renders the agent's vendor in English" {
    _stub_one_running_agent
    i18n_load en_US

    run cloud_audit

    [ "$(_agents_found_desc)" = "AliYunDun (Alibaba Cloud)" ]
}

@test "cloud i18n: the en_US agents_found check has no CJK anywhere" {
    _stub_one_running_agent
    i18n_load en_US

    run cloud_audit

    # The regression, stated as the operator would see it: an English report
    # on an Alibaba host contains no Chinese.
    local title desc
    title=$(jq -r '.[] | select(.id == "cloud.agents_found") | .title' \
        "$VPSSEC_STATE/checks.json")
    desc=$(_agents_found_desc)
    _assert_ascii_only "$title"
    _assert_ascii_only "$desc"
}

@test "cloud i18n: zh_CN still renders the Chinese vendor name" {
    # Proves the fix is translation, not deletion — the zh_CN report reads
    # exactly as it did before the columns became keys.
    _stub_one_running_agent
    i18n_load zh_CN

    run cloud_audit

    [ "$(_agents_found_desc)" = "AliYunDun (阿里云)" ]
}

@test "cloud i18n: the provider title follows the language too" {
    i18n_load en_US
    _assert_ascii_only "$(_get_provider_name alibaba)"
    [ "$(_get_provider_name alibaba)" = "Alibaba Cloud" ]

    i18n_load zh_CN
    [ "$(_get_provider_name alibaba)" = "阿里云 (Alibaba Cloud)" ]
}

# ==============================================================================
# 3. Keys stay keys on the wire
# ==============================================================================

@test "cloud i18n: _find_known_agents emits the key, not the rendered name" {
    _stub_one_running_agent
    i18n_load zh_CN

    local line vendor_key desc_key
    line=$(_find_known_agents | head -1)
    IFS='|' read -r _ _ vendor_key desc_key _ _ <<< "$line"

    [ "$vendor_key" = "alibaba" ]
    [ "$desc_key" = "aliyundun" ]
}

@test "cloud i18n: cloud_fix renders both columns for the operator" {
    _stub_one_running_agent
    i18n_load en_US

    run cloud_fix cloud.agents_found

    # Alert-only: the non-zero return is the contract, not a failure.
    [ "$status" -eq 1 ]
    [[ "$output" == *"Cloud Security Center agent (Aegis)"* ]]
    [[ "$output" == *"Alibaba Cloud"* ]]
}
