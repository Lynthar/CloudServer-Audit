#!/usr/bin/env bats
# Every en_US key must be read by production code: written out whole, or built
# by one of the families below from the table or function that builds it. A key
# neither reaches is text both translators maintain and no user ever sees.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh core/engine.sh
    REPO="$(_vpssec_repo_root)"
    local m
    for m in ssh cloud kernel cloudflared; do
        # shellcheck source=/dev/null
        source "$REPO/modules/$m.sh"
    done
}

# The files that load the language files; run.sh and install.sh never do.
_prod_files() {
    printf '%s\n' "$REPO/vpssec" "$REPO"/core/*.sh "$REPO"/modules/*.sh
}

# Dotted words anywhere in the source: a key written out whole. Comment lines
# count too, since a `#` line inside a heredoc is output (report.sh's headings).
_literal_tokens() {
    _prod_files | xargs grep -ohE '[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+'
}

# The expressions production code builds a key with. Each one has a family in
# _family_keys; drop both together when the code stops building it.
FAMILY_BUILDERS=(
    '"${module}.title"' '"${module}.desc"' '"${module}.not_installed"'
    '"category.${category}"' '"fixwarn.${fix_id}"' '[fixtmpl.${fix_id}]'
    '"ssh.check_${stem}"' '"${fail_id}_desc"'
    '"cloud.vendor_${1}"' '"cloud.agent_${1}"' '"cloud.provider_name_${provider}"'
    '"cloud.firewall_name_${provider}"'
    '"kernel.core_issue_$tok"' '"kernel.ipv6_issue_$tok"' '"cloudflared.issue_$tok"'
)

# Words the function $1 names: its case arm or the tokens it emits, which is
# where a key's dynamic half comes from.
_suffixes_in() {
    declare -f "$1" | grep -oE '[a-z][a-z0-9_]*'
}

# The keys each builder can produce, filled in from the values the code uses.
_family_keys() {
    local m c id row stem fail_id vendor desc fam
    for m in "${VPSSEC_MODULE_ORDER[@]}"; do
        printf '%s\n' "$m.title" "$m.desc" "$m.not_installed"
    done
    for c in "${VPSSEC_CATEGORY_ORDER[@]}" "${VPSSEC_MODULE_CATEGORY[@]}"; do
        printf 'category.%s\n' "$c"
    done
    # get_fix_warning looks a fixwarn key up only for these three maps.
    for id in "${!FIX_CONFIRM[@]}" "${!FIX_RISKY[@]}" "${!FIX_ALERT_ONLY[@]}"; do
        printf 'fixwarn.%s\n' "$id"
    done
    for id in "${!FIX_TEMPLATE_ONLY[@]}"; do
        printf 'fixtmpl.%s\n' "$id"
    done
    for row in "${SSH_DIRECTIVE_CHECKS[@]}"; do
        IFS='|' read -r stem _ _ _ _ _ fail_id _ <<< "$row"
        printf '%s\n' "ssh.check_$stem" "${fail_id}_desc"
    done
    for row in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r _ _ vendor desc _ <<< "$row"
        printf '%s\n' "cloud.vendor_$vendor" "cloud.agent_$desc"
    done
    for fam in cloud.provider_name_:_get_provider_name \
               cloud.firewall_name_:_get_provider_name \
               kernel.core_issue_:_kernel_core_issue_text \
               kernel.ipv6_issue_:_kernel_ipv6_check_security \
               cloudflared.issue_:_cloudflared_check_ingress_security; do
        _suffixes_in "${fam#*:}" | sed "s/^/${fam%%:*}/"
    done
}

@test "i18n: every en_US key is read by production code" {
    local dead
    dead=$(LC_ALL=C comm -23 \
        <(jq -r 'paths(scalars) | join(".")' "$REPO/core/i18n/en_US.json" | LC_ALL=C sort -u) \
        <({ _literal_tokens; _family_keys; } | LC_ALL=C sort -u))
    if [[ -n "$dead" ]]; then
        printf 'keys nothing reads (%s):\n%s\n' "$(wc -l <<< "$dead")" "$dead" >&2
        return 1
    fi
}

@test "i18n: production code still builds every key family" {
    # Without this a family outlives its builder and keeps its keys alive above.
    local b missing=""
    for b in "${FAMILY_BUILDERS[@]}"; do
        _prod_files | xargs grep -qF -- "$b" || missing+="$b "
    done
    [[ -z "$missing" ]] || { echo "no longer built: $missing" >&2; return 1; }
}
