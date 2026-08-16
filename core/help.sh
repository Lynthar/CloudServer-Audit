#!/usr/bin/env bash
# Per-module help dispatcher: vpssec_help_dispatch [<topic>].
# Read-only, and invoked BEFORE vpssec_init — no run-lock, no root, no mkdir.
# Depends only on i18n, VPSSEC_MODULE_ORDER and the FIX_* maps.

# ----------------------------------------------------------------------
# Colour helpers (degrade gracefully if VPSSEC_COLOR=0)
# ----------------------------------------------------------------------

_help_safety_badge() {
    local safety="$1"
    case "$safety" in
        safe)       echo "${GREEN}[safe]${NC}    " ;;
        confirm)    echo "${YELLOW}[confirm]${NC} " ;;
        risky)      echo "${RED}[risky]${NC}   " ;;
        alert_only) echo "${CYAN}[alert]${NC}   " ;;
        *)          echo "[?]      " ;;
    esac
}

# Bucket every fix_id from the four FIX_* maps by module and safety.
# Sets _help_fixes_<safety>_<module> (newline-separated) and
# _help_fixes_total_<module>, cleared on each call.
_help_collect_fixes() {
    local module="$1"
    local id

    declare -gA _help_fix_table=()  # fully overwritten each call
    _help_fix_table[safe]=""
    _help_fix_table[confirm]=""
    _help_fix_table[risky]=""
    _help_fix_table[alert_only]=""

    for id in "${!FIX_SAFE[@]}"; do
        [[ "$id" == "$module".* ]] && _help_fix_table[safe]+="$id"$'\n'
    done
    for id in "${!FIX_CONFIRM[@]}"; do
        [[ "$id" == "$module".* ]] && _help_fix_table[confirm]+="$id"$'\n'
    done
    for id in "${!FIX_RISKY[@]}"; do
        [[ "$id" == "$module".* ]] && _help_fix_table[risky]+="$id"$'\n'
    done
    for id in "${!FIX_ALERT_ONLY[@]}"; do
        [[ "$id" == "$module".* ]] && _help_fix_table[alert_only]+="$id"$'\n'
    done

    # Explicit: the loop's last `[[ X ]] && y` short-circuits to 1, which
    # bash propagates to the caller and set -e turns into a silent abort.
    return 0
}

# Per-class count for the summary line. Uses count_lines, not
# `printf | grep -c .`, which exits 1 on empty input and under pipefail
# aborts the script mid-render.
_help_fix_summary() {
    local module="$1"
    _help_collect_fixes "$module"

    local parts=()
    local s c r a
    s=$(count_lines "${_help_fix_table[safe]}")
    c=$(count_lines "${_help_fix_table[confirm]}")
    r=$(count_lines "${_help_fix_table[risky]}")
    a=$(count_lines "${_help_fix_table[alert_only]}")

    (( s > 0 )) && parts+=("${s} safe")
    (( c > 0 )) && parts+=("${c} confirm")
    (( r > 0 )) && parts+=("${r} risky")
    (( a > 0 )) && parts+=("${a} alert")

    if (( ${#parts[@]} == 0 )); then
        echo "audit-only"
    else
        local IFS=', '; echo "${parts[*]}"
    fi
}

# ----------------------------------------------------------------------
# Top-level: list all modules grouped by category
# ----------------------------------------------------------------------

_help_show_overview() {
    print_msg ""
    print_msg "${BOLD}vpssec ${VPSSEC_VERSION}${NC} — $(i18n 'cli.usage')"
    print_msg ""
    print_msg "${BOLD}$(i18n 'help.modules_by_category'):${NC}"
    print_msg ""

    local category module
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local cat_title
        cat_title=$(i18n "category.${category}")
        print_msg "  ${BOLD}${MAGENTA}${cat_title}${NC}"

        for module in "${VPSSEC_MODULE_ORDER[@]}"; do
            [[ "${VPSSEC_MODULE_CATEGORY[$module]:-}" == "$category" ]] || continue
            local title summary
            title=$(i18n "${module}.title")
            summary=$(_help_fix_summary "$module")
            printf "    %-13s ${DIM}%s${NC} ${DIM}(%s)${NC}\n" "$module" "$title" "$summary"
        done
        print_msg ""
    done

    print_msg "$(i18n 'help.see_module_detail')"
    print_msg "$(i18n 'help.see_cli_options')"
    print_msg ""
}

# ----------------------------------------------------------------------
# Module detail
# ----------------------------------------------------------------------

# Print one safety-class section of fix_ids, with each fix's warning
# text underneath.
_help_print_class_section() {
    local heading="$1"   # already-translated heading
    local list="$2"      # newline-separated fix_ids (may be empty)
    local map_name="$3"  # FIX_SAFE / FIX_CONFIRM / FIX_RISKY / FIX_ALERT_ONLY

    [[ -z "$list" ]] && return 0

    print_msg ""
    print_msg "  ${BOLD}${heading}:${NC}"
    local id
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        printf "    %s\n" "$id"
        # Fetched via get_fix_warning, not by indexing the map, so the
        # warning renders TRANSLATED. FIX_SAFE values are placeholders.
        if [[ "$map_name" != "FIX_SAFE" ]]; then
            local reason
            reason=$(get_fix_warning "$id")
            if [[ -n "$reason" ]]; then
                printf "      ${DIM}⚠ %s${NC}\n" "$reason"
            fi
        fi
        # Orthogonal to the safety class, so it is a note on the line rather
        # than a sixth section: these never clear the finding.
        if fix_is_template_only "$id"; then
            printf "      ${DIM}→ %s${NC}\n" "$(get_fix_manual_step "$id")"
        fi
    done <<< "$list"
}

_help_show_module() {
    local module="$1"

    # Verify the module is registered. Reject typos with a useful
    # hint (the full module list).
    local found=0 m
    for m in "${VPSSEC_MODULE_ORDER[@]}"; do
        [[ "$m" == "$module" ]] && { found=1; break; }
    done
    if (( found == 0 )); then
        print_error "$(i18n 'help.unknown_module' "name=$module")"
        print_msg ""
        print_msg "$(i18n 'help.available_modules'): ${VPSSEC_MODULE_ORDER[*]}"
        return 1
    fi

    local title desc category cat_title
    title=$(i18n "${module}.title")
    desc=$(i18n "${module}.desc")
    category="${VPSSEC_MODULE_CATEGORY[$module]:-}"
    cat_title=$(i18n "category.${category}")

    print_msg ""
    print_msg "${BOLD}${title}${NC}"
    print_msg "${DIM}${desc}${NC}"
    print_msg ""
    print_msg "$(i18n 'help.category'): ${cat_title}"
    print_msg "$(i18n 'help.module_id'): ${module}"

    _help_collect_fixes "$module"
    local total=0
    local k
    for k in safe confirm risky alert_only; do
        local n
        n=$(count_lines "${_help_fix_table[$k]}")
        total=$(( total + n ))
    done

    if (( total == 0 )); then
        print_msg ""
        print_msg "  ${DIM}$(i18n 'help.audit_only_module')${NC}"
        print_msg ""
        return 0
    fi

    print_msg ""
    print_msg "${BOLD}$(i18n 'help.available_fixes' "count=$total"):${NC}"

    _help_print_class_section "$(i18n 'help.class_safe')"       "${_help_fix_table[safe]}"       "FIX_SAFE"
    _help_print_class_section "$(i18n 'help.class_confirm')"    "${_help_fix_table[confirm]}"    "FIX_CONFIRM"
    _help_print_class_section "$(i18n 'help.class_risky')"      "${_help_fix_table[risky]}"      "FIX_RISKY"
    _help_print_class_section "$(i18n 'help.class_alert_only')" "${_help_fix_table[alert_only]}" "FIX_ALERT_ONLY"

    print_msg ""
}

# ----------------------------------------------------------------------
# Public dispatch
# ----------------------------------------------------------------------

vpssec_help_dispatch() {
    local topic="${1:-}"
    if [[ -z "$topic" ]]; then
        _help_show_overview
    else
        _help_show_module "$topic"
    fi
}
