#!/usr/bin/env bash
# vpssec — Per-module help dispatcher.
#
# Provides:
#   vpssec_help_dispatch [<topic>]
#     - no topic: print a category-grouped module summary
#     - topic == module name: print that module's audit/fix detail
#     - topic == anything else: print error + module list
#
# Help is read-only and has no system dependencies beyond what's
# already sourced (i18n, VPSSEC_MODULE_ORDER, FIX_* maps in
# security_levels.sh). The entry script invokes this BEFORE
# vpssec_init runs, so no run-lock, no root, no mkdir, no audit.

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

# Bucket every fix_id known to the four FIX_* maps into per-module
# arrays segregated by safety. Sets the following globals (cleared
# on each call):
#   _help_fixes_<safety>_<module> — newline-separated fix_ids
#   _help_fixes_total_<module>    — count
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

    # Explicit success return: the last for-loop's final iteration is
    # `[[ X ]] && y` and short-circuits to exit code 1 whenever that
    # last id doesn't match the requested module. Inside a function,
    # bash propagates that to the call site, where set -e then aborts
    # the caller silently. Pinning the return value here keeps the
    # function safe to call regardless of how the loop terminated.
    return 0
}

# Concise per-class count (e.g. "5 safe, 1 confirm, 2 risky, 3 alert")
# for the top-level summary. Uses count_lines (common.sh) instead of
# `printf | grep -c .`: the latter exits 1 on empty input, which
# under pipefail collapses the whole pipeline and aborts the script
# silently mid-render. count_lines always returns 0 + an integer.
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

# Print one safety-class section of fix_ids, with the warning text
# from the corresponding FIX_* map.
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
        # FIX_SAFE values are just "true"; CONFIRM/RISKY/ALERT_ONLY
        # values carry the human reason. Skip the placeholder for
        # SAFE; print the reason indented under others.
        if [[ "$map_name" != "FIX_SAFE" ]]; then
            local -n _map="$map_name"
            local reason="${_map[$id]:-}"
            if [[ -n "$reason" ]]; then
                printf "      ${DIM}⚠ %s${NC}\n" "$reason"
            fi
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
