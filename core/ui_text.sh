#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Text-based fallback interface
# Copyright (c) 2024

# ==============================================================================
# Text UI Functions (fallback when TUI not available)
# ==============================================================================

# Yes/No prompt
text_yesno() {
    local title="$1"
    local message="$2"
    local default="${3:-no}"

    print_header "$title"
    echo "$message"
    echo ""

    local prompt
    if [[ "$default" == "yes" ]]; then
        prompt="[Y/n]"
    else
        prompt="[y/N]"
    fi

    local answer
    read -rp "$prompt > " answer </dev/tty
    answer="${answer:-$default}"

    [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

# Multiple choice checklist
text_checklist() {
    local title="$1"
    local message="$2"
    shift 2

    print_header "$title"
    echo "$message"
    echo ""

    local -a tags=()
    local -a descs=()
    local -a states=()
    local i=1

    while [[ $# -gt 0 ]]; do
        tags+=("$1")
        descs+=("$2")
        states+=("$3")
        local marker="[ ]"
        [[ "$3" == "on" ]] && marker="[x]"
        echo "  $i) $marker $1 - $2"
        shift 3
        ((i++))
    done

    echo ""
    echo "$(i18n 'common.info'): Enter numbers separated by spaces, or 'all' for all, 'none' for none"
    local choices
    read -rp "> " choices </dev/tty

    local selected=""
    if [[ "$choices" == "all" ]]; then
        selected="${tags[*]}"
    elif [[ "$choices" != "none" ]]; then
        for choice in $choices; do
            if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#tags[@]})); then
                selected+="${tags[$((choice-1))]} "
            fi
        done
    fi

    echo "$selected"
}

# Display text content
text_textbox() {
    local title="$1"
    local file="$2"

    print_header "$title"

    if [[ -f "$file" ]]; then
        cat "$file"
    fi

    echo ""
    read -rp "$(i18n 'common.ok') > " _ </dev/tty
}

# ==============================================================================
# High-level Text UI Functions for vpssec
# ==============================================================================

# Same tag contract as tui_select_fixes: emit FIX ids (what generate_plan
# resolves), never check ids; dedupe because two checks can share a fix.
text_select_fixes() {
    local -n fixes_ref=$1
    local items=()
    local -A seen=()

    for i in "${!fixes_ref[@]}"; do
        local fix="${fixes_ref[$i]}"
        local fix_id=$(echo "$fix" | jq -r '.fix_id')
        local title=$(echo "$fix" | jq -r '.title')
        local severity=$(echo "$fix" | jq -r '.severity')

        [[ -z "$fix_id" || "$fix_id" == "null" ]] && continue
        [[ -n "${seen[$fix_id]:-}" ]] && continue
        seen[$fix_id]=1

        local prefix=""
        case "$severity" in
            high)   prefix="[HIGH]" ;;
            medium) prefix="[MED]" ;;
            low)    prefix="[LOW]" ;;
        esac

        items+=("$fix_id" "$prefix $title" "on")
    done

    text_checklist "$(i18n 'guide.select_fixes')" "$(i18n 'guide.select_fixes')" "${items[@]}"
}

text_review_plan() {
    local plan_file="$1"
    text_textbox "$(i18n 'guide.review_plan')" "$plan_file"
}

text_confirm_execute() {
    text_yesno "$(i18n 'common.confirm')" "$(i18n 'guide.confirm_execute')" "no"
}

# ==============================================================================
# Unified UI Interface
# ==============================================================================

# These functions auto-detect and use TUI or text fallback

ui_select_fixes() {
    if tui_available; then
        tui_select_fixes "$@"
    else
        text_select_fixes "$@"
    fi
}

ui_review_plan() {
    if tui_available; then
        tui_review_plan "$@"
    else
        text_review_plan "$@"
    fi
}

ui_confirm_execute() {
    if tui_available; then
        tui_confirm_execute
    else
        text_confirm_execute
    fi
}

