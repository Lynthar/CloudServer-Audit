#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# TUI interface using whiptail/dialog
# Copyright (c) 2024

# ==============================================================================
# TUI Detection and Setup
# ==============================================================================

TUI_BACKEND=""
TUI_WIDTH=78
TUI_HEIGHT=20
TUI_MENU_HEIGHT=12

tui_detect_backend() {
    if check_command whiptail; then
        TUI_BACKEND="whiptail"
    elif check_command dialog; then
        TUI_BACKEND="dialog"
    else
        TUI_BACKEND=""
        return 1
    fi
    return 0
}

tui_available() {
    [[ -n "$TUI_BACKEND" ]] && [[ -t 0 ]]
}

# ==============================================================================
# TUI Dialogs
# ==============================================================================

# Yes/No dialog
# Returns 0 for yes, 1 for no
tui_yesno() {
    local title="$1"
    local message="$2"
    local default="${3:-no}"

    # Both whiptail AND dialog default the highlight to "Yes" for --yesno and
    # accept --defaultno to preselect "No". So the rule is identical for both
    # backends: pass --defaultno unless the caller asked for a "yes" default.
    # The previous per-backend logic was inverted for dialog — a "no" default
    # (the fail-safe used by the plan-execution confirm) got NO flag, so dialog
    # highlighted "Yes" and a bare Enter EXECUTED the plan instead of cancelling.
    local default_opt=""
    [[ "$default" != "yes" ]] && default_opt="--defaultno"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" $default_opt --yesno "$message" $TUI_HEIGHT $TUI_WIDTH
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" $default_opt --yesno "$message" $TUI_HEIGHT $TUI_WIDTH
        local result=$?
        clear 2>/dev/null >/dev/tty || true
        return $result
    fi
}

# Checklist (multiple choice)
# Args: title message item1 tag1 status1 item2 tag2 status2 ...
# status should be "on" or "off"
tui_checklist() {
    local title="$1"
    local message="$2"
    shift 2

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --checklist "$message" $TUI_HEIGHT $TUI_WIDTH $TUI_MENU_HEIGHT "$@" 3>&1 1>&2 2>&3
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --checklist "$message" $TUI_HEIGHT $TUI_WIDTH $TUI_MENU_HEIGHT "$@" 3>&1 1>&2 2>&3
        clear 2>/dev/null >/dev/tty || true
    fi
}

# Text box for viewing files/content
tui_textbox() {
    local title="$1"
    local file="$2"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --scrolltext --textbox "$file" $TUI_HEIGHT $TUI_WIDTH
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --textbox "$file" $TUI_HEIGHT $TUI_WIDTH
        clear 2>/dev/null >/dev/tty || true
    fi
}

# ==============================================================================
# High-level TUI Functions for vpssec
# ==============================================================================

# Fix selection screen.
#
# The checklist TAG must be the FIX id, not the check id: whatever this
# function emits is handed verbatim to generate_plan, which looks checks up
# by `.fix_id`. Tagging with `.id` made every TUI selection resolve to zero
# plan entries — the user ticked boxes, confirmed, and nothing ran (while
# the summary said "complete"). The check id is display-only here.
# Deduplicate tags: two failed checks can share one fix_id, and whiptail
# rejects duplicate checklist tags.
tui_select_fixes() {
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
            high)   prefix="[!]" ;;
            medium) prefix="[*]" ;;
            low)    prefix="[-]" ;;
        esac

        items+=("$fix_id" "$prefix $title" "on")
    done

    local selected
    selected=$(tui_checklist "$(i18n 'guide.select_fixes')" "$(i18n 'guide.select_fixes')" "${items[@]}")

    echo "$selected" | tr -d '"'
}

# Plan review screen
tui_review_plan() {
    local plan_file="$1"

    if [[ -f "$plan_file" ]]; then
        tui_textbox "$(i18n 'guide.review_plan')" "$plan_file"
    fi
}

# Execution confirmation
tui_confirm_execute() {
    tui_yesno "$(i18n 'common.confirm')" "$(i18n 'guide.confirm_execute')" "no"
}

