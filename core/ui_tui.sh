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

# Message box
tui_msgbox() {
    local title="$1"
    local message="$2"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --msgbox "$message" $TUI_HEIGHT $TUI_WIDTH
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --msgbox "$message" $TUI_HEIGHT $TUI_WIDTH
        clear
    fi
}

# Yes/No dialog
# Returns 0 for yes, 1 for no
tui_yesno() {
    local title="$1"
    local message="$2"
    local default="${3:-no}"

    local default_opt=""
    if [[ "$default" == "yes" ]]; then
        default_opt="--defaultno"
        # whiptail is reversed
        [[ "$TUI_BACKEND" == "whiptail" ]] && default_opt=""
    else
        [[ "$TUI_BACKEND" == "whiptail" ]] && default_opt="--defaultno"
    fi

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" $default_opt --yesno "$message" $TUI_HEIGHT $TUI_WIDTH
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" $default_opt --yesno "$message" $TUI_HEIGHT $TUI_WIDTH
        local result=$?
        clear
        return $result
    fi
}

# Input box
tui_inputbox() {
    local title="$1"
    local message="$2"
    local default="${3:-}"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --inputbox "$message" $TUI_HEIGHT $TUI_WIDTH "$default" 3>&1 1>&2 2>&3
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --inputbox "$message" $TUI_HEIGHT $TUI_WIDTH "$default" 3>&1 1>&2 2>&3
        clear
    fi
}

# Menu selection (single choice)
# Args: title message item1 tag1 item2 tag2 ...
tui_menu() {
    local title="$1"
    local message="$2"
    shift 2

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --menu "$message" $TUI_HEIGHT $TUI_WIDTH $TUI_MENU_HEIGHT "$@" 3>&1 1>&2 2>&3
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --menu "$message" $TUI_HEIGHT $TUI_WIDTH $TUI_MENU_HEIGHT "$@" 3>&1 1>&2 2>&3
        clear
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
        clear
    fi
}

# Radio list (single choice with radio buttons)
tui_radiolist() {
    local title="$1"
    local message="$2"
    shift 2

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --radiolist "$message" $TUI_HEIGHT $TUI_WIDTH $TUI_MENU_HEIGHT "$@" 3>&1 1>&2 2>&3
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --radiolist "$message" $TUI_HEIGHT $TUI_WIDTH $TUI_MENU_HEIGHT "$@" 3>&1 1>&2 2>&3
        clear
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
        clear
    fi
}

# Progress gauge
# Usage: tui_gauge "title" percentage
tui_gauge() {
    local title="$1"
    local percent="$2"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        echo "$percent" | whiptail --title "$title" --gauge "Processing..." 6 $TUI_WIDTH "$percent"
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        echo "$percent" | dialog --title "$title" --gauge "Processing..." 6 $TUI_WIDTH "$percent"
    fi
}

# Progress gauge with piped input
# Usage: command | tui_gauge_pipe "title"
tui_gauge_pipe() {
    local title="$1"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --gauge "Processing..." 6 $TUI_WIDTH 0
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --gauge "Processing..." 6 $TUI_WIDTH 0
        clear
    fi
}

# Info box (auto-dismiss)
tui_infobox() {
    local title="$1"
    local message="$2"

    if [[ "$TUI_BACKEND" == "whiptail" ]]; then
        whiptail --title "$title" --infobox "$message" 8 $TUI_WIDTH
    elif [[ "$TUI_BACKEND" == "dialog" ]]; then
        dialog --title "$title" --infobox "$message" 8 $TUI_WIDTH
    fi
}

# ==============================================================================
# High-level TUI Functions for vpssec
# ==============================================================================

# Welcome screen
tui_show_welcome() {
    local welcome_text="$(i18n 'guide.welcome')

$(i18n 'cli.usage')

Version: ${VPSSEC_VERSION}
OS: $(detect_os) $(detect_os_version)"

    tui_msgbox "vpssec" "$welcome_text"
}

# Module selection screen
tui_select_modules() {
    local -n modules_ref=$1
    local items=()

    for module in "${!modules_ref[@]}"; do
        local desc="${modules_ref[$module]}"
        items+=("$module" "$desc" "on")
    done

    local selected
    selected=$(tui_checklist "$(i18n 'guide.select_modules')" "$(i18n 'guide.select_modules')" "${items[@]}")

    # Parse selected items (whiptail returns quoted space-separated list)
    echo "$selected" | tr -d '"'
}

# Fix selection screen
tui_select_fixes() {
    local -n fixes_ref=$1
    local items=()

    for i in "${!fixes_ref[@]}"; do
        local fix="${fixes_ref[$i]}"
        local id=$(echo "$fix" | jq -r '.id')
        local title=$(echo "$fix" | jq -r '.title')
        local severity=$(echo "$fix" | jq -r '.severity')

        local prefix=""
        case "$severity" in
            high)   prefix="[!]" ;;
            medium) prefix="[*]" ;;
            low)    prefix="[-]" ;;
        esac

        items+=("$id" "$prefix $title" "on")
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

# Show results summary
tui_show_results() {
    local score="$1"
    local high="$2"
    local medium="$3"
    local low="$4"
    local passed="$5"

    local message="$(i18n 'report.score'): ${score}/100

$(i18n 'report.high_issues'): $high
$(i18n 'report.medium_issues'): $medium
$(i18n 'report.low_issues'): $low
$(i18n 'report.passed_checks'): $passed"

    tui_msgbox "$(i18n 'report.summary')" "$message"
}

# Error dialog
tui_show_error() {
    local message="$1"
    tui_msgbox "$(i18n 'common.error')" "$message"
}

# Warning dialog with confirmation
tui_show_warning() {
    local message="$1"
    tui_yesno "$(i18n 'common.warning')" "$message" "no"
}
