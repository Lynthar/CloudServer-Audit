#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Text-based fallback interface
# Copyright (c) 2024

# ==============================================================================
# Text UI Functions (fallback when TUI not available)
# ==============================================================================

# Message box equivalent
text_msgbox() {
    local title="$1"
    local message="$2"

    print_header "$title"
    echo "$message"
    echo ""
    read -rp "$(i18n 'common.ok') > " _
}

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
    read -rp "$prompt > " answer
    answer="${answer:-$default}"

    [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

# Text input
text_inputbox() {
    local title="$1"
    local message="$2"
    local default="${3:-}"

    print_header "$title"
    echo "$message"

    local input
    if [[ -n "$default" ]]; then
        read -rp "[$default] > " input
        input="${input:-$default}"
    else
        read -rp "> " input
    fi

    echo "$input"
}

# Single choice menu
text_menu() {
    local title="$1"
    local message="$2"
    shift 2

    print_header "$title"
    echo "$message"
    echo ""

    local -a tags=()
    local -a descs=()
    local i=1

    while [[ $# -gt 0 ]]; do
        tags+=("$1")
        descs+=("$2")
        echo "  $i) $1 - $2"
        shift 2
        ((i++))
    done

    echo ""
    local choice
    read -rp "$(i18n 'common.next') [1-${#tags[@]}] > " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#tags[@]})); then
        echo "${tags[$((choice-1))]}"
    fi
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
    read -rp "> " choices

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
    read -rp "$(i18n 'common.ok') > " _
}

# Progress display
text_progress() {
    local title="$1"
    local current="$2"
    local total="$3"

    print_progress "$current" "$total"
}

# Info message (non-blocking)
text_infobox() {
    local title="$1"
    local message="$2"

    echo -e "${CYAN}${SYM_INFO} $title${NC}: $message"
}

# ==============================================================================
# High-level Text UI Functions for vpssec
# ==============================================================================

text_show_welcome() {
    print_header "vpssec - VPS Security Check & Hardening Tool"
    print_msg "$(i18n 'guide.welcome')"
    print_msg ""
    print_msg "Version: ${VPSSEC_VERSION}"
    print_msg "OS: $(detect_os) $(detect_os_version)"
    print_msg ""
}

text_select_modules() {
    local -n modules_ref=$1
    local items=()

    for module in "${!modules_ref[@]}"; do
        items+=("$module" "${modules_ref[$module]}" "on")
    done

    text_checklist "$(i18n 'guide.select_modules')" "$(i18n 'guide.select_modules')" "${items[@]}"
}

text_select_fixes() {
    local -n fixes_ref=$1
    local items=()

    for i in "${!fixes_ref[@]}"; do
        local fix="${fixes_ref[$i]}"
        local id=$(echo "$fix" | jq -r '.id')
        local title=$(echo "$fix" | jq -r '.title')
        local severity=$(echo "$fix" | jq -r '.severity')

        local prefix=""
        case "$severity" in
            high)   prefix="[HIGH]" ;;
            medium) prefix="[MED]" ;;
            low)    prefix="[LOW]" ;;
        esac

        items+=("$id" "$prefix $title" "on")
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

text_show_results() {
    local score="$1"
    local high="$2"
    local medium="$3"
    local low="$4"
    local passed="$5"

    print_header "$(i18n 'report.summary')"
    print_msg ""
    print_msg "$(i18n 'report.score'): ${score}/100"
    print_msg ""

    if ((high > 0)); then
        print_severity "high" "$(i18n 'report.high_issues'): $high"
    fi
    if ((medium > 0)); then
        print_severity "medium" "$(i18n 'report.medium_issues'): $medium"
    fi
    if ((low > 0)); then
        print_severity "low" "$(i18n 'report.low_issues'): $low"
    fi
    if ((passed > 0)); then
        print_severity "safe" "$(i18n 'report.passed_checks'): $passed"
    fi

    print_msg ""
}

text_show_error() {
    local message="$1"
    print_error "$message"
}

text_show_warning() {
    local message="$1"
    print_warn "$message"
    confirm "$(i18n 'common.confirm')?" "n"
}

# ==============================================================================
# Unified UI Interface
# ==============================================================================

# These functions auto-detect and use TUI or text fallback

ui_msgbox() {
    if tui_available; then
        tui_msgbox "$@"
    else
        text_msgbox "$@"
    fi
}

ui_yesno() {
    if tui_available; then
        tui_yesno "$@"
    else
        text_yesno "$@"
    fi
}

ui_inputbox() {
    if tui_available; then
        tui_inputbox "$@"
    else
        text_inputbox "$@"
    fi
}

ui_menu() {
    if tui_available; then
        tui_menu "$@"
    else
        text_menu "$@"
    fi
}

ui_checklist() {
    if tui_available; then
        tui_checklist "$@"
    else
        text_checklist "$@"
    fi
}

ui_textbox() {
    if tui_available; then
        tui_textbox "$@"
    else
        text_textbox "$@"
    fi
}

ui_infobox() {
    if tui_available; then
        tui_infobox "$@"
    else
        text_infobox "$@"
    fi
}

ui_show_welcome() {
    if tui_available; then
        tui_show_welcome
    else
        text_show_welcome
    fi
}

ui_select_modules() {
    if tui_available; then
        tui_select_modules "$@"
    else
        text_select_modules "$@"
    fi
}

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

ui_show_results() {
    if tui_available; then
        tui_show_results "$@"
    else
        text_show_results "$@"
    fi
}

ui_show_error() {
    if tui_available; then
        tui_show_error "$@"
    else
        text_show_error "$@"
    fi
}

ui_show_warning() {
    if tui_available; then
        tui_show_warning "$@"
    else
        text_show_warning "$@"
    fi
}
