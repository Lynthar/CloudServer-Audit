#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Text-based fallback interface
# Copyright (c) 2024

# --- Text UI Functions (fallback when TUI not available) ---

# Yes/No prompt
text_yesno() {
    local title="$1"
    local message="$2"
    local default="${3:-no}"

    tty_say ""
    tty_say "${BOLD}  $title${NC}"
    tty_say "$message"
    tty_say ""

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

# --- High-level Text UI Functions for vpssec ---

text_confirm_execute() {
    text_yesno "$(i18n 'common.confirm')" "$(i18n 'guide.confirm_execute')" "no"
}

# --- Unified UI Interface ---

ui_confirm_execute() {
    # --yes covers this prompt: the plan was just printed, and a risky fix
    # still gets its own confirm_critical, which --yes never satisfies.
    [[ "${VPSSEC_YES:-0}" == "1" ]] && return 0
    if tui_available; then
        tui_confirm_execute
    else
        text_confirm_execute
    fi
}

