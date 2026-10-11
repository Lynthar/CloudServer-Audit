#!/usr/bin/env bats
# The audit's opening lines name the modules that will actually run: --include
# gains the context modules it pulls in, and --exclude lists what is left.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/report.sh core/ui_tui.sh \
        core/ui_text.sh core/engine.sh core/help.sh
    local src
    src="$(_vpssec_repo_root)/vpssec"
    eval "$(awk '/^parse_args\(\)/,/^}/' "$src")"
    eval "$(awk '/^main\(\)/,/^}/' "$src")"
    VPSSEC_QUIET_SCAN=0

    # Everything up to the header, minus what needs a real root host.
    check_root() { return 0; }
    is_supported_os() { return 0; }
    check_required_deps() { :; }
    tui_detect_backend() { :; }
    audit_all() { :; }
}

# errexit as vpssec runs main (bats' `run` turns it off).
_errexit() { set -euo pipefail; "$@"; }

# The header's module list, comma-wrapped so whole names can be matched.
_header_modules() { printf ',%s,' "$(sed -n 's/^Modules: //p' <<<"$output")"; }

@test "audit header: --include names the context modules it pulls in" {
    run _errexit main audit --include=ssh --lang=en_US --yes
    [ "$status" -eq 0 ]
    local mods m
    mods=$(_header_modules)
    for m in ssh preflight cloud timezone; do
        [[ "$mods" == *",$m,"* ]]
    done
    [[ "$mods" != *",users,"* ]]
}

@test "audit header: --exclude lists the modules that run, not 'all'" {
    run _errexit main audit --exclude=malware --lang=en_US --yes
    [ "$status" -eq 0 ]
    local mods
    mods=$(_header_modules)
    [[ "$mods" == *",ssh,"* && "$mods" == *",preflight,"* ]]
    [[ "$mods" != *",malware,"* && "$mods" != *",all,"* ]]
}

@test "audit header: a full run has no Modules line" {
    run _errexit main audit --lang=en_US --yes
    [ "$status" -eq 0 ]
    [[ "$output" == *"VPS Security Audit"* ]]
    [[ "$output" != *"Modules:"* ]]
}

@test "audit header: printed in the language asked for" {
    run _errexit main audit --include=ssh --lang=zh_CN --yes
    [ "$status" -eq 0 ]
    i18n_load zh_CN
    [[ "$output" == *"$(i18n 'cli.header_title')"* ]]
    [[ "$output" == *"$(i18n 'report.host_modules'): "* ]]
    [[ "$output" != *"Date:"* && "$output" != *"Modules:"* ]]
}
