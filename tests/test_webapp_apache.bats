#!/usr/bin/env bats
# Apache's global directives, read the way Apache reads them: across the main
# file and the included conf directories in order, the last uncommented value
# wins. ServerSignature, ServerTokens and TraceEnable share that one reader.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    etc=$(_vpssec_fake_etc)
    APACHE_CONF="$etc/apache2/apache2.conf"
    APACHE_CONF_ALT="$etc/httpd/conf/httpd.conf"
    APACHE_CONF_DIRS="$etc/httpd/conf.d"
    mkdir -p "${APACHE_CONF_ALT%/*}" "$APACHE_CONF_DIRS"
    : > "$APACHE_CONF_ALT"
}

@test "trace: a later file that turns TraceEnable back on wins" {
    printf 'TraceEnable Off\n' >> "$APACHE_CONF_ALT"
    printf 'TraceEnable On\n' > "$APACHE_CONF_DIRS/zz-site.conf"
    run _webapp_apache_trace
    [ "$output" = "on" ]
}

@test "trace: the last Off wins over an earlier On" {
    printf 'TraceEnable On\n' >> "$APACHE_CONF_ALT"
    printf 'TraceEnable Off\n' > "$APACHE_CONF_DIRS/security.conf"
    run _webapp_apache_trace
    [ "$output" = "off" ]
}

@test "trace: a commented-out Off is not a setting, and the default is on" {
    printf '#TraceEnable Off\n' >> "$APACHE_CONF_ALT"
    run _webapp_apache_trace
    [ "$output" = "on" ]
}

@test "signature and tokens: the same last-value rule, and their defaults" {
    run _webapp_apache_server_signature
    [ "$output" = "default" ]
    run _webapp_apache_server_tokens
    [ "$output" = "Full" ]
    printf 'ServerSignature Off\nServerTokens Prod\n' >> "$APACHE_CONF_ALT"
    printf 'ServerSignature On\nServerTokens OS\n' > "$APACHE_CONF_DIRS/zz-site.conf"
    run _webapp_apache_server_signature
    [ "$output" = "on" ]
    run _webapp_apache_server_tokens
    [ "$output" = "OS" ]
}
