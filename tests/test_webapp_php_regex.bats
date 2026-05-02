#!/usr/bin/env bats
#
# Regression tests for word-boundary matching in
# _webapp_php_disable_functions and the strict HSTS check in
# _webapp_nginx_hsts.

load helpers.bash

setup() {
    _vpssec_load
    # webapp.sh sources clean (no top-level side effects) and exposes
    # the helpers we want to exercise.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
}

# --- disable_functions ---

@test "disable_functions: 'popen' is NOT considered disabled when only proc_open is listed" {
    # Original substring grep falsely matched 'popen' against
    # 'proc_open' — masking real exposure.
    _webapp_get_php_config() { echo "proc_open"; }
    PHP_DANGEROUS_FUNCTIONS=("popen")
    run _webapp_php_disable_functions
    [ "$status" -eq 0 ]
    [[ "$output" == *"popen"* ]]
}

@test "disable_functions: exact 'popen' in list IS considered disabled" {
    _webapp_get_php_config() { echo "popen,exec"; }
    PHP_DANGEROUS_FUNCTIONS=("popen")
    run _webapp_php_disable_functions
    [ "$status" -eq 0 ]
    [[ "$output" != *"popen"* ]]
}

@test "disable_functions: tolerates spaces around tokens" {
    _webapp_get_php_config() { echo "exec , popen ,system"; }
    PHP_DANGEROUS_FUNCTIONS=("popen")
    run _webapp_php_disable_functions
    [ "$status" -eq 0 ]
    [[ "$output" != *"popen"* ]]
}

@test "disable_functions: 'exec' is NOT disabled when only mb_exec_dir is listed" {
    _webapp_get_php_config() { echo "mb_exec_dir"; }
    PHP_DANGEROUS_FUNCTIONS=("exec")
    run _webapp_php_disable_functions
    [ "$status" -eq 0 ]
    [[ "$output" == *"exec"* ]]
}

@test "disable_functions: token at start of list works" {
    _webapp_get_php_config() { echo "exec,popen,system"; }
    PHP_DANGEROUS_FUNCTIONS=("exec")
    run _webapp_php_disable_functions
    [ "$status" -eq 0 ]
    [[ "$output" != *"exec"* ]]
}

@test "disable_functions: token at end of list works" {
    _webapp_get_php_config() { echo "popen,system,exec"; }
    PHP_DANGEROUS_FUNCTIONS=("exec")
    run _webapp_php_disable_functions
    [ "$status" -eq 0 ]
    [[ "$output" != *"exec"* ]]
}

# --- HSTS ---

@test "HSTS: commented-out add_header is reported as missing" {
    _webapp_nginx_dump() {
        cat <<'EOF'
# add_header Strict-Transport-Security "max-age=31536000" always;
EOF
    }
    run _webapp_nginx_hsts
    [ "$status" -eq 0 ]
    [ "$output" = "missing" ]
}

@test "HSTS: bare mention without add_header is reported as missing" {
    _webapp_nginx_dump() {
        cat <<'EOF'
# Note: Strict-Transport-Security recommended for HTTPS sites
EOF
    }
    run _webapp_nginx_hsts
    [ "$status" -eq 0 ]
    [ "$output" = "missing" ]
}

@test "HSTS: add_header without 'always' is reported as weak" {
    _webapp_nginx_dump() {
        cat <<'EOF'
add_header Strict-Transport-Security "max-age=31536000";
EOF
    }
    run _webapp_nginx_hsts
    [ "$status" -eq 0 ]
    [ "$output" = "weak" ]
}

@test "HSTS: add_header with 'always' is reported as configured" {
    _webapp_nginx_dump() {
        cat <<'EOF'
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF
    }
    run _webapp_nginx_hsts
    [ "$status" -eq 0 ]
    [ "$output" = "configured" ]
}

@test "HSTS: indented add_header is still detected" {
    _webapp_nginx_dump() {
        cat <<'EOF'
    add_header Strict-Transport-Security "max-age=63072000" always;
EOF
    }
    run _webapp_nginx_hsts
    [ "$status" -eq 0 ]
    [ "$output" = "configured" ]
}
