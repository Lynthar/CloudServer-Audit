#!/usr/bin/env bats
#
# Regression tests for _ufw_ssh_allowed (M4). The original pattern
# accepted only ALLOW; `ufw limit ssh` (the rate-limited variant
# recommended for SSH) was misreported as "no SSH rule", which routed
# users to fix_allow_ssh — silently downgrading their LIMIT to a
# plain ALLOW.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"

    # Stub `ufw` and `get_ssh_port` so the helper runs against
    # controlled output without needing a real UFW install.
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    mkdir -p "$BATS_TEST_TMPDIR/bin"

    # Default port for the stubbed get_ssh_port
    get_ssh_port() { echo "${VPSSEC_TEST_SSH_PORT:-22}"; }
    export -f get_ssh_port
}

# Install a fake ufw whose `ufw status` prints $1.
_install_ufw_stub() {
    cat >"$BATS_TEST_TMPDIR/bin/ufw" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "status" ]]; then
cat <<'STATUS'
$1
STATUS
fi
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/ufw"
}

@test "ssh: ALLOW rule on 22/tcp is accepted" {
    _install_ufw_stub "Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)"
    run _ufw_ssh_allowed
    [ "$status" -eq 0 ]
}

@test "ssh: LIMIT rule on 22/tcp is accepted (regression)" {
    # The exact M4 case: `ufw limit ssh` produces LIMIT, not ALLOW.
    _install_ufw_stub "Status: active

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT       Anywhere
22/tcp (v6)                LIMIT       Anywhere (v6)"
    run _ufw_ssh_allowed
    [ "$status" -eq 0 ]
}

@test "ssh: v6-only LIMIT line is also accepted" {
    _install_ufw_stub "Status: active

To                         Action      From
--                         ------      ----
22/tcp (v6)                LIMIT       Anywhere (v6)"
    run _ufw_ssh_allowed
    [ "$status" -eq 0 ]
}

@test "ssh: no rule → not allowed" {
    _install_ufw_stub "Status: active

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW       Anywhere"
    run _ufw_ssh_allowed
    [ "$status" -ne 0 ]
}

@test "ssh: DENY rule does not count as allowed" {
    _install_ufw_stub "Status: active

To                         Action      From
--                         ------      ----
22/tcp                     DENY        Anywhere"
    run _ufw_ssh_allowed
    [ "$status" -ne 0 ]
}

@test "ssh: custom port from get_ssh_port is honored" {
    export VPSSEC_TEST_SSH_PORT=2222
    _install_ufw_stub "Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   LIMIT       Anywhere"
    run _ufw_ssh_allowed
    [ "$status" -eq 0 ]
}
