#!/usr/bin/env bats
#
# Coverage for nginx.add_catchall — the module's only fix, and the one that
# had neither a test nor a single call into vpssec's own file machinery.
#
# What the entry survey found, and what each group below pins:
#
#   1. No backup_file and no write_file_atomic anywhere in the module. The
#      config, the certificate and the private key were all invisible to
#      `vpssec rollback`, and the config was written with a bare `cat >` —
#      the last non-atomic /etc writer in the repo.
#   2. The symlink under sites-enabled must NOT be registered for rollback.
#      backup_restore deliberately skips a created path that is a symlink and
#      counts it as *skipped*, so registering it would leave the link in place
#      AND drag the rollback's exit status from 0 to 2 — a rollback that did
#      everything it could would report "partial". The fix prints and logs the
#      `rm` instead, the way baseline's disable_unused prints its way back.
#   3. `ln -sf` was guarded by `[[ -d sites-enabled ]]` and silently skipped
#      when absent. Then `nginx -t` passed (nothing new to parse), the reload
#      succeeded, two print_ok's fired and the fix returned 0 — while the
#      catchall was not live and the next audit still reported it missing.
#   4. Four discarded statuses: the config write, the ssl mkdir, `openssl req`
#      and `chmod 600` on the key. errexit is OFF inside a fix, so none of them
#      aborted anything; an openssl failure surfaced several steps later as
#      "nginx test failed", pointing the operator at their own config.
#   5. No postcondition. The fix never re-asked _nginx_catchall_state, which is
#      the only thing that can tell "the config parses and was loaded" apart
#      from "this host now has a catchall".
#
# The certificate paths were hardcoded /etc/nginx/ssl literals, so none of the
# above was testable until NGINX_SSL_DIR / NGINX_CATCHALL_CERT /
# NGINX_CATCHALL_KEY / NGINX_CATCHALL_LINK became module path variables.

load helpers.bash

setup() {
    _vpssec_load core/state.sh
    i18n_load en_US
    export TMPDIR="$BATS_TEST_TMPDIR"
    export _log_file="$BATS_TEST_TMPDIR/vpssec.log"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"

    etc=$(_vpssec_fake_etc)
    NGINX_CONF_DIR="$etc/nginx"
    NGINX_SITES_AVAILABLE="$NGINX_CONF_DIR/sites-available"
    NGINX_SITES_ENABLED="$NGINX_CONF_DIR/sites-enabled"
    NGINX_CATCHALL_CONF="$NGINX_SITES_AVAILABLE/99-catchall.conf"
    NGINX_CATCHALL_LINK="$NGINX_SITES_ENABLED/99-catchall.conf"
    NGINX_SSL_DIR="$NGINX_CONF_DIR/ssl"
    NGINX_CATCHALL_CERT="$NGINX_SSL_DIR/default.crt"
    NGINX_CATCHALL_KEY="$NGINX_SSL_DIR/default.key"
    mkdir -p "$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED"

    _vpssec_stub systemctl
    _nginx_openssl_works
    _nginx_effective_reflects_link
}

# ---- stubs -----------------------------------------------------------------

# `nginx -T` dumps what nginx actually LOADS, so the stub reads sites-enabled
# rather than sites-available: a config staged but not linked must not show up,
# which is defect 3's whole point. The baseline vhost keeps the output
# non-empty, so _nginx_catchall_state always takes its primary branch — with an
# empty dump it would fall back to grepping NGINX_CONF_DIR, find the staged
# file in sites-available, and report a catchall that is not live.
_nginx_effective_reflects_link() {
    _vpssec_stub_script nginx <<SH
case "\$*" in
    *-T*)
        echo 'server { listen 8080; server_name app.example.com; return 200 "ok"; }'
        cat "$NGINX_SITES_ENABLED"/*.conf 2>/dev/null
        exit 0
        ;;
esac
exit 0
SH
}

# A host whose nginx.conf includes only conf.d/ — the link exists but nginx
# never reads it, so the catchall is not in force however cleanly the config
# parsed and the reload succeeded.
_nginx_effective_ignores_link() {
    _vpssec_stub_script nginx <<'SH'
case "$*" in
    *-T*)
        echo 'server { listen 8080; server_name app.example.com; return 200 "ok"; }'
        exit 0
        ;;
esac
exit 0
SH
}

# `nginx -t` rejects the config; `nginx -T` still answers so the state reader
# is not the thing under test. The diagnostic is the one real nginx prints on a
# stock Debian 12 host — see the test that asserts it reaches the operator.
_nginx_test_rejects() {
    _vpssec_stub_script nginx <<SH
case "\$*" in
    *-T*)
        echo 'server { listen 8080; server_name app.example.com; return 200 "ok"; }'
        cat "$NGINX_SITES_ENABLED"/*.conf 2>/dev/null
        exit 0
        ;;
esac
echo 'nginx: [emerg] a duplicate default server for 0.0.0.0:80 in /etc/nginx/sites-enabled/default:22' >&2
echo 'nginx: configuration file /etc/nginx/nginx.conf test failed' >&2
exit 1
SH
}

# The real openssl would work here, but the fix chmods the key straight after,
# so the stub has to actually create both halves for the happy path to be the
# happy path.
_nginx_openssl_works() {
    _vpssec_stub_script openssl <<'SH'
out=""; key=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -keyout) key="$2"; shift 2 ;;
        -out)    out="$2"; shift 2 ;;
        *)       shift ;;
    esac
done
[[ -n "$key" ]] && printf -- '-----BEGIN PRIVATE KEY-----\n' > "$key"
[[ -n "$out" ]] && printf -- '-----BEGIN CERTIFICATE-----\n' > "$out"
exit 0
SH
}

# ==============================================================================
# The rollback contract — the reason this module was next in the queue
# ==============================================================================

@test "catchall: a first run records config, cert and key so rollback can delete them" {
    # The module called backup_file zero times, so all three were invisible to
    # `vpssec rollback`. backup_file's second job is recording an ABSENT path in
    # .vpssec_created, which is the only thing that lets a rollback remove a
    # file the fix created — and on a first run none of these exist.
    _vpssec_begin_backup_session
    [ ! -f "$NGINX_CATCHALL_CONF" ]
    [ ! -f "$NGINX_CATCHALL_CERT" ]

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    grep -qxF "$NGINX_CATCHALL_CONF" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
    grep -qxF "$NGINX_CATCHALL_CERT" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
    grep -qxF "$NGINX_CATCHALL_KEY"  "${VPSSEC_BACKUP_SESSION}/.vpssec_created"
}

@test "catchall: a rollback removes the config and the certificate a first run created" {
    _vpssec_begin_backup_session

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    [ -f "$NGINX_CATCHALL_CONF" ]
    [ -f "$NGINX_CATCHALL_CERT" ]

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    [ ! -f "$NGINX_CATCHALL_CONF" ]
    [ ! -f "$NGINX_CATCHALL_CERT" ]
    [ ! -f "$NGINX_CATCHALL_KEY" ]
}

@test "catchall: the symlink is not registered, so the rollback reports 0 and not partial" {
    # Registering it would be worse than not registering it: backup_restore
    # skips a created path that is a symlink (symlink-escape safety) and counts
    # it as skipped, so the link would survive anyway AND the return would go
    # from 0 to 2. An operator whose rollback did everything it could would be
    # told it was partial.
    _vpssec_begin_backup_session

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    [ -L "$NGINX_CATCHALL_LINK" ]
    _vpssec_refute grep -qxF "$NGINX_CATCHALL_LINK" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
}

@test "catchall: the way to undo the symlink is printed and logged" {
    # A rollback restores files, not links, so this line is the only way back.
    # It is logged as well as printed because a printed line scrolls away and
    # this one may be wanted days later.
    VPSSEC_QUIET_SCAN=0

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    grep -qF "rm -f $NGINX_CATCHALL_LINK" <<<"$output"
    grep -qF "rm -f $NGINX_CATCHALL_LINK" "$_log_file"
}

@test "catchall: an operator's existing config is snapshotted before it is overwritten" {
    printf 'server { listen 80 default_server; return 301 https://example.com; }\n' \
        > "$NGINX_CATCHALL_CONF"
    _vpssec_begin_backup_session

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    grep -qF 'return 301 https://example.com' "${VPSSEC_BACKUP_SESSION}${NGINX_CATCHALL_CONF}"
}

# ==============================================================================
# sites-enabled absent — the "reports a success it did not achieve" defect
# ==============================================================================

@test "catchall: a host without sites-enabled is refused, not silently skipped" {
    # The headline defect. `ln -sf` sat under `[[ -d sites-enabled ]]`; with the
    # directory absent the link was skipped, nginx -t passed because nothing new
    # was included, the reload succeeded, and the fix returned 0 with the
    # catchall not live.
    VPSSEC_QUIET_SCAN=0
    rmdir "$NGINX_SITES_ENABLED"

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'does not exist' <<<"$output"
}

@test "catchall: a host without sites-enabled is told which include line would fix it" {
    VPSSEC_QUIET_SCAN=0
    rmdir "$NGINX_SITES_ENABLED"

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -qF "include $NGINX_SITES_ENABLED/*.conf;" <<<"$output"
}

@test "catchall: a host without sites-enabled gets nothing staged on disk" {
    # Refusing before any write is the point: a config in sites-available that
    # nothing links to is read by nobody, but IS found by the state reader's
    # fallback, which would turn a refusal into a false pass on the next audit.
    rmdir "$NGINX_SITES_ENABLED"

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    [ ! -f "$NGINX_CATCHALL_CONF" ]
    [ ! -f "$NGINX_CATCHALL_CERT" ]
}

# ==============================================================================
# The four statuses that used to be discarded
# ==============================================================================

@test "catchall: a config write the atomic writer refuses is reported" {
    # validate_path rejects '..', which makes the real guard chain refuse
    # without mocking write_file_atomic. The bare `cat >` this replaced had no
    # status to check at all.
    VPSSEC_QUIET_SCAN=0
    NGINX_CATCHALL_CONF="$NGINX_SITES_AVAILABLE/../sites-available/99-catchall.conf"

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'Could not write the catchall configuration' <<<"$output"
}

@test "catchall: a failing openssl is reported as a certificate failure" {
    # It used to surface several steps later as "nginx test failed" — because
    # the 443 block references a certificate that was never generated — which
    # sends the operator to look at their own config.
    VPSSEC_QUIET_SCAN=0
    _vpssec_stub openssl 1

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'Could not generate the self-signed certificate' <<<"$output"
    _vpssec_refute grep -q 'configuration test failed' <<<"$output"
}

@test "catchall: a failing openssl stops the fix before it reloads nginx" {
    _vpssec_stub openssl 1

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called systemctl 'reload'
}

@test "catchall: a key that cannot be chmodded fails the fix rather than shipping 644" {
    # The alternative is a world-readable private key on disk under a fix that
    # has just told the operator it hardened the host.
    VPSSEC_QUIET_SCAN=0
    _vpssec_stub_script chmod <<SH
case "\$*" in
    *"$NGINX_CATCHALL_KEY"*) exit 1 ;;
esac
exec "$_VPSSEC_REAL_CHMOD" "\$@"
SH

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'Could not restrict permissions on the private key' <<<"$output"
}

@test "catchall: an ssl directory that cannot be created is reported" {
    VPSSEC_QUIET_SCAN=0
    # A plain file where the directory belongs; mkdir -p then fails.
    printf 'not a directory\n' > "$NGINX_SSL_DIR"

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'Could not create the certificate directory' <<<"$output"
}

@test "catchall: a symlink that cannot be created is reported" {
    # Stubbed rather than provoked with a real filesystem state: the tests run
    # as root, so a read-only sites-enabled would not stop `ln`, and a
    # directory at the link path makes `ln` succeed by putting the link inside
    # it (-n only un-dereferences a symlink-to-directory, not a real one — that
    # case is caught by the postcondition instead, one message further on).
    VPSSEC_QUIET_SCAN=0
    _vpssec_stub ln 1

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'creating the symlink' <<<"$output"
}

@test "catchall: an existing certificate is left alone" {
    mkdir -p "$NGINX_SSL_DIR"
    printf 'operator cert\n' > "$NGINX_CATCHALL_CERT"
    printf 'operator key\n'  > "$NGINX_CATCHALL_KEY"

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    grep -qF 'operator cert' "$NGINX_CATCHALL_CERT"
    _vpssec_refute _vpssec_stub_called openssl
}

# ==============================================================================
# Validation failure: undo what this run staged, and only that
# ==============================================================================

@test "catchall: a rejected config leaves nothing this run created behind" {
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    [ ! -f "$NGINX_CATCHALL_CONF" ]
    # -L, not -e. -e follows the link, and the cleanup deletes the config the
    # link points at, so a surviving link is DANGLING and `[ ! -e link ]` is
    # true whether or not the removal happened — the assertion passed with the
    # removal deleted until mutation testing said so.
    [ ! -L "$NGINX_CATCHALL_LINK" ]
}

@test "catchall: nginx's own diagnostic reaches the operator" {
    # Measured against real nginx-light on stock Debian 12: this fix ALWAYS
    # lands on the validation-failure path there, because the distro's own
    # sites-enabled/default already carries `listen 80 default_server` and
    # nginx refuses a second one. "Configuration test failed" alone names
    # neither the file nor the line, so the operator cannot act on it — and
    # nothing in the module had ever been run against a real nginx until this
    # batch.
    VPSSEC_QUIET_SCAN=0
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'duplicate default server' <<<"$output"
    grep -q 'sites-enabled/default:22' <<<"$output"
}

@test "catchall: a pre-existing dangling symlink counts as pre-existing" {
    # Same -e trap, one level up: the fix decides what its cleanup may delete
    # by asking whether the link was already there. With -e a dangling link
    # reads as absent, so the cleanup would remove a link this run did not
    # create.
    ln -s "$NGINX_SITES_AVAILABLE/gone.conf" "$NGINX_CATCHALL_LINK"
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    [ -L "$NGINX_CATCHALL_LINK" ]
}

@test "catchall: a rejected config does not delete an operator's pre-existing file" {
    # The old cleanup was unconditional, so a validation failure caused by
    # something else entirely took the operator's own 99-catchall.conf with it.
    # It is backed up now, but deleting it is still not this fix's call.
    VPSSEC_QUIET_SCAN=0
    printf 'server { listen 80 default_server; return 444; }\n' > "$NGINX_CATCHALL_CONF"
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    [ -f "$NGINX_CATCHALL_CONF" ]
    grep -q 'existed before this run' <<<"$output"
}

# ==============================================================================
# Reload and postcondition
# ==============================================================================

@test "catchall: a failed reload is reported rather than counted as success" {
    VPSSEC_QUIET_SCAN=0
    _vpssec_stub systemctl 1

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'staged on disk but NOT live' <<<"$output"
}

@test "catchall: a reload that does not put the catchall in force fails the fix" {
    # nginx -t passing says the config PARSES and the reload says it was
    # loaded. Neither says this host now has a catchall — a nginx.conf that
    # includes only conf.d/ leaves the answer exactly where it was, and without
    # the postcondition the fix reported a success the next audit contradicted.
    VPSSEC_QUIET_SCAN=0
    _nginx_effective_ignores_link

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'still is not in force on both ports' <<<"$output"
}

@test "catchall: the postcondition rejects a catchall that only covers port 80" {
    # Partial coverage is what the audit calls 80only; the fix must not accept
    # it as done either, or the two disagree about the same host.
    VPSSEC_QUIET_SCAN=0
    _vpssec_stub_script nginx <<'SH'
case "$*" in
    *-T*)
        echo 'server { listen 80 default_server; return 444; }'
        exit 0
        ;;
esac
exit 0
SH

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q '80only' <<<"$output"
}

@test "catchall: the happy path returns 0 with the catchall live on both ports" {
    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    [ -L "$NGINX_CATCHALL_LINK" ]
    run _nginx_catchall_state
    [ "$output" = "both" ]
}

# ==============================================================================
# The generated config
# ==============================================================================

@test "catchall: the config points at the module's certificate paths" {
    # The heredoc used to be non-expanding with /etc/nginx/ssl written into it,
    # which is what made the whole fix untestable: on a redirected tree the
    # config still referenced the host's real certificate.
    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    grep -qxF "    ssl_certificate ${NGINX_CATCHALL_CERT};" "$NGINX_CATCHALL_CONF"
    grep -qxF "    ssl_certificate_key ${NGINX_CATCHALL_KEY};" "$NGINX_CATCHALL_CONF"
    # Anchored at the directive, not on the bare string: the fake tree is
    # BATS_TEST_TMPDIR/etc/nginx/ssl, so a plain grep for /etc/nginx/ssl
    # matches the redirected path too and the assertion fails on a passing fix.
    _vpssec_refute grep -qE '^[[:space:]]*ssl_certificate(_key)? /etc/' "$NGINX_CATCHALL_CONF"
}

@test "catchall: the config covers both ports with default_server and return 444" {
    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    run _nginx_catchall_state_from_text "$(cat "$NGINX_CATCHALL_CONF")"
    [ "$output" = "both" ]
}

@test "catchall: no line of the generated config ends in a backslash" {
    # The heredoc is expanding now, so a trailing backslash is a line
    # continuation: the three-line openssl hint the config used to carry would
    # be silently glued into one, and any future edit that reintroduces the
    # continuations would do the same to whatever followed.
    run _nginx_catchall_config
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q '\\$' <<<"$output"
}
