#!/usr/bin/env bats
# Coverage for nginx.add_catchall. The sites-enabled symlink must NOT be
# registered for rollback: backup_restore skips a created symlink and counts it
# as skipped, so the link survives AND the rollback's status goes 0 -> 2.

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

# The stub reads sites-enabled, not sites-available: a config staged but not
# linked must not show up. The baseline vhost keeps the dump non-empty, or
# _nginx_catchall_state falls back to the tree and reports a catchall not live.
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

# ---- the rollback contract -------------------------------------------------

@test "catchall: a first run records config, cert and key so rollback can delete them" {
    # backup_file's second job is recording an ABSENT path in .vpssec_created,
    # the only thing that lets a rollback remove a file the fix created.
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
    # backup_restore skips a created path that is a symlink (symlink-escape
    # safety) and counts it as skipped, so registering the link would leave it
    # in place anyway AND turn the rollback's 0 into a partial 2.
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

# ---- sites-enabled absent --------------------------------------------------

@test "catchall: a host without sites-enabled is refused, not silently skipped" {
    # With sites-enabled absent, nginx -t passes and the reload succeeds, so
    # nothing downstream catches it — only an explicit refusal does.
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

# ---- the four statuses that must not be discarded ---------------------------

@test "catchall: a config write the atomic writer refuses is reported" {
    # A regular file where the parent directory belongs defeats both the mkdir -p
    # and the mktemp inside write_file_atomic, so the real guard chain refuses
    # without mocking it. Not a '..' path: backup_file aborts before the write.
    VPSSEC_QUIET_SCAN=0
    : > "$NGINX_SITES_AVAILABLE/notadir"
    NGINX_CATCHALL_CONF="$NGINX_SITES_AVAILABLE/notadir/99-catchall.conf"

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
    # as root, so a read-only sites-enabled would not stop `ln`, and a directory
    # at the link path makes `ln` succeed by putting the link inside it.
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

# ---- validation failure: undo what this run staged, and only that ----------

@test "catchall: a rejected config leaves nothing this run created behind" {
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    [ ! -f "$NGINX_CATCHALL_CONF" ]
    # -L, not -e. -e follows the link, and the cleanup deletes the config the
    # link points at, so a surviving link is DANGLING and `[ ! -e link ]` is true
    # whether or not the removal happened.
    [ ! -L "$NGINX_CATCHALL_LINK" ]
}

@test "catchall: nginx's own diagnostic reaches the operator" {
    # On a stock Debian host this fix ALWAYS lands on the validation-failure
    # path: sites-enabled/default already carries `listen 80 default_server`.
    # "Configuration test failed" names neither file nor line, so nginx's own must.
    VPSSEC_QUIET_SCAN=0
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'duplicate default server' <<<"$output"
    grep -q 'sites-enabled/default:22' <<<"$output"
}

@test "catchall: a pre-existing dangling symlink counts as pre-existing" {
    # Same -e trap one level up: the fix decides what its cleanup may delete by
    # asking whether the link was already there, and with -e a dangling link
    # reads as absent, so the cleanup would remove a link this run did not create.
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

# ---- reload and postcondition ----------------------------------------------

@test "catchall: a failed reload is reported rather than counted as success" {
    VPSSEC_QUIET_SCAN=0
    _vpssec_stub systemctl 1

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    grep -q 'staged on disk but NOT live' <<<"$output"
}

@test "catchall: a reload that does not put the catchall in force fails the fix" {
    # nginx -t passing says the config PARSES and the reload says it was loaded.
    # Neither says this host now has a catchall — a nginx.conf that includes only
    # conf.d/ leaves the answer exactly where it was.
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

# ---- the generated config --------------------------------------------------

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
    # The heredoc expands, so a trailing backslash becomes a line continuation:
    # a multi-line hint in the generated config would be silently glued into one
    # line, taking whatever followed with it.
    run _nginx_catchall_config
    [ "$status" -eq 0 ]
    _vpssec_refute grep -q '\\$' <<<"$output"
}

# ---- the backup contract ---------------------------------------------

@test "catchall: a backup that cannot be taken aborts the fix" {
    _vpssec_begin_backup_session
    printf 'original\n' > "$NGINX_CATCHALL_CONF"
    _vpssec_stub cp 1

    run _nginx_fix_add_catchall
    [ "$status" -ne 0 ]
    [ "$(cat "$NGINX_CATCHALL_CONF")" = "original" ]
}
