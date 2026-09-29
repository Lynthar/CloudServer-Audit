#!/usr/bin/env bats
# Coverage for nginx.add_catchall. The catchall is a regular file in
# sites-enabled: rollback deletes the files a fix created but never a link, so a
# link into sites-available would be left dangling and fail nginx -t.

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
    NGINX_SITES_ENABLED="$NGINX_CONF_DIR/sites-enabled"
    NGINX_CATCHALL_CONF="$NGINX_SITES_ENABLED/99-catchall.conf"
    NGINX_SSL_DIR="$NGINX_CONF_DIR/ssl"
    NGINX_CATCHALL_CERT="$NGINX_SSL_DIR/default.crt"
    NGINX_CATCHALL_KEY="$NGINX_SSL_DIR/default.key"
    mkdir -p "$NGINX_SITES_ENABLED"

    _vpssec_stub systemctl
    _nginx_openssl_works
    _nginx_effective_reads_sites_enabled
}

# ---- stubs -----------------------------------------------------------------

# The stub reads sites-enabled, as Debian's nginx.conf does. The baseline vhost
# keeps the dump non-empty, or _nginx_catchall_state falls back to the tree and
# reports a catchall that is not live.
_nginx_effective_reads_sites_enabled() {
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

# A host whose nginx.conf includes only conf.d/ — the file exists but nginx
# never reads it, so the catchall is not in force however cleanly the config
# parsed and the reload succeeded.
_nginx_effective_ignores_sites_enabled() {
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

@test "catchall: after a rollback nothing is left in sites-enabled to fail nginx -t" {
    # The old layout linked sites-enabled to a sites-available file; rollback
    # deleted the file and left the link dangling, and nginx then refused to
    # start. A regular file is deleted outright.
    _vpssec_begin_backup_session

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    [ -f "$NGINX_CATCHALL_CONF" ]
    _vpssec_refute test -L "$NGINX_CATCHALL_CONF"

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    [ -z "$(ls -A "$NGINX_SITES_ENABLED")" ]
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
    : > "$NGINX_SITES_ENABLED/notadir"
    NGINX_CATCHALL_CONF="$NGINX_SITES_ENABLED/notadir/99-catchall.conf"

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
    [ ! -e "$NGINX_CATCHALL_CONF" ]
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

@test "catchall: a dangling link an older version left is replaced by the file" {
    # What a rollback of the symlink layout left behind. The write replaces it,
    # the file is registered as created, and a rollback then removes it too.
    ln -s "$NGINX_CONF_DIR/sites-available/99-catchall.conf" "$NGINX_CATCHALL_CONF"
    _vpssec_begin_backup_session

    run _nginx_fix_add_catchall
    [ "$status" -eq 0 ]
    [ -f "$NGINX_CATCHALL_CONF" ]
    _vpssec_refute test -L "$NGINX_CATCHALL_CONF"
    grep -qxF "$NGINX_CATCHALL_CONF" "${VPSSEC_BACKUP_SESSION}/.vpssec_created"

    run backup_restore "$VPSSEC_TEST_BACKUP_SESSION_TS"
    [ "$status" -eq 0 ]
    [ -z "$(ls -A "$NGINX_SITES_ENABLED")" ]
}

@test "catchall: a dangling link is not kept as an operator's file when nginx rejects the config" {
    # It only ever failed nginx -t, so it is not restored on the failure path;
    # keeping the staged file instead would leave nginx -t failing.
    ln -s "$NGINX_CONF_DIR/sites-available/99-catchall.conf" "$NGINX_CATCHALL_CONF"
    _nginx_test_rejects

    run _nginx_fix_add_catchall
    [ "$status" -eq 1 ]
    [ ! -e "$NGINX_CATCHALL_CONF" ]
    [ ! -L "$NGINX_CATCHALL_CONF" ]
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
    _nginx_effective_ignores_sites_enabled

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
    [ -f "$NGINX_CATCHALL_CONF" ]
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
