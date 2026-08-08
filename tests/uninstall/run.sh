#!/usr/bin/env bash
#
# Prove the uninstaller install.sh generates behaves, against REAL directories.
#
#   sudo bash tests/uninstall/run.sh      # from the repo root
#
# Why this is not a bats test: install.sh's allowlist deliberately accepts
# only /opt/<name> and /var/lib/<name>, so the success paths — data kept,
# data purged — cannot be reached from a bats tmpdir at all. The refusal
# paths and the generated text ARE covered by tests/test_install_uninstaller.bats;
# what is here is everything that needs a real allowlisted directory and a
# real `rm -rf`.
#
# Needs root and a disposable host, exactly like tests/mutation/ — it creates
# and deletes /opt/vpssec-proof-* and /srv/vpssec-proof-*. It is not wired
# into CI. Expected baseline: every line "ok", final line
# "UNINSTALLER PROOF: ALL PASS", exit 0.
#
# The four cases exist because this is the one change in the project that
# generates an `rm -rf`: paths baked correctly, data preserved by default,
# an out-of-allowlist path refused without touching anything, and a
# shell-metacharacter path quoted rather than executed.
cd /opt/vpssec || exit 1
fail=0

# Pull create_uninstaller out of install.sh without running the installer.
eval "$(awk '/^create_uninstaller\(\)/,/^}/' install.sh)"

mk_install() {           # $1 = dir
    rm -rf "$1" "$1.data-kept"
    mkdir -p "$1/core" "$1/state" "$1/backups/20260101_000000"
    printf 'ok\n' > "$1/state/ok.json"
    printf 'backed-up\n' > "$1/backups/20260101_000000/marker"
    printf 'code\n' > "$1/core/common.sh"
}

say() { printf '\n== %s ==\n' "$*"; }
ck()  { if [[ "$2" == "$3" ]]; then printf '  ok   %-52s %s\n' "$1" "$2"
        else printf '  FAIL %-52s got=%s want=%s\n' "$1" "$2" "$3"; fail=1; fi; }

# ---------------------------------------------------------------- 1
say "1. default (no terminal): data is KEPT, code is removed"
D=/opt/vpssec-proof-a
mk_install "$D"
INSTALL_DIR="$D" BIN_LINK=/tmp/proof-bin-a create_uninstaller
: > /tmp/proof-bin-a
bash "$D/uninstall.sh" < /dev/null > /tmp/out1 2>&1
ck "install dir removed"          "$([[ -e $D ]] && echo yes || echo no)"                  "no"
ck "symlink/bin removed"          "$([[ -e /tmp/proof-bin-a ]] && echo yes || echo no)"    "no"
ck "backups preserved"            "$(cat $D.data-kept/backups/20260101_000000/marker 2>/dev/null)" "backed-up"
ck "state preserved"              "$(cat $D.data-kept/state/ok.json 2>/dev/null)"          "ok"
ck "told the user where"          "$(grep -c 'Kept state and backups' /tmp/out1)"          "1"
rm -rf "$D.data-kept"

# ---------------------------------------------------------------- 2
say "2. VPSSEC_UNINSTALL_PURGE=1: everything goes, no prompt"
D=/opt/vpssec-proof-b
mk_install "$D"
INSTALL_DIR="$D" BIN_LINK=/tmp/proof-bin-b create_uninstaller
VPSSEC_UNINSTALL_PURGE=1 bash "$D/uninstall.sh" < /dev/null > /tmp/out2 2>&1
ck "install dir removed"          "$([[ -e $D ]] && echo yes || echo no)"                  "no"
ck "nothing kept behind"          "$([[ -e $D.data-kept ]] && echo yes || echo no)"        "no"
ck "did not print the keep line"  "$(grep -c 'Kept state and backups' /tmp/out2)"          "0"

# ---------------------------------------------------------------- 3
say "3. INSTALL_DIR outside the allowlist: refuses, touches nothing"
D=/srv/vpssec-proof-c
rm -rf "$D"; mkdir -p "$D/state"; printf 'precious\n' > "$D/state/ok.json"
INSTALL_DIR="$D" BIN_LINK=/tmp/proof-bin-c create_uninstaller
set +e; bash "$D/uninstall.sh" < /dev/null > /tmp/out3 2>&1; rc=$?; set -e
ck "exits non-zero"               "$([[ $rc -ne 0 ]] && echo yes || echo no)"              "yes"
ck "says why"                     "$(grep -c 'not a recognised vpssec install path' /tmp/out3)" "1"
ck "did NOT delete anything"      "$(cat $D/state/ok.json 2>/dev/null)"                    "precious"
rm -rf "$D"

# ---------------------------------------------------------------- 4
say "4. a shell-metacharacter INSTALL_DIR is inert, not executed"
D=/opt/vpssec-proof-d
mk_install "$D"
CANARY=/opt/vpssec-proof-canary
mkdir -p "$CANARY"; printf 'alive\n' > "$CANARY/marker"
INSTALL_DIR="$D" BIN_LINK=/tmp/proof-bin-d create_uninstaller
# Re-bake the hostile value the way a mis-set env var would, keeping the
# generated body verbatim. Strip everything up to and including the real
# BIN_LINK= line — an earlier version of this test took the body from the
# first blank line on, which left the ORIGINAL INSTALL_DIR= assignment in
# place to overwrite the hostile one, so the case passed against a benign
# path and proved nothing.
{ printf '#!/bin/bash\n'
  printf 'INSTALL_DIR=%q\n' "$D; rm -rf $CANARY"
  printf 'BIN_LINK=%q\n' /tmp/proof-bin-d
  sed '1,/^BIN_LINK=/d' "$D/uninstall.sh" ; } > /tmp/hostile.sh
grep -q '^INSTALL_DIR=' <(sed '1,3d' /tmp/hostile.sh) && {
    echo "  FAIL harness: body still re-assigns INSTALL_DIR"; fail=1; }
set +e; bash /tmp/hostile.sh < /dev/null > /tmp/out4 2>&1; rc=$?; set -e
ck "refuses the hostile path"     "$([[ $rc -ne 0 ]] && echo yes || echo no)"              "yes"
ck "canary untouched"             "$(cat $CANARY/marker 2>/dev/null)"                      "alive"
rm -rf "$D" "$D.data-kept" "$CANARY" /tmp/hostile.sh

# ---------------------------------------------------------------- 5
say "5. re-running the uninstaller is harmless"
D=/opt/vpssec-proof-e
mk_install "$D"
INSTALL_DIR="$D" BIN_LINK=/tmp/proof-bin-e create_uninstaller
cp "$D/uninstall.sh" /tmp/twice.sh
bash /tmp/twice.sh < /dev/null > /dev/null 2>&1
set +e; bash /tmp/twice.sh < /dev/null > /tmp/out5 2>&1; rc=$?; set -e
ck "second run still exits 0"     "$rc"                                                     "0"
rm -rf "$D" "$D.data-kept" /tmp/twice.sh /tmp/proof-bin-*

printf '\n%s\n' "$([[ $fail -eq 0 ]] && echo 'UNINSTALLER PROOF: ALL PASS' || echo 'UNINSTALLER PROOF: FAILURES')"
exit $fail
