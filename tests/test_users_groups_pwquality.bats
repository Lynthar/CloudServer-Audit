#!/usr/bin/env bats
#
# Regression tests for users.sh helpers.
#
# H8: _group_all_members must return primary-GID members in addition to
#     the secondary `members` field of getent group. The original
#     `getent group sudo | cut -d: -f4` only saw secondary members, so
#     `useradd -g sudo bob` was silently absent from the audit.
#
# H9: _pwquality_get_directive_from_files must merge /etc/security/pwquality.conf
#     and /etc/security/pwquality.conf.d/*.conf with last-write-wins semantics
#     (libpwquality reads drop-in directory in ASCII order). The original code
#     read only the main file, missing the recommended Debian 11+ / Ubuntu 22.04+
#     layout.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/users.sh"
}

# ---------- H8: _group_all_members_from_streams ----------

@test "group: secondary members emitted (sudo:x:27:alice,bob)" {
    local group_line='sudo:x:27:alice,bob'
    local passwd_text='root:x:0:0::/root:/bin/bash
daemon:x:1:1::/usr/sbin:/usr/sbin/nologin'
    run _group_all_members_from_streams "$group_line" "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice"* ]]
    [[ "$output" == *"bob"* ]]
}

@test "group: primary-GID member emitted even when secondary list is empty (regression)" {
    # The exact case the H8 fix exists to catch: bob has primary GID 27
    # (sudo) so getent group sudo | cut -d: -f4 returns nothing, but
    # bob still gets sudo membership.
    local group_line='sudo:x:27:'
    local passwd_text='root:x:0:0::/root:/bin/bash
bob:x:1001:27::/home/bob:/bin/bash
alice:x:1002:1002::/home/alice:/bin/bash'
    run _group_all_members_from_streams "$group_line" "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"bob"* ]]
    [[ "$output" != *"alice"* ]]
}

@test "group: combines secondary and primary-GID members" {
    local group_line='sudo:x:27:alice,charlie'
    local passwd_text='root:x:0:0::/root:/bin/bash
alice:x:1001:1001::/home/alice:/bin/bash
bob:x:1002:27::/home/bob:/bin/bash
charlie:x:1003:1003::/home/charlie:/bin/bash'
    run _group_all_members_from_streams "$group_line" "$passwd_text"
    [ "$status" -eq 0 ]
    # Should see all three
    [[ "$output" == *"alice"* ]]
    [[ "$output" == *"bob"* ]]
    [[ "$output" == *"charlie"* ]]
}

@test "group: empty secondary list and no matching primary GIDs → no output" {
    local group_line='sudo:x:27:'
    local passwd_text='root:x:0:0::/root:/bin/bash
alice:x:1001:1001::/home/alice:/bin/bash'
    run _group_all_members_from_streams "$group_line" "$passwd_text"
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}

@test "group: primary-GID match is exact (gid 7 must not match 27)" {
    # Defensive against a regex/substring mistake — awk uses == for the
    # comparison, so 27 must not collide with 7 or 270.
    local group_line='sudo:x:27:'
    local passwd_text='root:x:0:0::/root:/bin/bash
seven:x:1001:7::/home/seven:/bin/bash
twoseventy:x:1002:270::/home/twoseventy:/bin/bash
sudoer:x:1003:27::/home/sudoer:/bin/bash'
    run _group_all_members_from_streams "$group_line" "$passwd_text"
    [ "$status" -eq 0 ]
    [[ "$output" == *"sudoer"* ]]
    [[ "$output" != *"seven"* ]]
    [[ "$output" != *"twoseventy"* ]]
}

# ---------- H9: _pwquality_get_directive_from_files ----------

# Build a fixture set and return the file paths in ASCII order.
_make_pwquality_fixture() {
    mkdir -p "$BATS_TEST_TMPDIR/pwq.d"
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    : >"$main"
    echo "$main"
}

@test "pwquality: missing file → empty result" {
    run _pwquality_get_directive_from_files minlen
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}

@test "pwquality: main file directive read" {
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    cat >"$main" <<'EOF'
minlen = 12
dcredit = -1
EOF
    run _pwquality_get_directive_from_files minlen "$main"
    [ "$status" -eq 0 ]
    [ "$output" = "12" ]
}

@test "pwquality: drop-in overrides main (regression)" {
    # The H9 case: main says minlen=8 but a drop-in file says minlen=14.
    # libpwquality reads drop-in last → effective value is 14.
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    local drop="$BATS_TEST_TMPDIR/50-strict.conf"
    cat >"$main" <<'EOF'
minlen = 8
EOF
    cat >"$drop" <<'EOF'
minlen = 14
EOF
    run _pwquality_get_directive_from_files minlen "$main" "$drop"
    [ "$status" -eq 0 ]
    [ "$output" = "14" ]
}

@test "pwquality: drop-in only (no main file)" {
    # Some hosts ship pwquality.conf empty and only configure via drop-in.
    local drop="$BATS_TEST_TMPDIR/99-policy.conf"
    cat >"$drop" <<'EOF'
minlen = 16
ucredit = -1
EOF
    run _pwquality_get_directive_from_files minlen "$drop"
    [ "$status" -eq 0 ]
    [ "$output" = "16" ]
}

@test "pwquality: comments stripped" {
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    cat >"$main" <<'EOF'
# minlen = 8         <-- this whole line is a comment
minlen = 12          # inline comment
EOF
    run _pwquality_get_directive_from_files minlen "$main"
    [ "$status" -eq 0 ]
    [ "$output" = "12" ]
}

@test "pwquality: directive absent everywhere → empty" {
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    cat >"$main" <<'EOF'
minlen = 12
EOF
    run _pwquality_get_directive_from_files dcredit "$main"
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}

@test "pwquality: whitespace tolerance around = sign" {
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    cat >"$main" <<'EOF'
minlen=14
   dcredit  =  -1
EOF
    run _pwquality_get_directive_from_files minlen "$main"
    [ "$status" -eq 0 ]
    [ "$output" = "14" ]

    run _pwquality_get_directive_from_files dcredit "$main"
    [ "$status" -eq 0 ]
    [ "$output" = "-1" ]
}

@test "pwquality: last definition within a single file wins" {
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    cat >"$main" <<'EOF'
minlen = 8
minlen = 12
EOF
    run _pwquality_get_directive_from_files minlen "$main"
    [ "$status" -eq 0 ]
    [ "$output" = "12" ]
}

@test "pwquality: similar-prefix directive must not match (minlength != minlen)" {
    # Defensive against the original `grep -E "^minlen"` substring match.
    local main="$BATS_TEST_TMPDIR/pwquality.conf"
    cat >"$main" <<'EOF'
minlength = 99
EOF
    run _pwquality_get_directive_from_files minlen "$main"
    [ "$status" -eq 0 ]
    [[ -z "$output" ]]
}
