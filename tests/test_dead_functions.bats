#!/usr/bin/env bats
# Every function production defines has a production caller. Tests do not
# count: a function only tests reach is dead code its own tests keep green.

load helpers.bash

# "file:line name" for each function in the production files under $1 that no
# production line outside its own body names. Comments do not count; functions
# written into heredocs are a generated script's, not production's.
_dead_functions() {
    local root="$1" f files=()
    for f in "$root"/{vpssec,run.sh,install.sh} "$root"/core/*.sh "$root"/modules/*.sh; do
        [[ -f "$f" ]] && files+=("$f")
    done
    # The engine calls <module>_audit and <module>_fix by name for these.
    DF_MODULES=$(sed -n '/^declare -ga VPSSEC_MODULE_ORDER=(/,/^)/{s/#.*//;p;}' "$root/core/engine.sh" \
        | grep -o '"[a-z0-9_]*"' | tr -d '"' | tr '\n' ' ') \
    awk '
        function words(s,   n, i, w) {
            n = split(s, w, /[^A-Za-z0-9_]+/)
            for (i = 1; i <= n; i++) if (w[i] != "" && w[i] != fn) ref[w[i]] = 1
        }
        FNR == 1 { fn = ""; hd = "" }
        hd != "" { if ($0 ~ ("^\t*" hd "$")) hd = ""; else words($0); next }
        /^[ \t]*#/ { next }
        {
            line = $0
            sub(/[ \t]+#[ \t].*$/, "", line)
            body = line
            if (match(line, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\(\)/)) {
                name = substr(line, 1, RLENGTH); gsub(/[ \t()]/, "", name)
                def[name] = FILENAME ":" FNR
                # A column-0 body runs to the next column-0 "}"; a one-liner ends here.
                if (line ~ /^[A-Za-z_]/ && line !~ /}[ \t;]*$/) fn = name
                body = substr(line, RLENGTH + 1)
            }
            words(body)
            if (line ~ /^}/) fn = ""
            if (line !~ /<<</ && match(line, /<<-?[ \t]*[^A-Za-z0-9_ \t]?[A-Za-z_][A-Za-z0-9_]*/)) {
                hd = substr(line, RSTART, RLENGTH)
                sub(/^<<-?[ \t]*[^A-Za-z0-9_ \t]?/, "", hd)
            }
        }
        END {
            n = split(ENVIRON["DF_MODULES"], m, " ")
            for (i = 1; i <= n; i++) ref[m[i] "_audit"] = ref[m[i] "_fix"] = 1
            for (f in def) if (!(f in ref)) print def[f] " " f
        }
    ' "${files[@]}" | sed "s|^$root/||" | sort
}

# A minimal tree: core/engine.sh with a module order, plus $1 as modules/m.sh.
_fixture() {
    local root="$BATS_TEST_TMPDIR/tree"
    mkdir -p "$root/core" "$root/modules"
    printf 'declare -ga VPSSEC_MODULE_ORDER=(\n    "m"\n)\n' \
        > "$root/core/engine.sh"
    printf '%s\n' "$1" > "$root/modules/m.sh"
    echo "$root"
}

@test "every production function has a production caller" {
    run _dead_functions "$(_vpssec_repo_root)"
    [ "$status" -eq 0 ]
    [ -z "$output" ] || { echo "no production caller (delete it, or call it):"; echo "$output"; false; }
}

@test "lint: a name in a comment or a trailing comment is not a call" {
    run _dead_functions "$(_fixture 'm_fix() { :; }
dead_a() {
    :
}
dead_b() {
    :
}
# dead_a is called by nobody
m_fix   # dead_b')"
    [ "$output" = "$(printf 'modules/m.sh:2 dead_a\nmodules/m.sh:5 dead_b')" ]
}

@test "lint: a function that only calls itself is dead" {
    run _dead_functions "$(_fixture 'm_fix() { :; }
loop() {
    loop
}')"
    [ "$output" = "modules/m.sh:2 loop" ]
}

@test "lint: a call from a one-liner or top-level code counts" {
    run _dead_functions "$(_fixture 'm_fix() { helper; }
helper() { :; }
other() {
    :
}
trap other EXIT')"
    [ -z "$output" ]
}

@test "lint: a function written into a heredoc is not production's" {
    run _dead_functions "$(_fixture "m_fix() {
    cat <<'EOF'
generated() {
    :
}
EOF
}")"
    [ -z "$output" ]
}

@test "lint: <module>_audit and _fix are live only for listed modules" {
    local root
    root=$(_fixture 'm_fix() { :; }')
    printf 'declare -ga VPSSEC_MODULE_ORDER=(\n    "m"\n    # "n"\n)\n' > "$root/core/engine.sh"
    printf 'n_audit() { :; }\nn_fix() { :; }\n' > "$root/modules/n.sh"
    run _dead_functions "$root"
    [ "$output" = "$(printf 'modules/n.sh:1 n_audit\nmodules/n.sh:2 n_fix')" ]
}
