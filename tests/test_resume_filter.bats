#!/usr/bin/env bats
#
# Tests for the plan-resume filter logic in core/engine.sh's
# _guide_resume.
#
# We don't run execute_plan end-to-end here (that needs root + real
# system state). What matters for correctness is the jq filter that
# decides which fixes to re-apply: it must drop everything in
# progress.completed[] and KEEP progress.current_fix (so the half-
# applied fix gets re-run idempotently). These tests pin that.

load helpers

setup() {
    _vpssec_load
}

# Reproduce the same jq filter that lives inside _guide_resume.
# Kept in sync manually; if the production filter changes, update
# the corresponding line here too.
_filter_remaining() {
    local plan="$1"
    local progress="$2"
    local completed
    completed=$(echo "$progress" | jq -c '.completed // []')
    echo "$plan" | jq --argjson done "$completed" \
        '.fixes | map(select(.fix_id as $id | ($done | index($id)) | not))'
}

@test "resume filter: drops fixes already in completed[]" {
    local plan
    plan=$(jq -n '{
        fixes: [
            {fix_id: "ssh.disable_empty_password", title: "A"},
            {fix_id: "kernel.harden_kernel",      title: "B"},
            {fix_id: "ufw.allow_ssh",             title: "C"}
        ]
    }')
    local progress
    progress=$(jq -n '{
        current_fix: "kernel.harden_kernel",
        total_fixes: 3,
        completed: ["ssh.disable_empty_password"]
    }')

    local out
    out=$(_filter_remaining "$plan" "$progress")
    [ "$(echo "$out" | jq 'length')" = "2" ]
    [ "$(echo "$out" | jq -r '.[0].fix_id')" = "kernel.harden_kernel" ]
    [ "$(echo "$out" | jq -r '.[1].fix_id')" = "ufw.allow_ssh" ]
}

@test "resume filter: re-runs the in-flight current_fix" {
    # progress.current_fix is the one that was running when killed.
    # It is NOT in completed[] (that field is only updated AFTER
    # execute_fix succeeds). The filter must therefore keep it.
    local plan
    plan=$(jq -n '{
        fixes: [
            {fix_id: "a.x"},
            {fix_id: "b.y"}
        ]
    }')
    local progress
    progress=$(jq -n '{
        current_fix: "b.y",
        total_fixes: 2,
        completed: ["a.x"]
    }')

    local out
    out=$(_filter_remaining "$plan" "$progress")
    [ "$(echo "$out" | jq 'length')" = "1" ]
    [ "$(echo "$out" | jq -r '.[0].fix_id')" = "b.y" ]
}

@test "resume filter: empty completed[] keeps everything" {
    local plan
    plan=$(jq -n '{fixes: [{fix_id: "a.x"}, {fix_id: "b.y"}]}')
    local progress
    progress=$(jq -n '{current_fix: "a.x", total_fixes: 2, completed: []}')

    local out
    out=$(_filter_remaining "$plan" "$progress")
    [ "$(echo "$out" | jq 'length')" = "2" ]
}

@test "resume filter: all completed → empty result" {
    local plan
    plan=$(jq -n '{fixes: [{fix_id: "a"}, {fix_id: "b"}]}')
    local progress
    progress=$(jq -n '{current_fix: null, total_fixes: 2, completed: ["a", "b"]}')

    local out
    out=$(_filter_remaining "$plan" "$progress")
    [ "$(echo "$out" | jq 'length')" = "0" ]
}

@test "resume filter: tolerates missing 'completed' key" {
    # Older or hand-edited progress.json may lack the .completed
    # array entirely. The `// []` default in the filter means we
    # treat that as "nothing done yet" and keep the whole plan.
    local plan
    plan=$(jq -n '{fixes: [{fix_id: "a"}, {fix_id: "b"}]}')
    local progress
    progress=$(jq -n '{current_fix: "a", total_fixes: 2}')

    local out
    out=$(_filter_remaining "$plan" "$progress")
    [ "$(echo "$out" | jq 'length')" = "2" ]
}
