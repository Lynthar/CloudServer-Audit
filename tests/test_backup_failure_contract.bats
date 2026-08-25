#!/usr/bin/env bats
# A backup that could not be taken must abort the fix that asked for it. This
# file enumerates every backup_file call site and requires each to match one of
# the approved shapes below, so a call site written a fourth way goes red.
#
# Approved shapes:
#   backup_file "$x" >/dev/null || return 1        discard the path, abort
#   var=$(backup_file "$x") || return 1            keep the path, abort
#   if ! backup_file "$x" >/dev/null; then         abort AND account for it
#
# The third exists for _fs_fix_one, whose callers ignore its status: there the
# failure has to reach a counter or it is silent.

load helpers.bash

_backup_file_call_sites() {
    local root
    root=$(_vpssec_repo_root)
    grep -rnE '(^|[^_[:alnum:]])backup_file[[:space:]]+"' \
        "$root/core" "$root/modules" --include='*.sh' 2>/dev/null \
        | sed "s|^$root/||"
}

@test "every backup_file call site propagates a failed backup" {
    local bad=0 site text
    while read -r site; do
        [[ -n "$site" ]] || continue
        # Strip "path:lineno:" and then the leading indentation.
        text=${site#*:}
        text=${text#*:}
        text=${text#"${text%%[![:space:]]*}"}
        case "$text" in
            'backup_file "'*'" >/dev/null || return 1') ;;
            *'=$(backup_file "'*'") || return 1') ;;
            'if ! backup_file "'*'" >/dev/null; then') ;;
            *)
                printf 'unapproved backup_file shape: %s\n' "$site" >&2
                bad=1
                ;;
        esac
    done < <(_backup_file_call_sites)
    [ "$bad" -eq 0 ]
}

@test "the call-site enumeration is not vacuous" {
    # Without this the test above passes for free the day the pattern stops
    # matching. 26 is the count the contract was written against; a legitimate
    # removal updates the number, a silently broken grep does not.
    local n
    n=$(_backup_file_call_sites | wc -l)
    [ "$n" -ge 26 ]
    _backup_file_call_sites | grep -q '^modules/docker\.sh:'
}

@test "the shape check rejects the swallowing form it was written for" {
    # The reverse assertion: prove the case arms above actually discriminate,
    # rather than every string falling through to an approved arm.
    local text bad=0
    for text in 'backup_file "$X" >/dev/null 2>&1 || true' \
                'backup_file "$X"' \
                'bak=$(backup_file "$X")' \
                'bak=$(backup_file "$X" 2>/dev/null) || bak=""'; do
        case "$text" in
            'backup_file "'*'" >/dev/null || return 1') bad=1 ;;
            *'=$(backup_file "'*'") || return 1') bad=1 ;;
            'if ! backup_file "'*'" >/dev/null; then') bad=1 ;;
            *) ;;
        esac
    done
    [ "$bad" -eq 0 ]
}
