#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Report generation module
# Copyright (c) 2024

# --- Report Generation ---

# Generate JSON report
report_generate_json() {
    local output_file="${1:-${VPSSEC_REPORTS}/summary.json}"
    local checks=$(state_get_checks)
    local score=$(calculate_score)
    local stats=$(get_check_stats)

    local os=$(detect_os)
    local os_version=$(detect_os_version)
    local hostname=$(hostname 2>/dev/null || uname -n)
    local virt=$(detect_virtualization)

    local modules_checked="${VPSSEC_INCLUDE:-all}"
    # Machine-readable form of the terminal's "partial score" warning;
    # stats.scored_total carries the denominator itself.
    local partial="false"
    score_is_partial && partial="true"

    # The audit runs on three families; hardening does not. Without these a
    # consumer cannot tell that every fix_id in the file is unreachable here.
    # Named for guide_mode, the thing actually gated, not for single fixes.
    local distro_family="${VPSSEC_DISTRO_FAMILY:-unknown}"
    local guide_supported="false"
    is_debian_based && guide_supported="true"

    # Completeness, so a consumer can tell "scanned everything" from "scanned
    # what survived". Guarded: unit tests exercise report.sh without engine.sh.
    local failed_modules_json="[]"
    if declare -p VPSSEC_MODULES_FAILED >/dev/null 2>&1 \
       && (( ${#VPSSEC_MODULES_FAILED[@]} > 0 )); then
        failed_modules_json=$(printf '%s\n' "${VPSSEC_MODULES_FAILED[@]}" \
            | jq -Rn '[inputs] | unique') || failed_modules_json="[]"
    fi

    # Built via jq so every string field is escaped: a hostname or os-release
    # value with a quote or control char would otherwise break the document.
    # score/stats/checks are already valid JSON, so they go in as --argjson.
    [[ -n "$score" ]]  || score=0
    [[ -n "$stats" ]]  || stats='{}'
    [[ -n "$checks" ]] || checks='[]'

    local json
    json=$(jq -n \
        --arg version "${VPSSEC_VERSION:-}" \
        --arg timestamp "$(date -Iseconds)" \
        --arg os "$os" \
        --arg os_version "$os_version" \
        --arg hostname "$hostname" \
        --arg virt "$virt" \
        --arg lang "${VPSSEC_LANG:-}" \
        --arg modules "$modules_checked" \
        --arg distro_family "$distro_family" \
        --argjson guide_supported "$guide_supported" \
        --argjson partial "$partial" \
        --argjson failed_modules "$failed_modules_json" \
        --argjson score "$score" \
        --argjson stats "$stats" \
        --argjson checks "$checks" \
        --argjson tmpl_fixes "$(fix_template_only_ids_json)" \
        '
        # Set ONLY where true: absence from FIX_TEMPLATE_ONLY is no evidence
        # that a fix is direct. $fid binds before the pipe because inside
        # `$tmpl_fixes | ...` the input is the array, not the check.
        ($checks | map(
            (.fix_id // "") as $fid
            | if $fid != "" and ($tmpl_fixes | index($fid))
              then . + {fix_type: "template_only"}
              else . end
        )) as $checks_typed
        | {
            meta: {
                version: $version,
                timestamp: $timestamp,
                os: $os,
                os_version: $os_version,
                distro_family: $distro_family,
                hostname: $hostname,
                virtualization: $virt,
                guide_supported: $guide_supported,
                lang: $lang,
                modules: $modules,
                partial_scope: $partial,
                complete: ($failed_modules | length == 0),
                modules_failed: $failed_modules
            },
            score: $score,
            stats: $stats,
            checks: $checks_typed
        }') || { log_error "Failed to build JSON report"; return 1; }

    write_file_atomic "$output_file" "$json"

    log_info "JSON report generated: $output_file"
    echo "$output_file"
}

# Generate Markdown report - organized by category
report_generate_markdown() {
    local output_file="${1:-${VPSSEC_REPORTS}/summary.md}"
    local checks=$(state_get_checks)
    local score=$(calculate_score)

    _check_metrics_refresh
    local high="${VPSSEC_METRICS[high]:-0}"
    local medium="${VPSSEC_METRICS[medium]:-0}"
    local low="${VPSSEC_METRICS[low]:-0}"
    local passed="${VPSSEC_METRICS[passed]:-0}"
    local info="${VPSSEC_METRICS[info]:-0}"
    local scored_total="${VPSSEC_METRICS[scored_total]:-0}"

    local os=$(detect_os)
    local os_version=$(detect_os_version)
    local hostname=$(hostname 2>/dev/null || uname -n)
    local modules_checked="${VPSSEC_INCLUDE:-all}"

    # Stated on every report, not only where hardening is unavailable: a row
    # that appears only in the bad case makes its absence mean "supported",
    # and this project has already decided once that absence is not evidence.
    local distro_family="${VPSSEC_DISTRO_FAMILY:-unknown}"
    local guide_state
    if is_debian_based; then
        guide_state=$(i18n 'report.guide_supported')
    else
        guide_state=$(i18n 'report.guide_unsupported')
    fi

    local score_basis
    if score_is_partial; then
        score_basis=$(i18n 'report.score_partial' "count=${scored_total}" "modules=${modules_checked}")
    else
        score_basis=$(i18n 'report.score_basis' "count=${scored_total}")
    fi

    cat > "$output_file" <<EOF
# $(i18n 'report.title')

**$(i18n 'preflight.virtualization' "type=$(detect_virtualization)")**

| $(i18n 'common.info') | |
|---|---|
| Hostname | ${hostname} |
| OS | ${os} ${os_version} |
| Distro Family | ${distro_family} |
| Hardening | ${guide_state} |
| Date | $(date '+%Y-%m-%d %H:%M:%S') |
| vpssec Version | ${VPSSEC_VERSION} |
| Modules | ${modules_checked} |

---

## $(i18n 'report.summary')

**$(i18n 'report.score'): ${score}/100**

${score_basis}

| $(i18n 'common.warning') | $(i18n 'common.info') |
|---|---|
| 🔴 $(i18n 'report.high_issues') | ${high} |
| 🟡 $(i18n 'report.medium_issues') | ${medium} |
| 🔵 $(i18n 'report.low_issues') | ${low} |
| 🟢 $(i18n 'report.passed_checks') | ${passed} |
| ⚪ $(i18n 'report.advisory_checks') | ${info} |

$(i18n 'report.info_note' "count=${info}")

---

## $(i18n 'report.high_issues')

EOF

    local label_info=$(i18n "common.info")
    local label_recommendations=$(i18n "report.recommendations")

    # One jq per section, never per (category x module). Heading levels:
    # ## section, ### category, #### finding — a finding at ### would be a
    # sibling of its own category and flatten the document.
    _md_section "$checks" high   "$label_info" "$label_recommendations" >> "$output_file"

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.medium_issues')

EOF

    _md_section "$checks" medium "$label_info" "$label_recommendations" >> "$output_file"

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.low_issues')

EOF

    _md_section "$checks" low    "$label_info" "$label_recommendations" >> "$output_file"

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.passed_checks')

EOF

    _md_section "$checks" passed "$label_info" "$label_recommendations" >> "$output_file"

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.next_steps')

EOF

    if ((high > 0)); then
        # Derived from the modules that actually produced high-severity
        # failures; a literal hint sends the user to the wrong modules.
        local high_modules
        high_modules=$(state_get_checks \
            | jq -r '[.[] | select(.status == "failed" and (.severity == "high" or .severity == "critical")) | .module] | unique | join(",")')
        # Fallback to a generic hint if the query returned nothing
        # (shouldn't happen when high > 0, but the caller's stats and
        # the JQ reality could theoretically disagree — be defensive).
        if [[ -z "$high_modules" ]]; then
            high_modules=""
        fi

        cat >> "$output_file" <<EOF
1. **$(i18n 'common.high')**: $(i18n 'guide.select_fixes')
   \`\`\`bash
   vpssec guide${high_modules:+ --include=$high_modules}
   \`\`\`

EOF
    fi

    cat >> "$output_file" <<EOF
2. $(i18n 'guide.rollback_available')
   \`\`\`bash
   vpssec rollback
   \`\`\`

---

*Generated by vpssec v${VPSSEC_VERSION} at $(date -Iseconds)*
EOF

    log_info "Markdown report generated: $output_file"
    echo "$output_file"
}

# Render one Markdown section grouped under ### category headings.
# Args: <checks-json> <high|medium|low|passed> <info-label> <recs-label>
# Order is categories, then modules, then emission — never group_by, it sorts.
_md_section() {
    local checks="$1"
    local kind="$2"
    local label_info="$3"
    local label_recs="$4"

    # [{cat: "<translated title>", modules: ["ssh","users"]}, ...]
    local groups
    groups=$(
        local category module first_cat=1 first_mod
        printf '['
        for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
            (( first_cat )) || printf ','
            first_cat=0
            printf '{"cat":%s,"modules":[' \
                "$(printf '%s' "$(i18n "category.${category}" 2>/dev/null || echo "$category")" | jq -Rs .)"
            first_mod=1
            for module in $(_get_category_modules "$category"); do
                (( first_mod )) || printf ','
                first_mod=0
                printf '"%s"' "$module"
            done
            printf ']}'
        done
        printf ']'
    )

    echo "$checks" | jq -r \
        --argjson groups "$groups" \
        --arg kind "$kind" \
        --arg info "$label_info" \
        --arg recs "$label_recs" \
        --argjson tmpl_fixes "$(fix_template_only_ids_json)" \
        --arg tmpl_label "$(i18n 'fix.template_only')" '
        . as $checks
        # One check -> one Markdown block ending in exactly one newline.
        # The note on the Fix ID line marks fixes that leave the finding
        # standing, so the report does not imply every Fix ID clears one.
        | def tmpl_note($c):
            if (($c.fix_id // "") != "") and ($tmpl_fixes | index($c.fix_id))
            then " _(\($tmpl_label))_"
            else "" end;
        def render($c):
            if $kind == "passed" then
                "- ✓ \($c.title)\n"
            elif $kind == "low" then
                "#### \($c.title)\n\n- **ID**: \($c.id)\n- **\($info)**: \($c.desc)\n- **\($recs)**: \($c.suggestion)\n"
            else
                "#### \($c.title)\n\n- **ID**: \($c.id)\n- **\($info)**: \($c.desc)\n- **\($recs)**: \($c.suggestion)\n- **Fix ID**: \($c.fix_id // "N/A")\(tmpl_note($c))\n"
            end;
        def matches($c):
            if $kind == "passed"
            then $c.status == "passed"
            else $c.status == "failed" and $c.severity == $kind
            end;
        # The join happens in jq: command substitution strips the trailing
        # newline, which glued the next heading onto the previous line.
        (if $kind == "passed" then "" else "\n" end) as $sep
        | [ $groups[]
            | .cat as $title
            | [ .modules[] as $m | $checks[] | select(.module == $m and matches(.)) | render(.) ]
            | select(length > 0)
            | "### \($title)\n\n" + join($sep) + "\n"
          ]
        | join("")
        # Leave exactly one trailing newline; the caller'"'"'s heredoc
        # supplies the blank line before the next "---".
        | sub("\n+$"; "\n")
    '
}

# Get modules for a category in the correct order
_get_category_modules() {
    local category="$1"
    local result=()

    for module in "${VPSSEC_MODULE_ORDER[@]}"; do
        if [[ "${VPSSEC_MODULE_CATEGORY[$module]:-}" == "$category" ]]; then
            result+=("$module")
        fi
    done

    echo "${result[@]}"
}

# _strip_ansi / _display_width / pad_to_width / truncate_to_width live
# in core/common.sh — the interactive menus need the same cell-accurate
# padding and are rendered before this file's functions are reachable.

# Render a single module's checks to an array of lines (clean style, no tree connectors)
# Usage: _render_module_clean <module> <checks_json> <col_width>
# Output: Lines are stored in REPLY_LINES array
_render_module_clean() {
    local module="$1"
    local checks="$2"
    local col_width="${3:-40}"

    REPLY_LINES=()

    local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")

    # Module header - bold cyan, simple style
    REPLY_LINES+=("${BOLD}${CYAN}${mod_title}${NC}")

    # ONE jq per module, emitting status/severity/title as TSV. Tab is safe:
    # create_check_json escapes control characters, so no field can hold one.
    local status severity title
    while IFS=$'\t' read -r status severity title; do
        [[ -z "$status" ]] && continue

        # Compared in DISPLAY cells: bash counts a CJK char as one code
        # point but it occupies two cells.
        local max_title_len=$((col_width - 6))
        if (( $(_display_width "$title") > max_title_len )); then
            local target=$(( max_title_len - 2 ))
            (( target < 0 )) && target=0
            # Shrink until it fits. Bash slicing is code-point based,
            # so re-measure each time rather than computing an index.
            while [[ -n "$title" ]] && (( $(_display_width "$title") > target )); do
                title="${title:0:-1}"
            done
            title="${title}.."
        fi

        # Simple indentation with status icon
        if [[ "$status" == "passed" ]]; then
            REPLY_LINES+=("  ${GREEN}✓${NC} ${title}")
        else
            case "$severity" in
                high)   REPLY_LINES+=("  ${RED}✗${NC} ${title}") ;;
                medium) REPLY_LINES+=("  ${YELLOW}●${NC} ${title}") ;;
                low)    REPLY_LINES+=("  ${BLUE}○${NC} ${title}") ;;
            esac
        fi
    done < <(echo "$checks" | jq -r --arg m "$module" \
        '.[] | select(.module == $m) | [.status, .severity, .title] | @tsv')
}

# Print two columns side by side (compact style)
_print_columns_clean() {
    local -n _left_arr=$1
    local -n _right_arr=$2
    local col_width="$3"

    local left_count=${#_left_arr[@]}
    local right_count=${#_right_arr[@]}
    local max_count=$((left_count > right_count ? left_count : right_count))

    local idx
    for ((idx=0; idx<max_count; idx++)); do
        local left_line=""
        local right_line=""

        if ((idx < left_count)); then
            left_line="${_left_arr[$idx]}"
        fi
        if ((idx < right_count)); then
            right_line="${_right_arr[$idx]}"
        fi

        # Padded in DISPLAY cells: ${#var} undercounts CJK and drifts
        # the separator right.
        local pad_needed=$(( col_width - $(_display_width "$left_line") ))
        local padding=""
        ((pad_needed > 0)) && padding=$(printf '%*s' "$pad_needed" '')

        if [[ -n "$right_line" ]]; then
            echo -e " ${left_line}${padding} ${DIM}│${NC} ${right_line}"
        else
            echo -e " ${left_line}"
        fi
    done
}

# Generate a horizontal line header for a category (compact style)
_print_category_header() {
    local title="$1"
    local total_width="${2:-70}"

    # Calculate line lengths: ── Title ────────────────
    # Use display cells (not code points) so CJK titles like "系统基础"
    # (4 code points / 8 cells) get the right number of trailing dashes.
    local title_len
    title_len=$(_display_width "$title")
    local prefix_len=2
    local suffix_len=$((total_width - prefix_len - title_len - 2))
    ((suffix_len < 3)) && suffix_len=3

    local prefix_line=$(printf '─%.0s' $(seq 1 $prefix_len))
    local suffix_line=$(printf '─%.0s' $(seq 1 $suffix_len))

    # Only one blank line before header, none after
    echo ""
    echo -e "${DIM}${prefix_line}${NC} ${BOLD}${MAGENTA}${title}${NC} ${DIM}${suffix_line}${NC}"
}

# Print detailed test results - dual column layout (compact style)
report_print_details() {
    local checks=$(state_get_checks)

    # Get terminal width, default to 100 if not available
    local term_width=${COLUMNS:-$(tput cols 2>/dev/null || echo 100)}
    local col_width=$(( (term_width - 10) / 2 ))
    ((col_width < 35)) && col_width=35
    ((col_width > 50)) && col_width=50

    local header_width=$((col_width * 2 + 6))
    ((header_width > term_width - 4)) && header_width=$((term_width - 4))

    # Which modules produced any check? One jq for the whole run,
    # instead of a `[.[] | select(.module == $m)] | length` per module
    # per category (21 spawns to answer a question one pass can answer).
    local -A _module_has_checks=()
    local _m
    while IFS= read -r _m; do
        [[ -n "$_m" ]] && _module_has_checks["$_m"]=1
    done < <(echo "$checks" | jq -r '[.[].module] | unique | .[]')

    # Iterate through categories in order
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        # Collect modules with results
        local -a active_modules=()
        for module in $category_modules; do
            if [[ -n "${_module_has_checks[$module]:-}" ]]; then
                active_modules+=("$module")
            fi
        done

        [[ ${#active_modules[@]} -eq 0 ]] && continue

        # Print category header with horizontal line
        _print_category_header "$category_title" "$header_width"

        local mod_count=${#active_modules[@]}

        if ((mod_count == 1)); then
            # Single module - simple output
            local module="${active_modules[0]}"
            _render_module_clean "$module" "$checks" "$col_width"
            for line in "${REPLY_LINES[@]}"; do
                echo -e " ${line}"
            done
        elif ((mod_count == 2)); then
            # Two modules - side by side
            _render_module_clean "${active_modules[0]}" "$checks" "$col_width"
            local -a left_lines=("${REPLY_LINES[@]}")

            _render_module_clean "${active_modules[1]}" "$checks" "$col_width"
            local -a right_lines=("${REPLY_LINES[@]}")

            _print_columns_clean left_lines right_lines "$col_width"
        else
            # More than 2 modules - pair them up
            local i=0
            while ((i < mod_count)); do
                # Add blank line between module pairs (not before first pair)
                ((i > 0)) && echo ""

                _render_module_clean "${active_modules[$i]}" "$checks" "$col_width"
                local -a left_lines=("${REPLY_LINES[@]}")

                if ((i + 1 < mod_count)); then
                    _render_module_clean "${active_modules[$((i+1))]}" "$checks" "$col_width"
                    local -a right_lines=("${REPLY_LINES[@]}")
                    _print_columns_clean left_lines right_lines "$col_width"
                else
                    # Odd module - print alone
                    for line in "${left_lines[@]}"; do
                        echo -e " ${line}"
                    done
                fi

                ((i += 2))
            done
        fi
    done

    echo ""
}

# Print terminal summary - compact format
report_print_summary() {
    local score=$(calculate_score)

    # Read the metrics directly instead of re-parsing get_check_stats'
    # JSON with four more jq calls — same numbers, no subprocesses.
    _check_metrics_refresh
    local high="${VPSSEC_METRICS[high]:-0}"
    local medium="${VPSSEC_METRICS[medium]:-0}"
    local low="${VPSSEC_METRICS[low]:-0}"
    local passed="${VPSSEC_METRICS[passed]:-0}"
    local info="${VPSSEC_METRICS[info]:-0}"
    local scored_total="${VPSSEC_METRICS[scored_total]:-0}"

    # Score bar
    local score_color
    if ((score >= 80)); then
        score_color="${GREEN}"
    elif ((score >= 60)); then
        score_color="${YELLOW}"
    else
        score_color="${RED}"
    fi

    print_msg "────────────────────────────────────────────────────────"
    print_msg ""
    print_msg "  ${BOLD}$(i18n 'report.score'):${NC} ${score_color}${BOLD}${score}/100${NC}"

    # The score is only comparable across runs over the same module set, so
    # say so and always print the denominator alongside it.
    if score_is_partial; then
        print_msg "  ${DIM}$(i18n 'report.score_partial' "count=${scored_total}" "modules=${VPSSEC_INCLUDE:-all}")${NC}"
    else
        print_msg "  ${DIM}$(i18n 'report.score_basis' "count=${scored_total}")${NC}"
    fi
    print_msg ""

    # Compact stats line
    local stats_line="  "
    if ((high > 0)); then
        stats_line+="${RED}●${NC} ${high} $(i18n 'common.high')  "
    fi
    if ((medium > 0)); then
        stats_line+="${YELLOW}●${NC} ${medium} $(i18n 'common.medium')  "
    fi
    if ((low > 0)); then
        stats_line+="${BLUE}●${NC} ${low} $(i18n 'common.low')  "
    fi
    stats_line+="${GREEN}●${NC} ${passed} $(i18n 'common.safe')"
    echo -e "$stats_line"

    # Advisory findings look identical to scoring ones in the body, so the
    # count that does NOT move the score has to be stated here.
    if ((info > 0)); then
        print_msg "  ${DIM}$(i18n 'report.info_note' "count=${info}")${NC}"
    fi
    print_msg ""

    # Severity legend. The four glyphs (✗ ● ○ ✓) were used throughout
    # the run with nothing anywhere explaining them — ● vs ○ in
    # particular gives a reader no clue which is worse.
    print_msg "  ${DIM}$(i18n 'report.legend'):${NC} ${RED}✗${NC} $(i18n 'common.high')  ${YELLOW}●${NC} $(i18n 'common.medium')  ${BLUE}○${NC} $(i18n 'common.low')  ${GREEN}✓${NC} $(i18n 'common.safe')"
    print_msg ""
}

# Generate SARIF. The whole document is ONE jq invocation; building it
# incrementally in bash is quadratic. Rules derive from ALL checks and are
# de-duplicated first-wins in encounter order, hence reduce, not unique_by.
report_generate_sarif() {
    local output_file="${1:-${VPSSEC_REPORTS}/summary.sarif}"
    local checks=$(state_get_checks)
    [[ -n "$checks" ]] || checks='[]'

    local hostname=$(hostname 2>/dev/null || uname -n)
    local distro_family="${VPSSEC_DISTRO_FAMILY:-unknown}"
    local guide_supported="false"
    is_debian_based && guide_supported="true"

    # Same completeness source as summary.json's meta.modules_failed.
    local failed_modules_json="[]"
    if declare -p VPSSEC_MODULES_FAILED >/dev/null 2>&1 \
       && (( ${#VPSSEC_MODULES_FAILED[@]} > 0 )); then
        failed_modules_json=$(printf '%s\n' "${VPSSEC_MODULES_FAILED[@]}" \
            | jq -Rn '[inputs] | unique') || failed_modules_json="[]"
    fi

    local sarif
    sarif=$(jq -n \
        --argjson checks "$checks" \
        --argjson tmpl_fixes "$(fix_template_only_ids_json)" \
        --arg     version "${VPSSEC_VERSION:-}" \
        --arg     host    "$hostname" \
        --arg     family  "$distro_family" \
        --argjson guide   "$guide_supported" \
        --argjson failed_modules "$failed_modules_json" \
        --arg     endtime "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
        def level:
          if   . == "high"   then "error"
          elif . == "medium" then "warning"
          elif . == "low"    then "note"
          else "none" end;
        def secsev:
          if   . == "high"   then "8.0"
          elif . == "medium" then "5.0"
          elif . == "low"    then "2.0"
          else "0.0" end;
        {
          "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
          "version": "2.1.0",
          "runs": [{
            "tool": {
              "driver": {
                "name": "vpssec",
                "version": $version,
                "informationUri": "https://github.com/Lynthar/CloudServer-Audit",
                "rules": (
                  reduce $checks[] as $c ({seen: {}, out: []};
                    if (.seen[$c.id] // false) then .
                    else
                      .seen[$c.id] = true
                      | .out += [{
                          "id":               $c.id,
                          "name":             $c.title,
                          "shortDescription": { "text": $c.title },
                          "fullDescription":  { "text": ($c.desc // "") },
                          "defaultConfiguration": { "level": ($c.severity | level) },
                          "properties": (
                            { "security-severity": ($c.severity | secsev) }
                            # Only where true: absence from FIX_TEMPLATE_ONLY is
                            # not evidence that a fix resolves its finding.
                            + (if (($c.fix_id // "") != "") and ($tmpl_fixes | index($c.fix_id))
                               then { "fixType": "template_only" } else {} end)
                          )
                        }]
                    end)
                  | .out
                )
              }
            },
            "results": [
              $checks[]
              | select(.status == "failed")
              | {
                  "ruleId":  .id,
                  "level":   (.severity | level),
                  "message": { "text": "\(.title). \(.desc // "")" },
                  "locations": [{
                    "physicalLocation": {
                      "artifactLocation": { "uri": $host, "uriBaseId": "ROOTPATH" }
                    },
                    "logicalLocations": [{ "name": .module, "kind": "module" }]
                  }],
                  "fixes": [{ "description": { "text": (.suggestion // "") } }]
                }
            ],
            # executionSuccessful is a FACT, not a constant: false whenever a
            # module failed, with the names in toolExecutionNotifications.
            "invocations": [{
              "executionSuccessful": ($failed_modules | length == 0),
              "endTimeUtc": $endtime,
              "toolExecutionNotifications": [
                $failed_modules[] | {
                  "level": "error",
                  "message": { "text": "module did not complete: \(.)" }
                }
              ]
            }],
            # Run-level property bag: every fix named in "fixes" above is
            # unreachable when guideSupported is false, and nothing else in
            # the document says so.
            "properties": {
              "distroFamily":   $family,
              "guideSupported": $guide
            }
          }]
        }') || { log_error "Failed to build SARIF report"; return 1; }

    write_file_atomic "$output_file" "$sarif" || return 1

    log_info "SARIF report generated: $output_file"
    echo "$output_file"
}

# Write all three report files. The report_generate_* functions return their
# output path on stdout, so their output MUST be captured, not left bare.
_report_write_files() {
    mkdir -p "${VPSSEC_REPORTS}"
    local rc=0
    report_generate_json     >/dev/null || rc=1
    report_generate_markdown >/dev/null || rc=1
    report_generate_sarif    >/dev/null || rc=1
    return $rc
}

# Generate all reports
report_generate_all() {
    if [[ "${VPSSEC_JSON_ONLY}" != "1" ]]; then
        # Print detailed results first
        report_print_details

        # Print summary to terminal
        report_print_summary

        # Ask user if they want to save reports
        print_msg "───────────────────────────────"
        print_msg ""

        local save_prompt=$(i18n 'report.save_prompt' 2>/dev/null || echo "Save report files?")
        if confirm "$save_prompt" "n"; then
            _report_write_files || print_warn "$(i18n 'report.save_failed')"

            print_msg ""
            # All three files are written, so all three are listed. The
            # .sarif was silently omitted here before, which read as "it
            # wasn't generated".
            print_msg "  $(i18n 'report.report_saved' "path=${VPSSEC_REPORTS}/summary.json")"
            print_msg "  $(i18n 'report.report_saved' "path=${VPSSEC_REPORTS}/summary.md")"
            print_msg "  $(i18n 'report.report_saved' "path=${VPSSEC_REPORTS}/summary.sarif")"
            print_msg ""
        fi
    else
        # Regenerate ALL three files, or a CI job shipping the Markdown or
        # SARIF publishes the previous run's data. Only the JSON goes to
        # stdout; write failure is FATAL and the old file is NEVER echoed.
        if ! _report_write_files; then
            # Direct echo, not print_error: print_msg suppresses ALL output
            # under --json-only, which would turn this fatal error into a
            # silent empty stdout. stderr keeps the JSON channel clean.
            echo "vpssec: report generation failed; refusing to emit a stale summary.json (see logs/vpssec.log)" >&2
            return 1
        fi
        cat "${VPSSEC_REPORTS}/summary.json"
    fi
}

