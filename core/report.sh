#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Report generation module
# Copyright (c) 2024

# ==============================================================================
# Report Generation
# ==============================================================================

# Generate JSON report
report_generate_json() {
    local output_file="${1:-${VPSSEC_REPORTS}/summary.json}"
    local checks=$(state_get_checks)
    local score=$(calculate_score)
    local stats=$(get_check_stats)

    local os=$(detect_os)
    local os_version=$(detect_os_version)
    local hostname=$(hostname)
    local virt=$(detect_virtualization)

    local modules_checked="${VPSSEC_INCLUDE:-all}"

    cat > "$output_file" <<EOF
{
  "meta": {
    "version": "${VPSSEC_VERSION}",
    "timestamp": "$(date -Iseconds)",
    "os": "${os}",
    "os_version": "${os_version}",
    "hostname": "${hostname}",
    "virtualization": "${virt}",
    "lang": "${VPSSEC_LANG}",
    "modules": "${modules_checked}"
  },
  "score": ${score},
  "stats": ${stats},
  "checks": ${checks}
}
EOF

    log_info "JSON report generated: $output_file"
    echo "$output_file"
}

# Generate Markdown report - organized by category
report_generate_markdown() {
    local output_file="${1:-${VPSSEC_REPORTS}/summary.md}"
    local checks=$(state_get_checks)
    local score=$(calculate_score)
    local stats=$(get_check_stats)

    local high=$(echo "$stats" | jq '.high')
    local medium=$(echo "$stats" | jq '.medium')
    local low=$(echo "$stats" | jq '.low')
    local passed=$(echo "$stats" | jq '.passed')

    local os=$(detect_os)
    local os_version=$(detect_os_version)
    local hostname=$(hostname)
    local modules_checked="${VPSSEC_INCLUDE:-all}"

    cat > "$output_file" <<EOF
# $(i18n 'report.title')

**$(i18n 'preflight.virtualization' "type=$(detect_virtualization)")**

| $(i18n 'common.info') | |
|---|---|
| Hostname | ${hostname} |
| OS | ${os} ${os_version} |
| Date | $(date '+%Y-%m-%d %H:%M:%S') |
| vpssec Version | ${VPSSEC_VERSION} |
| Modules | ${modules_checked} |

---

## $(i18n 'report.summary')

**$(i18n 'report.score'): ${score}/100**

| $(i18n 'common.warning') | $(i18n 'common.info') |
|---|---|
| 🔴 $(i18n 'report.high_issues') | ${high} |
| 🟡 $(i18n 'report.medium_issues') | ${medium} |
| 🔵 $(i18n 'report.low_issues') | ${low} |
| 🟢 $(i18n 'report.passed_checks') | ${passed} |

---

## $(i18n 'report.high_issues')

EOF

    local label_info=$(i18n "common.info")
    local label_recommendations=$(i18n "report.recommendations")

    # High severity issues - organized by category
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        local category_highs=""
        for module in $category_modules; do
            local mod_highs=$(echo "$checks" | jq -r --arg m "$module" --arg info "$label_info" --arg recs "$label_recommendations" \
                '.[] | select(.module == $m and .status == "failed" and .severity == "high") | "### \(.title)\n\n- **ID**: \(.id)\n- **\($info)**: \(.desc)\n- **\($recs)**: \(.suggestion)\n- **Fix ID**: \(.fix_id)\n"')
            if [[ -n "$mod_highs" ]]; then
                category_highs+="$mod_highs"
            fi
        done

        if [[ -n "$category_highs" ]]; then
            echo "### ${category_title}" >> "$output_file"
            echo "" >> "$output_file"
            echo "$category_highs" >> "$output_file"
        fi
    done

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.medium_issues')

EOF

    # Medium severity issues - organized by category
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        local category_mediums=""
        for module in $category_modules; do
            local mod_mediums=$(echo "$checks" | jq -r --arg m "$module" --arg info "$label_info" --arg recs "$label_recommendations" \
                '.[] | select(.module == $m and .status == "failed" and .severity == "medium") | "### \(.title)\n\n- **ID**: \(.id)\n- **\($info)**: \(.desc)\n- **\($recs)**: \(.suggestion)\n- **Fix ID**: \(.fix_id // "N/A")\n"')
            if [[ -n "$mod_mediums" ]]; then
                category_mediums+="$mod_mediums"
            fi
        done

        if [[ -n "$category_mediums" ]]; then
            echo "### ${category_title}" >> "$output_file"
            echo "" >> "$output_file"
            echo "$category_mediums" >> "$output_file"
        fi
    done

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.low_issues')

EOF

    # Low severity issues - organized by category
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        local category_lows=""
        for module in $category_modules; do
            local mod_lows=$(echo "$checks" | jq -r --arg m "$module" --arg info "$label_info" --arg recs "$label_recommendations" \
                '.[] | select(.module == $m and .status == "failed" and .severity == "low") | "### \(.title)\n\n- **ID**: \(.id)\n- **\($info)**: \(.desc)\n- **\($recs)**: \(.suggestion)\n"')
            if [[ -n "$mod_lows" ]]; then
                category_lows+="$mod_lows"
            fi
        done

        if [[ -n "$category_lows" ]]; then
            echo "### ${category_title}" >> "$output_file"
            echo "" >> "$output_file"
            echo "$category_lows" >> "$output_file"
        fi
    done

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.passed_checks')

EOF

    # Passed checks - organized by category
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        local category_passed=""
        for module in $category_modules; do
            local mod_passed=$(echo "$checks" | jq -r --arg m "$module" \
                '.[] | select(.module == $m and .status == "passed") | "- ✓ \(.title)"')
            if [[ -n "$mod_passed" ]]; then
                category_passed+="$mod_passed"$'\n'
            fi
        done

        if [[ -n "$category_passed" ]]; then
            echo "### ${category_title}" >> "$output_file"
            echo "" >> "$output_file"
            echo "$category_passed" >> "$output_file"
        fi
    done

    cat >> "$output_file" <<EOF

---

## $(i18n 'report.next_steps')

EOF

    if ((high > 0)); then
        # Derive the --include= hint from the actual set of modules
        # that produced high-severity failed checks. The previous
        # literal `--include=ssh,ufw` was misleading when the high
        # severity items were elsewhere (kernel, webapp, docker, etc.)
        # and encouraged the user to skip the modules that actually
        # needed attention.
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

# Strip ANSI escape codes for calculating visible width
_strip_ansi() {
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g'
}

# Get visible string length (without ANSI codes)
_visible_len() {
    local stripped=$(_strip_ansi "$1")
    echo ${#stripped}
}

# Get DISPLAY column width (terminal cells) of a string after stripping
# ANSI codes. CJK Han / Hiragana / Katakana / fullwidth forms render as
# 2 cells each; bash `${#str}` counts code points, so a string like
# "✓ 操作系统支持" (8 code points) actually renders as 14 cells. Using
# the wrong count for column padding made the right-hand `│` separator
# zigzag whenever rows mixed ASCII-heavy and CJK-heavy content.
#
# Strategy: prefer python3's unicodedata.east_asian_width (accurate,
# handles fullwidth / wide / ambiguous / emoji); fall back to a pure
# UTF-8 byte heuristic otherwise.
#   - 1-byte (ASCII)            : 1 cell
#   - 2-byte (Latin-ext / Greek): 1 cell
#   - 3-byte starting with E2   : 1 cell  (Dingbats ✓, Geometric Shapes ●,
#                                          General Punctuation, etc. — all narrow)
#   - 3-byte starting with E3-E9: 2 cells (CJK Unified, kana, fullwidth)
#   - 4-byte (CJK Ext B+, emoji): 2 cells
# This heuristic is correct for the strings vpssec actually emits in
# zh_CN / en_US (no Indic, no Tibetan, no rare scripts). Off by one
# only for unusual symbols outside the project's vocabulary.
_display_width() {
    local s
    s=$(_strip_ansi "$1")
    [[ -z "$s" ]] && { echo 0; return; }

    if command -v python3 &>/dev/null; then
        python3 - "$s" <<'PYEOF' 2>/dev/null && return
import sys, unicodedata
s = sys.argv[1]
print(sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s))
PYEOF
    fi

    # Pure-bash fallback (no python3): walk the UTF-8 byte stream.
    local n_total n_cjk n_e2 n_2byte
    n_total=$(printf '%s' "$s" | wc -c)
    n_cjk=$(printf '%s' "$s" | LC_ALL=C grep -oE $'[\xe3-\xe9]' | wc -l)
    n_e2=$(printf '%s' "$s" | LC_ALL=C grep -oE $'\xe2[\x80-\xbf][\x80-\xbf]' | wc -l)
    n_2byte=$(printf '%s' "$s" | LC_ALL=C grep -oE $'[\xc2-\xdf][\x80-\xbf]' | wc -l)
    # cells = bytes − (1 saved per E3-E9 wide) − (2 saved per E2 narrow-multibyte) − (1 saved per 2-byte char)
    echo $(( n_total - n_cjk - 2 * n_e2 - n_2byte ))
}

# Render a single module's checks to an array of lines (clean style, no tree connectors)
# Usage: _render_module_clean <module> <checks_json> <col_width>
# Output: Lines are stored in REPLY_LINES array
_render_module_clean() {
    local module="$1"
    local checks="$2"
    local col_width="${3:-40}"

    REPLY_LINES=()

    local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
    local mod_checks=$(echo "$checks" | jq -c --arg m "$module" '[.[] | select(.module == $m)]')

    # Module header - bold cyan, simple style
    REPLY_LINES+=("${BOLD}${CYAN}${mod_title}${NC}")

    # Get checks
    local -a check_items=()
    while IFS= read -r check; do
        [[ -z "$check" ]] && continue
        check_items+=("$check")
    done < <(echo "$mod_checks" | jq -c '.[]')

    for check in "${check_items[@]}"; do
        local status=$(echo "$check" | jq -r '.status')
        local severity=$(echo "$check" | jq -r '.severity')
        local title=$(echo "$check" | jq -r '.title')

        # Truncate title if too long. Compare against DISPLAY cells so
        # CJK titles (where each char is 2 cells but bash counts 1
        # code point) get truncated correctly instead of overflowing
        # the column. Slice in a loop because bash string slicing is
        # code-point-based, not cell-based.
        local max_title_len=$((col_width - 6))
        local vis_title
        vis_title=$(_strip_ansi "$title")
        local vis_w
        vis_w=$(_display_width "$vis_title")
        if (( vis_w > max_title_len )); then
            local target=$(( max_title_len - 2 ))
            (( target < 0 )) && target=0
            local trial="$vis_title"
            # Shrink until it fits. For pure-ASCII titles this hits
            # the right length in one or two iterations; for CJK
            # titles each shrink saves 2 cells.
            while (( $(_display_width "$trial") > target )); do
                trial="${trial:0:-1}"
                [[ -z "$trial" ]] && break
            done
            title="${trial}.."
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
    done
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

        # Pad left column to fixed width using DISPLAY cells, not code
        # points. ${#left_visible} undercounts CJK characters (1 code
        # point but 2 display cells), which made the ` │` separator
        # drift right on CJK-heavy rows.
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

    # Iterate through categories in order
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        # Collect modules with results
        local -a active_modules=()
        for module in $category_modules; do
            local mod_check_count=$(echo "$checks" | jq --arg m "$module" '[.[] | select(.module == $m)] | length')
            if ((mod_check_count > 0)); then
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
    local checks=$(state_get_checks)
    local score=$(calculate_score)
    local stats=$(get_check_stats)

    local high=$(echo "$stats" | jq '.high')
    local medium=$(echo "$stats" | jq '.medium')
    local low=$(echo "$stats" | jq '.low')
    local passed=$(echo "$stats" | jq '.passed')

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
    print_msg ""
}

# Generate SARIF report (for CI/CD integration)
report_generate_sarif() {
    local output_file="${1:-${VPSSEC_REPORTS}/summary.sarif}"
    local checks=$(state_get_checks)

    local os=$(detect_os)
    local os_version=$(detect_os_version)
    local hostname=$(hostname)

    # Build results array
    local results="[]"
    while read -r check; do
        local id=$(echo "$check" | jq -r '.id')
        local severity=$(echo "$check" | jq -r '.severity')
        local status=$(echo "$check" | jq -r '.status')
        local title=$(echo "$check" | jq -r '.title')
        local desc=$(echo "$check" | jq -r '.desc // ""')
        local suggestion=$(echo "$check" | jq -r '.suggestion // ""')
        local module=$(echo "$check" | jq -r '.module')

        # Map severity to SARIF level
        local level
        case "$severity" in
            high)   level="error" ;;
            medium) level="warning" ;;
            low)    level="note" ;;
            *)      level="none" ;;
        esac

        # Only include failed checks. Build the JSON with `jq -n` so
        # characters in any interpolated field (`"`, `\`, newline, CR,
        # control chars) are escaped correctly; the previous heredoc
        # path produced invalid JSON whenever a title contained a
        # quote or a command-output snippet contained CR.
        if [[ "$status" == "failed" ]]; then
            local result
            # `--arg module ...` would create a jq variable named
            # `$module`, which jq 1.7.0+ rejects because `module` is
            # a reserved word (modules feature). Use `--arg mod` so
            # the injected variable is `$mod` instead. See the same
            # fix in core/common.sh's create_check_json.
            result=$(jq -n \
                --arg id         "$id" \
                --arg level      "$level" \
                --arg message    "$title. $desc" \
                --arg host       "$hostname" \
                --arg mod        "$module" \
                --arg suggestion "$suggestion" \
                '{
                    ruleId: $id,
                    level: $level,
                    message: { text: $message },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: {
                                uri: $host,
                                uriBaseId: "ROOTPATH"
                            }
                        },
                        logicalLocations: [{
                            name: $mod,
                            kind: "module"
                        }]
                    }],
                    fixes: [{
                        description: { text: $suggestion }
                    }]
                }')
            results=$(echo "$results" | jq --argjson r "$result" '. += [$r]')
        fi
    done < <(echo "$checks" | jq -c '.[]')

    # Build rules array
    local rules="[]"
    while read -r check; do
        local id=$(echo "$check" | jq -r '.id')
        local severity=$(echo "$check" | jq -r '.severity')
        local title=$(echo "$check" | jq -r '.title')
        local desc=$(echo "$check" | jq -r '.desc // ""')

        local level
        case "$severity" in
            high)   level="error" ;;
            medium) level="warning" ;;
            low)    level="note" ;;
            *)      level="none" ;;
        esac

        # Same JSON-escaping concern as the results block above — use
        # `jq -n` instead of a heredoc so special characters in title
        # or desc don't break the SARIF document.
        local sec_sev
        case "$severity" in
            high)   sec_sev="8.0" ;;
            medium) sec_sev="5.0" ;;
            low)    sec_sev="2.0" ;;
            *)      sec_sev="0.0" ;;
        esac
        local rule
        rule=$(jq -n \
            --arg id      "$id" \
            --arg name    "$title" \
            --arg desc    "$desc" \
            --arg level   "$level" \
            --arg sec_sev "$sec_sev" \
            '{
                id: $id,
                name: $name,
                shortDescription: { text: $name },
                fullDescription:  { text: $desc },
                defaultConfiguration: { level: $level },
                properties: { "security-severity": $sec_sev }
            }')
        # Check if rule already exists
        if ! echo "$rules" | jq -e --arg id "$id" '.[] | select(.id == $id)' &>/dev/null; then
            rules=$(echo "$rules" | jq --argjson r "$rule" '. += [$r]')
        fi
    done < <(echo "$checks" | jq -c '.[]')

    # Generate full SARIF document
    cat > "$output_file" <<EOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "vpssec",
        "version": "${VPSSEC_VERSION}",
        "informationUri": "https://github.com/Lynthar/CloudServer-Audit",
        "rules": ${rules}
      }
    },
    "results": ${results},
    "invocations": [{
      "executionSuccessful": true,
      "endTimeUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }]
  }]
}
EOF

    log_info "SARIF report generated: $output_file"
    echo "$output_file"
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
            mkdir -p "${VPSSEC_REPORTS}"
            report_generate_json
            report_generate_markdown
            report_generate_sarif

            print_msg ""
            print_msg "  $(i18n 'report.report_saved' "path=${VPSSEC_REPORTS}/summary.json")"
            print_msg "  $(i18n 'report.report_saved' "path=${VPSSEC_REPORTS}/summary.md")"
            print_msg ""
        fi
    else
        # JSON only mode - always generate and output JSON
        mkdir -p "${VPSSEC_REPORTS}"
        report_generate_json
        cat "${VPSSEC_REPORTS}/summary.json"
    fi
}

# Print a single check result to terminal
report_print_check() {
    local check_json="$1"

    local id=$(echo "$check_json" | jq -r '.id')
    local severity=$(echo "$check_json" | jq -r '.severity')
    local status=$(echo "$check_json" | jq -r '.status')
    local title=$(echo "$check_json" | jq -r '.title')
    local desc=$(echo "$check_json" | jq -r '.desc')

    if [[ "$status" == "passed" ]]; then
        print_ok "$title"
    else
        print_severity "$severity" "$title"
        if [[ -n "$desc" && "$desc" != "null" ]]; then
            print_msg "    ${DIM}${desc}${NC}"
        fi
    fi
}
