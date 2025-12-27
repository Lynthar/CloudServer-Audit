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
        cat >> "$output_file" <<EOF
1. **$(i18n 'common.high')**: $(i18n 'guide.select_fixes')
   \`\`\`bash
   vpssec guide --include=ssh,ufw
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

# Render a single module's checks to an array of lines
# Usage: _render_module_lines <module> <checks_json> <is_last_in_col> <col_width>
# Output: Lines are stored in REPLY_LINES array
_render_module_lines() {
    local module="$1"
    local checks="$2"
    local is_last="$3"
    local col_width="${4:-40}"

    REPLY_LINES=()

    local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
    local mod_checks=$(echo "$checks" | jq -c --arg m "$module" '[.[] | select(.module == $m)]')

    # Module header
    local mod_prefix="├─"
    local check_line_prefix="│  "
    if [[ "$is_last" == "1" ]]; then
        mod_prefix="└─"
        check_line_prefix="   "
    fi

    REPLY_LINES+=("${mod_prefix} ${BOLD}${CYAN}${mod_title}${NC}")

    # Get checks
    local -a check_items=()
    while IFS= read -r check; do
        [[ -z "$check" ]] && continue
        check_items+=("$check")
    done < <(echo "$mod_checks" | jq -c '.[]')

    local check_count=${#check_items[@]}
    local check_idx=0

    for check in "${check_items[@]}"; do
        ((check_idx++)) || true

        local status=$(echo "$check" | jq -r '.status')
        local severity=$(echo "$check" | jq -r '.severity')
        local title=$(echo "$check" | jq -r '.title')
        local check_id=$(echo "$check" | jq -r '.id')

        # Truncate title if too long
        local max_title_len=$((col_width - 8))
        local vis_title=$(_strip_ansi "$title")
        if ((${#vis_title} > max_title_len)); then
            title="${vis_title:0:$((max_title_len-2))}.."
        fi

        local check_prefix="${check_line_prefix}├─"
        local hint_prefix="${check_line_prefix}│  "
        if ((check_idx == check_count)); then
            check_prefix="${check_line_prefix}└─"
            hint_prefix="${check_line_prefix}   "
        fi

        if [[ "$status" == "passed" ]]; then
            REPLY_LINES+=("${check_prefix} ${GREEN}✓${NC} ${title}")
        else
            case "$severity" in
                high)   REPLY_LINES+=("${check_prefix} ${RED}✗${NC} ${title}") ;;
                medium) REPLY_LINES+=("${check_prefix} ${YELLOW}●${NC} ${title}") ;;
                low)    REPLY_LINES+=("${check_prefix} ${BLUE}○${NC} ${title}") ;;
            esac
        fi
    done
}

# Print two columns side by side
_print_dual_columns() {
    local -n _left_arr=$1
    local -n _right_arr=$2
    local col_width="$3"
    local cat_continued="$4"  # Whether category continues below

    local left_count=${#_left_arr[@]}
    local right_count=${#_right_arr[@]}
    local max_count=$((left_count > right_count ? left_count : right_count))

    local prefix="│  "
    [[ "$cat_continued" != "1" ]] && prefix="   "

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

        # Pad left column to fixed width
        local left_visible=$(_strip_ansi "$left_line")
        local pad_needed=$((col_width - ${#left_visible}))
        local padding=""
        ((pad_needed > 0)) && padding=$(printf '%*s' "$pad_needed" '')

        if [[ -n "$right_line" ]]; then
            echo -e "${prefix}${left_line}${padding}${DIM}│${NC} ${right_line}"
        else
            echo -e "${prefix}${left_line}"
        fi
    done
}

# Print detailed test results - dual column layout
report_print_details() {
    local checks=$(state_get_checks)
    local total_categories=${#VPSSEC_CATEGORY_ORDER[@]}
    local cat_idx=0

    # Get terminal width, default to 100 if not available
    local term_width=${COLUMNS:-$(tput cols 2>/dev/null || echo 100)}
    local col_width=$(( (term_width - 10) / 2 ))
    ((col_width < 35)) && col_width=35
    ((col_width > 50)) && col_width=50

    print_msg ""

    # Iterate through categories in order
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        ((cat_idx++)) || true
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

        # Category connector
        local cat_prefix="├─"
        local cat_continued="1"
        if ((cat_idx == total_categories)); then
            cat_prefix="└─"
            cat_continued="0"
        fi

        # Print category header
        print_msg "${BOLD}${MAGENTA}${cat_prefix} ${category_title}${NC}"

        local mod_count=${#active_modules[@]}

        if ((mod_count == 1)); then
            # Single module - simple output
            local module="${active_modules[0]}"
            _render_module_lines "$module" "$checks" "1" "$col_width"
            local prefix="│  "
            [[ "$cat_continued" != "1" ]] && prefix="   "
            for line in "${REPLY_LINES[@]}"; do
                echo -e "${prefix}${line}"
            done
        elif ((mod_count == 2)); then
            # Two modules - side by side
            _render_module_lines "${active_modules[0]}" "$checks" "1" "$col_width"
            local -a left_lines=("${REPLY_LINES[@]}")

            _render_module_lines "${active_modules[1]}" "$checks" "1" "$col_width"
            local -a right_lines=("${REPLY_LINES[@]}")

            _print_dual_columns left_lines right_lines "$col_width" "$cat_continued"
        else
            # More than 2 modules - pair them up
            local i=0
            while ((i < mod_count)); do
                local is_last_pair="0"
                ((i + 2 >= mod_count)) && is_last_pair="1"

                _render_module_lines "${active_modules[$i]}" "$checks" "$is_last_pair" "$col_width"
                local -a left_lines=("${REPLY_LINES[@]}")

                if ((i + 1 < mod_count)); then
                    _render_module_lines "${active_modules[$((i+1))]}" "$checks" "$is_last_pair" "$col_width"
                    local -a right_lines=("${REPLY_LINES[@]}")
                    _print_dual_columns left_lines right_lines "$col_width" "$cat_continued"
                else
                    # Odd module - print alone
                    local prefix="│  "
                    [[ "$cat_continued" != "1" ]] && prefix="   "
                    for line in "${left_lines[@]}"; do
                        echo -e "${prefix}${line}"
                    done
                fi

                ((i += 2))
            done
        fi
    done

    print_msg ""
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

        # Only include failed checks
        if [[ "$status" == "failed" ]]; then
            local result=$(cat <<EOF
{
  "ruleId": "$id",
  "level": "$level",
  "message": {
    "text": "$title. $desc"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {
        "uri": "$hostname",
        "uriBaseId": "ROOTPATH"
      }
    },
    "logicalLocations": [{
      "name": "$module",
      "kind": "module"
    }]
  }],
  "fixes": [{
    "description": {
      "text": "$suggestion"
    }
  }]
}
EOF
)
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

        local rule=$(cat <<EOF
{
  "id": "$id",
  "name": "$title",
  "shortDescription": {
    "text": "$title"
  },
  "fullDescription": {
    "text": "$desc"
  },
  "defaultConfiguration": {
    "level": "$level"
  },
  "properties": {
    "security-severity": "$(case $severity in high) echo "8.0";; medium) echo "5.0";; low) echo "2.0";; *) echo "0.0";; esac)"
  }
}
EOF
)
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
        "informationUri": "https://github.com/vpssec/vpssec",
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
