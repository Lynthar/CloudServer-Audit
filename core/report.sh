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

    local security_level="${VPSSEC_SECURITY_LEVEL:-standard}"

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
    "security_level": "${security_level}"
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
    local security_level="${VPSSEC_SECURITY_LEVEL:-standard}"

    # Get localized level name
    local level_name
    case "$security_level" in
        basic)    level_name=$(i18n 'level.basic' 2>/dev/null || echo "Basic") ;;
        standard) level_name=$(i18n 'level.standard' 2>/dev/null || echo "Standard") ;;
        strict)   level_name=$(i18n 'level.strict' 2>/dev/null || echo "Strict") ;;
        *)        level_name="$security_level" ;;
    esac

    cat > "$output_file" <<EOF
# $(i18n 'report.title')

**$(i18n 'preflight.virtualization' "type=$(detect_virtualization)")**

| $(i18n 'common.info') | |
|---|---|
| Hostname | ${hostname} |
| OS | ${os} ${os_version} |
| Date | $(date '+%Y-%m-%d %H:%M:%S') |
| vpssec Version | ${VPSSEC_VERSION} |
| Security Level | ${level_name} |

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

# Print detailed test results (before summary) - organized by category
report_print_details() {
    local checks=$(state_get_checks)

    # Iterate through categories in order
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        # Check if any modules in this category have results
        local has_results=0
        for module in $category_modules; do
            local mod_check_count=$(echo "$checks" | jq --arg m "$module" '[.[] | select(.module == $m)] | length')
            if ((mod_check_count > 0)); then
                has_results=1
                break
            fi
        done

        [[ "$has_results" == "0" ]] && continue

        # Print category header
        print_msg ""
        print_msg "${BOLD}${MAGENTA}━━━ ${category_title} ━━━${NC}"

        # Print modules in this category
        for module in $category_modules; do
            local mod_checks=$(echo "$checks" | jq -c --arg m "$module" '[.[] | select(.module == $m)]')
            local mod_check_count=$(echo "$mod_checks" | jq 'length')

            [[ "$mod_check_count" == "0" ]] && continue

            local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
            print_msg ""
            print_msg "${BOLD}${CYAN}▶ ${mod_title}${NC}"

            # Get checks for this module
            echo "$mod_checks" | jq -c '.[]' | while IFS= read -r check; do
                [[ -z "$check" ]] && continue

                local status=$(echo "$check" | jq -r '.status')
                local severity=$(echo "$check" | jq -r '.severity')
                local title=$(echo "$check" | jq -r '.title')

                if [[ "$status" == "passed" ]]; then
                    echo -e "  ${GREEN}✓${NC} ${title}"
                else
                    case "$severity" in
                        high)   echo -e "  ${RED}✗${NC} ${title}" ;;
                        medium) echo -e "  ${YELLOW}●${NC} ${title}" ;;
                        low)    echo -e "  ${BLUE}○${NC} ${title}" ;;
                    esac
                fi
            done
        done
    done

    print_msg ""
}

# Print terminal summary - organized by category
report_print_summary() {
    local checks=$(state_get_checks)
    local score=$(calculate_score)
    local stats=$(get_check_stats)

    local high=$(echo "$stats" | jq '.high')
    local medium=$(echo "$stats" | jq '.medium')
    local low=$(echo "$stats" | jq '.low')
    local passed=$(echo "$stats" | jq '.passed')

    local security_level="${VPSSEC_SECURITY_LEVEL:-standard}"

    # Get localized level name
    local level_name
    case "$security_level" in
        basic)    level_name=$(i18n 'level.basic' 2>/dev/null || echo "Basic") ;;
        standard) level_name=$(i18n 'level.standard' 2>/dev/null || echo "Standard") ;;
        strict)   level_name=$(i18n 'level.strict' 2>/dev/null || echo "Strict") ;;
        *)        level_name="$security_level" ;;
    esac

    print_header "$(i18n 'report.summary')"

    # Score bar
    local score_color
    if ((score >= 80)); then
        score_color="${GREEN}"
    elif ((score >= 60)); then
        score_color="${YELLOW}"
    else
        score_color="${RED}"
    fi

    print_msg ""
    print_msg "  ${BOLD}$(i18n 'report.score'):${NC} ${score_color}${score}/100${NC}  ${DIM}(${level_name})${NC}"
    print_msg ""

    # Category and module summary - organized by category
    for category in "${VPSSEC_CATEGORY_ORDER[@]}"; do
        local category_title=$(i18n "category.${category}" 2>/dev/null || echo "$category")
        local category_modules=$(_get_category_modules "$category")

        # Check if any modules in this category have results
        local has_results=0
        for module in $category_modules; do
            local mod_check_count=$(echo "$checks" | jq --arg m "$module" '[.[] | select(.module == $m)] | length')
            if ((mod_check_count > 0)); then
                has_results=1
                break
            fi
        done

        [[ "$has_results" == "0" ]] && continue

        # Print category header (subtle)
        print_msg "  ${DIM}── ${category_title} ──${NC}"

        # Print modules in this category
        for module in $category_modules; do
            local mod_checks=$(echo "$checks" | jq --arg m "$module" '[.[] | select(.module == $m)]')
            local mod_check_count=$(echo "$mod_checks" | jq 'length')

            [[ "$mod_check_count" == "0" ]] && continue

            local mod_high=$(echo "$mod_checks" | jq '[.[] | select(.status == "failed" and .severity == "high")] | length')
            local mod_medium=$(echo "$mod_checks" | jq '[.[] | select(.status == "failed" and .severity == "medium")] | length')
            local mod_low=$(echo "$mod_checks" | jq '[.[] | select(.status == "failed" and .severity == "low")] | length')
            local mod_passed=$(echo "$mod_checks" | jq '[.[] | select(.status == "passed")] | length')

            local status_icon
            local status_color
            if ((mod_high > 0)); then
                status_icon="🔴"
                status_color="${RED}"
            elif ((mod_medium > 0)); then
                status_icon="🟡"
                status_color="${YELLOW}"
            elif ((mod_low > 0)); then
                status_icon="🔵"
                status_color="${BLUE}"
            else
                status_icon="🟢"
                status_color="${GREEN}"
            fi

            local mod_title=$(i18n "${module}.title" 2>/dev/null || echo "$module")
            local mod_status=""

            if ((mod_high > 0)); then
                mod_status+="${mod_high} $(i18n 'common.high') "
            fi
            if ((mod_medium > 0)); then
                mod_status+="${mod_medium} $(i18n 'common.medium') "
            fi
            if ((mod_low > 0)); then
                mod_status+="${mod_low} $(i18n 'common.low') "
            fi
            if [[ -z "$mod_status" ]]; then
                mod_status="$(i18n 'common.safe')"
            fi

            printf "    %-18s %s " "${mod_title}" "${status_icon}"
            echo -e "${status_color}${mod_status}${NC}"
        done

        print_msg ""
    done
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
