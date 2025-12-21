# vpssec - VPS Security Check & Hardening Tool

English | [简体中文](README_zh.md)

A VPS security auditing and hardening script designed for individuals and small-scale operations.

## Features

- **Security Audit Mode (audit)**: Read-only security checks with Markdown + JSON + SARIF report output
- **Guided Hardening Mode (guide)**: Interactive security hardening wizard with step-by-step guidance
- **One-Click Rollback (rollback)**: Automatic backup before changes with quick recovery capability
- **Multi-language Support**: Chinese/English interface with i18n support
- **Modular Design**: Easily extendable security check modules

## Supported Systems

- Debian 12 / 13
- Ubuntu 22.04 / 24.04

## Quick Start

### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

### Manual Installation

```bash
git clone https://github.com/Lynthar/CloudServer-Audit.git
cd CloudServer-Audit
sudo ./vpssec audit
```

## Usage

### Security Audit (Read-Only)

```bash
sudo ./vpssec audit
```

Generates security reports in:
- `reports/summary.md` - Markdown report
- `reports/summary.json` - JSON format
- `reports/summary.sarif` - SARIF format (for CI/CD integration)

### Interactive Hardening

```bash
sudo ./vpssec guide
```

Provides an interactive interface to:
1. Review detected security issues
2. Select items to fix
3. Preview changes before applying
4. Execute fixes with automatic rollback points

### Rollback Changes

```bash
sudo ./vpssec rollback
```

Restore previous configurations from automatic backups.

### Check Status

```bash
sudo ./vpssec status
```

View current security score and status.

## Security Modules

### Core Modules (Enabled by Default)

| Module | Description |
|--------|-------------|
| `preflight` | Environment pre-checks (OS, network, dependencies) |
| `cloud` | Cloud provider detection and monitoring agent audit |
| `users` | User security audit (UID 0, empty passwords, suspicious accounts) |
| `ssh` | SSH hardening (password auth, root login, key auth) |
| `ufw` | Firewall configuration (UFW status, rules) |
| `fail2ban` | Fail2ban installation and SSH jail configuration |
| `update` | System updates (security updates, unattended-upgrades) |
| `docker` | Docker security (privileged containers, exposed ports) |
| `nginx` | Nginx catchall (prevent cert/hostname leakage) |
| `baseline` | Baseline hardening (AppArmor, unused services) |
| `logging` | Logging & audit (journald, auditd, logrotate) |
| `kernel` | Kernel hardening (ASLR, sysctl network/security params) |
| `filesystem` | Filesystem security (SUID/SGID, permissions, umask) |

### Optional Modules

| Module | Description |
|--------|-------------|
| `cloudflared` | Cloudflare Tunnel configuration checks |
| `backup` | Backup tool detection and template generation |
| `alerts` | Webhook/email alert configuration |

## Security Levels

vpssec supports three security levels that control check scope and fix behavior:

| Level | Check Scope | Fix Behavior |
|-------|-------------|--------------|
| `basic` | Core security only (SSH, firewall, updates) | Alert only, no auto-fixes |
| `standard` | Comprehensive checks (default) | Safe auto-fixes, confirm medium-risk |
| `strict` | Full compliance audit | Aggressive fixes with safeguards |

Use `--level=<level>` to set the security level:
```bash
sudo ./vpssec audit --level=basic      # Quick core checks
sudo ./vpssec guide --level=strict     # Maximum hardening
```

## Score Categories

Checks are categorized to ensure fair scoring:

| Category | Description | Example |
|----------|-------------|---------|
| `required` | Always affects score | SSH auth, firewall, kernel ASLR |
| `recommended` | Counts when relevant | fail2ban, AppArmor |
| `conditional` | Only if component installed | Docker, Nginx, Cloudflared |
| `optional` | Only in strict mode | auditd, alerts, backup |
| `info` | Never affects score | Cloud provider detection |

This prevents score penalties for components you don't use.

## Command Line Options

```bash
vpssec [mode] [options]

Modes:
  audit       Security audit only (default)
  guide       Interactive hardening wizard
  rollback    Rollback previous changes
  status      Show current security status

Options:
  --lang=LANG       Set language (zh_CN, en_US)
  --modules=LIST    Comma-separated module list
  --skip=LIST       Skip specified modules
  --yes             Auto-confirm non-critical prompts
  --json-only       Output JSON only (for CI/CD)
  --no-color        Disable colored output
  -v, --verbose     Verbose output
  -h, --help        Show help
  --version         Show version
```

## Security Score

The security score is calculated based on check results:

- Base score: 100
- High/Critical severity failure: -20 points each (max -80)
- Medium severity failure: -8 points each (max -40)
- Low severity failure: -3 points each (max -15)

Example outcomes:
| Issues | Score | Rating |
|--------|-------|--------|
| 0 issues | 100 | Excellent |
| 1 medium | 92 | Good |
| 2 medium | 84 | Good |
| 1 high | 80 | Fair |
| 2 high | 60 | Poor |
| 1 high + 2 medium | 64 | Poor |
| 3+ high | ≤40 | Critical |

Score ranges:
- 90-100: Excellent
- 75-89: Good
- 50-74: Fair
- 0-49: Poor

## Safety Features

- **Atomic writes**: Changes written to temp file first, validated, then moved
- **Automatic backups**: All modified files backed up with timestamps
- **SSH protection**: Rescue port (2222) enabled before SSH config changes
- **Config validation**: `sshd -t` / `nginx -t` validation before applying
- **Critical confirmation**: Important operations require explicit confirmation (not bypassed by `--yes`)

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Audit
        run: |
          curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh -o vpssec-run.sh
          chmod +x vpssec-run.sh
          sudo ./vpssec-run.sh --json-only

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/summary.sarif
```

## Directory Structure

```
vpssec/
├── vpssec              # Main entry script
├── run.sh              # One-line runner script
├── install.sh          # Installation script
├── core/               # Core engine
│   ├── common.sh       # Common utilities
│   ├── engine.sh       # Module loader & executor
│   ├── state.sh        # State management
│   ├── report.sh       # Report generation
│   ├── security_levels.sh  # Security level & score category definitions
│   ├── ui_tui.sh       # TUI interface (whiptail/dialog)
│   ├── ui_text.sh      # Text fallback interface
│   └── i18n/           # Internationalization
│       ├── zh_CN.json
│       └── en_US.json
├── modules/            # Security check modules
│   ├── preflight.sh    # Environment pre-checks
│   ├── cloud.sh        # Cloud provider & agent detection
│   ├── users.sh        # User security audit
│   ├── ssh.sh          # SSH hardening
│   ├── ufw.sh          # UFW firewall
│   ├── fail2ban.sh     # Fail2ban configuration
│   ├── update.sh       # System updates
│   ├── docker.sh       # Docker security
│   ├── nginx.sh        # Nginx catchall
│   ├── baseline.sh     # Baseline hardening
│   ├── logging.sh      # Logging & audit
│   ├── kernel.sh       # Kernel hardening
│   ├── filesystem.sh   # Filesystem security
│   ├── cloudflared.sh  # Cloudflare Tunnel
│   ├── backup.sh       # Backup configuration
│   └── alerts.sh       # Alert notifications
├── state/              # State files (runtime)
├── reports/            # Generated reports
├── backups/            # Configuration backups
└── logs/               # Log files
```

## Extending vpssec

### Adding a New Module

1. Create `modules/mymodule.sh`:

```bash
#!/usr/bin/env bash
# vpssec - My Custom Module

mymodule_audit() {
    print_item "Checking something..."

    local check=$(create_check_json \
        "mymodule.check_id" \
        "mymodule" \
        "medium" \
        "failed" \
        "Check title" \
        "Detailed description" \
        "How to fix" \
        "mymodule.fix_id")
    state_add_check "$check"
    print_severity "medium" "Issue found"
}

mymodule_fix() {
    case "$1" in
        mymodule.fix_id)
            print_info "Fixing issue..."
            # Fix logic here
            print_ok "Fixed"
            ;;
    esac
}
```

2. Add module name to `VPSSEC_MODULE_ORDER` in `engine.sh`

3. Add translations to `core/i18n/*.json`

## License

GPL-3.0 License

## Contributing

Issues and Pull Requests are welcome!
