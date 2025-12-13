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
curl -fsSL https://raw.githubusercontent.com/Lynthar/server-audit/main/run.sh | sudo bash
```

### Manual Installation

```bash
git clone https://github.com/Lynthar/server-audit.git
cd server-audit
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
| `ssh` | SSH hardening (password auth, root login, key auth) |
| `ufw` | Firewall configuration (UFW status, rules) |
| `update` | System updates (security updates, unattended-upgrades) |
| `docker` | Docker security (privileged containers, exposed ports) |
| `nginx` | Nginx catchall (prevent cert/hostname leakage) |
| `baseline` | Baseline hardening (AppArmor, unused services) |
| `logging` | Logging & audit (journald, auditd, logrotate) |

### Optional Modules

| Module | Description |
|--------|-------------|
| `cloudflared` | Cloudflare Tunnel configuration checks |
| `backup` | Backup tool detection and template generation |
| `alerts` | Webhook/email alert configuration |

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
- High severity failure: -15 points (max -60)
- Medium severity failure: -5 points (max -25)
- Low severity failure: -2 points (max -10)

Score ranges:
- 90-100: Excellent
- 70-89: Good
- 50-69: Fair
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
          curl -fsSL https://raw.githubusercontent.com/Lynthar/server-audit/main/run.sh -o vpssec-run.sh
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
│   ├── ui_tui.sh       # TUI interface (whiptail/dialog)
│   ├── ui_text.sh      # Text fallback interface
│   └── i18n/           # Internationalization
│       ├── zh_CN.json
│       └── en_US.json
└── modules/            # Security check modules
    ├── preflight.sh
    ├── ssh.sh
    ├── ufw.sh
    ├── update.sh
    ├── docker.sh
    ├── nginx.sh
    ├── baseline.sh
    ├── logging.sh
    ├── cloudflared.sh
    ├── backup.sh
    └── alerts.sh
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
