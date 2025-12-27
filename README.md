# CloudServer Audit - VPS Security Check & Hardening Tool

English | [简体中文](README_zh.md)

A VPS security auditing and hardening script designed for individuals and small-scale operations.

## Features

- **Security Audit Mode (audit)**: Read-only security checks with Markdown + JSON + SARIF report output
- **Guided Hardening Mode (guide)**: Interactive security hardening wizard with step-by-step guidance
- **Modular Selection**: Choose which security modules to run by category or individually
- **One-Click Rollback (rollback)**: Automatic backup before changes with quick recovery capability
- **Tree-Style Output**: Compact hierarchical display with hints for technical checks
- **Multi-language Support**: Chinese/English interface with i18n support
- **Malware Detection**: Lightweight rootkit, crypto miner, and webshell scanning

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
1. Select modules to check (by category or all)
2. Review detected security issues
3. Select items to fix
4. Preview changes before applying
5. Execute fixes with automatic rollback points

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

## Module Categories

vpssec organizes security checks into 6 categories. You can select which to run:

| # | Category | Modules | Description |
|---|----------|---------|-------------|
| 0 | All | All modules | Run comprehensive check (recommended) |
| 1 | Access Control | `users`, `ssh` | User accounts, SSH hardening |
| 2 | Network Security | `ufw`, `fail2ban` | Firewall, brute-force protection |
| 3 | System Hardening | `update`, `kernel`, `filesystem`, `baseline` | Updates, kernel params, permissions |
| 4 | Service Security | `docker`, `nginx`, `cloudflared`, `webapp` | Container, web server security |
| 5 | Security Scanning | `malware` | Rootkit, miner, webshell detection |
| 6 | Operations | `logging`, `backup`, `alerts` | Logging, backup, monitoring |

### Interactive Module Selection

When running vpssec, you'll see a module selection menu:

```
┌──────────────────────────────────────────────────────────┐
│  Select modules to check:                                │
│                                                          │
│  [0] All modules (recommended)                           │
│  [1] Access Control           (users,ssh)                │
│  [2] Network Security         (ufw,fail2ban)             │
│  [3] System Hardening         (update,kernel,...)        │
│  [4] Service Security         (docker,nginx,webapp,...)  │
│  [5] Security Scanning        (malware)                  │
│  [6] Operations               (logging,backup,alerts)    │
└──────────────────────────────────────────────────────────┘
Enter choices (space-separated, e.g., 1 2 3) [default: 0] >
```

Or use CLI to specify modules directly:
```bash
sudo ./vpssec audit --include=ssh,ufw,malware
```

## Security Modules

### Core Modules

| Module | Description |
|--------|-------------|
| `preflight` | Environment pre-checks (OS, network, dependencies) |
| `cloud` | Cloud provider detection and monitoring agent audit |
| `timezone` | Timezone and NTP time synchronization |
| `users` | User security audit (UID 0, empty passwords, suspicious accounts) |
| `ssh` | SSH hardening (password auth, root login, key auth) |
| `ufw` | Firewall configuration (UFW/firewalld/iptables/nftables) |
| `fail2ban` | Fail2ban installation and SSH jail configuration |
| `update` | System updates (security updates, unattended-upgrades) |
| `kernel` | Kernel hardening (ASLR, sysctl network/security params, IPv6) |
| `filesystem` | Filesystem security (SUID/SGID, permissions, umask) |
| `baseline` | Baseline hardening (AppArmor/SELinux, unused services) |
| `docker` | Docker security (privileged containers, exposed ports) |
| `nginx` | Nginx catchall (prevent cert/hostname leakage) |
| `webapp` | Web application security (Nginx/Apache/PHP config, SSL, sensitive files) |
| `malware` | Malware detection (rootkits, crypto miners, webshells, reverse shells) |
| `logging` | Logging & audit (journald, auditd, logrotate) |

### Optional Modules

| Module | Description |
|--------|-------------|
| `cloudflared` | Cloudflare Tunnel configuration checks |
| `backup` | Backup tool detection and template generation |
| `alerts` | Webhook/email alert configuration |

## Output Format

vpssec uses a tree-style output for compact, readable results:

```
├─ Access Control
│  ├─ User Security
│  │  ├─ ✓ No extra UID 0 accounts
│  │  └─ ✗ Empty password users detected
│  │     ↳ Users without passwords can login without authentication
│  └─ SSH Security
│     ├─ ✓ Password authentication disabled
│     ├─ ✓ Root login disabled
│     └─ ● MaxAuthTries too high
├─ Security Scanning
│  └─ Malware Detection
│     ├─ ✓ No hidden processes
│     ├─ ✓ No crypto miners found
│     └─ ✗ Processes with deleted binaries
│        ↳ Program file was deleted but still running - malware often deletes itself
────────────────────────────────────────────────────────
  Score: 72/100

  ● 2 High  ● 1 Medium  ● 12 Safe
```

**Legend:**
- `✓` Green: Passed
- `✗` Red: High severity issue
- `●` Yellow: Medium severity issue
- `○` Blue: Low severity issue
- `↳` Hint: Brief explanation for technical checks

## Score Categories

Checks are categorized to ensure fair scoring:

| Category | Description | Example |
|----------|-------------|---------|
| `required` | Always affects score | SSH auth, firewall, kernel ASLR |
| `recommended` | Counts when relevant | fail2ban, AppArmor |
| `conditional` | Only if component installed | Docker, Nginx, Cloudflared |
| `optional` | Lower weight | auditd, alerts, backup |
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
  --include=MODS    Run only specified modules (comma-separated)
  --exclude=MODS    Skip specified modules
  --yes             Auto-confirm non-critical prompts
  --json-only       Output JSON only (for CI/CD)
  --no-color        Disable colored output
  -h, --help        Show help
  --version         Show version
```

## Security Score

The security score is calculated based on check results:

- Base score: 100
- High/Critical severity failure: -20 points each (max -80)
- Medium severity failure: -8 points each (max -40)
- Low severity failure: -3 points each (max -15)

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
- **Fix classification**: Fixes categorized as safe/confirm/risky/alert-only

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
│   ├── report.sh       # Report generation (tree-style output)
│   ├── security_levels.sh  # Fix safety & score category definitions
│   ├── ui_tui.sh       # TUI interface (whiptail/dialog)
│   ├── ui_text.sh      # Text fallback interface
│   └── i18n/           # Internationalization
│       ├── zh_CN.json
│       └── en_US.json
├── modules/            # Security check modules
│   ├── preflight.sh    # Environment pre-checks
│   ├── cloud.sh        # Cloud provider & agent detection
│   ├── timezone.sh     # Timezone & NTP
│   ├── users.sh        # User security audit
│   ├── ssh.sh          # SSH hardening
│   ├── ufw.sh          # Firewall (UFW/firewalld/iptables/nftables)
│   ├── fail2ban.sh     # Fail2ban configuration
│   ├── update.sh       # System updates
│   ├── docker.sh       # Docker security
│   ├── nginx.sh        # Nginx catchall
│   ├── webapp.sh       # Web application security
│   ├── malware.sh      # Malware detection
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

4. Add fix safety classification to `core/security_levels.sh`

## License

GPL-3.0 License

## Contributing

Issues and Pull Requests are welcome!
