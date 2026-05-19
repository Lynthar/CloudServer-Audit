# vpssec

> Pure-bash security auditing and hardening for Debian / Ubuntu VPS.
> Read-only audit · guided hardening · atomic rollback.

English | [简体中文](README_zh.md) | [User Guide](docs/USER_GUIDE.md)

---

## Quick start

One-line install (downloads, runs, copies report to `/tmp/vpssec-report-*`):

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

Or clone and run manually (recommended for repeated use):

```bash
git clone https://github.com/Lynthar/CloudServer-Audit.git
cd CloudServer-Audit
sudo ./vpssec audit
```

Reports land in `reports/summary.{md,json,sarif}`.

**Supported:** Debian 12 / 13 · Ubuntu 22.04 / 24.04

> ⚠️ The one-liner downloads over TLS but does **not** verify signatures.
> For supply-chain assurance, clone the repo and review `run.sh` before
> piping it to a shell — or use the manual flow above.

---

## What it does

| Mode | Purpose |
|---|---|
| `audit` | Read-only security checks → Markdown + JSON + SARIF reports |
| `guide` | Interactive hardening wizard with safety gates |
| `rollback` | Restore any change from per-run backups |
| `status` | Last run summary + latest backup |

Every detection emits a stable `check_id`; fixes carry a `fix_id` you can
apply manually from the report or interactively via `guide`.

---

## Modules at a glance

**21 modules** organised into 6 categories. Default runs everything;
restrict via CLI or the interactive menu:

```bash
sudo ./vpssec audit --include=ssh,ufw,networking
```

| # | Category | Modules |
|---|---|---|
| 1 | Access Control | `users`, `ssh` |
| 2 | Network Security | `ufw`, `fail2ban`, `networking` |
| 3 | System Hardening | `update`, `kernel`, `filesystem`, `baseline` |
| 4 | Service Security | `docker`, `nginx`, `cloudflared`, `webapp` |
| 5 | Security Scanning | `malware` |
| 6 | Operations | `logging`, `backup`, `alerts`, `scheduling` |

> `preflight`, `cloud`, `timezone` always run as context for other modules.

Per-module check details, fix instructions, and the full module reference
live in the [**User Guide**](docs/USER_GUIDE.md).

---

## Sample output

```
─── Access Control ──────────────────────────────────────────────
  User Security                  │  SSH Security
    ✓ No extra UID 0 accounts    │    ✓ Password auth disabled
    ✗ Empty password users       │    ● MaxAuthTries too high
    ✓ System accounts secured    │    ● No access control configured

─── Security Scanning ───────────────────────────────────────────
  Malware Detection
    ✓ No hidden processes
    ✗ Processes with deleted binaries

────────────────────────────────────────────────────────────────
  Score: 69 / 100   ● 2 High   ● 1 Medium   ● 12 Safe
```

Legend: `✓` pass · `✗` high · `●` medium · `○` low

---

## Safety

vpssec touches `/etc/*` files. To make that defensible:

- **Atomic writes** — tempfile + validate + rename. No half-edited config.
- **Per-run backups** — `backups/<timestamp>/` mirrors every file before change. `rollback` restores any single run.
- **Validate before commit** — `sshd -t`, `nginx -t`, `visudo -c` all run on the staged file before it moves into place.
- **SSH rescue port** — port 2222 is auto-opened before any `sshd_config` change so a bad config can't lock you out.
- **Critical confirmation** — destructive ops (firewall enable, password-auth disable) require explicit confirmation that `--yes` cannot bypass.
- **Fix classification** — every fix is tagged `safe` / `confirm` / `risky` / `alert_only`; risky ones surface their warning before applying.

---

## Common commands

```bash
# Audit
sudo ./vpssec audit                    # full audit (recommended first run)
sudo ./vpssec audit --include=ssh      # only specific modules
sudo ./vpssec audit --exclude=docker   # skip a module
sudo ./vpssec audit --json-only        # CI-friendly output
sudo ./vpssec audit --lang=en_US       # English (default zh_CN)
sudo ./vpssec audit --debug            # verbose log to logs/vpssec.log

# Hardening + recovery
sudo ./vpssec guide                    # interactive hardening
sudo ./vpssec rollback                 # restore previous config

# Inspection (no root needed)
./vpssec status                        # last run + backup status
./vpssec help                          # list modules + fix_ids
./vpssec help ssh                      # detail for one module
```

Full CLI reference: [User Guide → 命令参考](docs/USER_GUIDE.md#附录-a-vpssec-命令参考).

---

## Security score

Score combines a pass-rate base with a severity-weighted penalty:

```
base    = 100 × passed / scored_total
penalty = 5 × high + 1.5 × medium + 0.25 × low
score   = clamp(0, 100, base − penalty)
```

Categories: `90+ Excellent · 75–89 Good · 50–74 Fair · <50 Poor`.

`info`-category checks (e.g. cloud-provider detection) don't move the
score. See [User Guide → 安全评分](docs/USER_GUIDE.md#附录-b-安全评分计算)
for the full model.

---

## Contributing

PRs welcome.

- Architecture and module-extension patterns: [`CLAUDE.md`](CLAUDE.md)
- Unit tests: `bats tests/` (~240 cases)
- Mutation harness (plant-defect verification): `tests/mutation/` — only run on a disposable VM
- Manifest update before commit: `bash tools/gen-manifest.sh && git add manifest.sha256`

## License

[GPL-3.0](LICENSE)
