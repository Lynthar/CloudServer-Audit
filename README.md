# vpssec

> **Hardening you can undo** — a pure-Bash hardening plan for Debian/Ubuntu VPS
> hosts: every change is backed up first, validated before it commits, and
> reversible as a unit, with a rescue sshd guarding the changes that could cost
> you your SSH session.
> The read-only audit driving the plan also covers RHEL-family and Arch hosts.

English | [简体中文](README.zh-CN.md) | [User Guide](docs/user-guide.md)

---

## Quick start

**Run once, install nothing.** Downloads the latest release to a temporary
directory, verifies its signature, runs, and deletes itself. A saved report is
copied to `/tmp/vpssec-report-*`:

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

Nothing persists after this — including `backups/`. **`guide` and `rollback`
are therefore refused here** (exit 2, with the install command in the message):
a fix writes its backups inside the tree this runner deletes on exit, so
hardening this way would change `/etc` and destroy the only means of undoing it
in the same command. Auditing is read-only and unaffected.

**Install for repeated use.** Same release, same signature check, but it lands
in `/opt/vpssec` with a `vpssec` command on your `PATH`, and it keeps `state/`
and `backups/` across upgrades:

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | sudo bash

sudo vpssec audit          # from any directory
sudo vpssec status         # last run, latest backup, and whether a newer release exists
```

To upgrade, re-run the same command — `state/` and `backups/` are moved aside
and restored, so a reinstall never costs you the data `vpssec rollback` needs.
To remove it, `sudo /opt/vpssec/uninstall.sh` (it asks before deleting state
and backups, and keeps them by default).

Both entry points install **the newest release**, never the `main` branch.
`VPSSEC_VERSION` pins a specific one and `INSTALL_DIR` moves the install tree
— see the environment variables below, and note they must be set on the `bash`
side of the pipe.

**Or work from a clone** (development, or to read the code before running it):

```bash
git clone https://github.com/Lynthar/CloudServer-Audit.git
cd CloudServer-Audit
sudo ./vpssec audit
```

A clone tracks `main`, which is ahead of the latest release and is not signed.
Use a release for production hosts.

After an interactive audit you're prompted to save the report; if you accept, `reports/summary.{md,json,sarif}` are written. `--json-only` writes all three too — only the JSON goes to stdout — so a CI job that publishes the Markdown or feeds the SARIF to a dashboard never picks up a stale file from an earlier run.

`--json-only` and `--yes` both imply a non-interactive run: the language / mode / module menus are skipped and their defaults used (audit, all modules).

**Audit (read-only):** Debian 12/13 · Ubuntu 22.04/24.04/26.04 · RHEL 8/9/10 family (Rocky / Alma / CentOS Stream) · Arch

**Guided hardening + rollback:** Debian / Ubuntu only

Both `run.sh` and `install.sh` download the release tarball and **verify its
signature with cosign keyless** (sigstore + GitHub Actions OIDC) before
extracting. The signing identity is pinned to this repo's `release.yml`
workflow at the exact tag being installed, so a swapped or re-labelled
release asset fails verification. The guarantee is scoped: it authenticates
the asset against this repository's release pipeline — it cannot protect
against a compromise of the repository itself, which could mint a new
validly-signed release or alter these bootstrap scripts on `main`. For a
stronger anchor, download the bootstrap from a release you have already
audited instead of from `main`. `cosign` is auto-installed via `apt` on Ubuntu
22.04+; otherwise the script installs a pinned asset from sigstore's
GitHub release with its SHA256 verified locally first — a `.deb` via
`dpkg` on Debian, or the static `cosign` binary into `/usr/local/bin`
on RHEL/Arch and other non-dpkg distros. The fallback path shifts
cosign's bootstrap trust from the distro archive to github.com — same
trust root used to fetch `run.sh` itself, so no new attack surface vs.
the existing one-liner. Skip verification entirely with `VPSSEC_NO_VERIFY=1`
(not recommended).

Every variable below must be set on the **bash** side of the pipe: written the
other way round, `VPSSEC_VERSION=… curl … | sudo bash` sets it for `curl` and
the script never sees it.

```bash
# Pin to a specific release (both v1.3.0 and 1.3.0 are accepted)
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo env VPSSEC_VERSION=v1.3.0 bash

# Install somewhere other than /opt/vpssec
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | sudo env INSTALL_DIR=/opt/vpssec-staging bash

# Skip verification (NOT recommended). Applies to both entry points.
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo env VPSSEC_NO_VERIFY=1 bash
```

Verify a release manually:

```bash
TAG=v1.3.0
curl -LO https://github.com/Lynthar/CloudServer-Audit/releases/download/$TAG/vpssec-${TAG#v}.tar.gz
curl -LO https://github.com/Lynthar/CloudServer-Audit/releases/download/$TAG/vpssec-${TAG#v}.tar.gz.sig.json
cosign verify-blob \
  --bundle vpssec-${TAG#v}.tar.gz.sig.json \
  --certificate-identity "https://github.com/Lynthar/CloudServer-Audit/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vpssec-${TAG#v}.tar.gz
```

---

## What it does

| Mode | Purpose |
|---|---|
| `audit` | Read-only security checks → Markdown + JSON + SARIF reports |
| `guide` | Interactive hardening wizard with safety gates |
| `rollback` | Restore the files a run backed up (service state / symlinks print their undo commands instead) |
| `status` | Last run summary + latest backup |

Every detection emits a stable `check_id`; fixes carry a `fix_id` you can
apply manually from the report or interactively via `guide`.

---

## Non-goals

Knowing what a tool refuses to be is part of trusting it:

- **Not a compliance product.** Checks overlap CIS/Lynis territory, but there
  are no benchmark profiles, control mappings or waivers, and no score here
  certifies anything.
- **Not unattended remediation.** Fixes run inside an interactive, per-fix
  plan; the riskiest ones require a typed confirmation on a TTY that `--yes`
  cannot bypass. There is deliberately no "fix everything" flag.
- **Not fleet management.** One host per run — no agent, no server, no
  cross-host aggregation.
- **Not an offline forensic tool.** The audit makes a few small, time-limited
  network probes and degrades gracefully without connectivity; GitHub being
  unreachable never changes a security conclusion. The complete list:

| When | Endpoint | Purpose |
|---|---|---|
| `audit` (preflight) | `www.google.com`, falling back to `www.baidu.com` | reachability probe, 5 s timeout |
| `audit` (cloud detection) | `169.254.169.254` (EC2 / Oracle / Hetzner / DigitalOcean paths) · `100.100.100.200` (Alibaba) · `metadata.tencentyun.com` (Tencent) | link-local instance-metadata probes, 1–2 s timeouts |
| `audit` (cloudflared module) | Cloudflare API, via `cloudflared tunnel list` | only when cloudflared is installed; 8 s timeout |
| alerts, once you configure them | the webhook URL you set | delivery and test-fire of your own alerts |
| `status` / `install.sh` | `api.github.com` | newer-release check — never during `audit` or `guide` |

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
live in the [**User Guide**](docs/user-guide.md).

---

## Sample output

```
─── Access Control ──────────────────────────────────────────────
  User Security                  │  SSH Security
    ✓ No extra UID 0 accounts    │    ✓ Password auth disabled
    ✗ Empty password users       │    ● Authorized_keys perms loose
    ✓ System accounts secured    │    ○ MaxAuthTries above 4

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
- **Per-run backups** — `backups/<timestamp>/` mirrors every file before change. `rollback` restores the files of any single run; side effects that are not files (a disabled service, a created symlink) are undone via the exact commands vpssec prints and logs when it makes them.
- **Validate before commit** — `sshd -t`, `nginx -t`, `visudo -c` all run on the staged file before it moves into place.
- **SSH rescue port** — before the two lockout-capable changes (disabling password auth / root login), a second sshd is opened on a spare port (2222 by default) and must be confirmed working before the live config is touched.
- **Critical confirmation** — destructive ops (firewall enable, password-auth disable) require explicit confirmation that `--yes` cannot bypass.
- **Fix classification** — every fix is tagged `safe` / `confirm` / `risky` / `alert_only`; risky ones surface their warning before applying.

These guarantees are the most-tested code here: 900+ bats tests run on every
push across Ubuntu, Rocky 9 and Arch, and a nightly CI sweep plants ~500 known
defects in module source and fails unless the paired suite catches every one.

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

Full CLI reference: [User Guide → 命令参考](docs/user-guide.md#附录-a-vpssec-命令参考).

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
score. See [User Guide → 安全评分](docs/user-guide.md#附录-b-安全评分计算)
for the full model.

**Only compare scores from runs over the same module set.** `base` scales
with the number of scored checks, `penalty` does not — so a narrow
`--include=` subset is a harsher denominator, and a subset in which every
scored check fails floors at 0 no matter how mild the findings are. Runs
that used `--include`/`--exclude` say so explicitly next to the number
("Partial score: computed over N scored checks…"), and `summary.json`
carries `meta.partial_scope` plus `stats.scored_total` for the same reason.

---

## Contributing

PRs welcome.

- Architecture and module-extension patterns: the `<module>_audit` / `<module>_fix` contracts and the comments under `core/`
- Unit tests: `bats tests/` (900+ cases; see CI for the current count)
- Mutation testing, two tools for two questions: `bash tools/mutate-all.sh` plants defects in module source and asks whether the paired bats suite notices (safe anywhere; CI reruns the full sweep nightly); `tests/mutation/` plants misconfigurations in a REAL `/etc` and asks whether the audit notices — only run that one on a disposable VM
- Manifest update before commit: `bash tools/gen-manifest.sh && git add manifest.sha256`
- Releasing: bump `VERSION` and commit it, then push a matching `vX.Y.Z` tag — `release.yml` refuses any tag that disagrees with `VERSION`, then builds and signs the tarball with cosign keyless and publishes the GitHub release

## License

[GPL-3.0](LICENSE)
