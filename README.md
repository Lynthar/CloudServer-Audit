# CloudServer-Audit

[![license](https://img.shields.io/github/license/Lynthar/CloudServer-Audit)](LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/Lynthar/CloudServer-Audit/tests.yml?branch=main&label=tests)](https://github.com/Lynthar/CloudServer-Audit/actions/workflows/tests.yml)
[![shellcheck](https://img.shields.io/github/actions/workflow/status/Lynthar/CloudServer-Audit/shellcheck.yml?branch=main&label=shellcheck)](https://github.com/Lynthar/CloudServer-Audit/actions/workflows/shellcheck.yml)
[![release](https://img.shields.io/github/v/release/Lynthar/CloudServer-Audit)](https://github.com/Lynthar/CloudServer-Audit/releases)

Rollback-first hardening for Debian/Ubuntu VPS hosts, with a read-only audit that also covers RHEL-family and Arch

English | [简体中文](README.zh-CN.md)

The command is `vpssec`. It's a Bash script you run as root, one machine at a
time, and it leaves no process running after it exits.

Audit mode is read-only, so you can point it at any machine and just read the
report. Guided hardening mode does edit `/etc`, so it backs every file up
first, validates the new version before committing it, and can restore changes
by timestamp. Before it touches password or root SSH login it stands up a
second sshd on a spare port and makes sure you can still get in.

## Install

A one-shot run that leaves no files on the system: this pulls the latest release
into a private temp directory, checks its signature, runs, and deletes itself.
The report is copied out to `/tmp/vpssec-report-*`.

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

If you want state and backups to survive between runs, install it locally
(cloning the repository works too). Re-running the same command upgrades in
place:

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | sudo bash
sudo vpssec audit
```

`guide` and `rollback` refuse to run under the one-shot form, on purpose: their
backups would be written to a directory that gets deleted the moment it exits.
Anything that changes the system needs the locally installed form.

Environment variables go on the `bash` side of the pipe:

```bash
curl -fsSL .../main/run.sh | sudo env VPSSEC_VERSION=v1.3.1 bash
```

You need `jq`. `cosign` gets installed on demand at a pinned version.

## Usage

```bash
sudo vpssec audit
```

```bash
sudo vpssec audit --include=ssh,ufw,networking   # just these modules
sudo vpssec audit --json-only                    # for CI: only JSON on stdout
sudo vpssec guide                                # walk through the fixes
sudo vpssec rollback                             # undo what the last run changed
```

Two of them don't need root:

```bash
vpssec status        # last run, newest backup, whether there's a newer release
vpssec help ssh      # the checks and fix ids in one module
```

Findings come out as `summary.md` for people to read, plus `summary.json` and
SARIF 2.1.0 for machines to parse — `summary.md` is for humans and its shape will
change, so don't parse it. All three are available in Chinese and English
(`VPSSEC_LANG`).

## What it checks

`vpssec audit` runs 323 checks across 21 modules:

| Area | Checks | What it covers |
|---|---|---|
| System and kernel | 72 | `sysctl` network and memory settings, mount options, world-writable and SUID files, unattended upgrades, time sync, cron and `at` access |
| SSH and accounts | 67 | sshd config end to end, key vs password auth, root login, empty passwords, sudo rules, stale accounts, password aging |
| Containers and web apps | 52 | Docker daemon exposure, privileged and `--net=host` containers, socket permissions, nginx TLS and headers, exposed admin paths |
| Detection and logging | 47 | fail2ban jails, rootkit and suspicious-binary scans, journald retention, log permissions, whether anything would actually alert you |
| Network and firewall | 45 | UFW rules and default policy, listening sockets vs what you meant to expose, nginx reverse-proxy exposure, cloudflared tunnels |
| Baseline and ops | 40 | drift from the last run, cloud-init and provider metadata exposure, backup presence, dependency preflight |

**124 of those checks have a fix attached**, graded by how much impact they can
have: 28 apply straight away, 18 ask before applying, 5 require you to type a
confirmation, and 73 are registered but never run automatically.

## Configuration

There's no config file — flags and a few environment variables:

| Variable | Effect |
|---|---|
| `VPSSEC_VERSION` | Pin a release. Defaults to the latest one, never to `main` |
| `VPSSEC_LANG` | `zh_CN` (default) or `en_US` |
| `VPSSEC_INCLUDE` / `VPSSEC_EXCLUDE` | Same as `--include=` / `--exclude=` |
| `VPSSEC_NO_VERIFY=1` | Skip signature verification — see [Security](#security) |
| `INSTALL_DIR` | Where to install, default `/opt/vpssec` |

State, reports and backups all live under the install tree.

## Limitations

- **Hardening and rollback are Debian and Ubuntu only.** The audit reads
  RHEL-family and Arch hosts too, but `guide` exits before the module menu on
  anything else. Debian derivatives like Mint or Kali can pass the audit, but
  still can't be hardened.
- **There's no fix-everything switch**, and there isn't going to be. Risky fixes
  require a confirmation typed on a TTY, and `--yes` can't skip them.
- **Rollback only restores files.** Other changes — a stopped service, a symlink
  it created — get printed with the command to undo them, for you to run.
- **It's not a compliance tool.** No benchmark profiles, no control mappings, no
  exemptions. The score certifies nothing.
- **One host per run.** No agent, no server, no cluster view.
- **Scores only compare against the same version and the same module set.** A run
  with `--include=` marks itself partial.

## Documentation

- [User guide](docs/user-guide.md) — full command reference, how the score is
  computed, every module, CI integration. Written in Chinese.
- [Compatibility](docs/compatibility.md) — what semantic versioning covers here,
  and what it explicitly doesn't.

## Security

Release artifacts are signed with cosign keyless signing, and both entry scripts
verify that signature against this repository's release workflow at the exact tag
being installed. That doesn't protect you from this repository being compromised
— a new release signed by the same workflow would verify fine. `VPSSEC_NO_VERIFY=1`
removes the check entirely.

The bootstrap scripts come from `main`, so installing means trusting this repo at
the moment you run the command. If you'd rather not, read a release you've
reviewed and run its scripts instead.

Before disabling password or root SSH login, a second sshd comes up on a spare
port and you have to confirm you can still connect. Every run writes to
`backups/<timestamp>/` first.

There's no private disclosure channel yet. Until there is, please don't file
sensitive findings as public issues.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE). Copyright (c) 2026 Lynthar.
