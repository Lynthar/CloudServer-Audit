# vpssec — Audit Coverage Review & Refinement Notes

**Review date:** 2026-05-18
**Target host:** Debian 13 KVM VPS (production-like)
**Reference baseline:** [Lynis](https://github.com/CISOfy/lynis) (CISOfy/lynis main, 2026-04 snapshot)
**Methodology:** four-phase comparison

1. **Phase 0** — run vpssec audit, run Lynis `audit system`, diff their reports
2. **Phase 1** — open-source Lynis modules and compare *implementations* (whitelists, parsers, thresholds) against vpssec equivalents
3. **Phase 2** — full coverage matrix (vpssec 19 modules ↔ Lynis 43 test files), identify zero-coverage gaps
4. **Phase 3** — build a mutation-testing harness to verify every newly-added detection actually fires

This document captures the full delta of bug fixes, new coverage, and forward-looking work items produced by that review.

---

## 1. Session totals at a glance

| Dimension | Count |
|---|---|
| Commits | 12 |
| `fix:` commits | 7 |
| `feat:` commits | 4 |
| `test:` commits | 1 |
| **True detection bugs fixed** | **~14** |
| New `check_id`s added | ~45 |
| New i18n keys added | 60+ (EN + CN combined) |
| New modules created | 2 (`networking`, `scheduling`) |
| Mutation test cases added | 18 |
| Net diff | ~+2,500 / -200 lines |

---

## 2. The full bug ledger (chronological)

### 2.1 Detection accuracy bugs (FP / FN class)

| # | Bug | File / line | Severity | Found via |
|---|---|---|---|---|
| 1 | SUID whitelist missing `ping`/`ping6`: every Debian 13 host falsely flagged inetutils-ping as suspicious SUID | `modules/filesystem.sh` (`FS_SUID_WHITELIST`) | FP, medium | live audit review |
| 2 | `getcap` output parser handled only legacy format (`/path = caps`); modern libcap (`/path caps`) parsed the entire line into both `$file` and `$caps`, breaking the whitelist match. Every cap-bearing binary on Debian 11+ was flagged. | `modules/filesystem.sh` `_fs_find_caps_files()` | FP, medium | live audit review |
| 3 | `update.reboot_required` looked only at `/var/run/reboot-required` (Ubuntu's `update-notifier-common` artifact) and needrestart; stock Debian without those packages silently missed kernel upgrades. **Real FN**, confirmed against KRNL-5830 from Lynis. | `modules/update.sh` `_update_reboot_required()` | **FN, high** | Lynis output diff |
| 4 | `_kernel_ip_forward_needed()` only covered Docker/LXC/libvirt; missed Tailscale, Wireguard (manual `ip link` *and* `wg-quick@*`), OpenVPN, Podman, Incus, k3s/kubelet. Every VPN-equipped host got `kernel.network_params_medium` FP. | `modules/kernel.sh` | FP, medium | section-3 user data check |
| 5 | `rp_filter` had no context-check at all (unlike `ip_forward`). Value `2` (loose mode, required for VPN subnet routers) was flagged identically to value `0`. | `modules/kernel.sh` `_kernel_audit_network_params` | FP, medium | same as #4 |
| 6 | `sshd -T` invocation missed the `-C user=doesnotexist,host=none,addr=none` connection spec. On hosts with `Match User root` blocks, every option was read **post-Match**, distorting the reported "base" config silently. | `modules/ssh.sh` `_ssh_get_config()` | FP **and** FN-class | Lynis SSH-7408 source read |
| 7 | `_kernel_audit_kernel_params` filter `^(kernel\.|fs\.)` silently dropped any `dev.*` entry. Latent — only exposed when adding `dev.tty.ldisc_autoload` (CVE-2019-13272 mitigation check). | `modules/kernel.sh` | latent FN | Lynis KRNL-6000 source read |
| 8 | `ufw_audit()` returned immediately after emitting `firewall_active` for the nftables/iptables/firewalld branches. Empty rulesets on those backends (kernel module loaded, zero rules) passed the audit cleanly. | `modules/ufw.sh` `ufw_audit()` | **FN, high** | Lynis FIRE-4540 cross-check |
| 9 | `users.hash_rounds_low` (Lynis AUTH-9230) ignored the configured hash method. Fired on every Debian 12+ install because yescrypt (the default) doesn't consult `SHA_CRYPT_*_ROUNDS`. | `modules/users.sh` `_check_hash_rounds()` | FP, low | full-audit report review |
| 10 | `modules/networking.sh` didn't recognise non-default SSH ports. SSH on port 33948 → `ssh.using_non_default_port` ✓ pass while `networking.public_listeners_present` flagged the same listener. Cross-module inconsistency. | `modules/networking.sh` | FP, low | full-audit report review |

### 2.2 Inconsistency / UX bugs (correct underlying detection, misleading presentation)

| # | Bug | File | Found via |
|---|---|---|---|
| 11 | Duplicate `auditd` check: both `modules/kernel.sh` and `modules/logging.sh` had full state machines for the same daemon, double-emitting `kernel.auditd_*` and `logging.auditd_*`. | `modules/kernel.sh` (removed) | live audit review |
| 12 | `users.sudo_users` title was "Privileged Users: 1 ✓" — but the 1 was root (every distro ships `root ALL=(ALL:ALL) ALL` in sudoers). UX implied "I have an admin, safe to disable root login" while `ssh.no_admin_user` correctly flagged the absence. Now displays `(root only — no non-root admin)`. | `modules/users.sh` `_find_sudo_users` consumer | live audit review |
| 13 | `ssh.root_login_enabled` Info field hardcoded `"PermitRootLogin is set to yes"` while the title softened to "(key-only; password auth disabled)". Two reads of the same record contradicted each other. Now context-aware. | `modules/ssh.sh` `_ssh_audit_root_login` | live audit review |
| 14 | Three `backup.*` checks were structurally independent: `no_tools` could fail while `scheduled` and `critical_paths` both passed (the latter pair only looked at cron-entry regex and on-disk paths, no cross-reference). Misleading "I have backups" reading on hosts with no backup tool installed. | `modules/backup.sh` | live audit review |
| 15 | `networking.public_listeners_present` listed dual-stack listeners (`0.0.0.0:N` and `[::]:N`) as two separate entries. Cosmetic but confusing. | `modules/networking.sh` | full-audit report review |
| 16 | i18n fallback pattern `$(i18n 'key' 2>/dev/null \|\| echo 'fallback')` doesn't fall back: the `i18n` function echoes the missing key with exit 0, so `\|\|` never fires. Visible result: raw `check_id`s in titles + raw `fix_*` keys in Recommendations for any check whose i18n keys hadn't been added. | `core/i18n/{en_US,zh_CN}.json` (missing keys) | full-audit report review |

### Bug-count notes

- Items 1–2 were originally committed together under `fix: four audit accuracy issues` along with 11 and 12+13 — that single "four" referred to the *first batch only*. Bugs 3–16 came in later batches.
- Item 16 (i18n) is one root cause but touched ~17 visible `check_id` titles; treating it as one bug for the count.
- Item 7 (`dev.*` filter) is a *latent* bug — it was harmless until we tried to add the first `dev.*` sysctl. Surfaced and fixed in the same commit.

**Cumulative true detection / behavior bugs fixed this session: ~14.**

---

## 3. Coverage additions (by module)

### 3.1 Modules deepened from Lynis cross-check

| Module | What was added | Lynis equivalent |
|---|---|---|
| `users` | 5 AUTH-* checks: `duplicate_uids`, `weak_hash_method`, `hash_rounds_low`, `faillog_disabled`, `sudoers_syntax_invalid` | AUTH-9208 / 9229 / 9230 / 9408 / 9250 |
| `ssh` | 11 SSH-7408 options: 6 ergonomic (`AllowTcpForwarding`, `ClientAliveCountMax`, `LogLevel`, `MaxSessions`, `TCPKeepAlive`, `AllowAgentForwarding`) + 5 security-boundary (`IgnoreRhosts`, `StrictModes`, `PermitUserEnvironment`, `PermitTunnel`, `GatewayPorts`) | SSH-7408 |
| `filesystem` | +13 entries to `FS_SENSITIVE_FILES`: `/etc/{passwd,shadow,group,gshadow}-` rotated backups (shadow- & gshadow- promoted to HIGH bucket), `/boot/grub*/grub.cfg`, `/etc/{at,cron}.{allow,deny}`, `/root/.{rhosts,shosts}` | `default.prf` `permfile=` set |
| `kernel` | +8 sysctls: IPv6 send_redirects (both `all` + `default`), `net.ipv4.conf.all.bootp_relay`, `mc_forwarding`, `proxy_arp`, `kernel.core_setuid_ok`, `kernel.ctrl-alt-del`, `dev.tty.ldisc_autoload`. Plus expanded `_kernel_ip_forward_needed` to recognise Tailscale/WG/Podman/Incus/k3s. | KRNL-6000 |
| `baseline` | FINT-4350 file-integrity-tool detection (aide/tripwire/samhain/...). INSE-* insecure-legacy-services check (telnet/rsh/inetd/xinetd/NIS/tftpd/...). | FINT-4350, INSE-8xxx |
| `fail2ban` | `no_jails_active` / `jails_active` — catches "service running but no jail enabled" failure mode | TOOL-5104 |
| `ufw` | `firewall_empty` (HIGH) — nftables/iptables active but ruleset has zero effective rules | FIRE-4540 / FIRE-4512 |
| `update` | kernel-package-mismatch fallback for `reboot_required` | KRNL-5830 |

### 3.2 New modules (filling Lynis "zero coverage" gaps)

| Module | Checks | Lynis equivalent |
|---|---|---|
| `modules/networking.sh` | `exposed_dangerous_ports` (HIGH, 21-port DB/cache/management blacklist on wildcard bind) · `public_listeners_present` (medium) · `listeners_loopback_only` / `listeners_ok` (positive) · `promiscuous_interface` (HIGH) | NETW-3012 / NETW-3015 |
| `modules/scheduling.sh` | `at_jobs_present` (low) · `cron_fetches_internet` (medium, `curl\|sh` supply-chain pattern) · `cron_clean` / `no_at_jobs` (positive) | SCHD-7702 / SCHD-7704 / SCHD-7718 |

### 3.3 Coverage Lynis has but vpssec deliberately skipped

| Lynis ID | What | Why skipped |
|---|---|---|
| LOGG-2154 | Remote syslog | User decision — single-host VPS focus |
| BOOT-5122 | GRUB password | VPS context: no physical console; mostly compliance theater |
| BANN-7126 / 7130 | /etc/issue / motd legal banners | Operator preference, not security |
| AUTH-9282 | Per-account expiry dates | High FP rate against cloud-init users |
| AUTH-9288 | Expired passwords | Operational, not a security boundary |
| AUTH-9266/9268 | Deep PAM config scan | Rabbit hole; `pwquality_weak` already covers the main control |
| AUTH-9278 / 9402 / 9406 | LDAP / NIS in PAM | Rare on cloud VPS |
| PKGS-7370/7394 | debsums / apt-show-versions | Helper-package recommendations, not detections |
| USB-1000 / STRG-1846 | USB / firewire driver disabling | VPS has no physical bus |
| FILE-6310 | Separate /home /var partitions | Cloud VPS layout decision, not security |
| FIRE-4586 | iptables LOG/NFLOG target | Defense-in-depth, low VPS value |
| FIRE-4513 | Unused iptables rules with counters at 0 | Operational hygiene |
| `kernel.modules_disabled=1` | One-way switch to block all future module loads | Breaks legitimate runtime module loads; operational cost exceeds gain |

---

## 4. Mutation test harness (`tests/mutation/`)

Built fresh this session as the trust-but-verify automation. 18 cases, each plants a known defect, runs audit, asserts detection fires, then restores.

| Number | Case | Covers |
|---|---|---|
| 010 | SSH `PasswordAuthentication yes` | `ssh.password_auth_enabled` HIGH |
| 011 | SSH `PermitUserEnvironment yes` | `ssh.permit_user_env_enabled` |
| 012 | SSH `IgnoreRhosts no` | `ssh.ignore_rhosts_disabled` |
| 013 | SSH `StrictModes no` | `ssh.strict_modes_disabled` |
| 014 | SSH `PermitTunnel yes` | `ssh.permit_tunnel_enabled` |
| 015 | SSH `GatewayPorts yes` | `ssh.gateway_ports_enabled` |
| 020 | Plant a non-whitelisted SUID at `/usr/local/bin/*` | `filesystem.suspicious_suid` |
| 021 | chmod `/etc/shadow-` to 644 | `filesystem.sensitive_perms_wrong` HIGH (verifies shadow- → HIGH bucket) |
| 022 | chmod `/boot/grub/grub.cfg` to 644 | `filesystem.sensitive_perms_wrong_minor` (with desc-substring assert) |
| 023 | `setcap cap_net_raw=ep /usr/local/bin/...` | `filesystem.non_standard_caps` (verifies the getcap parser fix from bug #2) |
| 030 | `sysctl -w kernel.core_setuid_ok=1` | `kernel.kernel_params_weak` (desc-substring) |
| 031 | `sysctl -w kernel.ctrl-alt-del=1` | same |
| 032 | `sysctl -w dev.tty.ldisc_autoload=1` | same — **doubles as regression test for the dev.* filter fix (#7)** |
| 040 | Append duplicate-UID account to `/etc/passwd` | `users.duplicate_uids` HIGH |
| 041 | Write malformed `/etc/sudoers.d/...` (unmatched quote) | `users.sudoers_syntax_invalid` HIGH |
| 042 | `SHA_CRYPT_MIN_ROUNDS 5000` in `/etc/login.defs` | `users.hash_rounds_low` |
| 043 | `FAILLOG_ENAB no` in `/etc/login.defs` | `users.faillog_disabled` |
| 050 | jail.local disabling sshd | `fail2ban.no_jails_active` |
| 060 | Python listener on `0.0.0.0:6379` | `networking.exposed_dangerous_ports` HIGH |
| 061 | `at now + 1 year` no-op job | `scheduling.at_jobs_present` |

Cases not added (intentionally):
- `users.weak_hash_method` — mutating `/etc/shadow` is too risky for an automated harness
- `ufw.firewall_empty` — flushing a live ruleset on a real server is unacceptable
- `baseline.insecure_services_active` — package install / removal is heavier than the detection logic warrants

**Driver feature added mid-session:** `EXPECT_DESC_CONTAINS` — narrows the assertion to "this specific mutation appeared in the check's description", critical for aggregate checks like `kernel.kernel_params_weak` that share one `check_id` across many sysctls.

---

## 5. Module status matrix

### ✅ Fully reviewed and aligned this session (no further Lynis comparison needed)

| Module | Last touched | State |
|---|---|---|
| `users` | Round A | 5 AUTH-* checks + Privileged Users UX + hash_rounds yescrypt FP |
| `ssh` | Round ② | 11 new options + Match-block bug fix |
| `filesystem` | Round ① | SUID/CAPS bugs fixed + 13 sensitive files |
| `kernel` | Round ③ | 8 sysctls + dev.* filter + ip_forward/rp_filter context |
| `ufw` | Round B | empty-ruleset detection + early-return bug |
| `fail2ban` | Round B | any-jail-active check |
| `update` | Round 2 | reboot kernel-package fallback |
| `backup` | Round 3 | three-checks gating |
| `baseline` | Round C | FINT + insecure_services |
| `networking` | Round C | new module, three follow-up bugs fixed |
| `scheduling` | Round C | new module |

### ✅ vpssec-strong → don't bother comparing to Lynis

| Module | Why |
|---|---|
| `malware` | vpssec runs active detection (LD_PRELOAD, memfd, deleted_binary, hidden processes/ports, reverse shell, crypto miner, C2). Lynis just asks "did you install rkhunter?". Different leagues. |
| `docker` | vpssec covers exposed ports, privileged containers, root containers, capabilities, seccomp, userns, socket perms — ~700 LOC. Lynis tests_containers is 226 LOC. |
| `webapp` + `nginx` | TLSv1 detection, HSTS, security headers, SSL cert expiry, PHP `disable_functions`, Apache TRACE. Lynis tests_webservers still in 90s Apache mindset. |
| `cloud` | Cloud-provider fingerprinting + agent detection (Tencent / Alibaba / AWS / Azure / GCP / Hetzner). Lynis has no equivalent. |
| `cloudflared` | Cloudflare Tunnel posture. Lynis: 0. |
| `alerts` | vpssec-internal report-routing concept. Lynis: 0. |
| `preflight` | OS support / network / deps / listener count. Bootstrap, not security-deep. |

### 🟡 Could be deepened but ROI is low

| Module | Potential addition | Why not done |
|---|---|---|
| `timezone` | TIME-3104 NTP daemon nuances (chrony/ntpsec leap-second handling, version specifics) | Already covers the critical state machine |
| `logging` | LOGG-2138 logrotate config depth, LOGG-2146 klogd, LOGG-2190 deleted-but-open log files | Marginal; user explicitly skipped LOGG-2154 |
| `nginx` | HTTP/2 settings, large buffer sizing, slowloris, header-size limits | Lynis doesn't cover these either — no reference to crib |

---

## 6. Forward-looking work (where engineering value is left)

Lynis cross-check has plateaued. The remaining high-ROI work is **not** "find more checks Lynis has and we don't" — it's:

1. **Cross-distro / cross-version matrix testing.** We only tested on Debian 13 with kernel 6.12. Debian 12, Ubuntu 22.04 & 24.04 almost certainly contain more FPs/FNs of the hash_rounds-yescrypt class. Each major distro release surfaces new corner cases.

2. **Mutation harness expansion to full coverage.** Current: 18 cases covering ~20 check_ids. Total vpssec check_ids: ~100+. Every fix path should have a mutation case eventually — this is the only automated way to keep "detection still fires" guarantees over time.

3. **Calibration / threshold tuning from real-world feedback.** `MaxSessions ≤4` (vs Lynis ≤2), `LoginGraceTime ≤60` (vs Lynis ≤120), the 21-port "dangerous public" list, etc. — these need user feedback to refine, not more Lynis reading.

4. **i18n function semantics fix.** Bug #16 surfaced that `$(i18n 'key' \|\| echo 'fallback')` doesn't actually fall back — `i18n` echoes the key + returns 0. Today it doesn't bite because every existing `check_id` has its keys defined, but any future check added without keys will leak its raw ID into the report. **Root fix: change `i18n` to return non-zero on missing key** (single function in `core/common.sh`), then the fallback pattern actually works. That would eliminate this whole class of presentational bug.

5. **Report UX polish.** Score calibration (35 vs 36 was a stable diff), severity distribution presentation, long-desc truncation. Best fed by watching real operators use the report, not by audit-tool comparison.

---

## 7. Key reference points

- **Lynis source** (for future cross-check): https://github.com/CISOfy/lynis
  - SSH options: `include/tests_ssh` — search `SSHOPS=`
  - File perms: `default.prf` — search `^permfile=` / `^permdir=`
  - Sysctls: `default.prf` — search `^config-data=sysctl`
  - Authentication: `include/tests_authentication` (1663 LOC; AUTH-9204 onward)
  - Firewalls: `include/tests_firewalls` (639 LOC; FIRE-4502 onward)
  - Networking: `include/tests_networking` (801 LOC; NETW-2400 onward)
  - Scheduling: `include/tests_scheduling` (316 LOC; SCHD-7702 onward)
  - Insecure services: `include/tests_insecure_services` (521 LOC; INSE-8000 onward)

- **vpssec internal references**
  - `core/security_levels.sh` — `FIX_SAFE` / `FIX_CONFIRM` / `FIX_RISKY` / `FIX_ALERT_ONLY` classification, plus `CHECK_SCORE_CATEGORY` (required / recommended / conditional / optional / info)
  - `core/engine.sh` — `VPSSEC_MODULE_ORDER` and `VPSSEC_MODULE_CATEGORY` (register new modules here)
  - `CLAUDE.md` — high-level architecture and safety invariants (NOTE: the score-weight description there is drifted from current implementation; see commit `3097c58`)

- **Mutation harness**: `tests/mutation/run.sh`. Run on a *disposable* VM only:
  ```bash
  sudo bash tests/mutation/run.sh           # all cases
  sudo bash tests/mutation/run.sh ssh       # filter by name
  ```
