# vpssec

> 面向 Debian / Ubuntu VPS 的纯 Bash 安全审计与加固工具。
> 只读审计 · 引导式加固 · 原子回滚。

[English](README.md) | 简体中文 | [用户指南](docs/USER_GUIDE.md)

---

## 快速开始

一行命令安装（下载执行，报告复制到 `/tmp/vpssec-report-*`）：

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

或者克隆仓库手动运行（推荐重复使用）：

```bash
git clone https://github.com/Lynthar/CloudServer-Audit.git
cd CloudServer-Audit
sudo ./vpssec audit
```

报告生成在 `reports/summary.{md,json,sarif}`。

**支持系统：** Debian 12 / 13 · Ubuntu 22.04 / 24.04

一行命令下载最新 release tarball，**用 cosign keyless（sigstore + GitHub
Actions OIDC）验证签名**后才解包。签名身份锁定为本仓库的 `release.yml`
workflow，攻击者无法在不攻破 sigstore Fulcio CA 的情况下替换 tarball。
Ubuntu 22.04+ 走 `apt` 自动安装 `cosign`；Debian 等 apt 仓库无 cosign 的
系统会回退到从 sigstore GitHub release 下载 pinned 版本的 `.deb`，并在
`dpkg` 执行前本地校验 SHA256。fallback 路径把 cosign 的引导信任从 distro
仓库切到 github.com —— 与下载 `run.sh` 本身同源，不引入新的攻击面。完全
跳过验证用 `VPSSEC_NO_VERIFY=1`（不推荐）。

```bash
# 固定版本
VPSSEC_VERSION=v0.0.9 curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash

# 跳过验证（不推荐）
VPSSEC_NO_VERIFY=1   curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

手动验证某个 release：

```bash
TAG=v0.0.9
curl -LO https://github.com/Lynthar/CloudServer-Audit/releases/download/$TAG/vpssec-${TAG#v}.tar.gz
curl -LO https://github.com/Lynthar/CloudServer-Audit/releases/download/$TAG/vpssec-${TAG#v}.tar.gz.sig.json
cosign verify-blob \
  --bundle vpssec-${TAG#v}.tar.gz.sig.json \
  --certificate-identity-regexp '^https://github\.com/Lynthar/CloudServer-Audit/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vpssec-${TAG#v}.tar.gz
```

---

## 它做什么

| 模式 | 用途 |
|---|---|
| `audit` | 只读安全检测 → Markdown + JSON + SARIF 报告 |
| `guide` | 交互式加固向导，带安全闸门 |
| `rollback` | 从每次运行的备份中恢复任意变更 |
| `status` | 上次运行摘要 + 最新备份信息 |

每条检测都有稳定的 `check_id`；可修复项还有 `fix_id`，你可以从报告里
手动执行，或者通过 `guide` 交互式执行。

---

## 模块速览

**21 个模块**，按 6 类组织。默认全跑；可以通过 CLI 或交互菜单选子集：

```bash
sudo ./vpssec audit --include=ssh,ufw,networking
```

| # | 类别 | 模块 |
|---|---|---|
| 1 | 访问控制 | `users`, `ssh` |
| 2 | 网络安全 | `ufw`, `fail2ban`, `networking` |
| 3 | 系统加固 | `update`, `kernel`, `filesystem`, `baseline` |
| 4 | 服务安全 | `docker`, `nginx`, `cloudflared`, `webapp` |
| 5 | 安全扫描 | `malware` |
| 6 | 运维合规 | `logging`, `backup`, `alerts`, `scheduling` |

> `preflight`、`cloud`、`timezone` 始终作为上下文模块自动运行。

每个模块的检测项详解和修复方法，见[**用户指南**](docs/USER_GUIDE.md)。

---

## 示例输出

```
─── 访问控制 ────────────────────────────────────────────────────
  用户安全                       │  SSH 安全
    ✓ 无额外 UID 0 账户          │    ✓ 密码登录已禁用
    ✗ 检测到空密码账户           │    ● MaxAuthTries 过高
    ✓ 系统账户已锁定             │    ● 未配置 SSH 访问控制

─── 安全扫描 ────────────────────────────────────────────────────
  恶意软件检测
    ✓ 未发现隐藏进程
    ✗ 检测到已删除二进制进程

────────────────────────────────────────────────────────────────
  Score: 69 / 100   ● 2 High   ● 1 Medium   ● 12 Safe
```

图例：`✓` 通过 · `✗` 高危 · `●` 中危 · `○` 低危

---

## 安全保障

vpssec 会改 `/etc/*` 配置文件。为此设了几道防线：

- **原子写入** —— 写临时文件、校验、再 rename。不会留下半个写完的配置。
- **每次运行都备份** —— `backups/<时间戳>/` 镜像所有被改文件，`rollback` 可任意恢复某次运行。
- **改动前先校验** —— `sshd -t`、`nginx -t`、`visudo -c` 都在 staged 文件上跑过才上线。
- **SSH 救援端口** —— 改 `sshd_config` 前自动开放 2222 端口，配置错也不会把你锁出去。
- **关键操作强制确认** —— 防火墙启用、密码登录禁用等高危操作必须显式确认，`--yes` 无法跳过。
- **修复分级** —— 每个 fix 标记为 `safe` / `confirm` / `risky` / `alert_only`，risky 项执行前显式告警。

---

## 常用命令

```bash
# 审计
sudo ./vpssec audit                    # 完整审计（首次推荐）
sudo ./vpssec audit --include=ssh      # 只跑指定模块
sudo ./vpssec audit --exclude=docker   # 排除某模块
sudo ./vpssec audit --json-only        # CI 友好输出
sudo ./vpssec audit --lang=en_US       # 英文输出（默认 zh_CN）
sudo ./vpssec audit --debug            # 详细日志写到 logs/vpssec.log

# 加固和恢复
sudo ./vpssec guide                    # 交互式加固
sudo ./vpssec rollback                 # 恢复上次配置

# 查看（不需要 root）
./vpssec status                        # 上次运行 + 备份状态
./vpssec help                          # 列出所有模块和 fix_id
./vpssec help ssh                      # 某个模块的详情
```

完整 CLI 参考：[用户指南 → 命令参考](docs/USER_GUIDE.md#附录-a-vpssec-命令参考)。

---

## 安全评分

分数由"通过率基线"与"严重度加权惩罚"组合而成：

```
base    = 100 × passed / scored_total
penalty = 5 × high + 1.5 × medium + 0.25 × low
score   = clamp(0, 100, base − penalty)
```

档位：`90+ 优秀 · 75–89 良好 · 50–74 一般 · <50 较差`。

`info` 类检查项（如云厂商识别）不计入评分。完整模型见
[用户指南 → 安全评分](docs/USER_GUIDE.md#附录-b-安全评分计算)。

---

## 贡献

欢迎 PR。

- 架构和模块扩展规范：[`CLAUDE.md`](CLAUDE.md)
- 单元测试：`bats tests/`（约 240 个用例）
- 变异测试 harness（注入缺陷验证检测）：`tests/mutation/` —— 仅在可丢弃的 VM 上跑
- commit 前更新 manifest：`bash tools/gen-manifest.sh && git add manifest.sha256`
- 发布版本：在 main 打 `vX.Y.Z` tag 并 push —— `release.yml` 会用 cosign keyless 构建+签名 tarball 并创建 GitHub release

## 许可证

[GPL-3.0](LICENSE)
