# vpssec

> 面向 Linux VPS 的纯 Bash 安全审计与加固工具。
> 审计(只读):Debian/Ubuntu/RHEL/Arch · 引导式加固 + 回滚:Debian/Ubuntu。

[English](README.md) | 简体中文 | [用户指南](docs/user-guide.md)

---

## 快速开始

**一次性运行，不安装任何东西。** 把最新发布版下载到临时目录，验签、运行，退出时自删。
若选择保存，报告会复制到 `/tmp/vpssec-report-*`：

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

跑完机器上不留任何东西，**`backups/` 也不留**。因此**这条路径拒绝 `guide` 与 `rollback`**（退出码 2，
错误消息里直接给出安装命令）：修复写入的备份就在这个退出即删的目录里，从这里加固等于改了 `/etc`
又在同一条命令里销毁了撤销它的唯一凭据。审计是只读的，不受影响。

**安装到本地重复使用。** 同一个发布版、同一道验签，但装进 `/opt/vpssec` 并在 `PATH` 里留下
`vpssec` 命令，升级时保留 `state/` 与 `backups/`：

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | sudo bash

sudo vpssec audit          # 任何目录下都能跑
sudo vpssec status         # 上次运行、最新备份，以及是否有更新版本
```

升级就是重跑同一条命令——`state/` 与 `backups/` 会先移走再放回，重装不会带走 `vpssec rollback`
所依赖的数据。卸载用 `sudo /opt/vpssec/uninstall.sh`（删除状态与备份前会询问，默认保留）。

两条入口装的都是**最新发布版**，都不是 `main` 分支。用 `VPSSEC_VERSION` 钉具体版本、
用 `INSTALL_DIR` 换安装位置——见下方环境变量说明，注意它们必须写在管道的 `bash` 那一侧。

**或者从克隆的仓库运行**（开发用，或想先读代码再运行）：

```bash
git clone https://github.com/Lynthar/CloudServer-Audit.git
cd CloudServer-Audit
sudo ./vpssec audit
```

克隆跟的是 `main`，它领先于最新发布版且没有签名。生产主机请用发布版。

交互式审计结束后会提示是否保存；选择保存才会写入 `reports/summary.{md,json,sarif}`。`--json-only` 同样会重写这三个文件，只是仅把 JSON 打印到标准输出——这样 CI 里发布 Markdown 或消费 SARIF 的环节不会读到上一轮跑剩下的旧文件。

`--json-only` 与 `--yes` 都意味着非交互运行：语言 / 模式 / 模块三个菜单会被跳过，直接采用默认值（审计、全部模块）。

**审计(只读)：** Debian 12/13 · Ubuntu 22.04/24.04/26.04 · RHEL 8/9/10 家族(Rocky / Alma / CentOS Stream) · Arch

**引导式加固 + 回滚：** 仅 Debian / Ubuntu

`run.sh` 与 `install.sh` 都会下载 release tarball，**用 cosign keyless（sigstore
+ GitHub Actions OIDC）验证签名**后才解包。签名身份锁定为本仓库的 `release.yml`
workflow 在**所装 tag** 上的那次签名，被调包或换标签的 release 资产过不了
验证。但保证的边界要说清：它验证的是"资产出自本仓库的发布流水线"，防不住
仓库本身被攻破——拿到仓库写权限的人可以走正规流水线签出新版本，也可以直接
改 `main` 上的这两个引导脚本。想要更强的锚点，请从你已经审计过的 release
里下载引导脚本，而不是从 `main` 取。
Ubuntu 22.04+ 走 `apt` 自动安装 `cosign`；其它系统从 sigstore GitHub
release 下载 pinned 资产、先本地校验 SHA256 再安装——Debian 用 `.deb`
（`dpkg`），RHEL/Arch 等无 dpkg 的系统装静态 `cosign` 二进制到
`/usr/local/bin`。fallback 路径把 cosign 的引导信任从 distro
仓库切到 github.com —— 与下载引导脚本本身同源，不引入新的攻击面。完全
跳过验证用 `VPSSEC_NO_VERIFY=1`（不推荐）。

下面每个变量都必须设在管道的 **bash** 那一侧：写反了——`VPSSEC_VERSION=… curl … | sudo bash`
——变量只传给了 `curl`，脚本根本看不到。

```bash
# 固定版本（v1.3.0 与 1.3.0 两种写法都收）
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo env VPSSEC_VERSION=v1.3.0 bash

# 装到 /opt/vpssec 以外的位置
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | sudo env INSTALL_DIR=/opt/vpssec-staging bash

# 跳过验证（不推荐）。两条入口都适用。
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo env VPSSEC_NO_VERIFY=1 bash
```

手动验证某个 release：

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

## 它做什么

| 模式 | 用途 |
|---|---|
| `audit` | 只读安全检测 → Markdown + JSON + SARIF 报告 |
| `guide` | 交互式加固向导，带安全闸门 |
| `rollback` | 恢复某次运行备份下的文件（服务状态/软链不在其内——vpssec 改动它们时会打印并记录撤销命令） |
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

每个模块的检测项详解和修复方法，见[**用户指南**](docs/user-guide.md)。

---

## 示例输出

```
─── 访问控制 ────────────────────────────────────────────────────
  用户安全                       │  SSH 安全
    ✓ 无额外 UID 0 账户          │    ✓ 密码登录已禁用
    ✗ 检测到空密码账户           │    ● authorized_keys 权限过松
    ✓ 系统账户已锁定             │    ○ MaxAuthTries 超过 4

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
- **每次运行都备份** —— `backups/<时间戳>/` 镜像所有被改文件，`rollback` 恢复其中任意一次；不是文件的副作用（禁用的服务、创建的软链）按 vpssec 当时打印并记录的撤销命令还原。
- **改动前先校验** —— `sshd -t`、`nginx -t`、`visudo -c` 都在 staged 文件上跑过才上线。
- **SSH 救援端口** —— 在两个可能锁死连接的变更（禁用密码登录/禁用 root 登录）动手之前，先在空闲端口（默认 2222）拉起第二个 sshd，并要求你确认能连上，才碰线上配置。
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

完整 CLI 参考：[用户指南 → 命令参考](docs/user-guide.md#附录-a-vpssec-命令参考)。

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
[用户指南 → 安全评分](docs/user-guide.md#附录-b-安全评分计算)。

**只有模块范围相同的两次运行，分数才可比。** `base` 随计分检查数缩放，
`penalty` 不随之缩放——因此 `--include=` 选的范围越窄，惩罚占比越重；
若子集里被计分的检查恰好全部失败，无论问题多轻，分数都会落到 0。
用了 `--include`/`--exclude` 的运行会在分数旁明确标注（"部分评分：仅基于
… 项计分检查"），`summary.json` 里也会带上 `meta.partial_scope` 与
`stats.scored_total`。

---

## 贡献

欢迎 PR。

- 架构和模块扩展规范：见 `<module>_audit` / `<module>_fix` 契约和 `core/` 下的注释
- 单元测试：`bats tests/`（800+ 用例，具体数以 CI 为准）
- 变异测试有两套工具、问两个问题：`bash tools/mutate-all.sh` 往模块源码里植入缺陷，问配对的 bats 套件能不能发现（哪里都能跑）；`tests/mutation/` 往**真实 `/etc`** 里植入错误配置，问审计能不能发现——后者仅在可丢弃的 VM 上跑
- commit 前更新 manifest：`bash tools/gen-manifest.sh && git add manifest.sha256`
- 发布版本：先改 `VERSION` 并提交，再打对应的 `vX.Y.Z` tag 并 push —— `release.yml` 会拒绝与 `VERSION` 不一致的 tag，通过后用 cosign keyless 构建+签名 tarball 并创建 GitHub release

## 许可证

[GPL-3.0](LICENSE)
