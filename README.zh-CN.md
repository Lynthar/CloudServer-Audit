# CloudServer-Audit

[![license](https://img.shields.io/github/license/Lynthar/CloudServer-Audit)](LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/Lynthar/CloudServer-Audit/tests.yml?branch=main&label=tests)](https://github.com/Lynthar/CloudServer-Audit/actions/workflows/tests.yml)
[![shellcheck](https://img.shields.io/github/actions/workflow/status/Lynthar/CloudServer-Audit/shellcheck.yml?branch=main&label=shellcheck)](https://github.com/Lynthar/CloudServer-Audit/actions/workflows/shellcheck.yml)
[![release](https://img.shields.io/github/v/release/Lynthar/CloudServer-Audit)](https://github.com/Lynthar/CloudServer-Audit/releases)

可回滚的 Debian/Ubuntu 主机加固执行器；只读审计另覆盖 RHEL 系与 Arch

[English](README.md) | 简体中文

命令叫 `vpssec`，是纯 Bash 脚本，以 root 运行，一次处理一台机器，退出之后不留常驻进程。

审计模式是只读的，可以放心在任何机器上运行，看完报告就结束。引导加固模式会改
`/etc`：它会先把每个文件备份下来，把新版本验证通过之后才提交，并且能按时间戳把改动
复原。在动「禁用密码登录」或「禁用 root 登录」之前，它会在另一个端口先起一个 sshd，
确保你还能连得进来。

## 安装

一次性运行，除了装上的依赖（见下文）不在系统里留下文件：这条命令把最新 release 下载到
一个私有临时目录，验签、执行、然后自删。结束时选了保存报告的话，报告会拷到
`/tmp/vpssec-report-*`。

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

想让状态和备份在多次运行之间留存，就用下面这条装到本地（也可以直接 clone 本仓库）。
重跑同一条命令就是原地升级：

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/install.sh | sudo bash
sudo vpssec audit
```

`guide` 和 `rollback` 在一次性运行下会被拒绝，这是有意的：它们的备份会写在一个
退出时就删掉的目录里。**凡是会改动系统的操作，都要用装在本地的形式。**

环境变量要写在管道的 `bash` 那一侧：

```bash
curl -fsSL .../main/run.sh | sudo env VPSSEC_VERSION=v1.5.0 bash
```

服务器自带的那些（bash、coreutils、systemd、iproute2 里的 `ss`）之外，只额外需要
`jq`，缺了两个脚本都会自己装。验签用的 `cosign` 优先装发行版软件源里的；软件源里没有，
就装一个钉死版本、先核对哈希。脚本装上的东西都会留在系统里，一次性运行也一样。

## 用法

```bash
sudo vpssec audit
```

```bash
sudo vpssec audit --include=ssh,ufw,networking   # 只跑这几个模块
sudo vpssec audit --json-only                    # 给 CI 用：stdout 只出 JSON
sudo vpssec guide                                # 交互式走一遍修复
sudo vpssec guide --fix=ssh.enable_pubkey --yes  # 不出菜单，只执行指定修复
sudo vpssec rollback                             # 撤销上次运行改过的东西
```

两条不需要 root 也能跑：

```bash
vpssec status        # 版本、有没有新版本；root 下还有上次审计与修复、备份
vpssec help ssh      # 某个模块里的检查项与 fix id
```

结果出成 `summary.md` 给人读，`summary.json` 与 SARIF 2.1.0 给机器解析——`summary.md`
的格式会变，不要拿它做解析。三种输出都支持中英文（`--lang`，默认中文）。审计结束时会先问
要不要写进 `reports/`（默认不写）；带 `--yes` 或 `--json-only` 则总是写出。

## 检查什么

`vpssec audit` 跑 21 个模块共 355 项检查：

| 领域 | 项数 | 主要检查内容 |
|---|---|---|
| 系统与内核 | 83 | `sysctl` 的网络与内存参数及其开机后能否保持、挂载选项、全局可写与 SUID 文件、自动更新、时间同步、cron 与 `at` 的访问控制 |
| SSH 与账号 | 73 | sshd 配置从头到尾、密钥与口令登录、root 登录、空口令、sudo 规则、僵尸账号、口令时效 |
| 容器与 Web 应用 | 56 | Docker 守护进程暴露面、特权容器与 `--net=host`、socket 权限、nginx 的 TLS 与响应头、暴露的管理路径 |
| 检测与日志 | 53 | fail2ban 的 jail、rootkit 与可疑二进制扫描、journald 保留策略、日志权限、出事时到底有没有人会被通知到 |
| 网络与防火墙 | 46 | UFW 规则与默认策略、监听端口与你以为暴露的是否一致、nginx 反代暴露面、cloudflared 隧道 |
| 基线与运维 | 44 | 与上次运行的偏差、cloud-init 与云厂商 metadata 暴露、备份是否存在、依赖预检 |

**vpssec 能执行 50 个修复**，按可能造成的影响分档：25 个直接执行、20 个执行前询问、
5 个需要你在终端输入确认。另有 73 类发现只给建议、没有修复，要你手工处理。

## 配置

没有配置文件——行为由旗标和几个环境变量决定：

| 变量 | 作用 |
|---|---|
| `VPSSEC_VERSION` | 钉一个 release。默认取最新的那个，**永远不是 `main`** |
| `VPSSEC_LANG` | `zh_CN`（默认）或 `en_US`，同 `--lang=`。`sudo` 不会把你 shell 里的这个变量传下去，用 `sudo` 时请改用旗标 |
| `VPSSEC_INCLUDE` / `VPSSEC_EXCLUDE` | 等价于 `--include=` / `--exclude=` |
| `VPSSEC_NO_VERIFY=1` | 跳过签名校验——见[安全](#安全) |
| `INSTALL_DIR` | vpssec 目录本身的路径（不是它的父目录），默认 `/opt/vpssec`。已存在且不是 vpssec 的目录会被拒绝 |

状态、报告和备份都在安装目录下面。

## 能力边界

- **加固与回滚只支持 Debian 和 Ubuntu。** 审计也读 RHEL 系与 Arch，但 `guide` 在别的
  发行版上会在模块菜单之前就退出。Mint、Kali 这类 Debian 衍生版可以通过审计，
  但同样不能加固。
- **没有「一键全修」这个开关**，以后也不会有。高风险的修复需要在终端输入确认，
  `--yes` 不能跳过。
- **回滚只恢复文件。** 其余的改动——停掉的服务、防火墙规则、装上的软件包——会连同
  撤销命令一起打印并写进日志，由你自己执行。
- **它不是合规工具。** 没有 benchmark profile、没有控制项映射、没有豁免机制，
  那个分数不构成任何认证。
- **一次一台。** 没有 agent、没有服务端、没有集群视图。
- **分数只在同版本、同模块集之间可比。** 用了 `--include=` 的运行会自己标注为部分覆盖。

## 文档

- [用户指南](docs/user-guide.md) —— 命令参考、评分怎么算、八个核心模块的检测内容与手工修法、CI 集成。
- [兼容性说明](docs/compatibility.md) —— 语义化版本在这里覆盖什么、明确不覆盖什么。

## 安全

发布产物用 cosign keyless 签名，两个入口脚本都会验证签名确实来自**本仓库的 release
workflow、且对应被安装的那个精确 tag**。这挡不住本仓库自己被攻破——同一个 workflow
签出来的新版本照样验得过。`VPSSEC_NO_VERIFY=1` 会把这道检查整个关掉。

引导脚本是从 `main` 取的，所以安装这个动作等于信任本仓库在你执行命令那一刻的状态。
不接受这一点的话，从一个你已经审过的 release 里取脚本来运行，并把 `VPSSEC_VERSION`
设成它的 tag——不设的话，脚本装的是最新的 release，不是它们出自的那一个。

vpssec 与两个入口脚本自己发起的连接只有下面这些：

| 时机 | 目标 | 用途 |
|---|---|---|
| `audit` | `www.google.com`，不通再试 `www.baidu.com` | 外网连通性探测，5 秒 |
| `audit` | `169.254.169.254` · `100.100.100.200`（阿里云）· `metadata.tencentyun.com`（腾讯云）· `169.254.42.42`（Scaleway） | 实例元数据：判断是哪家云、IMDS 是否暴露，并读取 user-data 扫描其中的凭据（不保存、不打印）；1–2 秒 |
| `audit`，装了 cloudflared 时 | Cloudflare API，经 `cloudflared tunnel list` | 列出隧道，8 秒 |
| `status` | `api.github.com` | 检查有没有新版本，5 秒；`audit` 与 `guide` 从不调用 |
| `guide`，修复需要安装或升级软件包时 | 这台主机已配置的软件源 | 只针对你选中的修复 |
| `guide` 写出的告警脚本，在你把它们启用之后 | 你配置的 webhook 或邮件 | 发送你的告警；vpssec 本身从不发送 |
| `run.sh` / `install.sh` | `github.com` 与 `api.github.com` · sigstore · 缺 `jq` 或 `cosign` 时，你的软件源或 cosign 的 GitHub release | 下载 release（`latest` 经 API 解析成 tag），并按 cosign 的信任根验签；安装缺的依赖 |

在禁用密码或 root 登录之前，会在另一个端口起第二个 sshd 并要求你确认还能连进来。
修复改动文件之前，先把原件存进 `backups/<时间戳>/`。

目前没有私密的漏洞报告渠道。在建立之前，敏感问题请不要发公开 issue。

## 许可证

GNU 通用公共许可证 v3.0 —— 见 [LICENSE](LICENSE)。Copyright (c) 2026 Lynthar。
