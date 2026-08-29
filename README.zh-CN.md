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

一次性运行，不在系统里留下文件：这条命令把最新 release 下载到一个私有临时目录，验签、
执行、然后自删，报告拷到 `/tmp/vpssec-report-*`。

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
curl -fsSL .../main/run.sh | sudo env VPSSEC_VERSION=v1.3.1 bash
```

需要 `jq`。`cosign` 会在需要时按钉死的版本装上。

## 用法

```bash
sudo vpssec audit
```

```bash
sudo vpssec audit --include=ssh,ufw,networking   # 只跑这几个模块
sudo vpssec audit --json-only                    # 给 CI 用：stdout 只出 JSON
sudo vpssec guide                                # 交互式走一遍修复
sudo vpssec rollback                             # 撤销上次运行改过的东西
```

两条不需要 root：

```bash
vpssec status        # 上次运行、最新备份、有没有新版本
vpssec help ssh      # 某个模块里的检查项与 fix id
```

结果出成 `summary.md` 给人读，`summary.json` 与 SARIF 2.1.0 给机器解析——`summary.md`
的格式会变，不要拿它做解析。三种输出都支持中英文（`VPSSEC_LANG`）。

## 检查什么

`vpssec audit` 跑 21 个模块共 323 项检查：

| 领域 | 项数 | 主要检查内容 |
|---|---|---|
| 系统与内核 | 72 | `sysctl` 的网络与内存参数、挂载选项、全局可写与 SUID 文件、自动更新、时间同步、cron 与 `at` 的访问控制 |
| SSH 与账号 | 67 | sshd 配置从头到尾、密钥与口令登录、root 登录、空口令、sudo 规则、僵尸账号、口令时效 |
| 容器与 Web 应用 | 52 | Docker 守护进程暴露面、特权容器与 `--net=host`、socket 权限、nginx 的 TLS 与响应头、暴露的管理路径 |
| 检测与日志 | 47 | fail2ban 的 jail、rootkit 与可疑二进制扫描、journald 保留策略、日志权限、出事时到底有没有人会被通知到 |
| 网络与防火墙 | 45 | UFW 规则与默认策略、监听端口与你以为暴露的是否一致、nginx 反代暴露面、cloudflared 隧道 |
| 基线与运维 | 40 | 与上次运行的偏差、cloud-init 与云厂商 metadata 暴露、备份是否存在、依赖预检 |

**其中 124 项带修复动作**，按可能造成的影响分档：28 项直接执行、18 项执行前询问、
5 项需要你在终端输入确认，另外 73 项登记在案但**永不自动执行**。

## 配置

没有配置文件——行为由旗标和几个环境变量决定：

| 变量 | 作用 |
|---|---|
| `VPSSEC_VERSION` | 钉一个 release。默认取最新的那个，**永远不是 `main`** |
| `VPSSEC_LANG` | `zh_CN`（默认）或 `en_US` |
| `VPSSEC_INCLUDE` / `VPSSEC_EXCLUDE` | 等价于 `--include=` / `--exclude=` |
| `VPSSEC_NO_VERIFY=1` | 跳过签名校验——见[安全](#安全) |
| `INSTALL_DIR` | 安装位置，默认 `/opt/vpssec` |

状态、报告和备份都在安装目录下面。

## 能力边界

- **加固与回滚只支持 Debian 和 Ubuntu。** 审计也读 RHEL 系与 Arch，但 `guide` 在别的
  发行版上会在模块菜单之前就退出。Mint、Kali 这类 Debian 衍生版可以通过审计，
  但同样不能加固。
- **没有「一键全修」这个开关**，以后也不会有。高风险的修复需要在终端输入确认，
  `--yes` 不能跳过。
- **回滚只恢复文件。** 其余的改动——停掉的服务、建立的软链接——会连同撤销命令
  一起打印出来，由你自己执行。
- **它不是合规工具。** 没有 benchmark profile、没有控制项映射、没有豁免机制，
  那个分数不构成任何认证。
- **一次一台。** 没有 agent、没有服务端、没有集群视图。
- **分数只在同版本、同模块集之间可比。** 用了 `--include=` 的运行会自己标注为部分覆盖。

## 文档

- [用户指南](docs/user-guide.md) —— 完整命令参考、评分怎么算、每个模块、CI 集成。
- [兼容性说明](docs/compatibility.md) —— 语义化版本在这里覆盖什么、明确不覆盖什么。

## 安全

发布产物用 cosign keyless 签名，两个入口脚本都会验证签名确实来自**本仓库的 release
workflow、且对应被安装的那个精确 tag**。这挡不住本仓库自己被攻破——同一个 workflow
签出来的新版本照样验得过。`VPSSEC_NO_VERIFY=1` 会把这道检查整个关掉。

引导脚本是从 `main` 取的，所以安装这个动作等于信任本仓库在你执行命令那一刻的状态。
不接受这一点的话，从一个你已经审过的 release 里取脚本来运行。

在禁用密码或 root 登录之前，会在另一个端口起第二个 sshd 并要求你确认还能连进来。
每次运行都先写 `backups/<时间戳>/`。

目前没有私密的漏洞报告渠道。在建立之前，敏感问题请不要发公开 issue。

## 许可证

GNU 通用公共许可证 v3.0 —— 见 [LICENSE](LICENSE)。Copyright (c) 2026 Lynthar。
