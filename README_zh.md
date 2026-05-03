# CloudServer Audit - VPS 安全检查与加固工具

[English](README.md) | 简体中文 | [用户指南](docs/USER_GUIDE.md)

VPS 安全检查与加固脚本，为个人与小型运维场景设计的安全体检与修复工具。

## 特性

- **安全审计模式 (audit)**: 只读安全检查，生成 Markdown + JSON + SARIF 报告
- **交互式加固 (guide)**: 基于审计结果进行模块选择、修复和执行
- **模块化选择**: 按类别或单独选择要运行的安全模块
- **一键回滚 (rollback)**: 修改前自动备份，支持快速恢复
- **双列布局输出**: 简洁紧凑的双列布局，提高信息密度
- **多语言支持**: 中英文界面，支持 i18n
- **恶意软件检测**: 轻量级 rootkit、挖矿程序、webshell 扫描
- **详细用户指南**: 每项检测的详细说明与修复指南

## 系统要求

- Debian 12 / 13
- Ubuntu 22.04 / 24.04

## 快速开始

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

> **注意**：`curl | sudo bash` 通过 TLS 下载 tarball，但不校验签名或
> checksum。若需要更强的供应链信任，请使用下方的手动安装，或单独下
> 载 `run.sh`、审阅后再本地执行。

### 手动安装

```bash
git clone https://github.com/Lynthar/CloudServer-Audit.git
cd CloudServer-Audit
sudo ./vpssec audit
```

## 使用方法

### 安全审计（只读）

```bash
sudo ./vpssec audit
```

报告生成位置：
- `reports/summary.md` - Markdown 报告
- `reports/summary.json` - JSON 格式
- `reports/summary.sarif` - SARIF 格式（用于 CI/CD 集成）

### 交互式加固

```bash
sudo ./vpssec guide
```

提供交互界面：
1. 选择要检查的模块（按类别或全选）
2. 查看检测到的安全问题
3. 选择要修复的项目
4. 执行前预览变更
5. 执行修复并自动创建回滚点

### 回滚更改

```bash
sudo ./vpssec rollback
```

从自动备份中恢复之前的配置。

### 查看状态

```bash
sudo ./vpssec status
```

查看当前安全评分和状态。

## 模块分类

vpssec 将安全检查组织为 6 个类别。您可以选择要运行的类别：

| # | 类别 | 模块 | 说明 |
|---|------|------|------|
| 0 | 全部 | 所有模块 | 运行全面检查（推荐） |
| 1 | 访问控制 | `users`, `ssh` | 用户账户、SSH 加固 |
| 2 | 网络安全 | `ufw`, `fail2ban` | 防火墙、暴力破解防护 |
| 3 | 系统加固 | `update`, `kernel`, `filesystem`, `baseline` | 更新、内核参数、权限 |
| 4 | 服务安全 | `docker`, `nginx`, `cloudflared`, `webapp` | 容器、Web 服务器安全 |
| 5 | 安全扫描 | `malware` | rootkit、挖矿、webshell 检测 |
| 6 | 运维合规 | `logging`, `backup`, `alerts` | 日志、备份、监控 |

### 交互式模块选择

运行 vpssec 时，您会看到模块选择菜单：

```
┌──────────────────────────────────────────────────────────┐
│  请选择要检查的模块:                                      │
│                                                          │
│  [0] 全部模块（推荐）                                     │
│  [1] 访问控制           (users,ssh)                      │
│  [2] 网络安全           (ufw,fail2ban)                   │
│  [3] 系统加固           (update,kernel,...)              │
│  [4] 服务安全           (docker,nginx,webapp,...)        │
│  [5] 安全扫描           (malware)                        │
│  [6] 运维合规           (logging,backup,alerts)          │
└──────────────────────────────────────────────────────────┘
请输入选择（空格分隔，如 1 2 3）[默认: 0] >
```

> **说明**：无论选哪几个类别，`preflight`、`cloud`、`timezone` 都
> 会被自动加入——它们提供操作系统、网络、时钟基线，是其他模块的
> 前置上下文。

或使用命令行直接指定模块：
```bash
sudo ./vpssec audit --include=ssh,ufw,malware
```

## 安全模块

### 核心模块

| 模块 | 说明 |
|------|------|
| `preflight` | 环境预检（系统、网络、依赖） |
| `cloud` | 云厂商检测和监控代理审计 |
| `timezone` | 时区和 NTP 时间同步 |
| `users` | 用户安全审计（UID 0、空密码、可疑账户） |
| `ssh` | SSH 加固（密码认证、root 登录、公钥认证） |
| `ufw` | 防火墙配置（UFW/firewalld/iptables/nftables） |
| `fail2ban` | Fail2ban 安装和 SSH jail 配置 |
| `update` | 系统更新（安全更新、自动更新） |
| `kernel` | 内核加固（ASLR、sysctl 网络/安全参数、IPv6） |
| `filesystem` | 文件系统安全（SUID/SGID、权限、umask） |
| `baseline` | 基线加固（AppArmor/SELinux、未用服务） |
| `docker` | Docker 安全（特权容器、暴露端口） |
| `nginx` | Nginx 兜底（防止证书/主机名泄露） |
| `webapp` | Web 应用安全（Nginx/Apache/PHP 配置、SSL、敏感文件） |
| `malware` | 恶意软件检测（rootkit、挖矿程序、webshell、反向 shell） |
| `logging` | 日志与审计（journald、auditd、logrotate） |

### 可选模块

| 模块 | 说明 |
|------|------|
| `cloudflared` | Cloudflare Tunnel 配置检查 |
| `backup` | 备份工具检测和模板生成 |
| `alerts` | Webhook/邮件告警配置 |

## 输出格式

vpssec 使用简洁的双列布局输出，紧凑易读：

```
─── 访问控制 ─────────────────────────────────────────────────

  用户安全                               │  SSH 安全
    ✓ 无额外 UID 0 账户                  │    ✓ 已禁用密码认证
    ✗ 检测到空密码用户                   │    ✓ 已禁用 root 登录
    ✓ 系统账户已加固                     │    ● MaxAuthTries 过高

─── 安全扫描 ─────────────────────────────────────────────────

  恶意软件检测
    ✓ 无隐藏进程
    ✓ 未发现挖矿程序
    ✗ 存在已删除二进制文件的进程

────────────────────────────────────────────────────────
  评分: 69/100

  ● 2 高危  ● 1 中危  ● 12 安全
```

**图例:**
- `✓` 绿色: 通过
- `✗` 红色: 高危问题
- `●` 黄色: 中危问题
- `○` 蓝色: 低危问题

各检测项的详细说明和修复指南请参阅[用户指南](docs/USER_GUIDE.md)。

## 评分分类

检查项按类别计入评分，确保公平：

| 类别 | 说明 | 示例 |
|------|------|------|
| `required` | 始终计入评分 | SSH 认证、防火墙、内核 ASLR |
| `recommended` | 相关时计入 | fail2ban、AppArmor |
| `conditional` | 仅安装时计入 | Docker、Nginx、Cloudflared |
| `optional` | 较低权重 | auditd、alerts、backup |
| `info` | 不计入评分 | 云厂商检测 |

这样可以避免未使用的组件影响评分。

## 命令行选项

```bash
vpssec [模式] [选项]

模式:
  audit             仅安全审计（默认）
  guide             交互式加固向导
  rollback [TS]     回滚到指定时间戳的备份（不带参数则交互选择）
  status            显示当前安全状态
  help [MODULE]     列出所有模块和 fix_id；带 MODULE 参数则展示该
                    模块的审计/修复细节（无需 root，无副作用）

选项:
  --lang=LANG       设置语言 (zh_CN [默认], en_US)
  --include=MODS    仅运行指定模块（逗号分隔）
  --exclude=MODS    跳过指定模块
  --yes             自动确认非关键提示
  --json-only       仅输出 JSON（用于 CI/CD）
  --no-color        禁用彩色输出
  --debug           启用详细日志（写入 logs/vpssec.log）
  -h, --help        显示帮助
  --version         显示版本

环境变量覆盖:
  VPSSEC_FS_TIMEOUT=N   单次文件系统扫描的超时秒数（默认 60），
                        作用于 SUID/SGID/world-writable/no-owner
                        等扫描
```

## 安全评分

评分由"通过率基线 − 严重度加权惩罚"两部分合成（实现见
`core/state.sh` 的 `calculate_score`）：

```
base    = 100 × passed / scored_total
penalty = 5 × high + 1.5 × medium + 0.25 × low
score   = clamp(0, 100, base − penalty)
```

`scored_total` 只计入分类为 `required`、`recommended`、`conditional`
（当对应组件已安装时）以及 `optional` 的检查项。`info` 类仅供参
考，不计入分子也不计入分母——所以"未安装 Docker"或"已识别云厂
商"等说明性条目不会影响分数。

参考结果（按某台有约 50 个计分项的主机估算）：

| 失败项                            | 分数  | 区间       |
|-----------------------------------|-------|------------|
| 无失败                             | 100   | 优秀       |
| 1 项中危                           | 97    | 优秀       |
| 1 项高危                           | 93    | 良好       |
| 3 项高危                           | 79    | 中等       |
| 3 高危 + 6 中危 + 3 低危           | 53    | 中等       |
| 10 高危 + 20 中危 + 30 低危        | 0     | 严重       |

评分区间：
- 90-100：优秀
- 75-89：良好
- 50-74：中等
- 0-49：较差

## 安全护栏

- **原子写入**: 改动先写临时文件，验证后再移动
- **自动备份**: 所有修改的文件都带时间戳备份
- **SSH 保护**: SSH 配置变更前启用救援端口 (2222)
- **配置验证**: 应用前执行 `sshd -t` / `nginx -t` 验证
- **关键确认**: 重要操作需明确确认（不被 `--yes` 跳过）
- **修复分类**: 修复按安全/确认/风险/仅告警分类

## CI/CD 集成

vpssec 的设计目标是审计真实服务器。在一次性的 GitHub Actions runner 上
运行虽然能跑通，但结果主要反映的是 runner 镜像本身，而非你的基础设施。
下方 workflow 更适合作为"用 self-hosted runner / SSH 审计**你自己的服
务器**"的模板，而不是在 `ubuntu-latest` 上做有意义的检查。

### GitHub Actions（self-hosted runner 示例）

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 6 * * 1'  # 每周一
  workflow_dispatch:

jobs:
  audit:
    # 替换为指向要审计的生产服务器的 self-hosted runner 标签。
    runs-on: [self-hosted, my-production-host]
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Audit
        run: sudo ./vpssec audit --json-only

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/summary.sarif
```

## 目录结构

```
vpssec/
├── vpssec              # 主入口脚本
├── run.sh              # 一键运行脚本
├── install.sh          # 安装脚本（会校验 manifest.sha256）
├── manifest.sha256     # 所有 runtime 关键文件的 SHA-256；
│                       # 由 install.sh 的 verify_integrity 校验
├── core/               # 核心引擎
│   ├── common.sh       # 公共函数（日志、i18n、校验、原子写、
│   │                   # 单实例运行锁）
│   ├── engine.sh       # 模块加载、audit/guide 调度、计划续跑
│   ├── state.sh        # checks/plan/progress 状态、备份、评分
│   ├── report.sh       # 报告生成（双列布局输出）
│   ├── security_levels.sh  # 修复安全与评分分类定义
│   ├── help.sh         # `vpssec help [module]` 调度器
│   ├── ui_tui.sh       # TUI 界面 (whiptail/dialog)
│   ├── ui_text.sh      # 文本降级界面
│   └── i18n/           # 国际化
│       ├── zh_CN.json
│       └── en_US.json
├── modules/            # 安全检查模块（共 19 个）
│   ├── preflight.sh    # 环境预检
│   ├── cloud.sh        # 云厂商与代理检测
│   ├── timezone.sh     # 时区与 NTP
│   ├── users.sh        # 用户安全审计
│   ├── ssh.sh          # SSH 加固
│   ├── ufw.sh          # 防火墙 (UFW/firewalld/iptables/nftables)
│   ├── fail2ban.sh     # Fail2ban 配置
│   ├── update.sh       # 系统更新
│   ├── docker.sh       # Docker 安全
│   ├── nginx.sh        # Nginx 兜底
│   ├── webapp.sh       # Web 应用安全
│   ├── malware.sh      # 恶意软件检测
│   ├── baseline.sh     # 基线加固
│   ├── logging.sh      # 日志与审计
│   ├── kernel.sh       # 内核加固
│   ├── filesystem.sh   # 文件系统安全
│   ├── cloudflared.sh  # Cloudflare Tunnel
│   ├── backup.sh       # 备份配置
│   └── alerts.sh       # 告警通知
├── tests/              # bats 单元测试（用 `bats tests/` 运行）
├── tools/              # 开发者工具
│   └── gen-manifest.sh # 重新生成 manifest.sha256（任何 runtime
│                       # 关键文件改动后提交前都要跑一次）
├── docs/               # 用户文档
├── state/              # 状态文件（运行时）
├── reports/            # 生成的报告
├── backups/            # 配置备份
└── logs/               # 日志文件
```

## 扩展 vpssec

### 添加新模块

1. 创建 `modules/mymodule.sh`：

```bash
#!/usr/bin/env bash
# vpssec - 自定义模块

mymodule_audit() {
    print_item "检查某项内容..."

    local check=$(create_check_json \
        "mymodule.check_id" \
        "mymodule" \
        "medium" \
        "failed" \
        "检查标题" \
        "详细描述" \
        "修复方法" \
        "mymodule.fix_id")
    state_add_check "$check"
    print_severity "medium" "发现问题"
}

mymodule_fix() {
    case "$1" in
        mymodule.fix_id)
            print_info "正在修复..."
            # 修复逻辑
            print_ok "已修复"
            ;;
    esac
}
```

2. 在 `core/engine.sh` 的 `VPSSEC_MODULE_ORDER` 中添加模块名，
   并在 `VPSSEC_MODULE_CATEGORY` 中给它选好类别

3. **同时**在 `core/i18n/en_US.json` 与 `core/i18n/zh_CN.json` 中
   添加翻译——CI 的 `i18n-parity` 任务会拒绝 key 集合不一致的 PR

4. 在 `core/security_levels.sh` 中给每个 `fix_id` 选定分类
   （`FIX_SAFE` / `FIX_CONFIRM` / `FIX_RISKY` / `FIX_ALERT_ONLY`
   之一）

5. 运行 `bash tools/gen-manifest.sh` 并提交更新后的
   `manifest.sha256`——CI 的 `manifest-freshness` 任务会拒绝过时
   的 manifest

CI 中的 `module-contract` 任务会校验：每个 `VPSSEC_MODULE_ORDER`
里的模块都必须有对应的 `modules/<name>.sh` 并导出
`<name>_audit()` 与 `<name>_fix()`，且必须在
`VPSSEC_MODULE_CATEGORY` 中归类。

### 测试

```bash
bats tests/                 # 运行完整测试套件（约 239 用例）
bats tests/test_score.bats  # 单个测试文件
```

覆盖范围既包括纯函数（`count_lines`、`validate_*`、
`calculate_score`、修复分类、计划续跑过滤器、help 调度、
备份恢复路径安全），也包括各模块的解析器与回归测试：
UFW IPv6 一致性、UFW LIMIT vs ALLOW、nginx catchall 状态机
（含 IPv6 bracket 写法与端口边界）、journald drop-in 语义、
needrestart KSTA、可疑用户名回归、跨模块 `declare -g`
顶层数组作用域、webapp PHP 正则 / HSTS、baseline AppArmor、
cloudflared 用户 / 配置、文件系统权限 / umask、fail2ban
自定义 jail、malware 隐藏进程检测等。每个测试用例独立隔离
（各自的 `state/` / `backups/` / `logs/` 都在 `BATS_TEST_TMPDIR`
下），不会污染本地系统状态。

## 许可证

GPL-3.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！
