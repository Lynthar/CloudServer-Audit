# CloudServer Audit - VPS 安全检查与加固工具

[English](README.md) | 简体中文

VPS 安全检查与加固脚本，为个人与小型运维场景设计的安全体检与修复工具。

## 特性

- **安全审计模式 (audit)**: 只读安全检查，生成 Markdown + JSON + SARIF 报告
- **交互式加固 (guide)**: 基于审计结果进行模块选择、修复和执行
- **模块化选择**: 按类别或单独选择要运行的安全模块
- **一键回滚 (rollback)**: 修改前自动备份，支持快速恢复
- **树形输出**: 紧凑的层级显示，技术检查项附带提示说明
- **多语言支持**: 中英文界面，支持 i18n
- **恶意软件检测**: 轻量级 rootkit、挖矿程序、webshell 扫描

## 系统要求

- Debian 12 / 13
- Ubuntu 22.04 / 24.04

## 快速开始

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/Lynthar/CloudServer-Audit/main/run.sh | sudo bash
```

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

vpssec 使用树形输出，紧凑易读：

```
├─ 访问控制
│  ├─ 用户安全
│  │  ├─ ✓ 无额外 UID 0 账户
│  │  └─ ✗ 检测到空密码用户
│  │     ↳ 无密码用户可无需认证登录
│  └─ SSH 安全
│     ├─ ✓ 已禁用密码认证
│     ├─ ✓ 已禁用 root 登录
│     └─ ● MaxAuthTries 过高
├─ 安全扫描
│  └─ 恶意软件检测
│     ├─ ✓ 无隐藏进程
│     ├─ ✓ 未发现挖矿程序
│     └─ ✗ 存在已删除二进制文件的进程
│        ↳ 程序文件已被删除但仍在运行 - 恶意软件常自删除以躲避检测
────────────────────────────────────────────────────────
  评分: 72/100

  ● 2 高危  ● 1 中危  ● 12 安全
```

**图例:**
- `✓` 绿色: 通过
- `✗` 红色: 高危问题
- `●` 黄色: 中危问题
- `○` 蓝色: 低危问题
- `↳` 提示: 技术检查项的简要说明

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
  audit       仅安全审计（默认）
  guide       交互式加固向导
  rollback    回滚之前的更改
  status      显示当前安全状态

选项:
  --lang=LANG       设置语言 (zh_CN, en_US)
  --include=MODS    仅运行指定模块（逗号分隔）
  --exclude=MODS    跳过指定模块
  --yes             自动确认非关键提示
  --json-only       仅输出 JSON（用于 CI/CD）
  --no-color        禁用彩色输出
  -h, --help        显示帮助
  --version         显示版本
```

## 安全评分

安全评分基于检查结果计算：

- 基础分：100
- 高危/严重问题：每个 -20 分（上限 -80）
- 中危问题：每个 -8 分（上限 -40）
- 低危问题：每个 -3 分（上限 -15）

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

### GitHub Actions

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 6 * * 1'  # 每周一
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

## 目录结构

```
vpssec/
├── vpssec              # 主入口脚本
├── run.sh              # 一键运行脚本
├── install.sh          # 安装脚本
├── core/               # 核心引擎
│   ├── common.sh       # 公共函数
│   ├── engine.sh       # 模块加载与执行
│   ├── state.sh        # 状态管理
│   ├── report.sh       # 报告生成（树形输出）
│   ├── security_levels.sh  # 修复安全与评分分类定义
│   ├── ui_tui.sh       # TUI 界面 (whiptail/dialog)
│   ├── ui_text.sh      # 文本降级界面
│   └── i18n/           # 国际化
│       ├── zh_CN.json
│       └── en_US.json
├── modules/            # 安全检查模块
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

2. 在 `engine.sh` 的 `VPSSEC_MODULE_ORDER` 中添加模块名

3. 在 `core/i18n/*.json` 中添加翻译

4. 在 `core/security_levels.sh` 中添加修复安全分类

## 许可证

GPL-3.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！
