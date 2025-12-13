# vpssec - VPS Security Check & Hardening Tool

[English](README.md) | 简体中文

VPS 安全检查与加固脚本，为个人与小型运维场景设计的安全体检与修复工具。

## 特性

- **安全审计模式 (audit)**: 只读安全检查，生成 Markdown + JSON + SARIF 报告
- **交互式加固 (guide)**: 基于审计结果进行模块选择、修复和执行
- **可回滚**: 所有被修改的文件均有时间戳快照，支持回滚
- **幂等性**: 重复执行不会引起额外副作用
- **多语言**: 支持中文 (zh_CN) 和英文 (en_US)
- **TUI 界面**: 支持 whiptail/dialog，无 TTY 时自动降级为文本模式
- **CI/CD 集成**: SARIF 格式输出，可集成到 GitHub Security 等平台
- **告警通知**: 支持 Webhook (Slack/Discord/Telegram) 和邮件告警

## 系统要求

- **操作系统**: Debian 12/13, Ubuntu 22.04/24.04
- **权限**: 需要 root 权限
- **依赖**: jq, ss, systemctl, sed, awk, tar, grep

## 安装

### 一键安装

```bash
# 使用安装脚本
curl -fsSL https://raw.githubusercontent.com/Lynthar/server-audit/main/install.sh | sudo bash
```

### 手动安装

```bash
# 克隆仓库
git clone https://github.com/Lynthar/server-audit.git
cd server-audit

# 添加执行权限
chmod +x vpssec

# 可选：创建符号链接到 PATH
sudo ln -s $(pwd)/vpssec /usr/local/bin/vpssec
```

## 快速开始

### 安全审计

```bash
# 运行完整安全检查
sudo ./vpssec audit

# 仅输出 JSON 格式
sudo ./vpssec audit --json-only

# 指定语言
sudo ./vpssec audit --lang=en_US
```

### 交互式加固

```bash
# 启动加固向导
sudo ./vpssec guide

# 仅检查 SSH 和 UFW 模块
sudo ./vpssec guide --include=ssh,ufw

# 排除 Docker 模块
sudo ./vpssec guide --exclude=docker

# 跳过非关键确认（SSH/UFW 仍需确认）
sudo ./vpssec guide --yes
```

### 回滚更改

```bash
# 交互式选择备份进行回滚
sudo ./vpssec rollback

# 回滚指定时间戳的备份
sudo ./vpssec rollback 20241213_120000
```

### 查看状态

```bash
./vpssec status
```

## 检查模块

### 核心模块（默认启用）

| 模块 | 说明 |
|------|------|
| preflight | 环境预检、网络状态、依赖检查 |
| ssh | SSH 加固（密码登录、root 登录、公钥认证） |
| ufw | UFW 防火墙配置 |
| update | 系统更新、自动安全更新 |
| docker | Docker 容器安全检查、daemon 配置 |
| nginx | Nginx 兜底配置 |
| baseline | 基线加固（AppArmor、未用服务） |
| logging | 日志持久化、审计系统 |

### 可选模块

| 模块 | 说明 |
|------|------|
| cloudflared | Cloudflare Tunnel 配置检查 |
| backup | 备份配置模板生成 (restic/borg) |
| alerts | 告警通知配置 (Webhook/邮件) |

## 命令行选项

```
用法: vpssec <命令> [选项]

命令:
  audit     只读安全检查，生成报告
  guide     交互式安全加固向导
  rollback  回滚之前的修改
  status    查看当前安全状态

选项:
  --lang=LANG      设置语言 (zh_CN|en_US)
  --no-color       禁用彩色输出
  --json-only      仅输出 JSON 格式
  --yes            跳过非关键确认
  --include=MODS   仅运行指定模块
  --exclude=MODS   排除指定模块
  --help           显示帮助信息
  --version        显示版本信息
```

## 目录结构

```
vpssec/
├── vpssec              # 主入口脚本
├── core/
│   ├── common.sh       # 公共函数
│   ├── engine.sh       # 核心引擎
│   ├── state.sh        # 状态管理
│   ├── report.sh       # 报告生成
│   ├── ui_tui.sh       # TUI 界面
│   ├── ui_text.sh      # 文本界面
│   └── i18n/
│       ├── zh_CN.json  # 中文
│       └── en_US.json  # 英文
├── modules/
│   ├── preflight.sh    # 环境预检
│   ├── ssh.sh          # SSH 加固
│   ├── ufw.sh          # UFW 防火墙
│   ├── update.sh       # 系统更新
│   ├── docker.sh       # Docker 安全
│   ├── nginx.sh        # Nginx 兜底
│   └── baseline.sh     # 基线加固
├── state/              # 状态文件
├── reports/            # 生成的报告
├── backups/            # 配置备份
└── logs/               # 日志文件
```

## 安全护栏

- **SSH 断连保护**: 变更前自动添加当前 IP 临时白名单，启用救援端口
- **原子写入**: 所有改动先写临时文件，验证通过后原子替换
- **配置快照**: 每次执行前对改动文件做 tar 快照
- **回滚机制**: 支持模块级与全局回滚
- **配置验证**: SSH/Nginx 等服务修改前自动验证配置

## 报告示例

### 终端输出

```
───────────────────────────────
VPS Security Check Summary
───────────────────────────────
SSH 加固             🔴 2 高危
UFW 防火墙           🟡 1 中风险
系统更新             🟢 安全
Docker 出口          🟡 暴露端口 8080
───────────────────────────────
综合评分：68/100
报告已保存：reports/summary.md
───────────────────────────────
```

### JSON 报告

报告保存在 `reports/summary.json`，包含详细的检查结果和修复建议。

## 开发

### 添加新模块

1. 在 `modules/` 目录创建新模块文件，如 `mymodule.sh`
2. 实现 `mymodule_audit()` 和 `mymodule_fix()` 函数
3. 在 `core/engine.sh` 的 `VPSSEC_MODULE_ORDER` 数组中添加模块名
4. 在 `core/i18n/*.json` 中添加翻译

### 模块接口

```bash
# 审计函数 - 执行只读检查，调用 state_add_check() 添加结果
mymodule_audit() {
    local check=$(create_check_json \
        "mymodule.check_id" \
        "mymodule" \
        "high" \
        "failed" \
        "检查标题" \
        "详细描述" \
        "修复建议" \
        "mymodule.fix_id")
    state_add_check "$check"
}

# 修复函数 - 执行修复操作
mymodule_fix() {
    local fix_id="$1"
    case "$fix_id" in
        mymodule.fix_id)
            # 执行修复
            ;;
    esac
}
```

## 许可证

GPL-3.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！
