# CloudServer-Audit vs Lynis 检查项对比

本文档详细对比 CloudServer-Audit 与 Lynis 在安全检查项目上的差异。

## 概述

| 特性 | CloudServer-Audit | Lynis |
|------|-------------------|-------|
| **检查项总数** | ~180+ | ~449 |
| **目标用户** | 个人 VPS 用户、业余爱好者 | 企业安全团队、合规审计 |
| **支持系统** | Debian 12/13, Ubuntu 22.04/24.04 | Linux, macOS, BSD, Solaris, AIX |
| **自动修复** | ✅ 支持 (guide 模式) | ❌ 仅审计报告 |
| **回滚功能** | ✅ 支持 | ❌ 不适用 |
| **合规标准** | ❌ | ✅ HIPAA, PCI-DSS, ISO27001 |
| **恶意软件检测** | ✅ 内置检测 | ❌ 仅检查是否安装扫描工具 |
| **中文支持** | ✅ | ❌ |

---

## 检查分类详细对比

### 1. 系统与启动 (Boot & System)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| 操作系统检测 | ✅ | ✅ |
| 内核版本检查 | ✅ | ✅ |
| Bootloader (GRUB/LILO) 安全 | ❌ | ✅ |
| Bootloader 密码保护 | ❌ | ✅ |
| 启动权限检查 | ❌ | ✅ |
| 运行级别检查 | ❌ | ✅ |
| 系统重启需求检测 | ✅ | ✅ |
| 容器环境检测 | ✅ | ✅ |

### 2. 内核安全 (Kernel Security)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| ASLR 地址空间随机化 | ✅ | ✅ |
| Sysctl 网络安全参数 | ✅ | ✅ |
| IP 转发检测 | ✅ | ✅ |
| ICMP 重定向 | ✅ | ✅ |
| SYN Cookies | ✅ | ✅ |
| 源路由验证 | ✅ | ✅ |
| IPv6 安全配置 | ✅ | ✅ |
| 内核模块加载检查 | ❌ | ✅ |
| Core Dump 限制 | ✅ | ✅ |
| 非特权用户命名空间 | ✅ | ✅ |
| BPF 限制 | ✅ | ✅ |
| Ptrace 范围 | ✅ | ✅ |
| Dmesg 限制 | ✅ | ✅ |
| I/O 调度器检查 | ❌ | ✅ |
| 内核配置文件检查 | ❌ | ✅ |

### 3. 用户与认证 (Users & Authentication)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| 空密码账户检测 | ✅ | ✅ |
| 系统账户 Shell 检查 | ✅ | ✅ |
| Sudo 用户枚举 | ✅ | ✅ |
| NOPASSWD Sudo 检测 | ✅ | ✅ |
| 可疑用户名检测 | ✅ | ❌ |
| 最近创建用户 | ✅ | ❌ |
| 密码策略 (login.defs) | ✅ | ✅ |
| 密码复杂度 (pwquality) | ✅ | ✅ |
| PAM 配置检查 | ❌ | ✅ |
| 密码哈希算法 | ❌ | ✅ |
| 账户锁定策略 | ❌ | ✅ |
| UID 0 非 root 用户 | ❌ | ✅ |
| 用户目录权限 | ✅ | ✅ |
| Shell 历史安全 | ✅ | ❌ |
| LDAP 认证检查 | ❌ | ✅ |

### 4. SSH 安全 (SSH Security)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| SSH 端口检测 | ✅ | ✅ |
| Root 登录禁用 | ✅ | ✅ |
| 密码认证状态 | ✅ | ✅ |
| 公钥认证状态 | ✅ | ✅ |
| 空密码登录 | ✅ | ✅ |
| MaxAuthTries 限制 | ✅ | ✅ |
| LoginGraceTime | ✅ | ✅ |
| AllowUsers/AllowGroups | ✅ | ✅ |
| SSH 密钥权限 | ✅ | ✅ |
| 弱加密算法检测 | ✅ | ✅ |
| X11 Forwarding | ❌ | ✅ |
| TCP KeepAlive | ❌ | ✅ |
| Agent Forwarding | ❌ | ✅ |
| StrictModes | ❌ | ✅ |
| SSH 版本检测 | ❌ | ✅ |
| 管理员用户存在检测 | ✅ | ❌ |

### 5. 文件系统 (Filesystem)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| SUID 文件检测 | ✅ | ✅ |
| SGID 文件检测 | ✅ | ✅ |
| 全局可写文件 | ✅ | ✅ |
| 敏感文件权限 | ✅ | ✅ |
| /tmp 挂载选项 | ✅ | ✅ |
| Umask 配置 | ✅ | ✅ |
| 文件能力 (Capabilities) | ✅ | ✅ |
| ACL 支持检查 | ❌ | ✅ |
| 分区加密 (LUKS) | ❌ | ✅ |
| Sticky bit 目录 | ❌ | ✅ |
| 无属主文件 | ❌ | ✅ |
| 隐藏文件检测 | ❌ | ✅ |
| /var, /home 分区检查 | ❌ | ✅ |
| Swap 加密 | ❌ | ✅ |

### 6. 防火墙 (Firewall)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| UFW 状态检查 | ✅ | ✅ |
| iptables 规则 | ✅ | ✅ |
| nftables 检测 | ✅ | ✅ |
| 默认策略 (DENY/ACCEPT) | ✅ | ✅ |
| SSH 端口规则 | ✅ | ❌ |
| 过于宽松规则检测 | ✅ | ❌ |
| 危险端口暴露检测 | ✅ | ❌ |
| pf 防火墙 (BSD) | ❌ | ✅ |
| firewalld 检查 | ❌ | ✅ |
| IPv6 防火墙规则 | ✅ | ✅ |

### 7. 网络与端口 (Network & Ports)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| 监听端口检测 | ✅ | ✅ |
| 危险端口暴露 | ✅ | ❌ |
| 网络连接检查 | ✅ | ❌ |
| 外部连通性测试 | ✅ | ❌ |
| 混杂模式接口 | ❌ | ✅ |
| IPv6 状态 | ✅ | ✅ |
| DHCP 客户端 | ❌ | ✅ |
| 网络接口配置 | ❌ | ✅ |

### 8. 日志与审计 (Logging & Auditing)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| Journald 持久化 | ✅ | ✅ |
| Logrotate 配置 | ✅ | ✅ |
| Auditd 状态 | ✅ | ✅ |
| Auditd 规则检查 | ✅ | ✅ |
| SSH 登录失败统计 | ✅ | ❌ |
| Sudo 日志 | ✅ | ❌ |
| Syslog 守护进程 | ❌ | ✅ |
| 远程日志 | ❌ | ✅ |
| 日志文件权限 | ❌ | ✅ |

### 9. 恶意软件检测 (Malware Detection)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| 隐藏进程检测 | ✅ | ❌ |
| 隐藏端口检测 | ✅ | ❌ |
| LD_PRELOAD 劫持 | ✅ | ❌ |
| 可疑内核模块 | ✅ | ❌ |
| 已删除二进制运行检测 | ✅ | ❌ |
| 内存执行检测 (memfd) | ✅ | ❌ |
| 挖矿进程检测 | ✅ | ❌ |
| 挖矿矿池连接 | ✅ | ❌ |
| 反向 Shell 检测 | ✅ | ❌ |
| WebShell 检测 | ✅ | ❌ |
| CPU 异常检测 | ✅ | ❌ |
| ClamAV 安装检查 | ❌ | ✅ |
| Rkhunter 安装检查 | ❌ | ✅ |
| Chkrootkit 安装检查 | ❌ | ✅ |
| AIDE 安装检查 | ❌ | ✅ |

**说明**: Lynis 仅检查是否安装了恶意软件扫描工具，而 CloudServer-Audit 内置实际的恶意软件检测功能。

### 10. 系统更新 (System Updates)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| 可用更新检测 | ✅ | ✅ |
| 安全更新检测 | ✅ | ✅ |
| 自动更新配置 | ✅ | ✅ |
| 包管理器状态 | ✅ | ✅ |
| APT/YUM/Pacman 检查 | ✅ (APT only) | ✅ |

### 11. 时间同步 (Time Synchronization)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| NTP 同步状态 | ✅ | ✅ |
| Chronyd/timesyncd | ✅ | ✅ |
| 时区配置 | ✅ | ✅ |
| 时间偏移检测 | ✅ | ✅ |
| RTC 时钟设置 | ✅ | ❌ |

### 12. 容器安全 (Container Security)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| Docker 安装检测 | ✅ | ✅ |
| 特权容器检测 | ✅ | ✅ |
| Root 运行容器 | ✅ | ✅ |
| 暴露端口检测 | ✅ | ❌ |
| 额外能力检测 | ✅ | ❌ |
| Daemon 安全配置 | ✅ | ✅ |
| Live-restore 配置 | ✅ | ❌ |
| 容器数量统计 | ❌ | ✅ |

### 13. Web 服务器 (Web Server)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| Nginx 安装检测 | ✅ | ✅ |
| Apache 安装检测 | ✅ | ✅ |
| Server Tokens 隐藏 | ✅ | ✅ |
| 安全 Headers | ✅ | ✅ |
| SSL/TLS 协议 | ✅ | ✅ |
| 弱加密套件 | ✅ | ✅ |
| HSTS 配置 | ✅ | ✅ |
| 目录列表 | ✅ | ✅ |
| 模块安全检查 | ✅ | ✅ |
| PHP 安全配置 | ✅ | ✅ |
| 敏感文件暴露 | ✅ | ❌ |
| WebShell 检测 | ✅ | ❌ |
| SSL 证书过期 | ✅ | ✅ |
| ModSecurity WAF | ❌ | ✅ |

### 14. Fail2ban (暴力破解防护)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| Fail2ban 安装检测 | ✅ | ✅ |
| 服务状态 | ✅ | ✅ |
| SSH Jail 配置 | ✅ | ❌ |
| Jail 激活状态 | ✅ | ❌ |

### 15. 强制访问控制 (MAC Frameworks)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| AppArmor 状态 | ✅ | ✅ |
| SELinux 状态 | ✅ | ✅ |
| AppArmor 配置文件 | ✅ | ✅ |
| SELinux 拒绝统计 | ✅ | ✅ |
| TOMOYO 检测 | ❌ | ✅ |
| GRSecurity 检测 | ❌ | ✅ |

### 16. 数据库安全 (Database Security)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| MySQL/MariaDB 检测 | ❌ | ✅ |
| PostgreSQL 检测 | ❌ | ✅ |
| MongoDB 检测 | ❌ | ✅ |
| Redis 检测 | ❌ | ✅ |
| Oracle 检测 | ❌ | ✅ |
| 数据库端口暴露 | ✅ (preflight) | ❌ |

### 17. 邮件服务 (Mail Services)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| Postfix 检测 | ❌ | ✅ |
| Exim 检测 | ❌ | ✅ |
| Dovecot 检测 | ❌ | ✅ |
| 邮件中继检查 | ❌ | ✅ |

### 18. 文件完整性 (File Integrity)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| AIDE 检测 | ❌ | ✅ |
| Tripwire 检测 | ❌ | ✅ |
| Samhain 检测 | ❌ | ✅ |
| OSSEC 检测 | ❌ | ✅ |
| dm-verity 检测 | ❌ | ✅ |
| IMA/EVM 检测 | ❌ | ✅ |

### 19. 加密 (Cryptography)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| SSL 证书检查 | ✅ | ✅ |
| 磁盘加密 (LUKS) | ❌ | ✅ |
| 熵源检查 | ❌ | ✅ |
| 冷启动攻击防护 | ❌ | ✅ |

### 20. 其他服务 (Other Services)

| 检查项 | CloudServer-Audit | Lynis |
|--------|:-----------------:|:-----:|
| NFS 导出检查 | ❌ | ✅ |
| SNMP 配置 | ❌ | ✅ |
| LDAP 服务 | ❌ | ✅ |
| Squid 代理 | ❌ | ✅ |
| DNS 服务 | ❌ | ✅ |
| 打印服务 (CUPS) | ❌ | ✅ |
| Cloudflared 隧道 | ✅ | ❌ |

### 21. CloudServer-Audit 独有功能

| 功能 | 说明 |
|------|------|
| **自动修复 (Guide 模式)** | 交互式引导修复安全问题 |
| **备份与回滚** | 修改前自动备份，支持回滚 |
| **实时恶意软件检测** | 内置检测隐藏进程、挖矿、WebShell |
| **双栏输出布局** | 紧凑美观的报告格式 |
| **中文支持** | 完整的中文界面和文档 |
| **危险端口告警** | 检测常见高危端口暴露 |
| **SSH 攻击统计** | 24小时内登录失败统计 |
| **可疑用户名检测** | 检测 admin, test, guest 等可疑账户 |

### 22. Lynis 独有功能

| 功能 | 说明 |
|------|------|
| **合规审计** | HIPAA, PCI-DSS, ISO27001 等合规检查 |
| **企业版支持** | CISOfy 提供企业级支持和功能 |
| **跨平台** | 支持 macOS, BSD, Solaris, AIX |
| **Hardening Index** | 系统加固指数评分 |
| **插件系统** | 支持自定义测试插件 |
| **数据库检查** | 完整的数据库安全审计 |
| **邮件服务检查** | Postfix, Exim, Dovecot 等 |
| **DNS 服务检查** | BIND, PowerDNS 等 |
| **打印服务检查** | CUPS 配置审计 |

---

## 统计汇总

| 分类 | CloudServer-Audit | Lynis |
|------|:-----------------:|:-----:|
| 系统与启动 | 4/8 | 8/8 |
| 内核安全 | 12/15 | 15/15 |
| 用户与认证 | 12/15 | 13/15 |
| SSH 安全 | 13/16 | 14/16 |
| 文件系统 | 8/14 | 14/14 |
| 防火墙 | 7/10 | 8/10 |
| 网络与端口 | 5/8 | 5/8 |
| 日志与审计 | 6/9 | 7/9 |
| 恶意软件 | 11/14 | 4/14 |
| Web 服务器 | 13/14 | 11/14 |
| 容器安全 | 6/8 | 5/8 |
| 数据库 | 1/6 | 6/6 |
| 邮件服务 | 0/4 | 4/4 |

---

## 总结

### CloudServer-Audit 优势

1. **实用性强**: 内置自动修复功能，不只是报告问题
2. **恶意软件检测**: 真正检测隐藏进程、挖矿软件、WebShell
3. **上手简单**: 专为个人 VPS 用户设计，无需安全专业知识
4. **中文友好**: 完整的中文界面和详细使用指南
5. **安全修改**: 备份回滚机制，修改可逆

### Lynis 优势

1. **覆盖全面**: 449+ 检查项，涵盖几乎所有安全领域
2. **企业级**: 支持合规审计 (HIPAA, PCI-DSS, ISO27001)
3. **跨平台**: 支持多种 Unix 系统
4. **成熟稳定**: 开发历史悠久，社区活跃
5. **可扩展**: 支持自定义插件和测试

### 使用场景建议

| 场景 | 推荐工具 |
|------|----------|
| 个人 VPS 快速安全检查 | CloudServer-Audit |
| 自动修复常见安全问题 | CloudServer-Audit |
| 恶意软件/挖矿检测 | CloudServer-Audit |
| 企业合规审计 | Lynis |
| 多平台统一审计 | Lynis |
| 详细安全评估报告 | Lynis |
| 数据库/邮件服务检查 | Lynis |

---

## 参考资料

- [CloudServer-Audit GitHub](https://github.com/Lynthar/CloudServer-Audit)
- [Lynis Official Website](https://cisofy.com/lynis/)
- [Lynis GitHub](https://github.com/CISOfy/lynis)

*最后更新: 2024年12月*
