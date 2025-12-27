# CloudServer-Audit 检测项详解与修复指南

本指南详细说明脚本的每项安全检测内容，帮助您理解检测结果并解决发现的问题。

---

## 目录

1. [结果图标说明](#结果图标说明)
2. [用户安全检测 (users)](#用户安全检测-users)
3. [SSH 安全检测 (ssh)](#ssh-安全检测-ssh)
4. [内核安全检测 (kernel)](#内核安全检测-kernel)
5. [文件系统检测 (filesystem)](#文件系统检测-filesystem)
6. [防火墙检测 (ufw)](#防火墙检测-ufw)
7. [入侵防护检测 (fail2ban)](#入侵防护检测-fail2ban)
8. [Docker 安全检测 (docker)](#docker-安全检测-docker)
9. [恶意软件检测 (malware)](#恶意软件检测-malware)
10. [常见问题解答](#常见问题解答)

---

## 结果图标说明

| 图标 | 含义 | 说明 |
|------|------|------|
| ✓ (绿色) | 通过 | 该检测项符合安全标准 |
| ✗ (红色) | 高危 | 严重安全问题，需要立即处理 |
| ● (黄色) | 中危 | 存在安全风险，建议尽快修复 |
| ○ (蓝色) | 低危 | 轻微问题或优化建议 |

---

## 用户安全检测 (users)

### 1. 额外的 UID 0 账户检测

**检测内容**: 检查系统中是否存在除 root 以外的 UID 为 0 的账户

**为什么重要**: UID 0 是超级管理员权限。如果存在多个 UID 0 账户，可能表示：
- 系统被入侵后创建了后门账户
- 配置错误导致普通用户拥有 root 权限

**通过条件**: 系统中只有 root 账户的 UID 为 0

**修复方法**:
```bash
# 1. 查看所有 UID 为 0 的账户
awk -F: '$3 == 0 {print $1}' /etc/passwd

# 2. 如果发现可疑账户，先备份后删除
userdel <可疑账户名>

# 3. 或者修改其 UID
usermod -u <新UID> <账户名>
```

---

### 2. 空密码账户检测

**检测内容**: 检查是否存在没有设置密码的账户

**为什么重要**: 空密码账户允许任何人无需认证即可登录，是严重的安全漏洞

**通过条件**: 所有账户都设置了密码或已被锁定

**修复方法**:
```bash
# 1. 查看空密码账户
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow

# 2. 为账户设置密码
passwd <账户名>

# 3. 或者锁定不需要的账户
usermod -L <账户名>
```

---

### 3. 系统账户登录权限检测

**检测内容**: 检查系统服务账户（如 www-data、nobody）是否拥有登录 shell

**为什么重要**: 系统账户不应该能够登录，如果可以登录，攻击者可能利用这些账户访问系统

**通过条件**: 系统账户的 shell 设置为 `/sbin/nologin` 或 `/bin/false`

**修复方法**:
```bash
# 禁用账户的登录 shell
usermod -s /sbin/nologin <账户名>
```

---

### 4. sudo 配置安全检测

**检测内容**: 检查 sudo 配置是否存在 NOPASSWD 设置

**为什么重要**: NOPASSWD 允许用户无需输入密码即可执行 sudo 命令，降低了安全性

**通过条件**: sudoers 配置中不存在 NOPASSWD 选项（或仅用于自动化场景）

**修复方法**:
```bash
# 1. 编辑 sudoers 文件
visudo

# 2. 删除或注释包含 NOPASSWD 的行
# 例如将：
# user ALL=(ALL) NOPASSWD: ALL
# 改为：
# user ALL=(ALL) ALL
```

---

## SSH 安全检测 (ssh)

### 1. SSH 端口检测

**检测内容**: 检查 SSH 服务是否使用默认的 22 端口

**为什么重要**: 默认端口更容易受到自动化扫描和暴力破解攻击

**通过条件**: SSH 使用非 22 的端口

**修复方法**:
```bash
# 1. 编辑 SSH 配置
nano /etc/ssh/sshd_config

# 2. 修改端口号
Port 2222  # 使用其他端口，如 2222

# 3. 确保防火墙允许新端口
ufw allow 2222/tcp

# 4. 重启 SSH 服务
systemctl restart sshd

# 注意：修改前确保新端口已在防火墙中放行！
```

---

### 2. Root 登录检测

**检测内容**: 检查是否允许 root 用户直接通过 SSH 登录

**为什么重要**:
- root 是已知的账户名，容易被暴力破解
- 直接使用 root 登录无法追踪操作者身份
- 一旦被入侵，攻击者直接获得最高权限

**通过条件**: SSH 配置中 `PermitRootLogin` 设置为 `no` 或 `prohibit-password`

**修复方法**:
```bash
# 1. 首先确保有其他可用的 sudo 用户
useradd -m -G sudo newadmin
passwd newadmin

# 2. 测试新用户能否登录并使用 sudo

# 3. 编辑 SSH 配置
nano /etc/ssh/sshd_config

# 4. 添加或修改
PermitRootLogin no

# 5. 重启 SSH
systemctl restart sshd
```

---

### 3. 密码认证检测

**检测内容**: 检查是否允许使用密码登录 SSH

**为什么重要**: 密码可能被暴力破解，SSH 密钥认证更安全

**通过条件**: SSH 配置中禁用了密码认证，仅使用密钥认证

**修复方法**:
```bash
# 1. 首先设置 SSH 密钥
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id user@server

# 2. 测试密钥登录正常后，禁用密码认证
nano /etc/ssh/sshd_config

# 3. 添加或修改
PasswordAuthentication no
PubkeyAuthentication yes

# 4. 重启 SSH
systemctl restart sshd

# 警告：禁用前务必确认密钥登录正常！
```

---

### 4. MaxAuthTries 检测

**检测内容**: 检查 SSH 允许的最大认证尝试次数

**为什么重要**: 过高的值使暴力破解更容易，过低可能影响正常使用

**通过条件**: MaxAuthTries 设置为 3-6 之间

**修复方法**:
```bash
# 编辑 SSH 配置
nano /etc/ssh/sshd_config

# 设置合理的值
MaxAuthTries 3

# 重启 SSH
systemctl restart sshd
```

---

### 5. 协议版本检测

**检测内容**: 检查是否禁用了不安全的 SSH 协议版本 1

**为什么重要**: SSH 协议版本 1 存在已知安全漏洞

**通过条件**: 仅使用 SSH 协议版本 2

**修复方法**: 现代 OpenSSH 默认只支持 v2，如果使用旧版本：
```bash
# 编辑配置
nano /etc/ssh/sshd_config

# 添加
Protocol 2

# 重启 SSH
systemctl restart sshd
```

---

## 内核安全检测 (kernel)

### 1. ASLR (地址空间布局随机化) 检测

**检测内容**: 检查内核是否启用了地址空间布局随机化

**为什么重要**: ASLR 使内存地址随机化，显著增加了缓冲区溢出等内存攻击的难度

**通过条件**: `kernel.randomize_va_space = 2`（完全随机化）

**修复方法**:
```bash
# 临时启用
sysctl -w kernel.randomize_va_space=2

# 永久生效
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-security.conf
sysctl -p /etc/sysctl.d/99-security.conf
```

---

### 2. 网络参数安全检测

**检测内容**: 检查多项网络内核参数是否正确配置

| 参数 | 推荐值 | 说明 |
|------|--------|------|
| `net.ipv4.ip_forward` | 0 | 禁用 IP 转发（除非运行 Docker/LXC） |
| `net.ipv4.tcp_syncookies` | 1 | 防止 SYN 洪水攻击 |
| `net.ipv4.conf.all.accept_redirects` | 0 | 拒绝 ICMP 重定向 |
| `net.ipv4.conf.all.send_redirects` | 0 | 不发送 ICMP 重定向 |
| `net.ipv4.conf.all.rp_filter` | 1 | 反向路径过滤 |

**修复方法**:
```bash
# 创建安全配置文件
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# 网络安全
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF

# 应用配置
sysctl -p /etc/sysctl.d/99-security.conf
```

---

### 3. IPv6 安全检测

**检测内容**: 检查 IPv6 是否安全配置或已禁用

**为什么重要**: 如果启用了 IPv6 但没有正确配置，可能成为攻击入口

**关键配置**:
- `net.ipv6.conf.all.accept_ra = 0` - 禁止接受路由通告
- `net.ipv6.conf.all.accept_redirects = 0` - 禁止接受重定向
- IPv6 防火墙应与 IPv4 防火墙同步配置

**修复方法**:
```bash
# 如果不使用 IPv6，可以禁用
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf

# 如果使用 IPv6，确保安全配置
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf
```

---

### 4. 核心转储(Core Dump)检测

**检测内容**: 检查是否限制了核心转储

**为什么重要**: 核心转储可能包含敏感信息（密码、密钥等）

**修复方法**:
```bash
# 1. 内核参数
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-security.conf

# 2. limits.conf
echo "* hard core 0" >> /etc/security/limits.conf

# 3. systemd (如果使用)
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
```

---

## 文件系统检测 (filesystem)

### 1. SUID/SGID 文件检测

**检测内容**: 查找系统中异常的 SUID/SGID 文件

**为什么重要**:
- SUID 文件以文件所有者权限运行
- 恶意的 SUID 文件可能被用于权限提升

**通过条件**: 仅存在系统标准的 SUID/SGID 文件

**修复方法**:
```bash
# 1. 查找所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 2. 查找所有 SGID 文件
find / -perm -2000 -type f 2>/dev/null

# 3. 移除不必要文件的特殊权限
chmod u-s /path/to/file  # 移除 SUID
chmod g-s /path/to/file  # 移除 SGID

# 4. 如果是恶意文件，直接删除
rm /path/to/malicious/file
```

**正常的 SUID 文件示例**:
- `/usr/bin/sudo`
- `/usr/bin/passwd`
- `/usr/bin/su`

---

### 2. 全局可写文件/目录检测

**检测内容**: 查找除 /tmp 等临时目录外的全局可写文件和目录

**为什么重要**: 全局可写文件可能被任何用户修改，可能导致权限提升或数据篡改

**修复方法**:
```bash
# 1. 查找全局可写文件
find / -xdev -type f -perm -0002 2>/dev/null

# 2. 移除全局可写权限
chmod o-w /path/to/file

# 3. 对于目录，确保设置了粘滞位
chmod +t /path/to/directory
```

---

### 3. 敏感文件权限检测

**检测内容**: 检查关键配置文件的权限是否正确

| 文件 | 推荐权限 | 说明 |
|------|----------|------|
| `/etc/passwd` | 644 | 用户信息，需可读 |
| `/etc/shadow` | 640 | 密码哈希，仅 root 可读 |
| `/etc/ssh/sshd_config` | 644 | SSH 配置 |
| `/etc/ssh/ssh_host_*_key` | 600 | SSH 私钥，仅 root 可读 |
| `/etc/sudoers` | 440 | sudo 配置 |

**修复方法**:
```bash
# 修复 shadow 文件权限
chmod 640 /etc/shadow
chown root:shadow /etc/shadow

# 修复 SSH 密钥权限
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub

# 修复 sudoers 权限
chmod 440 /etc/sudoers
```

---

### 4. 无主文件检测

**检测内容**: 查找没有有效属主或属组的文件

**为什么重要**: 无主文件可能是：
- 用户被删除后遗留的文件
- 入侵者创建的文件
- 可能被恶意利用

**修复方法**:
```bash
# 1. 查找无主文件
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# 2. 指定新的属主
chown root:root /path/to/file

# 3. 或者删除不需要的文件
rm /path/to/orphan/file
```

---

### 5. 可疑 Cron 任务检测

**检测内容**: 检查计划任务中是否存在可疑命令

**检测的可疑模式**:
- `curl ... | sh` 或 `wget ... | sh` - 从网络下载并执行
- `base64 -d` - Base64 解码（常用于混淆）
- `/dev/tcp/` - Bash 网络连接
- `nc -e` - Netcat 反向 shell
- 在 `/tmp` 中执行隐藏文件

**修复方法**:
```bash
# 1. 检查系统 cron
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/

# 2. 检查用户 cron
crontab -l
crontab -l -u <username>

# 3. 检查 cron spool 目录
ls -la /var/spool/cron/crontabs/

# 4. 删除可疑条目
crontab -e  # 编辑并删除可疑行
```

---

## 防火墙检测 (ufw)

### 1. 防火墙状态检测

**检测内容**: 检查是否启用了防火墙

**为什么重要**: 防火墙是网络安全的第一道防线

**修复方法**:
```bash
# 安装 UFW（如果未安装）
apt install ufw

# 允许 SSH（重要！先执行此步骤）
ufw allow ssh
# 或指定端口
ufw allow 22/tcp

# 启用防火墙
ufw enable

# 查看状态
ufw status verbose
```

---

### 2. 默认策略检测

**检测内容**: 检查防火墙默认入站策略是否为拒绝

**为什么重要**: 默认拒绝策略只允许明确放行的流量通过

**修复方法**:
```bash
# 设置默认策略
ufw default deny incoming
ufw default allow outgoing
```

---

### 3. 敏感端口暴露检测

**检测内容**: 检查数据库等敏感服务端口是否对外开放

**敏感端口列表**:
| 端口 | 服务 | 建议 |
|------|------|------|
| 3306 | MySQL | 仅限本地或内网 |
| 5432 | PostgreSQL | 仅限本地或内网 |
| 6379 | Redis | 仅限本地或内网 |
| 27017 | MongoDB | 仅限本地或内网 |
| 9200 | Elasticsearch | 仅限本地或内网 |
| 2375/2376 | Docker API | 绝对不要暴露 |

**修复方法**:
```bash
# 1. 删除现有的开放规则
ufw delete allow 3306

# 2. 仅允许特定 IP 访问
ufw allow from 10.0.0.0/8 to any port 3306

# 3. 或者配置服务只监听本地
# MySQL 示例：编辑 /etc/mysql/mysql.conf.d/mysqld.cnf
# bind-address = 127.0.0.1
```

---

## 入侵防护检测 (fail2ban)

### 1. Fail2ban 安装检测

**检测内容**: 检查是否安装了 fail2ban

**为什么重要**: fail2ban 自动封禁多次登录失败的 IP，有效防止暴力破解

**修复方法**:
```bash
# 安装 fail2ban
apt install fail2ban

# 启用服务
systemctl enable fail2ban
systemctl start fail2ban
```

---

### 2. SSH Jail 配置检测

**检测内容**: 检查是否配置了 SSH 防护规则

**修复方法**:
```bash
# 创建自定义配置
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
EOF

# 重启 fail2ban
systemctl restart fail2ban

# 查看状态
fail2ban-client status sshd
```

---

### 3. MaxRetry 设置检测

**检测内容**: 检查允许的最大失败尝试次数

**推荐设置**: 3-5 次

**修复方法**:
```bash
# 编辑配置
nano /etc/fail2ban/jail.local

# 设置
maxretry = 3

# 重启服务
systemctl restart fail2ban
```

---

## Docker 安全检测 (docker)

### 1. 暴露端口检测

**检测内容**: 检查 Docker 容器是否将端口暴露到 0.0.0.0

**为什么重要**: 暴露到 0.0.0.0 意味着所有网络接口都可访问

**修复方法**:
```bash
# 修改 docker-compose.yml
ports:
  - "127.0.0.1:8080:8080"  # 仅本地访问
  # 而不是
  # - "8080:8080"  # 对外开放

# 使用反向代理（如 Nginx/Traefik）处理外部访问
```

---

### 2. 特权容器检测

**检测内容**: 检查是否有容器以特权模式运行

**为什么重要**: 特权容器几乎等同于 root 权限，可能导致容器逃逸

**修复方法**:
```bash
# 避免使用 --privileged
# 如果需要特定能力，使用 --cap-add
docker run --cap-add NET_ADMIN myimage

# 而不是
# docker run --privileged myimage
```

---

### 3. Root 用户容器检测

**检测内容**: 检查容器是否以 root 用户运行

**修复方法**:
```dockerfile
# 在 Dockerfile 中
FROM ubuntu:22.04

# 创建非 root 用户
RUN useradd -m -s /bin/bash appuser

# 切换到非 root 用户
USER appuser
```

或在运行时:
```bash
docker run --user 1000:1000 myimage
```

---

### 4. 守护进程安全配置检测

**检测内容**: 检查 Docker 守护进程的安全设置

**推荐配置** `/etc/docker/daemon.json`:
```json
{
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

**修复方法**:
```bash
# 编辑或创建配置文件
nano /etc/docker/daemon.json

# 重启 Docker
systemctl restart docker
```

---

## 恶意软件检测 (malware)

### 1. 隐藏进程检测

**检测内容**: 通过比较 `/proc` 和 `ps` 输出检测隐藏进程

**为什么重要**: Rootkit 通常会隐藏其进程

**发现问题时的处理**:
```bash
# 1. 记录可疑进程信息
cat /proc/<PID>/cmdline
cat /proc/<PID>/maps

# 2. 考虑系统可能已被入侵，应该：
#    - 备份重要数据
#    - 进行取证分析
#    - 考虑重装系统
```

---

### 2. LD_PRELOAD 劫持检测

**检测内容**: 检查是否存在 LD_PRELOAD 环境变量劫持

**为什么重要**: LD_PRELOAD 可被用于库注入攻击

**检查位置**:
- `/etc/ld.so.preload`
- `/etc/profile`
- `/etc/environment`
- `~/.bashrc`

**修复方法**:
```bash
# 1. 检查并清空 ld.so.preload
cat /etc/ld.so.preload
echo "" > /etc/ld.so.preload

# 2. 检查环境文件
grep -r "LD_PRELOAD" /etc/profile* /etc/environment
```

---

### 3. 挖矿进程检测

**检测内容**: 检测加密货币挖矿进程和矿池连接

**检测特征**:
- 进程名: xmrig, minerd, kswapd0(伪装)
- 高 CPU 使用率
- 连接到已知矿池端口 (3333, 4444, 5555 等)

**修复方法**:
```bash
# 1. 终止挖矿进程
kill -9 <PID>

# 2. 查找并删除挖矿程序
find / -name "xmrig" -o -name "minerd" 2>/dev/null

# 3. 检查持久化机制
crontab -l
cat /etc/rc.local
systemctl list-units --type=service

# 4. 检查入侵点并修复
```

---

### 4. WebShell 检测

**检测内容**: 在 Web 目录中检测可疑的 PHP 文件

**检测模式**:
- `eval($_POST[...])`
- `base64_decode + eval`
- `system($_GET[...])`
- 已知 WebShell 特征 (c99, r57 等)

**修复方法**:
```bash
# 1. 隔离可疑文件
mv suspicious.php suspicious.php.quarantine

# 2. 检查 Web 服务器访问日志
grep "suspicious.php" /var/log/nginx/access.log

# 3. 检查入侵时间线
stat suspicious.php

# 4. 审查上传功能和权限
```

---

### 5. 已删除二进制进程检测

**检测内容**: 检测正在运行但二进制文件已被删除的进程

**为什么重要**: 恶意软件常删除自身文件以躲避检测

**修复方法**:
```bash
# 1. 查看进程详情
ls -la /proc/<PID>/exe

# 2. 导出内存中的程序（用于分析）
cp /proc/<PID>/exe /tmp/suspicious_binary

# 3. 终止可疑进程
kill -9 <PID>
```

---

### 6. 反向 Shell 检测

**检测内容**: 检测 Shell 进程是否具有网络连接

**为什么重要**: 反向 Shell 是入侵者远程控制系统的常用方法

**修复方法**:
```bash
# 1. 查看可疑连接
ss -tnp | grep <PID>

# 2. 终止进程
kill -9 <PID>

# 3. 阻止相关 IP
ufw deny out to <可疑IP>
iptables -A OUTPUT -d <可疑IP> -j DROP
```

---

## 常见问题解答

### Q: 检测结果全是红色/失败，我的服务器很危险吗？

A: 不一定。许多检测项是安全加固建议而非实际漏洞。优先处理：
1. 红色(✗)高危项目 - 需要立即关注
2. 恶意软件检测结果 - 需要调查
3. 开放的敏感端口 - 需要评估

### Q: 修改 SSH 配置后无法登录怎么办？

A: 这是常见问题，预防措施：
1. 修改前保持一个现有 SSH 会话不要关闭
2. 先测试新配置：`sshd -t`
3. 使用云服务商的 VNC/控制台访问恢复

### Q: 某些检测项不适用于我的环境怎么办？

A: 脚本支持模块选择。运行时可以选择跳过不适用的模块：
```bash
./vpssec.sh --modules users,ssh,ufw
```

### Q: 如何定期运行检测？

A: 可以设置 cron 任务：
```bash
# 每周日凌晨 3 点运行检测
0 3 * * 0 /path/to/vpssec.sh --report > /var/log/security-audit.log 2>&1
```

### Q: 检测到恶意软件该怎么办？

A: 建议步骤：
1. **不要惊慌** - 保持冷静，避免破坏证据
2. **隔离系统** - 考虑断开网络连接
3. **取证保存** - 保存日志和可疑文件
4. **调查入侵** - 确定入侵时间和方式
5. **评估损失** - 检查数据是否泄露
6. **修复漏洞** - 找到并修复入侵点
7. **考虑重装** - 严重入侵时重装是最安全的选择

---

## 获取帮助

如果在使用过程中遇到问题：

1. 查看脚本帮助：`./vpssec.sh --help`
2. 查看详细日志：检查 `/var/log/vpssec/` 目录
3. 提交 Issue：[GitHub Issues](https://github.com/your-repo/CloudServer-Audit/issues)

---

*本指南将随脚本更新持续完善。最后更新: 2024年*
