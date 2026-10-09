# CloudServer-Audit 检测项详解与修复指南

本指南详细说明脚本的每项安全检测内容，帮助您理解检测结果并解决发现的问题。

---

> **覆盖范围说明**：本指南覆盖最常触发问题与修复的八个核心模块——
> users、ssh、kernel、filesystem、ufw、fail2ban、docker、malware。
> 每节先给 vpssec 能自动执行的修复（fix_id），再给手工步骤；手工步骤
> 与 vpssec 自己的修复用同一套做法（写进 drop-in、改完核对生效值），两条路的
> 区别见[先用 vpssec 自己修](#先用-vpssec-自己修)。
> 其余模块（cloud、timezone、update、baseline、nginx、webapp、
> cloudflared、logging、backup、alerts、networking、scheduling）的
> 检测项标题与建议会在审计报告（`reports/summary.md`）和终端输出
> 中以 i18n 方式直接给出，本指南暂未对每一项展开，欢迎通过 PR 补充。
>
> **本指南更新说明**：vpssec 后续陆续加入了若干新检查（CIS / Lynis
> 交叉对照衍生），包括 users 的 `duplicate_uids` / `weak_hash_method` /
> `faillog_disabled` / `sudoers_syntax_invalid`，ssh 的 SSH-7408 全集
> （`AllowTcpForwarding` / `IgnoreRhosts` / `StrictModes` /
> `PermitTunnel` / `GatewayPorts` 等共 11 项），filesystem 新增的
> sensitive 文件清单（`/etc/shadow-`、`/boot/grub/grub.cfg` 等），
> kernel 的 8 条新 sysctl，docker 的
> `host_network_used` / `secrets_in_env` / `unlimited_memory` 等。
> 上述新增项**没有**在本指南详细展开，但每条检查的 Recommendations
> 字段已自带具体修复命令，可直接在审计报告里看到。设计依据
> （CIS 控件、NIST、Lynis 对照）保留在各检测函数的代码注释中。

## 目录

1. [结果图标说明](#结果图标说明)
2. [先用 vpssec 自己修](#先用-vpssec-自己修)
3. [用户安全检测 (users)](#用户安全检测-users)
4. [SSH 安全检测 (ssh)](#ssh-安全检测-ssh)
5. [内核安全检测 (kernel)](#内核安全检测-kernel)
6. [文件系统检测 (filesystem)](#文件系统检测-filesystem)
7. [防火墙检测 (ufw)](#防火墙检测-ufw)
8. [入侵防护检测 (fail2ban)](#入侵防护检测-fail2ban)
9. [Docker 安全检测 (docker)](#docker-安全检测-docker)
10. [恶意软件检测 (malware)](#恶意软件检测-malware)
11. [常见问题解答](#常见问题解答)

---

## 结果图标说明

| 图标 | 含义 | 说明 |
|------|------|------|
| ✓ (绿色) | 通过 | 该检测项符合安全标准 |
| ✗ (红色) | 高危 | 严重安全问题，需要立即处理 |
| ● (黄色) | 中危 | 存在安全风险，建议尽快修复 |
| ○ (蓝色) | 低危 | 轻微问题或优化建议 |

---

## 先用 vpssec 自己修

每节的「自动修复」一行给出这一项对应的 fix_id。`vpssec help <模块>` 列出
该模块全部 fix_id 和各自的风险分级（不需要 root，不改系统）。只执行其中一项：

```bash
sudo vpssec guide --fix=ssh.set_max_auth_tries
```

走 vpssec 和照下文手工改，差别在三处：

- vpssec 改文件之前先把原件存进 `backups/<时间戳>/`，`vpssec rollback` 能整批撤回；
  手工改的东西不进备份，回滚管不到。
- 修复跑完，vpssec 再用审计的判据查一遍，查不过就记为失败，不会报「已完成」。
  手工改完请照每节给的命令自己核对**生效值**，而不只是看文件写对了没有。
- 「高风险」一档（禁用 SSH 密码登录、禁用 root 登录、启用 UFW、UFW 默认拒绝入站、
  安装安全更新）以及会重启 dockerd 的那一项，要在终端上手打 `yes`，`--yes` 跳不过。
  两项 SSH 修复还会先在另一个端口起一个临时 sshd，让你确认从那里登得进来，再动配置。

`guide` 与 `rollback` 只支持 Debian / Ubuntu。RHEL 系与 Arch 上审计照常可用，修复按下文
手工做；命令因发行版而异的地方，各节分别给出。

---

## 用户安全检测 (users)

### 1. 额外的 UID 0 账户检测

**检测内容**: 检查系统中是否存在除 root 以外的 UID 为 0 的账户

**为什么重要**: UID 0 是超级管理员权限。如果存在多个 UID 0 账户，可能表示：
- 系统被入侵后创建了后门账户
- 配置错误导致普通用户拥有 root 权限

**通过条件**: 系统中只有 root 账户的 UID 为 0

**自动修复**: 无（仅告警）

**修复方法**:
```bash
# 1. 查看所有 UID 为 0 的账户（getent 也列出 LDAP 等外部账户源里的条目，
#    那类账户不在 /etc/passwd 里）
getent passwd | awk -F: '$3 == 0 {print $1}'

# 2. 如果发现可疑账户，先备份后删除
userdel <可疑账户名>

# 3. 或者修改其 UID
usermod -u <新UID> <账户名>
```

---

### 2. 空密码账户检测

**检测内容**: 检查是否存在没有设置密码的账户

**为什么重要**: 空密码账户允许任何人无需认证即可登录，是严重的安全漏洞

**通过条件**: 能登录的账户都设置了密码或已被锁定（shadow 里的 `!`、`!!`、`*` 是锁定，不算空密码）

**自动修复**: 无（仅告警）

**修复方法**:
```bash
# 1. 查看空密码账户：shadow 里密码字段为空的，以及 passwd 里第二个字段
#    直接为空的（这种写法根本不经过 shadow）
awk -F: '$2 == "" {print $1}' /etc/shadow
getent passwd | awk -F: '$2 == "" {print $1}'

# 2. 为账户设置密码
passwd <账户名>

# 3. 或者锁定不需要的账户
usermod -L <账户名>
```

---

### 3. 系统账户登录权限检测

**检测内容**: 检查系统服务账户（如 www-data、nobody）是否拥有登录 shell

**为什么重要**: 系统账户不应该能够登录，如果可以登录，攻击者可能利用这些账户访问系统

**通过条件**: UID 小于 1000 的系统账户，shell 是 `nologin`、`false`，或 RHEL 自带的
`/bin/sync`、`shutdown`、`halt` 这几个专用账户

**自动修复**: 无（仅告警）

**修复方法**:
```bash
# 禁用账户的登录 shell
usermod -s /sbin/nologin <账户名>
```

---

### 4. sudo 配置安全检测

**检测内容**: 按 sudo 自己的读法展开 `/etc/sudoers` 与它 `@includedir` 进来的文件，
找出免密授权：带 `NOPASSWD` 的规则，以及 `Defaults !authenticate`

**为什么重要**: NOPASSWD 允许用户无需输入密码即可执行 sudo 命令，降低了安全性

**通过条件**: 没有任何免密授权

**严重性分级**:
- 仅云镜像 cloud-init 默认用户（如 `debian` / `ubuntu` / `ec2-user` /
  `centos` / `admin` / `azureuser` / `opc` 等）的 NOPASSWD：低危。
  几乎所有云厂商出厂镜像都给 cloud-init 默认用户配了 NOPASSWD，是事实
  标准、普遍且预期内，单独标高危没有信号增益。
- 其它 NOPASSWD 条目：中危。免密 sudo 可直接提权到 root，但需先拿到
  该账户才能利用（提权放大器，并非"当下已暴露"），故为中危而非高危。

**自动修复**: 无（仅告警；vpssec 不自动改 sudoers）

**修复方法**:
```bash
# 1. 找出免密授权在哪个文件（云镜像通常在 /etc/sudoers.d/90-cloud-init-users）
grep -rnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d/

# 2. 用 visudo 编辑第 1 步找到的文件（保存前做语法检查；
#    直接用编辑器写坏了，sudo 会整个不可用）
visudo -f /etc/sudoers.d/90-cloud-init-users

# 3. 删除或注释包含 NOPASSWD 的行
# 例如将：
# user ALL=(ALL) NOPASSWD: ALL
# 改为：
# user ALL=(ALL) ALL
# 改之前先确认这个账户设了密码（passwd <账户名>），否则改完它就用不了 sudo
```

---

## SSH 安全检测 (ssh)

### 手工改 sshd 配置之前

sshd 对同一个选项**只认第一次读到的值**（`Port`、`ListenAddress` 这类可以写多次的除外，
它们是累加）。Debian / Ubuntu / RHEL 9+ / Arch 的主配置开头都有一行
`Include /etc/ssh/sshd_config.d/*.conf`，于是：

- `sshd_config.d/` 里的文件比主配置先读，文件名排在前面的又比后面的先读。云镜像常带的
  `50-cloud-init.conf` 写着 `PasswordAuthentication yes` 时，在主配置末尾追加
  `PasswordAuthentication no` 不会生效，`sshd -t` 照样通过、重载也成功，只有看生效值才发现。
- 所以设置写进一个文件名排在最前的 drop-in。vpssec 自己写的是
  `/etc/ssh/sshd_config.d/00-vpssec-hardening.conf`；手工改可以新建
  `/etc/ssh/sshd_config.d/00-local.conf`。同一个文件里也是第一行生效：文件里已经有这个
  选项就改那一行，下面各节用 `>>` 追加只适用于文件里还没有它的时候。
- RHEL 8 的主配置没有这行 `Include`：直接改主配置里已有的那一行；没有就加在文件开头、
  任何 `Match` 块之前。

改完按这个顺序收尾：

```bash
# 1. 语法检查（只查语法，查不出被别的文件盖掉）
sshd -t

# 2. 看生效值：-C 让 sshd 按一次真实登录套用 Match 块
sshd -T -C user=root,host=localhost,addr=127.0.0.1 \
  | grep -iE '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '

# 3. 重新加载（已登录的会话不受影响）
systemctl reload ssh     # Debian / Ubuntu
systemctl reload sshd    # RHEL / Arch
```

Ubuntu 24.04 默认没有 `sshd` 这个单元别名，`systemctl restart sshd` 会报找不到单元，要用
`ssh`。改完**保持当前会话不要断开**，另开一个终端确认能登录，再关掉旧会话。

---

### 1. SSH 端口检测

**检测内容**: 检查 sshd 是否在默认的 22 端口监听。端口取自 `sshd -T` 的 `port` 与
`listenaddress` 两类行，所以 `ListenAddress 0.0.0.0:2222` 这种写法也算数

**为什么重要**: 默认端口会持续承受自动化扫描和暴力破解流量；改用非默
认端口可显著降低噪声，但**不是真正的安全防线**——配合密钥登录、
fail2ban、防火墙才是关键。

**评估方式**: 这是一个建议性（低危/info）提示，使用默认 22 端口本身
不会被判为高危失败。修改端口属于操作偏好，不是合规硬性要求。

**自动修复**: 无

**修复方法**:
```bash
# 1. 先在防火墙放行新端口（云厂商的安全组同样要放行）
ufw allow 2222/tcp
# RHEL 系用 firewalld：firewall-cmd --permanent --add-port=2222/tcp && firewall-cmd --reload
# RHEL 系开着 SELinux 时还要登记端口，否则 sshd 绑不上：
# semanage port -a -t ssh_port_t -p tcp 2222

# 2. 写进 drop-in。Port 是累加的：主配置里还有一行没注释的 Port 22 时，
#    两个端口都会监听
echo 'Port 2222' >> /etc/ssh/sshd_config.d/00-local.conf
sshd -t
sshd -T | grep -E '^(port|listenaddress) '

# 3. 让新端口生效
systemctl reload ssh       # Debian；RHEL / Arch 用 sshd
# Ubuntu 24.04 起默认用 ssh.socket 套接字激活，监听端口由 socket 决定，要重新生成：
# systemctl daemon-reload
# systemctl restart ssh.socket

# 4. 确认在监听新端口，另开终端用新端口登录成功后，再删掉旧端口的放行规则
ss -tln | grep ':2222 '
```

---

### 2. Root 登录检测

**检测内容**: 检查是否允许 root 用户直接通过 SSH 登录

**为什么重要**:
- root 是已知的账户名，容易被暴力破解
- 直接使用 root 登录无法追踪操作者身份
- 一旦被入侵，攻击者直接获得最高权限

**通过条件**: `sshd -T` 给出的 `PermitRootLogin` 不是 `yes`（`no`、`prohibit-password` 都算通过）

**严重性分级**:
- `PermitRootLogin yes` **且** `PasswordAuthentication yes`：高危
- `PermitRootLogin yes` **但** `PasswordAuthentication no`（仅密钥）：中危
  （操作上等同于一个有 sudo 权限的密钥用户，但仍建议改成
  `prohibit-password` 或 `no` 以减少误配置风险）

**自动修复**: `ssh.disable_root_login`（高风险）。先确认存在一个改完之后还能用现有方式
登录、并能经 sudo 提权的管理员；再起临时救援 sshd，等你手打 `yes` 确认后才写配置

**修复方法**:
```bash
# 1. 首先确保有其他可用的 sudo 用户
#    管理员组：Debian / Ubuntu 是 sudo，RHEL / Arch 是 wheel
#    （Arch 还要在 visudo 里取消 %wheel 那一行的注释）
useradd -m -G sudo newadmin
passwd newadmin
# 把你的公钥放进 /home/newadmin/.ssh/authorized_keys

# 2. 另开终端，确认能以 newadmin 登录并 sudo -v 成功

# 3. 写进 drop-in
echo 'PermitRootLogin no' >> /etc/ssh/sshd_config.d/00-local.conf

# 4. 按本节开头的顺序检查生效值并重新加载
sshd -t && sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -i '^permitrootlogin '
systemctl reload ssh       # RHEL / Arch 用 sshd
```

---

### 3. 密码认证检测

**检测内容**: 检查是否还能用密码登录 SSH。除了 `PasswordAuthentication`，
`KbdInteractiveAuthentication yes` 加上 `UsePAM yes` 时，密码也能经键盘交互认证输入，
同样算作可用密码登录（除非每一组 `AuthenticationMethods` 都还要求密码以外的东西）

**为什么重要**: 密码可能被暴力破解，SSH 密钥认证更安全

**通过条件**: 生效值里 `PasswordAuthentication no`，且键盘交互这条路也走不了密码

**自动修复**: `ssh.disable_password_auth`（高风险）。先确认改完之后仍有人能用密钥登录并
提权，再起临时救援 sshd，等你手打 `yes` 确认。键盘交互那条路开着时它拒绝执行：
那一项可能是你的第二因素，要不要关由你决定

**修复方法**:
```bash
# 1. 首先设置 SSH 密钥（在你自己的电脑上执行）
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id user@server

# 2. 另开终端确认密钥登录正常，然后写进 drop-in
echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/00-local.conf
# 键盘交互认证没有当第二因素用的话，一并关掉：
echo 'KbdInteractiveAuthentication no' >> /etc/ssh/sshd_config.d/00-local.conf

# 3. 检查生效值：50-cloud-init.conf 之类的文件若写着 yes，
#    只有放在排序更靠前的文件里才盖得过它
sshd -t && sshd -T -C user=root,host=localhost,addr=127.0.0.1 \
  | grep -iE '^(passwordauthentication|kbdinteractiveauthentication) '
systemctl reload ssh       # RHEL / Arch 用 sshd

# 警告：禁用前务必确认密钥登录正常！
```

---

### 4. MaxAuthTries 检测

**检测内容**: 检查 SSH 允许的最大认证尝试次数

**为什么重要**: 过高的值使暴力破解更容易，过低可能影响正常使用

**通过条件**: MaxAuthTries 设置为 4 或更小（推荐 3-4）

**自动修复**: `ssh.set_max_auth_tries`（安全，写入 `MaxAuthTries 4`）

**修复方法**:
```bash
echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config.d/00-local.conf
sshd -t && sshd -T | grep -i '^maxauthtries '
systemctl reload ssh       # RHEL / Arch 用 sshd
```

---

### 5. 弱算法检测

**检测内容**: 读 `sshd -T` 实际提供的加密算法、MAC 与密钥交换算法，找出
3des-cbc、arcfour、blowfish-cbc、cast128-cbc，hmac-md5 与 hmac-sha1 系列 MAC，
以及基于 SHA-1 的 diffie-hellman 密钥交换。SSH 协议 1 在 OpenSSH 7.4 起已不被 sshd
支持，`Protocol` 选项也已作废，vpssec 不检查它

**为什么重要**: 这些算法已被弃用，留着它们只为兼容很老的客户端

**评分**: 低危，属于 `optional` 类别，只在 `--strict` 下计分

**自动修复**: `ssh.harden_algorithms`（需确认）。用「从默认集合里去掉」的写法，
发行版自带的默认算法（包括后量子混合密钥交换）原样保留；只支持 SHA-1 MAC 的老客户端
改完后将连不上

**修复方法**:
```bash
# 写进 drop-in（减号开头表示从默认集合里去掉，OpenSSH 7.5 起支持）
cat >> /etc/ssh/sshd_config.d/00-local.conf << 'EOF'
Ciphers -3des-cbc,arcfour*,blowfish-cbc,cast128-cbc
MACs -hmac-md5*,hmac-sha1*
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
EOF
sshd -t && sshd -T | grep -E '^(ciphers|macs|kexalgorithms) '
systemctl reload ssh       # Arch 用 sshd
```

RHEL 系的 sshd 算法列表来自系统的 crypto-policies，在 drop-in 里另写会绕开它；
调整用 `update-crypto-policies`。

---

## 内核安全检测 (kernel)

第 1–4 项读的都是**运行时**的值（`sysctl -n <参数>`），第 5 项再看这些值开机后保不保得住。
手工持久化时注意顺序：开机时
`/etc/sysctl.d` 等目录里的文件按文件名顺序应用，同一个参数**后应用的覆盖先应用的**
（与 sshd 正好相反）。vpssec 自己写的是 `/etc/sysctl.d/99-vpssec-hardening.conf`。

写完用 `systemctl restart systemd-sysctl` 按开机时的方式整体重新套用一遍，再用
`sysctl <参数>` 看实际值，比 `sysctl -p <单个文件>` 更能暴露被别的文件盖掉的情况。
不用 `sysctl --system`：它最后还会再读一遍 `/etc/sysctl.conf`，顺序和开机时不一样，
而 Debian 13、Ubuntu 26.04 开机时根本不读这个文件。重新套用会把别的服务运行时改过、
又被某个文件写死的值一并改回去（例如 Docker 打开的 `ip_forward`），容器主机上留意。

### 1. ASLR (地址空间布局随机化) 检测

**检测内容**: 检查内核是否启用了地址空间布局随机化

**为什么重要**: ASLR 使内存地址随机化，显著增加了缓冲区溢出等内存攻击的难度

**通过条件**: `kernel.randomize_va_space = 2`（完全随机化）

**自动修复**: `kernel.enable_aslr`（安全）

**修复方法**:
```bash
# 临时启用
sysctl -w kernel.randomize_va_space=2

# 永久生效
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-security.conf
systemctl restart systemd-sysctl
sysctl kernel.randomize_va_space
```

---

### 2. 网络参数安全检测

**检测内容**: 检查多项网络内核参数是否正确配置

| 参数 | 推荐值 | 说明 |
|------|--------|------|
| `net.ipv4.ip_forward` | 0 | 禁用 IP 转发；本机跑着 Docker / Podman / LXC / libvirt、Kubernetes 节点，或 Tailscale / WireGuard / OpenVPN 时不判 |
| `net.ipv4.tcp_syncookies` | 1 | 防止 SYN 洪水攻击 |
| `net.ipv4.conf.all.accept_redirects` | 0 | 拒绝 ICMP 重定向 |
| `net.ipv4.conf.all.send_redirects` | 0 | 不发送 ICMP 重定向 |
| `net.ipv4.conf.all.rp_filter` | 1 | 反向路径过滤 |

**自动修复**: `kernel.harden_network`（需确认；可能影响容器网络。这一项也包含 IPv6 的
`accept_ra`，靠路由通告拿 IPv6 默认路由的主机会自动跳过它，见下一节）

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

# 按开机时的方式整体重新套用，再抽查实际值
systemctl restart systemd-sysctl
sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter
```

---

### 3. IPv6 安全检测

**检测内容**: 检查 IPv6 是否安全配置或已禁用

**为什么重要**: 如果启用了 IPv6 但没有正确配置，可能成为攻击入口

**关键配置**:
- `net.ipv6.conf.all.accept_redirects = 0` - 禁止接受重定向
- `net.ipv6.conf.all.use_tempaddr = 2` - 优先使用隐私扩展地址
- `net.ipv6.conf.all.accept_ra = 0` - 禁止接受路由通告，**只适用于静态配置 IPv6 的主机**：
  靠路由通告（RA / SLAAC）拿默认路由的主机上，`accept_ra = 1` 正是它保住 IPv6 连通的设置，
  审计对这类主机不报这一项
- IPv6 防火墙应与 IPv4 防火墙同步配置

这三个参数写在 `all` / `default` 下，**只对之后新建的网卡生效**，`eth0` 这类已经存在的
网卡保持原值，vpssec 也只检查 `all` / `default`。要让已有网卡立刻生效，按网卡名再写一行，
例如 `net.ipv6.conf.eth0.accept_redirects = 0`。

**自动修复**: `kernel.harden_ipv6`（需确认）。`accept_ra` 只在默认路由不是来自路由通告时
才写；查不出来时一律按「来自路由通告」处理，宁可不改

**修复方法**:
```bash
# 1. 先看 IPv6 默认路由从哪来
ip -6 route show default
#    输出里有 proto ra：这台机器靠路由通告拿默认路由，下面不要写 accept_ra
#    （写了之后，路由器给的默认路由一过期或机器重启，IPv6 就断了；
#    通过 IPv6 管理这台机器的话，人也就进不来了）

# 2. 任何主机都可以写的部分
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
EOF

# 3. 仅当第 1 步没有 proto ra（IPv6 是静态配置的）时，再加这两行
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

systemctl restart systemd-sysctl

# 不使用 IPv6、也确认没有服务依赖它时，可以整体禁用（审计直接判通过）
# echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf
```

---

### 4. 核心转储(Core Dump)检测

**检测内容**: 检查是否限制了核心转储：`fs.suid_dumpable` 为 0、`limits.conf` 里有
`* hard core 0`（或 `soft`）、systemd-coredump 设了 `Storage=none`（主配置或 drop-in 均可）

**为什么重要**: 核心转储可能包含敏感信息（密码、密钥等）

**自动修复**: `kernel.disable_core_dump`（安全）

**修复方法**:
```bash
# 1. 内核参数
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-security.conf
systemctl restart systemd-sysctl

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

### 5. 开机配置检查（重启后保不保得住）

**检测内容**: 上面几项读的都是运行时的值。这一项只看其中**现在已经达标**的参数（两组参数
扫描里通过的，以及完全开启的 ASLR），按 systemd-sysctl 开机时的读法，算出下次开机它们会被
设成什么：`/etc/sysctl.d`、`/run/sysctl.d`、`/usr/local/lib/sysctl.d`、`/usr/lib/sysctl.d`
里的 `*.conf`，同名文件只认靠前目录里的那份，全部按文件名排序依次套用，同一个参数后写的胜出。
结论是三条之一：

- `kernel.boot_params_revert`（失败）：某个 sysctl.d 文件开机时会把参数设回不达标的值，描述里
  给出文件、行号和那个值；或者参数只写在 `/etc/sysctl.conf` 里，而本机 sysctl.d 里没有链接
  指向这个文件——Debian 13 与 Ubuntu 26.04 原装就没有这条 `99-sysctl.conf` 链接，开机时
  systemd-sysctl 根本不读 `/etc/sysctl.conf`。
- `kernel.boot_params_ok`（通过）：没有 sysctl.d 文件在开机时改回已加固的参数。
- `kernel.boot_params_unreadable`（失败）：有 sysctl.d 文件读不到，不下任何结论。

没有任何 sysctl.d 文件设置的参数，开机时取内核默认值，而运行时读不出默认值是多少：这类参数
只在描述里列出，不判通过，也不判回退。运行时就不达标的参数由上面几项负责，这里不重复比。
内核命令行上的 `sysctl.*=`、开机后别的服务（tuned、cloud-init、Docker 打开的 `ip_forward`）
再改的值，都不在本项的判断之内。RHEL 8 的 systemd（239）不认通配写法，本项也照此忽略通配行。

**为什么重要**: `sysctl -w`、`sysctl -p` 只改正在运行的内核。加固值没写进开机会读的文件，
或者被一个文件名排得更靠后的文件改回去，重启之后就悄悄失效，而重启前的审计看不出来。

**评分**: 三条都是 `info`，不计分。

**自动修复**: 无（仅告警）。vpssec 的内核修复写在 `/etc/sysctl.d/99-vpssec-hardening.conf`，
开机时会被读到；回滚删掉了这个文件、而运行时还是加固值时，这一项会报出来。

**修复方法**:
```bash
# 1. 看开机时 systemd-sysctl 读到的全部内容（按套用顺序拼在一起，每段标着来源文件）
systemd-analyze cat-config sysctl.d
# RHEL 8 的 systemd 239 不支持这条命令，就逐个目录看
ls -l /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d

# 2. 描述里点名的那一行：改成达标的值，或者删掉。要另外写的加固值放进 /etc/sysctl.d，
#    文件名排在会把它改回去的那个文件之后（后写的胜出），例如
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-zz-local.conf

# 3. 只写在 /etc/sysctl.conf 里的参数：先看有没有链接，没有就把那几行挪进 /etc/sysctl.d
ls -l /etc/sysctl.d/99-sysctl.conf

# 4. 按开机的方式重新套用一遍，再审计核对
systemctl restart systemd-sysctl
sudo vpssec audit --include=kernel
```

---

## 文件系统检测 (filesystem)

### 1. SUID/SGID 文件检测

**检测内容**: 查找系统中异常的 SUID/SGID 文件

**为什么重要**:
- SUID 文件以文件所有者权限运行
- 恶意的 SUID 文件可能被用于权限提升

**通过条件**: 仅存在系统标准的 SUID/SGID 文件

**自动修复**: 无（仅告警）

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

**自动修复**: 无（仅告警）

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

**检测内容**: 检查关键配置文件的权限与属主。权限只看有没有**多出**下表以外的位，
比表里更严（例如 RHEL 出厂的 `/etc/shadow` 是 000）照样通过；属主必须是 root

| 文件 | 最宽允许 | 说明 |
|------|----------|------|
| `/etc/passwd` | 644 | 用户信息，需可读 |
| `/etc/shadow`、`/etc/gshadow` 及备份 `shadow-` 等 | 640 | 密码哈希；属组只允许 root 或 shadow |
| `/etc/ssh/sshd_config` | 644 | SSH 配置 |
| `/etc/ssh/ssh_host_*_key` | 600 | SSH 私钥；RHEL 出厂是 640 root:ssh_keys，也算通过 |
| `/etc/sudoers` | 440 | sudo 配置 |

**自动修复**: `filesystem.fix_sensitive_perms`（安全）。只动多出了权限位的文件，把它们
chmod 成表里的值，不改属主

**修复方法**:
```bash
# 先看现状
stat -c '%a %U:%G %n' /etc/shadow /etc/gshadow /etc/sudoers /etc/ssh/ssh_host_*_key

# 修复 shadow 文件权限（只在它比 640 宽的时候）
chmod 640 /etc/shadow
# 属组按发行版：Debian / Ubuntu 是 shadow，RHEL 与 Arch 是 root
chown root:shadow /etc/shadow      # Debian / Ubuntu
chown root:root /etc/shadow        # RHEL / Arch

# 修复 SSH 密钥权限（RHEL 出厂的 640 root:ssh_keys 已算通过，不用改）
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

**自动修复**: 无（仅告警）

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
- `nc -e` 或 `ncat -e` - Netcat 反向 shell
- `python -c ... import` / `perl -e` / `ruby -e` - 内联解释器执行
- `\xNN` 形式 - 十六进制编码 payload
- 在 `/tmp` 中执行隐藏文件（`/tmp/.`）

**自动修复**: 无（仅告警）

**修复方法**:
```bash
# 1. 检查系统 cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/

# 2. 检查用户 cron
crontab -l
crontab -l -u <username>

# 3. 检查 cron spool 目录
ls -la /var/spool/cron/crontabs/   # Debian / Ubuntu
ls -la /var/spool/cron/            # RHEL / Arch（cronie）

# 4. 删除可疑条目
crontab -e  # 编辑并删除可疑行
```

---

## 防火墙检测 (ufw)

### 1. 防火墙状态检测

**检测内容**: 先问主机上有没有防火墙**真的在过滤入站**——UFW、firewalld、nftables、
iptables 都算；只有 fail2ban、Tailscale 自己的链，或者「默认放行、规则也全是放行」的规则集，
不算在过滤。是 UFW 的话，再往下查它的默认策略、SSH 规则、宽松规则与 IPv6 设置；
是别的防火墙就到此为止

**为什么重要**: 防火墙是网络安全的第一道防线

**自动修复**: `ufw.install`（安全，仅 Debian / Ubuntu）；`ufw.enable`（高风险）。
启用之前它先给 sshd 监听的**每一个**端口各加一条放行规则，再给你当前的来源 IP 加一条
救援规则，列出将要生效的规则，等你手打 `yes` 才启用。UFW 已启用、但有 SSH 端口没被放行时
（`ufw.no_ssh_rule`），`ufw.allow_ssh`（安全）只补缺的那几个端口

**修复方法**（Debian / Ubuntu）:
```bash
# 安装 UFW（如果未安装）
apt install ufw

# 1. 列出 sshd 实际监听的端口。改过端口、或用 ListenAddress 写了端口时不止 22；
#    不要用 `ufw allow ssh`，它按 /etc/services 只放行 22
sshd -T | grep -E '^(port|listenaddress) '

# 2. 每个端口放行一条（重要！先执行此步骤；例：22 和 2222）
ufw allow 22/tcp
ufw allow 2222/tcp

# 3. 确认规则都已写入，再启用
ufw show added
ufw enable

# 查看状态
ufw status verbose
```

SSH 只允许从 VPN 或某个网卡进来的话（例如 Tailscale），放行写成
`ufw allow in on tailscale0 to any port 22 proto tcp`。`ufw.allow_ssh` 认这类规则，
不会再加一条对全网开放的；`ufw.enable` 与 `ufw.set_default_deny` 为了不把你锁在外面，
切换前仍会给每个 SSH 端口补一条对全网的放行，确认能从 VPN 登录后可以自己删掉。

RHEL 系用 firewalld：`systemctl enable --now firewalld`，默认区域已放行 `ssh` 服务（22）；
SSH 改过端口时先 `firewall-cmd --permanent --add-port=<端口>/tcp && firewall-cmd --reload`。

---

### 2. 默认策略检测

**检测内容**: 检查防火墙默认入站策略是否为拒绝

**为什么重要**: 默认拒绝策略只允许明确放行的流量通过

**自动修复**: `ufw.set_default_deny`（高风险）。切换前先给每个 sshd 端口加放行规则；
没有显式放行的在跑服务会被切断

**修复方法**:
```bash
# 1. 先按上一节第 1、2 步放行每个 sshd 端口，以及要对外提供的服务
ufw allow 22/tcp

# 2. 设置默认策略
ufw default deny incoming
ufw default allow outgoing
```

---

### 3. 敏感端口暴露检测

**检测内容**: 读 UFW 的规则，找出对 Anywhere 放行敏感端口的条目（只看规则，
实际在监听什么由 networking 模块查）

**敏感端口列表**:
| 端口 | 服务 | 建议 |
|------|------|------|
| 3306 | MySQL | 仅限本地或内网 |
| 5432 | PostgreSQL | 仅限本地或内网 |
| 6379 | Redis | 仅限本地或内网 |
| 11211 | Memcached | 仅限本地或内网 |
| 5672 | RabbitMQ | 仅限本地或内网 |
| 27017 | MongoDB | 仅限本地或内网 |
| 9200 | Elasticsearch | 仅限本地或内网 |
| 1433 | MSSQL | 仅限本地或内网 |
| 2375/2376 | Docker API | 绝对不要暴露 |
| 21 / 23 | FTP / Telnet | 明文协议，改用 SFTP / SSH |
| 3389 / 5900 | RDP / VNC | 走 VPN 或 SSH 隧道 |
| 8080 | HTTP 代理/管理后台 | 评估是否对外开放 |

不在表里、又对 Anywhere 放行的端口（22、80、443 除外）也会列出来，提示你复核。
MySQL、PostgreSQL、Redis、MongoDB、Elasticsearch、Docker API 命中时为高危，其余为中危。

**自动修复**: 无（仅告警）

**修复方法**:
```bash
# 1. 找到并删除现有的开放规则
ufw status numbered
ufw delete <编号>

# 2. 仅允许特定 IP 访问
ufw allow from 10.0.0.0/8 to any port 3306

# 3. 或者配置服务只监听本地
# MySQL 示例：编辑 /etc/mysql/mysql.conf.d/mysqld.cnf
# bind-address = 127.0.0.1
```

---

### 4. IPv6 一致性检测

**检测内容**: 检查 UFW 是否同时管理 IPv6 流量

**为什么重要**: `/etc/default/ufw` 中 `IPV6=no` 会让 UFW 只生效于 IPv4。
如果主机本身有全局 IPv6 地址（多数云厂商默认会下发 v6），那么所有
IPv6 入站连接都直接绕过 UFW 规则——你以为只放行了 22，但任何监听
`::` 的服务（Redis、PostgreSQL、应用调试端口等）都暴露在 v6 公网上。
UFW 默认 `IPV6=yes`，只有手动改过才会触发本告警。

**通过条件**: 满足以下任一即可：
- `/etc/default/ufw` 设为 `IPV6=yes`（UFW 同时管理 v4/v6 流量）
- 主机没有全局 IPv6 地址（`IPV6=no` 在此情况下无风险）

**自动修复**: 无（仅告警）

**修复方法**:
```bash
# 1. 编辑 /etc/default/ufw，把 IPV6=no 改回 IPV6=yes
sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw

# 2. 重新加载 UFW（必须 disable 后再 enable，
#    单独 reload 不会重建 ip6tables 规则）
ufw disable
ufw enable

# 3. 验证 IPv6 规则已生效
ufw status verbose
ip6tables -L -n | head -20
```

---

## 入侵防护检测 (fail2ban)

fail2ban 的 jail 配置按这个顺序读，同一个设置**后读的覆盖先读的**：
`jail.conf` → `jail.d/*.conf` → `jail.local` → `jail.d/*.local`（`jail.d` 里按文件名排序）。
`jail.local` 是运维自己的文件，可能还写着别的 jail，不要整份重写它。vpssec 自己写的是
`/etc/fail2ban/jail.d/99-vpssec-sshd.local`；手工配置也写成 `jail.d` 里的一个 `.local` 文件。

### 1. Fail2ban 安装检测

**检测内容**: 检查是否安装了 fail2ban、服务是否在运行且开机自启、是否至少有一个 jail 在工作

**为什么重要**: fail2ban 自动封禁多次登录失败的 IP，有效防止暴力破解

**自动修复**: `fail2ban.install`（安全，仅 Debian / Ubuntu）：安装、启用服务，没有任何
自定义配置时顺带写入上面那个 SSH jail；`fail2ban.enable_service`（安全）

**修复方法**:
```bash
# 安装 fail2ban
apt install fail2ban                                # Debian / Ubuntu
dnf install epel-release && dnf install fail2ban    # RHEL 系（来自 EPEL）
pacman -S fail2ban                                  # Arch

# 启用服务
systemctl enable --now fail2ban
systemctl status fail2ban
```

Debian 12 起默认不再安装 rsyslog，没有 `/var/log/auth.log`，而 Debian 12 自带的 `[sshd]`
jail 要读这个文件：服务会起不来，`fail2ban-client -t` 报
`Have not found any log file for sshd jail`。这时接着做下一节。

---

### 2. SSH Jail 配置检测

**检测内容**: 检查 SSH jail 是否已加载，并且**真能封禁**——它挂着封禁动作，动作要用的
命令（`ufw`、`nft`、`iptables`、`firewall-cmd`）在本机存在。动作的命令不在时，fail2ban 照常
计数、显示「已封禁」，实际一条防火墙规则也没加上，vpssec 会报 `fail2ban.ssh_jail_not_banning`

**自动修复**: `fail2ban.enable_ssh_jail` / `fail2ban.configure_ssh_jail`（需确认）。写入
`jail.d/99-vpssec-sshd.local`：覆盖 sshd 的全部端口；只有能用 journald 时才设
`backend = systemd`；封禁动作按本机防火墙选；`ignoreip` 带上回环地址和你当前的 SSH 来源 IP。
写完先 `fail2ban-client -t` 检查，加载后确认 jail 能封禁，不能就撤回这个文件

**修复方法**:
```bash
# 1. 收集三样信息
sshd -T | grep -E '^(port|listenaddress) '             # sshd 的全部端口（含 listenaddress 冒号后的）
python3 -c 'import systemd.journal' && echo journald-ok   # 能不能用 systemd 后端
who am i                                                  # 括号里是你当前的来源地址

# 2. 写一个 jail.d 的 .local 文件（文件已存在就先看内容，改它而不是覆盖）
cat > /etc/fail2ban/jail.d/sshd-local.local << 'EOF'
[sshd]
enabled  = true
port     = 22,2222
backend  = systemd
maxretry = 3
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1 203.0.113.7
EOF
```

按第 1 步的结果调整这几行：

- `port`：填第 1 步列出的全部端口。只写 22 的话，sshd 在 2222 上挨的暴力破解一个也封不住。
- `backend = systemd`：第 1 步打印了 `journald-ok` 才写。没打印、但有 `/var/log/auth.log`
  或 `/var/log/secure` 时删掉这一行，按发行版默认读日志文件；两样都没有就先装
  `python3-systemd` 包（Debian / Ubuntu、RHEL 都叫这个名字）。
- `ignoreip`：把示例里的 203.0.113.7 换成你自己的管理 IP，否则手滑输错几次密码，
  会被自己的 jail 封上一小时。
- 封禁动作：UFW 在管防火墙时加一行 `banaction = ufw`。Debian 12 默认的动作是
  `iptables-multiport`，精简安装却可能只有 `nft`、没有 `iptables` 命令，这时加一行
  `banaction = nftables-multiport`。RHEL 系从 EPEL 装的 fail2ban 带着 firewalld 的动作，不用写。

```bash
# 3. 检查配置、加载、确认 jail 能封禁
fail2ban-client -t
systemctl restart fail2ban
fail2ban-client status sshd
fail2ban-client get sshd actions
```

---

### 3. MaxRetry 设置检测

**检测内容**: 检查 SSH jail 生效的最大失败尝试次数（取 `fail2ban-client get sshd maxretry`）

**推荐设置**: 3-5 次（大于 5 判失败）

**自动修复**: `fail2ban.configure_ssh_jail`（需确认，写入 `maxretry = 3`）

**修复方法**: 改上一节那个 `jail.d/*.local` 文件里的 `maxretry`。改 `jail.local` 不会生效——
`jail.d/*.local` 在它之后读，会把它盖掉。

```bash
sed -i 's/^maxretry *=.*/maxretry = 3/' /etc/fail2ban/jail.d/sshd-local.local
fail2ban-client -t && systemctl restart fail2ban
fail2ban-client get sshd maxretry
```

---

## Docker 安全检测 (docker)

### 1. 暴露端口检测

**检测内容**: 检查容器是否把端口发布在回环以外的地址上（`0.0.0.0`、`::` 或某个公网 IP）

**为什么重要**: 发布在这些地址上的端口所有网络接口都能访问；而且 Docker 自己改写 iptables，
发布的端口走的是转发链，不经过 UFW 管的入站规则，`ufw deny` 挡不住它

**自动修复**: `docker.generate_proxy_template`（模板类）：只写出一份反向代理模板供你审阅部署，
在你部署并改掉端口发布之前，这一项照旧失败

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

**自动修复**: 无（仅告警）

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

**自动修复**: 无（仅告警）

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

**检测内容**: 检查 dockerd **正在用的**两项设置：`live-restore` 与 `no-new-privileges`。
答案取自 `docker info`，所以只写进 `daemon.json`、还没加载的设置不算数；dockerd 没在跑时
才退回去读配置

| 设置 | 作用 | 怎么生效 |
|------|------|----------|
| `"live-restore": true` | dockerd 停掉或重启时，容器继续运行 | `systemctl reload docker`，不影响运行中的容器 |
| `"no-new-privileges": true` | 新容器里的进程不能再通过 setuid 等方式提权 | 必须重启 dockerd；只对此后新建的容器生效 |

**自动修复**: `docker.enable_live_restore`（需确认，写入后 reload）；
`docker.enable_no_new_privileges`（需确认，要手打 `yes` 才重启 dockerd）。两项都把设置合并进
现有的 `daemon.json`，保留文件原来的权限与属主（它可能存着镜像仓库或代理的凭据）

**修复方法**:
```bash
# 0. dockerd 的命令行上已经带了同名参数（例如 --live-restore）时，改 unit 里那个参数，
#    不要再写进 daemon.json：两处同时设置，dockerd 拒绝启动
systemctl show -p ExecStart docker

# 1. 先开 live-restore：合并进现有文件，不要整份覆盖；
#    写回用 cat >，文件原来的权限与属主保持不变
f=/etc/docker/daemon.json
[ -f "$f" ] || echo '{}' > "$f"
jq '. + {"live-restore": true}' "$f" > /tmp/daemon.json.new && cat /tmp/daemon.json.new > "$f"
systemctl reload docker
docker info --format '{{.LiveRestoreEnabled}}'      # 应为 true

# 2. 再开 no-new-privileges。它要重启 dockerd：live-restore 已经生效时容器不停；
#    否则所有容器都会停掉，没设重启策略的不会自己再起
jq '. + {"no-new-privileges": true}' "$f" > /tmp/daemon.json.new && cat /tmp/daemon.json.new > "$f"
systemctl restart docker
docker info --format '{{json .SecurityOptions}}'   # Engine 24 起应含 name=no-new-privileges
```

---

## 恶意软件检测 (malware)

本模块的发现全部只告警，vpssec 不做任何自动处置。处置之前先保留证据（进程信息、可疑文件的
副本、日志），删掉之后就无从查起入侵是怎么发生的。

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

**检测内容**: 检查是否存在 LD_PRELOAD 环境变量劫持，以及 `/etc/ld.so.preload` 是否非空

**为什么重要**: LD_PRELOAD 可被用于库注入攻击

**检查位置**:
- `/etc/ld.so.preload`（非空即报）
- `/etc/profile`、`/etc/profile.d/*.sh`、`/etc/environment`、`/etc/bash.bashrc`
- root 和每个普通用户（UID ≥ 1000）家目录下的 `.bashrc`、`.bash_profile`、`.bash_login`、
  `.profile`、`.zshrc`、`.zshenv`（只认真正的赋值或 export 行，注释掉的不算）

**修复方法**:
```bash
# 1. 先留证据，再清空 ld.so.preload。用 `: >` 清空；`echo "" >` 会留下一个换行，
#    文件仍然非空，这一项会一直报
cat /etc/ld.so.preload
cp -a /etc/ld.so.preload /root/ld.so.preload.evidence
: > /etc/ld.so.preload

# 2. 检查环境文件
grep -rn "LD_PRELOAD" /etc/profile /etc/profile.d/ /etc/environment /etc/bash.bashrc
grep -n "LD_PRELOAD" /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null
```

---

### 3. 挖矿进程检测

**检测内容**: 检测加密货币挖矿进程和矿池连接

**检测特征**:
- 进程名: xmrig, minerd, kinsing 等
- 高 CPU 使用率（按可执行文件名跳过 apt、python、java 等已知的高负载程序）
- 本机向公网地址的已知矿池端口 (3333, 4444, 5555 等) 发起的连接；回环、私网、链路本地、100.64/10 与 IPv6 ULA 上的连接是本机或内网服务，不算

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

**检测内容**: 读 Web 目录（`/var/www`、`/home/*/public_html` 等）下每一个 `.php` 文件的内容，不限深度与数量；整次遍历受 `VPSSEC_FS_TIMEOUT` 约束，超时则报「恶意软件扫描不完整」，不报「未发现恶意软件指标」

**检测模式**（只看内容，文件名与权限不作为证据）:
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

**检测内容**: 检测正在运行但二进制文件已被删除的进程。原路径上已经有新文件的不算——
那是升级软件包后还没重启的守护进程；从内存文件（memfd）运行的进程另有一项检查

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
1. 修改前保持一个现有 SSH 会话不要关闭，另开终端验证能登录后再关
2. 先测试新配置：`sshd -t` 只查语法；再用 `sshd -T` 看生效值（见
   [手工改 sshd 配置之前](#手工改-sshd-配置之前)），确认改动没有被别的文件盖掉
3. 改了端口或启用防火墙之前，先放行 sshd 的每一个端口
4. 已经进不去了：用云服务商的 VNC/控制台登录恢复；用 vpssec 改的，可以在控制台里
   `sudo vpssec rollback` 撤回

### Q: 某些检测项不适用于我的环境怎么办？

A: 脚本支持模块选择。可以用 `--include=` 仅运行指定模块，或用
`--exclude=` 跳过不适用的模块：
```bash
sudo ./vpssec audit --include=users,ssh,ufw
sudo ./vpssec audit --exclude=docker,cloudflared
```

### Q: 如何定期运行检测？

A: 可以设置 cron 任务，配合 `--json-only` 让输出适合采集：
```bash
# 每周日凌晨 3 点运行检测，JSON 报告写入 reports/summary.json
0 3 * * 0 cd /path/to/CloudServer-Audit && sudo ./vpssec audit --json-only > /var/log/vpssec-audit.log 2>&1
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

---

## 附录 A：vpssec 命令参考

```bash
vpssec [mode] [options]
```

### 模式

| 模式 | 说明 |
|---|---|
| `audit` | 只读审计（默认模式） |
| `guide` | 交互式加固向导（会修改系统） |
| `rollback [TS]` | 回滚到指定时间戳的备份；省略 `TS` 进入交互选择 |
| `status` | 显示版本与有没有新版本；以 root 运行时还显示上次审计的时间与得分（有模块没跑完会注明）、上次应用修复的时间、备份会话数与位置——状态目录只归 root 可读 |
| `help [MODULE]` | 列出所有模块和 `fix_id`；带模块名时显示该模块的详情（不需要 root，不会改系统） |

### 选项

| 选项 | 说明 |
|---|---|
| `--lang=LANG` | 语言（`zh_CN` 默认，`en_US`） |
| `--include=MODS` | 只运行指定模块（逗号分隔） |
| `--exclude=MODS` | 排除指定模块 |
| `--fix=IDS` | 只对 `guide`：不出菜单，直接执行逗号分隔的修复 ID；本次审计没给出的 ID 一律拒绝并退出 1 |
| `--yes` | 自动确认非关键提示（**critical_confirm 仍然必须手动确认**）；审计结束时的「是否保存报告」也算，带 `--yes` 报告总是写出（不带时默认不写，`reports/` 里已有的旧报告不动，并说明它们是哪次写的） |
| `--json-only` | 只输出 JSON（CI/CD 用） |
| `--strict` | 严格评分：`optional` 类别的检查也计入分数（见附录 B） |
| `--no-color` | 关闭彩色输出 |
| `--debug` | 详细日志写到 `logs/vpssec.log` |
| `-h, --help` | 显示帮助 |
| `-v, --version` | 显示版本 |

### 环境变量

| 变量 | 说明 |
|---|---|
| `VPSSEC_FS_TIMEOUT=N` | 单次文件系统遍历的超时秒数，大于 0 的整数（默认 60），用于 SUID/SGID/世界可写/无主文件/文件能力与网站目录扫描；值不合法时 `audit`/`guide` 直接拒绝并退出 1。遍历超时或没跑成时，相应的「未发现」通过项不再给出，报告多一条 `filesystem.scan_incomplete`（或 `webapp.scan_incomplete`），审计退出 3 |

---

## 附录 B：安全评分计算

```
base    = 100 × passed / scored_total
penalty = 5 × high + 1.5 × medium + 0.25 × low
score   = clamp(0, 100, base − penalty)
```

`base` 与 `penalty` 都按整数向下取整后再相减。

`scored_total` 只统计分类为 `required`、`recommended`、`conditional`
（且对应组件已安装）、`optional`（仅 `--strict`）的检查。`info` 类
检查（如云厂商识别、"Docker 未安装"）既不进分子也不进分母——所以
这些项不会影响分数。`summary.md` 在这类发现的标题后标「不计分」，
`summary.json` 的每条检查带 `scored` 字段。

### 分数只在相同模块范围内可比

`base` 是比率，会随 `scored_total` 缩放；`penalty` 是绝对值，不会。
两者相加意味着：

- 用 `--include=` 缩小范围时，同样的惩罚落在更小的基数上，分数被压得更低；
- 若子集里被计分的检查恰好**全部失败**，`base` 就是 0，无论问题多轻，
  最终分数都会落到 0。

例如某台机器全量跑是 40 分，`--include=ufw` 单跑却是 0 分（上下文模块
preflight/cloud/timezone 会自动随任何 `--include` 一起运行，无需手动列出）
——两个数字各自都没算错，但**不能拿来互相比较**。

因此凡是带了 `--include`/`--exclude` 的运行，终端与 Markdown 报告都会
在分数旁标注「部分评分：仅基于模块 [...] 的 N 项计分检查，与全量运行的分数不可比」，
`summary.json` 里也会带
`meta.partial_scope: true` 与 `stats.scored_total`。要做趋势对比，请
固定同一组模块，或直接跑全量。

### 不同失败组合下的示例（按 ~50 个 scored check 估算）

| 失败情况 | 分数 | 档位 |
|---|---|---|
| 0 | 100 | 优秀 |
| 1 medium | 97 | 优秀 |
| 1 high | 93 | 优秀 |
| 3 high | 79 | 良好 |
| 3 high + 6 medium + 3 low | 52 | 一般 |
| 10 high + 20 medium + 30 low | 0 | 较差 |

### 评分档位

下面的档位只是读分数的参考，vpssec 不输出这些名称；终端里的分数按 80 分以上绿色、
60–79 黄色、60 以下红色着色。

- **90–100 优秀**：基线已建立
- **75–89 良好**：少数项目可改善
- **50–74 一般**：有多个值得修的项
- **0–49 较差**：建议尽快加固

### 评分类别

| 类别 | 说明 | 示例 |
|---|---|---|
| `required` | 始终计入分数 | SSH 认证、防火墙、kernel ASLR |
| `recommended` | 始终计入分数，与 `required` 同权 | fail2ban、AppArmor、内核网络参数 |
| `conditional` | 仅当组件已安装时计入 | Docker、Nginx、Cloudflared |
| `optional` | 只在 `--strict` 下计入 | SSH 弱算法、fail2ban 的 maxretry、Nginx 的 DoS 加固、SGID 文件 |
| `info` | 不影响分数 | 云厂商识别、auditd、alerts、backup |

这样保证没使用的组件不会拖累分数。

---

## 附录 C：模块完整列表

### 始终运行的上下文模块

| 模块 | 用途 |
|---|---|
| `preflight` | 环境预检（系统、网络、依赖、监听端口计数） |
| `cloud` | 云厂商 / Agent 识别 + IMDS 姿态（IMDSv1/v2、user-data 凭据扫描、多云 tier1/tier2 覆盖） |
| `timezone` | 时区与 NTP 时间同步 |

### 核心模块

| 模块 | 用途 |
|---|---|
| `users` | 用户安全（UID 0、空密码、重复 UID、NOPASSWD sudo、哈希方法、faillog、sudoers 语法） |
| `ssh` | SSH 加固（密码认证、root 登录、SSH-7408 全量选项） |
| `ufw` | 防火墙（UFW/firewalld/iptables/nftables；只认真正在过滤入站的规则集） |
| `fail2ban` | Fail2ban 服务 + SSH jail + 活动 jail 清单 |
| `networking` | 监听端口（公网/loopback 区分、危险端口黑名单、混杂模式接口） |
| `update` | 系统更新（安全更新、自动更新、内核版本不匹配 reboot 检测） |
| `kernel` | 内核加固（ASLR、sysctl 网络/安全参数、IPv6、少用协议模块黑名单） |
| `filesystem` | 文件系统（SUID/SGID、权限、umask、敏感文件含 shadow- 备份） |
| `baseline` | 基线（AppArmor/SELinux、未用服务、文件完整性工具、传统不安全服务） |
| `docker` | Docker 安全（特权容器、暴露端口、host-network、env 凭据、内存限制） |
| `nginx` | Nginx 兜底 + DoS 加固（CIS 5.2.1 超时、速率限制） |
| `webapp` | Web 应用（Nginx/Apache/PHP 配置、SSL、敏感文件） |
| `malware` | 恶意软件检测（rootkit、挖矿、webshell、反向 shell、已删二进制进程） |
| `logging` | 日志与审计（journald、auditd、logrotate） |
| `scheduling` | cron/at 任务清单 + 供应链模式扫描 |

### 可选模块

| 模块 | 用途 |
|---|---|
| `cloudflared` | Cloudflare Tunnel 配置检查 |
| `backup` | 备份工具检测和模板生成 |
| `alerts` | Webhook/邮件告警配置 |

---

## 附录 D：目录结构

```
vpssec/
├── vpssec              # 主入口脚本
├── VERSION             # 版本号唯一来源；release.yml 拒绝与它不一致的 tag
├── run.sh              # 一次性运行入口（拉 release tarball + cosign 验签，跑完自删）
├── install.sh          # 安装到 /opt/vpssec（同样 cosign 验签，升级保留 state/backups）
├── core/               # 核心引擎
│   ├── common.sh       # 公共工具（日志、i18n、校验、原子写、单例锁）
│   ├── engine.sh       # 模块加载、audit/guide 调度、计划恢复
│   ├── state.sh        # JSON 状态（checks/plan/progress）、备份、评分
│   ├── report.sh       # 报告生成（双列布局）
│   ├── security_levels.sh  # fix 安全分级 + 评分类别定义
│   ├── help.sh         # `vpssec help [module]` 调度
│   ├── ui_tui.sh       # TUI 界面（whiptail/dialog）
│   ├── ui_text.sh      # 文本回退界面
│   └── i18n/           # 国际化
│       ├── zh_CN.json
│       └── en_US.json
├── modules/            # 安全检查模块（共 21 个）
├── tests/              # 测试基础设施
│   ├── *.bats          # bats 单元测试（用 `bats tests/` 运行）
│   ├── mutation/       # 变异测试 harness
│   │   ├── run.sh      # 驱动（sudo bash tests/mutation/run.sh）
│   │   └── cases/      # 每个 check_id 一个文件
│   └── uninstall/      # 卸载脚本的破坏性验证
│       └── run.sh      # 驱动（sudo bash tests/uninstall/run.sh）
├── tools/              # 开发者工具（变异测试驱动与用例）
├── docs/               # 用户文档
├── state/              # 运行时状态
├── reports/            # 生成的报告
├── backups/            # 配置备份
└── logs/               # 日志文件
```

---

## 附录 E：扩展开发指南

### 添加新模块

1. 创建 `modules/mymodule.sh`：

```bash
#!/usr/bin/env bash
# vpssec - My Custom Module

mymodule_audit() {
    print_item "$(i18n 'mymodule.check_something')"

    if _mymodule_something_ok; then
        check_emit "mymodule.something_ok" low passed
        print_ok "$(i18n 'mymodule.something_ok')"
    else
        check_emit "mymodule.something_wrong" medium failed \
            desc="$(i18n 'mymodule.something_wrong_desc')" \
            suggestion="$(i18n 'mymodule.fix_something')" \
            fix="mymodule.fix_something"
        print_severity "medium" "$(i18n 'mymodule.something_wrong')"
    fi
}

mymodule_fix() {
    case "$1" in
        mymodule.fix_something)
            # 修复逻辑。改文件之前先 backup_file "<路径>"，回滚才找得回原件
            ;;
        *)
            return 1
            ;;
    esac
}
```

   `check_emit` 不传 `title=` 时，标题取 i18n 里与 check_id 同名的键（上例是
   `mymodule.something_ok`）。

2. 在 `core/engine.sh` 中把模块名加到 `VPSSEC_MODULE_ORDER`，并在
   `VPSSEC_MODULE_CATEGORY` 给它分类。

3. **同时**在 `core/i18n/en_US.json` 和 `core/i18n/zh_CN.json` 添加翻译——
   `tests` workflow 的 `i18n-parity` job 会校验两边的 key 集合相同。

4. 在 `core/security_levels.sh` 给每个 `fix_id` 分类（`FIX_SAFE` /
   `FIX_CONFIRM` / `FIX_RISKY` / `FIX_ALERT_ONLY`；只写出模板、解决不了发现的另登记
   `FIX_TEMPLATE_ONLY`），以及给每个 `check_id` 加 `CHECK_SCORE_CATEGORY` 条目。
   `FIX_SAFE`、`FIX_CONFIRM`、`FIX_RISKY` 里的 fix（`FIX_TEMPLATE_ONLY` 除外）还要在
   `FIX_VERIFY` 登记审计判定通过的那个函数，修复跑完由引擎再问一次；漏登记 `bats` 会报红。

`module-contract` CI job 会验证每个 `VPSSEC_MODULE_ORDER` 里的名字
都对应 `modules/<name>.sh`，并且导出了 `<name>_audit()` 和 `<name>_fix()`。

### 单元测试

```bash
bats tests/                 # 跑完整 bats 套件（1400+ 用例，具体数以 CI 为准）
bats tests/test_score.bats  # 跑单个测试文件
```

bats 测试覆盖纯函数（`count_lines`、`validate_*`、`calculate_score`、
fix 分级、plan-resume 过滤、help 调度、backup-restore 路径安全）
和模块级解析/回归测试。每个测试有独立的 `BATS_TEST_TMPDIR`，不
触碰真实系统状态。

### 变异测试

```bash
sudo bash tests/mutation/run.sh            # 跑全部 case（仅在可丢弃 VM）
sudo bash tests/mutation/run.sh ssh        # 按名字过滤
sudo bash tests/mutation/run.sh -k 020     # 按编号过滤
sudo bash tests/mutation/run.sh --strict   # 有 case 被跳过就算这次运行失败
sudo bash tests/mutation/run.sh --manual   # 连声明为仅手工的 case 一起跑
```

每个 `.case` 文件负责：注入一个已知缺陷 → 运行审计 → 断言对应
检测命中 → 还原。restore 是 best-effort，因此**只在可丢弃的 VM
或容器上运行**。每一次审计的退出码都要和报告对得上：0 必须是 `meta.complete` 为 true，
3 必须是 false，别的组合算这条 case 失败。

带 `FIX_ID` 的 case（`1xx-*-fix.case`）在检出之后还走两段：用真正的
CLI `vpssec guide --fix=<id> --yes` 执行修复 → 重新审计，断言
`EXPECT_FIXED_ID` 变成 `EXPECT_FIXED_STATUS`；再 `vpssec rollback` 回滚
这次的备份会话 → 重新审计，断言 `EXPECT_ROLLBACK_ID` /
`EXPECT_ROLLBACK_STATUS` 与回滚的退出码。每条断言读的都是审计的
结论，不是修复函数的退出码。回滚那段没有默认期望：文件类修复回滚后
必须重新变红；回滚够不着的修复（运行中的 sysctl 值、经 ufw 写入的防火墙
规则、装上的软件包、起停的服务）回滚后照旧是绿的，它们改为打印并在日志
里记下撤销命令——case 自己写明它属于哪一种，这张「回滚不覆盖什么」的
清单因此是跑出来的。

高风险修复不认 `--yes`，要在终端上回答：case 在 `FIX_TTY_ANSWERS` 里逐行写好要输入的内容，
runner 经伪终端喂进去，并核对每一行 yes / no 都碰上了自己那一个 `[yes/NO]` 提示——修复要是
根本没问就执行了，这条 case 失败。带 `EXPECT_DECLINED=1` 的 case 答 no：guide 必须退出 0
（拒绝算跳过），不留备份会话、不留撤销命令，`EXPECT_FIXED_ID` 保持原状，没有回滚那一段。

#### 在一次性容器里跑，CI 也这么跑

```bash
bash tests/mutation/run-in-container.sh        # 自己起容器、拷树、带 --strict 跑全部 case
bash tests/mutation/run-in-container.sh ssh    # 参数原样透传给 run.sh
```

`tests/mutation/Dockerfile` 是那台一次性主机：Debian 12 + systemd 当
PID 1（修复要 enable / reload 服务）+ openssh-server + nginx + sudo，再加上 case 要往里种
东西的 `at` 与 `python3-minimal`；logrotate / ufw / fail2ban 故意不预装，对应的 `*.install`
修复要从「没装」起步，需要 fail2ban 在跑的 `050-fail2ban-no-jails` 自己装、跑完再卸干净。
镜像里屏蔽了 `systemd-binfmt`：binfmt_misc 是整台宿主共用的一张表，只要有软件包带了
binfmt.d 文件，特权容器里的 systemd 开机和关机时都会把宿主上的登记（Rosetta、qemu）全部清掉。
GitHub Actions 的 `mutation-integration` job 跑的就是这一条命令。

**期望结果（上面那个镜像）**：汇总行形如
`Total: … Passed: … Failed: 0  Errored: 0  Skipped: 0  Manual: 1`。容器里总是带 `--strict`：
case 是照这个镜像写的，`precheck` 不成立说明镜像漂了，这时它不记为跳过，而是记为失败，
并打印卡在哪个条件上，不能让 CI 照样绿着。唯一的 Manual 是 `080-docker-host-network`
（容器里没有 Docker），它在 case 里用 `MANUAL_ONLY` 写明原因，只在带 `--manual` 时才跑。
不带 `--strict` 在别的主机上跑时，`precheck` 不成立的 case 记为跳过，同样打印卡在哪里。

**`Failed` 或 `Errored` 非零就是回归**，需要定位到底是检测逻辑退化了，
还是 case 的期望值过时了——两种情况历史上都发生过：

- `EXPECT_SEVERITY` 曾经和模块里实际发出的严重度对不上（用例没跟上
  一次分类收敛），表现为长期 `WARN | severity drift`；
- `042-users-hash-rounds` 曾经只改 `/etc/login.defs`，而被测检查在
  yescrypt（Debian 12+ 默认）下会正确跳过，于是这条 case 在所有受
  支持的发行版上都永久失败——代码是对的，用例够不到它。

写新 case 时，前置条件照样写进 `precheck`；在这个镜像里注定跑不起来的，用 `MANUAL_ONLY`
写明原因，而不是让它每次默默跳过。

### 卸载脚本验证

```bash
sudo bash tests/uninstall/run.sh          # 仅在可丢弃 VM 或容器
```

`install.sh` 生成的 `uninstall.sh` 是全项目**唯一会生成 `rm -rf` 的
地方**，而它的白名单只接受 `/opt/<名字>` 与 `/var/lib/<名字>`——bats
的临时目录一律不在其中，所以「数据保留」「数据清除」这两条成功路径
在单元测试里根本走不到。拒绝路径和生成内容由
`tests/test_install_uninstaller.bats` 覆盖，需要真实目录和真实
`rm -rf` 的那一半在这里。

这个脚本只在 `/opt/vpssec-proof-*` 与 `/srv/vpssec-proof-*` 下操作，
但它确实执行删除，因此同样**只在可丢弃主机上跑**。

**期望基线：** 每一行都是 `ok`，末行 `UNINSTALLER PROOF: ALL PASS`，
退出码 0。五组分别验证：路径被正确烤进脚本、默认保留 state/backups、
`VPSSEC_UNINSTALL_PURGE=1` 时全清、白名单外的路径拒绝且不动任何东西、
含 shell 元字符的路径被引用而不是被执行。

---

## 附录 F：CI/CD 集成示例

vpssec 是给真实运行的服务器做审计用的。在 throwaway GitHub Actions
runner 上跑技术上可行，但报告反映的是 runner 镜像本身——下面的
workflow 是为**审计你自己的服务器**用的模板（通过 SSH 远程执行或
self-hosted runner），不是在 `ubuntu-latest` 上跑出有意义结果的用法。

### GitHub Actions（self-hosted runner 示例）

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 6 * * 1'  # 每周一早上 6:00
  workflow_dispatch:

jobs:
  audit:
    # 替换为指向你要审计的生产服务器的 self-hosted runner 标签
    runs-on: [self-hosted, my-production-host]
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Audit
        # 用 --yes 让审计非交互地保存全部报告格式（md/json/sarif）——
        # 审计是只读的，没有破坏性操作需要确认。（--json-only 也会重新生成
        # 全部三个报告文件、只把 JSON 打到 stdout；这里用 --yes 是为了保留
        # 终端可读输出。）
        run: sudo ./vpssec audit --yes

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/summary.sarif
```

---

## 获取帮助

如果在使用过程中遇到问题：

1. 查看脚本帮助：`sudo ./vpssec --help`
2. 查看详细日志：项目根目录下的 `logs/vpssec.log`（追加 `--debug` 可获得更详细的输出）
3. 提交 Issue：[GitHub Issues](https://github.com/Lynthar/CloudServer-Audit/issues)

---

*本指南将随脚本更新持续完善。*
