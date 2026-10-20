# vps-ssh-hardening

新 VPS 一键安全加固脚本，支持 **Debian / Ubuntu / Alpine**，全中文交互。

配置 **fail2ban** 现代化监狱、SSH 自定义端口、切换为 **仅密钥登录**，并用两步验证流程确保不会把自己锁在门外。

## 功能

**必做项：**

- **系统更新** — 开机先把系统升级到最新
- **交互式配置** — SSH 端口、最大失败次数、统计窗口、封禁时长（预设或自定义）、惯犯监狱开关，全有默认值，一路回车也行
- **现代化 fail2ban** — `[sshd]` 监狱 + `[recidive]` 惯犯监狱，封禁动作绑定你*实际*的 SSH 端口（老脚本写死 `port=ssh`，改了端口根本不生效）
- **仅密钥登录，不锁死** — 先装好公钥，但密码登录保持开启，直到你*在新终端确认密钥登录成功*，才禁用密码

**可选项：**

- **时区设置**（默认 Asia/Shanghai）
- **自动安全更新** unattended-upgrades（仅 Debian/Ubuntu）
- **UFW 防火墙**（仅 Debian/Ubuntu，默认拒绝入站，可追加放行端口）
- **sysctl 内核加固**（防 IP 欺骗、SYN 洪水、ICMP 重定向攻击、内核指针泄露等 17 项）
- **新建 sudo 管理用户**（可顺带禁止 root 直接 SSH 登录）

**兼容与安全细节：**

- Debian 12 缺失 `/var/log/auth.log` 会导致 fail2ban 无法启动 —— 脚本自动补装 rsyslog 并配置日志规则
- `filter = recidive` 显式写入（官方 `jail.conf` 缺这一行，惯犯监狱会静默失效）
- 每次修改前都带时间戳备份 `sshd_config` 和 `jail.local`，且每次重启前都跑 `sshd -t` 校验配置，可回滚

## 要求

- Debian / Ubuntu（systemd）或 Alpine（OpenRC，需先 `apk add bash`）
- root 权限
- 本地有一对 SSH 密钥（如 `ssh-keygen -t ed25519`）

## 使用

新机器上一行命令（root 执行）：

```bash
bash <(curl -sL https://raw.githubusercontent.com/termv8/引导程序/main/vps-ssh-hardening.sh)
```

提示输入公钥时，三种给法都行：直接粘贴公钥内容、填 `.pub` 文件路径、或填 URL（如 `https://github.com/你的用户名.keys`）。

想手动跑的话：

1. 没有密钥先生成一个：

   ```bash
   ssh-keygen -t ed25519
   ```

2. 下载并运行脚本：

   ```bash
   curl -O https://raw.githubusercontent.com/termv8/引导程序/main/vps-ssh-hardening.sh
   bash vps-ssh-hardening.sh
   ```

3. 按提示回答。脚本让你确认时，在**新终端**里验证密钥登录（`ssh -p 端口 用户@服务器IP`）成功后再回车 —— 确认之前密码登录不会被禁用。

4. 别忘了去云厂商安全组 / 防火墙放行新的 SSH 端口。

## 改动内容

| 文件 / 项 | 改动 |
|---|---|
| `/etc/ssh/sshd_config` | `Port` 改为所选端口；密钥验证后：`PasswordAuthentication no`、`ChallengeResponseAuthentication no`、`KbdInteractiveAuthentication no`、`PubkeyAuthentication yes`（可选 `PermitRootLogin no`） |
| `/etc/fail2ban/jail.local` | `[sshd]` 监狱（你的参数），启用时加 `[recidive]` |
| `~/.ssh/authorized_keys` | 为所选用户（默认 root）添加你的公钥 |
| `/etc/sysctl.d/99-vps-hardening.conf` | 可选：17 项内核加固参数 |
| 软件包 | `fail2ban`、`rsyslog`，可选 `ufw`、`unattended-upgrades` |

## 注意事项

- 密钥登录确认之前，**不要关闭当前 SSH 窗口** —— 这正是两步流程的意义
- 私钥丢了的话，用云厂商网页控制台（VNC）进去重新添加公钥
- 重复运行是安全的：每次都会重新备份，已装过的公钥不会重复添加

## 致谢

改编自 [FunctionClub/Fail2ban](https://github.com/FunctionClub/Fail2ban)，针对现代 fail2ban 与 Debian 12 做了更新，并扩展了多系统与多项加固。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
