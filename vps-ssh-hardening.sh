#!/bin/bash
#
# vps-ssh-hardening.sh — 新 VPS 一键安全加固
# 支持: Debian / Ubuntu / Alpine
#
# 功能:
#  [必做] 系统更新到最新
#  [必做] fail2ban (sshd 监狱 + recidive 惯犯监狱)
#  [必做] SSH: 自定义端口 + 密钥登录(两步验证,防锁死)
#  [可选] 设置时区
#  [可选] unattended-upgrades 自动安全更新 (仅 Debian/Ubuntu)
#  [可选] UFW 防火墙,默认只放行 SSH (仅 Debian/Ubuntu)
#  [可选] sysctl 内核加固 (防 IP 欺骗/SYN 洪水/重定向攻击等)
#  [可选] 新建 sudo 管理用户
#
# 注意:
#  - Alpine 请先安装 bash: apk add bash
#  - 用法: bash <(curl -sL https://raw.githubusercontent.com/USER/REPO/main/vps-ssh-hardening.sh)
#

# ================= 基础函数 =================
CFAILURE="\033[31m"; CWARNING="\033[33m"; CMSG="\033[36m"; COK="\033[32m"; CEND="\033[0m"
info() { echo -e "${CMSG}$*${CEND}"; }
ok()   { echo -e "${COK}$*${CEND}"; }
warn() { echo -e "${CWARNING}$*${CEND}"; }
fail() { echo -e "${CFAILURE}$*${CEND}"; exit 1; }

[ "$(id -u)" = "0" ] || fail "错误：请用 root 用户运行此脚本。"

# ================= 系统识别 =================
OS_ID=""; PRETTY_NAME="未知"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="$ID"
fi
case "$OS_ID" in
    debian|ubuntu) PKG="apt"; INIT="systemd"; SSH_SVC="ssh" ;;
    alpine)        PKG="apk"; INIT="openrc";  SSH_SVC="sshd" ;;
    *) fail "此脚本仅支持 Debian / Ubuntu / Alpine（检测到：$OS_ID）。" ;;
esac
info "检测到系统：$PRETTY_NAME"
echo ""

pkg_install() {
    if [ "$PKG" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1
    else
        apk add --no-cache "$@" >/dev/null 2>&1
    fi
}
svc_enable() {
    if [ "$INIT" = "systemd" ]; then
        systemctl enable "$1" >/dev/null 2>&1
    else
        rc-update add "$1" default >/dev/null 2>&1
    fi
}
svc_restart() {
    if [ "$INIT" = "systemd" ]; then
        systemctl restart "$1"
    else
        rc-service "$1" restart
    fi
}
svc_active() {
    if [ "$INIT" = "systemd" ]; then
        systemctl is-active --quiet "$1"
    else
        rc-service "$1" status >/dev/null 2>&1
    fi
}
ask_yn() {
    local prompt="$1" def="$2" ans
    while true; do
        if [ "$def" = "Y" ]; then
            read -rp "$prompt [Y/n]: " ans
        else
            read -rp "$prompt [y/N]: " ans
        fi
        ans=${ans:-$def}
        case "$ans" in
            [Yy]) echo "yes"; return ;;
            [Nn]) echo "no"; return ;;
            *) warn "请输入 y 或 n。" ;;
        esac
    done
}

# ================= 1. SSH 端口 =================
cur_port=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
[ -z "$cur_port" ] && cur_port=22
while true; do
    read -rp "SSH 端口（当前：$cur_port，直接回车保持不变）: " SSH_PORT
    [ -z "$SSH_PORT" ] && SSH_PORT=$cur_port
    case "$SSH_PORT" in
        ''|*[!0-9]*) warn "端口无效，请输入 1-65535 之间的数字。" ;;
        *)
            if [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
                break
            fi
            warn "端口无效，请输入 1-65535 之间的数字。"
            ;;
    esac
done
[ "$SSH_PORT" = "22" ] && warn "22 是全网被扫描最多的端口，强烈建议换一个自定义端口。"
echo ""

# ================= 2. fail2ban 参数 =================
while true; do
    read -rp "封禁前允许失败几次 [2-10]（默认 5）: " MAXRETRY
    [ -z "$MAXRETRY" ] && MAXRETRY=5
    case "$MAXRETRY" in
        ''|*[!0-9]*) warn "请输入 2-10 之间的数字。" ;;
        *)
            if [ "$MAXRETRY" -ge 2 ] && [ "$MAXRETRY" -le 10 ]; then break; fi
            warn "请输入 2-10 之间的数字。"
            ;;
    esac
done
while true; do
    read -rp "统计失败次数的时间窗口，单位分钟（默认 10）: " FINDTIME
    [ -z "$FINDTIME" ] && FINDTIME=10
    case "$FINDTIME" in
        ''|*[!0-9]*) warn "请输入一个正数。" ;;
        *)
            if [ "$FINDTIME" -ge 1 ]; then break; fi
            warn "请输入一个正数。"
            ;;
    esac
done
info "封禁时长："
info "  1) 10 分钟"
info "  2) 1 小时"
info "  3) 24 小时"
info "  4) 1 周"
info "  5) 自定义（小时）"
while true; do
    read -rp "请选择 [1-5]（默认 2）: " BC
    [ -z "$BC" ] && BC=2
    case "$BC" in
        1) BANTIME="10m"; break ;;
        2) BANTIME="1h";  break ;;
        3) BANTIME="24h"; break ;;
        4) BANTIME="1w";  break ;;
        5)
            read -rp "自定义封禁时长（小时）: " BH
            case "$BH" in
                ''|*[!0-9]*) warn "请输入一个正数。" ;;
                *)
                    if [ "$BH" -ge 1 ]; then BANTIME="${BH}h"; break; fi
                    warn "请输入一个正数。"
                    ;;
            esac
            ;;
        *) warn "请选择 1-5。" ;;
    esac
done
RECIDIVE=$(ask_yn "是否启用惯犯监狱（屡犯者封 1 周）？" "Y")
echo ""

# ================= 3. 时区 =================
read -rp "设置时区（默认 Asia/Shanghai，直接回车跳过）: " TZ_IN
TZ_IN=${TZ_IN:-Asia/Shanghai}
if [ ! -f "/usr/share/zoneinfo/$TZ_IN" ]; then
    warn "时区 $TZ_IN 不存在，将跳过时区设置（如需请先安装 tzdata）。"
    SET_TZ="no"
else
    SET_TZ="yes"
fi
echo ""

# ================= 4. 可选加固项 =================
if [ "$PKG" = "apt" ]; then
    AUTO_UPGRADE=$(ask_yn "启用自动安全更新（unattended-upgrades）？" "Y")
    USE_UFW=$(ask_yn "启用 UFW 防火墙（默认拒绝入站，只放行 SSH）？" "N")
    if [ "$USE_UFW" = "yes" ]; then
        read -rp "除 SSH 外还要放行的端口（逗号分隔，如 80,443，直接回车则只放行 SSH）: " EXTRA_PORTS
    fi
else
    info "Alpine 跳过自动更新与 UFW（可用 apk 手动管理）。"
    AUTO_UPGRADE="no"; USE_UFW="no"; EXTRA_PORTS=""
fi
USE_SYSCTL=$(ask_yn "应用 sysctl 内核加固（防欺骗/SYN洪水/重定向攻击）？" "Y")
echo ""

# ================= 5. SSH 公钥 =================
info "注意：最后会禁用密码登录，你必须提供一个 SSH 公钥。"
info "三种提供方式：服务器上的 .pub 文件路径、直接粘贴公钥内容、"
info "或一个 URL（例如 https://github.com/你的用户名.keys）。"
PUBKEY=""
while [ -z "$PUBKEY" ]; do
    read -rp "公钥（文件路径 / 粘贴 / URL）: " KEY_INPUT
    [ -z "$KEY_INPUT" ] && { warn "输入为空。"; continue; }
    CANDIDATE=""
    case "$KEY_INPUT" in
        http://*|https://*)
            info "正在从 URL 获取公钥..."
            CANDIDATE=$(curl -fsSL --max-time 15 "$KEY_INPUT" 2>/dev/null | head -5)
            if [ -z "$CANDIDATE" ]; then warn "从 URL 获取失败。"; continue; fi
            ;;
        ssh-rsa*|ssh-ed25519*|ecdsa-sha2-nistp*)
            CANDIDATE="$KEY_INPUT"
            ;;
        *)
            if [ -f "$KEY_INPUT" ]; then
                CANDIDATE=$(cat "$KEY_INPUT")
            else
                warn "既不是文件、URL，也不是公钥，请重试。"
                continue
            fi
            ;;
    esac
    while IFS= read -r line; do
        case "$line" in
            ssh-rsa*|ssh-ed25519*|ecdsa-sha2-nistp*|sk-ssh-ed25519*|sk-ecdsa-sha2-nistp*)
                PUBKEY="$line"; break ;;
        esac
    done <<EOF_CANDIDATE
$CANDIDATE
EOF_CANDIDATE
    [ -z "$PUBKEY" ] && warn "输入中没有找到有效的 SSH 公钥。"
done
ok "公钥已接受。"
read -rp "把公钥装给哪个用户？（默认 root）: " KEY_USER
KEY_USER=${KEY_USER:-root}
id "$KEY_USER" >/dev/null 2>&1 || fail "用户 $KEY_USER 不存在。"
USER_HOME=$(eval echo "~$KEY_USER")
echo ""

# ================= 6. 可选：新建 sudo 用户 =================
NEW_USER=""
DISABLE_ROOT_SSH="no"
if [ "$(ask_yn "是否新建一个 sudo 管理用户（可选）？" "N")" = "yes" ]; then
    while true; do
        read -rp "新用户名（小写字母开头）: " NEW_USER
        case "$NEW_USER" in
            [a-z]*)
                if id "$NEW_USER" >/dev/null 2>&1; then
                    warn "用户已存在，换一个。"
                    continue
                fi
                break
                ;;
            *) warn "用户名不合法。" ;;
        esac
    done
    read -rp "把公钥同时装给 $NEW_USER 吗？[Y/n]: " KEY_FOR_NEW
    KEY_FOR_NEW=${KEY_FOR_NEW:-Y}
    DISABLE_ROOT_SSH=$(ask_yn "是否禁止 root 直接 SSH 登录（只能用 $NEW_USER 登录）？" "N")
fi
echo ""

# ================= 确认 =================
info "================ 配置确认 ================"
info "SSH 端口：       $SSH_PORT"
info "fail2ban：       ${FINDTIME}分钟内失败 $MAXRETRY 次 -> 封 $BANTIME"
info "惯犯监狱：       $RECIDIVE"
[ "$SET_TZ" = "yes" ] && info "时区：           $TZ_IN"
[ "$PKG" = "apt" ] && info "自动安全更新：   $AUTO_UPGRADE"
[ "$PKG" = "apt" ] && info "UFW 防火墙：      $USE_UFW"
info "sysctl 加固：     $USE_SYSCTL"
info "公钥用户：       $KEY_USER"
[ -n "$NEW_USER" ] && info "新建 sudo 用户：  $NEW_USER"
[ "$DISABLE_ROOT_SSH" = "yes" ] && info "禁止 root 登录： 是"
info "密码登录：       密钥验证通过后禁用"
info "=========================================="
if [ "$(ask_yn "确认执行？" "Y")" = "no" ]; then
    info "已取消，未做任何更改。"
    exit 0
fi
echo ""

# ================= 执行 =================
# ---- 1/8 系统更新 ----
info "[1/8] 正在更新系统..."
if [ "$PKG" = "apt" ]; then
    # Debian 9/10 已停止维护,主镜像站不再提供,自动切换到 archive.debian.org
    if [ "$OS_ID" = "debian" ]; then
        case "${VERSION_ID%%.*}" in
            9|10)
                if grep -qE "mirrors|deb.debian.org|security.debian.org" /etc/apt/sources.list 2>/dev/null; then
                    warn "检测到 Debian $VERSION_ID 已停止维护,切换 apt 源到 archive.debian.org ..."
                    cp /etc/apt/sources.list "/etc/apt/sources.list.bak-$(date +%F_%T)"
                    codename=$(grep -m1 "^deb " /etc/apt/sources.list | awk "{print \$3}")
                    [ -z "$codename" ] && codename="buster"
                    printf "deb http://archive.debian.org/debian/ %s main contrib non-free\n" "$codename" > /etc/apt/sources.list
                    printf "deb http://archive.debian.org/debian-security/ %s/updates main contrib non-free\n" "$codename" >> /etc/apt/sources.list
                    # archive 的 Release 文件已过期,关闭有效期检查
                    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99-no-check-valid-until
                    warn "建议重装为 Debian 12,旧版本不再有安全更新。"
                fi
                ;;
        esac
    fi
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq >/dev/null 2>&1
else
    apk update >/dev/null 2>&1
    apk upgrade >/dev/null 2>&1
fi
ok "系统更新完成。"

# ---- 2/8 时区 ----
if [ "$SET_TZ" = "yes" ]; then
    info "[2/8] 设置时区为 $TZ_IN ..."
    if [ "$INIT" = "systemd" ]; then
        timedatectl set-timezone "$TZ_IN" 2>/dev/null
    else
        pkg_install tzdata
        ln -sf "/usr/share/zoneinfo/$TZ_IN" /etc/localtime
        echo "$TZ_IN" > /etc/timezone
    fi
    ok "当前时间：$(date)"
fi

# ---- 3/8 安装基础软件 ----
info "[3/8] 正在安装 fail2ban、rsyslog 等..."
if [ "$PKG" = "apk" ]; then
    pkg_install openssh fail2ban rsyslog sudo curl
    ssh-keygen -A >/dev/null 2>&1
    svc_enable sshd
    svc_enable rsyslog
    svc_enable fail2ban
else
    pkg_install fail2ban rsyslog sudo curl
    if [ "$USE_UFW" = "yes" ]; then pkg_install ufw; fi
    if [ "$AUTO_UPGRADE" = "yes" ]; then pkg_install unattended-upgrades; fi
fi
if ! grep -qr "auth.log" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
    echo "auth,authpriv.*    /var/log/auth.log" > /etc/rsyslog.d/10-auth.conf
fi
[ -f /var/log/auth.log ] || touch /var/log/auth.log
svc_enable fail2ban
ok "基础软件安装完成。"

# ---- 4/8 fail2ban 配置 ----
info "[4/8] 正在配置 fail2ban ..."
if [ -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak-$(date +%F_%T)"
fi
cat > /etc/fail2ban/jail.local <<EOF_JAIL
# Generated by vps-ssh-hardening.sh on $(date +%F_%T)
[DEFAULT]
ignoreip = 127.0.0.1/8

[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
maxretry = $MAXRETRY
findtime = ${FINDTIME}m
bantime  = $BANTIME
EOF_JAIL
if [ "$RECIDIVE" = "yes" ]; then
cat >> /etc/fail2ban/jail.local <<'EOF_RECIDIVE'

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
maxretry = 3
findtime = 1d
bantime  = 1w
EOF_RECIDIVE
fi

# ---- 5/8 sysctl 加固 ----
if [ "$USE_SYSCTL" = "yes" ]; then
info "[5/8] 正在应用 sysctl 内核加固..."
cat > /etc/sysctl.d/99-vps-hardening.conf <<'EOF_SYSCTL'
# Generated by vps-ssh-hardening.sh
# 防 IP 欺骗 / SYN 洪水 / ICMP 重定向攻击
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 2
EOF_SYSCTL
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-vps-hardening.conf >/dev/null 2>&1
ok "sysctl 加固已应用。"
fi

# ---- 6/8 自动更新 + 防火墙 (Debian/Ubuntu) ----
if [ "$AUTO_UPGRADE" = "yes" ]; then
info "[6/8] 正在启用自动安全更新..."
svc_enable apt-daily-upgrade.timer
svc_enable apt-daily.timer
ok "自动安全更新已启用。"
fi
if [ "$USE_UFW" = "yes" ]; then
info "[6/8] 正在配置 UFW 防火墙..."
ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1
if [ -n "$EXTRA_PORTS" ]; then
for p in $(echo "$EXTRA_PORTS" | tr ',' ' '); do
ufw allow "${p}/tcp" >/dev/null 2>&1
done
fi
ufw --force enable >/dev/null 2>&1
ok "UFW 已启用。"
fi

# ---- 7/8 SSH: 端口 + 公钥 (密码登录暂保留) ----
info "[7/8] 正在设置 SSH 端口并安装公钥..."
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak-$(date +%F_%T)"
if grep -qE "^#?Port" /etc/ssh/sshd_config; then
sed -i -E "s/^#?Port.*/Port $SSH_PORT/" /etc/ssh/sshd_config
else
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
fi
install_key() {
local u="$1" home
home=$(eval echo "~$u")
mkdir -p "$home/.ssh"
chmod 700 "$home/.ssh"
touch "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
if ! grep -qxF "$PUBKEY" "$home/.ssh/authorized_keys" 2>/dev/null; then
echo "$PUBKEY" >> "$home/.ssh/authorized_keys"
fi
chown -R "$u:$u" "$home/.ssh"
}
install_key "$KEY_USER"
if [ -n "$NEW_USER" ]; then
info "正在创建 sudo 用户 $NEW_USER..."
if [ "$PKG" = "apt" ]; then
adduser --disabled-password --gecos "" "$NEW_USER" >/dev/null 2>&1
usermod -aG sudo "$NEW_USER"
else
adduser -D "$NEW_USER" >/dev/null 2>&1
addgroup "$NEW_USER" wheel >/dev/null 2>&1
if ! grep -q "^%wheel" /etc/sudoers 2>/dev/null; then
echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
fi
fi
case "$KEY_FOR_NEW" in
[Yy]) install_key "$NEW_USER";;
esac
ok "用户 $NEW_USER 已创建。"
fi

sshd -t || fail "sshd 配置检查失败，不重启。原配置已备份为 /etc/ssh/sshd_config.bak-*"
svc_restart "$SSH_SVC"
svc_restart fail2ban 2>/dev/null
sleep 2
if [ "$INIT" = "systemd" ]; then
if fail2ban-client status >/dev/null 2>&1; then
ok "fail2ban 运行中。"
else
fail "fail2ban 启动失败，请运行 journalctl -u fail2ban 查看。"
fi
else
if svc_active fail2ban; then
ok "fail2ban 运行中。"
else
warn "请手动检查 fail2ban 状态：rc-service fail2ban status"
fi
fi

# ---- 8/8 验证密钥后禁用密码 ----
echo ""
warn ">>> 请打开一个，用密钥登录测试：ssh -p $SSH_PORT $KEY_USER@<服务器IP>"
warn ">>> 在密钥登录确认成功之前，不要关闭这个窗口！"
echo ""
if [ "$(ask_yn "新终端里密钥能登录成功吗？" "Y")" = "no" ]; then
fail "密钥登录失败，密码登录保持开启。请修好密钥后重新运行此脚本。"
fi

info "正在禁用密码登录..."
for opt in PasswordAuthentication ChallengeResponseAuthentication KbdInteractiveAuthentication; do
if grep -qE "^#?$opt" /etc/ssh/sshd_config; then
sed -i -E "s/^#?$opt.*/$opt no/" /etc/ssh/sshd_config
else
echo "$opt no" >> /etc/ssh/sshd_config
fi
done
if grep -qE "^#?PubkeyAuthentication" /etc/ssh/sshd_config; then
sed -i -E "s/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
else
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
fi
if [ "$DISABLE_ROOT_SSH" = "yes" ]; then
if grep -qE "^#?PermitRootLogin" /etc/ssh/sshd_config; then
sed -i -E "s/^#?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
else
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi
info "已禁止 root 直接 SSH 登录。"
fi
sshd -t || fail "sshd 配置检查失败，不重启。"
svc_restart "$SSH_SVC"
ok "密码登录已禁用，现在只能用密钥登录。"

# ================= 完成报告 =================
echo ""
info "================ 完成 ================"
info "SSH 端口：$SSH_PORT（密钥登录）"
[ -n "$NEW_USER" ] && info "管理用户：$NEW_USER（sudo）"
info "fail2ban：${FINDTIME}分钟内失败 $MAXRETRY 次 -> 封 $BANTIME"
[ "$RECIDIVE" = "yes" ] && info "惯犯监狱：已启用（屡犯封 1 周）"
[ "$USE_SYSCTL" = "yes" ] && info "sysctl 内核加固：已应用"
[ "$USE_UFW" = "yes" ] && info "UFW 防火墙：已启用"
[ "$AUTO_UPGRADE" = "yes" ] && info "自动安全更新：已启用"
info "======================================="
echo ""
warn "提醒：去云厂商安全组放行 $SSH_PORT 端口，否则连不上！"
warn "如果私钥丢了，用云厂商的网页控制台（VNC）进去恢复。"
