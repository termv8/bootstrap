#!/bin/bash
#
# vps-ssh-hardening.sh — new-VPS first-boot SSH hardening (Debian/Ubuntu)
#
# Rewritten from FunctionClub/Fail2ban. What changed:
#  - modern fail2ban jails: [sshd] + [recidive] (old script used the
#    obsolete [ssh-iptables] name and hardcoded port=ssh, so a custom
#    SSH port was never actually protected)
#  - ban action targets the real SSH port you choose
#  - installs rsyslog when needed (Debian 12 has no /var/log/auth.log
#    without it, and fail2ban refuses to start)
#  - 'filter = recidive' is set explicitly (stock jail.conf omits it,
#    the jail silently fails without it)
#  - interactive: SSH port, maxretry, findtime, bantime, recidive on/off
#  - disables password login ONLY after you prove the key works in a
#    separate session (two-phase, no lockout risk)
#
# Usage: upload your .pub key to the server first, then as root:
#        bash vps-ssh-hardening.sh
#

# ---------- colors ----------
CFAILURE="\033[31m"; CWARNING="\033[33m"; CMSG="\033[36m"; COK="\033[32m"; CEND="\033[0m"
info() { echo -e "${CMSG}$*${CEND}"; }
ok()   { echo -e "${COK}$*${CEND}"; }
warn() { echo -e "${CWARNING}$*${CEND}"; }
fail() { echo -e "${CFAILURE}$*${CEND}"; exit 1; }

# ---------- must be root ----------
[ "$(id -u)" = "0" ] || fail "Error: You must be root to run this script."

# ---------- OS check (Debian/Ubuntu) ----------
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    fail "Cannot detect OS."
fi
case "$ID" in
    debian|ubuntu) ;;
    *) fail "This script supports Debian/Ubuntu only (detected: $ID)." ;;
esac
info "Detected OS: $PRETTY_NAME"
echo ""

# ---------- 1. SSH port ----------
cur_port=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
[ -z "$cur_port" ] && cur_port=22
while :; do
    read -rp "SSH port (current: $cur_port, Enter to keep): " SSH_PORT
    [ -z "$SSH_PORT" ] && SSH_PORT=$cur_port
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
        break
    fi
    warn "Invalid port. Enter a number between 1 and 65535."
done
if [ "$SSH_PORT" = "22" ]; then
    warn "Port 22 is the most scanned port on the internet. A custom port is strongly recommended."
fi
echo ""

# ---------- 2. fail2ban parameters ----------
while :; do
    read -rp "Max failed logins before ban [2-10] (default 5): " MAXRETRY
    [ -z "$MAXRETRY" ] && MAXRETRY=5
    if [[ "$MAXRETRY" =~ ^[0-9]+$ ]] && [ "$MAXRETRY" -ge 2 ] && [ "$MAXRETRY" -le 10 ]; then break; fi
    warn "Enter a number between 2 and 10."
done
while :; do
    read -rp "Time window in minutes for counting failures (default 10): " FINDTIME
    [ -z "$FINDTIME" ] && FINDTIME=10
    if [[ "$FINDTIME" =~ ^[0-9]+$ ]] && [ "$FINDTIME" -ge 1 ]; then break; fi
    warn "Enter a positive number."
done
info "Ban duration:"
info "  1) 10 minutes"
info "  2) 1 hour"
info "  3) 24 hours"
info "  4) 1 week"
info "  5) Custom (hours)"
while :; do
    read -rp "Choose [1-5] (default 2): " BC
    [ -z "$BC" ] && BC=2
    case "$BC" in
        1) BANTIME="10m"; break ;;
        2) BANTIME="1h";  break ;;
        3) BANTIME="24h"; break ;;
        4) BANTIME="1w";  break ;;
        5) read -rp "Custom ban time in hours: " BH
           if [[ "$BH" =~ ^[0-9]+$ ]] && [ "$BH" -ge 1 ]; then BANTIME="${BH}h"; break; fi
           warn "Enter a positive number." ;;
        *) warn "Choose 1-5." ;;
    esac
done
while :; do
    read -rp "Enable recidive jail (1-week ban for repeat offenders)? [Y/n]: " RC
    RC=${RC:-Y}
    if [[ "$RC" =~ ^[Yy]$ ]]; then RECIDIVE="yes"; break
    elif [[ "$RC" =~ ^[Nn]$ ]]; then RECIDIVE="no"; break
    else warn "Please answer y or n."; fi
done
echo ""

# ---------- 3. SSH public key ----------
info "Password login will be DISABLED at the end. You must provide an SSH public key."
info "Upload your .pub file to this server first, e.g.: scp ~/.ssh/id_ed25519.pub root@server:/root/"
KEY_PATH=""
while :; do
    read -rp "Path to your public key file on this server: " KEY_PATH
    [ -f "$KEY_PATH" ] || { warn "File not found: $KEY_PATH"; continue; }
    KEY_TYPE=$(awk '{print $1}' "$KEY_PATH")
    case "$KEY_TYPE" in
        ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)
            break ;;
        *) warn "Not a valid SSH public key (starts with: $KEY_TYPE)." ;;
    esac
done
read -rp "Install the key for which user? (default: root): " KEY_USER
KEY_USER=${KEY_USER:-root}
id "$KEY_USER" >/dev/null 2>&1 || fail "User $KEY_USER does not exist."
USER_HOME=$(eval echo "~$KEY_USER")
echo ""

# ---------- summary & confirm ----------
info "================ Summary ================"
info "SSH port:        $SSH_PORT"
info "fail2ban:        $MAXRETRY failures / ${FINDTIME}min  ->  ban $BANTIME"
info "recidive jail:   $RECIDIVE"
info "Key for user:    $KEY_USER  ($USER_HOME/.ssh/authorized_keys)"
info "Password login:  DISABLED after key is verified"
info "========================================="
while :; do
    read -rp "Proceed? [y/n]: " GO
    if [[ "$GO" =~ ^[Yy]$ ]]; then break
    elif [[ "$GO" =~ ^[Nn]$ ]]; then info "Aborted, nothing changed."; exit 0
    else warn "Please answer y or n."; fi
done
echo ""

# ---------- 4. install fail2ban (+ rsyslog for /var/log/auth.log) ----------
info "[1/6] Installing fail2ban..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban rsyslog \
    || fail "apt install failed."
# fail2ban's sshd jail needs /var/log/auth.log; Debian 12 only has it with rsyslog
[ -f /var/log/auth.log ] || touch /var/log/auth.log
systemctl enable fail2ban >/dev/null 2>&1

# ---------- 5. write jail.local ----------
info "[2/6] Writing /etc/fail2ban/jail.local ..."
[ -f /etc/fail2ban/jail.local ] && cp /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak-$(date +%F_%T)"
cat > /etc/fail2ban/jail.local <<EOF
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
EOF
if [ "$RECIDIVE" = "yes" ]; then
cat >> /etc/fail2ban/jail.local <<'EOF'

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
maxretry = 3
findtime = 1d
bantime  = 1w
EOF
fi

# ---------- 6. set SSH port + install key (password auth STAYS ON for now) ----------
info "[3/6] Setting SSH port to $SSH_PORT and installing your public key ..."
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak-$(date +%F_%T)"
if grep -qE "^#?Port" /etc/ssh/sshd_config; then
    sed -i -E "s/^#?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
else
    echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
fi
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
touch "$USER_HOME/.ssh/authorized_keys"
chmod 600 "$USER_HOME/.ssh/authorized_keys"
PUBKEY=$(cat "$KEY_PATH")
grep -qxF "$PUBKEY" "$USER_HOME/.ssh/authorized_keys" 2>/dev/null \
    || echo "$PUBKEY" >> "$USER_HOME/.ssh/authorized_keys"
chown -R "$KEY_USER:$KEY_USER" "$USER_HOME/.ssh"

sshd -t || fail "sshd config test FAILED. Not restarting. Original saved as /etc/ssh/sshd_config.bak-*"
systemctl restart sshd
systemctl restart fail2ban
sleep 2
fail2ban-client status >/dev/null 2>&1 \
    || fail "fail2ban failed to start. Run 'journalctl -u fail2ban' for details."
ok "fail2ban running, jails:$(fail2ban-client status | grep 'Jail list' | cut -d: -f2)"

# ---------- 7. verify key login BEFORE disabling passwords ----------
echo ""
warn ">>> STEP 7: open a NEW terminal and SSH with your key:  ssh -p $SSH_PORT $KEY_USER@<server-ip>"
warn ">>> Do NOT close THIS session until the key login is confirmed."
echo ""
while :; do
    read -rp "Can you log in with the SSH key in the new session? [y/n]: " KEY_OK
    if [[ "$KEY_OK" =~ ^[Yy]$ ]]; then break
    elif [[ "$KEY_OK" =~ ^[Nn]$ ]]; then
        fail "Key login did NOT work. Password auth left ENABLED. Fix the key and re-run this script."
    else warn "Please answer y or n."; fi
done

# ---------- 8. disable password authentication ----------
info "[4/6] Disabling password authentication ..."
for opt in PasswordAuthentication ChallengeResponseAuthentication KbdInteractiveAuthentication; do
    if grep -qE "^#?$opt" /etc/ssh/sshd_config; then
        sed -i -E "s/^#?$opt .*/$opt no/" /etc/ssh/sshd_config
    else
        echo "$opt no" >> /etc/ssh/sshd_config
    fi
done
if grep -qE "^#?PubkeyAuthentication" /etc/ssh/sshd_config; then
    sed -i -E "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
else
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
fi
sshd -t || fail "sshd config test FAILED. Not restarting."
systemctl restart sshd
ok "Password login DISABLED. Key-only authentication is now enforced."

# ---------- 9. final report ----------
echo ""
info "================ Done ================"
info "Effective sshd settings:"
sshd -T 2>/dev/null | grep -iE "^(port|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication)"
echo ""
info "fail2ban:"
fail2ban-client status
info "======================================="
echo ""
warn "Reminder: open port $SSH_PORT in your cloud security group / firewall, or you will lock yourself out."
warn "If you ever lose the private key, regain access via your provider's web console (VNC)."
