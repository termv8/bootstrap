# vps-ssh-hardening

A first-boot SSH hardening script for new VPS (Debian / Ubuntu).

Sets up **fail2ban** with modern jails, moves SSH to a custom port, and switches login to **key-only** — with a safe two-phase flow that never locks you out.

## Features

- **Interactive setup** — SSH port, max retries, find-time window, ban duration (presets or custom), recidive jail on/off. Sensible defaults throughout, so you can just press Enter.
- **Modern fail2ban config** — uses the current `[sshd]` jail plus a `[recidive]` jail for repeat offenders, with the ban action bound to your *actual* SSH port (not the hardcoded `port=ssh` of older scripts).
- **Key-only login, safely** — the script installs your public key first but keeps password auth enabled until *you* confirm a key login works in a fresh session. Only then is password auth disabled.
- **Debian 12 ready** — installs `rsyslog` when missing so `/var/log/auth.log` exists (fail2ban refuses to start without it), and writes `filter = recidive` explicitly (the stock `jail.conf` omits it and the recidive jail silently fails).
- **Reversible** — `sshd_config` and `jail.local` are backed up with timestamps before every change, and `sshd -t` validates the config before each restart.

## Requirements

- Debian 11/12 or Ubuntu (systemd)
- Root access
- An SSH key pair on your local machine (e.g. `ssh-keygen -t ed25519`)

## Usage

1. Generate a key if you don't have one:

   ```bash
   ssh-keygen -t ed25519
   ```

2. Upload your **public** key to the server:

   ```bash
   scp ~/.ssh/id_ed25519.pub root@<server-ip>:/root/
   ```

3. Run the script as root:

   ```bash
   bash vps-ssh-hardening.sh
   ```

4. Answer the prompts. When the script asks, open a **new** terminal and verify the key login (`ssh -p <port> root@<server-ip>`) before confirming — the script will not disable password auth until you do.

5. Don't forget to open the new SSH port in your cloud provider's security group / firewall.

## What it changes

| Item | Change |
|---|---|
| `/etc/ssh/sshd_config` | `Port` set to your choice; after key verification: `PasswordAuthentication no`, `ChallengeResponseAuthentication no`, `KbdInteractiveAuthentication no`, `PubkeyAuthentication yes` |
| `/etc/fail2ban/jail.local` | `[sshd]` jail with your parameters (+ `[recidive]` if enabled) |
| `~/.ssh/authorized_keys` | Your public key appended for the chosen user (default `root`) |
| Packages | `fail2ban`, `rsyslog` installed via apt |

## Notes

- Keep your current SSH session open until the key login is confirmed — that's the whole point of the two-phase flow.
- If you ever lose the private key, regain access through your provider's web console (VNC) and re-add a key.
- Re-running the script is safe: backups are created each time and an already-installed key is not duplicated.

## Credits

Rewritten from [FunctionClub/Fail2ban](https://github.com/FunctionClub/Fail2ban), updated for current fail2ban and Debian 12.

## License

MIT — see [LICENSE](LICENSE).
