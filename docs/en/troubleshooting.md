# Troubleshooting

Start with the health checks on the gatekeeper — they reveal most causes:
```bash
sudo bash install/setup-gatekeeper.sh --verify
sudo bash tools/gk_check.sh
```

## The site does not load

| Symptom | Common cause | Fix |
| --- | --- | --- |
| **504 Gateway Time-out** | The backend PC's firewall silently drops connections from the gatekeeper | Firewall section of [Backend PC setup](backend.md) (allow 10.0.0.1). On Windows, re-run the batch file |
| **502 Bad Gateway** | The web app is not running / listens on `localhost` only / the PII guard is down | Start the app on `10.0.0.2:8080`. `systemctl status gatekeeper-piiguard` |
| No response at all | nginx on the gatekeeper is down, or the breaker is active | `systemctl status nginx`; check the breaker status in the dashboard |
| Browser certificate warning | The gatekeeper's own certificate (LAN) | Install `ca.crt` on the device ([Installation guide](install.md#6-move-the-ca-key-off-the-device-important)) or use a public certificate |

Check directly from the gatekeeper:
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://10.0.0.2:8080/
```

## Real users get 403

| What they see | Cause | Fix |
| --- | --- | --- |
| `Blocked by Gatekeeper WAF: ...` | False positive in the simple WAF | Review it and adjust the rule in `/etc/nginx/snippets/gatekeeper_https_body.conf` if needed |
| "個人情報の一括送信を門番が止めました" (bulk personal data blocked) | PII guard | Check the history in the dashboard. If the business needs it, raise the limits or switch to "record only" |
| Nothing / cannot connect | Auto-block (10 min) | Unblock in the dashboard's dynamic block list. Put your own PC on the allow list |

## Cannot reach the dashboard

- An **SSH tunnel** always works: `ssh -L 9000:localhost:9000 <user>@<gatekeeper-ip>` → `https://localhost:9000/`
- Direct access from the home LAN requires the dashboard switch to be open (with `DASH_MODE="switch"`).
- Forgot the password: see [Forgotten passwords](#forgotten-passwords) below

## SSH does not connect / times out

- New SSH connections from the home LAN are rate-limited to **6 per minute** (brute-force protection). Wait a moment.
- **5 wrong passwords within 5 minutes** block that PC for **10 minutes**. Wait, or unblock it from the dashboard via the closed side (backend PC).
- Adding your PC to the allow list avoids this.

## Integrity monitor shows "warn" or "critical"

- **Unexpected listening port**: newly installed software opened a port. Stop it if unneeded (e.g. rpcbind on port 111).
- **Possible tampering**: a monitored file changed. If you changed it, rebuild the manifest (`sudo GK_REBUILD_MANIFEST=1 python3 /opt/gatekeeper/dashboard.py`). If not, cut external access with the emergency breaker and investigate.
- In read-only mode, a "critical" finding triggers an automatic reboot after 120 seconds.

## Emails do not arrive

- Check the result of the dashboard's "テスト送信" (send test).
- Gmail does not accept your normal password. Enable 2-step verification and create an **app password**.

## The installer stops with "files do not match" or "Windows line endings"

- **Windows line endings (CRLF)**: happens when a ZIP is extracted on Windows and then copied to the Pi. Send the ZIP itself and `unzip` it on the Pi, or `git clone` on the Pi.
- **Mismatch with SHA256SUMS.txt**: the file was damaged or modified on the way. Get a fresh copy from the official source. Only if you changed the file yourself, continue with `sudo GK_SKIP_SUMS=1 bash install/setup-gatekeeper.sh`.

## Forgotten passwords

There are three cases depending on what you forgot. Try them in order.

### 1. Only the admin password (web dashboard / on-device screen) — you can still SSH in

To look it up:
```bash
sudo cat /opt/gatekeeper/secret.conf
```
To create a new one (in the folder you installed from):
```bash
sudo bash install/setup-gatekeeper.sh --reset-password
```
- Generates a new **initial password** and shows it once. The old password stops working.
- All other settings, logs and certificates are kept.
- The on-device screen will again ask you to set your own password first.

### 2. Start the gatekeeper over from scratch

```bash
sudo bash install/uninstall.sh --purge     # remove settings, logs, certificates; reset the firewall
sudo bash install/setup-gatekeeper.sh      # reinstall (a new initial password is shown)
```
- Certificates are regenerated, so replace the `ca.crt` installed on your browsers/devices (if you kept `ca.key`, you can restore it and keep the old CA).
- The backend PC setup still works as long as you didn't change the settings block.

### 3. You also forgot the Pi login (SSH) password

**The reliable way is a full reset from the OS up.**
1. On a PC, use Raspberry Pi Imager to write Raspberry Pi OS (64-bit) to the SD card. In the pre-write settings, set the user name, password, Wi-Fi and SSH. **Write the new password down.**
2. Reinstall the gatekeeper following the [Installation guide](install.md).
3. Replace the certificate as in case 2.

> Restoring an SD backup (spare card or image) does **not** help: it contains the old passwords.

With a monitor and keyboard attached you can reset just the Pi password without rewriting the OS (advanced; steps vary by OS version):
1. Shut down, put the SD card in a PC, and append ` init=/bin/sh` (with a leading space) to the end of the line in `cmdline.txt` on the boot partition (bootfs).
2. Put the card back and boot. You get a shell without logging in. Type:
   ```
   mount -o remount,rw /
   passwd <user-name>
   sync
   ```
3. Shut down, remove `init=/bin/sh` from `cmdline.txt` on a PC, and boot normally.

> That this works also means **anyone who can take out the SD card can change the password**. Keep the gatekeeper in a locked place.
