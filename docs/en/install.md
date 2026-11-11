# Installation guide

How to install micro-monban on a fresh Raspberry Pi. It takes roughly 30–60 minutes, depending on your internet speed.

## 0. Plan the layout

| Device | Connection | Address (default) |
| --- | --- | --- |
| Gatekeeper (Raspberry Pi), outer side | Wi-Fi or USB Ethernet to your router | DHCP (a DHCP reservation on the router is recommended) |
| Gatekeeper, inner side (`eth0`) | One LAN cable directly to the backend PC | 10.0.0.1 |
| Backend PC | Wired to the gatekeeper only. **Turn Wi-Fi off** | 10.0.0.2 |
| Admin PC | On your home LAN | anything |

> If the backend PC's Wi-Fi is on, there is a path that bypasses the gatekeeper. Always turn it off.

## 1. Prepare the Raspberry Pi

1. Use Raspberry Pi Imager to write **Raspberry Pi OS (64-bit, Bookworm or later)**.
   - In the settings, set a user name and password, Wi-Fi (if the outer side uses Wi-Fi), and **enable SSH**.
2. Boot the Pi and confirm you can SSH in from the admin PC:
   ```bash
   ssh <user>@raspberrypi.local
   ```
3. A **DHCP reservation** for the Pi's outer interface on your router makes things easier later.

## 2. Get the repository onto the Pi

On the Pi:
```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/takanyan12/monban.git micro-monban
cd micro-monban
```

> If you extract a ZIP on Windows and copy it over, line endings may change and the scripts will not run. Prefer `git clone` on the Pi itself (the installer stops if it detects CRLF line endings).
> If you received a ZIP, send the ZIP itself to the Pi and run `unzip` there.

### Check the files (before editing the settings block)

```bash
sha256sum -c --quiet SHA256SUMS.txt && echo "all files match"
```

"all files match" means you have exactly what was released. If any file is listed as failing, it was damaged or modified on the way — get a fresh copy.
The installer runs the same check before it starts and stops on a mismatch (`install/setup-gatekeeper.sh` itself is skipped because you edit its settings block; only its line endings are checked).

## 3. Edit the settings block

```bash
nano install/setup-gatekeeper.sh
```
Only edit the "★ settings block ★" at the top.

| Variable | Default | Meaning |
| --- | --- | --- |
| `EXT_IF` | `auto` | Outer interface. If auto-detection fails, set e.g. `wlan0` or `eth1` (check with `ip -o link`) |
| `EXT_IP` | `auto` | Outer IP. `auto` keeps DHCP |
| `HOME_NET` | `192.168.1.0/24` | **Your home LAN. If your router uses 192.168.0.x, change this to `192.168.0.0/24`** |
| `INT_IF` / `INT_IP` | `eth0` / `10.0.0.1/24` | Inner (closed) side. Usually leave as is |
| `BACKEND_IP` / `BACKEND_PORT` | `10.0.0.2` / `8080` | Backend PC and its web app port |
| `DASH_PORT` | `9000` | Dashboard port |
| `DASH_MODE` | `switch` | `switch`: the dashboard can be temporarily opened to the home LAN with a switch / `port-forward-only`: never reachable from the home LAN (SSH tunnel only) |

Save with `Ctrl+O` → `Enter`, exit with `Ctrl+X`.

## 4. Run the installer

```bash
sudo bash install/setup-gatekeeper.sh
```

- It starts by updating the OS and installing packages (nginx, nftables, certbot, …).
- At the end, **the dashboard password is shown once.** Save it in a password manager.
  - To look it up later: `sudo cat /opt/gatekeeper/secret.conf`
- Re-running the installer upgrades in place, keeping your settings and password.

### Self-test

```bash
sudo bash install/setup-gatekeeper.sh --verify
```
`結果: 合格（FAIL 0 …）` ("Result: PASS") means success. If the backend PC is not set up yet, a △ warning about the backend is expected.

A more detailed, read-only health check:
```bash
sudo bash tools/gk_check.sh
```

## 5. Set up the backend PC

See [Backend PC setup](backend.md). On Windows, run `backend/setup-windows.bat` **as Administrator**.

## 6. Move the CA key off the device (important)

The gatekeeper creates its own small certificate authority (CA) and signs certificates with `ca.key`.
Anyone holding `ca.key` can forge certificates for the gatekeeper, so **move it off the device and delete it from the Pi** (this does not affect operation).

1. On the Pi, copy the key to your home directory temporarily:
   ```bash
   sudo install -m 600 -o "$(whoami)" /opt/gatekeeper/tls/ca.key ~/ca.key
   ```
2. On the admin PC, fetch the key and certificate:
   ```bash
   scp <user>@<gatekeeper-ip>:ca.key .
   scp <user>@<gatekeeper-ip>:/opt/gatekeeper/tls/ca.crt .
   ```
3. Move `ca.key` to offline storage such as a USB stick.
4. On the Pi, delete the temporary copy and the original:
   ```bash
   rm ~/ca.key && sudo rm /opt/gatekeeper/tls/ca.key
   ```
5. `sudo bash install/setup-gatekeeper.sh --verify` should now report that `ca.key` is not on the device.

### Removing browser warnings

Register `ca.crt` as a trusted root CA on the devices you use for administration.
- Windows: double-click `ca.crt` → "Install Certificate" → "Local Machine" → "Place all certificates in the following store" → "Trusted Root Certification Authorities"

For internet publishing, a proper certificate for your domain is used instead ([Publishing](publish.md)).

## 7. Open the dashboard

| From | How |
| --- | --- |
| Backend PC (closed side) | `https://10.0.0.1:9000/` (no login) |
| Admin PC (normally) | SSH tunnel: keep `ssh -L 9000:localhost:9000 <user>@<gatekeeper-ip>` running and open `https://localhost:9000/` |
| Admin PC (temporarily) | Only while the dashboard switch is "open": `https://<gatekeeper-ip>:9000/` (user `admin`) |

### Changing the dashboard password

With a monitor attached, you can also change it from the [on-device screen](kiosk.md) ("パスワード"). Over SSH:

```bash
sudo nano /opt/gatekeeper/secret.conf          # change the value after GK_ADMIN_PASS=
sudo chmod 600 /opt/gatekeeper/secret.conf
sudo systemctl restart gatekeeper-dashboard
```

## Uninstall

```bash
sudo bash install/uninstall.sh            # remove the features (keep settings and certificates)
sudo bash install/uninstall.sh --purge    # remove everything and reset the firewall
```

## Further hardening (optional, experimental)

- `tools/enable-readonly.sh`: read-only mode (writes go to RAM only; on detected tampering the device reboots back to its original state). Limited testing.
- `tools/setup-ab-recovery.sh`: A/B recovery image. **Theoretical design, untested.**
