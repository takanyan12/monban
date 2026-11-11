# micro-monban

**A small but strong gatekeeper built on a Raspberry Pi.**
Put one Raspberry Pi in front of a home or small-office server to **reinforce** — not replace — your router and firewall.

[日本語 README](README.md) · Version: v1.14.3 · License: [Apache-2.0](LICENSE)

> ⚠ **This is an experimental project.** It is developed by an individual, is not a certified product, and comes with no warranty.
> Read "[What it protects — and what it doesn't](#what-it-protects--and-what-it-doesnt)" before using it in production.

> ℹ The dashboard UI and log messages are in **Japanese**. This English documentation explains what each part does.

---

## What is it?

Your server is **not** connected to the internet or your home LAN directly. Instead it sits in a **closed segment with a single cable** behind the gatekeeper (a Raspberry Pi).
The only path from the outside to the server is the gatekeeper's reverse proxy (nginx), which inspects both what comes in and what goes out.

```
[Internet]
    │
[Router]  ← home LAN (e.g. 192.168.1.0/24)
    │
    ├── Gatekeeper (Raspberry Pi), outer side … only ports 80/443 exposed
    │        │  inbound: simple WAF, auto-blocking   outbound: DLP masking, PII bulk-exfiltration guard
    │        │
    │   Gatekeeper inner side 10.0.0.1 ── one cable, closed segment 10.0.0.0/24 ──
    │                                        │
    │                                Backend PC 10.0.0.2 (web app on 8080, etc.)
    │
    └── Admin PC (dashboard, SSH)
```

## Features

| Area | Features |
| --- | --- |
| Inbound | nftables (everything except 80/443 is dropped), SSH brute-force auto-blocking, simple WAF (scanners, path traversal, SQL injection), behavior scoring with automatic 10-minute blocks |
| Outbound | **DLP**: masks secrets in responses (API keys, tokens, DB errors, phone numbers, …). **PII bulk-exfiltration guard**: blocks responses that carry more than a few personal records, per response and per 10 minutes |
| Self-defense | Tamper detection of key files, detection of unexpected outbound connections / listening ports, emergency breaker (cut external access / isolate backend with one click) |
| Operations | HTTPS dashboard, email alerts, **handover report** (full status in one document, emailed weekly / on change), **internet publishing wizard** (Let's Encrypt / Cloudflare Tunnel) |
| On-device screen | **Dashboard and settings for an HDMI touch monitor** (initial password change, Wi-Fi, switches, unblock, mail, self-test; auto-lock after 5 minutes) |

## What it protects — and what it doesn't

**It helps with**
- The architecture itself: the server is never exposed directly (closed segment, no forwarding, only 80/443 inbound)
- Common automated attacks (scanners, simple SQL injection and path traversal, SSH brute force)
- Some outbound leaks caused by application bugs (masking of keys/tokens/DB errors/phone numbers; stopping bulk PII responses)

**It does not / limitations**
- **Large DDoS attacks**: one Pi on a home connection cannot absorb them. Put Cloudflare or similar in front if needed.
- **The WAF is basic** — a handful of regular expressions, not a comprehensive commercial WAF.
- **Request bodies (POST payloads) are not inspected.**
- DLP and the PII guard are **heuristics**. Both false negatives and false positives happen (e.g. a list of names alone is not counted; a 12-digit ID may be mistaken for a Japanese My Number).
- **Single device.** If the Pi or SD card fails, the site goes down. Keep a spare and a recovery plan.
- **IPv4 only.**
- You are responsible for operations (OS updates, responding to alerts, keeping logs).

> 💡 Recommended: let Cloudflare handle the broad outer protection (DDoS, large WAF, certificates) and let micro-monban handle the fine-grained inner protection (app-specific inspection, PII guard, self-monitoring).

> 🇯🇵 Some features are tuned for Japan (Japanese phone numbers, My Number, prefecture-based address detection). Contributions for other locales are welcome.

## Requirements

- **Raspberry Pi 5** (development/test device; other models untested) and a microSD card (16 GB+)
- **Raspberry Pi OS (64-bit, Bookworm or later)**
- The built-in Ethernet port for the closed side (the outer side uses Wi-Fi or a USB Ethernet adapter)
- A backend PC (Windows or Linux) and one LAN cable
- To publish on the internet: your own domain name

## Installation (overview)

```bash
git clone https://github.com/takanyan12/monban.git micro-monban
cd micro-monban
nano install/setup-gatekeeper.sh        # edit the settings block at the top (HOME_NET, etc.)
sudo bash install/setup-gatekeeper.sh
sudo bash install/setup-gatekeeper.sh --verify
```

1. Install Raspberry Pi OS and enable SSH
2. Clone this repository on the Pi, edit the settings block, run the installer (**write down the dashboard password it prints**)
3. Configure the backend PC (on Windows, run `backend/setup-windows.bat` as Administrator)
4. Move the CA key `ca.key` off the Pi (USB stick, etc.) and delete it from the Pi

See the [Installation guide](docs/en/install.md) for details.

## Documentation

| Document | Contents |
| --- | --- |
| [Installation guide](docs/en/install.md) | From OS setup to self-test and certificates |
| [Backend PC setup](docs/en/backend.md) | Windows (PHP, Ollama, firewall) / Linux |
| [Operation guide](docs/en/operation.md) | What each dashboard card means |
| [Publishing to the internet](docs/en/publish.md) | Let's Encrypt and Cloudflare Tunnel |
| [On-device screen (HDMI monitor)](docs/en/kiosk.md) | View status and change settings on the device |
| [Troubleshooting](docs/en/troubleshooting.md) | Common symptoms and fixes |
| [Changelog](CHANGELOG.md) | Changes by version |

## Repository layout

```
install/   installer and uninstaller
src/       dashboard (dashboard.py), PII guard (pii_guard.py), on-device screen (kiosk.py, kiosk.html)
conf/      nginx / nftables / systemd templates, default DLP rules
backend/   backend PC setup scripts (Windows / Linux)
tools/     health check, on-device screen setup, SD clone and backup, Let's Encrypt via MyDNS DNS, read-only mode, A/B recovery (experimental), SHA256SUMS generator
tests/     self-test (selftest.sh), DLP test page (fake values only)
docs/      documentation (Japanese / English)
```

## Security issues

Please do not open a public issue. Report privately as described in [SECURITY.md](SECURITY.md).

## Author and license

- Concept and design: **AiLab-Japan** (sole proprietorship, Japan)
- Developed with the assistance of AI tools.
- License: [Apache License 2.0](LICENSE) (see also [NOTICE](NOTICE))

Pull requests are welcome. This project is maintained by one person, so replies may take some time.
