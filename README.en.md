# micro-monban

**Just plug it in between your LAN and your server. One Raspberry Pi takes your server's protection up a level.**

micro-monban ("monban" means *gatekeeper* in Japanese) watches the part that routers, firewalls and Cloudflare leave open: **the last step in front of your server, and the data going back out**.
From home servers to small-business and on-premises servers — a **low-cost gatekeeper with a dashboard and easy maintenance**.

[日本語 README](README.md) · Version: v1.14.3 · License: [Apache-2.0](LICENSE) (free, modify as you like)

> ℹ The dashboard UI and log messages are in **Japanese**. This English documentation explains what each part does.

---

## Highlights

| Feature | What it means |
| --- | --- |
| 🔌 **Just plug it in** | Place it between your LAN and the server and move one cable. Your server software stays almost as it is |
| 💰 **Low cost** | Free software on a Raspberry Pi kit — far cheaper than dedicated appliances or monthly services |
| 🛡️ **Guards the way in *and* out** | Blocks attacks on the way in, and stops passwords, keys and personal data from **leaking out** |
| 🖥️ **Dashboard included** | A browser dashboard and an on-device HDMI touch screen. Certificates via a step-by-step wizard |
| 🔧 **Easy maintenance** | It's just a Raspberry Pi. Swap in a spare SD card, replace the whole Pi, or reset and reinstall — done |
| 📖 **Anyone can run it** | One installer script, docs in Japanese and English, and a self-test of about 40 checks |

## Why a gatekeeper?

Routers, firewalls and Cloudflare are all important *outer doors*.
But something that **looks inside the traffic right in front of your server, and watches what goes back out**, is often missing. micro-monban fills that gap.

| What you want to protect | Router / FW | Cloudflare | **micro-monban** |
| --- | :---: | :---: | :---: |
| Close unused ports | ◎ | ○ | ◎ |
| Absorb large DDoS floods | – | ◎ | – |
| Stop SQL injection and path traversal | – | ○ | ◎ |
| Auto-block scanners and suspicious behavior | – | ○ | ◎ |
| **Mask passwords, keys and error details** leaking in responses | – | △ | ◎ |
| **Stop bulk exfiltration of personal data** | – | △ | ◎ |
| **Isolate the server** from your home / office LAN | △ | – | ◎ |
| **Watch its own configuration** for tampering | – | – | ◎ |
| Runs entirely on your premises (no monthly fee) | ◎ | △ | ◎ |

◎ strong ○ capable △ conditional / paid plans – not its role

**Best used together**: let your router or Cloudflare handle the wide outer defense, and micro-monban the fine-grained defense right in front of the server. Layering makes you much safer.

## Who it's for

- 🏠 **Home servers** you want to publish (blogs, websites, photo sharing)
- 🏢 **Small businesses and offices** that want solid protection for web servers and internal systems at a modest cost
- 🤖 **Local AI (e.g. Ollama)** and internal tools you don't want exposed directly to the internet or the LAN
- 🧪 Development and test servers you want to show to the outside safely

## How it works

The server sits in a **closed segment behind the gatekeeper, on a single Ethernet cable**. The only way in is through the gatekeeper's proxy, which inspects traffic in both directions.

```
[Internet]
     │
[Router]  ← home / office LAN
     │
     ├── micro-monban (Raspberry Pi 5)  … only ports 80/443 exposed
     │        │  inbound: WAF, auto-blocking   outbound: DLP masking, personal-data guard
     │        │
     │   closed segment on one cable (10.0.0.0/24)
     │        │
     │   your server (web app, AI, …)
     │
     └── admin PC (dashboard)
```

## Defenses at a glance

### 🚪 Inbound
- Firewall that only allows ports 80/443 (nftables)
- Lightweight WAF: turns away SQL injection, path traversal and scanner user agents
- Hidden-file probes (`.env`, `.git`, …) get a 404 before reaching the server
- SSH brute-force auto-blocking
- **Behavior analysis**: scores clients by error rate and request timing, and auto-blocks suspicious ones
- Slow, stealthy scans detected over a one-hour window

### 📤 Outbound
- **DLP**: masks API keys, tokens, passwords, database errors, phone numbers and more in responses (15 rules, editable in the dashboard)
- **Personal-data bulk-exfiltration guard**: counts emails, phone and card numbers, Japanese My Number IDs and addresses, and stops large leaks
- Detects large data dumps and error bursts

### 🔍 Self-defense
- Checks critical config files for tampering every 5 minutes
- Detects unexpected outbound connections and listening ports
- **Emergency breaker**: close the internet entrance or cut off the server with one click

### 🔐 Certificates and publishing
- Let's Encrypt certificates obtained and renewed automatically
- Works even when your ISP blocks port 80, via MyDNS DNS validation
- Cloudflare Tunnel supported

### 📨 Notifications
- Email alerts on incidents
- **Handover report**: the whole configuration in one document, emailed on a schedule

## Configure it on screen

- **Dashboard (browser)**: see protection status, blocked clients and alert history at a glance. Toggle switches, manage the allow list, set up email alerts and run the publishing wizard.
- **On-device screen (HDMI touch monitor)**: check status and change Wi-Fi and other settings without a PC. Auto-locks after 5 minutes and asks you to change the initial password.
- **Publishing wizard**: enter your domain, run the pre-check, then "issue and publish". Renewal is automatic, with a dry-run button.

## Easy maintenance

- **If something goes wrong**: swap in a spare SD card. If the Pi itself fails, move the card to a new Pi. A tool to make spare cards is included.
- **Reset and reinstall**: the uninstall script restores the system, then run the installer again. There is a procedure for forgotten dashboard passwords, too.
- **Day to day, just watch**: alerts arrive by email and certificates renew themselves. `--verify` and the self-test confirm the defenses are working at any time.

## What it protects — and what it doesn't

**It protects**
- The architecture itself: the server is never directly exposed (closed segment, no forwarding, only 80/443 inbound)
- Common automated attacks (scanners, SQL injection and path traversal, hidden-file probes, SSH brute force)
- Many outbound leaks caused by application bugs (masking keys, tokens, DB errors and phone numbers; stopping bulk personal-data responses)

**Limits**
- **Large DDoS attacks**: one Pi and your connection cannot absorb them. Put Cloudflare or similar in front if needed.
- **The WAF is lightweight** — not as comprehensive as a commercial WAF.
- **Request bodies (POST data) are not inspected.**
- DLP and the personal-data guard are **heuristic**; misses and false positives happen.
- **Single device**: keep a spare SD card or Pi for quick recovery.
- **IPv4 only.**
- OS updates and responding to alerts are up to you (the docs explain how).

## Requirements

- **Raspberry Pi 5** and a microSD card (16 GB or more)
- **Raspberry Pi OS (64-bit, Bookworm or later)**
- One wired LAN port (server side); Wi-Fi or a USB LAN adapter for the outer side
- A server PC (Windows or Linux) and one Ethernet cable
- To publish on the internet: a domain (a free dynamic DNS name works)

## Installation overview

```bash
git clone https://github.com/takanyan12/monban.git micro-monban
cd micro-monban
nano install/setup-gatekeeper.sh        # edit the settings block at the top (HOME_NET, etc.)
sudo bash install/setup-gatekeeper.sh
sudo bash install/setup-gatekeeper.sh --verify
sudo bash tests/selftest.sh
```

1. Install the OS on the Pi and enable SSH
2. Put this repository on the Pi, adjust the settings block and run the installer (**write down the dashboard password it prints**)
3. Configure the server PC (on Windows, run `backend/setup-windows.bat` as administrator)
4. Move the CA key `ca.key` to a USB stick and delete it from the Pi

See the [installation guide](docs/en/install.md) for details.

## Documentation

| Document | Contents |
| --- | --- |
| [Installation guide](docs/en/install.md) | From OS setup to installation, self-check and certificates |
| [Server PC setup](docs/en/backend.md) | Windows (PHP, Ollama, firewall) / Linux, sample page |
| [Operation guide](docs/en/operation.md) | What each dashboard card means and how to use it |
| [Publishing to the internet](docs/en/publish.md) | Let's Encrypt (port 80 / MyDNS DNS) and Cloudflare Tunnel |
| [On-device screen (HDMI monitor)](docs/en/kiosk.md) | View status and change settings on the device |
| [Troubleshooting](docs/en/troubleshooting.md) | Common symptoms, fixes and forgotten passwords |
| [Changelog](CHANGELOG.md) | Changes per version |

## Repository layout

```
install/   install and uninstall scripts
src/       dashboard (dashboard.py), personal-data guard (pii_guard.py), on-device screen (kiosk.py, kiosk.html)
conf/      templates for nginx, nftables and systemd, default DLP rules, certificate scripts
backend/   setup scripts for the server PC (Windows / Linux) and a sample page
tools/     health check, on-device screen setup, SD clone and backup, Let's Encrypt via MyDNS DNS, read-only mode, A/B recovery (experimental), SHA256SUMS generator
tests/     self-test (selftest.sh), DLP test page (fictitious values only)
docs/      documentation (Japanese and English)
```

## Reporting security issues

Please do not open a public issue. Report privately as described in [SECURITY.md](SECURITY.md) (Security tab → "Report a vulnerability").

## Author and license

- Concept and design: **AiLab-Japan** (sole proprietorship). Developed with the help of AI tools.
- License: [Apache License 2.0](LICENSE) (see also [NOTICE](NOTICE)). Free to use, modify and redistribute.
- Provided without warranty. Please read "[What it protects — and what it doesn't](#what-it-protects--and-what-it-doesnt)" before using it in production.

Feedback and improvements (issues and pull requests) are welcome. As this is run by an individual, replies may take some time.
