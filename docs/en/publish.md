# Publishing to the internet

Make the gatekeeper reachable from outside your home LAN. Use the "🌐 インターネット公開" (internet publishing) card in the dashboard.
Both methods require **your own domain name** (e.g. `www.example.com`).

| | A. Let's Encrypt | B. Cloudflare Tunnel |
| --- | --- | --- |
| For | People who can forward ports on their router | People who can't or don't want to |
| Router setup | Forward ports 80 and 443 to the gatekeeper | Not needed |
| Certificate | Let's Encrypt (obtained and renewed by the gatekeeper) | Provided by Cloudflare |
| Your home IP | Public | Hidden |
| DDoS resilience | Weak (your whole connection goes down) | Strong (absorbed by Cloudflare) |

## A. Let's Encrypt (you can forward ports)

1. **DNS**: create an **A record** for your domain pointing to your home's public IP (the card's "調べる" button looks it up via the external service api.ipify.org).
   - If your public IP changes, you also need dynamic DNS.
2. **Router**: forward **ports 80 and 443** to the gatekeeper's outer IP.
3. In the dashboard, enter the domain and a contact email, agree to the Let's Encrypt terms, and press **"① 事前確認（試験取得）"** (pre-check / test issuance).
   - It tries a real issuance against Let's Encrypt's staging environment (does not consume production rate limits).
   - On failure it explains the cause (DNS / port forwarding / domain points elsewhere / rate limit) — in Japanese.
4. If it succeeds, press **"② 本番取得して公開"** (issue for real and publish). This obtains the certificate and enables a dedicated server block for your domain.
5. Renewal is automatic (`certbot.timer`). The remaining days are shown in the dashboard and the handover report.

"公開をやめる" (stop publishing) disables the domain's server block. The certificate and its renewal remain.

> The dashboard (port 9000) and LAN access by IP keep using the gatekeeper's own certificate.

### A'. When port 80 is not reachable from outside (DNS validation with MyDNS)

Sometimes port 443 works but the pre-check keeps failing with "Timeout during connect" — the ISP blocks inbound port 80 even though the router forwards it.
If you use **MyDNS (mydns.jp)** for dynamic DNS, you can obtain the certificate with **DNS validation (DNS-01)** instead of port 80 (selectable in the dashboard since v1.14.0):

1. In card A, set the validation method to **"MyDNS の DNS（80番が外から届かないとき）"** (MyDNS DNS).
2. Enter your MyDNS **master ID and password**. They are stored in `/etc/letsencrypt/mydns.netrc` (root only) and reused for renewal; they are never shown or logged. Once saved, the card shows "保存済み" (saved) and you only re-enter them to change them.
3. Press "① 事前確認" then "② 本番取得して公開". Each takes 2–4 minutes while waiting for MyDNS to update.
4. Renewal uses the same method automatically. **"更新の予行演習"** (renewal dry run) tests it without touching the real certificate; the result is shown on the card.

- Port 80 forwarding is no longer needed (443 is enough).
- Command-line alternative: `sudo bash tools/le-mydns.sh <domain> <contact-email>` (`--reset-login` to re-enter credentials, `--revert` to stop publishing).
- The self-test (`tests/selftest.sh`) checks the remaining days, the renewal timer, the hook script and the credentials file permissions.

## B. Cloudflare Tunnel (you can't forward ports)

1. Create a free Cloudflare account and add your domain to Cloudflare (requires changing name servers).
2. In Cloudflare **Zero Trust → Networks → Tunnels → "Create a tunnel" → Cloudflared**, copy the **token** shown.
3. On the same screen, add a **Public Hostname**:
   - Hostname: the domain to publish
   - Service: **HTTPS** / **localhost:443**
   - Additional application settings → TLS → **"No TLS Verify" ON** (to accept the gatekeeper's own certificate)
4. In the dashboard, press "**cloudflared を導入**" (install cloudflared; from Cloudflare's official repository pkg.cloudflare.com; takes a few minutes).
5. Paste the token and press "**接続**" (connect).

"接続を外す" (disconnect) removes the tunnel service.

### How the gatekeeper behaves behind Cloudflare
- **Real client IP**: the `CF-Connecting-IP` header set by cloudflared is trusted only for requests coming from the gatekeeper itself (127.0.0.1). The same header sent from outside is ignored.
- **Auto-blocking**: firewall (nftables) IP blocks do not apply to tunneled traffic, so blocked IPs are also denied in nginx.
- **Integrity check**: cloudflared's persistent connections are not reported as unexpected outbound traffic.

## Either way

- After publishing, check access from outside (a phone on mobile data is the easiest).
- Never publish the dashboard (port 9000) to the internet.
