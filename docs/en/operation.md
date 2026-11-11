# Operation guide (the dashboard)

Open the dashboard at `https://10.0.0.1:9000/` (closed side) or `https://localhost:9000/` through an SSH tunnel (see the [Installation guide](install.md#7-open-the-dashboard)).
The dashboard is in Japanese. The "？" button next to each card title opens built-in help (also Japanese). This page explains each card in English; the Japanese card titles are shown in parentheses.

## What to check daily / weekly

| Where | Normal | Watch for |
| --- | --- | --- |
| Emergency banner at the top (緊急アラート) | not shown | Read it; if it is a false positive, press "誤検知として解除" (dismiss as false positive) |
| Self-integrity monitor (セルフ整合性監視) | ✓ 正常 (OK) | "重大（改竄の疑い）" (critical, possible tampering): if you did not change anything, consider the emergency breaker |
| PII bulk guard (個人情報 一括持ち出しガード) | ON（超えたら遮断） | Real users appearing in the block history |
| Handover report (設定レポート) | arrives weekly by email | The "items to check" at the top |

## Cards

### External management access (外部側 管理アクセス)
A temporary switch that makes the dashboard (port 9000) reachable from the home LAN. Keep it **closed** normally and use an SSH tunnel. While open, it is protected by HTTPS and a password (user `admin`).
The switch state is saved and restored after reboots or firewall reloads.

### Allow list / dynamic block list (許可リスト／AI 動的遮断リスト)
- **Allow list**: IPs here are never auto-blocked. Adding your admin PC prevents locking yourself out during tests.
- **Dynamic block list**: IPs auto-blocked for suspicious behavior (score ≥ 80, 5 SSH failures in 5 minutes, slow scans over 1 hour). Released automatically after 10 minutes. You can also move them to the allow list or unblock them.
- So that blocks also work via Cloudflare Tunnel, blocked IPs are denied in nginx as well (synced every 15 seconds).

### DLP masking rules (DLP 機密マスキング ルール)
Rules that mask secrets in server responses. 15 rules by default (11 enabled).
- Email addresses, card numbers, My Number format, and internal IPs are OFF by default because they easily cause false positives that break pages.
- Paste text into the masking test box to see how it would be masked.
- New rules cannot contain a single quote `'`, `;`, or line breaks.

### Self-integrity monitor (セルフ整合性監視)
Every 5 minutes it checks fingerprints (sha256) of key files, unexpected outbound connections from the gatekeeper, and unexpected listening ports.
If you change settings by hand, rebuild the manifest: `sudo GK_REBUILD_MANIFEST=1 python3 /opt/gatekeeper/dashboard.py` (the installer does this automatically).

### Egress defense & emergency breaker (出口防御 & 緊急ブレーカー)
- **Egress defense**: alerts on bulk transfers (50 MB per response / 100 MB per 10 min), bursts of 5xx errors, and repeated PII responses on monitored paths. Default is "alert only".
- **Emergency breaker**: "外部入口を遮断" cuts all external access; "バックエンドと分離" isolates the backend PC; "復旧" restores.
- **Email alerts (管理者メール通知)**: set SMTP and recipient. For Gmail, use an app password, `smtp.gmail.com`, port `587`.

### PII bulk-exfiltration guard (個人情報 一括持ち出しガード)
Counts personal data in server responses (emails, phone numbers, card numbers, Japanese My Number, Japanese addresses) and **lets a few records through but blocks bulk responses** (HTTP 403).
- Defaults: **5 records per response**, **30 records per client per 10 minutes**
- "止めずに記録だけする" (record only) logs without blocking — useful right after installation
- Counting is heuristic: name-only lists are not counted; a 12-digit business ID may occasionally be mistaken for a My Number
- The guard runs between nginx and the backend. **If it stops, the whole site returns 502** (it restarts automatically)

### Handover report (設定レポート)
Puts the current state (version, services, network, integrity, each guard, rules, alerts, list of backups) into one document and emails it. It starts with "how to tell something is wrong and the first thing to do", so you can hand it to someone less familiar with the system.
- When: weekly (choose day and hour), on configuration changes, or "今すぐ送信" (send now)
- No passwords, keys, or mail credentials are included
- Even without email configured, reports are saved on the Pi in `/var/lib/gatekeeper/reports`; "ファイルに保存" downloads one

### Internet publishing (インターネット公開)
See [Publishing to the internet](publish.md).

### Behavior analysis / threat radar (AI 振る舞い分析)
Scores each client by request-interval regularity, error ratio, and path diversity. 80 points or more triggers an automatic block.

## Routine tasks

| How often | What |
| --- | --- |
| Weekly | Read the handover report |
| Monthly | `sudo apt update && sudo apt upgrade`, then `--verify` |
| Every 3 months | `sudo bash tools/gk_check.sh`; clean up old backups (`/opt/gatekeeper/backup_*`) |
| Every 2 years | The gatekeeper's own certificate expires after 825 days; regenerate it before then |
