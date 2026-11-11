import http.server
import base64
import hmac
import json
import os
import re
import subprocess
import threading
import time
import math
import collections
import ipaddress
from datetime import datetime

# [v1.9.7] nft に渡すIPは必ず検証する（"{ ip }" への構文差し込み防止）。
#  nft の set は ipv4_addr 型なので IPv4 の単一アドレスのみ許可し、正規化した文字列を返す。
def valid_ipv4(ip):
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return None

# ================================================================
# [v1.12.0] 環境ごとの値は導入スクリプトが書く /opt/gatekeeper/config.json から読む
#  （以前はインストーラがこのファイルに直接埋め込んでいた）
# ================================================================
CONFIG_FILE = "/opt/gatekeeper/config.json"
CONFIG_DEFAULT = {
    "ext_if": "wlan0",              # 外側（家庭LAN・インターネット側）のインターフェース
    "home_net": "192.168.1.0/24",   # 家庭LANのネットワーク（SSH許可・管理スイッチ開放の範囲）
    "int_if": "eth0",               # 内側（閉域・サーバー役PC直結）のインターフェース
    "int_ip": "10.0.0.1",           # 門番の内側 IP
    "backend_ip": "10.0.0.2",       # 信頼できるのは「閉域直結のこの1台」だけ
    "backend_port": 8080,
    "dash_port": 9000,
    "dash_mode": "switch",          # "switch" / "port-forward-only"
    "kiosk_port": 9100,             # [v1.13.0] 本体画面のサーバー（127.0.0.1 のみ）
}

def _load_config():
    c = dict(CONFIG_DEFAULT)
    try:
        with open(CONFIG_FILE) as f:
            d = json.load(f)
        c.update({k: d[k] for k in CONFIG_DEFAULT if k in d})
    except Exception:
        pass
    return c

CFG = _load_config()
PORT = int(CFG["dash_port"])
LOG_FILE = "/var/log/nginx/gatekeeper_access.log"
WHITELIST_FILE = "/opt/gatekeeper/whitelist.json"
WINDOW_SIZE = 30
# [v1.14.3] 紹介ページ（backend/demo-site/index.php）の「試してみる」が送る要求。完全一致のものだけ点数に数えない
DEMO_URIS = {
    "/?id=1+union+select+password+from+users&gk-demo=1",
    "/?file=..%2f..%2fetc%2fpasswd&gk-demo=1",
    "/.env?gk-demo=1",
}

EXT_IF = CFG["ext_if"]
HOME_NET = CFG["home_net"]
INT_IP = CFG["int_ip"]
INT_PREFIX = INT_IP.rsplit(".", 1)[0] + "."
BACKEND_IP = CFG["backend_ip"]
BACKEND_PORT = int(CFG["backend_port"])
DASH_MODE = CFG["dash_mode"]

def render_page():
    """管理画面の HTML に環境ごとの値を差し込む（HTML_PAGE は下の方で定義）"""
    note = ("外部側からの管理画面直叩き: 常時遮断（SSHポートフォワード経由でのみ管理します）"
            if DASH_MODE == "port-forward-only" else
            "外部側からの管理画面直叩き: スイッチ開放時のみ許可（HTTPS＋Basic認証で防護）")
    return HTML_PAGE.replace("@@DASH_PORT@@", str(PORT)).replace("@@DASH_MODE_NOTE@@", note)

# ================================================================
# [v1.9] 出口防御（Egress Guard）: 大量持ち出し・個人情報ハーベスト・5xx連発を検知
#  ・検知 → ダッシュボード緊急バナー＋履歴保存＋（設定時）管理者メール通知
#  ・緊急ブレーカーは独立テーブル inet gatekeeper_breaker で実装。
#    メインの inet filter / dynamic_blocks は一切触らないため、復旧（テーブル削除）で
#    動的遮断リストやwhitelistを壊す恐れがない。iifname は文字列照合なので
#    IFが存在しなくてもルール插入が安全。
#  ・既定は「監視・通報のみ」（auto_block=False）。誤検知によるセルフDoSを防止する。
# ================================================================
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate

GUARD_FILE = "/opt/gatekeeper/guard.json"
MAIL_FILE = "/opt/gatekeeper/alertmail.json"
BREAKER_TABLE = "gatekeeper_breaker"
BREAKER_STATE = "/opt/gatekeeper/breaker.json"
ALERT_COOLDOWN = 600   # 同一理由キーの再通知は10分抑止（アラートストーム防止）
ALERT_TTL = 900        # バナーは15分で自動消灯（履歴には残る）

guard_cfg = {
    "auto_block": False,
    "harvest_threshold": 15,                # 業務操作なしの個人情報応答の連続上限
    "pii_burst_60s": 30,                    # 60秒内の個人情報応答上限（スクリプト的バースト）
    "max_body_bytes": 50 * 1024 * 1024,     # 単一レスポンス上限
    "bytes10m": 100 * 1024 * 1024,          # 10分累計上限
    "err5_rate": 30,                        # 1分あたりの5xx上限
    "pii_paths": ["/profile", "/mypage", "/api/user", "/api/customer", "/member"],
    "biz_paths": ["/submit", "/confirm", "/action", "/checkout"]
}
guard_lock = threading.Lock()
guard_track = collections.defaultdict(lambda: {
    "pii": collections.deque(maxlen=256),
    "post": collections.deque(maxlen=128),
    "streak": 0,
    "bytes10m": collections.deque(maxlen=4096),
    "e5": collections.deque(maxlen=256),
})
alert_history = collections.deque(maxlen=50)
active_alert = None
last_alert_at = {}

mail_cfg = {"enabled": False, "host": "", "port": 587, "user": "", "pass": "", "to": ""}
mail_state = {"last_result": "", "ts": 0}

def _load_json_file(path, default):
    try:
        with open(path) as f:
            d = json.load(f)
            if isinstance(d, dict):
                default.update(d)
    except Exception:
        pass
    return default

_load_json_file(GUARD_FILE, guard_cfg)
_load_json_file(MAIL_FILE, mail_cfg)

def save_guard():
    try:
        with open(GUARD_FILE, "w") as f:
            json.dump(guard_cfg, f, ensure_ascii=False)
    except Exception:
        pass

def save_mail():
    try:
        with open(MAIL_FILE, "w") as f:
            json.dump(mail_cfg, f, ensure_ascii=False)
        os.chmod(MAIL_FILE, 0o600)
    except Exception:
        pass

_wl_cache = {"ips": set(), "ts": 0.0}

def guard_whitelisted(ip):
    now = time.time()
    if now - _wl_cache["ts"] > 10:
        try:
            with open(WHITELIST_FILE) as f:
                _wl_cache["ips"] = set(json.load(f))
        except Exception:
            _wl_cache["ips"] = set()
        _wl_cache["ts"] = now
    return ip in _wl_cache["ips"]

def is_pii_path(path):
    return any(p and path.startswith(p) for p in guard_cfg.get("pii_paths", []))

def is_biz_action(method, path):
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    return any(p and p in path for p in guard_cfg.get("biz_paths", []))

def _smtp_send(subject, body):
    """同期送信（テストボタン用）。結果 (ok, err) を返す。587=STARTTLS / 465=SSL"""
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = mail_cfg.get("user") or "gatekeeper@localhost"
        msg["To"] = mail_cfg["to"]
        msg["Date"] = formatdate()
        port = int(mail_cfg.get("port") or 587)
        host = mail_cfg["host"]
        if port == 465:
            srv = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            srv = smtplib.SMTP(host, port, timeout=10)
        try:
            if port != 465:
                try:
                    srv.starttls()
                except smtplib.SMTPException:
                    pass
            if mail_cfg.get("user") and mail_cfg.get("pass"):
                srv.login(mail_cfg["user"], mail_cfg["pass"])
            srv.send_message(msg)
        finally:
            try:
                srv.quit()
            except Exception:
                pass
        return True, ""
    except Exception as e:
        return False, str(e)[:160]

def notify_admin(reason, ip, path):
    """検知を管理者へメール通知（別スレッドで非同期・監視ループをブロックしない）"""
    if not mail_cfg.get("enabled") or not mail_cfg.get("host") or not mail_cfg.get("to"):
        return
    subject = "[Gatekeeper緊急] 異常通信を検知しました"
    body = ("Gatekeeper が異常な通信を検知しました。\n\n"
            "検知時刻: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
            "検知理由: " + reason + "\n"
            "接続元IP: " + (ip or "-") + "\n"
            "対象パス: " + (path or "-") + "\n\n"
            "管理画面を確認し、状況に応じて緊急ブレーカーを発動してください。\n"
            "（誤検知の場合はアラートを解除すれば通知は静まります）")
    def _worker():
        ok, err = _smtp_send(subject, body)
        mail_state["last_result"] = ("送信OK " + datetime.now().strftime("%H:%M:%S")) if ok else ("送信失敗: " + err)
        print("[alert-mail] " + mail_state["last_result"], flush=True)
    threading.Thread(target=_worker, daemon=True).start()

def raise_alert(key, reason, ip="", path=""):
    global active_alert
    now = time.time()
    with guard_lock:
        dup = (now - last_alert_at.get(key, 0)) < ALERT_COOLDOWN
        last_alert_at[key] = now
        a = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "key": key,
             "reason": reason, "ip": ip, "path": path, "epoch": now}
        alert_history.appendleft(a)
        if not dup:
            active_alert = a
    if dup:
        return
    print("[guard] ALERT " + key + ": " + reason + " (" + ip + " " + path + ")", flush=True)
    if guard_cfg.get("auto_block") and ip:
        block_ip(ip)
        print("[guard] auto-blocked " + ip, flush=True)
    notify_admin(reason, ip, path)

def guard_check(rec, ip, method, path, status):
    if not path or ip in ("127.0.0.1", "::1") or ip == BACKEND_IP:
        return
    if guard_whitelisted(ip):
        return
    try:
        nb = int(rec.get("body_bytes") or 0)
    except (TypeError, ValueError):
        nb = 0
    now = time.time()
    t = guard_track[ip]
    while t["bytes10m"] and now - t["bytes10m"][0][0] > 600:
        t["bytes10m"].popleft()
    while t["e5"] and now - t["e5"][0] > 60:
        t["e5"].popleft()
    while t["pii"] and now - t["pii"][0] > 60:
        t["pii"].popleft()
    alert = None
    if nb >= guard_cfg["max_body_bytes"]:
        alert = ("mass_transfer", "単一レスポンスが " + str(round(nb / 1048576, 1)) + "MB: 大量ダンプの疑い")
    if alert is None:
        t["bytes10m"].append((now, nb))
        tot = sum(b for _, b in t["bytes10m"])
        if tot >= guard_cfg["bytes10m"]:
            alert = ("volume_spike", "10分間の転送量が " + str(round(tot / 1048576)) + "MB: 異常な大量転送")
    if status >= 500:
        t["e5"].append(now)
        if alert is None and len(t["e5"]) >= guard_cfg["err5_rate"]:
            alert = ("err5_burst", "1分間にHTTP 5xxが " + str(len(t["e5"])) + " 回: エクスプロイト試行の疑い")
    if is_biz_action(method, path):
        t["post"].append(now)
        t["streak"] = 0
    elif is_pii_path(path):
        t["pii"].append(now)
        t["streak"] += 1
        if alert is None and (t["streak"] >= guard_cfg["harvest_threshold"]
                              or (len(t["pii"]) >= guard_cfg["pii_burst_60s"] and not t["post"])):
            alert = ("pii_harvest",
                     "業務操作のない個人情報応答が連続（連続=" + str(t["streak"]) +
                     ", 60秒内=" + str(len(t["pii"])) + "件）: データ収集(harvest)の疑い")
            t["streak"] = 0
            t["pii"].clear()
            t["post"].clear()
    if alert:
        raise_alert(alert[0], alert[1], ip=ip, path=path)

# ---- 緊急ブレーカー（独立nftテーブル。メインのルールセットには触れない） ----
def breaker_active():
    out = subprocess.getoutput("sudo nft list tables 2>/dev/null")
    return ("inet " + BREAKER_TABLE) in out

def breaker_mode():
    try:
        with open(BREAKER_STATE) as f:
            return json.load(f).get("mode", "")
    except Exception:
        return ""

def _nft_apply(ruleset):
    try:
        with open("/tmp/gk_breaker.nft", "w") as f:
            f.write(ruleset)
        return subprocess.run(["sudo", "nft", "-f", "/tmp/gk_breaker.nft"], check=False).returncode == 0
    except Exception:
        return False

def breaker_cut(mode):
    # 既存ブレーカーテーブルがあれば先に削除（モード排他）。delete は無くても失敗しない。
    subprocess.run(["sudo", "nft", "delete", "table", "inet", BREAKER_TABLE], check=False)
    if mode == "cut_ext":
        # 外部入口の全遮断: 入力(EXT_IF)と転送(EXT_IF→)を落とす。
        # Pi自身の外向き(output)は生かすので、緊急メール送信・更新は継続できる。
        rules = ("table inet " + BREAKER_TABLE + " {\n"
                 "  chain input { type filter hook input priority -10; policy accept; iifname \"" + EXT_IF + "\" drop }\n"
                 "  chain forward { type filter hook forward priority -10; policy accept; iifname \"" + EXT_IF + "\" drop }\n"
                 "}")
    elif mode == "cut_link":
        # バックエンド1台だけを完全分離（BACKEND_IP 個別DROP）。
        # ip link down と違い、同一セグメントの管理画面や他機器には影響しない。
        rules = ("table inet " + BREAKER_TABLE + " {\n"
                 "  chain input { type filter hook input priority -10; policy accept; ip saddr " + BACKEND_IP + " drop }\n"
                 "  chain output { type filter hook output priority -10; policy accept; ip daddr " + BACKEND_IP + " drop }\n"
                 "  chain forward { type filter hook forward priority -10; policy accept; ip saddr " + BACKEND_IP + " drop; ip daddr " + BACKEND_IP + " drop }\n"
                 "}")
    else:
        return False
    ok = _nft_apply(rules)
    if ok:
        try:
            with open(BREAKER_STATE, "w") as f:
                json.dump({"mode": mode, "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f)
        except Exception:
            pass
    return ok

def breaker_restore():
    subprocess.run(["sudo", "nft", "delete", "table", "inet", BREAKER_TABLE], check=False)
    try:
        os.remove(BREAKER_STATE)
    except Exception:
        pass
    return True

def breaker_status():
    act = breaker_active()
    return {"active": act, "mode": breaker_mode() if act else ""}

def current_alert():
    aa = active_alert
    if aa and (time.time() - aa.get("epoch", 0)) < ALERT_TTL:
        return aa
    return None

def guard_summary():
    return {"auto_block": bool(guard_cfg.get("auto_block")),
            "harvest_threshold": guard_cfg.get("harvest_threshold"),
            "pii_burst_60s": guard_cfg.get("pii_burst_60s"),
            "max_body_mb": round(guard_cfg.get("max_body_bytes", 0) / 1048576),
            "bytes10m_mb": round(guard_cfg.get("bytes10m", 0) / 1048576),
            "err5_rate": guard_cfg.get("err5_rate"),
            "pii_paths": guard_cfg.get("pii_paths", [])}

# ================================================================
# [v1.10.0] 個人情報 一括持ち出しガード（pii_guard.py と連携）
#  ・pii_guard.py が応答本文の個人情報を数え、上限超えを止めて events.jsonl に記録
#  ・ダッシュボードは設定ファイルを書き（ON/OFF・件数）、記録を読んで表示・警報する
# ================================================================
PII_CFG_FILE = "/opt/gatekeeper/pii_guard.json"
PII_DIR = "/var/lib/gatekeeper/pii"
PII_EVENTS = PII_DIR + "/events.jsonl"
PII_STATS = PII_DIR + "/stats.json"
PII_SERVICE = "gatekeeper-piiguard"
PII_DEFAULT = {"enabled": True, "monitor_only": False,
               "max_per_response": 5, "window_limit": 30, "window_sec": 600}

def pii_guard_cfg():
    c = dict(PII_DEFAULT)
    try:
        with open(PII_CFG_FILE) as f:
            d = json.load(f)
        c.update({k: d[k] for k in PII_DEFAULT if k in d})
    except Exception:
        pass
    return c

def pii_guard_save(c):
    tmp = PII_CFG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, PII_CFG_FILE)

def pii_read_events(limit=20):
    out = []
    try:
        with open(PII_EVENTS) as f:
            lines = f.readlines()[-limit:]
        for ln in reversed(lines):
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
    except Exception:
        pass
    return out

def pii_guard_summary():
    st = {}
    try:
        with open(PII_STATS) as f:
            st = json.load(f)
    except Exception:
        pass
    return {"cfg": pii_guard_cfg(),
            "service": subprocess.call(["systemctl", "is-active", "--quiet", PII_SERVICE]) == 0,
            "stats": st,
            "events": pii_read_events(20)}

def pii_event_watcher():
    """pii_guard の新しい記録を見つけたら、緊急バナー・履歴・（設定時）メールで知らせる。"""
    last = 0.0
    for ev in pii_read_events(1):
        last = ev.get("epoch", 0)
    while True:
        try:
            for ev in reversed(pii_read_events(50)):
                ep = ev.get("epoch", 0)
                if ep <= last:
                    continue
                last = ep
                ip = ev.get("ip", "")
                if ip in ("127.0.0.1", "::1"):      # 門番自身からの試験は警報にしない
                    continue
                act = "遮断" if ev.get("action") == "block" else "記録のみ"
                raise_alert("pii_bulk:" + ip, "個人情報の一括持ち出し（" + act + "）: " + ev.get("reason", ""),
                            ip=ip, path=ev.get("path", ""))
        except Exception:
            pass
        time.sleep(2)

# ================================================================
# [v1.11.0] 設定レポート（引き継ぎ用）
#  ・門番の今の状態を1つの文書にまとめ、メール（本文=要約／添付=全文）で送る
#  ・送るタイミング: 週1回の定期 / 設定ファイルの変更（2分落ち着いてから）/ 画面の「今すぐ送信」
#  ・パスワード・鍵・メール認証情報は入れない。生成した文書は /var/lib/gatekeeper/reports にも保存
# ================================================================
import glob
import shutil
import socket
from email.message import EmailMessage

GK_VERSION = "v1.14.3"
REPORT_CFG_FILE = "/opt/gatekeeper/report.json"
REPORT_DIR = "/var/lib/gatekeeper/reports"
REPORT_STATE = "/var/lib/gatekeeper/report_state.json"
REPORT_DEFAULT = {"enabled": True, "weekday": 0, "hour": 9, "on_change": True, "to": ""}
WEEKDAYS = ["月", "火", "水", "木", "金", "土", "日"]
SITE_FILE = "/etc/nginx/sites-available/gatekeeper"
CHANGE_FILES = [
    ("DLPルール", "/opt/gatekeeper/dlp_rules.json"),
    ("個人情報ガード設定", PII_CFG_FILE),
    ("出口防御設定", GUARD_FILE),
    ("許可リスト", WHITELIST_FILE),
    ("管理スイッチ", "/opt/gatekeeper/wifi_mgmt.json"),
    ("メール通知設定", MAIL_FILE),
    ("nginx 設定", SITE_FILE),
    ("nftables 設定", "/etc/nftables.conf"),
    ("dashboard.py", "/opt/gatekeeper/dashboard.py"),
    ("pii_guard.py", "/opt/gatekeeper/pii_guard.py"),
    ("サーバー証明書", "/opt/gatekeeper/tls/server.crt"),
    ("環境の設定（config.json）", "/opt/gatekeeper/config.json"),
]
report_lock = threading.Lock()

def report_cfg():
    c = dict(REPORT_DEFAULT)
    try:
        with open(REPORT_CFG_FILE) as f:
            d = json.load(f)
        c.update({k: d[k] for k in REPORT_DEFAULT if k in d})
    except Exception:
        pass
    return c

def report_cfg_save(c):
    tmp = REPORT_CFG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, ensure_ascii=False)
    os.replace(tmp, REPORT_CFG_FILE)

def report_state():
    try:
        with open(REPORT_STATE) as f:
            return json.load(f)
    except Exception:
        return {}

def report_state_save(st):
    try:
        os.makedirs(os.path.dirname(REPORT_STATE), exist_ok=True)
        tmp = REPORT_STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, ensure_ascii=False)
        os.replace(tmp, REPORT_STATE)
    except Exception:
        pass

def _fhash(p):
    try:
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def config_fingerprint():
    return {name: _fhash(p) for name, p in CHANGE_FILES}

def _active(unit):
    return "稼働" if subprocess.call(["systemctl", "is-active", "--quiet", unit]) == 0 else "停止"

def _cert_days(path):
    try:
        end = subprocess.getoutput(f"openssl x509 -enddate -noout -in {path}").split("=", 1)[1].strip()
        from datetime import timezone
        dt = datetime.strptime(end, "%b %d %H:%M:%S %Y %Z")           # openssl は GMT で返す
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        return end, (dt - now_utc).days
    except Exception:
        return "不明", None

def build_report(trigger, changes=None):
    """門番の状態を Markdown 文書にする。戻り値 (件名の要約, 全文, 要約本文)"""
    now = datetime.now()
    host = socket.gethostname()
    integ = dict(integrity_state)
    br = breaker_status()
    pii = pii_guard_summary()
    pc, ps = pii.get("cfg", {}), pii.get("stats", {})
    rc = report_cfg()
    services = [("nginx（Web中継・WAF・DLP）", "nginx"), ("nftables（ファイアウォール）", "nftables"),
                ("gatekeeper-dashboard（監視・管理画面）", "gatekeeper-dashboard"),
                ("gatekeeper-piiguard（個人情報ガード）", PII_SERVICE), ("ssh", "ssh")]
    svc = [(label, _active(u)) for label, u in services]
    be = subprocess.getoutput(f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' http://{BACKEND_IP}:{BACKEND_PORT}/")
    ol = subprocess.getoutput(f"curl -s -m 3 http://{BACKEND_IP}:11434/api/version")
    cert_end, cert_days = _cert_days("/opt/gatekeeper/tls/server.crt")
    du = shutil.disk_usage("/")
    mem = {}
    try:
        for ln in open("/proc/meminfo"):
            k, v = ln.split(":", 1)
            mem[k] = int(v.split()[0])
    except Exception:
        pass
    temp = "N/A"
    try:
        temp = f"{int(open('/sys/class/thermal/thermal_zone0/temp').read().strip()) / 1000:.1f}"
    except Exception:
        pass

    # ---- 総合判定 ----
    problems = []
    for label, s in svc:
        if s != "稼働":
            problems.append(f"{label} が停止")
    if integ.get("state") == "critical":
        problems.append("整合性: 改竄の疑い")
    elif integ.get("state") == "warn":
        problems.append("整合性: 注意 → " + " / ".join(f["msg"] for f in integ.get("findings", [])))
    if br.get("active"):
        problems.append("緊急ブレーカー作動中（" + br.get("mode", "") + "）")
    if be != "200":
        problems.append(f"バックエンド {BACKEND_IP}:{BACKEND_PORT} の応答が {be}")
    if not pc.get("enabled"):
        problems.append("個人情報ガードが OFF")
    if cert_days is not None and cert_days < 30:
        problems.append(f"サーバー証明書の期限まで {cert_days} 日")
    if du.used / du.total > 0.85:
        problems.append(f"ディスク使用 {du.used * 100 // du.total}%")
    al = current_alert()
    if al:
        problems.append("未解除の警報: " + al.get("reason", ""))
    _pub = publish_state()
    _lc = le_cert_info()
    if _pub["le"].get("active") and (_lc.get("days") is None or _lc.get("days") < 20):
        problems.append(f"公開用の証明書（{_pub['le'].get('domain')}）の残り日数 {_lc.get('days')}。自動更新を確認（sudo certbot renew --dry-run）")
    if _pub["cf"].get("active") and subprocess.call(["systemctl", "is-active", "--quiet", "cloudflared"]) != 0:
        problems.append("Cloudflare Tunnel（cloudflared）が停止しています")
    verdict = "正常" if not problems else f"要確認 {len(problems)} 件"

    T = {"weekly": "定期レポート", "change": "設定変更の通知", "manual": "手動送信", "preview": "プレビュー"}.get(trigger, trigger)
    L = []
    a = L.append
    a(f"# 門番（micro-monban）設定レポート — {verdict}")
    a("")
    a(f"- 作成: {now.strftime('%Y-%m-%d %H:%M:%S')}（{T}）  ホスト: {host}  版: {GK_VERSION}")
    a("- このレポートにパスワード・鍵・メール認証情報は含まれていません。")
    a("")
    a("## 0. まず読む: 異常の見分け方と最初の一手")
    if problems:
        a("**要確認の項目:**")
        for p in problems:
            a(f"- {p}")
    else:
        a("**要確認の項目はありません。** 以下は参考情報です。")
    a("")
    a("| こんなとき | 最初の一手 |")
    a("| --- | --- |")
    a(f"| サイトが表示されない（502/504） | サーバー役PC（{BACKEND_IP}）の電源・LAN ケーブル・PHP（php-server）が動いているか確認 |")
    a("| 本当の利用者が 403 で止められる | 管理画面の「AI 動的遮断リスト」「個人情報ガードの履歴」を見て、該当 IP を解除／ガードを「記録のみ」に |")
    a("| 整合性が「重大（改竄の疑い）」 | 心当たりのない変更なら、管理画面の緊急ブレーカー「外部入口を遮断」→ 詳しい人に連絡 |")
    a("| 攻撃を受けている・情報が漏れている疑い | 管理画面の緊急ブレーカー（外部入口を遮断／バックエンドと分離）。解除は「復旧」 |")
    a(f"| 管理画面に入れない | ssh -L {PORT}:localhost:{PORT} ユーザー名@門番 で接続し https://localhost:{PORT} |")
    a("")
    a("## 1. 本体")
    a("| 項目 | 値 |")
    a("| --- | --- |")
    a(f"| 版 | {GK_VERSION} |")
    a(f"| 稼働時間 | {subprocess.getoutput('uptime -p')} |")
    a(f"| CPU 温度 | {temp} ℃ |")
    a(f"| ディスク | {du.used // 2**30}GB / {du.total // 2**30}GB（{du.used * 100 // du.total}%） |")
    if mem:
        a(f"| メモリ使用 | {(mem.get('MemTotal', 0) - mem.get('MemAvailable', 0)) // 1024}MB / {mem.get('MemTotal', 0) // 1024}MB |")
    a(f"| サーバー証明書 | 期限 {cert_end}（残り {cert_days} 日） |")
    a("")
    a("## 2. サービス")
    a("| サービス | 状態 |")
    a("| --- | --- |")
    for label, s in svc:
        a(f"| {label} | {s} |")
    a("")
    a("## 3. ネットワーク")
    a("| 項目 | 値 |")
    a("| --- | --- |")
    a(f"| 外側口 | {EXT_IF} {get_ext_ip()}（{HOME_NET}） |")
    a(f"| 内側口 | {CFG['int_if']} {INT_IP} |")
    a(f"| バックエンド | {BACKEND_IP}:{BACKEND_PORT} → HTTP {be} / Ollama {ol or '応答なし'} |")
    wm = "ON（家庭LANから管理画面に入れる）" if wifi_mgmt_is_open() else "OFF"
    a(f"| 管理スイッチ（{PORT}番の外側公開） | {wm} |")
    a(f"| 許可リスト | {', '.join(get_set_elements('whitelist')) or '（なし）'} |")
    a(f"| 自動遮断中の IP | {', '.join(get_set_elements('dynamic_blocks')) or '（なし）'} |")
    a(f"| 緊急ブレーカー | {'作動中: ' + br.get('mode', '') if br.get('active') else '非作動'} |")
    pub = publish_state()
    lc = le_cert_info()
    pubs = []
    if pub["le"].get("active"):
        pubs.append(f"Let's Encrypt（{pub['le'].get('domain')}、証明書 残り {lc.get('days')} 日）")
    if pub["cf"].get("active"):
        cfs = "接続中" if subprocess.call(["systemctl", "is-active", "--quiet", "cloudflared"]) == 0 else "停止"
        pubs.append(f"Cloudflare Tunnel（{cfs}）")
    a(f"| インターネット公開 | {' / '.join(pubs) or '未公開（家庭内LANのみ）'} |")
    a("")
    a("## 4. 整合性（改竄・異常の自己点検）")
    a(f"- 状態: **{integ.get('state', '不明')}**（最終点検 {integ.get('checked_at', '--')}）")
    for f in integ.get("findings", []):
        a(f"  - {f['level']}: {f['msg']}")
    a("- 監視しているファイルの指紋（sha256 先頭16桁）:")
    for p in MONITOR_PATHS:
        h = _fhash(p)
        a(f"  - {p}: {h[:16] if h else '（なし）'}")
    a("")
    a("## 5. 個人情報 一括持ち出しガード")
    a("| 項目 | 値 |")
    a("| --- | --- |")
    a(f"| スイッチ | {'ON' if pc.get('enabled') else 'OFF'}{'（記録のみ）' if pc.get('monitor_only') else ''} / サービス {'稼働' if pii.get('service') else '停止'} |")
    a(f"| 上限 | 1回の応答 {pc.get('max_per_response')} 件 / 同じ接続元へ {int(pc.get('window_sec', 600)) // 60} 分で {pc.get('window_limit')} 件 |")
    a(f"| 集計（{ps.get('since', '--')} から） | 中継 {ps.get('requests', 0)} / 検査 {ps.get('inspected', 0)} / 個人情報を含む {ps.get('with_pii', 0)} / 遮断 {ps.get('blocked', 0)} / 記録のみ {ps.get('monitored', 0)} |")
    evs = pii.get("events", [])[:10]
    if evs:
        a("")
        a("直近の検知:")
        for e in evs:
            a(f"- {e.get('time')} {e.get('ip')} {e.get('path')} 約{e.get('est')}件 {'遮断' if e.get('action') == 'block' else '記録のみ'}")
    a("")
    a("## 6. 出口防御・メール通知")
    g = guard_summary()
    a(f"- 自動IP遮断: {'ON' if g.get('auto_block') else 'OFF'} / 個人情報連続 {g.get('harvest_threshold')} 回 / 単応答上限 {g.get('max_body_mb')}MB / 10分累計 {g.get('bytes10m_mb')}MB / 5xx {g.get('err5_rate')} 回/分")
    m = mail_summary()
    a(f"- メール通知: {'ON' if m.get('enabled') else 'OFF'}（SMTP {m.get('host') or '未設定'} / 宛先 {m.get('to') or '未設定'}）")
    a(f"- 設定レポート: 定期 {'毎週' + WEEKDAYS[int(rc.get('weekday', 0)) % 7] + '曜 ' + str(rc.get('hour')) + '時' if rc.get('enabled') else 'OFF'} / 変更時 {'送る' if rc.get('on_change') else '送らない'}")
    a("")
    a("## 7. DLP（応答の機密情報の伏せ字）")
    rules = load_dlp_rules()
    on = [r for r in rules if r.get("enabled")]
    a(f"- 有効 {len(on)} / 全 {len(rules)} ルール")
    for r in rules:
        a(f"  - [{'ON ' if r.get('enabled') else 'OFF'}] {r.get('name')}")
    a("")
    a("## 8. WAF（入口の簡易検査）")
    try:
        conds = []
        for ln in open(SITE_FILE):
            s = ln.strip()
            if s.startswith("if (") and "~*" in s and s not in conds:
                conds.append(s)
        for s in conds:
            a(f"- `{s.rstrip('{').strip()}`")
    except Exception:
        a("- （設定を読めませんでした）")
    a("")
    a("## 9. 警報の履歴（直近10件）")
    hist = list(alert_history)[:10]
    if hist:
        for h in hist:
            a(f"- {h.get('time')} {h.get('reason')}（{h.get('ip')} {h.get('path')}）")
    else:
        a("- なし")
    a("")
    a("## 10. 脅威スコア上位（直近24時間）")
    with stats_lock:
        top = sorted(ip_stats.items(), key=lambda kv: -kv[1].get("score", 0))[:5]
    if top:
        for ip, s in top:
            a(f"- {ip}: スコア {s.get('score')} {s.get('stage')}（要求 {s.get('req_count')} / エラー率 {s.get('error_ratio')}% / SSH失敗 {s.get('ssh_fail', 0)}）")
    else:
        a("- なし")
    a("")
    if changes:
        a("## 11. 今回の変更")
        for ch in changes:
            a(f"- {ch}")
        a("")
    a("## 12. バックアップ（元に戻すときに使う）")
    bks = sorted(glob.glob("/opt/gatekeeper/backup_*") + glob.glob(SITE_FILE + ".bak_*"))
    for b in bks[-15:]:
        a(f"- {b}")
    if not bks:
        a("- なし")
    a("")
    a("— 門番（micro-monban）が自動で作成しました —")
    full = "\n".join(L) + "\n"
    summary = "\n".join(L[:L.index("## 1. 本体")]) + "\n詳しい内容は添付ファイルをご覧ください。\n"
    return verdict, full, summary

def save_report_file(full, stamp):
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        p = os.path.join(REPORT_DIR, f"report_{stamp}.md")
        with open(p, "w") as f:
            f.write(full)
        for old in sorted(glob.glob(os.path.join(REPORT_DIR, "report_*.md")))[:-30]:
            os.remove(old)
        return p
    except Exception:
        return ""

def send_report(trigger, changes=None):
    """レポートを作ってメールで送る。戻り値 (ok, メッセージ)"""
    with report_lock:
        verdict, full, summary = build_report(trigger, changes)
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        save_report_file(full, stamp)
        st = report_state()
        rc = report_cfg()
        to = [x.strip() for x in (rc.get("to") or mail_cfg.get("to") or "").split(",") if x.strip()]
        if not mail_cfg.get("host") or not to:
            msg = "メール未設定のため送信できません（文書は Pi に保存しました）。管理画面の「管理者メール通知」で SMTP と宛先を設定してください"
            st.update({"last_result": msg, "last_try": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            report_state_save(st)
            return False, msg
        kind = {"weekly": "定期", "change": "設定変更", "manual": "手動"}.get(trigger, trigger)
        try:
            em = EmailMessage()
            em["Subject"] = f"[門番] 設定レポート（{kind}）{verdict} — {socket.gethostname()} {datetime.now().strftime('%Y-%m-%d')}"
            em["From"] = mail_cfg.get("user") or "gatekeeper@localhost"
            em["To"] = ", ".join(to)
            em["Date"] = formatdate(localtime=True)
            em.set_content(summary)
            em.add_attachment(full.encode("utf-8"), maintype="text", subtype="markdown", filename=f"gatekeeper_report_{stamp}.md")
            port = int(mail_cfg.get("port") or 587)
            srv = smtplib.SMTP_SSL(mail_cfg["host"], port, timeout=15) if port == 465 else smtplib.SMTP(mail_cfg["host"], port, timeout=15)
            try:
                if port != 465:
                    try:
                        srv.starttls()
                    except smtplib.SMTPException:
                        pass
                if mail_cfg.get("user") and mail_cfg.get("pass"):
                    srv.login(mail_cfg["user"], mail_cfg["pass"])
                srv.send_message(em)
            finally:
                try:
                    srv.quit()
                except Exception:
                    pass
            msg = f"送信しました（{kind}・{verdict}・宛先 {len(to)} 件）"
            ok = True
        except Exception as e:
            msg = "送信失敗: " + str(e)[:160]
            ok = False
        now_s = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.update({"last_result": msg, "last_try": now_s})
        if ok:
            st["last_sent"] = now_s
        report_state_save(st)
        print("[report] " + msg, flush=True)
        return ok, msg

def report_summary():
    rc = report_cfg()
    st = report_state()
    return {"cfg": rc, "last_sent": st.get("last_sent", ""), "last_try": st.get("last_try", ""),
            "last_result": st.get("last_result", ""), "pending_change": bool(st.get("pending_since")),
            "mail_ready": bool(mail_cfg.get("host") and (rc.get("to") or mail_cfg.get("to")))}

def report_loop():
    """週1回の定期送信と、設定ファイルの変更（2分落ち着いてから）での送信。"""
    time.sleep(30)
    while True:
        try:
            rc = report_cfg()
            st = report_state()
            now = datetime.now()
            fp = config_fingerprint()
            if "fp" not in st:                       # 初回: 基準だけ記録
                st["fp"] = fp
                report_state_save(st)
            elif fp != st["fp"]:
                if st.get("pending_fp") != fp:       # 変化の途中: 落ち着くのを待つ
                    st["pending_fp"], st["pending_since"] = fp, time.time()
                    report_state_save(st)
                elif time.time() - st.get("pending_since", 0) >= 120:
                    changed = [n for n, _ in CHANGE_FILES if fp.get(n) != st["fp"].get(n)]
                    st["fp"] = fp
                    st.pop("pending_fp", None)
                    st.pop("pending_since", None)
                    report_state_save(st)
                    if rc.get("on_change"):
                        send_report("change", ["変更されたもの: " + "、".join(changed)])
            elif st.get("pending_since"):
                st.pop("pending_fp", None)
                st.pop("pending_since", None)
                report_state_save(st)
            wk = now.strftime("%G-W%V")
            if (rc.get("enabled") and now.weekday() == int(rc.get("weekday", 0)) % 7
                    and now.hour == int(rc.get("hour", 9)) and report_state().get("last_weekly") != wk):
                st = report_state()
                st["last_weekly"] = wk
                report_state_save(st)
                send_report("weekly")
        except Exception as e:
            print("[report] loop error: " + str(e), flush=True)
        time.sleep(60)

# ================================================================
# [v1.12.0] インターネット公開ウィザード
#  A) Let's Encrypt（ポート開放ができる人）: 事前確認=試験環境で取得を試す → 本番取得 → ドメイン専用の
#     server（sites-available/gatekeeper-public）を有効化。証明書の更新は certbot.timer が自動で行う
#  B) Cloudflare Tunnel（ポート開放が難しい人）: cloudflared を導入 → トークンで接続
#  ・どちらも重い処理は「ジョブ」として裏で実行し、進み具合を画面に出す（同時に1つまで）
#  ・Cloudflare 経由は nftables の IP 遮断が効かないため、遮断IPを nginx の deny にも同期する
# ================================================================
PUBLISH_FILE = "/opt/gatekeeper/publish.json"
ACME_ROOT = "/var/www/acme"
PUBLIC_SITE = "/etc/nginx/sites-available/gatekeeper-public"
PUBLIC_LINK = "/etc/nginx/sites-enabled/gatekeeper-public"
HTTPS_BODY = "/etc/nginx/snippets/gatekeeper_https_body.conf"
DENY_SNIPPET = "/etc/nginx/snippets/gatekeeper_deny.conf"
DEPLOY_HOOK = "/opt/gatekeeper/gk_cert_deploy.sh"
# [v1.14.0] MyDNS の DNS で確認（DNS-01）。80 番が外から届かない回線用
MYDNS_NETRC = "/etc/letsencrypt/mydns.netrc"
MYDNS_HOOK = "/opt/gatekeeper/le-mydns-hook.sh"
MYDNS_CRED_RE = re.compile(r"^[!-~]{1,128}$")     # 空白なしの表示できる ASCII
LE_METHODS = ("webroot", "dns-mydns")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-=.]{40,4096}$")

job = {"name": "", "running": False, "ok": None, "started": "", "ended": "", "log": []}
job_lock = threading.Lock()

def publish_state():
    d = {"le": {"domain": "", "email": "", "active": False}, "cf": {"active": False}}
    try:
        with open(PUBLISH_FILE) as f:
            s = json.load(f)
        d["le"].update(s.get("le", {}))
        d["cf"].update(s.get("cf", {}))
    except Exception:
        pass
    return d

def publish_save(d):
    tmp = PUBLISH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, PUBLISH_FILE)

def jlog(msg):
    line = datetime.now().strftime("%H:%M:%S ") + msg
    with job_lock:
        job["log"].append(line)
        job["log"] = job["log"][-200:]
    print("[publish] " + msg, flush=True)

def jrun(cmd, show=None, timeout=600):
    """コマンドを実行して出力をジョブ記録に残す。show は記録に出す表示（秘密を伏せる用）。"""
    jlog("$ " + (show or " ".join(cmd)))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout + p.stderr).strip()
        for ln in out.splitlines()[-25:]:
            jlog("  " + ln)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        jlog("  時間切れ")
        return 124, "timeout"
    except FileNotFoundError:
        jlog("  コマンドが見つかりません: " + cmd[0])
        return 127, "not found"

def start_job(name, fn, *args):
    with job_lock:
        if job["running"]:
            return False, "別の処理（" + job["name"] + "）が実行中です。終わってから操作してください"
        job.update({"name": name, "running": True, "ok": None,
                    "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ended": "", "log": []})
    def _w():
        ok = False
        try:
            ok = bool(fn(*args))
        except Exception as e:
            jlog("エラー: " + str(e)[:200])
        with job_lock:
            job.update({"running": False, "ok": ok, "ended": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        jlog("■ " + ("完了しました" if ok else "失敗しました（上の記録を確認してください）"))
    threading.Thread(target=_w, daemon=True).start()
    return True, name + " を開始しました"

def nginx_reload_checked():
    if subprocess.call(["nginx", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        jrun(["nginx", "-t"])
        return False
    return subprocess.call(["systemctl", "reload", "nginx"]) == 0

def le_explain(out, method="webroot"):
    o = out.lower()
    if "mydns: ログインできません" in o:
        return "原因: MyDNS にログインできません。マスターID とパスワード（mydns.jp にログインするときのもの）を入れ直してください。"
    if "mydns:" in o:
        return "原因: MyDNS に確認用の値を登録できませんでした。しばらく待ってから再度お試しください（MyDNS 側の一時的な不調のことがあります）。"
    if method == "dns-mydns" and ("txt" in o or "dns problem" in o or "unauthorized" in o):
        return "原因: MyDNS の DNS に確認用の値（TXT）がまだ反映されていません。数分おいて再度お試しください。続くときは、そのドメインが MyDNS で管理されているか確認してください。"
    if "nxdomain" in o or "no valid a records" in o or "dns problem" in o:
        return "原因: DNS。ドメインの A レコードが、この家の外向き IP を指しているか確認してください（反映まで数分〜数時間かかることがあります）。"
    if "timeout during connect" in o or "connection refused" in o or "connection reset" in o or "fetching http" in o:
        return "原因: 外から 80 番に届いていません。ルーターで 80/443 番をこの門番の外側 IP（" + get_ext_ip() + "）へ転送しているか、プロバイダが 80 番を止めていないか確認してください。転送が正しいのに届かないときは、DDNS が MyDNS なら確認の方法を「MyDNS の DNS」にすると取得できます（80 番は不要）。"
    if "invalid response" in o or "404" in o or "unauthorized" in o:
        return "原因: ドメインが別の機器（別のサーバーやルーターの管理画面）を指しています。DNS の向き先とルーターの転送先を確認してください。"
    if "too many" in o or "ratelimit" in o or "rate limit" in o:
        return "原因: Let's Encrypt の回数制限です。しばらく（1時間〜1週間）待ってから再度お試しください。"
    return "原因を特定できませんでした。上の記録の最後の数行を確認してください。"

def le_auth_args(method):
    """certbot に渡す「持ち主の確認」の方法。webroot = 80 番、dns-mydns = MyDNS の DNS（TXT）"""
    if method == "dns-mydns":
        return ["--manual", "--preferred-challenges", "dns",
                "--manual-auth-hook", MYDNS_HOOK + " auth", "--manual-cleanup-hook", MYDNS_HOOK + " cleanup"]
    return ["--webroot", "-w", ACME_ROOT]

def le_renewal_method(domain):
    """既にある証明書の更新方法（certbot の renewal 設定から読む）。無ければ空"""
    try:
        with open(f"/etc/letsencrypt/renewal/{domain}.conf") as f:
            t = f.read()
    except Exception:
        return ""
    m = re.search(r"^authenticator\s*=\s*(\S+)", t, re.M)
    if not m:
        return ""
    if m.group(1) == "manual":
        return "dns-mydns" if "le-mydns-hook" in t else "manual"
    return m.group(1)

def mydns_save_login(mid, mpw):
    """MyDNS のログイン情報を root だけ読めるファイルに保存（値は記録にも画面にも出さない）"""
    os.makedirs("/etc/letsencrypt", exist_ok=True)
    tmp = MYDNS_NETRC + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"machine www.mydns.jp login {mid} password {mpw}\n")
    os.replace(tmp, MYDNS_NETRC)
    os.chmod(MYDNS_NETRC, 0o600)

def le_check(domain, email, global_ip, method="webroot"):
    jlog(f"ドメイン {domain} の事前確認を始めます（確認の方法: " + ("MyDNS の DNS" if method == "dns-mydns" else "80 番") + "）")
    if method == "dns-mydns" and not (os.path.exists(MYDNS_HOOK) and os.path.exists(MYDNS_NETRC)):
        jlog("✗ MyDNS の確認に必要なもの（" + MYDNS_HOOK + " か ログイン情報）がありません。マスターID とパスワードを入れてください。")
        return False
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(domain, 80, socket.AF_INET)})
    except Exception:
        ips = []
    if not ips:
        jlog("✗ DNS: " + domain + " の A レコードが見つかりません。ドメイン管理画面で A レコード（値 = この家の外向き IP）を登録してください。")
        return False
    jlog("✓ DNS: " + domain + " → " + ", ".join(ips))
    if any(ip.startswith(("10.", "192.168.", "127.")) or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip) for ip in ips):
        jlog("✗ DNS が家庭内の IP を指しています。外向き（グローバル）IP を登録してください。")
        return False
    if global_ip:
        jlog(("✓ " if global_ip in ips else "△ ") + "この家の外向き IP: " + global_ip +
             ("（一致）" if global_ip in ips else "（DNS と一致しません。DNS の値を確認してください）"))
    os.makedirs(ACME_ROOT + "/.well-known/acme-challenge", exist_ok=True)
    jlog("Let's Encrypt の試験環境で、外から実際に取得できるかを確かめます（本番の回数制限は消費しません）")
    if method == "dns-mydns":
        jlog("MyDNS に確認用の値を登録し、反映を待ちます（2〜4分かかります）")
    rc, out = jrun(["certbot", "certonly"] + le_auth_args(method) + ["-d", domain, "--dry-run",
                    "-m", email, "--agree-tos", "-n"], timeout=600)
    if rc != 0:
        jlog("✗ 試験取得に失敗。" + le_explain(out, method))
        return False
    jlog("✓ 試験取得に成功しました。「本番取得して公開」に進めます。")
    return True

def public_site_text(domain):
    return ("# [v1.12.0] インターネット公開（Let's Encrypt）— ダッシュボードが生成\n"
            "server {\n"
            "    listen 443 ssl;\n"
            f"    server_name {domain};\n"
            "    access_log /var/log/nginx/gatekeeper_access.log ai_watch;\n"
            f"    ssl_certificate     /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
            f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n"
            f"    include {HTTPS_BODY};\n"
            "}\n")

def le_issue(domain, email, global_ip, method="webroot"):
    if not le_check(domain, email, global_ip, method):
        return False
    jlog("本番の証明書を取得します")
    # 既にある証明書の更新方法が今回と違うときは取り直す（そのままだと自動更新が古い方法のまま残る）
    cur = le_renewal_method(domain)
    keep = "--keep-until-expiring" if cur in ("", method) else "--force-renewal"
    if keep == "--force-renewal":
        jlog("更新の方法を切り替えるため、証明書を取り直します")
    rc, out = jrun(["certbot", "certonly"] + le_auth_args(method) + ["-d", domain, "--cert-name", domain,
                    "-m", email, "--agree-tos", "-n", keep,
                    "--deploy-hook", DEPLOY_HOOK], timeout=600)
    if rc != 0:
        jlog("✗ 本番取得に失敗。" + le_explain(out, method))
        return False
    if not os.path.exists(f"/etc/letsencrypt/live/{domain}/fullchain.pem"):
        jlog("✗ 証明書ファイルが見つかりません")
        return False
    with open(PUBLIC_SITE, "w") as f:
        f.write(public_site_text(domain))
    if os.path.lexists(PUBLIC_LINK):
        os.remove(PUBLIC_LINK)
    os.symlink(PUBLIC_SITE, PUBLIC_LINK)
    if not nginx_reload_checked():
        os.remove(PUBLIC_LINK)
        nginx_reload_checked()
        jlog("✗ nginx に組み込めなかったため元に戻しました")
        return False
    rebuild_manifest()
    d = publish_state()
    d["le"] = {"domain": domain, "email": email, "active": True, "method": method,
               "since": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    publish_save(d)
    code = subprocess.getoutput(f"curl -s -m 10 -o /dev/null -w '%{{http_code}}' --resolve {domain}:443:127.0.0.1 https://{domain}/")
    jlog(("✓ " if code not in ("000",) else "△ ") + f"https://{domain}/ を正規の証明書で確認: HTTP {code}")
    jlog("✓ 公開しました。証明書は自動で更新されます（certbot.timer）。")
    return True

def le_revert():
    jlog("Let's Encrypt での公開をやめます（証明書は残し、自動更新も続けます）")
    if os.path.lexists(PUBLIC_LINK):
        os.remove(PUBLIC_LINK)
    ok = nginx_reload_checked()
    rebuild_manifest()
    d = publish_state()
    d["le"]["active"] = False
    publish_save(d)
    jlog("✓ ドメイン用の設定を外しました" if ok else "△ nginx の再読み込みに失敗")
    return ok

def le_cert_info():
    d = publish_state()["le"]
    dom = d.get("domain")
    if not dom:
        return {}
    p = f"/etc/letsencrypt/live/{dom}/fullchain.pem"
    if not os.path.exists(p):
        return {"domain": dom, "exists": False}
    end, days = _cert_days(p)
    # [v1.14.0] 更新の方法・自動更新の次回・最後の予行演習
    nxt = subprocess.getoutput("systemctl show certbot.timer -p NextElapseUSecRealtime --value 2>/dev/null").strip()
    return {"domain": dom, "exists": True, "end": end, "days": days,
            "method": le_renewal_method(dom),
            "timer": subprocess.call(["systemctl", "is-active", "--quiet", "certbot.timer"]) == 0,
            "next": nxt, "renew_test": d.get("renew_test", {})}

def le_renew_test():
    """証明書の自動更新の予行演習（試験環境で更新を試す。本物の証明書は変わらない）"""
    d = publish_state()
    dom = d["le"].get("domain")
    if not dom or not os.path.exists(f"/etc/letsencrypt/renewal/{dom}.conf"):
        jlog("✗ 更新する証明書がありません（先に「本番取得して公開」を行ってください）")
        return False
    m = le_renewal_method(dom)
    jlog(f"{dom} の更新を試験環境で試します（確認の方法: " + ("MyDNS の DNS。2〜4分かかります" if m == "dns-mydns" else ("80 番" if m == "webroot" else m)) + "）")
    rc, out = jrun(["certbot", "renew", "--dry-run", "--cert-name", dom, "-n"], timeout=600)
    ok = rc == 0 and "succeeded" in out.lower()
    d = publish_state()
    d["le"]["renew_test"] = {"ok": ok, "at": datetime.now().strftime("%Y-%m-%d %H:%M")}
    publish_save(d)
    jlog("✓ 予行演習に成功しました。期限の30日前ごろに自動で更新されます" if ok else "✗ 予行演習に失敗。" + le_explain(out, m))
    return ok

def cf_install():
    if shutil.which("cloudflared"):
        jlog("✓ cloudflared は導入済みです: " + subprocess.getoutput("cloudflared --version").splitlines()[0])
        return True
    jlog("Cloudflare 公式の配布元（pkg.cloudflare.com）から cloudflared を導入します")
    os.makedirs("/usr/share/keyrings", exist_ok=True)
    rc, _ = jrun(["curl", "-fsSL", "-o", "/usr/share/keyrings/cloudflare-main.gpg", "https://pkg.cloudflare.com/cloudflare-main.gpg"], timeout=120)
    if rc != 0:
        jlog("✗ 配布元の鍵を取得できません（インターネット接続を確認）")
        return False
    with open("/etc/apt/sources.list.d/cloudflared.list", "w") as f:
        f.write("deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main\n")
    rc, _ = jrun(["apt-get", "update"], timeout=600)
    if rc != 0:
        return False
    rc, _ = jrun(["apt-get", "install", "-y", "cloudflared"], timeout=900)
    if rc != 0 or not shutil.which("cloudflared"):
        return False
    jlog("✓ 導入しました: " + subprocess.getoutput("cloudflared --version").splitlines()[0])
    return True

def cf_connect(token):
    if not shutil.which("cloudflared"):
        jlog("✗ 先に「cloudflared を導入」を実行してください")
        return False
    if subprocess.call(["systemctl", "is-active", "--quiet", "cloudflared"]) == 0:
        jlog("既存の接続を外してから付け直します")
        jrun(["cloudflared", "service", "uninstall"])
    rc, _ = jrun(["cloudflared", "service", "install", token], show="cloudflared service install ********（トークンは伏せています）", timeout=120)
    time.sleep(5)
    if rc != 0 or subprocess.call(["systemctl", "is-active", "--quiet", "cloudflared"]) != 0:
        jrun(["journalctl", "-u", "cloudflared", "-n", "15", "--no-pager"])
        jlog("✗ 接続できませんでした。トークンが正しいか、Cloudflare 側でトンネルが作られているか確認してください")
        return False
    rebuild_manifest()
    d = publish_state()
    d["cf"] = {"active": True, "since": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    publish_save(d)
    jlog("✓ Cloudflare とつながりました。Cloudflare の画面で、公開ホスト名のサービスが「HTTPS://localhost:443」かつ「No TLS Verify」= ON になっているか確認してください")
    return True

def cf_disconnect():
    jlog("Cloudflare Tunnel の接続を外します")
    if shutil.which("cloudflared"):
        jrun(["cloudflared", "service", "uninstall"])
    d = publish_state()
    d["cf"]["active"] = False
    publish_save(d)
    ok = subprocess.call(["systemctl", "is-active", "--quiet", "cloudflared"]) != 0
    jlog("✓ 外しました" if ok else "△ cloudflared がまだ動いています")
    return ok

def publish_summary():
    d = publish_state()
    with job_lock:
        jb = {k: (list(v) if isinstance(v, list) else v) for k, v in job.items()}
    return {"le": d["le"], "cf": d["cf"], "le_cert": le_cert_info(),
            "certbot": bool(shutil.which("certbot")),
            "mydns_login": os.path.exists(MYDNS_NETRC),      # [v1.14.0] 値そのものは返さない
            "mydns_hook": os.path.exists(MYDNS_HOOK),
            "cloudflared": bool(shutil.which("cloudflared")),
            "cf_service": subprocess.call(["systemctl", "is-active", "--quiet", "cloudflared"]) == 0,
            "job": jb}

def deny_sync_loop():
    """自動遮断中の IP を nginx の deny にも反映（Cloudflare 経由では nftables の遮断が効かないため）。"""
    last = None
    while True:
        try:
            ips = sorted({v for v in (valid_ipv4(x) for x in get_set_elements("dynamic_blocks")) if v})
            text = "# [v1.12.0] ダッシュボードが自動生成（自動遮断中の IP）\n" + "".join(f"deny {ip};\n" for ip in ips)
            cur = None
            try:
                with open(DENY_SNIPPET) as f:
                    cur = f.read()
            except Exception:
                pass
            if text != cur and os.path.exists(HTTPS_BODY):
                with open(DENY_SNIPPET, "w") as f:
                    f.write(text)
                if subprocess.call(["nginx", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                    subprocess.call(["systemctl", "reload", "nginx"])
                elif cur is not None:
                    with open(DENY_SNIPPET, "w") as f:
                        f.write(cur)
                if ips != last:
                    print("[deny_sync] nginx deny = " + (", ".join(ips) or "(なし)"), flush=True)
                last = ips
        except Exception as e:
            print("[deny_sync] error: " + str(e), flush=True)
        time.sleep(15)

def mail_summary():
    return {"enabled": bool(mail_cfg.get("enabled")),
            "host": mail_cfg.get("host", ""), "port": mail_cfg.get("port", 587),
            "user": mail_cfg.get("user", ""), "to": mail_cfg.get("to", ""),
            "configured": bool(mail_cfg.get("host") and mail_cfg.get("to")),
            "last_result": mail_state.get("last_result", "")}


# 管理画面Basic認証
#  ・閉域側（INT_PREFIX配下 / ループバック）は認証なし（信頼セグメント）
#  ・外部側（HOME_NET、スイッチ開放時）はBasic認証必須
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("GK_ADMIN_PASS", "change-me")

# [v1.3] DLPマスキングルール管理
#  ・ルールの実体は /opt/gatekeeper/dlp_rules.json（ダッシュボードから編集・永続化）
#  ・ここから nginx 用スニペットを生成し、nginx -t 検証のうえリロードで反映する
#  ・パターン内にシングルクォートは使えない（nginx設定文字列の制約）
DLP_FILE = "/opt/gatekeeper/dlp_rules.json"
DLP_SNIPPET = "/etc/nginx/snippets/gatekeeper_dlp.conf"

def load_dlp_rules():
    try:
        with open(DLP_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def save_dlp_rules(rules):
    try:
        with open(DLP_FILE, 'w') as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def render_dlp_conf(rules):
    lines = ["# /etc/nginx/snippets/gatekeeper_dlp.conf - Gatekeeper dashboard generated (do not edit)"]
    for r in rules:
        if r.get("enabled"):
            p = r["pattern"].replace("'", "")
            rep = r["replacement"].replace("'", "")
            lines.append(f"subs_filter '{p}' '{rep}' irg;")
    return "\n".join(lines) + "\n"

def apply_dlp_rules(rules):
    """スニペットを生成し、nginx -t 合格なら反映。不合格なら元に戻す。"""
    try:
        backup = None
        if os.path.exists(DLP_SNIPPET):
            with open(DLP_SNIPPET, 'r') as f:
                backup = f.read()
        os.makedirs(os.path.dirname(DLP_SNIPPET), exist_ok=True)
        with open(DLP_SNIPPET, 'w') as f:
            f.write(render_dlp_conf(rules))
        if subprocess.call(["nginx", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            if backup is not None:
                with open(DLP_SNIPPET, 'w') as f:
                    f.write(backup)
            return False, "nginx設定テストが不合格のため変更を取り消しました（パターンを確認してください）"
        subprocess.run(["systemctl", "reload", "nginx"], check=False)
        rebuild_manifest()  # [v1.4] スニペットが変わったので台帳を更新（誤検知防止）
        return True, "DLPルールを反映しました。"
    except Exception as e:
        return False, f"反映エラー: {e}"

def ensure_dlp_conf():
    """起動時にスニペットがルールJSONと一致しなければ再生成する（自己修復）。"""
    try:
        rendered = render_dlp_conf(load_dlp_rules())
        current = None
        if os.path.exists(DLP_SNIPPET):
            with open(DLP_SNIPPET, 'r') as f:
                current = f.read()
        if current != rendered:
            os.makedirs(os.path.dirname(DLP_SNIPPET), exist_ok=True)
            with open(DLP_SNIPPET, 'w') as f:
                f.write(rendered)
            subprocess.run(["systemctl", "reload", "nginx"], check=False)
            print("[dlp] snippet regenerated", flush=True)
    except Exception:
        pass

# [v1.4] セルフ整合性監視（静的台帳 + 動的指標）
#  ・「変化線」を毎5分で照合し、歪みを検知する
#  ・静的台帳: 重要ファイルのsha256（DLPルール変更時は自動で台帳更新）
#  ・動的指標: 外向き接続・予定外の待ち受けポート
#  ・読み取り専用モード(OvlerayFS)中の重大検知は120秒後に自動再起動
#    （書き込みはメモリ上のため消失し、本来の自己で立ち上がる）
import hashlib
INTEGRITY_FILE = "/var/lib/gatekeeper/integrity_manifest.json"
MONITOR_PATHS = [
    "/etc/nginx/sites-available/gatekeeper",
    "/etc/nginx/conf.d/log_format.conf",
    "/etc/nginx/snippets/gatekeeper_dlp.conf",
    "/etc/nftables.conf",
    "/etc/systemd/system/gatekeeper-dashboard.service",
    "/opt/gatekeeper/dashboard.py",
    "/opt/gatekeeper/tls/server.crt",
    "/opt/gatekeeper/pii_guard.py",                       # [v1.10.0]
    "/etc/systemd/system/gatekeeper-piiguard.service",    # [v1.10.0]
    "/etc/nginx/snippets/gatekeeper_https_body.conf",     # [v1.12.0] 443番の共通本体（WAF・DLP・中継）
    "/etc/nginx/conf.d/gatekeeper_realip.conf",           # [v1.12.0] 本当の利用者IPの読み取り
    "/etc/nginx/sites-available/gatekeeper-public",       # [v1.12.0] 公開ドメイン用（無ければ対象外）
    "/opt/gatekeeper/gk_cert_deploy.sh",                  # [v1.12.0] 証明書更新後の処理
    "/opt/gatekeeper/le-mydns-hook.sh",                   # [v1.14.0] MyDNS の DNS 確認（無ければ対象外）
    "/opt/gatekeeper/config.json",                        # [v1.12.0] 環境の設定（IF・IP・ポート）
    "/opt/gatekeeper/kiosk.py",                           # [v1.13.0] 本体画面のサーバー
    "/opt/gatekeeper/kiosk.html",                         # [v1.13.0] 本体画面
    "/etc/systemd/system/gatekeeper-kiosk.service",       # [v1.13.0]
]
GK_AUTO_REBOOT = os.environ.get("GK_AUTO_REBOOT", "1")
integrity_state = {"state": "unknown", "findings": [], "checked_at": "", "ro_mode": False}

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()

def is_ro_mode():
    try:
        return "overlay" in subprocess.getoutput("findmnt -n -o FSTYPE /")
    except Exception:
        return False

def rebuild_manifest():
    m = {}
    for p in MONITOR_PATHS:
        try:
            m[p] = sha256_file(p)
        except Exception:
            m[p] = None
    try:
        os.makedirs(os.path.dirname(INTEGRITY_FILE), exist_ok=True)
        with open(INTEGRITY_FILE, 'w') as f:
            json.dump(m, f)
    except Exception:
        pass
    return m

def self_integrity_check():
    findings = []
    base = None
    try:
        with open(INTEGRITY_FILE, 'r') as f:
            base = json.load(f)
    except Exception:
        base = None
    if not base:
        rebuild_manifest()
        findings.append({"level": "info", "msg": "基準台帳を新規作成しました（初回チェック）"})
    else:
        for p, want in base.items():
            try:
                if want and sha256_file(p) != want:
                    findings.append({"level": "critical", "msg": f"改竄の疑い: {p}"})
            except Exception:
                findings.append({"level": "warn", "msg": f"読み出し失敗: {p}"})
    # 動的指標1: 外向き接続（外の世界への「電話」は門番の異常）
    out = subprocess.getoutput("ss -tnp state established 2>/dev/null | tail -n +2")
    for line in out.splitlines():
        # [v1.12.0] Cloudflare Tunnel（cloudflared）の常時接続と、公開ウィザードの処理中（apt・certbot）の通信は正常
        if "cloudflared" in line or job.get("running"):
            continue
        cols = line.split()
        if cols and cols[0] in ("ESTAB", "ESTABLISHED"):
            cols = cols[1:]  # State列の有無はiproute2の版で変わるため正規化
        if len(cols) < 4:
            continue
        peer = cols[3]
        if "users:" in peer or ':' not in peer:
            continue
        # [v1.7修正] 自分の待ち受けポートへの「着信」は正常（インバウンド）。
        # ローカル側が一時ポートのときだけ外向き接続の可能性とみなす。
        local_port = cols[2].rsplit(':', 1)[-1]
        if local_port in ("80", "443", "22", str(PORT)):
            continue
        addr = peer.rsplit(':', 1)[0].strip('[]')
        if addr.startswith(("10.", "192.168.", "127.", "169.254.", "172.")) or addr == "::1":
            continue
        findings.append({"level": "warn", "msg": f"外向き接続を検出: {peer}"})
        break
    # 動的指標2: 予定外の待ち受けポート
    expect = {"80", "443", "22", str(PORT), "8081",    # 8081 = [v1.10.0] pii_guard（127.0.0.1のみ）
              str(CFG.get("kiosk_port", 9100))}         # [v1.13.0] 本体画面のサーバー（127.0.0.1のみ）
    out = subprocess.getoutput("ss -tlnp 2>/dev/null | tail -n +2")
    extra = set()
    for line in out.splitlines():
        if "cloudflared" in line:      # [v1.12.0] cloudflared の内部用ポート（127.0.0.1）は正常
            continue
        cols = line.split()
        if len(cols) < 4:
            continue
        port = cols[3].rsplit(':', 1)[-1]
        if port.isdigit() and port not in expect:
            extra.add(port)
    if extra:
        findings.append({"level": "warn", "msg": f"予定外の待ち受けポート: {sorted(extra)}"})
    # 判定と自動防衛（重大=台帳不一致のみ。曖昧な歪みは警報で人間に判定させる）
    crit = [f for f in findings if f["level"] == "critical"]
    if crit and GK_AUTO_REBOOT == "1" and is_ro_mode():
        findings.append({"level": "info", "msg": "読み取り専用モードのため120秒後に再起動します（自己を初期化し、本来の自己で立ち上がります）"})
        threading.Timer(120, lambda: subprocess.run(["sudo", "reboot"])).start()
    state = "critical" if crit else ("warn" if any(f["level"] == "warn" for f in findings) else "ok")
    return state, findings

def integrity_loop():
    while True:
        try:
            st, fd = self_integrity_check()
            integrity_state.update({"state": st, "findings": fd,
                                    "checked_at": datetime.now().strftime("%H:%M:%S"),
                                    "ro_mode": is_ro_mode()})
        except Exception:
            pass
        time.sleep(300)

ip_history = collections.defaultdict(lambda: collections.deque(maxlen=WINDOW_SIZE))
ip_stats = {}
stats_lock = threading.Lock()

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                ips = [v for v in (valid_ipv4(x) for x in json.load(f)) if v]
                for ip in ips:
                    subprocess.run(["sudo", "nft", "add", "element", "inet", "filter", "whitelist", f"{{ {ip} }}"], check=False)
        except Exception:
            pass

def save_whitelist(ips):
    try:
        with open(WHITELIST_FILE, 'w') as f:
            json.dump(ips, f)
    except Exception:
        pass

def calculate_threat(records):
    if len(records) < 3:
        return 0, "Stage 0: 正常 (データ蓄積中)", 1.0, 0.0, 0.0

    timestamps = [r['time'] for r in records]
    statuses = [r['status'] for r in records]
    paths = [r['path'] for r in records]

    # 1. 時間間隔の規則性 (変動係数: CV)
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean_int = sum(intervals) / len(intervals) if intervals else 1.0
    var = sum((x - mean_int) ** 2 for x in intervals) / len(intervals) if intervals else 0
    std_dev = math.sqrt(var)
    cv = (std_dev / mean_int) if mean_int > 0 else 1.0

    # 2. エラー集中率
    err_cnt = sum(1 for s in statuses if s in [400, 403, 404, 405, 500])
    err_ratio = err_cnt / len(statuses)

    # 3. パス探索エントロピー
    uniq_paths = len(set(paths))
    path_entropy = uniq_paths / len(paths)

    score = 0
    if cv < 0.2:
        score += 35
    elif cv < 0.4:
        score += 20

    if err_ratio >= 0.7:
        score += 40
    elif err_ratio >= 0.4:
        score += 25

    if path_entropy >= 0.7 and len(records) >= 6:
        score += 25

    score = min(100, score)
    if score >= 80:
        stage = "Stage 3: 危険 (攻撃直前 / 即時遮断)"
    elif score >= 60:
        stage = "Stage 2: 警戒 (脆弱性走査中)"
    elif score >= 30:
        stage = "Stage 1: 偵察 (情報収集の偏り)"
    else:
        stage = "Stage 0: 正常"

    return score, stage, round(cv, 2), round(err_ratio * 100, 1), round(path_entropy * 100, 1)

def get_set_elements(set_name):
    """nftablesのセット要素一覧を取得"""
    res = subprocess.getoutput(f"sudo nft list set inet filter {set_name} 2>/dev/null")
    elements = []
    if "elements = {" in res:
        block_content = res.split("elements = {")[1].split("}")[0]
        for token in block_content.split(","):
            token = token.strip()
            if token:
                elements.append(token.split()[0])
    return elements

def parse_access_line(line):
    """JSON化されたnginxアクセスログ行を安全にパースする。
    不正レコードは None を返して分析対象から完全に除外する。"""
    try:
        rec = json.loads(line)
        if not isinstance(rec, dict):
            return None
        rec['status'] = int(rec.get('status', 0))
        return rec
    except (json.JSONDecodeError, ValueError, TypeError):
        return None

def get_ext_ip():
    """[v1.2] 外部側IFの現在のIPv4アドレスを取得する"""
    try:
        out = subprocess.getoutput(f"ip -4 addr show {EXT_IF} 2>/dev/null")
        m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', out)
        return m.group(1) if m else "未取得"
    except Exception:
        return "未取得"

def is_whitelisted(ip):
    # [v1.9.7] 部分一致（"1.2.3.4" が "11.2.3.45" に含まれる等）を避け、要素単位で照合
    return ip in get_set_elements("whitelist")

def block_ip(ip):
    ip = valid_ipv4(ip)
    if not ip or is_whitelisted(ip):
        return
    subprocess.run(["sudo", "nft", "add", "element", "inet", "filter", "dynamic_blocks", f"{{ {ip} timeout 600s }}"], check=False)

def whitelist_watchdog():
    """whitelist.json を正として、nftables側の欠落を10秒ごとに自動復元する。
    systemctl restart nftables や flush ruleset による消失から自動回復。"""
    while True:
        try:
            desired = []
            if os.path.exists(WHITELIST_FILE):
                with open(WHITELIST_FILE, 'r') as f:
                    desired = [v for v in (valid_ipv4(x) for x in json.load(f)) if v]
            current = set(get_set_elements("whitelist"))
            missing = [ip for ip in desired if ip not in current]
            if missing:
                for ip in missing:
                    subprocess.run(["sudo", "nft", "add", "element", "inet", "filter",
                                    "whitelist", f"{{ {ip} }}"], check=False)
                print(f"[watchdog] whitelist restored: {missing}", flush=True)
        except Exception:
            pass
        # [v1.9.7] 管理スイッチ(wifi_mgmt)も同じく「保存状態を正」として復元する。
        #  nftables 再起動 / flush ruleset で chain が空に戻る事故（K2）への対策。
        try:
            if wifi_mgmt_desired() is True and not wifi_mgmt_is_open():
                wifi_mgmt_set(True, persist=False)
                print("[watchdog] wifi_mgmt restored (open)", flush=True)
        except Exception:
            pass
        time.sleep(10)

# [v1.9.7] 管理スイッチの状態を保存（再起動・nftables 再読込後も維持）
WIFI_STATE_FILE = "/opt/gatekeeper/wifi_mgmt.json"

def wifi_mgmt_is_open():
    res = subprocess.getoutput("sudo nft list chain inet filter wifi_mgmt 2>/dev/null")
    return "accept" in res

def wifi_mgmt_desired():
    """保存済みの希望状態。ファイルが無ければ None（＝何もしない・従来どおり）。"""
    try:
        with open(WIFI_STATE_FILE) as f:
            return bool(json.load(f).get("open"))
    except Exception:
        return None

def wifi_mgmt_set(open_, persist=True):
    subprocess.run(["sudo", "nft", "flush", "chain", "inet", "filter", "wifi_mgmt"], check=False)
    if open_:
        subprocess.run(["sudo", "nft", "add", "rule", "inet", "filter", "wifi_mgmt", "ip", "saddr", HOME_NET, "accept"], check=False)
    if persist:
        try:
            with open(WIFI_STATE_FILE, "w") as f:
                json.dump({"open": bool(open_), "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f)
        except Exception:
            pass

def nft_health_watchdog():
    """nftables.service 自体が停止していたら再起動する自己修復。"""
    while True:
        try:
            if subprocess.call(["systemctl", "is-active", "--quiet", "nftables"]) != 0:
                subprocess.run(["sudo", "systemctl", "restart", "nftables"], check=False)
                print("[watchdog] nftables was inactive; restarted", flush=True)
        except Exception:
            pass
        time.sleep(30)

# [v1.6] SSH監視: AIの目をnginxログの外まで届かせる
#  sshdの認証失敗を journalctl -kf で追跡し、5分間に5回以上の失敗IPを自動遮断する
SSH_FAIL_WINDOW = 300
# [v1.7修正] IP抽出は「from」に束縛（ユーザー名に数字が混ざっても誤抽出しない）
IP_RE = re.compile(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
ssh_fail = collections.defaultdict(lambda: collections.deque(maxlen=50))

def ssh_watch():
    # [v1.7修正] 認証ログは ssh ユニットに出るのでユニット明示で追跡（-k はカーネル専用）。
    # [v1.8修正] log_watcher と同じ死活監視（p.poll）を追加。
    # journald 再起動等で journalctl が終了しても自動で立ち上げ直し、監視の沈黙を防ぐ。
    def spawn_ssh():
        return subprocess.Popen(["journalctl", "-u", "ssh", "-u", "sshd", "-f", "-n", "0", "-o", "cat"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p = spawn_ssh()
    while True:
        line = p.stdout.readline()
        if not line:
            if p.poll() is not None:
                print("[ssh_watch] journalctl died; restarting", flush=True)
                time.sleep(1)
                p = spawn_ssh()
                continue
            time.sleep(0.2)
            continue
        if "Failed password" not in line and "Invalid user" not in line and "Connection closed by authenticating user" not in line:
            continue
        m = IP_RE.search(line)
        if not m:
            continue
        ip = m.group(1)
        if ip == BACKEND_IP or ip == "127.0.0.1":
            continue
        now = time.time()
        with stats_lock:
            dq = ssh_fail[ip]
            dq.append(now)
            while dq and now - dq[0] > SSH_FAIL_WINDOW:
                dq.popleft()
            ip_stats.setdefault(ip, {
                'score': 0, 'stage': 'Stage 0: 正常', 'cv': 1.0, 'error_ratio': 0.0,
                'entropy': 0.0, 'req_count': 0, 'last_seen': '', 'ssh_fail': 0, 'slow': ''
            })
            ip_stats[ip]['ssh_fail'] = len(dq)
            ip_stats[ip]['last_seen'] = datetime.now().strftime("%H:%M:%S")
            ip_stats[ip]['epoch'] = now
            if len(dq) >= 5:
                block_ip(ip)
                ip_stats[ip]['stage'] = "Stage 3: SSH総当たりで自動遮断"
                print(f"[ssh-watch] blocked {ip} (brute force)", flush=True)

# [v1.6] 低速スキャン第二窓（1時間規模）: 短期窓を遅く・散らす攻撃を捕まえる
SLOW_WINDOW = 3600
slow_hist = collections.defaultdict(lambda: collections.deque(maxlen=400))

def analyze_slow(ip):
    """1時間窓のエラー率・パス探索度で、短期窓には現れない低速走査を判定する"""
    dq = slow_hist[ip]
    now = time.time()
    recent = [r for r in dq if now - r['time'] <= SLOW_WINDOW]
    n = len(recent)
    if n < 30:
        return ""
    errs = sum(1 for r in recent if r['status'] in (400, 403, 404, 405, 500))
    ent = len({r['path'] for r in recent}) / n
    if errs / n >= 0.7 and n >= 50:
        return "低速走査(1h)で自動遮断"
    if errs / n >= 0.5 or (ent >= 0.8 and n >= 40):
        return "低速走査の兆し(1h)"
    return ""

def log_watcher():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    # [v1.7修正] tail の死活監視: プロセスが死んだら自動で再起動（監視の沈黙を防ぐ）
    def spawn_tail():
        return subprocess.Popen(["tail", "-F", "-n", "0", LOG_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p = spawn_tail()
    while True:
        line = p.stdout.readline()
        if not line:
            if p.poll() is not None:
                print("[log_watcher] tail died; restarting", flush=True)
                time.sleep(1)
                p = spawn_tail()
                continue
            time.sleep(0.1)
            continue

        rec = parse_access_line(line)
        if rec is None:
            continue

        ip = rec.get('remote_addr', '')
        if ip == BACKEND_IP or ip == "127.0.0.1":
            continue

        path = rec.get('request_uri', '')
        status = rec['status']

        # [v1.14.3] 紹介ページの「試してみる」の3つ（まったく同じ要求で、門番が止めたもの）は
        #  振る舞い分析の点数に数えない。デモを何度も押した人が締め出されないように。
        #  遮断（403/404）はそのまま行い、ほかの要求は今までどおり数える
        if path in DEMO_URIS and status in (403, 404):
            continue

        now = time.time()
        with stats_lock:
            ip_history[ip].append({'time': now, 'path': path, 'status': status})
            score, stage, cv, err_r, entropy = calculate_threat(ip_history[ip])
            ip_stats[ip] = {
                'score': score,
                'stage': stage,
                'cv': cv,
                'error_ratio': err_r,
                'entropy': entropy,
                'req_count': len(ip_history[ip]),
                'last_seen': datetime.now().strftime("%H:%M:%S"),
                'epoch': now
            }

            if score >= 80:
                block_ip(ip)

            # [v1.6] 低速スキャン第二窓（1時間規模）の判定
            slow_hist[ip].append({'time': now, 'path': path, 'status': status})
            slow_flag = analyze_slow(ip)
            if slow_flag == "低速走査(1h)で自動遮断":
                block_ip(ip)
            ip_stats[ip]['slow'] = slow_flag

        guard_check(rec, ip, (rec.get('request') or '').split(' ')[0], path, status)

# 起動処理
load_whitelist()
ensure_dlp_conf()
threading.Thread(target=log_watcher, daemon=True).start()
threading.Thread(target=whitelist_watchdog, daemon=True).start()
threading.Thread(target=nft_health_watchdog, daemon=True).start()
threading.Thread(target=integrity_loop, daemon=True).start()
threading.Thread(target=ssh_watch, daemon=True).start()
threading.Thread(target=pii_event_watcher, daemon=True).start()   # [v1.10.0]
threading.Thread(target=report_loop, daemon=True).start()         # [v1.11.0]
threading.Thread(target=deny_sync_loop, daemon=True).start()      # [v1.12.0]

def stats_gc_once():
    """[v1.7] 最終検知から24時間経過したIPを全辞書から掃除（メモリ肥大化の防止）"""
    now = time.time()
    with stats_lock:
        stale = [ip for ip, s in ip_stats.items()
                 if now - s.get('epoch', now) > 86400]
        for ip in stale:
            ip_stats.pop(ip, None)
            ip_history.pop(ip, None)
            ssh_fail.pop(ip, None)
            slow_hist.pop(ip, None)
            guard_track.pop(ip, None)
    return len(stale)

def stats_gc():
    while True:
        time.sleep(3600)
        try:
            n = stats_gc_once()
            if n:
                print(f"[gc] purged {n} stale IPs", flush=True)
        except Exception:
            pass

threading.Thread(target=stats_gc, daemon=True).start()

HTML_PAGE = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>micro-monban 管理画面</title>
<style>
  body { background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; }
  h1 { font-size: 20px; margin-bottom: 20px; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
  .card { background: #1e293b; border-radius: 8px; padding: 16px; border: 1px solid #334155; }
  .card h2 { font-size: 14px; text-transform: uppercase; color: #94a3b8; margin: 0 0 12px 0; }
  .metric { font-size: 26px; font-weight: bold; color: #f8fafc; }
  .metric-sub { font-size: 12px; color: #64748b; margin-top: 4px; }
  .status-badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: bold; background: #065f46; color: #34d399; }
  .status-badge.off { background: #7f1d1d; color: #f87171; }
  
  .switch-box { display: flex; align-items: center; justify-content: space-between; margin-top: 10px; padding: 12px; background: #0b1329; border-radius: 6px; border: 1px solid #1e293b; }
  .btn-toggle { font-size: 13px; font-weight: bold; padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; transition: 0.2s; }
  .btn-on { background: #ef4444; color: white; }
  .btn-off { background: #10b981; color: white; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; margin-top: 8px; }
  th { background: #0b1329; color: #94a3b8; padding: 8px 12px; border-bottom: 1px solid #334155; }
  td { padding: 8px 12px; border-bottom: 1px solid #1e293b; }
  .bar-container { background: #334155; border-radius: 4px; height: 10px; width: 80px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 8px; }
  .bar-fill { height: 100%; border-radius: 4px; }

  .btn-sm { color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: bold; margin-right: 4px; }
  .btn-blue { background: #0284c7; }
  .btn-green { background: #059669; }
  .btn-red { background: #dc2626; }
  .btn-gray { background: #475569; }

  .ip-tag { display: inline-flex; align-items: center; gap: 8px; padding: 4px 10px; border-radius: 6px; margin-right: 8px; margin-bottom: 8px; font-size: 13px; }
  .ip-tag.blocked { background: #450a0a; border: 1px solid #7f1d1d; }
  .ip-tag.allowed { background: #064e3b; border: 1px solid #047857; }

  pre { background: #020617; padding: 12px; border-radius: 6px; font-size: 12px; color: #cbd5e1; overflow-x: auto; max-height: 200px; border: 1px solid #1e293b; }
  input[type="text"] { background: #020617; border: 1px solid #334155; color: white; padding: 6px 10px; border-radius: 4px; font-size: 13px; width: 180px; }
</style>
</head>
<body>
  <h1>🛡️ micro-monban ダッシュボード <span style="font-size:11px; color:#94a3b8; font-weight:normal;">— ラズパイで作る、小さいけれど強い門番</span> <span style="font-size:11px; color:#64748b; border:1px solid #334155; border-radius:6px; padding:2px 6px; font-weight:normal;">v1.14.3</span></h1>
  
  <div id="emergency-banner" style="display:none; background:#450a0a; border:2px solid #ef4444; border-radius:8px; padding:14px 16px; margin-bottom:20px;">
  <div style="font-size:15px; font-weight:bold; color:#fecaca;">🚨 緊急アラート</div>
  <div id="emg-text" style="margin-top:6px; font-size:13px; color:#fca5a5; white-space:pre-wrap;"></div>
  <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
    <button class="btn-sm btn-red" onclick="killSwitch('restore')">🔓 復旧（遮断解除）</button>
    <button class="btn-sm btn-gray" onclick="dismissAlert()">✕ 誤検知として解除</button>
  </div>
  </div>
<div class="grid">

  <div class="card" style="border-color: #3b82f6;">
      <h2>外部側 管理アクセス (<span id="ext-if-name">--</span> : @@DASH_PORT@@)</h2>
      <div class="switch-box">
        <div><span class="status-badge off" id="wifi-mgmt-status">停止中 (BLOCKED)</span></div>
        <button id="wifi-toggle-btn" class="btn-toggle btn-off" onclick="toggleWifiMgmt()">公開する</button>
      </div>
      <div class="metric-sub" id="ext-ip-line" style="margin-top: 8px;">外部側IP: 取得中...</div>
      <div class="metric-sub">外部側ネットワークからのポート @@DASH_PORT@@ スキャンを完全無言破棄(DROP)します。開放中はBasic認証が必要です（ユーザー名: admin）。</div>
      <div class="metric-sub" style="margin-top:4px;">@@DASH_MODE_NOTE@@</div>
    </div>

    <div class="card">
      <h2>System Status</h2>
      <div class="metric" id="cpu-temp">-- °C</div>
      <div class="metric-sub" id="sys-uptime">Uptime: --</div>
    </div>

    <div class="card">
      <h2>micro-monban Services</h2>
      <div style="display:flex; gap:8px; align-items:center; margin-top:8px;">
        Nginx: <span class="status-badge" id="nginx-status">Checking</span>
        nftables: <span class="status-badge" id="nft-status">Checking</span>
      </div>
      <div style="margin-top:16px;">
        <button class="btn-sm btn-blue" style="padding: 6px 12px;" onclick="reloadNginx()">Nginx 設定再読み込み</button>
      </div>
    </div>
  </div>

  <div class="card" id="pii-card" style="margin-bottom: 20px; border-color: #f472b6;">
    <h2 style="color:#f9a8d4;">🧾 個人情報 一括持ち出しガード <span style="font-size:10px; color:#64748b; font-weight:normal;">(v1.10)</span></h2>
    <div class="switch-box" style="margin-top:0;">
      <div>
        <span class="status-badge off" id="pii-status">確認中</span>
        <span class="metric-sub" id="pii-svc" style="margin-left:8px;"></span>
      </div>
      <button id="pii-toggle-btn" class="btn-toggle btn-off" onclick="piiToggle()">ONにする</button>
    </div>
    <div class="metric-sub" style="margin-top:8px;">サーバーからの応答に含まれる個人情報（メール・電話・カード番号・マイナンバー・住所）を数え、<b style="color:#e2e8f0;">数件までは通し</b>、それを超える一括送信を止めます（403）。本人が自分の情報を見る・変える程度は止まりません。</div>
    <div style="display:flex; gap:14px; flex-wrap:wrap; margin-top:10px; align-items:center; font-size:12px;">
      <label>1回の応答で <input type="number" id="pii-max" min="1" style="width:56px;"> 件まで通す</label>
      <label>同じ接続元へ10分間で合計 <input type="number" id="pii-win" min="1" style="width:64px;"> 件まで</label>
      <label><input type="checkbox" id="pii-monitor"> 止めずに記録だけする（試験用）</label>
      <button class="btn-sm btn-blue" onclick="piiSave()">設定を保存</button>
    </div>
    <div class="metric-sub" id="pii-stats" style="margin-top:8px;">--</div>
    <table style="margin-top:8px;">
      <thead><tr><th>時刻</th><th>接続元</th><th>パス</th><th>推定件数</th><th>内訳</th><th>処置</th></tr></thead>
      <tbody id="pii-tbody"><tr><td colspan="6" style="text-align:center; color:#64748b;">記録なし</td></tr></tbody>
    </table>
  </div>

  <div class="card" id="pub-card" style="margin-bottom: 20px; border-color: #22c55e;">
    <h2 style="color:#86efac;">🌐 インターネット公開 <span style="font-size:10px; color:#64748b; font-weight:normal;">(v1.12)</span></h2>
    <div style="font-size:14px; font-weight:bold;" id="pub-now">確認中...</div>
    <div class="metric-sub" style="margin-top:4px;">家庭内LANだけで使っている門番を、インターネットから見られるようにします。<b style="color:#e2e8f0;">ルーターのポート開放ができる人は A、難しい人は B</b> を選んでください。どちらも独自ドメイン（例: www.example.jp）が必要です。</div>
    <div class="grid" style="margin-top:12px; margin-bottom:0;">
      <div class="card" style="background:#0b1329;">
        <h2 style="color:#e2e8f0; text-transform:none;">A. Let's Encrypt（ポート開放ができる人）</h2>
        <ol class="metric-sub" style="padding-left:18px; margin:0 0 8px 0; line-height:1.7;">
          <li>ドメイン管理画面で <b>A レコード</b> を登録（値 = この家の外向き IP <button class="btn-sm btn-gray" onclick="pubGlobalIp()">調べる</button> <span id="pub-gip" style="color:#e2e8f0;"></span>）</li>
          <li>ルーターで <b>80番と443番</b> を <b id="pub-extip">この門番</b> へ転送（「MyDNS の DNS」で確認するときは 443番だけ）</li>
          <li>下に入力して「事前確認」→ 成功したら「本番取得して公開」</li>
        </ol>
        <div style="display:flex; gap:6px; flex-wrap:wrap; font-size:12px; align-items:center;">
          <input type="text" id="pub-domain" placeholder="ドメイン 例: www.example.jp" style="width:200px;">
          <input type="text" id="pub-email" placeholder="連絡用メール（期限切れ通知が届く）" style="width:220px;">
        </div>
        <div style="margin-top:6px; font-size:12px;">持ち主の確認の方法:
          <label style="margin-left:6px;"><input type="radio" name="pub-method" value="webroot" checked onchange="pubMethodUi()"> 80番（標準）</label>
          <label style="margin-left:8px;"><input type="radio" name="pub-method" value="dns-mydns" onchange="pubMethodUi()"> MyDNS の DNS（80番が外から届かないとき）</label>
        </div>
        <div id="pub-mydns" style="display:none; margin-top:6px; font-size:12px; padding:6px 8px; border:1px dashed #334155; border-radius:6px;">
          <div class="metric-sub" style="margin-bottom:4px;">DDNS に MyDNS（mydns.jp）を使っている場合だけ選べます。mydns.jp にログインするときの<b>マスターID とパスワード</b>を入れてください。門番の中の root だけが読めるファイルに保存し、証明書の自動更新にも使います（画面や記録には出しません）。</div>
          <input type="text" id="pub-mid" placeholder="MyDNS マスターID" autocomplete="off" style="width:160px;">
          <input type="password" id="pub-mpw" placeholder="MyDNS パスワード" autocomplete="new-password" style="width:160px;">
          <span id="pub-mydns-state" style="margin-left:6px; color:#94a3b8;"></span>
        </div>
        <label style="display:block; margin-top:6px; font-size:12px;"><input type="checkbox" id="pub-agree"> <a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener" style="color:#7dd3fc;">Let's Encrypt の利用規約</a> に同意します</label>
        <div style="margin-top:8px; display:flex; gap:6px; flex-wrap:wrap;">
          <button class="btn-sm btn-blue pub-btn" onclick="pubLe('le_check')">① 事前確認（試験取得）</button>
          <button class="btn-sm btn-green pub-btn" onclick="pubLe('le_issue')">② 本番取得して公開</button>
          <button class="btn-sm btn-gray pub-btn" onclick="pubSimple('le_revert', 'ドメインでの公開（Let’s Encrypt）をやめます。よろしいですか？')">公開をやめる</button>
          <button class="btn-sm btn-gray pub-btn" onclick="pubSimple('le_renew_test', '証明書の自動更新を、試験環境で予行演習します（本物の証明書は変わりません。数分かかります）。よろしいですか？')">更新の予行演習</button>
        </div>
        <div class="metric-sub" id="pub-le-state" style="margin-top:6px;"></div>
        <div class="metric-sub" id="pub-le-renew" style="margin-top:2px;"></div>
      </div>
      <div class="card" style="background:#0b1329;">
        <h2 style="color:#e2e8f0; text-transform:none;">B. Cloudflare Tunnel（ポート開放が難しい人）</h2>
        <ol class="metric-sub" style="padding-left:18px; margin:0 0 8px 0; line-height:1.7;">
          <li>Cloudflare の無料アカウントを作り、ドメインを登録</li>
          <li>Zero Trust → Networks → Tunnels →「Create a tunnel」→ <b>Cloudflared</b> を選び、表示された<b>トークン</b>をコピー</li>
          <li>同じ画面の Public Hostname で、ドメイン → Service <b>HTTPS</b> : <b>localhost:443</b>、Additional settings → TLS →「<b>No TLS Verify</b>」を ON</li>
          <li>下で「cloudflared を導入」→ トークンを貼って「接続」</li>
        </ol>
        <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
          <button class="btn-sm btn-blue pub-btn" onclick="pubSimple('cf_install', 'Cloudflare 公式の配布元から cloudflared を導入します（数分かかります）。よろしいですか？')">cloudflared を導入</button>
          <input type="password" id="pub-token" placeholder="トークンを貼り付け" style="width:220px;">
          <button class="btn-sm btn-green pub-btn" onclick="pubCf()">接続</button>
          <button class="btn-sm btn-gray pub-btn" onclick="pubSimple('cf_disconnect', 'Cloudflare Tunnel の接続を外します。よろしいですか？')">接続を外す</button>
        </div>
        <div class="metric-sub" id="pub-cf-state" style="margin-top:6px;"></div>
      </div>
    </div>
    <div style="margin-top:10px;">
      <b style="font-size:13px;">進み具合</b> <span class="metric-sub" id="pub-job-head"></span>
      <pre id="pub-log" style="max-height:220px; overflow:auto; margin-top:4px; white-space:pre-wrap;">（まだ操作していません）</pre>
    </div>
  </div>

  <div class="card" id="rep-card" style="margin-bottom: 20px; border-color: #38bdf8;">
    <h2 style="color:#7dd3fc;">📨 設定レポート（引き継ぎ用） <span style="font-size:10px; color:#64748b; font-weight:normal;">(v1.11)</span></h2>
    <div class="metric-sub">門番の今の状態（版・サービス・ネットワーク・整合性・各ガードの設定・ルール・警報・バックアップ）を1つの文書にまとめ、メールで送ります。冒頭に「異常の見分け方と最初の一手」が入るので、詳しくない人にも渡せます。パスワード・鍵・メール認証情報は含みません。</div>
    <div style="display:flex; gap:14px; flex-wrap:wrap; margin-top:10px; align-items:center; font-size:12px;">
      <label><input type="checkbox" id="rep-enabled"> 毎週送る</label>
      <label><select id="rep-wd"><option value="0">月</option><option value="1">火</option><option value="2">水</option><option value="3">木</option><option value="4">金</option><option value="5">土</option><option value="6">日</option></select> 曜日</label>
      <label><input type="number" id="rep-hour" min="0" max="23" style="width:52px;"> 時</label>
      <label><input type="checkbox" id="rep-change"> 設定が変わったら送る</label>
    </div>
    <div style="margin-top:8px; font-size:12px; color:#94a3b8;">宛先（カンマ区切り・空ならメール通知の宛先へ）:</div>
    <input type="text" id="rep-to" placeholder="例: me@example.com, colleague@example.com" style="width:100%; box-sizing:border-box; margin-top:4px;">
    <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
      <button class="btn-sm btn-blue" onclick="repSave()">設定を保存</button>
      <button class="btn-sm btn-gray" onclick="repPreview()">内容を見る</button>
      <button class="btn-sm btn-gray" onclick="repDownload()">ファイルに保存</button>
      <button class="btn-sm btn-green" onclick="repSend()">今すぐ送信</button>
      <span class="metric-sub" id="rep-state"></span>
    </div>
    <pre id="rep-preview" style="display:none; max-height:420px; overflow:auto; margin-top:8px; white-space:pre-wrap;"></pre>
  </div>

  <div class="card" style="margin-bottom: 20px; border-color: #10b981;">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2 style="color: #34d399; margin: 0;">✅ 許可リスト (Whitelist / 常時バイパス)</h2>
      <div>
        <input type="text" id="manual-whitelist-ip" placeholder="例: 192.168.1.50">
        <button class="btn-sm btn-green" style="padding: 6px 12px;" onclick="addManualWhitelist()">IPを追加</button>
      </div>
    </div>
    <div class="metric-sub" style="margin-bottom: 12px;">このリストに登録されたIPはAI検知・自動遮断の対象外となり、最優先で通信が通過します。nftables再起動後もウォッチドッグが自動復元します。</div>
    <div id="whitelist-container">
      <span style="color:#64748b; font-size:13px;">登録されている許可IPはありません。</span>
    </div>
  </div>

  <div class="card" style="margin-bottom: 20px; border-color: #ef4444;">
    <h2 style="color: #f87171;">🚫 AI 動的遮断リスト (nftables dynamic_blocks: 10分間自動DROP)</h2>
    <div class="metric-sub" style="margin-bottom: 12px;">「許可リストへ移動」を押すと遮断が即時解除され、常時許可リストへ登録されます。</div>
    <div id="blocked-container">
      <span style="color:#64748b; font-size:13px;">現在遮断中のIPはありません。</span>
    </div>
  </div>

  <div class="card" style="margin-bottom: 20px; border-color: #f59e0b;">
    <h2>🔒 DLP 機密マスキング ルール（個別ON/OFF）</h2>
    <div class="metric-sub" style="margin-bottom: 8px;">応答本文のマスキング（subs_filter）ルールです。チェックを外すと即時OFF（nginx -t 検証のうえ反映・失敗時は自動取消）。パターンにシングルクォート ' は使えません。マスキングは大小文字を区別せず行われます（テストも同じ基準で判定します）。</div>
    <table id="dlp-table">
      <thead>
        <tr><th>ルール名</th><th>パターン</th><th>置換後</th><th>状態</th></tr>
      </thead>
      <tbody id="dlp-tbody">
        <tr><td colspan="4" style="text-align:center; color:#64748b;">読み込み中...</td></tr>
      </tbody>
    </table>
    <div style="margin-top: 10px; display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
      <input type="text" id="dlp-name" placeholder="ルール名（例: 顧客ID）" style="width: 150px;">
      <input type="text" id="dlp-pattern" placeholder="正規表現パターン" style="width: 280px;">
      <input type="text" id="dlp-replacement" placeholder="置換後テキスト" style="width: 200px;">
      <button class="btn-sm btn-blue" onclick="dlpAdd()">ルール追加</button>
    </div>
    <div style="margin-top: 12px;">
      <textarea id="dlp-testtext" placeholder="マスキング試験したいテキストを貼り付け（例: 電話番号やトークンを含むJSON）" style="width:100%; box-sizing:border-box; height:56px; background:#020617; color:#e2e8f0; border:1px solid #334155; border-radius:4px; padding:6px; font-size:12px;"></textarea>
      <button class="btn-sm btn-gray" style="margin-top:6px;" onclick="dlpTest()">マスキング試験</button>
      <pre id="dlp-testout" style="display:none; margin-top:8px;"></pre>
    </div>
  </div>

  <div class="card" style="margin-bottom: 20px; border-color: #a855f7;">
    <h2>🧬 セルフ整合性監視（変化線モニタ） <span id="integ-ro" style="font-size:10px; color:#64748b; font-weight:normal;"></span></h2>
    <div style="display:flex; gap:10px; align-items:center; margin-bottom:6px;">
      <span style="font-weight:bold;" id="integ-state">---</span>
      <span class="metric-sub">最終チェック: <span id="integ-time">--</span></span>
      <button class="btn-sm btn-blue" onclick="integrityRecheck()">再チェック</button>
    </div>
    <pre id="integ-findings">読み込み中...</pre>
    <div class="metric-sub" style="margin-top:6px;">重要ファイルの台帳照合・外向き接続・予定外ポートを5分ごとに点検します。読み取り専用モード中に「重大（改竄の疑い）」を検知すると120秒後に自動再起動し、書き込みを全て破棄して本来の自己で立ち上がります。</div>
  </div>

  <div class="card" style="margin-bottom: 20px; border-color: #ef4444;">
    <h2>🛑 出口防御 &amp; 緊急ブレーカー <span style="font-size:10px; color:#64748b; font-weight:normal;">(v1.9)</span></h2>
    <div class="metric-sub">大量ダンプ・業務操作のない個人情報の連続取得・5xx連発を検知してアラート（設定で管理者メール通知も可）。ブレーカーは独立nftテーブルで動くため、復旧しても通常の遮断リストは壊れません。既定は監視・通報のみ（自動IP遮断OFF）。</div>
    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; align-items:center;">
      <button class="btn-sm btn-red" onclick="killSwitch('cut_ext')">🌐 外部入口を遮断</button>
      <button class="btn-sm btn-red" onclick="killSwitch('cut_link')">🔌 バックエンドと分離</button>
      <button class="btn-sm btn-gray" onclick="killSwitch('restore')">🔓 復旧</button>
      <span id="breaker-state" style="font-weight:bold; font-size:13px;">通常運用</span>
    </div>
    <div style="margin-top:14px; border-top:1px solid #334155; padding-top:10px;">
      <b style="font-size:13px;">監視しきい値</b>
      <div style="display:flex; gap:12px; flex-wrap:wrap; margin-top:6px; align-items:center; font-size:12px;">
        <label><input type="checkbox" id="guard-auto"> 検知時に自動IP遮断</label>
        <label>個人情報連続 <input type="number" id="g-harvest" style="width:60px;"> 回</label>
        <label>PII応答 <input type="number" id="g-burst" style="width:60px;"> 件/分</label>
        <label>単応答上限 <input type="number" id="g-maxmb" style="width:64px;"> MB</label>
        <label>10分累計 <input type="number" id="g-volmb" style="width:64px;"> MB</label>
        <label>5xx <input type="number" id="g-e5" style="width:56px;"> 回/分</label>
      </div>
      <div style="margin-top:6px; font-size:12px; color:#94a3b8;">個人情報パス（カンマ区切り・前方一致）:</div>
      <input type="text" id="g-piipaths" style="width:100%; box-sizing:border-box; margin-top:4px;">
      <button class="btn-sm btn-blue" style="margin-top:8px;" onclick="guardSave()">監視設定を保存</button> <span id="guard-dirty" class="metric-sub"></span>
    </div>
    <div style="margin-top:14px; border-top:1px solid #334155; padding-top:10px;">
      <b style="font-size:13px;">📧 管理者メール通知</b>
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:6px; align-items:center; font-size:12px;">
        <label><input type="checkbox" id="m-enabled"> 有効</label>
        <label>SMTP <input type="text" id="m-host" placeholder="smtp.example.com" style="width:150px;"></label>
        <label>ポート <input type="number" id="m-port" style="width:64px;"></label>
        <label>USER <input type="text" id="m-user" style="width:120px;"></label>
        <label>PASS <input type="password" id="m-pass" placeholder="(変更時のみ)" style="width:120px;"></label>
        <label>宛先 <input type="text" id="m-to" placeholder="admin@example.com" style="width:150px;"></label>
      </div>
      <div style="margin-top:8px; display:flex; gap:8px; align-items:center;">
        <button class="btn-sm btn-blue" onclick="mailSave()">保存</button>
        <button class="btn-sm btn-gray" onclick="mailTest()">テスト送信</button>
        <span id="mail-state" class="metric-sub"></span>
      </div>
      <div class="metric-sub" style="margin-top:4px;">587=STARTTLS / 465=SSL。資格情報は /opt/gatekeeper/alertmail.json (600) に保存され、画面には返しません。</div>
    </div>
    <div style="margin-top:10px;">
      <b style="font-size:13px;">📜 検知履歴（直近50件）</b>
      <pre id="alert-history" style="max-height:160px; overflow:auto; margin-top:4px;">読み込み中...</pre>
    </div>
  </div>

  <div class="card" style="margin-bottom: 20px; border-color: #6366f1;">
    <h2>⚡ AI 振る舞い分析 & 攻撃予測 (Real-time Threat Radar)</h2>
    <table id="threat-table">
      <thead>
        <tr>
          <th>接続元 IP</th>
          <th>脅威スコア</th>
          <th>判定フェーズ</th>
          <th>特徴量 (時間均一度 / エラー率 / パス探索度)</th>
          <th>最終検知</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody id="threat-tbody">
        <tr><td colspan="6" style="text-align:center; color:#64748b;">外部アクセス待機中...</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card" style="margin-bottom: 20px;">
    <h2>直近のアクセス / WAF 遮断ログ (末尾20行)</h2>
    <pre id="access-log">読み込み中...</pre>
  </div>

<script>
// [v1.9.7] CSRF対策: この画面からの POST には必ず X-GK-CSRF ヘッダを付ける
(function () {
  const _fetch = window.fetch.bind(window);
  window.fetch = function (url, opts) {
    opts = opts || {};
    if ((opts.method || 'GET').toUpperCase() === 'POST') {
      const h = new Headers(opts.headers || {});
      h.set('X-GK-CSRF', '1');
      opts.headers = h;
    }
    return _fetch(url, opts);
  };
})();
let currentWifiMgmtOpen = false;

// [v1.14.2] 入力中の欄を、2秒ごとの再表示で上書きしない
//  ・欄を触ったら「未保存」にし、保存するまでその設定の欄は再表示で書き換えない
//  （以前はチェックボックスが保存前に元に戻り、「有効」が OFF のまま保存されることがあった）
var FORM_GROUPS = {
  mail:  ['m-enabled', 'm-host', 'm-port', 'm-user', 'm-pass', 'm-to'],
  guard: ['guard-auto', 'g-harvest', 'g-burst', 'g-maxmb', 'g-volmb', 'g-e5', 'g-piipaths'],
  rep:   ['rep-enabled', 'rep-wd', 'rep-hour', 'rep-change', 'rep-to']
};
var formDirty = {};
function markDirty(g) {
  formDirty[g] = true;
  const st = document.getElementById(g === 'mail' ? 'mail-state' : (g === 'rep' ? 'rep-state' : 'guard-dirty'));
  if (st) { st.innerText = '未保存の変更があります（「保存」を押してください）'; st.style.color = '#fbbf24'; }
}
document.addEventListener('DOMContentLoaded', function () {
  for (const g of Object.keys(FORM_GROUPS)) {
    for (const id of FORM_GROUPS[g]) {
      const el = document.getElementById(id);
      if (!el) continue;
      el.addEventListener('input', function () { markDirty(g); });
      el.addEventListener('change', function () { markDirty(g); });
    }
  }
});
function clearDirty(g) {
  formDirty[g] = false;
  const st = document.getElementById(g === 'mail' ? 'mail-state' : (g === 'rep' ? 'rep-state' : 'guard-dirty'));
  if (st) st.style.color = '';
}

async function gkPost(url, obj) {
  const res = await fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(obj || {}) });
  return await res.json();
}

async function killSwitch(action) {
  const q = {
    cut_ext: '外部入口（外部IF）への全入力と転送を遮断します。解除するまで外部から一切アクセスできなくなります。よろしいですか？',
    cut_link: 'バックエンドサーバーとの通信を全面的に分離します。Webサービスは停止しますが、管理画面とメール通知は生きます。よろしいですか？',
    restore: '緊急遮断を解除し、通常運用に戻します。よろしいですか？'
  };
  if (!confirm(q[action])) return;
  const r = await gkPost('/api/killswitch', { action: action, confirm: 'yes' });
  alert(r.msg || (r.success ? '実行しました' : '失敗しました'));
  updateData();
}

async function guardSave() {
  const r = await gkPost('/api/guard/set', {
    auto_block: document.getElementById('guard-auto').checked,
    harvest_threshold: +document.getElementById('g-harvest').value,
    pii_burst_60s: +document.getElementById('g-burst').value,
    max_body_mb: +document.getElementById('g-maxmb').value,
    bytes10m_mb: +document.getElementById('g-volmb').value,
    err5_rate: +document.getElementById('g-e5').value,
    pii_paths: document.getElementById('g-piipaths').value
  });
  if (r.success) { clearDirty('guard'); const gd = document.getElementById('guard-dirty'); if (gd) gd.innerText = ''; }
  alert(r.success ? ('監視設定を保存しました（自動IP遮断: ' + (document.getElementById('guard-auto').checked ? 'ON' : 'OFF') + '）') : '保存に失敗しました');
  updateData();
}

async function mailSave() {
  const body = {
    enabled: document.getElementById('m-enabled').checked,
    host: document.getElementById('m-host').value,
    port: +document.getElementById('m-port').value,
    user: document.getElementById('m-user').value,
    to: document.getElementById('m-to').value
  };
  const p = document.getElementById('m-pass').value;
  if (p) body.pass = p;
  const r = await gkPost('/api/mail/set', body);
  if (r.success) { clearDirty('mail'); document.getElementById('m-pass').value = ''; }
  alert(r.success ? ('メール設定を保存しました（通知: ' + (body.enabled ? '有効' : '無効') + '）') : '保存に失敗しました');
  updateData();
}

async function mailTest() {
  const r = await gkPost('/api/mail/test', {});
  alert(r.msg || (r.success ? '送信しました' : '失敗しました'));
}

// [v1.10.0] 個人情報 一括持ち出しガード
let piiCfg = null;
async function piiToggle() {
  if (!piiCfg) return;
  const turnOn = !piiCfg.enabled;
  if (!turnOn && !confirm('個人情報 一括持ち出しガードを OFF にします。応答は検査されずに通過します。よろしいですか？')) return;
  const r = await gkPost('/api/pii_guard/set', { enabled: turnOn });
  if (!r.success) alert('切り替えに失敗しました');
  updateData();
}
async function piiSave() {
  const r = await gkPost('/api/pii_guard/set', {
    max_per_response: +document.getElementById('pii-max').value,
    window_limit: +document.getElementById('pii-win').value,
    monitor_only: document.getElementById('pii-monitor').checked
  });
  alert(r.success ? '設定を保存しました（数秒以内に反映）' : '保存に失敗しました');
  updateData();
}
function piiRender(p) {
  if (!p) return;
  const c = p.cfg || {}, st = p.stats || {};
  piiCfg = c;
  const badge = document.getElementById('pii-status'), btn = document.getElementById('pii-toggle-btn');
  if (!p.service) {
    badge.className = 'status-badge off'; badge.innerText = '⚠ 停止中（サービス停止）';
  } else if (!c.enabled) {
    badge.className = 'status-badge off'; badge.innerText = 'OFF（検査していません）';
  } else if (c.monitor_only) {
    badge.className = 'status-badge'; badge.style.background = '#78350f'; badge.style.color = '#fbbf24';
    badge.innerText = 'ON（記録のみ・止めない）';
  } else {
    badge.className = 'status-badge';
    badge.innerText = 'ON（超えたら遮断）';
  }
  if (!(p.service && c.enabled && c.monitor_only)) { badge.style.background = ''; badge.style.color = ''; }
  btn.className = 'btn-toggle ' + (c.enabled ? 'btn-on' : 'btn-off');
  btn.innerText = c.enabled ? 'OFFにする' : 'ONにする';
  document.getElementById('pii-svc').innerText = p.service ? 'サービス稼働中' : 'サービス gatekeeper-piiguard が動いていません';
  const ids = ['pii-max', 'pii-win'];
  if (!(document.activeElement && ids.includes(document.activeElement.id))) {
    document.getElementById('pii-max').value = c.max_per_response ?? 5;
    document.getElementById('pii-win').value = c.window_limit ?? 30;
    document.getElementById('pii-monitor').checked = !!c.monitor_only;
  }
  document.getElementById('pii-stats').innerText =
    '集計（' + (st.since || '--') + ' から）: 中継 ' + (st.requests || 0) + ' 件 / 検査 ' + (st.inspected || 0) +
    ' 件 / 個人情報を含む応答 ' + (st.with_pii || 0) + ' 件 / 遮断 ' + (st.blocked || 0) + ' 件 / 記録のみ ' + (st.monitored || 0) + ' 件';
  const tb = document.getElementById('pii-tbody');
  const evs = p.events || [];
  tb.textContent = '';
  if (evs.length === 0) {
    const td = tb.insertRow().insertCell(); td.colSpan = 6; td.style.textAlign = 'center'; td.style.color = '#64748b'; td.textContent = '記録なし';
    return;
  }
  for (const e of evs) {
    const tr = tb.insertRow();
    const cats = Object.entries(e.cats || {}).map(([k, v]) => k + ' ' + v).join(' / ');
    for (const v of [e.time, e.ip, e.path, '約 ' + e.est + ' 件', cats]) tr.insertCell().textContent = v;
    const a = tr.insertCell();
    a.textContent = e.action === 'block' ? '遮断' : '記録のみ';
    a.style.color = e.action === 'block' ? '#f87171' : '#fbbf24';
    a.title = e.reason || '';
  }
}

// [v1.12.0] インターネット公開ウィザード
let pubGip = '';
async function pubGlobalIp() {
  const r = await gkPost('/api/publish/global_ip', {});
  pubGip = r.ip || '';
  document.getElementById('pub-gip').innerText = r.msg || '';
}
function pubMethod() {
  const el = document.querySelector('input[name="pub-method"]:checked');
  return el ? el.value : 'webroot';
}
function pubMethodUi() {
  document.getElementById('pub-mydns').style.display = pubMethod() === 'dns-mydns' ? 'block' : 'none';
}
let pubMethodInit = false;
async function pubLe(act) {
  const body = { domain: document.getElementById('pub-domain').value, email: document.getElementById('pub-email').value,
                 agree: document.getElementById('pub-agree').checked, global_ip: pubGip, method: pubMethod() };
  if (body.method === 'dns-mydns') {
    body.mydns_id = document.getElementById('pub-mid').value;
    body.mydns_pw = document.getElementById('pub-mpw').value;
  }
  if (act === 'le_issue') {
    if (!confirm('本番の証明書を取得し、このドメインで公開します。よろしいですか？')) return;
    body.confirm = 'yes';
  }
  const r = await gkPost('/api/publish/' + act, body);
  document.getElementById('pub-mpw').value = '';
  if (!r.success) alert(r.msg || '開始できませんでした');
  updateData();
}
async function pubCf() {
  const t = document.getElementById('pub-token').value;
  if (!t) { alert('トークンを貼り付けてください'); return; }
  const r = await gkPost('/api/publish/cf_connect', { token: t });
  document.getElementById('pub-token').value = '';
  if (!r.success) alert(r.msg || '開始できませんでした');
  updateData();
}
async function pubSimple(act, q) {
  if (q && !confirm(q)) return;
  const r = await gkPost('/api/publish/' + act, {});
  if (!r.success) alert(r.msg || '開始できませんでした');
  updateData();
}
function pubRender(p) {
  if (!p) return;
  const now = [];
  if (p.le && p.le.active) now.push('A. Let’s Encrypt で公開中: https://' + p.le.domain + '/（証明書 残り ' + ((p.le_cert || {}).days ?? '?') + ' 日）');
  if (p.cf && p.cf.active) now.push('B. Cloudflare Tunnel ' + (p.cf_service ? '接続中' : '（cloudflared 停止中）'));
  const el = document.getElementById('pub-now');
  el.innerText = now.length ? '✓ ' + now.join(' / ') : '未公開（家庭内LANのみ）';
  el.style.color = now.length ? '#86efac' : '#94a3b8';
  document.getElementById('pub-le-state').innerText = 'certbot: ' + (p.certbot ? '導入済み' : '未導入') + (p.le && p.le.domain ? ' / 登録ドメイン: ' + p.le.domain : '');
  // [v1.14.0] 更新の方法と予行演習の結果
  const c = p.le_cert || {};
  const mname = { 'dns-mydns': 'MyDNS の DNS', 'webroot': '80番', 'manual': '手動' };
  const rn = [];
  if (c.exists) {
    rn.push('更新の方法: ' + (mname[c.method] || c.method || '不明'));
    rn.push('自動更新: ' + (c.timer ? '有効' : '無効（certbot.timer が止まっています）'));
    if (c.end) rn.push('期限: ' + c.end);
    const t = c.renew_test || {};
    rn.push('予行演習: ' + (t.at ? ((t.ok ? '成功 ' : '失敗 ') + t.at) : 'まだ'));
  }
  const rEl = document.getElementById('pub-le-renew');
  rEl.innerText = rn.join(' / ');
  rEl.style.color = (c.exists && (!c.timer || (c.renew_test && c.renew_test.at && !c.renew_test.ok))) ? '#fbbf24' : '';
  document.getElementById('pub-mydns-state').innerText = p.mydns_login ? 'ログイン情報: 保存済み（入れ直すときだけ入力）' : 'ログイン情報: 未保存';
  if (!pubMethodInit) {
    pubMethodInit = true;
    const m = (p.le && p.le.method) || c.method;
    if (m === 'dns-mydns') {
      for (const r of document.querySelectorAll('input[name="pub-method"]')) r.checked = (r.value === 'dns-mydns');
      pubMethodUi();
    }
  }
  document.getElementById('pub-cf-state').innerText = 'cloudflared: ' + (p.cloudflared ? '導入済み' : '未導入') + ' / 接続: ' + (p.cf_service ? 'あり' : 'なし');
  const ids = ['pub-domain', 'pub-email'];
  if (p.le && !(document.activeElement && ids.includes(document.activeElement.id))) {
    if (!document.getElementById('pub-domain').value) document.getElementById('pub-domain').value = p.le.domain || '';
    if (!document.getElementById('pub-email').value) document.getElementById('pub-email').value = p.le.email || '';
  }
  const j = p.job || {};
  document.getElementById('pub-job-head').innerText = j.name ? (j.name + '：' + (j.running ? '実行中…' : (j.ok ? '完了' : '失敗')) + '（' + j.started + '）') : '';
  if (j.log && j.log.length) document.getElementById('pub-log').textContent = j.log.join(String.fromCharCode(10));
  for (const b of document.querySelectorAll('.pub-btn')) b.disabled = !!j.running;
}

// [v1.11.0] 設定レポート
async function repSave() {
  const r = await gkPost('/api/report/set', {
    enabled: document.getElementById('rep-enabled').checked,
    weekday: +document.getElementById('rep-wd').value,
    hour: +document.getElementById('rep-hour').value,
    on_change: document.getElementById('rep-change').checked,
    to: document.getElementById('rep-to').value
  });
  if (r.success) clearDirty('rep');
  alert(r.success ? '設定を保存しました' : '保存に失敗しました');
  updateData();
}
async function repPreview() {
  const box = document.getElementById('rep-preview');
  if (box.style.display === 'block') { box.style.display = 'none'; return; }
  box.textContent = '作成中...'; box.style.display = 'block';
  const r = await gkPost('/api/report/preview', {});
  box.textContent = r.text || '作成できませんでした';
}
async function repDownload() {
  const r = await gkPost('/api/report/preview', {});
  if (!r.text) { alert('作成できませんでした'); return; }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([r.text], {type: 'text/markdown;charset=utf-8'}));
  a.download = r.filename || 'gatekeeper_report.md';
  document.body.appendChild(a); a.click(); a.remove();
}
async function repSend() {
  if (!confirm('設定レポートを今すぐメールで送信します。よろしいですか？')) return;
  const r = await gkPost('/api/report/send', {});
  alert(r.msg || (r.success ? '送信しました' : '送信に失敗しました'));
  updateData();
}
function repRender(p) {
  if (!p) return;
  const c = p.cfg || {};
  const ids = ['rep-wd', 'rep-hour', 'rep-to'];
  if (!formDirty.rep && !(document.activeElement && ids.includes(document.activeElement.id))) {
    document.getElementById('rep-enabled').checked = !!c.enabled;
    document.getElementById('rep-change').checked = !!c.on_change;
    document.getElementById('rep-wd').value = String(c.weekday ?? 0);
    document.getElementById('rep-hour').value = c.hour ?? 9;
    document.getElementById('rep-to').value = c.to || '';
  }
  if (formDirty.rep) return;
  let s = p.mail_ready ? '' : '⚠ メール通知（SMTP・宛先）が未設定のため送信できません。 ';
  s += '最終送信: ' + (p.last_sent || 'まだ') + (p.last_result ? '（' + p.last_result + '）' : '');
  if (p.pending_change) s += ' / 設定変更を検知、2分後に送信予定';
  document.getElementById('rep-state').innerText = s;
}

async function dismissAlert() {
  await gkPost('/api/alert/dismiss', {});
  updateData();
}

function getScoreColor(score) {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 30) return '#eab308';
  return '#10b981';
}

async function updateData() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('cpu-temp').innerText = data.temp + ' °C';
    document.getElementById('sys-uptime').innerText = 'Uptime: ' + data.uptime;
    document.getElementById('nginx-status').innerText = data.nginx ? 'ACTIVE' : 'DOWN';
    document.getElementById('nft-status').innerText = data.nftables ? 'ACTIVE' : 'DOWN';
    document.getElementById('access-log').innerText = data.logs || 'ログなし';
    document.getElementById('ext-if-name').innerText = data.ext_if || '--';
    document.getElementById('ext-ip-line').innerText = '現在の外部側IP: ' + (data.ext_ip || '未取得') + '（IF: ' + (data.ext_if || '--') + '）';

    const integ = data.integrity || {};
    const integColor = integ.state === 'critical' ? '#f87171' : (integ.state === 'warn' ? '#fbbf24' : '#34d399');
    const stEl = document.getElementById('integ-state');
    stEl.innerText = integ.state === 'ok' ? '✓ 正常' : (integ.state === 'warn' ? '△ 注意（要確認）' : (integ.state === 'critical' ? '✗ 重大（改竄の疑い）' : '---'));
    stEl.style.color = integColor;
    document.getElementById('integ-time').innerText = integ.checked_at || '--';
    document.getElementById('integ-ro').innerText = integ.ro_mode ? '読み取り専用モード: ON' : '読み取り専用モード: OFF（検知時は警報のみ）';
    document.getElementById('integ-findings').innerText = (integ.findings && integ.findings.length)
      ? integ.findings.map(f => '[' + f.level + '] ' + f.msg).join('\\n')
      : '異常なし（台帳と一致・外向き接続なし・予定外ポートなし）';

    currentWifiMgmtOpen = data.wifi_mgmt_open;
    const statusEl = document.getElementById('wifi-mgmt-status');
    const btnEl = document.getElementById('wifi-toggle-btn');
    if (data.wifi_mgmt_open) {
      statusEl.className = 'status-badge';
      statusEl.innerText = '公開中 (OPEN)';
      btnEl.className = 'btn-toggle btn-on';
      btnEl.innerText = '停止する (閉じる)';
    } else {
      statusEl.className = 'status-badge off';
      statusEl.innerText = '停止中 (BLOCKED)';
      btnEl.className = 'btn-toggle btn-off';
      btnEl.innerText = '公開する (開く)';
    }

    const whitelistDiv = document.getElementById('whitelist-container');
    const whitelisted = data.whitelist_ips || [];
    if (whitelisted.length === 0) {
      whitelistDiv.innerHTML = '<span style="color:#64748b; font-size:13px;">登録されている許可IPはありません。</span>';
    } else {
      whitelistDiv.innerHTML = whitelisted.map(ip => `
        <span class="ip-tag allowed">
          <strong style="color:#34d399;">${ip}</strong>
          <button class="btn-sm btn-gray" onclick="removeWhitelist('${ip}')">許可解除</button>
        </span>
      `).join('');
    }

    const blockedDiv = document.getElementById('blocked-container');
    const blocked = data.blocked_ips || [];
    if (blocked.length === 0) {
      blockedDiv.innerHTML = '<span style="color:#64748b; font-size:13px;">現在遮断中のIPはありません。</span>';
    } else {
      blockedDiv.innerHTML = blocked.map(ip => `
        <span class="ip-tag blocked">
          <strong style="color:#f87171;">${ip}</strong>
          <button class="btn-sm btn-green" onclick="promoteToWhitelist('${ip}')">許可リストへ移動</button>
          <button class="btn-sm btn-red" onclick="manualUnblock('${ip}')">単に解除</button>
        </span>
      `).join('');
    }

    // [v1.9] 出口防御・緊急ブレーカー
    const bk = data.breaker || {};
    const bEl = document.getElementById('breaker-state');
    bEl.innerText = bk.active ? ('⚠ 緊急遮断中: ' + (bk.mode === 'cut_ext' ? '外部入口遮断' : (bk.mode === 'cut_link' ? 'バックエンド分離' : bk.mode))) : '通常運用';
    bEl.style.color = bk.active ? '#f87171' : '#34d399';
    const al = data.active_alert;
    const ban = document.getElementById('emergency-banner');
    if (bk.active || al) {
      ban.style.display = 'block';
      let txt = '';
      if (bk.active) txt += '【緊急遮断作動中】\\n';
      if (al) txt += '検知: ' + al.reason + '\\n接続元: ' + al.ip + '  パス: ' + al.path + '  時刻: ' + al.time;
      document.getElementById('emg-text').innerText = txt;
    } else {
      ban.style.display = 'none';
    }
    const hist = data.alert_history || [];
    document.getElementById('alert-history').innerText = hist.length
      ? hist.map(h => '[' + h.time + '] ' + h.reason + '（' + h.ip + ' ' + h.path + '）').join('\\n')
      : '検知なし';
    const g = data.guard || {};
    const gIds = ['g-harvest', 'g-burst', 'g-maxmb', 'g-volmb', 'g-e5', 'g-piipaths'];
    if (!formDirty.guard && !(document.activeElement && gIds.includes(document.activeElement.id))) {
      document.getElementById('guard-auto').checked = !!g.auto_block;
      document.getElementById('g-harvest').value = g.harvest_threshold ?? 15;
      document.getElementById('g-burst').value = g.pii_burst_60s ?? 30;
      document.getElementById('g-maxmb').value = g.max_body_mb ?? 50;
      document.getElementById('g-volmb').value = g.bytes10m_mb ?? 100;
      document.getElementById('g-e5').value = g.err5_rate ?? 30;
      document.getElementById('g-piipaths').value = (g.pii_paths || []).join(',');
    }
    piiRender(data.pii_guard);
    repRender(data.report);
    pubRender(data.publish);
    const mc = data.mail || {};
    const mIds = ['m-host', 'm-port', 'm-user', 'm-pass', 'm-to'];
    if (!formDirty.mail) {
      document.getElementById('mail-state').innerText = (mc.enabled ? '通知: 有効' : '⚠ 通知: 無効（「有効」に印を付けて保存すると届きます）') + (mc.last_result ? ' / ' + mc.last_result : '');
      document.getElementById('mail-state').style.color = mc.enabled ? '' : '#fbbf24';
    }
    if (!formDirty.mail && !(document.activeElement && mIds.includes(document.activeElement.id))) {
      document.getElementById('m-enabled').checked = !!mc.enabled;
      document.getElementById('m-host').value = mc.host || '';
      document.getElementById('m-port').value = mc.port || 587;
      document.getElementById('m-user').value = mc.user || '';
      document.getElementById('m-to').value = mc.to || '';
    }
    const dlpBody = document.getElementById('dlp-tbody');
    const dlpRules = data.dlp_rules || [];
    if (dlpRules.length === 0) {
      dlpBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#64748b;">DLPルールがありません。</td></tr>';
    } else {
      dlpBody.innerHTML = dlpRules.map(r => `
        <tr>
          <td><strong>${esc(r.name)}</strong>${r.builtin ? '' : ' <span style="font-size:10px; color:#38bdf8;">[カスタム]</span>'}</td>
          <td style="font-family:monospace; font-size:11px; color:#94a3b8; word-break:break-all;">${esc(r.pattern)}</td>
          <td style="font-family:monospace; font-size:11px; color:#94a3b8; word-break:break-all;">${esc(r.replacement)}</td>
          <td style="white-space:nowrap;">
            <label style="cursor:pointer;">
              <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="dlpSet('${r.id}', this.checked)"> ${r.enabled ? 'ON' : 'OFF'}
            </label>
            ${r.builtin ? '' : `<button class="btn-sm btn-red" onclick="dlpDelete('${r.id}')">削除</button>`}
          </td>
        </tr>
      `).join('');
    }

    const tbody = document.getElementById('threat-tbody');
    const ips = Object.keys(data.threat_stats || {});
    if (ips.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#64748b;">外部アクセス待機中...</td></tr>';
    } else {
      tbody.innerHTML = ips.map(ip => {
        const item = data.threat_stats[ip];
        const isWhite = whitelisted.includes(ip);
        const color = isWhite ? '#10b981' : getScoreColor(item.score);
        return `
          <tr>
            <td>
              <strong>${ip}</strong>
              ${isWhite ? '<span style="font-size:11px; color:#34d399; margin-left:6px;">[許可済]</span>' : ''}
            </td>
            <td>
              <div class="bar-container">
                <div class="bar-fill" style="width: ${item.score}%; background: ${color};"></div>
              </div>
              <span style="font-weight:bold; color:${color};">${item.score}</span>
            </td>
            <td><span style="color:${color}; font-weight:bold;">${isWhite ? '許可 (Bypassed)' : item.stage}</span>${item.slow ? '<br><span style="color:#fbbf24; font-size:11px;">' + esc(item.slow) + '</span>' : ''}</td>
            <td style="color:#94a3b8;">CV: ${item.cv} / Err: ${item.error_ratio}% / Path: ${item.entropy}%${item.ssh_fail ? ' / SSH失敗: ' + item.ssh_fail + '回' : ''}</td>
            <td>${item.last_seen}</td>
            <td>
              ${isWhite 
                ? `<button class="btn-sm btn-gray" onclick="removeWhitelist('${ip}')">許可解除</button>`
                : `<button class="btn-sm btn-green" onclick="promoteToWhitelist('${ip}')">許可リストへ</button>
                   <button class="btn-sm btn-red" onclick="manualBlock('${ip}')">即時遮断</button>`
              }
            </td>
          </tr>
        `;
      }).join('');
    }
  } catch(e) {}
}

async function promoteToWhitelist(ip) {
  if (!confirm(`${ip} を許可リスト（ホワイトリスト）に登録しますか？\\n（現在遮断中の場合は即座に解除されます）`)) return;
  await fetch('/api/whitelist/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip })
  });
  updateData();
}

async function addManualWhitelist() {
  const input = document.getElementById('manual-whitelist-ip');
  const ip = input.value.trim();
  if (!ip) return;
  await fetch('/api/whitelist/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip })
  });
  input.value = '';
  updateData();
}

async function removeWhitelist(ip) {
  if (!confirm(`${ip} の許可を取り消しますか？`)) return;
  await fetch('/api/whitelist/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip })
  });
  updateData();
}

async function manualBlock(ip) {
  if (!confirm(`${ip} を直ちに遮断リストへ登録しますか？`)) return;
  await fetch('/api/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip })
  });
  updateData();
}

async function manualUnblock(ip) {
  await fetch('/api/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip })
  });
  updateData();
}

async function toggleWifiMgmt() {
  const targetAction = currentWifiMgmtOpen ? 'close' : 'open';
  if (!confirm(currentWifiMgmtOpen ? '外部側からの管理アクセスを遮断しますか？' : '外部側からの管理アクセスを許可しますか？')) return;
  await fetch('/api/wifi_mgmt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: targetAction })
  });
  updateData();
}

async function reloadNginx() {
  if(!confirm('Nginx 設定をリロードしますか？')) return;
  const res = await fetch('/api/reload', { method: 'POST' });
  const data = await res.json();
  alert(data.msg);
  updateData();
}

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function dlpSet(id, enabled) {
  await fetch('/api/dlp/set', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id, enabled: enabled }) });
  updateData();
}

async function dlpAdd() {
  const name = document.getElementById('dlp-name').value.trim();
  const pattern = document.getElementById('dlp-pattern').value.trim();
  const replacement = document.getElementById('dlp-replacement').value.trim();
  if (!name || !pattern) { alert('ルール名とパターンは必須です'); return; }
  if (/[;\\r\\n]/.test(pattern) || /[;\\r\\n]/.test(replacement) || pattern.includes("'") || replacement.includes("'")) { alert("使用できない文字が含まれます（ ' / ; / 改行 ）"); return; }
  const res = await fetch('/api/dlp/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name, pattern: pattern, replacement: replacement }) });
  const data = await res.json();
  if (!data.success) {
    alert(data.msg || '追加に失敗しました');
  } else {
    document.getElementById('dlp-name').value = '';
    document.getElementById('dlp-pattern').value = '';
    document.getElementById('dlp-replacement').value = '';
  }
  updateData();
}

async function dlpDelete(id) {
  if (!confirm('このルールを削除しますか？')) return;
  await fetch('/api/dlp/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id }) });
  updateData();
}

async function dlpTest() {
  const text = document.getElementById('dlp-testtext').value;
  const out = document.getElementById('dlp-testout');
  if (!text.trim()) { alert('テスト用テキストを入力してください'); return; }
  const res = await fetch('/api/dlp/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: text }) });
  const data = await res.json();
  out.style.display = 'block';
  out.innerText = '--- マスキング結果 ---\\n' + data.masked + '\\n\\n--- ルール別ヒット数 ---\\n' + (data.results || []).map(r => r.name + ': ' + r.count).join('\\n');
}

async function integrityRecheck() {
  await fetch('/api/integrity/recheck', { method: 'POST' });
  updateData();
}

setInterval(updateData, 2000);
updateData();
</script>
<script>
// ---- micro-monban help system (v1.9.6): short notes + ? detail help on every card ----
(function(){
  var MM_HELP = {
    '外部側 管理アクセス': { s: '外出先から緊急に管理画面へ入りたいときだけ使う非常用スイッチです。基本は「停止中」のままでOKです。',
      d: '<b>これは何？</b> 通常、外側ネットワークからこの管理画面へアクセスしようとすると、無言で破棄（DROP）され「画面が存在しない」のと同じに見えます。このスイッチを「公開する」にすると一時的に外側から応答するようになり、Basic認証（ユーザー名 admin）が要求されます。<br/><br/><b>いつ使う？</b> SSHポートフォワードが使えない緊急時にのみ。用が済んだら必ず「停止する」へ戻してください。<br/><br/><b>ふだんの管理は</b> SSHポートフォワード経由を推奨します（ssh -L @@DASH_PORT@@:localhost:@@DASH_PORT@@ ユーザー名@装置アドレス → https://localhost:@@DASH_PORT@@）。' },
    'System Status': { s: '装置の体温（CPU温度）と連続稼働時間です。温度は50〜65°C前後が正常です。',
      d: '<b>これは何？</b> Raspberry Pi のCPU温度と、電源ONからの連続稼働時間（Uptime）を表示します。<br/><br/><b>見方</b> 50〜65°Cが安定域。70°Cを超えるとファンや設置場所（通気）を確認してください。Uptimeが意図せず短ければ、停電や電源トラブルの疑いがあります。' },
    'micro-monban Services': { s: '受付係（Nginx）と通信制御係（nftables）が生きているかの表示です。緑なら正常です。',
      d: '<b>これは何？</b> 2つの心臓部の稼働状況です。<br/>・<b>Nginx</b>（緑=稼働中）— 通信の受付と検査をする係。止まると外部公開が応答しなくなります。<br/>・<b>nftables</b>（緑=稼働中）— 扉の開閉と遮断を司る係。止まると防御が機能しません。<br/><br/><b>Nginx 設定再読み込みボタン</b> — DLPルールなどの設定変更が画面に反映されないときに押します（設定文法チェックつきで安全です）。' },
    '許可リスト': { s: '「この相手はいつでも信頼できる」というIPの登録簿。最優先で通信が通ります。',
      d: '<b>これは何？</b> 登録されたIPはAI検知・自動遮断の対象外となり、最優先で通過します。nftables再起動後もウォッチドッグが自動復元します。<br/><br/><b>何を登録する？</b> 自宅の回線、会社の支店、管理者自身のPCなど、確実に信頼できる相手だけ。<br/><br/><b>解除は</b> 各タグの「許可解除」ボタンで。誤登録は防御の穴になるので、使わなくなったら外してください。' },
    'AI 動的遮断リスト': { s: '怪しい挙動の相手をAIが自動で止めた一覧。10分で自動解除されます。',
      d: '<b>これは何？</b> AIの振る舞い分析が「攻撃の予兆」と判定したIPが、nftablesの動的遮断（dynamic_blocks）に入り、10分間は無言で捨てられます。10分経つと自動で解除され、また怪しい動きをすれば再び遮断されます。<br/><br/><b>ボタンの意味</b><br/>・<b>許可リストへ移動</b> — 誤検知のとき。即時解除され、以後は常時許可になります（家族のPCならこれ）。<br/>・<b>単に解除</b> — 1回だけ解除（10分待たずに通す）。' },
    'DLP 機密マスキング': { s: 'サーバーから外へ出ていくデータに個人情報が含まれていたら、自動で伏せ字にするルールです。',
      d: '<b>これは何？</b> 万一サーバーが侵入されても、外へ流れる応答データの中の個人情報（電話番号・顧客ID・クレジット番号など）を検出して「***」などに置換します。データが外に出る前に、中身だけ無力化する堤防です。<br/><br/><b>操作</b><br/>・チェックON/OFFで個別に有効化（nginx検証つき・失敗時は自動取消）。<br/>・<b>マスキング試験</b> — 実際のテキストを貼って、どのように伏せられるか確認できます。<br/><br/><b>注意</b> パターンにシングルクォート（’）は使えません。' },
    'セルフ整合性監視': { s: '門番自身の体調チェック。重要ファイルの改竄や予定外の扉がないか5分ごとに点検します。',
      d: '<b>これは何？</b> 装置自身が自分の重要ファイルの台帳照合・外向き接続・予定外ポートを5分ごとに点検します。<br/><br/><b>「重大（改竄の疑い）」と出たら</b> 読み取り専用モードでは120秒後に自動再起動し、書き込みを全て破棄して本来の自分で立ち上がります。お任せでOKです。<br/><br/><b>「再チェック」ボタン</b> — 何か操作した直後にすぐ点検したいときに。' },
    '出口防御 & 緊急ブレーカー': { s: '「情報が外へ流れ出す」を検知して止める堤防と、緊急時に回路を切るブレーカーです。',
      d: '<b>これは何？</b> 攻撃の最終段階は「サーバー内の情報を大量に持ち出す」こと。この機能は応答データの様子（大量ダンプ・個人情報の連続取得・5xxエラー連発）を監視し、異変を検知してアラート（設定でメール通知も可）します。<br/><br/><b>ブレーカーの3ボタン</b><br/>・<b>🌐 外部入口を遮断</b> — インターネット側との出入りを全部止める。<br/>・<b>🔌 バックエンドと分離</b> — 内側サーバーとの接続だけを切る。<br/>・<b>🔓 復旧</b> — 元に戻す。<br/><br/><b>安全設計</b> ブレーカーは独立したnftテーブルで動くので、復旧しても通常の遮断リストは壊れません。既定は「監視・通報のみ」で、自動IP遮断はOFFです。<br/><br/><b>しきい値</b> 個人情報の連続取得回数・PII応答の毎分件数・単応答サイズ・10分累計・5xx毎分回数を、お使いの規模に合わせて調整し「監視設定を保存」してください。<br/><br/><b>メール通知</b> SMTP（587=STARTTLS / 465=SSL）を設定すると検知時に通知。資格情報は装置内の許可ファイル（600）に保存され、画面には返りません。' },
    'AI 振る舞い分析': { s: '接続元ごとに「怪しさ」を点数化する脅威レーダー。まだ被害になる前ののぞき回りが見えます。',
      d: '<b>これは何？</b> 各接続元IPを、<br/>・<b>時間均一度</b> — 機械的な等間隔アクセスか（botの兆候）<br/>・<b>エラー率</b> — 連続で失敗させていないか（総当たりの兆候）<br/>・<b>パス探索度</b> — 存在しないページを次々試していないか（地雷サーチの兆候）<br/>から点数化し、攻撃の予兆段階で表示します。<br/><br/><b>点数が高い相手には</b> 「即時遮断」か、様子を見るなら放置（自動で動的遮断に入ることもあります）。誤検知なら「許可リストへ移動」。' },
    '直近のアクセス': { s: '最新のアクセスとWAF遮断の記録（監査ログ）。1日1回眺めるだけで十分です。',
      d: '<b>これは何？</b> 受付係が処理した直近20件の通信と、入口検査で止めた記録です。<br/><br/><b>見方</b> 403/444など検査で止めた行が時々出るのは正常（攻撃のノイズが止まっている証拠）。同じIPが短時間に何十行も並んでいたら脅威レーダーと照らしてみてください。<br/><br/><b>保存先</b> /var/log/nginx 配下に常時記録されています（本体マニュアル第12章）。' }
  };
  function mmCards(){
    var cards = document.querySelectorAll('.card');
    var done = 0;
    cards.forEach(function(card){
      var h2 = card.querySelector('h2');
      if(!h2 || card.dataset.mmHelp) return;
      var txt = h2.textContent || '';
      var key = null;
      for(var k in MM_HELP){ if(txt.indexOf(k) !== -1){ key = k; break; } }
      if(!key) return;
      card.dataset.mmHelp = '1';
      var h = MM_HELP[key];
      var btn = document.createElement('button');
      btn.className = 'mm-help-btn';
      btn.textContent = '?';
      btn.setAttribute('aria-label', 'この項目の詳しい説明');
      btn.title = '詳しい説明を開く';
      btn.addEventListener('click', function(){
        var d = card.querySelector('.mm-help-detail');
        var open = d.style.display !== 'none';
        d.style.display = open ? 'none' : 'block';
        btn.textContent = open ? '?' : '×';
        btn.title = open ? '詳しい説明を開く' : '説明を閉じる';
      });
      h2.appendChild(btn);
      var short = document.createElement('div');
      short.className = 'mm-help-short';
      short.textContent = h.s;
      var anchor = (h2.parentNode === card) ? h2 : h2.parentNode;
      anchor.parentNode.insertBefore(short, anchor.nextSibling);
      var detail = document.createElement('div');
      detail.className = 'mm-help-detail';
      detail.style.display = 'none';
      detail.innerHTML = h.d;
      anchor.parentNode.insertBefore(detail, short.nextSibling);
      done++;
    });
  }
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', mmCards);
  } else {
    setTimeout(mmCards, 0);
  }
})();
</script>
<style>
  .mm-help-btn { background: #334155; color: #f8fafc; border: none; border-radius: 50%; width: 20px; height: 20px; font-size: 12px; line-height: 20px; text-align: center; cursor: pointer; margin-left: 8px; vertical-align: middle; padding: 0; font-weight: bold; }
  .mm-help-btn:hover { background: #0ea5e9; }
  .mm-help-short { font-size: 12px; color: #94a3b8; margin: 4px 0 8px 0; line-height: 1.55; }
  .mm-help-detail { background: #0b1329; border: 1px solid #334155; border-radius: 6px; padding: 10px 14px; font-size: 12.5px; color: #cbd5e1; margin: 4px 0 10px 0; line-height: 1.75; }
  .mm-help-detail b { color: #f8fafc; }
</style>
</body>
</html>
"""

class AdminHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    # ---------------- Basic認証（信頼セグメントはバイパス） ----------------
    def is_trusted(self):
        """[v1.7修正] ループバックと、閉域直結のバックエンド機（BACKEND_IP）のみ信頼。
        旧実装は「10.0.0. で始まる」前方一致だったため、宅内LANが偶然 10.0.0.0/24
        だと外部側端末が Basic認証をバイパスしてしまう崩壊が起きていた。"""
        addr = self.client_address[0]
        return addr in ("127.0.0.1", "::1", BACKEND_IP)

    def require_auth(self):
        """外部側 (HOME_NET) からのアクセスにはBasic認証を要求する。"""
        if self.is_trusted():
            return True
        header = self.headers.get('Authorization', '')
        if header.startswith('Basic '):
            try:
                user, _, pwd = base64.b64decode(header[6:]).decode('utf-8').partition(':')
            except Exception:
                user, pwd = '', ''
            if hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(pwd, ADMIN_PASS):
                return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Gatekeeper"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        return False

    def is_wifi_mgmt_open(self):
        return wifi_mgmt_is_open()

    def csrf_ok(self):
        """[v1.9.7] CSRF対策。画面のJSは全POSTに X-GK-CSRF: 1 を付ける。
        他サイトのページはカスタムヘッダ付きの送信ができない（CORS事前確認で止まる）ため、
        ブラウザに残ったBasic認証を悪用した「踏ませ」操作を防げる。
        Origin が付いていれば、自分自身（Hostと同じ）からのものに限る。"""
        if self.headers.get('X-GK-CSRF') != '1':
            return False
        origin = self.headers.get('Origin')
        if origin and origin != 'null':
            host = self.headers.get('Host', '')
            if origin.split('://', 1)[-1] != host:
                return False
        return True

    def get_set_elements(self, set_name):
        return get_set_elements(set_name)

    def do_HEAD(self):
        if not self.require_auth():
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

    def do_GET(self):
        if not self.require_auth():
            return
        # [v1.7修正] クエリ文字列（キャッシュバスター ?_=... 等）を除去してルーティング
        self.path = self.path.split('?')[0]
        if self.path == '/' or self.path.startswith('/?'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(render_page().encode('utf-8'))
        elif self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            temp = "N/A"
            try:
                with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                    temp = f"{int(f.read().strip()) / 1000:.1f}"
            except Exception:
                pass

            uptime = subprocess.getoutput("uptime -p")
            nginx_active = subprocess.call(["systemctl", "is-active", "--quiet", "nginx"]) == 0
            nft_active = subprocess.call(["systemctl", "is-active", "--quiet", "nftables"]) == 0
            logs = subprocess.getoutput("tail -n 20 /var/log/nginx/gatekeeper_access.log 2>/dev/null")
            wifi_open = self.is_wifi_mgmt_open()
            blocked = self.get_set_elements("dynamic_blocks")
            whitelisted = self.get_set_elements("whitelist")

            with stats_lock:
                stats_copy = dict(ip_stats)

            payload = {
                "temp": temp,
                "uptime": uptime,
                "nginx": nginx_active,
                "nftables": nft_active,
                "logs": logs,
                "wifi_mgmt_open": wifi_open,
                "threat_stats": stats_copy,
                "blocked_ips": blocked,
                "whitelist_ips": whitelisted,
                "ext_if": EXT_IF,
                "ext_ip": get_ext_ip(),
                "home_net": HOME_NET,
                "dlp_rules": load_dlp_rules(),
                "integrity": integrity_state,
                "breaker": breaker_status(),
                "active_alert": current_alert(),
                "alert_history": list(alert_history),
                "guard": guard_summary(),
                "mail": mail_summary(),
                "pii_guard": pii_guard_summary(),
                "report": report_summary(),
                "publish": publish_summary()
            }
            self.wfile.write(json.dumps(payload).encode('utf-8'))
        else:
            self.send_error(404)

    def do_POST(self):
        if not self.require_auth():
            return
        # [v1.7修正] クエリ文字列を除去してルーティング（GET側と同じ扱い）
        self.path = self.path.split('?')[0]
        if not self.csrf_ok():
            self.send_error(403, "CSRF check failed")
            return
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            req = json.loads(body) if body else {}
            if not isinstance(req, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            self.send_error(400, "Bad JSON")
            return
        # [v1.9.7] IPを受け取るAPIは検証済みの値だけを通す（不正値は無視＝何もしない）
        if 'ip' in req:
            req['ip'] = valid_ipv4(req.get('ip'))

        if self.path == '/api/whitelist/add':
            ip = req.get('ip')
            if ip:
                subprocess.run(["sudo", "nft", "delete", "element", "inet", "filter", "dynamic_blocks", f"{{ {ip} }}"], check=False)
                subprocess.run(["sudo", "nft", "add", "element", "inet", "filter", "whitelist", f"{{ {ip} }}"], check=False)
                elements = self.get_set_elements("whitelist")
                save_whitelist(elements)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))

        elif self.path == '/api/whitelist/remove':
            ip = req.get('ip')
            if ip:
                subprocess.run(["sudo", "nft", "delete", "element", "inet", "filter", "whitelist", f"{{ {ip} }}"], check=False)
                elements = self.get_set_elements("whitelist")
                save_whitelist(elements)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))

        elif self.path == '/api/block':
            ip = req.get('ip')
            if ip:
                block_ip(ip)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))

        elif self.path == '/api/unblock':
            ip = req.get('ip')
            if ip:
                subprocess.run(["sudo", "nft", "delete", "element", "inet", "filter", "dynamic_blocks", f"{{ {ip} }}"], check=False)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))

        elif self.path == '/api/wifi_mgmt':
            action = req.get('action')
            if action == 'open':
                wifi_mgmt_set(True)
            elif action == 'close':
                wifi_mgmt_set(False)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "open": self.is_wifi_mgmt_open()}).encode('utf-8'))

        elif self.path == '/api/dlp/set':
            rid = req.get('id')
            enabled = bool(req.get('enabled'))
            rules = load_dlp_rules()
            for r in rules:
                if r.get('id') == rid:
                    r['enabled'] = enabled
            ok, msg = apply_dlp_rules(rules)
            if ok:
                save_dlp_rules(rules)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "msg": msg}).encode('utf-8'))

        elif self.path == '/api/dlp/add':
            name = (req.get('name') or '').strip()[:60]
            pattern = (req.get('pattern') or '').strip()[:200]
            replacement = (req.get('replacement') or '').strip()[:120]
            if not name or not pattern:
                ok, msg = False, "ルール名とパターンは必須です。"
            elif "'" in pattern or "'" in replacement or ";" in pattern or ";" in replacement or "\n" in pattern or "\n" in replacement or "\r" in pattern or "\r" in replacement:
                ok, msg = False, "使用できない文字が含まれます（ ' / ; / 改行 ）"
            else:
                try:
                    re.compile(pattern)
                    rules = load_dlp_rules()
                    rid = "user_" + str(int(time.time() * 1000))
                    rules.append({"id": rid, "name": name, "pattern": pattern, "replacement": replacement, "enabled": True, "builtin": False})
                    ok, msg = apply_dlp_rules(rules)
                    if ok:
                        save_dlp_rules(rules)
                except re.error as e:
                    ok, msg = False, f"正規表現として不正です: {e}"
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "msg": msg}).encode('utf-8'))

        elif self.path == '/api/dlp/delete':
            rid = req.get('id')
            rules = load_dlp_rules()
            rules = [r for r in rules if not (r.get('id') == rid and not r.get('builtin'))]
            ok, msg = apply_dlp_rules(rules)
            if ok:
                save_dlp_rules(rules)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "msg": msg}).encode('utf-8'))

        elif self.path == '/api/dlp/test':
            text = (req.get('text') or '')[:20000]
            results = []
            masked = text
            for r in load_dlp_rules():
                if not r.get('enabled'):
                    continue
                try:
                    rx = re.compile(r['pattern'], re.IGNORECASE)
                    cnt = len(rx.findall(masked))
                    if cnt:
                        masked = rx.sub(r['replacement'], masked)
                    results.append({"id": r['id'], "name": r['name'], "count": cnt})
                except re.error:
                    results.append({"id": r['id'], "name": r['name'], "count": "regex error"})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"results": results, "masked": masked}, ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/integrity/recheck':
            st, fd = self_integrity_check()
            integrity_state.update({"state": st, "findings": fd,
                                    "checked_at": datetime.now().strftime("%H:%M:%S"),
                                    "ro_mode": is_ro_mode()})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "state": st}).encode('utf-8'))

        elif self.path == '/api/reload':
            ret = subprocess.call(["sudo", "systemctl", "reload", "nginx"])
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            msg = "Nginx をリロードしました。" if ret == 0 else "リロードに失敗しました。"
            self.wfile.write(json.dumps({"status": ret, "msg": msg}).encode('utf-8'))

        elif self.path == '/api/killswitch':
            action = req.get('action')
            ok, msg = False, "不明なアクション"
            if req.get('confirm') != 'yes':
                ok, msg = False, "誤操作防止のため confirm=yes の指定が必要です"
            elif action == 'cut_ext':
                ok = breaker_cut('cut_ext')
                msg = "外部入口を緊急遮断しました（外部IFへの入力と転送をDROP）。" if ok else "遮断に失敗しました（nft を確認してください）"
            elif action == 'cut_link':
                ok = breaker_cut('cut_link')
                msg = "バックエンドサーバーとの通信を分離しました。" if ok else "遮断に失敗しました（nft を確認してください）"
            elif action == 'restore':
                ok = breaker_restore()
                msg = "緊急遮断を解除し、通常運用に戻しました。"
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "msg": msg, "active": breaker_active()}).encode('utf-8'))

        elif self.path == '/api/guard/set':
            for k, cast in (("harvest_threshold", int), ("pii_burst_60s", int),
                            ("max_body_mb", int), ("bytes10m_mb", int), ("err5_rate", int)):
                if k in req:
                    try:
                        v = cast(req[k])
                        if v <= 0:
                            raise ValueError
                    except (TypeError, ValueError):
                        continue
                    if k == "max_body_mb":
                        guard_cfg["max_body_bytes"] = v * 1048576
                    elif k == "bytes10m_mb":
                        guard_cfg["bytes10m"] = v * 1048576
                    else:
                        guard_cfg[k] = v
            guard_cfg["auto_block"] = bool(req.get("auto_block"))
            if "pii_paths" in req:
                paths = [p.strip() for p in str(req.get("pii_paths", "")).split(",") if p.strip()]
                guard_cfg["pii_paths"] = paths[:20]
            save_guard()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "guard": guard_summary()}, ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/mail/set':
            for k in ("host", "user", "to"):
                if k in req:
                    mail_cfg[k] = str(req.get(k, ""))[:200]
            if "port" in req:
                try:
                    mail_cfg["port"] = int(req.get("port"))
                except (TypeError, ValueError):
                    pass
            mail_cfg["enabled"] = bool(req.get("enabled"))
            if req.get("pass"):
                mail_cfg["pass"] = str(req.get("pass"))[:200]
            save_mail()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "mail": mail_summary()}, ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/mail/test':
            if not mail_cfg.get("host") or not mail_cfg.get("to"):
                ok, msg = False, "SMTPホストと宛先を入力して保存してから試験してください"
            else:
                ok, err = _smtp_send("[Gatekeeper] テスト送信",
                                     "これは Gatekeeper ダッシュボードからのテスト送信です。\n正常に届いていれば通知設定は完了しています。")
                msg = "テストメールを送信しました。" if ok else ("送信失敗: " + err)
                mail_state["last_result"] = msg
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "msg": msg}).encode('utf-8'))

        elif self.path == '/api/pii_guard/set':
            # [v1.10.0] 個人情報 一括持ち出しガードの ON/OFF・件数設定
            c = pii_guard_cfg()
            if 'enabled' in req:
                c['enabled'] = bool(req.get('enabled'))
            if 'monitor_only' in req:
                c['monitor_only'] = bool(req.get('monitor_only'))
            for k, lo, hi in (('max_per_response', 1, 1000), ('window_limit', 1, 100000)):
                if k in req:
                    try:
                        v = int(req.get(k))
                        if lo <= v <= hi:
                            c[k] = v
                    except (TypeError, ValueError):
                        pass
            ok = True
            try:
                pii_guard_save(c)
            except Exception:
                ok = False
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "cfg": c}, ensure_ascii=False).encode('utf-8'))

        elif self.path.startswith('/api/publish/'):
            # [v1.12.0] インターネット公開ウィザード
            act = self.path[len('/api/publish/'):]
            ok, msg, extra = False, "不明な操作です", {}
            domain = str(req.get('domain') or '').strip().lower().rstrip('.')
            email = str(req.get('email') or '').strip()
            if act == 'global_ip':
                ip = subprocess.getoutput("curl -s -m 8 https://api.ipify.org")
                ok = bool(valid_ipv4(ip))
                msg = ("この家の外向き IP: " + ip) if ok else "外向き IP を調べられませんでした"
                extra = {"ip": ip if ok else ""}
            elif act in ('le_check', 'le_issue'):
                gip = valid_ipv4(req.get('global_ip')) or ""
                method = str(req.get('method') or 'webroot')
                mid = str(req.get('mydns_id') or '').strip()
                mpw = str(req.get('mydns_pw') or '')
                if method not in LE_METHODS:
                    msg = "確認の方法が正しくありません"
                elif method == 'dns-mydns' and (mid or mpw) and not (MYDNS_CRED_RE.match(mid) and MYDNS_CRED_RE.match(mpw)):
                    msg = "MyDNS のマスターID とパスワードを、両方とも入れてください（空白は使えません）"
                elif method == 'dns-mydns' and not (mid and mpw) and not os.path.exists(MYDNS_NETRC):
                    msg = "MyDNS のマスターID とパスワードを入れてください（mydns.jp にログインするときのもの）"
                elif method == 'dns-mydns' and not os.path.exists(MYDNS_HOOK):
                    msg = MYDNS_HOOK + " がありません（導入スクリプト v1.14.0 以降で上書き更新してください）"
                elif not DOMAIN_RE.match(domain):
                    msg = "ドメイン名の形が正しくありません（例: www.example.jp）"
                elif not EMAIL_RE.match(email):
                    msg = "連絡用メールアドレスの形が正しくありません"
                elif not req.get('agree'):
                    msg = "Let's Encrypt の利用規約への同意が必要です"
                elif not shutil.which("certbot"):
                    msg = "certbot が入っていません（install_v112.sh を実行してください）"
                elif act == 'le_issue' and req.get('confirm') != 'yes':
                    msg = "確認のため confirm=yes が必要です"
                else:
                    if method == 'dns-mydns' and mid and mpw:
                        mydns_save_login(mid, mpw)      # 値は記録に残さない
                    mid = mpw = ""
                    if act == 'le_check':
                        ok, msg = start_job("事前確認（試験取得）", le_check, domain, email, gip, method)
                    else:
                        ok, msg = start_job("本番取得して公開", le_issue, domain, email, gip, method)
            elif act == 'le_revert':
                ok, msg = start_job("Let's Encrypt の公開をやめる", le_revert)
            elif act == 'le_renew_test':
                ok, msg = start_job("証明書の更新の予行演習", le_renew_test)
            elif act == 'cf_install':
                ok, msg = start_job("cloudflared を導入", cf_install)
            elif act == 'cf_connect':
                token = str(req.get('token') or '').strip()
                if token.startswith('cloudflared'):
                    token = token.split()[-1]          # 「cloudflared service install XXX」を丸ごと貼っても可
                if not TOKEN_RE.match(token):
                    msg = "トークンの形が正しくありません（Cloudflare の画面に表示された長い文字列を貼り付けてください）"
                else:
                    ok, msg = start_job("Cloudflare に接続", cf_connect, token)
            elif act == 'cf_disconnect':
                ok, msg = start_job("Cloudflare の接続を外す", cf_disconnect)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(dict({"success": ok, "msg": msg}, **extra), ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/report/set':
            # [v1.11.0] 設定レポートの送信設定
            c = report_cfg()
            for k in ('enabled', 'on_change'):
                if k in req:
                    c[k] = bool(req.get(k))
            for k, lo, hi in (('weekday', 0, 6), ('hour', 0, 23)):
                if k in req:
                    try:
                        v = int(req.get(k))
                        if lo <= v <= hi:
                            c[k] = v
                    except (TypeError, ValueError):
                        pass
            if 'to' in req:
                addrs = [x.strip() for x in str(req.get('to') or '').split(',') if x.strip()]
                c['to'] = ', '.join(a for a in addrs if re.fullmatch(r'[^@\s,]+@[^@\s,]+\.[^@\s,]+', a))[:500]
            ok = True
            try:
                report_cfg_save(c)
            except Exception:
                ok = False
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "report": report_summary()}, ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/report/preview':
            verdict, full, _ = build_report('preview')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "verdict": verdict, "text": full,
                                         "filename": "gatekeeper_report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".md"},
                                        ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/report/send':
            ok, msg = send_report('manual')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "msg": msg}, ensure_ascii=False).encode('utf-8'))

        elif self.path == '/api/alert/dismiss':
            global active_alert
            active_alert = None
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))

        else:
            self.send_error(404)

if __name__ == '__main__':
    # [v1.5] インストーラーからの台帳再構築モード（再インストール後の誤検知防止）
    if os.environ.get("GK_REBUILD_MANIFEST") == "1":
        rebuild_manifest()
        print("[manifest] integrity manifest rebuilt")
    else:
        server = http.server.ThreadingHTTPServer(('0.0.0.0', PORT), AdminHandler)
        # [v1.6] 管理画面もTLS化（門番のサーバー証明書を共用・SANに閉域側IPを焼き込み済み）
        TLS_CERT = "/opt/gatekeeper/tls/server.crt"
        TLS_KEY = "/opt/gatekeeper/tls/server.key"
        if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(TLS_CERT, TLS_KEY)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            print(f"[tls] dashboard serving HTTPS on :{PORT}")
        server.serve_forever()
