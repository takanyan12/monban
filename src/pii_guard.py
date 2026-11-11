#!/usr/bin/env python3
# micro-monban v1.12.0  個人情報 一括持ち出しガード（PII Bulk Guard）
#
#  nginx(443) → 127.0.0.1:8081（このプログラム）→ バックエンド（config.json の backend_ip:backend_port）
#  ・バックエンドの応答本文に含まれる個人情報を種類別に数え、
#    「1回の応答で max_per_response 件を超える」または
#    「同じ接続元へ window_sec 秒で window_limit 件を超える」ときに止める（403）。
#  ・数件程度（本人が自分の情報を見る・変える）は通す。
#  ・設定 /opt/gatekeeper/pii_guard.json はダッシュボードが書き、ここは毎リクエスト mtime を見て再読込。
#  ・検知は /var/lib/gatekeeper/pii/events.jsonl に追記（ダッシュボードが読んで警報・表示）。
#  ・WebSocket は nginx 側でこのプログラムを通さない。SSE・画像・大きな応答は検査せず素通し。
import html
import http.client
import http.server
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

LISTEN = ("127.0.0.1", 8081)
def _backend():
    try:
        with open("/opt/gatekeeper/config.json") as f:
            c = json.load(f)
        return (str(c.get("backend_ip", "10.0.0.2")), int(c.get("backend_port", 8080)))
    except Exception:
        return ("10.0.0.2", 8080)

BACKEND = _backend()          # [v1.12.0] /opt/gatekeeper/config.json の backend_ip / backend_port
CFG_FILE = "/opt/gatekeeper/pii_guard.json"
DATA_DIR = "/var/lib/gatekeeper/pii"
EVENTS = DATA_DIR + "/events.jsonl"
STATS = DATA_DIR + "/stats.json"
MAX_INSPECT = 8 * 1024 * 1024          # これより大きい応答は検査しない（容量監視は出口防御側）
DEFAULT_CFG = {"enabled": True, "monitor_only": False,
               "max_per_response": 5, "window_limit": 30, "window_sec": 600}

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "trailers", "transfer-encoding", "upgrade", "content-length"}

# ---------------- 設定 ----------------
_cfg = dict(DEFAULT_CFG)
_cfg_mtime = 0.0
_cfg_lock = threading.Lock()

def cfg():
    global _cfg, _cfg_mtime
    try:
        m = os.stat(CFG_FILE).st_mtime
    except OSError:
        return _cfg
    if m != _cfg_mtime:
        with _cfg_lock:
            try:
                with open(CFG_FILE) as f:
                    d = json.load(f)
                c = dict(DEFAULT_CFG)
                c.update({k: d[k] for k in DEFAULT_CFG if k in d})
                _cfg = c
                _cfg_mtime = m
                print("[pii_guard] config loaded: " + json.dumps(c), flush=True)
            except Exception as e:
                print("[pii_guard] config read error: " + str(e), flush=True)
    return _cfg

# ---------------- 個人情報の検出 ----------------
PREFS = ("北海道|東京都|大阪府|京都府|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|"
         "埼玉県|千葉県|神奈川県|新潟県|富山県|石川県|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|"
         "滋賀県|兵庫県|奈良県|和歌山県|鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|"
         "福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県")
RX = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?<![\d-])0\d{1,4}-\d{1,4}-\d{3,4}(?![\d-])|(?<!\d)0[5789]0\d{8}(?!\d)"),
    "card": re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
    "mynumber": re.compile(r"(?<!\d)(?<!\d-)(?<!\d )\d{4}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)"),
    "address": re.compile(r"(?:" + PREFS + r")[^\s\"'<>,、。]{1,20}?[市区町村郡][^\s\"'<>,、。]{0,40}"),
}
LABEL = {"email": "メール", "phone": "電話", "card": "カード", "mynumber": "マイナンバー", "address": "住所"}

def luhn(d):
    s, alt = 0, False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0

def card_ok(d):
    """カード会社の番号体系（先頭）と桁数・Luhn で判定。時刻やIDの偶然一致を避ける。"""
    if not (13 <= len(d) <= 19) or not luhn(d):
        return False
    if d[0] == "4":                                   # VISA
        return len(d) in (13, 16, 19)
    if d[:2] in ("34", "37"):                         # AMEX
        return len(d) == 15
    if d[:2] in ("51", "52", "53", "54", "55") or 2221 <= int(d[:4]) <= 2720:   # Mastercard
        return len(d) == 16
    if d[:2] == "35":                                 # JCB
        return len(d) in (16, 17, 18, 19)
    if d[:2] in ("30", "36", "38", "39"):             # Diners
        return 14 <= len(d) <= 19
    if d[:1] == "6":                                  # Discover / 銀聯 等
        return 16 <= len(d) <= 19
    return False

def mynumber_ok(d):
    if len(d) != 12:
        return False
    p = d[:11]
    s = sum(int(p[11 - n]) * (n + 1 if n <= 6 else n - 5) for n in range(1, 12))
    r = s % 11
    return int(d[11]) == (0 if r <= 1 else 11 - r)

def count_pii(text):
    found = {}
    for k, rx in RX.items():
        vals = set()
        for m in rx.finditer(text):
            v = m.group(0)
            if k in ("card", "mynumber"):
                d = re.sub(r"\D", "", v)
                if k == "card" and not card_ok(d):
                    continue
                if k == "mynumber" and not mynumber_ok(d):
                    continue
                v = d
            vals.add(v)
        if vals:
            found[k] = len(vals)
    est = max(found.values()) if found else 0
    return est, found

def normalize(body, ctype):
    t = body.decode("utf-8", errors="replace")
    if "json" in ctype:
        try:
            t = json.dumps(json.loads(t), ensure_ascii=False)   # \uXXXX を日本語に戻す
        except Exception:
            pass
    if "html" in ctype or "xml" in ctype or "&" in t:
        t = html.unescape(t)
    return t

def inspectable(ctype):
    c = ctype.lower()
    if "event-stream" in c:
        return False
    return (c.startswith("text/") or "json" in c or "xml" in c or "javascript" in c
            or c.startswith("application/x-www-form-urlencoded"))

# ---------------- 集計・記録 ----------------
_win = defaultdict(deque)            # ip -> deque[(t, n)]
_win_lock = threading.Lock()
stats = {"since": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "requests": 0, "inspected": 0,
         "with_pii": 0, "blocked": 0, "monitored": 0, "last_event": ""}
_stats_lock = threading.Lock()
_stats_dirty = True

def bump(**kw):
    global _stats_dirty
    with _stats_lock:
        for k, v in kw.items():
            stats[k] = stats.get(k, 0) + v if isinstance(v, int) else v
        _stats_dirty = True

def stats_writer():
    global _stats_dirty
    while True:
        time.sleep(3)
        if not _stats_dirty:
            continue
        try:
            with _stats_lock:
                snap = dict(stats)
                _stats_dirty = False
            tmp = STATS + ".tmp"
            with open(tmp, "w") as f:
                json.dump(snap, f, ensure_ascii=False)
            os.replace(tmp, STATS)
        except Exception as e:
            print("[pii_guard] stats write error: " + str(e), flush=True)

def window_total(ip, now, sec):
    with _win_lock:
        dq = _win[ip]
        while dq and now - dq[0][0] > sec:
            dq.popleft()
        return sum(n for _, n in dq)

def window_add(ip, now, n):
    with _win_lock:
        _win[ip].append((now, n))
        if len(_win) > 5000:                     # 古い接続元を掃除
            for k in [k for k, v in _win.items() if not v]:
                _win.pop(k, None)

def log_event(ev):
    try:
        with open(EVENTS, "a") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        if os.path.getsize(EVENTS) > 512 * 1024:      # 肥大化防止: 末尾 500 行だけ残す
            with open(EVENTS) as f:
                lines = f.readlines()[-500:]
            with open(EVENTS, "w") as f:
                f.writelines(lines)
    except Exception as e:
        print("[pii_guard] event write error: " + str(e), flush=True)
    print("[pii_guard] " + ev["action"] + " " + ev["ip"] + " " + ev["path"] + " est=" + str(ev["est"]) + " " + ev["reason"], flush=True)

# ---------------- 中継 ----------------
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "gk-pii-guard"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _read_body(self):
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            out = b""
            while True:
                line = self.rfile.readline()
                size = int(line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return out
                out += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n > 0 else b""

    def _proxy(self):
        bump(requests=1)
        body = self._read_body()
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        if body or self.command in ("POST", "PUT", "PATCH"):
            hdrs["Content-Length"] = str(len(body))
        hdrs["Connection"] = "close"
        try:
            conn = http.client.HTTPConnection(*BACKEND, timeout=55)
            conn.request(self.command, self.path, body=body or None, headers=hdrs)
            resp = conn.getresponse()
        except Exception as e:
            self.send_error(502, "Backend unreachable")
            print("[pii_guard] backend error: " + str(e), flush=True)
            return
        try:
            self._relay(resp)
        finally:
            conn.close()

    def _send_head(self, status, reason, headers, length=None):
        self.send_response_only(status, reason)
        for k, v in headers:
            if k.lower() not in HOP:
                self.send_header(k, v)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.end_headers()

    def _relay(self, resp):
        headers = resp.getheaders()
        ctype = resp.getheader("Content-Type", "") or ""
        cenc = (resp.getheader("Content-Encoding", "") or "").lower()
        clen = resp.getheader("Content-Length")
        c = cfg()
        head_only = self.command == "HEAD" or resp.status in (204, 304)
        can = (c.get("enabled") and not head_only and inspectable(ctype)
               and cenc in ("", "identity") and not (clen and clen.isdigit() and int(clen) > MAX_INSPECT))
        if not can:
            self._send_head(resp.status, resp.reason, headers)
            if not head_only:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            return
        data = resp.read(MAX_INSPECT + 1)
        if len(data) > MAX_INSPECT:                    # 想定より大きい: 検査せず素通し
            self._send_head(resp.status, resp.reason, headers)
            self.wfile.write(data)
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
            return
        bump(inspected=1)
        est, found = count_pii(normalize(data, ctype))
        ip = self.headers.get("X-Real-IP") or self.client_address[0]
        now = time.time()
        reason = ""
        if est:
            bump(with_pii=1)
            limit = int(c.get("max_per_response") or 5)
            wl = int(c.get("window_limit") or 30)
            ws = int(c.get("window_sec") or 600)
            if est > limit:
                reason = "1回の応答に個人情報 約%d件（上限 %d件）" % (est, limit)
            else:
                tot = window_total(ip, now, ws) + est
                if tot > wl:
                    reason = "%d分間の累計 約%d件（上限 %d件）" % (ws // 60, tot, wl)
        if reason:
            action = "monitor" if c.get("monitor_only") else "block"
            ev = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "epoch": now, "ip": ip,
                  "method": self.command, "path": self.path[:300], "est": est,
                  "cats": {LABEL[k]: v for k, v in found.items()}, "action": action, "reason": reason}
            log_event(ev)
            bump(**{("blocked" if action == "block" else "monitored"): 1, "last_event": ev["time"]})
            if action == "block":
                self._blocked(ctype, reason)
                return
        if est:
            window_add(ip, now, est)
        self._send_head(resp.status, resp.reason, headers, len(data))
        self.wfile.write(data)

    def _blocked(self, ctype, reason):
        if "json" in ctype.lower():
            body = json.dumps({"error": "blocked_by_gatekeeper", "reason": "pii_bulk",
                               "message": "個人情報の一括送信を門番が止めました。" + reason}, ensure_ascii=False).encode()
            ct = "application/json; charset=utf-8"
        else:
            body = ("<!doctype html><meta charset=utf-8><title>門番が止めました</title>"
                    "<h1>個人情報の一括送信を門番が止めました</h1><p>" + html.escape(reason) +
                    "</p><p>必要な場合は管理者に連絡してください。</p>").encode()
            ct = "text/html; charset=utf-8"
        self._send_head(403, "Forbidden", [("Content-Type", ct), ("Cache-Control", "no-store"),
                                           ("X-Gatekeeper-Block", "pii-bulk")], len(body))
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _proxy


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    cfg()
    threading.Thread(target=stats_writer, daemon=True).start()
    print("[pii_guard] listening on %s:%d -> backend %s:%d" % (LISTEN + BACKEND), flush=True)
    Server(LISTEN, Handler).serve_forever()
