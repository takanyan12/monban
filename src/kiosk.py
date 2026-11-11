#!/usr/bin/env python3
# =====================================================================
#  micro-monban 本体画面サーバー（v1.13.0）
#   ・Pi の HDMI（タッチ）モニターに出す「ダッシュボード」と「設定」の画面を配る
#   ・127.0.0.1 だけで待ち受ける（外からは見えない）。画面は Chromium のキオスク表示で開く
#   ・見るだけの状態表示はパスワード不要。設定はパスワードを入れてから（5分触らないとロック）
#   ・初期パスワードのままなら、最初に新しいパスワードを決めるまで設定に進めない
#   ・既存の機能（スイッチ・遮断の解除・メール・レポート）は管理画面（dashboard.py）の API を
#     ループバック経由で使う。Wi-Fi・パスワード変更・自己試験・再起動はここで行う
#   ・ネットワークを変える操作は「60 秒以内に確認しないと元に戻る」
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
import http.server
import json
import os
import re
import hmac
import hashlib
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from datetime import datetime

VERSION = "v1.14.3"
GK = "/opt/gatekeeper"
CONFIG_FILE = GK + "/config.json"
SECRET_FILE = GK + "/secret.conf"
STATE_FILE = GK + "/kiosk.json"            # {"must_change": true/false}
HTML_FILE = GK + "/kiosk.html"
SELFTEST = GK + "/selftest.sh"
ACCESS_LOG = "/var/log/nginx/gatekeeper_access.log"
PII_EVENTS = "/var/lib/gatekeeper/pii/events.jsonl"

IDLE_SEC = 300          # 設定画面の自動ロック（5分）
CONFIRM_SEC = 60        # ネットワーク変更の確認待ち
FAIL_MAX = 5            # パスワードを続けて間違えたら
FAIL_LOCK = 60          # この秒数は受け付けない

DEFAULTS = {"ext_if": "wlan0", "home_net": "192.168.1.0/24", "int_if": "eth0", "int_ip": "10.0.0.1",
            "backend_ip": "10.0.0.2", "backend_port": 8080, "dash_port": 9000, "kiosk_port": 9100}


def load_cfg():
    c = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE) as f:
            d = json.load(f)
        c.update({k: d[k] for k in DEFAULTS if k in d})
    except Exception:
        pass
    return c


C = load_cfg()
PORT = int(C["kiosk_port"])
EXT_IF = str(C["ext_if"])


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, str(e)


# ---------------------------------------------------------------- パスワード
def admin_pass():
    try:
        with open(SECRET_FILE) as f:
            for ln in f:
                if ln.startswith("GK_ADMIN_PASS="):
                    return ln.split("=", 1)[1].strip().strip("\"'")
    except Exception:
        pass
    return ""


def must_change():
    """初期パスワードのままか。導入スクリプトが初期パスワードの指紋（sha256）を kiosk.json に残すので、
    今のパスワードと比べる（SSH で手で変えた場合も、変えたと分かる）。"""
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
    except Exception:
        return False
    h = d.get("initial_sha256")
    if h:
        return hmac.compare_digest(hashlib.sha256(admin_pass().encode()).hexdigest(), str(h))
    return bool(d.get("must_change"))


def set_must_change(v):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"must_change": bool(v), "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


# systemd の EnvironmentFile で安全に読める文字だけ（引用符・\・$・`・#・空白は使わない）
PASS_RE = re.compile(r"^[A-Za-z0-9!%&()*+,\-./:;<=>?@\[\]^_{|}~]{10,128}$")


def write_pass(new):
    tmp = SECRET_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("GK_ADMIN_PASS=" + new + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRET_FILE)
    # 管理画面は起動時にパスワードを読むので入れ直す（少し待ってから・応答を先に返す）
    threading.Timer(1.0, lambda: run(["systemctl", "restart", "gatekeeper-dashboard"])).start()


# ---------------------------------------------------------------- 入室（セッション）
lock = threading.Lock()
session = {"token": "", "seen": 0.0}
fails = {"n": 0, "until": 0.0}


def new_session():
    with lock:
        session["token"] = secrets.token_urlsafe(32)
        session["seen"] = time.time()
        return session["token"]


def end_session():
    with lock:
        session["token"] = ""


def session_alive(token):
    """状態の読み取り用。確かめるだけで、ロックまでの時間は延ばさない。"""
    with lock:
        t = session["token"]
        return bool(t and token and hmac.compare_digest(t, token) and time.time() - session["seen"] <= IDLE_SEC)


def session_ok(token):
    with lock:
        t = session["token"]
        if not t or not token or not hmac.compare_digest(t, token):
            return False
        if time.time() - session["seen"] > IDLE_SEC:
            session["token"] = ""
            return False
        session["seen"] = time.time()
        return True


# ---------------------------------------------------------------- 管理画面 API（ループバック）
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE        # 自分自身（127.0.0.1）の自己署名証明書


def dash(path, body=None, timeout=20):
    url = "https://127.0.0.1:%d%s" % (int(C["dash_port"]), path)
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="GET" if data is None else "POST",
                                 headers={"X-GK-CSRF": "1", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


# ---------------------------------------------------------------- 状態のまとめ
_cache = {}
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def cached(key, sec, fn):
    now = time.time()
    v = _cache.get(key)
    if v and now - v[0] < sec:
        return v[1]
    r = fn()
    _cache[key] = (now, r)
    return r


def today_log_counts():
    n = d = 0
    now = datetime.now()
    tag = "%02d/%s/%d:" % (now.day, MONTHS[now.month - 1], now.year)
    try:
        with open(ACCESS_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8 * 1024 * 1024))
            for raw in f:
                ln = raw.decode("utf-8", "replace")
                if tag not in ln:
                    continue
                n += 1
                if '"status":"403"' in ln:
                    d += 1
    except Exception:
        pass
    return {"requests": n, "denied": d}


def pii_today():
    day = datetime.now().strftime("%Y-%m-%d")
    out = []
    try:
        with open(PII_EVENTS) as f:
            for ln in f.readlines()[-500:]:
                try:
                    e = json.loads(ln)
                except Exception:
                    continue
                if str(e.get("time", "")).startswith(day):
                    out.append(e)
    except Exception:
        pass
    return out


def backend_ok():
    try:
        with socket.create_connection((str(C["backend_ip"]), int(C["backend_port"])), timeout=2):
            return True
    except Exception:
        return False


def wifi_ssid():
    rc, out = run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"], 10)
    for ln in out.splitlines():
        if ln.startswith("yes:"):
            return ln[4:].replace("\\:", ":")
    return ""


def build_state():
    s, dash_ok = {}, True
    try:
        s = dash("/api/status", timeout=15)
    except Exception:
        dash_ok = False
    integ = s.get("integrity") or {}
    pii = s.get("pii_guard") or {}
    pcfg = pii.get("cfg") or {}
    brk = (s.get("breaker") or {}).get("active", False)
    alert = s.get("active_alert")
    be = cached("backend", 15, backend_ok)
    logc = cached("logc", 15, today_log_counts)
    pev = cached("pii", 15, pii_today)
    svc = {"nginx": bool(s.get("nginx")), "nftables": bool(s.get("nftables")),
           "dashboard": dash_ok, "piiguard": bool(pii.get("service"))}
    # 総合判定
    msgs = []
    level = "ok"
    if not (svc["nginx"] and svc["nftables"] and dash_ok):
        level = "ng"
        msgs.append("止まっている部品があります")
    if brk:
        level = "ng"
        msgs.append("緊急ブレーカーが作動中です（外部からの通信を止めています）")
    if integ.get("state") == "critical":
        level = "ng"
        msgs.append("改ざんの疑いがあります")
    if level != "ng":
        if integ.get("state") == "warn":
            level = "warn"
            msgs.append("整合性チェックに注意があります")
        if alert:
            level = "warn"
            msgs.append("警報: " + str(alert.get("reason", "")))
        if not pcfg.get("enabled", True) or not svc["piiguard"]:
            level = "warn"
            msgs.append("個人情報ガードが止まっています")
        if not be:
            level = "warn"
            msgs.append("サーバー役PC が応答しません")
    headline = {"ok": "守りは正常に働いています", "warn": "確認が必要なことがあります",
                "ng": "すぐに確認してください"}[level]
    # 最近のできごと（警報と個人情報ガード）
    events = []
    for a in (s.get("alert_history") or [])[:8]:
        events.append({"time": str(a.get("time", ""))[11:16], "text": str(a.get("reason", ""))[:60],
                       "ip": a.get("ip", ""), "kind": "alert", "sort": str(a.get("time", ""))})
    for e in pev[-8:]:
        events.append({"time": str(e.get("time", ""))[11:16],
                       "text": "個人情報ガード: " + str(e.get("reason", ""))[:50],
                       "ip": e.get("ip", ""), "kind": e.get("action", "block"), "sort": str(e.get("time", ""))})
    events.sort(key=lambda x: x["sort"], reverse=True)
    dlp = [r for r in (s.get("dlp_rules") or []) if r.get("enabled")]
    mail = s.get("mail") or {}
    with job_lock:
        jb = dict(job)
    with pend_lock:
        pd = {"kind": pending["kind"], "remaining": max(0, int(pending["deadline"] - time.time())),
              "result": pending["result"]} if (pending["kind"] or pending["result"]) else None
    return {
        "version": VERSION, "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "hostname": socket.gethostname(), "level": level, "headline": headline, "messages": msgs,
        "checked": integ.get("checked_at", ""), "integrity": integ.get("state", "unknown"),
        "services": svc, "backend": {"ok": be, "addr": "%s:%s" % (C["backend_ip"], C["backend_port"])},
        "counts": {"requests": logc["requests"], "denied": logc["denied"],
                   "blocked_now": len(s.get("blocked_ips") or []),
                   "pii_today": len(pev), "dlp_rules": len(dlp)},
        "blocked": (s.get("blocked_ips") or [])[:50],
        "events": [{k: v for k, v in e.items() if k != "sort"} for e in events[:6]],
        "net": {"ext_if": EXT_IF, "ext_ip": s.get("ext_ip", ""), "ssid": cached("ssid", 10, wifi_ssid),
                "int_ip": C["int_ip"], "home_net": C["home_net"]},
        "switches": {"pii": bool(pcfg.get("enabled", True)), "monitor_only": bool(pcfg.get("monitor_only")),
                     "mgmt": bool(s.get("wifi_mgmt_open")), "breaker": bool(brk)},
        "mail": {"enabled": bool(mail.get("enabled")), "to": mail.get("to", ""), "host": mail.get("host", ""),
                 "port": mail.get("port", 587), "user": mail.get("user", ""),
                 "configured": bool(mail.get("configured")), "last": mail.get("last_result", "")},
        "uptime": s.get("uptime", ""), "temp": s.get("temp", ""),
        "job": jb, "pending": pd,
    }


# ---------------------------------------------------------------- 自己試験（裏で実行）
job_lock = threading.Lock()
job = {"running": False, "name": "", "lines": [], "ok": None, "done_at": ""}
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run_selftest():
    with job_lock:
        if job["running"]:
            return False
        job.update({"running": True, "name": "自己試験", "lines": [], "ok": None, "done_at": ""})

    def worker():
        lines, rc = [], 1
        try:
            p = subprocess.Popen(["bash", SELFTEST], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for ln in p.stdout:
                ln = ANSI.sub("", ln.rstrip())
                if ln.strip():
                    lines.append(ln[:120])
                    with job_lock:
                        job["lines"] = lines[-40:]
            rc = p.wait(timeout=600)
        except Exception as e:
            lines.append("実行できませんでした: " + str(e))
        with job_lock:
            job.update({"running": False, "lines": lines[-40:], "ok": rc == 0,
                        "done_at": datetime.now().strftime("%H:%M")})
    threading.Thread(target=worker, daemon=True).start()
    return True


# ---------------------------------------------------------------- 確認待ち（元に戻す仕組み）
pend_lock = threading.Lock()
pending = {"kind": "", "deadline": 0.0, "rollback": None, "result": ""}


def start_pending(kind, rollback):
    with pend_lock:
        pending.update({"kind": kind, "deadline": time.time() + CONFIRM_SEC, "rollback": rollback, "result": ""})


def confirm_pending():
    with pend_lock:
        if not pending["kind"]:
            return False
        pending.update({"kind": "", "rollback": None, "result": "保存しました"})
        return True


def pending_loop():
    while True:
        time.sleep(1)
        fn = None
        with pend_lock:
            if pending["kind"] and time.time() > pending["deadline"]:
                fn = pending["rollback"]
                pending.update({"kind": "", "rollback": None, "result": "確認がなかったので元に戻しました"})
        if fn:
            try:
                fn()
            except Exception:
                pass


# ---------------------------------------------------------------- Wi-Fi（NetworkManager）
def nm_split(line):
    return [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]


def wifi_scan():
    if not EXT_IF.startswith("wl"):
        return False, "外側は有線（%s）です。Wi-Fi の設定はありません" % EXT_IF, []
    rc, out = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list",
                   "ifname", EXT_IF, "--rescan", "yes"], 30)
    if rc != 0:
        return False, "Wi-Fi を調べられませんでした", []
    best = {}
    for ln in out.splitlines():
        f = nm_split(ln)
        if len(f) < 4 or not f[1]:
            continue
        ssid = f[1]
        try:
            sig = int(f[2])
        except ValueError:
            sig = 0
        cur = best.get(ssid)
        if not cur or sig > cur["signal"] or f[0] == "*":
            best[ssid] = {"ssid": ssid, "signal": sig, "secure": f[3] not in ("", "--"),
                          "in_use": f[0] == "*" or (cur or {}).get("in_use", False)}
    lst = sorted(best.values(), key=lambda x: (not x["in_use"], -x["signal"]))[:15]
    return True, "", lst


def active_conn():
    rc, out = run(["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"], 10)
    for ln in out.splitlines():
        f = nm_split(ln)
        if len(f) >= 2 and f[1] == EXT_IF:
            return f[0]
    return ""


SSID_RE = re.compile(r"^[^\x00-\x1f]{1,32}$")


def wifi_connect(ssid, pw):
    if not EXT_IF.startswith("wl"):
        return False, "外側は有線です"
    if not SSID_RE.match(ssid or ""):
        return False, "Wi-Fi の名前が正しくありません"
    if pw and not (8 <= len(pw) <= 63):
        return False, "Wi-Fi のパスワードは 8〜63 文字です"
    prev = active_conn()
    cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", EXT_IF]
    if pw:
        cmd += ["password", pw]       # 注: 数秒だけ root のプロセス引数に載る
    rc, out = run(cmd, 60)
    if rc != 0:
        if prev:
            run(["nmcli", "con", "up", "id", prev], 60)
        return False, "接続できませんでした（パスワードか電波を確認してください）"

    def back():
        if prev:
            run(["nmcli", "con", "up", "id", prev], 60)
    start_pending("wifi", back)
    return True, "%s に接続しました" % ssid


# ---------------------------------------------------------------- HTTP
JSON_HDR = "application/json; charset=utf-8"
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
IP_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "gk-kiosk"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def host_ok(self):
        # DNS の付け替えを使った外部ページからの読み取りを防ぐ
        return self.headers.get("Host", "") in ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT)

    def token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "gk_kiosk":
                return v
        return ""

    def send(self, code, obj, cookie=None):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", JSON_HDR)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not self.host_ok():
            self.send_error(403)
            return
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            try:
                with open(HTML_FILE, "rb") as f:
                    b = f.read()
            except Exception:
                self.send_error(500, "kiosk.html がありません")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)
        elif path == "/api/state":
            try:
                st = build_state()
            except Exception as e:
                st = {"level": "ng", "headline": "状態を読み取れません", "messages": [str(e)[:200]]}
            st["authed"] = session_alive(self.token())
            with lock:
                st["idle_left"] = max(0, int(IDLE_SEC - (time.time() - session["seen"]))) if st["authed"] else 0
            self.send(200, st)
        else:
            self.send_error(404)

    def do_POST(self):
        if not self.host_ok():
            self.send_error(403)
            return
        if self.headers.get("X-GK-CSRF") != "1":
            self.send(403, {"ok": False, "msg": "CSRF"})
            return
        origin = self.headers.get("Origin")
        if origin and origin != "null" and origin.split("://", 1)[-1] != self.headers.get("Host", ""):
            self.send(403, {"ok": False, "msg": "origin"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > 65536:
                raise ValueError
            req = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            if not isinstance(req, dict):
                raise ValueError
        except Exception:
            self.send(400, {"ok": False, "msg": "形式が正しくありません"})
            return
        path = self.path.split("?")[0]

        if path == "/api/login":
            now = time.time()
            if now < fails["until"]:
                self.send(429, {"ok": False, "msg": "続けて間違えたため %d 秒待ってください" % int(fails["until"] - now)})
                return
            pw, real = str(req.get("password", "")), admin_pass()
            if real and hmac.compare_digest(pw.encode(), real.encode()):
                fails.update({"n": 0, "until": 0.0})
                tok = new_session()
                self.send(200, {"ok": True, "must_change": must_change()},
                          cookie="gk_kiosk=%s; Path=/; HttpOnly; SameSite=Strict" % tok)
            else:
                fails["n"] += 1
                if fails["n"] >= FAIL_MAX:
                    fails.update({"n": 0, "until": now + FAIL_LOCK})
                time.sleep(1)
                self.send(401, {"ok": False, "msg": "パスワードが違います"})
            return

        if not session_ok(self.token()):
            self.send(401, {"ok": False, "msg": "ロックされました。もう一度パスワードを入れてください"})
            return

        if path == "/api/logout":
            end_session()
            self.send(200, {"ok": True}, cookie="gk_kiosk=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
            return

        if path == "/api/ping":
            self.send(200, {"ok": True})
            return

        if path == "/api/password":
            new, cur = str(req.get("new", "")), str(req.get("current", ""))
            real = admin_pass()
            if not must_change() and not hmac.compare_digest(cur.encode(), real.encode()):
                self.send(200, {"ok": False, "msg": "今のパスワードが違います"})
            elif not PASS_RE.match(new):
                self.send(200, {"ok": False, "msg": "10文字以上で、英数字と一部の記号（\" ' \\ $ ` # と空白は不可）にしてください"})
            elif hmac.compare_digest(new.encode(), real.encode()):
                self.send(200, {"ok": False, "msg": "今と同じパスワードは使えません"})
            else:
                try:
                    write_pass(new)
                    set_must_change(False)
                    self.send(200, {"ok": True, "msg": "パスワードを変更しました（管理画面も同じパスワードになります）"})
                except Exception:
                    self.send(200, {"ok": False, "msg": "保存できませんでした（読み取り専用モードではありませんか）"})
            return

        # ここから先は初期パスワードのままでは使えない
        if must_change():
            self.send(403, {"ok": False, "msg": "先に新しいパスワードを決めてください"})
            return

        try:
            self.route(path, req)
        except Exception as e:
            self.send(200, {"ok": False, "msg": "処理できませんでした: " + str(e)[:120]})

    def route(self, path, req):
        if path == "/api/wifi/scan":
            ok, msg, lst = wifi_scan()
            self.send(200, {"ok": ok, "msg": msg, "list": lst})

        elif path == "/api/wifi/connect":
            ok, msg = wifi_connect(str(req.get("ssid", "")), str(req.get("password", "")))
            self.send(200, {"ok": ok, "msg": msg, "confirm_sec": CONFIRM_SEC if ok else 0})

        elif path == "/api/confirm":
            self.send(200, {"ok": confirm_pending()})

        elif path == "/api/switch":
            name, val = req.get("name"), bool(req.get("value"))
            if name == "pii":
                r = dash("/api/pii_guard/set", {"enabled": val})
            elif name == "monitor_only":
                r = dash("/api/pii_guard/set", {"monitor_only": val})
            elif name == "mgmt":
                r = dash("/api/wifi_mgmt", {"action": "open" if val else "close"})
            elif name == "breaker":
                r = dash("/api/killswitch", {"action": "cut_ext" if val else "restore", "confirm": "yes"})
            else:
                self.send(200, {"ok": False, "msg": "不明なスイッチです"})
                return
            self.send(200, {"ok": bool(r.get("success", True)), "msg": r.get("msg", "")})

        elif path == "/api/unblock":
            ips = []
            if req.get("all"):
                ips = dash("/api/status").get("blocked_ips") or []
            elif IP_RE.match(str(req.get("ip", ""))):
                ips = [str(req.get("ip"))]
            for ip in ips[:500]:
                dash("/api/unblock", {"ip": ip})
            self.send(200, {"ok": True, "msg": "%d 件を解除しました" % len(ips)})

        elif path == "/api/mail":
            body = {"enabled": bool(req.get("enabled"))}
            to = str(req.get("to", "")).strip()
            if to and not all(EMAIL_RE.match(a.strip()) for a in to.split(",")):
                self.send(200, {"ok": False, "msg": "宛先の形が正しくありません"})
                return
            host = str(req.get("host", "")).strip()
            if host and not HOST_RE.match(host):
                self.send(200, {"ok": False, "msg": "送信サーバーの形が正しくありません"})
                return
            for k in ("to", "host", "user"):
                v = str(req.get(k, "")).strip()
                if v or k in req:
                    body[k] = v[:200]
            if req.get("port"):
                body["port"] = int(req.get("port"))
            if req.get("pass"):
                body["pass"] = str(req.get("pass"))[:200]
            r = dash("/api/mail/set", body)
            self.send(200, {"ok": bool(r.get("success")), "msg": "保存しました" if r.get("success") else "保存できませんでした"})

        elif path == "/api/mail/test":
            r = dash("/api/mail/test", {}, timeout=40)
            self.send(200, {"ok": bool(r.get("success")), "msg": r.get("msg", "")})

        elif path == "/api/report/send":
            r = dash("/api/report/send", {}, timeout=60)
            self.send(200, {"ok": bool(r.get("success")), "msg": r.get("msg", "")})

        elif path == "/api/selftest":
            ok = os.path.exists(SELFTEST) and run_selftest()
            self.send(200, {"ok": bool(ok), "msg": "" if ok else "自己試験を始められませんでした（実行中か、試験の部品がありません）"})

        elif path == "/api/backend/test":
            _cache.pop("backend", None)
            ok = backend_ok()
            self.send(200, {"ok": ok, "msg": "応答あり" if ok else "応答がありません"})

        elif path == "/api/system":
            act = req.get("action")
            if act not in ("reboot", "poweroff") or req.get("confirm") != "yes":
                self.send(200, {"ok": False, "msg": "確認が必要です"})
                return
            self.send(200, {"ok": True, "msg": "まもなく%sします" % ("再起動" if act == "reboot" else "停止")})
            threading.Timer(2.0, lambda: run(["systemctl", act])).start()

        else:
            self.send(404, {"ok": False, "msg": "not found"})


if __name__ == "__main__":
    threading.Thread(target=pending_loop, daemon=True).start()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("[kiosk] serving on 127.0.0.1:%d" % PORT, flush=True)
    srv.serve_forever()
