#!/bin/bash
# =====================================================================
#  micro-monban（マイクロ門番）— 全自動セットアップ v1.13.0
#  「ラズパイで作る、小さいけれど強い門番」
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
#  使い方（Raspberry Pi 上、リポジトリを展開したフォルダで）:
#    sudo bash install/setup-gatekeeper.sh            導入／更新（再実行可）
#    sudo bash install/setup-gatekeeper.sh --verify   導入後の自己診断
#    sudo bash install/setup-gatekeeper.sh --reset-password   管理パスワードを忘れたとき（新しい初期パスワードを作る）
#    sudo bash install/setup-gatekeeper.sh --help     使い方
#
#  何が入るか:
#    nginx（TLS 終端・簡易WAF・DLP・中継）、nftables（入口の守り）、
#    管理画面 dashboard.py（:9000）、個人情報 一括持ち出しガード pii_guard.py、
#    設定レポート、インターネット公開ウィザード（Let's Encrypt / Cloudflare Tunnel）、
#    本体画面のサーバー kiosk.py（127.0.0.1:9100。モニターに出すのは tools/setup-kiosk.sh）
#  変更履歴は CHANGELOG.md を参照。
# =====================================================================
set -e

# =====================================================================
#  ★ 設定ブロック —— 自分の環境に合わせて書き換えるのはここだけ ★
# =====================================================================
# [外部側] 家庭 LAN（ルーター）につながる側
EXT_IF="auto"            # "auto"=自動検出 / 明示するなら "wlan0" "eth1" など（ip -o link で確認）
EXT_IP="auto"            # "auto"=DHCP（ルーターの DHCP 予約で固定するのがおすすめ）
                         #  有線(USB-LAN)なら "192.168.1.167" のように固定も可
EXT_PREFIX="24"          # 外部側のプレフィックス（通常は 24 のまま）
HOME_NET="192.168.1.0/24"  # 家庭 LAN: SSH 許可と管理画面スイッチの開放範囲
                           # ※ ルーターのセグメントが違う人は必ず変更（例: 192.168.0.0/24）
# [閉域側] サーバー役PCと有線1本で直結する側（基本はそのまま）
INT_IF="eth0"
INT_IP="10.0.0.1/24"
BACKEND_IP="10.0.0.2"
BACKEND_PORT="8080"
# [管理画面]
DASH_PORT="9000"
DASH_MODE="switch"       # "switch"=スイッチで外部側に開放できる（HTTPS＋Basic認証）
                         # "port-forward-only"=外部側からは常に遮断（SSH ポートフォワード経由のみ）
# [本体画面] HDMI（タッチ）モニター用。本体の中（127.0.0.1）だけで待ち受ける
KIOSK_PORT="9100"
# =====================================================================

VERSION="v1.14.3"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
GK=/opt/gatekeeper
MODE="${1:-install}"

case "$MODE" in
  --help|-h)
    echo "用法: sudo bash install/setup-gatekeeper.sh [オプション]"
    echo "  (引数なし)  導入／更新"
    echo "  --verify    導入後の自己診断"
    echo "  --reset-password  管理パスワードを忘れたとき。新しい初期パスワードを作って1回だけ表示する"
    echo "              （ほかの設定・記録はそのまま。本体画面では最初にまた変更を求められる）"
    echo "  --help      この表示"
    echo ""
    echo "環境に合わせるときは、このファイル冒頭の設定ブロックを編集してから再実行してください。"
    exit 0 ;;
  --verify) VERIFY=1 ;;
  --reset-password) VERIFY=0 ;;
  install|"") VERIFY=0 ;;
  *) echo "不明なオプション: $MODE（--help を参照）" >&2; exit 1 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "sudo で実行してください: sudo bash $0" >&2; exit 1; }

# =====================================================================
#  --reset-password: 管理パスワードを忘れたとき
#   ・新しい初期パスワードを作り、1回だけ表示する（ほかの設定・記録・証明書はそのまま）
#   ・管理画面と本体画面の両方に効く。本体画面では最初に新しいパスワードを決め直す
# =====================================================================
if [ "$MODE" = "--reset-password" ]; then
  [ -d $GK ] || { echo "門番が導入されていません（$GK がありません）" >&2; exit 1; }
  read -r -p "管理パスワードを作り直します。今のパスワードは使えなくなります。yes と入力: " ans
  [ "$ans" = "yes" ] || { echo "取りやめました"; exit 1; }
  NEW_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  umask 077
  printf 'GK_ADMIN_PASS=%s\n' "$NEW_PASS" > $GK/secret.conf.tmp && mv $GK/secret.conf.tmp $GK/secret.conf
  printf '{"initial_sha256": "%s"}\n' "$(printf '%s' "$NEW_PASS" | sha256sum | cut -d' ' -f1)" > $GK/kiosk.json
  chmod 600 $GK/secret.conf $GK/kiosk.json
  systemctl restart gatekeeper-dashboard
  systemctl is-enabled --quiet gatekeeper-kiosk 2>/dev/null && systemctl restart gatekeeper-kiosk
  echo ""
  echo "【新しい初期パスワード（この1回だけ表示）】 $NEW_PASS"
  echo "  管理画面（ユーザー名 admin）と本体画面の共通です。本体画面では最初に新しいパスワードを決めてください。"
  exit 0
fi

INT_ADDR="${INT_IP%/*}"
INT_NET="$(echo "$INT_ADDR" | cut -d. -f1-3).0/${INT_IP#*/}"

# 外部側 IF の自動検出: デフォルト経路を持つ IF。無ければ Wi-Fi/有線から閉域側を除いて選ぶ
if [ "$EXT_IF" = "auto" ]; then
  EXT_IF="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
  if [ -z "$EXT_IF" ] || [ "$EXT_IF" = "$INT_IF" ]; then
    EXT_IF="$(ls /sys/class/net 2>/dev/null | grep -E '^(wl|eth|en)' | grep -v "^${INT_IF}$" | head -n1)"
  fi
fi
if [ -z "$EXT_IF" ] || [ "$EXT_IF" = "$INT_IF" ]; then
  echo "⚠ 外部側インターフェースを特定できませんでした（閉域側 $INT_IF との重複は不可）。" >&2
  echo "  ip -o link で IF 名を確認し、設定ブロックの EXT_IF に明示してください。" >&2
  exit 1
fi
echo "・外部側インターフェース: $EXT_IF（設定: EXT_IF）"

# =====================================================================
#  配布物の照合（SHA256SUMS.txt）
#   ・改ざんや、Windows を経由したときの改行の変化（CRLF）に気づくため
#   ・このファイル自身は設定ブロックを書き換えて使うので照合から外し、改行だけ確かめる
# =====================================================================
SUMS_BAD=""; SUMS_CR=""; SUMS_STATE="none"
if [ -f "$REPO/SHA256SUMS.txt" ]; then
  SUMS_BAD=$(cd "$REPO" && grep -v '[ *]install/setup-gatekeeper\.sh$' SHA256SUMS.txt \
             | sha256sum -c --quiet - 2>/dev/null | sed 's/: .*//' | tr '\n' ' ' || true)
  SUMS_STATE="ok"; [ -n "$SUMS_BAD" ] && SUMS_STATE="bad"
fi
SUMS_CR=$(cd "$REPO" && grep -rlI $'\r' --include='*.sh' --include='*.py' --include='*.conf' \
          --include='*.tmpl' --include='*.service' --include='*.json' . 2>/dev/null | tr '\n' ' ' || true)

# =====================================================================
#  --verify: 導入後の自己診断
# =====================================================================
if [ "$VERIFY" = "1" ]; then
  FAIL=0; WARN=0
  ok(){ echo "  ✓ $1"; }
  ng(){ echo "  ✗ $1"; FAIL=$((FAIL+1)); }
  wr(){ echo "  △ $1"; WARN=$((WARN+1)); }
  echo "=== micro-monban 自己診断（$VERSION） ==="
  case "$SUMS_STATE" in
    ok)   ok "配布物の照合: SHA256SUMS.txt と一致" ;;
    bad)  wr "配布物の照合: 一致しないファイル → $SUMS_BAD（自分で直したのでなければ、入手し直してください）" ;;
    none) wr "配布物の照合: SHA256SUMS.txt が無いので省略" ;;
  esac
  [ -z "$SUMS_CR" ] && ok "改行: Windows 形式（CRLF）のファイル無し" || ng "改行が Windows 形式のファイル → $SUMS_CR（zip のまま Pi へ送って展開し直してください）"
  for f in /etc/nginx/sites-enabled/gatekeeper /etc/nginx/snippets/gatekeeper_https_body.conf \
           /etc/nginx/conf.d/gatekeeper_realip.conf $GK/dashboard.py $GK/pii_guard.py $GK/config.json \
           /etc/nftables.conf /etc/systemd/system/gatekeeper-dashboard.service \
           /etc/systemd/system/gatekeeper-piiguard.service $GK/kiosk.py $GK/kiosk.html \
           /etc/systemd/system/gatekeeper-kiosk.service; do
    [ -e "$f" ] && ok "ファイル: $f" || ng "ファイル不在: $f"
  done
  for s in nginx nftables gatekeeper-dashboard gatekeeper-piiguard gatekeeper-kiosk; do
    systemctl is-active --quiet $s && ok "$s: ACTIVE" || ng "$s: DOWN（journalctl -u $s -e）"
  done
  nginx -t >/dev/null 2>&1 && ok "nginx 設定テスト合格" || ng "nginx 設定テスト不合格（sudo nginx -t で詳細）"
  nft list set inet filter whitelist >/dev/null 2>&1 && ok "nftables: whitelist あり" || ng "nftables: whitelist が無い"
  nft list chain inet filter wifi_mgmt >/dev/null 2>&1 && ok "nftables: wifi_mgmt あり" || ng "nftables: wifi_mgmt が無い"
  python3 -c "import json; json.load(open('$GK/dlp_rules.json'))" 2>/dev/null && ok "DLP ルール JSON: 有効" || ng "DLP ルール JSON が不正"
  [ -s /etc/nginx/snippets/gatekeeper_dlp.conf ] && ok "DLP スニペット: あり" || ng "DLP スニペットが無い"
  [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ] && ok "ip_forward=0（転送しない）" || ng "ip_forward が 0 ではありません"
  [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "1" ] && ok "IPv6: 無効" || wr "IPv6: 有効（v6 経由は遮断リストが効きません）"
  ip -4 addr show "$INT_IF" 2>/dev/null | grep -q "$INT_ADDR" && ok "$INT_IF に $INT_ADDR" || ng "$INT_IF に $INT_ADDR がありません"
  [ "$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$DASH_PORT/api/status" 2>/dev/null)" = 200 ] && ok "管理画面 API 応答" || ng "管理画面 API 無応答"
  [ "$(curl -s -m 20 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$KIOSK_PORT/api/state" 2>/dev/null)" = 200 ] && ok "本体画面のサーバー応答（127.0.0.1:$KIOSK_PORT）" || ng "本体画面のサーバーが応答しない（journalctl -u gatekeeper-kiosk -e）"
  if [ -f $GK/kiosk.py ] && python3 -B -c "import sys; sys.path.insert(0, '$GK'); import kiosk; sys.exit(0 if kiosk.must_change() else 1)" 2>/dev/null; then
    wr "管理パスワードが初期値のままです（本体画面か $GK/secret.conf で変更してください）"
  fi
  if [ -f "$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/.config/autostart/micro-monban-kiosk.desktop" ]; then
    ok "本体画面: モニターへの自動表示を設定済み"
  else
    wr "本体画面: モニターへの自動表示は未設定（使うときは sudo bash tools/setup-kiosk.sh）"
  fi
  c=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' https://127.0.0.1/ 2>/dev/null)
  [ "$c" != 000 ] && ok "HTTPS(443) 応答: HTTP $c" || ng "HTTPS(443) が応答しない"
  c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$BACKEND_IP:$BACKEND_PORT/" 2>/dev/null)
  [ "$c" != 000 ] && ok "バックエンド $BACKEND_IP:$BACKEND_PORT 応答: HTTP $c" || wr "バックエンド $BACKEND_IP:$BACKEND_PORT 無応答（サーバー役PCの電源・ファイアウォール・アプリを確認）"
  [ -f $GK/tls/ca.key ] && wr "ca.key が装置内に残っています（USB 等へ退避して sudo rm $GK/tls/ca.key を推奨）" || ok "ca.key: 装置内に無し"
  openssl x509 -in $GK/tls/server.crt -noout -checkend 864000 >/dev/null 2>&1 && ok "サーバー証明書: 残り10日以上" || wr "サーバー証明書の期限が近い"
  command -v certbot >/dev/null && ok "certbot: 導入済み（公開ウィザード A 用）" || wr "certbot が無い（公開ウィザード A が使えません）"
  findmnt -n -o FSTYPE / 2>/dev/null | grep -q overlay && ok "読み取り専用モード: 有効" || wr "読み取り専用モード: 無効（tools/enable-readonly.sh で強化できます）"
  echo "-----------------------------"
  if [ "$FAIL" -eq 0 ]; then echo "結果: 合格（FAIL 0 ／ WARN $WARN）✅"; else echo "結果: FAIL $FAIL ／ WARN $WARN — ✗ の項目を解消してください"; fi
  exit "$FAIL"
fi

# =====================================================================
#  導入本体
# =====================================================================
if [ -n "$SUMS_CR" ]; then
  echo "✗ 改行が Windows 形式（CRLF）になっているファイルがあります: $SUMS_CR" >&2
  echo "  このままでは正しく動きません。zip のまま Pi へ送り、Pi の上で展開し直してください。" >&2
  exit 1
fi
case "$SUMS_STATE" in
  ok)   echo "・配布物の照合: SHA256SUMS.txt と一致" ;;
  none) echo "・配布物の照合: SHA256SUMS.txt が無いので省略" ;;
  bad)
    echo "✗ SHA256SUMS.txt と一致しないファイルがあります: $SUMS_BAD" >&2
    echo "  入手の途中で壊れたか、書き換えられた可能性があります。正しい配布元から入手し直してください。" >&2
    echo "  自分で直したファイルだと分かっている場合だけ、GK_SKIP_SUMS=1 を付けて続けられます:" >&2
    echo "    sudo GK_SKIP_SUMS=1 bash install/setup-gatekeeper.sh" >&2
    [ "${GK_SKIP_SUMS:-0}" = "1" ] || exit 1
    echo "・GK_SKIP_SUMS=1 のため照合の不一致を無視して続けます" ;;
esac
for f in src/dashboard.py src/pii_guard.py conf/nginx/gatekeeper.site.tmpl conf/nginx/gatekeeper_https_body.conf \
         conf/nginx/log_format.conf conf/nginx/gatekeeper_realip.conf conf/nftables.conf.tmpl \
         conf/systemd/gatekeeper-dashboard.service conf/systemd/gatekeeper-piiguard.service \
         conf/systemd/gatekeeper-kiosk.service src/kiosk.py src/kiosk.html tests/selftest.sh \
         conf/dlp_rules.default.json conf/gk_cert_deploy.sh conf/le-mydns-hook.sh; do
  [ -f "$REPO/$f" ] || { echo "リポジトリのファイルが足りません: $f（リポジトリ全体を展開してから実行してください）" >&2; exit 1; }
done
grep -q $'\r' "$REPO/src/dashboard.py" && { echo "改行コードが CRLF になっています。Windows で展開した場合は Git の設定（core.autocrlf=false）を確認してください。" >&2; exit 1; }

echo "=== [1/9] システム更新と必須パッケージ ==="
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx libnginx-mod-http-subs-filter nftables curl jq python3 openssl certbot

echo "=== [2/9] IP 転送の無効化・IPv6 の無効化・sshd を IPv4 に固定 ==="
sysctl -w net.ipv4.ip_forward=0 >/dev/null
echo "net.ipv4.ip_forward = 0" > /etc/sysctl.d/99-no-forward.conf
printf 'net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\n' > /etc/sysctl.d/98-disable-ipv6.conf
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
if [ -d /etc/ssh/sshd_config.d ]; then
  echo "AddressFamily inet" > /etc/ssh/sshd_config.d/99-gatekeeper-inet.conf
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi
# 使っていない rpcbind（111番）は止める（NFS を使っていない場合だけ）
if systemctl list-unit-files rpcbind.service >/dev/null 2>&1 && [ "$(findmnt -t nfs,nfs4 -n | wc -l)" = 0 ]; then
  systemctl disable --now rpcbind.socket rpcbind.service >/dev/null 2>&1 || true
  systemctl mask rpcbind.socket rpcbind.service >/dev/null 2>&1 || true
  echo "・rpcbind（111番）を停止しました（戻すとき: sudo systemctl unmask rpcbind.service rpcbind.socket）"
fi

echo "=== [3/9] 閉域 LAN（$INT_IF: $INT_IP）と外部側の設定 ==="
nmcli connection delete internal-lan >/dev/null 2>&1 || true
nmcli connection add type ethernet con-name internal-lan ifname "$INT_IF" ip4 "$INT_IP" >/dev/null
nmcli connection up internal-lan >/dev/null || echo "・$INT_IF はまだリンクしていません（ケーブル接続後に自動で有効になります）"
if [ "$EXT_IP" = "auto" ]; then
  echo "・外部側 $EXT_IF は DHCP のまま（ルーターの DHCP 予約で固定するのがおすすめ）"
elif [ -d "/sys/class/net/$EXT_IF/wireless" ]; then
  echo "⚠ $EXT_IF は Wi-Fi です。Wi-Fi の固定 IP は自動化しません（ルーターの DHCP 予約をお使いください）。"
else
  nmcli connection delete external-net >/dev/null 2>&1 || true
  nmcli connection add type ethernet con-name external-net ifname "$EXT_IF" ip4 "$EXT_IP/$EXT_PREFIX" >/dev/null
  nmcli connection up external-net >/dev/null || true
  echo "・外部側 $EXT_IF に $EXT_IP/$EXT_PREFIX を設定しました"
fi

echo "=== [4/9] TLS 証明書（門番のローカル認証局） ==="
TLS_DIR=$GK/tls
mkdir -p "$TLS_DIR"
if [ -s "$TLS_DIR/server.crt" ] && [ -s "$TLS_DIR/server.key" ]; then
  echo "・既存の証明書を引き継ぎます ($TLS_DIR)"
else
  if [ ! -s "$TLS_DIR/ca.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" \
      -days 3650 -subj "/CN=micro-monban Local CA" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    echo "・ローカル認証局を作成しました"
  fi
  EXT_IP_NOW="$(ip -4 addr show "$EXT_IF" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  SAN="DNS:gatekeeper.local,IP:127.0.0.1"
  [ -n "$EXT_IP_NOW" ] && SAN="$SAN,IP:$EXT_IP_NOW"
  SAN="$SAN,IP:$INT_ADDR"
  openssl req -newkey rsa:2048 -nodes -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" -subj "/CN=gatekeeper.local" 2>/dev/null
  EXT_FILE="$(mktemp)"
  printf "subjectAltName=%s\nextendedKeyUsage=serverAuth" "$SAN" > "$EXT_FILE"
  openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -out "$TLS_DIR/server.crt" -days 825 -extfile "$EXT_FILE" 2>/dev/null
  rm -f "$EXT_FILE" "$TLS_DIR/server.csr" "$TLS_DIR/ca.srl"
  chmod 600 "$TLS_DIR/ca.key" "$TLS_DIR/server.key"
  echo "・サーバー証明書を作成しました（SAN: $SAN）"
fi
echo "  ※ ca.key は USB 等へ退避し、sudo rm $TLS_DIR/ca.key で装置から消すのがおすすめです（稼働に影響なし）"

echo "=== [5/9] 門番の設定ファイル（/opt/gatekeeper） ==="
mkdir -p $GK /var/lib/gatekeeper/pii /var/lib/gatekeeper/reports /var/www/acme/.well-known/acme-challenge
chown www-data:www-data /var/lib/gatekeeper/pii && chmod 750 /var/lib/gatekeeper/pii
chmod -R 755 /var/www/acme
python3 - "$GK/config.json" <<PY
import json, sys
c = {"ext_if": "$EXT_IF", "home_net": "$HOME_NET", "int_if": "$INT_IF", "int_ip": "$INT_ADDR",
     "backend_ip": "$BACKEND_IP", "backend_port": int("$BACKEND_PORT"), "dash_port": int("$DASH_PORT"),
     "dash_mode": "$DASH_MODE", "kiosk_port": int("$KIOSK_PORT")}
json.dump(c, open(sys.argv[1], "w"), ensure_ascii=False, indent=2)
PY
chmod 644 $GK/config.json
echo "・環境の設定を書き出しました: $GK/config.json"
if [ -s $GK/secret.conf ]; then
  echo "・既存の管理パスワードを引き継ぎます（$GK/secret.conf）"
  NEW_PASS=""
else
  NEW_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  printf 'GK_ADMIN_PASS=%s\n' "$NEW_PASS" > $GK/secret.conf
  # 初期パスワード: 本体画面では、最初に新しいパスワードを決めるまで設定に進めない
  #  （初期パスワードそのものは残さず、指紋 sha256 だけを残す。今のパスワードと同じ間は「初期のまま」）
  printf '{"initial_sha256": "%s"}\n' "$(printf '%s' "$NEW_PASS" | sha256sum | cut -d' ' -f1)" > $GK/kiosk.json
fi
chmod 600 $GK/secret.conf
[ -f $GK/kiosk.json ] || echo '{"must_change": false}' > $GK/kiosk.json
chmod 600 $GK/kiosk.json
if [ -s $GK/dlp_rules.json ]; then
  echo "・既存の DLP ルールを引き継ぎます"
  # 以前の版から更新する場合、新しい既定ルール（html_cred など）だけを足す
  python3 - "$GK/dlp_rules.json" "$REPO/conf/dlp_rules.default.json" <<'PY'
import json, sys
cur, dflt = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
ids = {r.get("id") for r in cur}
add = [r for r in dflt if r.get("id") not in ids]
if add:
    json.dump(cur + add, open(sys.argv[1], "w"), ensure_ascii=False, indent=2)
    print("・新しい既定 DLP ルールを追加: " + ", ".join(r["id"] for r in add))
PY
else
  install -m 644 "$REPO/conf/dlp_rules.default.json" $GK/dlp_rules.json
  echo "・DLP ルール 15 種を登録しました（11 種 ON ／ 内部IP・メール・マイナンバー・カードは OFF）"
fi
[ -f $GK/pii_guard.json ] || echo '{"enabled": true, "monitor_only": false, "max_per_response": 5, "window_limit": 30, "window_sec": 600}' > $GK/pii_guard.json
chmod 644 $GK/pii_guard.json
[ -f $GK/report.json ] || echo '{"enabled": true, "weekday": 0, "hour": 9, "on_change": true, "to": ""}' > $GK/report.json
install -m 644 "$REPO/src/dashboard.py" $GK/dashboard.py
install -m 644 "$REPO/src/pii_guard.py" $GK/pii_guard.py
install -m 644 "$REPO/src/kiosk.py" $GK/kiosk.py
install -m 644 "$REPO/src/kiosk.html" $GK/kiosk.html
install -m 755 "$REPO/tests/selftest.sh" $GK/selftest.sh
install -m 755 "$REPO/conf/gk_cert_deploy.sh" $GK/gk_cert_deploy.sh
install -m 700 "$REPO/conf/le-mydns-hook.sh" $GK/le-mydns-hook.sh     # [v1.14.0] MyDNS の DNS 確認（証明書）
rm -f $GK/__pycache__/dashboard.cpython-*.pyc

echo "=== [6/9] nginx（TLS 終端・WAF・DLP・中継） ==="
install -m 644 "$REPO/conf/nginx/log_format.conf" /etc/nginx/conf.d/log_format.conf
install -m 644 "$REPO/conf/nginx/gatekeeper_realip.conf" /etc/nginx/conf.d/gatekeeper_realip.conf
mkdir -p /etc/nginx/snippets
install -m 644 "$REPO/conf/nginx/gatekeeper_https_body.conf" /etc/nginx/snippets/gatekeeper_https_body.conf
[ -f /etc/nginx/snippets/gatekeeper_deny.conf ] || echo "# micro-monban: ダッシュボードが自動生成（自動遮断中の IP）" > /etc/nginx/snippets/gatekeeper_deny.conf
sed -e "s|@@BACKEND_IP@@|$BACKEND_IP|g" -e "s|@@BACKEND_PORT@@|$BACKEND_PORT|g" \
  "$REPO/conf/nginx/gatekeeper.site.tmpl" > /etc/nginx/sites-available/gatekeeper
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/gatekeeper /etc/nginx/sites-enabled/gatekeeper
# DLP スニペットの生成（dashboard.py と同じ形式）
python3 - <<'PY'
import json
rules = json.load(open("/opt/gatekeeper/dlp_rules.json"))
lines = ["# /etc/nginx/snippets/gatekeeper_dlp.conf - Gatekeeper dashboard generated (do not edit)"]
for r in rules:
    if r.get("enabled"):
        lines.append("subs_filter '" + r["pattern"].replace("'", "") + "' '" + r["replacement"].replace("'", "") + "' irg;")
open("/etc/nginx/snippets/gatekeeper_dlp.conf", "w").write("\n".join(lines) + "\n")
PY
nginx -t

echo "=== [7/9] nftables（入口の守り） ==="
if [ "$DASH_MODE" = "port-forward-only" ]; then
  JUMP_LINE="# 管理画面: 外部側からは常に遮断（SSH ポートフォワード経由のみ）"
else
  JUMP_LINE="iif \"$EXT_IF\" tcp dport $DASH_PORT jump wifi_mgmt"
fi
sed -e "s|@@INT_IF@@|$INT_IF|g" -e "s|@@EXT_IF@@|$EXT_IF|g" -e "s|@@HOME_NET@@|$HOME_NET|g" \
    -e "s|@@INT_NET@@|$INT_NET|g" -e "s|@@DASH_PORT@@|$DASH_PORT|g" -e "s|@@DASH_JUMP@@|$JUMP_LINE|g" \
    "$REPO/conf/nftables.conf.tmpl" > /etc/nftables.conf
nft -c -f /etc/nftables.conf
systemctl enable nftables >/dev/null
systemctl restart nftables

echo "=== [8/9] サービス（管理画面・個人情報ガード・本体画面）と証拠ログの転送 ==="
install -m 644 "$REPO/conf/systemd/gatekeeper-dashboard.service" /etc/systemd/system/gatekeeper-dashboard.service
install -m 644 "$REPO/conf/systemd/gatekeeper-piiguard.service" /etc/systemd/system/gatekeeper-piiguard.service
install -m 644 "$REPO/conf/systemd/gatekeeper-kiosk.service" /etc/systemd/system/gatekeeper-kiosk.service
systemctl daemon-reload
systemctl enable gatekeeper-piiguard gatekeeper-dashboard gatekeeper-kiosk >/dev/null
systemctl restart gatekeeper-piiguard
if command -v rsyslogd >/dev/null 2>&1; then
  printf '# micro-monban: 証拠ログをバックエンド(%s)へ転送（受信側の設定は docs を参照）\n*.* @%s:514\n' "$BACKEND_IP" "$BACKEND_IP" > /etc/rsyslog.d/90-gatekeeper-remote.conf
  systemctl restart rsyslog || true
fi

echo "=== [9/9] 最終反映 ==="
GK_REBUILD_MANIFEST=1 python3 $GK/dashboard.py >/dev/null
systemctl restart gatekeeper-dashboard
systemctl restart gatekeeper-kiosk
nginx -t && systemctl restart nginx
sleep 3
for s in nginx nftables gatekeeper-piiguard gatekeeper-dashboard gatekeeper-kiosk; do
  systemctl is-active --quiet $s && echo "  ✓ $s" || echo "  ✗ $s が動いていません（journalctl -u $s -e）"
done

echo ""
echo "=== micro-monban $VERSION の導入が完了しました ==="
echo "・管理画面（閉域側・認証なし）  : https://$INT_ADDR:$DASH_PORT/"
echo "・管理画面（家庭 LAN 側）       : スイッチを開けたときだけ https://<外部側IP>:$DASH_PORT/（ユーザー名 admin）"
echo "・公開 Web（中継）              : https://<外部側IP>/"
echo "・本体画面（HDMI モニター用）   : 本体の中だけ http://127.0.0.1:$KIOSK_PORT/（モニターに出すのは sudo bash tools/setup-kiosk.sh）"
if [ -n "$NEW_PASS" ]; then
  echo ""
  echo "【初期パスワード（この1回だけ表示）】 $NEW_PASS"
  echo "  管理画面と本体画面の共通のパスワードです。控えておいてください（あとで確認: sudo cat $GK/secret.conf）"
  echo "  本体画面では、最初にこの初期パスワードで開くと新しいパスワードを決める画面になります"
  echo "  画面を使わないときは $GK/secret.conf の GK_ADMIN_PASS を書き換えて sudo systemctl restart gatekeeper-dashboard"
fi
echo ""
echo "次の一歩:"
echo "  1) 自己診断:                sudo bash $0 --verify"
echo "  2) サーバー役PC の設定:     backend/ の手順（Windows は setup-windows.bat）"
echo "  3) ca.key の退避と削除:     docs の「証明書」の章"
echo "  4) インターネットに公開:    管理画面の「🌐 インターネット公開」"
echo "  5) 本体にモニターをつなぐ:  sudo bash tools/setup-kiosk.sh（デスクトップ付きの OS が必要）"
