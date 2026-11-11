#!/bin/bash
# micro-monban: MyDNS（mydns.jp）の DNS で Let's Encrypt の証明書を取り、ドメインで公開する
#  ・プロバイダやルーターの都合で、外から 80 番に届かないとき用（管理画面のウィザード A は 80 番を使う）
#  ・持ち主の確認は DNS の TXT レコードで行う（DNS-01）。MyDNS の DirectEdit で自動登録・削除する
#  ・証明書の更新も同じ方法で自動（certbot.timer）。MyDNS のマスターID とパスワードは
#    /etc/letsencrypt/mydns.netrc（root だけ読める）に保存する
#
#  使い方:  sudo bash tools/le-mydns.sh <ドメイン> <連絡用メール>
#           sudo bash tools/le-mydns.sh --reset-login <ドメイン> <連絡用メール>   （ID・パスワードを入れ直す）
#           sudo bash tools/le-mydns.sh --revert                                  （ドメインでの公開をやめる）
set -u
[ "$(id -u)" = 0 ] || { echo "sudo で実行してください"; exit 1; }
GK=/opt/gatekeeper
NETRC=/etc/letsencrypt/mydns.netrc
HOOK=$GK/le-mydns-hook.sh
DEPLOY_HOOK=$GK/gk_cert_deploy.sh
PUBLIC_SITE=/etc/nginx/sites-available/gatekeeper-public
PUBLIC_LINK=/etc/nginx/sites-enabled/gatekeeper-public
HTTPS_BODY=/etc/nginx/snippets/gatekeeper_https_body.conf
PUBLISH_FILE=$GK/publish.json
die(){ echo "✗ $*" >&2; exit 1; }
reload_checked(){ nginx -t >/dev/null 2>&1 && systemctl reload nginx; }
rebuild(){ GK_REBUILD_MANIFEST=1 python3 $GK/dashboard.py >/dev/null 2>&1; }

if [ "${1:-}" = "--revert" ]; then
  [ -L "$PUBLIC_LINK" ] && rm -f "$PUBLIC_LINK"
  reload_checked && echo "✓ ドメインでの公開をやめました（証明書と自動更新は残っています）"
  python3 - "$PUBLISH_FILE" <<'PY'
import json, sys
p = sys.argv[1]
try: d = json.load(open(p))
except Exception: d = {}
d.setdefault("le", {})["active"] = False
json.dump(d, open(p, "w"), ensure_ascii=False, indent=2)
PY
  rebuild; exit 0
fi
RESET=0; [ "${1:-}" = "--reset-login" ] && { RESET=1; shift; }
DOMAIN="${1:-}"; EMAIL="${2:-}"
echo "$DOMAIN" | grep -qE '^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$' || die "ドメインの書き方が正しくありません（例: example.mydns.jp）"
echo "$EMAIL"  | grep -qE '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' || die "メールアドレスの書き方が正しくありません"
command -v certbot >/dev/null || die "certbot がありません（sudo apt install certbot）"
[ -x "$DEPLOY_HOOK" ] || die "$DEPLOY_HOOK がありません（導入スクリプトを先に実行してください）"
[ -f "$HTTPS_BODY" ] || die "$HTTPS_BODY がありません（導入スクリプトを先に実行してください）"

# 1) MyDNS のログイン情報（画面には出さない）
if [ ! -s "$NETRC" ] || [ "$RESET" = 1 ]; then
  echo "MyDNS のマスターID とパスワードを入れてください（mydns.jp にログインするときのもの。入力は表示されません）"
  read -r -s -p "  マスターID: " MID; echo
  read -r -s -p "  パスワード: " MPW; echo
  [ -n "$MID" ] && [ -n "$MPW" ] || die "空欄があります"
  case "$MID$MPW" in *[[:space:]]*) die "空白を含む ID・パスワードには対応していません";; esac
  ( umask 077; mkdir -p /etc/letsencrypt; printf 'machine www.mydns.jp login %s password %s\n' "$MID" "$MPW" > "$NETRC" )
  unset MID MPW
  echo "✓ ログイン情報を $NETRC に保存しました（root だけ読めます）"
fi
chmod 600 "$NETRC"

# 2) certbot から呼ぶ登録・削除の手順（DirectEdit）。パッケージの conf/le-mydns-hook.sh があればそれを使う
SRC_HOOK="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)/conf/le-mydns-hook.sh"
if [ -f "$SRC_HOOK" ]; then
  install -m 700 "$SRC_HOOK" "$HOOK"
else
cat > "$HOOK" <<'EOS'
#!/bin/bash
# micro-monban: certbot の DNS-01 で、MyDNS に _acme-challenge の TXT を登録（auth）・削除（cleanup）する
NETRC=/etc/letsencrypt/mydns.netrc
case "${1:-}" in auth) CMD=REGIST;; cleanup) CMD=DELETE;; *) echo "auth か cleanup を指定" >&2; exit 2;; esac
code=$(curl -s -m 30 -o /dev/null -w '%{http_code}' --netrc-file "$NETRC" \
  --data-urlencode "CERTBOT_DOMAIN=${CERTBOT_DOMAIN}" \
  --data-urlencode "CERTBOT_VALIDATION=${CERTBOT_VALIDATION}" \
  --data-urlencode "EDIT_CMD=${CMD}" https://www.mydns.jp/directedit.html)
case "$code" in 2??) ;; 401|403) echo "MyDNS: ログインできません（マスターID・パスワードを確認。sudo bash tools/le-mydns.sh --reset-login ...）" >&2; exit 1;;
  *) echo "MyDNS: 登録できませんでした（HTTP $code）" >&2; exit 1;; esac
[ "$CMD" = REGIST ] && sleep 90   # MyDNS の DNS に反映されるまで待つ
exit 0
EOS
fi
chmod 700 "$HOOK"

CB=(certbot certonly --manual --preferred-challenges dns
    --manual-auth-hook "$HOOK auth" --manual-cleanup-hook "$HOOK cleanup"
    -d "$DOMAIN" -m "$EMAIL" --agree-tos -n)

# 3) 試験環境で取得を試す（本番の回数制限を使わない）
echo "== 試験環境で取得を試します（2〜4分。MyDNS への反映を待つ時間を含みます）"
if ! "${CB[@]}" --dry-run 2>&1 | sed 's/^/  /' | tee /tmp/le-mydns.log | grep -vE '^\s*$' ; then :; fi
grep -q 'The dry run was successful' /tmp/le-mydns.log || die "試験取得に失敗しました。上の記録を確認してください（ログイン失敗なら --reset-login で入れ直し）"
echo "✓ 試験取得に成功"

# 4) 本番の証明書
echo "== 本番の証明書を取得します"
"${CB[@]}" --cert-name "$DOMAIN" --keep-until-expiring --deploy-hook "$DEPLOY_HOOK" 2>&1 | sed 's/^/  /'
[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] || die "証明書ファイルが見つかりません"
echo "✓ 証明書: $(openssl x509 -noout -enddate -in /etc/letsencrypt/live/$DOMAIN/fullchain.pem | cut -d= -f2) まで（自動で更新されます）"

# 5) ドメイン用の server を有効にする（管理画面のウィザード A と同じ形）
cat > "$PUBLIC_SITE" <<EOF
# [v1.13.2] インターネット公開（Let's Encrypt・MyDNS の DNS 確認）— tools/le-mydns.sh が生成
server {
    listen 443 ssl;
    server_name $DOMAIN;
    access_log /var/log/nginx/gatekeeper_access.log ai_watch;
    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include $HTTPS_BODY;
}
EOF
ln -sfn "$PUBLIC_SITE" "$PUBLIC_LINK"
if ! reload_checked; then
  rm -f "$PUBLIC_LINK"; reload_checked
  die "nginx に組み込めなかったため元に戻しました（nginx -t で確認してください）"
fi
python3 - "$PUBLISH_FILE" "$DOMAIN" "$EMAIL" <<'PY'
import json, sys
from datetime import datetime
p, dom, mail = sys.argv[1:4]
try: d = json.load(open(p))
except Exception: d = {}
d["le"] = {"domain": dom, "email": mail, "active": True, "method": "dns-mydns",
           "since": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
json.dump(d, open(p, "w"), ensure_ascii=False, indent=2)
PY
rebuild
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/")
echo "✓ https://$DOMAIN/ を正規の証明書で確認: HTTP $code"
echo "✓ 公開しました。証明書の更新は certbot.timer が自動で行います（確かめるとき: sudo certbot renew --dry-run）"
