#!/bin/bash
# =====================================================================
#  micro-monban 自己試験（導入後に、守りが実際に働いているかを確かめる）
#    sudo bash tests/selftest.sh
#  ・門番の中（127.0.0.1）から要求を送るので、自分の PC が遮断される心配はない
#  ・試験用 IP には文書用に予約された 198.51.100.x（実在しない）を使い、最後に片付ける
#  ・サーバー役PC に tests/dlp_test.php や個人情報の試験ページがあれば、それも試す
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
set -u
[ "$(id -u)" = 0 ] || { echo "sudo で実行してください" >&2; exit 1; }
GK=/opt/gatekeeper
LOG=/var/log/nginx/gatekeeper_access.log
DENY=/etc/nginx/snippets/gatekeeper_deny.conf
DASH_PORT=$(python3 -c "import json; print(json.load(open('$GK/config.json')).get('dash_port', 9000))" 2>/dev/null || echo 9000)
API="https://127.0.0.1:$DASH_PORT"
ok=0; ng=0; sk=0
res(){ case "$1" in OK) ok=$((ok+1));; NG) ng=$((ng+1));; *) sk=$((sk+1));; esac; printf '  [%s] %s\n' "$1" "$2"; }
code(){ curl -sk -m 15 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
hd(){ echo; echo "== $*"; }

hd "サービス"
for s in nginx nftables gatekeeper-dashboard gatekeeper-piiguard; do
  systemctl is-active --quiet $s && res OK "$s が動いている" || res NG "$s が止まっている"
done

hd "入口（nginx・WAF）"
c=$(code https://127.0.0.1/);                                  [ "$c" != 000 ] && [ "$c" != 403 ] && res OK "HTTPS が応答（HTTP $c）" || res NG "HTTPS が応答しない（$c）"
c=$(code http://127.0.0.1/);                                   [ "$c" = 308 ] && res OK "80番 → HTTPS へ転送（308）" || res NG "80番の転送（$c）"
c=$(code -A sqlmap/1.0 https://127.0.0.1/);                    [ "$c" = 403 ] && res OK "WAF: スキャナを拒否（403）" || res NG "WAF: スキャナ（$c）"
c=$(code "https://127.0.0.1/?id=1+union+select+1");            [ "$c" = 403 ] && res OK "WAF: SQL インジェクションを拒否（403）" || res NG "WAF: SQLi（$c）"
c=$(code "https://127.0.0.1/?id=1%20and%20sleep%285%29");      [ "$c" = 403 ] && res OK "WAF: エンコードした sleep( を拒否（403）" || res NG "WAF: sleep%28（$c）"
c=$(code "https://127.0.0.1/?q=order%20by%20date%202");        [ "$c" != 403 ] && res OK "WAF: 普通の文章は通す（$c）" || res NG "WAF: 普通の文章を誤って拒否"
c=$(code --path-as-is "https://127.0.0.1/%2e%2e/etc/passwd");  [ "$c" = 400 ] || [ "$c" = 403 ] && res OK "パストラバーサルを拒否（$c）" || res NG "パストラバーサル（$c）"
# [v1.13.1] 引数に入れた符号化パストラバーサル（%2e%2e%2f・..%5c）も拒否する（以前は素通りしていた）
c=$(code "https://127.0.0.1/?f=%2e%2e%2fetc%2fpasswd");        [ "$c" = 403 ] && res OK "WAF: 符号化した ../ を拒否（403）" || res NG "WAF: %2e%2e%2f（$c）"
c=$(code "https://127.0.0.1/?f=..%5c..%5cwin.ini");            [ "$c" = 403 ] && res OK "WAF: Windows 形式の ..\\ を拒否（403）" || res NG "WAF: ..%5c（$c）"
# [v1.14.1] 隠しファイルの探り（.env・.git）は奥へ渡さず 404
c=$(code "https://127.0.0.1/.env");  c2=$(code "https://127.0.0.1/.git/config")
[ "$c" = 404 ] && [ "$c2" = 404 ] && res OK "WAF: 隠しファイル（.env・.git）の探りを 404" || res NG "WAF: 隠しファイル（.env $c / .git $c2）"
TOK="gk-selftest-$$"; mkdir -p /var/www/acme/.well-known/acme-challenge; echo "$TOK" > /var/www/acme/.well-known/acme-challenge/$TOK
b=$(curl -s -m 10 http://127.0.0.1/.well-known/acme-challenge/$TOK); rm -f /var/www/acme/.well-known/acme-challenge/$TOK
[ "$b" = "$TOK" ] && res OK "証明書確認用の通り道（転送されずに届く）" || res NG "証明書確認用の通り道"
h=$(curl -skI -m 10 https://127.0.0.1/ | tr -d '\r')
echo "$h" | grep -qi '^x-powered-by' && res NG "X-Powered-By が外に出ている" || res OK "バックエンドの版数（X-Powered-By）を隠している"
echo "$h" | grep -qi '^strict-transport-security' && res OK "HSTS を付けている" || res NG "HSTS が無い"

hd "本当の利用者 IP と遮断の nginx 反映"
curl -sk -m 10 -o /dev/null -H 'CF-Connecting-IP: 198.51.100.77' https://127.0.0.1/; sleep 1
tail -n 5 $LOG | grep -q '"remote_addr":"198.51.100.77"' && res OK "Cloudflare 経由を想定した利用者 IP の読み取り" || res NG "利用者 IP が記録されない"
nft add element inet filter dynamic_blocks '{ 198.51.100.99 timeout 180s }'
n=0; until grep -q 'deny 198.51.100.99;' $DENY 2>/dev/null || [ $n -ge 45 ]; do sleep 3; n=$((n+3)); done
if grep -q 'deny 198.51.100.99;' $DENY 2>/dev/null; then
  sleep 2; c=$(code -H 'CF-Connecting-IP: 198.51.100.99' https://127.0.0.1/)
  [ "$c" = 403 ] && res OK "遮断した IP を nginx でも拒否（${n}秒で反映）" || res NG "nginx 側の拒否が効かない（$c）"
else res NG "遮断した IP が nginx に反映されない"; fi
nft delete element inet filter dynamic_blocks '{ 198.51.100.99 }' 2>/dev/null
n=0; until ! grep -q 'deny 198.51.100.99;' $DENY 2>/dev/null || [ $n -ge 45 ]; do sleep 3; n=$((n+3)); done
grep -q 'deny 198.51.100.99;' $DENY 2>/dev/null && res NG "解除が nginx に反映されない" || res OK "解除も nginx に反映（${n}秒）"

hd "管理画面"
c=$(code "$API/api/status");                                   [ "$c" = 200 ] && res OK "状態 API が応答" || res NG "状態 API（$c）"
c=$(code -X POST "$API/api/dlp/test" -d '{"text":"x"}');       [ "$c" = 403 ] && res OK "CSRF 対策: 専用ヘッダの無い POST を拒否（403）" || res NG "CSRF 対策（$c）"
c=$(code -X POST -H 'X-GK-CSRF: 1' "$API/api/dlp/test" -d '{"text":"TEL 03-1234-5678"}'); [ "$c" = 200 ] && res OK "専用ヘッダ付きの POST は通す（200）" || res NG "正しい POST（$c）"
m=$(curl -sk -m 15 -X POST -H 'X-GK-CSRF: 1' "$API/api/dlp/test" -d '{"text":"TEL 03-1234-5678"}' 2>/dev/null)
echo "$m" | grep -q 'PHONE_NUMBER_PROTECTED' && res OK "DLP の試験機能（電話番号が伏せ字になる）" || res NG "DLP の試験機能"
curl -sk -m 30 -X POST -H 'X-GK-CSRF: 1' "$API/api/integrity/recheck" -o /dev/null 2>/dev/null
st=$(curl -sk -m 20 "$API/api/status" 2>/dev/null | python3 -c "import json,sys; i=json.load(sys.stdin)['integrity']; print(i['state'], ' / '.join(f['msg'] for f in i['findings']))" 2>/dev/null)
case "$st" in ok*) res OK "整合性チェック ok";; *) res NG "整合性チェック: $st";; esac

hd "本体画面のサーバー（v1.13.0）"
KPORT=$(python3 -c "import json; print(json.load(open('$GK/config.json')).get('kiosk_port', 9100))" 2>/dev/null || echo 9100)
KS="http://127.0.0.1:$KPORT"
if [ -f $GK/kiosk.py ] && [ -f /etc/systemd/system/gatekeeper-kiosk.service ]; then
  systemctl is-active --quiet gatekeeper-kiosk && res OK "gatekeeper-kiosk が動いている" || res NG "gatekeeper-kiosk が止まっている"
  c=$(curl -s -m 20 -o /dev/null -w '%{http_code}' "$KS/api/state");                          [ "$c" = 200 ] && res OK "状態の読み取り（200）" || res NG "状態の読み取り（$c）"
  c=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "$KS/api/state");   [ "$c" = 403 ] && res OK "よその名前（Host）での読み取りを拒否（403）" || res NG "Host 確認（$c）"
  c=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -d '{"name":"pii","value":false}' "$KS/api/switch"); [ "$c" = 403 ] && res OK "専用ヘッダの無い操作を拒否（403）" || res NG "CSRF 対策（$c）"
  c=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'X-GK-CSRF: 1' -d '{"name":"pii","value":false}' "$KS/api/switch"); [ "$c" = 401 ] && res OK "パスワード無しの操作を拒否（401）" || res NG "未ログインの操作（$c）"
  ls_addr=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep ":$KPORT\$" || true)
  [ -n "$ls_addr" ] && ! echo "$ls_addr" | grep -qv '^127\.0\.0\.1:' && res OK "本体画面は 127.0.0.1 だけで待ち受け" || res NG "本体画面の待ち受け先（$ls_addr）"
else res SKIP "本体画面のサーバーが入っていないので省略"; fi

hd "インターネット公開の証明書（v1.14.0・公開中のとき）"
PUBDOM=$(python3 -c 'import json;d=json.load(open("/opt/gatekeeper/publish.json")).get("le",{});print(d.get("domain","") if d.get("active") else "")' 2>/dev/null)
if [ -n "$PUBDOM" ] && [ -f "/etc/letsencrypt/live/$PUBDOM/fullchain.pem" ]; then
  if openssl x509 -checkend $((14*86400)) -noout -in "/etc/letsencrypt/live/$PUBDOM/fullchain.pem" >/dev/null; then res OK "証明書の期限まで14日以上（$PUBDOM）"; else res NG "証明書の期限が14日以内（$PUBDOM）"; fi
  systemctl is-active --quiet certbot.timer && res OK "証明書の自動更新（certbot.timer）が有効" || res NG "certbot.timer が止まっている"
  b=$(curl -s -m 10 -o /dev/null -w '%{http_code}' --resolve "$PUBDOM:443:127.0.0.1" "https://$PUBDOM/")
  [ "$b" != 000 ] && res OK "正規の証明書で https://$PUBDOM/ に応答（$b）" || res NG "https://$PUBDOM/ が正規の証明書で応答しない"
  if grep -q 'le-mydns-hook' "/etc/letsencrypt/renewal/$PUBDOM.conf" 2>/dev/null; then
    [ -x /opt/gatekeeper/le-mydns-hook.sh ] && res OK "MyDNS の確認用スクリプトがある" || res NG "/opt/gatekeeper/le-mydns-hook.sh が無い（更新に失敗する）"
    [ "$(stat -c %a /etc/letsencrypt/mydns.netrc 2>/dev/null)" = 600 ] && res OK "MyDNS のログイン情報は root だけが読める（600）" || res NG "MyDNS のログイン情報が無いか、権限が 600 でない"
  fi
else res SKIP "ドメインで公開していないので省略"; fi

hd "サーバー役PC の試験ページ（あれば）"
if [ "$(code https://127.0.0.1/dlp_test.php)" = 200 ]; then
  b=$(curl -sk -m 10 https://127.0.0.1/dlp_test.php)
  echo "$b" | grep -q 'sk_live_\*\*\*\*' && echo "$b" | grep -q 'AWS_KEY_REDACTED' && res OK "DLP: 応答の秘密情報を伏せ字に" || res NG "DLP が効いていない"
  echo "$b" | grep -q 'version 8\|date 2026\|port 8080' && res OK "DLP: 普通の数字は残す" || res SKIP "DLP: 誤検知の確認（試験ページの形が違う）"
else res SKIP "dlp_test.php が無いので DLP の実応答試験は省略（tests/dlp_test.php をサーバー役PC に置くと試せる）"; fi
if [ "$(code 'https://127.0.0.1/pii-test.php?api=send&n=1')" = 200 ]; then
  c=$(code 'https://127.0.0.1/pii-test.php?api=send&n=20'); [ "$c" = 403 ] && res OK "個人情報ガード: 20件を止める（403）" || res NG "個人情報ガード（$c）"
else res SKIP "個人情報の試験ページが無いので省略"; fi

echo
echo "== 結果: OK $ok / NG $ng / 省略 $sk"
[ $ng = 0 ] && echo "✅ すべての守りが期待どおりに働いています" || echo "✗ NG の項目を docs の「困ったとき」で確認してください"
exit $ng
