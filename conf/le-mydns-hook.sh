#!/bin/bash
# micro-monban: certbot の DNS-01 で、MyDNS に _acme-challenge の TXT を登録（auth）・削除（cleanup）する
#  ・管理画面のウィザード「MyDNS の DNS」と tools/le-mydns.sh が使う。証明書の自動更新（certbot.timer）でも呼ばれる
#  ・MyDNS のログイン情報は /etc/letsencrypt/mydns.netrc（root だけ読める）から読む（コマンド行には出さない）
NETRC=/etc/letsencrypt/mydns.netrc
case "${1:-}" in auth) CMD=REGIST;; cleanup) CMD=DELETE;; *) echo "auth か cleanup を指定" >&2; exit 2;; esac
[ -r "$NETRC" ] || { echo "MyDNS: ログイン情報（$NETRC）がありません" >&2; exit 1; }
code=$(curl -s -m 30 -o /dev/null -w '%{http_code}' --netrc-file "$NETRC" \
  --data-urlencode "CERTBOT_DOMAIN=${CERTBOT_DOMAIN}" \
  --data-urlencode "CERTBOT_VALIDATION=${CERTBOT_VALIDATION}" \
  --data-urlencode "EDIT_CMD=${CMD}" https://www.mydns.jp/directedit.html)
case "$code" in
  2??) ;;
  401|403) echo "MyDNS: ログインできません（マスターID・パスワードを確認してください）" >&2; exit 1;;
  *) echo "MyDNS: 登録できませんでした（HTTP $code）" >&2; exit 1;;
esac
[ "$CMD" = REGIST ] && sleep 90   # MyDNS の DNS に反映されるまで待つ
exit 0
