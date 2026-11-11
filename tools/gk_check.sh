#!/bin/bash
# micro-monban 健康診断（読み取り専用・何も変更しない）
# Copyright 2026 AiLab-Japan / Apache License 2.0
#   使い方（Pi上で）: sudo bash tools/gk_check.sh
GK=/opt/gatekeeper
ok(){ echo "  [OK]   $*"; }
ng(){ echo "  [NG]   $*"; }
hd(){ echo; echo "== $*"; }

hd "サービス"
for s in nginx nftables gatekeeper-dashboard gatekeeper-piiguard ssh; do
  systemctl is-active --quiet $s && ok "$s active" || ng "$s が停止"
done
for s in rpcbind.service rpcbind.socket; do
  systemctl is-active --quiet $s && echo "  [注意] $s が動作中（不要なら停止推奨）"
done
nginx -t >/dev/null 2>&1 && ok "nginx -t 合格" || ng "nginx -t 不合格"
nft -c -f /etc/nftables.conf >/dev/null 2>&1 && ok "nftables.conf 検証合格" || ng "nftables.conf 検証不合格"

hd "nftables 実行中ルール"
nft list chain inet filter input >/dev/null 2>&1 && ok "inet filter input あり" || ng "inet filter が無い"
nft list chain inet filter input | grep -q "policy drop" && ok "input policy drop" || ng "input が policy drop でない"
nft list chain inet filter forward | grep -q "policy drop" && ok "forward policy drop（転送なし）" || ng "forward が drop でない"
nft list chain inet filter wifi_mgmt | grep -q accept && echo "  [情報] 管理スイッチ ON" || echo "  [情報] 管理スイッチ OFF"
echo "  [情報] 保存状態: $(cat $GK/wifi_mgmt.json 2>/dev/null || echo 無し)"
nft list tables | grep -q gatekeeper_breaker && ng "緊急ブレーカー作動中" || ok "緊急ブレーカー非作動"
echo "  [情報] whitelist: $(nft list set inet filter whitelist | grep -o 'elements = {[^}]*}' || echo '(空)')"
echo "  [情報] 自動遮断中: $(nft list set inet filter dynamic_blocks | grep -o 'elements = {[^}]*}' || echo '(なし)')"

hd "管理画面の内部状態（/api/status）"
ST=$(mktemp)
T0=$(date +%s)
CODE=$(curl -sk -m 30 -o "$ST" -w '%{http_code}' https://127.0.0.1:9000/api/status); RC=$?
echo "  [情報] /api/status: HTTP $CODE（curl終了コード $RC、$(( $(date +%s) - T0 ))秒）"
if [ "$CODE" != 200 ]; then
  ng "管理画面の状態を取得できません"
  ss -tlnp | grep ':9000' | sed 's/^/           /'
else
python3 - "$ST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
i = d.get('integrity', {})
print(f"  [{'OK' if i.get('state')=='ok' else '注意'}]   整合性: {i.get('state')}（{i.get('checked_at')} 確認, RO={i.get('ro_mode')}）")
for f in i.get('findings', []):
    print(f"           - {f['level']}: {f['msg']}")
print(f"  [情報] 温度 {d.get('temp')}℃ / {d.get('uptime')} / 外側IP {d.get('ext_ip')}")
a = d.get('active_alert')
print(f"  [{'注意' if a else 'OK'}]   出口防御アラート: {a['reason'] if a else 'なし'}")
for h in d.get('alert_history', [])[:5]:
    print(f"           履歴 {h['time']} {h['key']} {h['ip']} {h['path']}")
g = d.get('guard', {})
print(f"  [情報] 出口防御: auto_block={g.get('auto_block')}  メール通知={d.get('mail',{}).get('enabled')}")
on = [r['name'] for r in d.get('dlp_rules', []) if r.get('enabled')]
print(f"  [情報] DLP 有効ルール {len(on)} 個")
print("  [情報] 脅威スコア（IP別・上位）:")
ts = sorted(d.get('threat_stats', {}).items(), key=lambda kv: -kv[1].get('score', 0))
for ip, s in ts[:8]:
    print(f"           {ip:16} score={s.get('score'):>3}  {s.get('stage')}  req={s.get('req_count')} err={s.get('error_ratio')}% last={s.get('last_seen')} ssh_fail={s.get('ssh_fail',0)} {s.get('slow','')}")
PY
fi
rm -f "$ST"

hd "ファイル"
echo "  [情報] dashboard.py sha256: $(sha256sum $GK/dashboard.py | cut -c1-16)…（README の値と比べると改変の有無が分かります）"
cmp -s <(python3 -c "import json;r=json.load(open('$GK/dlp_rules.json'));print('\n'.join(x['pattern'] for x in r if x.get('enabled')))" ) \
       <(grep '^subs_filter' /etc/nginx/snippets/gatekeeper_dlp.conf | sed -E "s/^subs_filter '(.*)' '.*' irg;$/\1/") \
  && ok "DLP スニペットはルールJSONと一致" || echo "  [注意] DLP スニペットとルールJSONの差異（' を含むパターンは除去されるため差が出る場合あり）"
end=$(openssl x509 -in $GK/tls/server.crt -noout -enddate | cut -d= -f2)
echo "  [情報] サーバー証明書の期限: $end"
[ -f $GK/tls/ca.key ] && ng "ca.key が装置内にある（PCへ退避すべき）" || ok "ca.key は装置内に無い"

hd "閉域側のサーバー役PC"
BE_IP=$(python3 -c "import json; print(json.load(open('$GK/config.json')).get('backend_ip','10.0.0.2'))" 2>/dev/null || echo 10.0.0.2)
BE_PORT=$(python3 -c "import json; print(json.load(open('$GK/config.json')).get('backend_port',8080))" 2>/dev/null || echo 8080)
ping -c 1 -W 2 $BE_IP >/dev/null && ok "$BE_IP ping 応答" || ng "$BE_IP ping 無応答"
c=$(curl -s -m 4 -o /dev/null -w '%{http_code}' http://$BE_IP:$BE_PORT/); [ "$c" != 000 ] && ok "Web アプリ $BE_IP:$BE_PORT → HTTP $c" || ng "Web アプリ $BE_IP:$BE_PORT 応答なし"
v=$(curl -s -m 4 http://$BE_IP:11434/api/version); [ -n "$v" ] && echo "  [情報] Ollama → $v" || echo "  [情報] Ollama は応答なし（使っていなければ問題なし）"

hd "ログ（直近の異常）"
echo "  dashboard（今日のエラー/警告）:"
journalctl -u gatekeeper-dashboard --since today --no-pager -o cat 2>/dev/null | grep -iE "error|traceback|exception|ALERT|blocked|restored|restarted" | tail -8 | sed 's/^/    /'
echo "  nginx error.log（末尾）:"
tail -n 5 /var/log/nginx/error.log 2>/dev/null | sed 's/^/    /'
echo "  WAF で 403 にした件数（今日のアクセスログ）: $(grep -c '"status":"403"' /var/log/nginx/gatekeeper_access.log 2>/dev/null)"

hd "資源"
df -h / | awk 'NR==2{print "  [情報] ディスク使用 "$5" ("$3"/"$2")"}'
free -m | awk '/Mem/{print "  [情報] メモリ使用 "$3"MB / "$2"MB"}'
echo
echo "== 点検終了（何も変更していません）"
