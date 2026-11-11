#!/bin/bash
# =====================================================================
#  micro-monban 取り外し
#    sudo bash install/uninstall.sh            門番の機能を止めて外す（設定・証明書・記録は残す）
#    sudo bash install/uninstall.sh --purge    設定・証明書・記録も消し、ファイアウォールを初期状態に戻す
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
set -u
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "sudo で実行してください" >&2; exit 1; }

echo "micro-monban を取り外します。"
if [ $PURGE = 1 ]; then
  echo "  --purge: 管理パスワード・証明書・設定・記録も消し、ファイアウォール（nftables）を初期状態（すべて許可）に戻します。"
  echo "  ※ 証明書の ca.key を退避していない場合、門番の証明書は作り直しになります。"
fi
read -r -p "続けるには yes と入力してください: " ans
[ "$ans" = "yes" ] || { echo "中止しました"; exit 1; }

# 1) サービス
for s in gatekeeper-kiosk gatekeeper-dashboard gatekeeper-piiguard; do
  systemctl disable --now $s 2>/dev/null && echo "・$s を停止しました"
  rm -f /etc/systemd/system/$s.service
done
if command -v cloudflared >/dev/null && systemctl is-active --quiet cloudflared; then
  cloudflared service uninstall && echo "・Cloudflare Tunnel の接続を外しました"
fi
H=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
rm -f "$H/.config/autostart/micro-monban-kiosk.desktop" && echo "・本体画面の自動表示を外しました"
systemctl daemon-reload

# 2) nginx
rm -f /etc/nginx/sites-enabled/gatekeeper /etc/nginx/sites-enabled/gatekeeper-public
rm -f /etc/nginx/conf.d/gatekeeper_realip.conf
rm -f /etc/nginx/snippets/gatekeeper_https_body.conf /etc/nginx/snippets/gatekeeper_deny.conf /etc/nginx/snippets/gatekeeper_dlp.conf
if [ -f /etc/nginx/sites-available/default ] && [ ! -e /etc/nginx/sites-enabled/default ]; then
  ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
fi
if [ $PURGE = 1 ]; then
  rm -f /etc/nginx/sites-available/gatekeeper /etc/nginx/sites-available/gatekeeper-public /etc/nginx/conf.d/log_format.conf
fi
nginx -t >/dev/null 2>&1 && systemctl reload nginx && echo "・nginx から門番の設定を外しました（標準のページに戻ります）"

# 3) 証拠ログの転送
rm -f /etc/rsyslog.d/90-gatekeeper-remote.conf && systemctl restart rsyslog 2>/dev/null

if [ $PURGE = 1 ]; then
  # 4) ファイアウォールを初期状態（すべて許可）に
  printf '#!/usr/sbin/nft -f\nflush ruleset\n\ntable inet filter {\n  chain input { type filter hook input priority filter; }\n  chain forward { type filter hook forward priority filter; }\n  chain output { type filter hook output priority filter; }\n}\n' > /etc/nftables.conf
  systemctl restart nftables && echo "・nftables を初期状態に戻しました"
  # 5) 設定・証明書・記録
  rm -rf /opt/gatekeeper /var/lib/gatekeeper /var/www/acme
  rm -f /etc/letsencrypt/mydns.netrc   # [v1.14.0] MyDNS のログイン情報
  [ -d /etc/letsencrypt/live ] && echo "・Let's Encrypt の証明書は /etc/letsencrypt に残っています（消すとき: sudo certbot delete）"
  rm -f /etc/sysctl.d/99-no-forward.conf /etc/sysctl.d/98-disable-ipv6.conf /etc/ssh/sshd_config.d/99-gatekeeper-inet.conf
  nmcli connection delete internal-lan >/dev/null 2>&1
  echo "・設定・証明書・記録を消しました（IPv6・IP転送の設定は再起動後に元へ戻ります）"
else
  echo ""
  echo "ファイアウォール（/etc/nftables.conf）と /opt/gatekeeper は残しています。"
  echo "すべて消すときは: sudo bash $0 --purge"
fi
echo "取り外しが終わりました。"
