#!/bin/bash
# =====================================================================
#  micro-monban: 本体の HDMI（タッチ）モニターに「ダッシュボード／設定」画面を出す（実験的）
#    sudo bash tools/setup-kiosk.sh            設定する（Chromium を全画面で自動起動）
#    sudo bash tools/setup-kiosk.sh --remove   やめる（自動起動を外す）
#  前提: Raspberry Pi OS（デスクトップ付き）。Lite 版には対応していない
#  ・画面のサーバー（gatekeeper-kiosk・127.0.0.1:9100）は導入スクリプトが入れる
#  ・ここでは「ログインしたら全画面で開く」設定と、日本語フォント・Chromium の導入を行う
#  ・画面は本体の中（127.0.0.1）からしか開けない。外部からは見えない
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
set -eu
say(){ echo "[setup-kiosk] $*"; }
die(){ echo "[setup-kiosk] 中止: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "sudo で実行してください"

U="${SUDO_USER:-}"
[ -n "$U" ] && [ "$U" != root ] || die "画面に出すユーザーで sudo してください（root ユーザーのままでは不可）"
HOMEDIR=$(getent passwd "$U" | cut -d: -f6)
AUTO="$HOMEDIR/.config/autostart/micro-monban-kiosk.desktop"
LAUNCH=/opt/gatekeeper/kiosk-launch.sh
PORT=$(python3 -c "import json;print(json.load(open('/opt/gatekeeper/config.json')).get('kiosk_port',9100))" 2>/dev/null || echo 9100)

if [ "${1:-}" = "--remove" ]; then
  rm -f "$AUTO" "$LAUNCH"
  say "画面の自動起動を外しました（次にログインしたときから出ません）"
  exit 0
fi

systemctl is-active --quiet gatekeeper-kiosk || die "画面のサーバー（gatekeeper-kiosk）が動いていません。先に導入スクリプトを実行してください"
if ! ls /usr/bin/labwc /usr/bin/wayfire /usr/bin/startlxde-pi >/dev/null 2>&1; then
  die "デスクトップが見つかりません。Raspberry Pi OS（デスクトップ付き）が必要です"
fi

PKGS=""
command -v chromium >/dev/null || command -v chromium-browser >/dev/null || PKGS="$PKGS chromium"
fc-list 2>/dev/null | grep -qi "Noto Sans CJK JP" || PKGS="$PKGS fonts-noto-cjk"
if [ -n "$PKGS" ]; then
  say "導入します:$PKGS（数分かかります）"
  apt-get update -qq && apt-get install -y -qq $PKGS >/dev/null
fi
BROWSER=$(command -v chromium || command -v chromium-browser)

cat > "$LAUNCH" <<EOF
#!/bin/bash
# micro-monban: 本体画面を全画面で開く（tools/setup-kiosk.sh が作成）
for i in \$(seq 1 60); do
  curl -s -o /dev/null -m 2 http://127.0.0.1:$PORT/api/state && break
  sleep 2
done
exec "$BROWSER" --kiosk --app=http://127.0.0.1:$PORT/ \\
  --noerrdialogs --disable-infobars --no-first-run --disable-session-crashed-bubble \\
  --disable-features=Translate,TranslateUI --disable-background-networking --disable-component-update \\
  --disable-sync --disable-default-apps --password-store=basic --check-for-update-interval=31536000 \\
  --overscroll-history-navigation=0 --disable-pinch --incognito \\
  --user-data-dir="\$HOME/.config/micro-monban-kiosk"
EOF
chmod 755 "$LAUNCH"

install -d -o "$U" -g "$U" "$HOMEDIR/.config/autostart"
cat > "$AUTO" <<EOF
[Desktop Entry]
Type=Application
Name=micro-monban screen
Exec=$LAUNCH
X-GNOME-Autostart-enabled=true
EOF
chown "$U": "$AUTO"
say "ログインしたら本体画面が全画面で開くように設定しました（ユーザー: $U）"

if command -v raspi-config >/dev/null; then
  read -r -p "電源を入れたら自動でデスクトップにログインするようにしますか？（モニター用。yes/no）: " a
  if [ "$a" = "yes" ]; then
    raspi-config nonint do_boot_behaviour B4 && say "自動ログイン（デスクトップ）を有効にしました"
  fi
fi
say "完了。再起動すると画面が出ます: sudo reboot"
say "やめるとき: sudo bash tools/setup-kiosk.sh --remove"
