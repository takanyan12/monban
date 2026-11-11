#!/bin/bash
# =====================================================================
#  Gatekeeper 読み取り専用モード導入スクリプト v1.4
#  （イミュータブル化: 「自己を初期化して本来の自己で再起動」を可能にする）
# =====================================================================
#  仕組み: Raspberry Pi OS 公式の Overlay File System（raspi-config に搭載）で
#  ルートファイルシステムを読み取り専用にします。以後の書き込みはすべて
#  メモリ(tmpfs)に乗るため、電源を落とせば消えます。
#   ・rootを奪われても永続化（裏口の設置）が不可能になる
#   ・整合性監視が「改竄の疑い」を検知したら自動再起動で自己初期化できる
#   ・SDカードの書き換え寿命が大幅に延びる
#
#  制限（よく読んでください）:
#   ・シャットダウン前の書き込み（ダッシュボードでのルール変更や
#     ホワイトリスト追加など）は再起動で消えます
#     → 恒久変更したいときは、このスクリプトの --unlock → 変更 → --lock の順に
#   ・OS更新（apt upgrade）も --unlock → 更新 → --lock の手順になります
#   ・NGINX/ダッシュボードのログはメモリ上にあり、rsyslog で隔離PCへ
#     常時転送されます（v1.4本体で設定済み。証拠保全はそちらが担う）
#
#  使い方:
#     sudo bash enable-readonly.sh            導入（最後に raspi-config を案内）
#     sudo bash enable-readonly.sh --check    有効/無効の確認
#     sudo bash enable-readonly.sh --unlock   恒久変更のために一時解除（再起動適用）
# =====================================================================
set -e

CONF="/etc/ssh/sshd_config"

# --- raspi-config の OverlayFS 切り替え（対話）の案内 ---
how_to_enable() {
  echo ""
  echo "====================================================================="
  echo " 準備が整いました。最後の切り替えは公式ツール raspi-config で行います:"
  echo ""
  echo "   sudo raspi-config"
  echo "     → Performance Options"
  echo "     → Overlay File System"
  echo "     → <Enable> を選択（bootパーティションも読み取り専用にするかは"
  echo "       Yes 推奨・指示に従ってください）"
  echo "     → Finish → 再起動"
  echo ""
  echo " 再起動後に次のコマンドで有効化を確認してください:"
  echo "   sudo bash $0 --check"
  echo "====================================================================="
}

case "${1:-install}" in
  --check)
    if findmnt -n -o FSTYPE / 2>/dev/null | grep -q overlay; then
      echo "✓ 読み取り専用モード（OverlayFS）: 有効"
      echo "  ・root領域の書き込みはメモリ上のみ。再起動で初期化されます。"
      echo "  ・恒久変更のときは --unlock → 変更 → raspi-config で再び有効化。"
    else
      echo "－ 読み取り専用モード: 無効（通常モードで動作中）"
    fi
    exit 0 ;;
  --unlock)
    echo "=== 読み取り専用モードの一時解除（恒久変更のため） ==="
    echo "raspi-config → Performance Options → Overlay File System → Disable"
    echo "のあと再起動してください。変更後、再び Enable に戻すのをお忘れなく。"
    sudo raspi-config || true
    exit 0 ;;
  install|"")
    :
    ;;
  *)
    echo "使い方: sudo bash enable-readonly.sh [--check|--unlock]" >&2
    exit 1 ;;
esac

echo "=== Gatekeeper 読み取り専用モード 導入前チェック ==="
[ "$(id -u)" -eq 0 ] || { echo "エラー: sudo bash $0 で実行してください" >&2; exit 1; }
command -v raspi-config >/dev/null 2>&1 || { echo "エラー: raspi-config が見つかりません（Raspberry Pi OS でのみ動作します）" >&2; exit 1; }
findmnt -n -o FSTYPE / 2>/dev/null | grep -q overlay && { echo "すでに有効です（--check で確認できます）"; exit 0; }

echo "[1/4] 整合性監視の稼働確認"
systemctl is-active --quiet gatekeeper-dashboard && echo "  ✓ ダッシュボード稼働中（監視は自動）" || { echo "  ✗ ダッシュボードが止まっています。先に setup-gatekeeper.sh を実行してください" >&2; exit 1; }

echo "[2/4] 証拠ログの外部退避（rsyslog転送）確認"
if [ -f /etc/rsyslog.d/90-gatekeeper-remote.conf ]; then
  echo "  ✓ 転送設定あり: $(head -n 3 /etc/rsyslog.d/90-gatekeeper-remote.conf | tail -n 1)"
else
  echo "  △ 転送設定がありません。読み取り専用化の前に証拠保全を強くお勧めします。"
  echo "    （sudo bash setup-gatekeeper.sh を再実行すると作成されます）"
fi

echo "[3/4] 恒久設定の凍結（現在の状態を「本来の自己」として保存）"
echo "  ・現在のDLPルール・ホワイトリスト・パスワードが、読み取り専用化後の"
echo "    起動時に毎回読み込まれます。この時点の内容が正しいか確認してください:"
ls -l /opt/gatekeeper/ 2>/dev/null | sed 's/^/      /'
sudo nft list set inet filter whitelist 2>/dev/null | grep -A5 "elements" | sed 's/^/      /' || echo "      （ホワイトリストは空です）"

echo "[4/4] 確認"
echo "====================================================================="
echo " 読み取り専用モードにすると、以後の書き込みはすべてメモリ上になり、"
echo " 再起動で消えます（恒久変更は --unlock → 変更 → 再度有効化）。",
echo " 導入してよろしいですか？"
echo "====================================================================="
read -r -p "続行しますか？ (yes/No): " ANS
[ "$ANS" = "yes" ] || { echo "中止しました。"; exit 0; }

how_to_enable
