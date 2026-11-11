#!/bin/bash
# =====================================================================
#  Gatekeeper Linux Backend Initializer v0.96（理論上・未実機検証版）
#  【v1.8修正】ufw に proto icmp を指定しない（Invalid protocol で set -e 異常終了するため）。
#   ping の許可は ufw 既定ルール (/etc/ufw/before.rules) が処理します。
# =====================================================================
#  閉域側バックエンドとして Windows ではなく Linux（Debian / Ubuntu 系）を
#  置く場合の設定スクリプトです。ゲートキーパー（Raspberry Pi 5, 10.0.0.1）
#  と有線直結するマシン上で、sudo 権限で実行してください。
#
#  ※※ 重要 ※※
#  このスクリプトは Windows版の手順を Linux に置き換えた「理論上の手順」に
#  基づいており、実機での検証はまだです。まずテスト機で動作確認してから
#  本番採用してください。ディストリビューションによっては NetworkManager
#  が無い場合があります（その場合は手動設定手順をマニュアルで確認してください）。
#
#  使い方:
#     sudo bash setup-backend-linux.sh                  # 基本設定のみ
#     sudo bash setup-backend-linux.sh --test-page      # テストWebページも起動
#     sudo bash setup-backend-linux.sh --syslog-server  # 証拠ログの受け皿（rsyslog受信）にもなる
# =====================================================================
set -e

# ===== 設定（基本はそのまま） =====
BACK_IF=""            # ゲートキーパーと繋ぐNIC名。空欄なら対話的に決めさせる
BACK_IP="10.0.0.2/24" # 閉域側IP（ゲートキーパーのeth0が10.0.0.1なので /24 で隣接）
GATEKEEPER="10.0.0.1" # 相手側（ラズパイ）のIP
WEB_PORT="8080"       # バックエンドWebサービスのポート
# ==================================

echo "=== Gatekeeper Linux Backend 初期設定（理論上・未検証版） ==="

# --- 1. NICの決定 ---
if [ -z "$BACK_IF" ]; then
  echo "現在のネットワークインターフェース一覧:"
  ls /sys/class/net | grep -v '^lo$' | sed 's/^/  - /'
  printf "ゲートキーパーと繋ぐNIC名を入力してください（例: enp3s0 / eth1）: "
  read -r BACK_IF
fi
if [ ! -d "/sys/class/net/$BACK_IF" ]; then
  echo "エラー: インターフェース $BACK_IF が見つかりません" >&2
  exit 1
fi
echo "・対象NIC: $BACK_IF に $BACK_IP を設定します"

# --- 2. 静的IP設定（NetworkManager 環境: Raspberry Pi OS / Ubuntu デスクトップ等） ---
if command -v nmcli >/dev/null 2>&1 && nmcli general status >/dev/null 2>&1; then
  nmcli connection delete backend-isolated 2>/dev/null || true
  # gateway を指定しない → デフォルトゲートウェイ無し = 物理的閉域の重要ポイント
  nmcli connection add type ethernet con-name backend-isolated ifname "$BACK_IF" ip4 "$BACK_IP"
  nmcli connection up backend-isolated
# --- netplan 環境（Ubuntu Server 等: NetworkManagerが管理していない場合） ---
else
  echo "・NetworkManagerが見つかりません。netplan で設定します。"
  NETPLAN_FILE="/etc/netplan/60-backend-isolated.yaml"
  if [ -e "$NETPLAN_FILE" ]; then
    echo "  ※ $NETPLAN_FILE は既存のため上書きしません。手動確認してください。" >&2
  else
    cat > "$NETPLAN_FILE" << EOF
network:
  version: 2
  ethernets:
    $BACK_IF:
      dhcp4: false
      addresses: [$BACK_IP]
      # routes を書かない → デフォルトゲートウェイ無し = 閉域化
EOF
    chmod 600 "$NETPLAN_FILE"
    netplan apply
  fi
fi

# --- 3. ファイアウォール: 閉域側からの Web/ICMP のみ許可 ---
echo "=== ファイアウォール設定 ==="
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow in on "$BACK_IF" to any port "$WEB_PORT" proto tcp comment 'Gatekeeper backend web' || echo "  ⚠ 上記ufwルールの追加に失敗しました"
  # [v1.8修正] ufw は proto icmp を受け付けない（Invalid protocol）。指定行を削除。
  echo "・ufw に許可を追加しました（ICMP/ping は ufw 既定ルール /etc/ufw/before.rules に委ねます）"
elif command -v nft >/dev/null 2>&1; then
  nft add table inet gatekeeper_backend 2>/dev/null || true
  nft add chain inet gatekeeper_backend input '{ type filter hook input priority -10; }' 2>/dev/null || true
  nft add rule inet gatekeeper_backend input iifname "$BACK_IF" tcp dport "$WEB_PORT" accept
  nft add rule inet gatekeeper_backend input iifname "$BACK_IF" icmp type echo-request accept
  echo "・nftables に許可を追加しました（ufw等が無効な環境向けの補助ルール）"
else
  echo "・ufw / nft が見つかりません。手動でポート $WEB_PORT とICMPを許可してください。"
fi

# --- 4. 疎通テスト ---
echo "=== 疎通テスト ==="
if ping -c 2 -W 2 "$GATEKEEPER" >/dev/null 2>&1; then
  echo "✓ ゲートキーパー $GATEKEEPER と通信できます"
else
  echo "× $GATEKEEPER と通信できません。ケーブル・ラズパイ側の internal-lan を確認してください。" >&2
fi

# --- 4.5 証拠ログの受け皿（オプション: --syslog-server） ---
# ゲートキーパー(rsyslog → UDP 514)から届くログを受信して保存する
if [ "${1:-}" = "--syslog-server" ]; then
  echo "=== rsyslog 受信設定（証拠ログの受け皿） ==="
  if command -v rsyslogd >/dev/null 2>&1; then
    cat > /etc/rsyslog.d/90-gatekeeper-receive.conf << EOF
# Gatekeeper v1.4: ゲートキーパーから証拠ログを受信
module(load="imudp")
input(type="imudp" port="514")
if \$fromhost-ip startswith '$(echo "$GATEKEEPER" | sed 's/\./\\./g')' then /var/log/gatekeeper.log
& stop
EOF
    systemctl restart rsyslog
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
      ufw allow in on "$BACK_IF" from "$GATEKEEPER" to any port 514 proto udp comment 'Gatekeeper evidence syslog' || echo "  ⚠ ufwルール追加に失敗しました（手動で UDP 514 を許可してください）"
    fi
    echo "✓ UDP 514 で受信し、/var/log/gatekeeper.log に保存します。"
  else
    echo "× rsyslog が見つかりません。手動設定が必要です。" >&2
  fi
fi

# --- 5. テストページ（オプション） ---
if [ "${1:-}" = "--test-page" ]; then
  echo "=== テスト用Webサーバーの起動 ==="
  mkdir -p /opt/gatekeeper-backend-test
  printf '{"backend":"linux-test","message":"Gatekeeper backend is alive","phone":"090-0000-0000"}' > /opt/gatekeeper-backend-test/index.html
  cat > /etc/systemd/system/gatekeeper-backend-test.service << EOF
[Unit]
Description=Gatekeeper Backend Test Page
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server $WEB_PORT --directory /opt/gatekeeper-backend-test --bind 0.0.0.0
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now gatekeeper-backend-test
  echo "・テストページを 0.0.0.0:$WEB_PORT で起動しました（外部からラズパイ経由でDLPの動作確認ができます）"
fi

echo "=== 完了（理論上・未検証版） ==="
echo "・次は実Webサービス（PHP / Node / nginx等）を 0.0.0.0:$WEB_PORT で起動してください。"
echo "・動作確認が済んだら、結果を教えていただければ本番版へ昇格させます。"
