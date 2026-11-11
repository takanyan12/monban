#!/bin/bash
# =====================================================================
#  Gatekeeper A/B ゴールデンイメージ復旧 v1.7（理論上・未実機検証版）
# =====================================================================
#  大容量SDカード（64GB以上推奨・A2クラス推奨）を使い、
#   ・SD-B（黄金の自己=ゴールデンイメージ保存用）
#  を用意して、たとえOS領域が書き換えられても「黄金の自己」で
#  完全に書き戻せるようにする補助スクリプトです。
#
#  【v1.8修正】sfdisk直後のデバイスノード生成待ち(partprobe/udevadm settle)を追加。
#   書き戻し先がレスキューOS等で自動マウント済みの場合は実行を拒否します（破損防止）。
#  【v1.7修正・重要な設計変更】
#   起動中の自分自身のルートパーティションへ dd で上書きすることは
#   Linuxのアーキテクチャ上できません（実行途中でカーネルが触っている
#   ブロックと不整合になり、パニックや破損で二度と起動しなくなります）。
#   そこで recover は「レスキュー起動してから書き戻す」設計に変更しました:
#
#     1) 別のSD（レスキュー用 Raspberry Pi OS）または USB で起動する
#     2) そのレスキュー環境で本スクリプト recover を実行する
#     3) 黄金の自己を「動いていない対象パーティション」へ書き戻す
#     4) 再起動してSD-Aから立ち上げる
#
#   スクリプトは「対象が起動中のルートなら実行を拒否する」ガードを持ちます。
#   また create も、稼働中の読み取りは走り書きを含むため、理想は
#   レスキュー起動で行うこと（少なくとも直起動直後の静かな状態）を案内します。
#
#  ※※ 重要 ※※
#  このスクリプトは理論上の手順で、実機検証はまだです。必ずテスト機と
#  使わなくなったSDカードで練習してください。dd は指定を間違えると
#  ディスクを完全に消します。デバイス名の確認を必ず2回行ってください。
#
#  使い方（ラズパイに USBカードリーダー経由で SD-B を挿して作業）:
#     sudo bash setup-ab-recovery.sh create <ゴールデンSDデバイス>   例: create /dev/sdb
#     sudo bash setup-ab-recovery.sh status <ゴールデンSDデバイス>
#     （レスキュー起動後）
#     sudo bash setup-ab-recovery.sh recover <ゴールデンSD> <書き戻し先パーティション>
#         例: recover /dev/sdb /dev/mmcblk0p2
# =====================================================================
set -e

GOLDEN_IMG="/mnt/golden/gatekeeper-golden.img"
GOLDEN_MANIFEST="/mnt/golden/gatekeeper-golden.sha256"
MOUNT_POINT="/mnt/golden"

die(){ echo "エラー: $1" >&2; exit 1; }
banner(){ echo "====================================================================="; echo "※ このスクリプトは『理論上・未実機検証版』です。テスト機で練習してください。"; echo "====================================================================="; }

pick_part(){
  # [v1.7修正] デバイス命名規則の差異に対応（/dev/sda1 vs /dev/mmcblk1p1 vs /dev/nvme0n1p1）
  PART_DEV="${DEV}1"
  [ -b "$PART_DEV" ] || PART_DEV="${DEV}p1"
  [ -b "$PART_DEV" ] || die "パーティション ${DEV}1 / ${DEV}p1 が見つかりません"
  echo "  パーティション: $PART_DEV"
}

do_create(){
  banner
  [ -n "${2:-}" ] || die "使い方: sudo bash $0 create <ゴールデンSDデバイス>  例: create /dev/sdb"
  DEV="$2"
  [ -b "$DEV" ] || die "$DEV はブロックデバイスではありません"
  ROOT_DEV="$(findmnt -n -o SOURCE /)" || die "ルートデバイスを特定できません"
  case "$ROOT_DEV" in
    ${DEV}*|${DEV}p*) die "ゴールデン先に自分自身（起動中のディスク）は指定できません" ;;
  esac
  echo "  対象: $DEV（現在のルート: $ROOT_DEV）"
  echo "  ※ このデバイスの全データが消えます。よろしければ yes と入力してください。"
  read -r -p "  確認: " ANS
  [ "$ANS" = "yes" ] || die "中止しました"

  echo "[1/5] パーティション作成（全領域を1パーティションで使用）"
  sfdisk "$DEV" << EOF
label: dos
start=2048, type=83
EOF
  # [v1.8修正] sfdisk直後はカーネル/udevがデバイスノードを生成するまで遅延がある
  partprobe "$DEV" 2>/dev/null || true
  udevadm settle 2>/dev/null || true
  sleep 1
  pick_part
  mkfs.ext4 -F -L GOLDEN "$PART_DEV" || die "フォーマットに失敗しました"
  mkdir -p "$MOUNT_POINT"
  mount "$PART_DEV" "$MOUNT_POINT" || die "マウントに失敗しました"

  echo "[2/5] ルート領域の特定"
  ROOT_PART="$(findmnt -n -o SOURCE /)" || die "ルートパーティションを特定できません"
  ROOT_SIZE="$(blockdev --getsize64 "$ROOT_PART")"
  echo "  ルート: $ROOT_PART ($(numfmt --to=iec "$ROOT_SIZE"))"
  FREE_ON_GOLDEN="$(df -B1 "${MOUNT_POINT}" | tail -1 | awk '{print $4}')"
  [ "$FREE_ON_GOLDEN" -gt "$ROOT_SIZE" ] || die "ゴールデン側の空きが足りません（必要: $(numfmt --to=iec "$ROOT_SIZE")）"

  echo "[3/5] ルート領域をゴールデン側へ保存（数分〜十数分）"
  echo "  ※ v1.7注記: 稼働中の読み取りには走り書き（実行中状態）が混じる可能性があります。"
  echo "    最もきれいな黄金の自己は、レスキュー起動から create 相当を行ったものです。"
  echo "    ここでは、起動直後の静かな状態で実行することを推奨します。"
  sync
  dd if="$ROOT_PART" of="$GOLDEN_IMG" bs=4M status=progress conv=sparse || die "イメージ保存に失敗しました"
  sync

  echo "[4/5] 整合性台帳の作成（イメージの指紋）"
  sha256sum "$GOLDEN_IMG" > "$GOLDEN_MANIFEST" || die "ハッシュ計算に失敗しました"
  cat "$GOLDEN_MANIFEST" | sed 's/^/  /'

  echo "[5/5] 完成。安全に取り外します"
  umount "$MOUNT_POINT"
  echo ""
  echo "✓ 黄金の自己を $DEV に保存しました。"
  echo "  このSD-Bを保管してください（書き換えない＝審判が書き換えられない）"
  echo "  復旧は: まずレスキュー起動 → sudo bash $0 recover $DEV <書き戻し先パーティション>"
}

do_status(){
  banner
  [ -n "${2:-}" ] || die "使い方: sudo bash $0 status <ゴールデンSDデバイス>"
  DEV="$2"
  [ -b "$DEV" ] || die "$DEV はブロックデバイスではありません"
  pick_part
  mkdir -p "$MOUNT_POINT"
  mount -o ro "$PART_DEV" "$MOUNT_POINT" 2>/dev/null || die "ゴールデン領域を読み取り専用でマウントできません"
  if [ -f "$GOLDEN_MANIFEST" ]; then
    echo "台帳: $(cat "$GOLDEN_MANIFEST")"
    echo "検証中（数分）..."
    if sha256sum -c "$GOLDEN_MANIFEST"; then
      echo "✓ 黄金の自己は改変されていません"
    else
      echo "✗ 台帳不一致！イメージが書き換えられています"
    fi
  else
    echo "$MOUNT_POINT に台帳が見つかりません。SD-Bを接続してから実行してください。"
  fi
  umount "$MOUNT_POINT" 2>/dev/null || true
}

do_recover(){
  banner
  [ -n "${2:-}" ] || die "使い方: sudo bash $0 recover <ゴールデンSDデバイス> <書き戻し先パーティション>"
  [ -n "${3:-}" ] || die "書き戻し先パーティションを指定してください（例: /dev/mmcblk0p2）"
  DEV="$2"; TARGET_PART="$3"
  [ -b "$DEV" ] || die "$DEV はブロックデバイスではありません"
  [ -b "$TARGET_PART" ] || die "$TARGET_PART はブロックデバイスではありません"

  # [v1.7修正・最重要ガード] 起動中のルートへの書き戻しを禁止する
  LIVE_ROOT="$(findmnt -n -o SOURCE /)"
  [ "$TARGET_PART" != "$LIVE_ROOT" ] || die "対象 $TARGET_PART は起動中のルートです。dd による上書きはできません。
  手順: (1) レスキュー用SD/USBで起動する (2) その環境で本コマンドを実行する (3) 再起動"
  # [v1.8修正] 書き戻し先が（レスキューOSの自動マウント等で）マウント済みなら拒否
  if findmnt -n "$TARGET_PART" >/dev/null 2>&1; then
    die "対象 $TARGET_PART は $(findmnt -n -o TARGET "$TARGET_PART") にマウントされています。先に umount してから実行してください。"
  fi
  case "$TARGET_PART" in
    ${DEV}*|${DEV}p*) die "ゴールデンSD自身($TARGET_PART)を書き戻し先にはできません" ;;
  esac

  pick_part
  mkdir -p "$MOUNT_POINT"
  mount -o ro "$PART_DEV" "$MOUNT_POINT" 2>/dev/null || die "ゴールデン領域をマウントできません"
  [ -f "$GOLDEN_MANIFEST" ] || die "台帳がありません"
  sha256sum -c "$GOLDEN_MANIFEST" || die "黄金の自己が改変されています。復旧を中止します（台帳が読み取り専用メディア上にあるのが急所です）"

  GOLDEN_SIZE="$(stat -c %s "$GOLDEN_IMG")"
  TARGET_SIZE="$(blockdev --getsize64 "$TARGET_PART")"
  [ "$GOLDEN_SIZE" -le "$TARGET_SIZE" ] || die "書き戻し先($TARGET_PART)がゴールデンイメージより小さすぎます"

  echo "=============================================================="
  echo " これから $TARGET_PART（現在は未マウントであることを確認済み）へ"
  echo " 黄金の自己を書き戻します。対象を間えるとそのディスクが消えます。"
  echo " 書き戻し後は対象から起動します（レスキュー環境では reboot で抜ける）。"
  read -r -p " 実行しますか？ yes/No: " ANS
  [ "$ANS" = "yes" ] || die "中止しました"
  echo "書き戻し中（数分〜十数分）..."
  dd if="$GOLDEN_IMG" of="$TARGET_PART" bs=4M status=progress conv=notrunc || die "書き戻しに失敗しました"
  sync
  umount "$MOUNT_POINT" 2>/dev/null || true
  echo "✓ 書き戻し完了。レスキュー媒体を外して再起動してください。"
}

case "${1:-}" in
  create)  do_create "$@" ;;
  status)  do_status "$@" ;;
  recover) do_recover "$@" ;;
  *) echo "使い方: sudo bash $0 create <デバイス> | status <デバイス> | recover <デバイス> <対象パーティション>" >&2; exit 1 ;;
esac
