#!/bin/bash
# =====================================================================
#  micro-monban: 起動中の SD カードを、PC に保管できる1つのファイル（.img.gz）にする
#    sudo bash tools/sd-backup.sh /dev/sda
#  流れ: USB でつないだ2枚目のカードへ写す（sd-clone.sh）→ 空き領域をゼロで埋める
#        → 使っている範囲だけを圧縮したイメージにする（ホームフォルダに作る）
#  ・門番は動いたまま。2枚目のカードは、そのまま起動できる予備カードとしても使える
#  ・できたファイルは Raspberry Pi Imager の「カスタムイメージを使う」で新しいカードに書き戻せる
#    （本体の区画は使用量に合わせて小さめ。広げたいときは sudo raspi-config → Advanced → Expand Filesystem）
#  ・ファイルには管理画面のパスワード・鍵・Wi-Fi 設定が入る。人に渡したり共有の場所に置いたりしない
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
set -eu
DST="${1:-}"
OWNER="${SUDO_USER:-root}"
OUT_DIR="${2:-$(getent passwd "$OWNER" | cut -d: -f6)}"
say(){ echo "[sd-backup] $*"; }
die(){ echo "[sd-backup] 中止: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "sudo で実行してください"
[ -n "$DST" ] || die "2枚目のカードを指定してください（例: sudo bash $0 /dev/sda）"
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/sd-clone.sh" ] || die "同じフォルダに sd-clone.sh がありません"

USED_MB=$(( $(df --output=used -k / | tail -1) / 1024 ))
ROOT_MB=$(( USED_MB * 14 / 10 + 1024 ))                 # 使用量の1.4倍＋1GB
FREE_MB=$(( $(df --output=avail -k "$OUT_DIR" | tail -1) / 1024 ))
NEED_MB=$(( USED_MB * 7 / 10 + 512 ))                    # 圧縮後の見込み（多めに）
[ "$FREE_MB" -gt "$NEED_MB" ] || die "保存先 $OUT_DIR の空きが足りません（空き ${FREE_MB}MB・必要 約${NEED_MB}MB）"
say "本体の区画を ${ROOT_MB}MB にして写します（使用 ${USED_MB}MB）"

# 1) 2枚目のカードへ写す（写し先の確認と yes 入力は sd-clone.sh が行う）
GK_ROOT_MB=$ROOT_MB GK_FROM_BACKUP=1 bash "$DIR/sd-clone.sh" "$DST"

# 2) 空き領域をゼロで埋める（前の中身が残っていると圧縮が効かないため）
T=$(mktemp -d)
trap 'umount "$T" 2>/dev/null; rmdir "$T" 2>/dev/null' EXIT
for p in 2 1; do
  say "区画 ${p} の空き領域を整理しています（数分かかります）"
  mount "${DST}${p}" "$T"
  dd if=/dev/zero of="$T/.gk_zero" bs=4M status=none 2>/dev/null || true
  rm -f "$T/.gk_zero"; sync; umount "$T"
done
rmdir "$T"; trap - EXIT

# 3) 使っている範囲だけを圧縮してファイルにする
D=$(basename "$DST")
END=$(( $(cat /sys/block/$D/${D}2/start) + $(cat /sys/block/$D/${D}2/size) ))
OUT="$OUT_DIR/monban-sd-$(date +%Y%m%d-%H%M).img.gz"
say "イメージを作っています → $OUT"
dd if="$DST" bs=4M count=$(( END * 512 )) iflag=count_bytes status=progress | gzip -1 > "$OUT"
( cd "$OUT_DIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
chown "$OWNER": "$OUT" "$OUT.sha256"
chmod 600 "$OUT" "$OUT.sha256"
say "完了: $(du -h "$OUT" | cut -f1)  $OUT"
say "PC へ取り出したら、Pi の中のファイルは消してください: rm $OUT $OUT.sha256"
say "2枚目のカードは、そのまま起動できる予備カードです（本番と同時に差して起動しないこと）"
say "使い終わったら、カードリーダーを Pi から外してください（同じ ID のカードが差さったままだと取り違えのもと）"
