#!/bin/bash
# =====================================================================
#  micro-monban: 起動中の SD カードを、USB でつないだ別のカードへ丸ごと写す（予備づくり）
#    sudo bash tools/sd-clone.sh /dev/sda
#  ・門番を動かしたまま写せる（ファイル単位でコピー）
#  ・写し先は「使っている量」より大きければよい（本番と同じ容量でなくてもよい）
#  ・起動の設定（PARTUUID）も同じにするので、写したカードはそのまま起動できる
#    ※ 元のカードと写したカードを同時に差したまま起動しないこと（同じ ID のため取り違える）
#    ※ 同じ ID のカードを差しているあいだ、systemd が /boot/firmware を外すことがある。
#       このスクリプトは起動用の区画を元のカードから直接読み、最後に /boot/firmware を元のカードに付け直す
#  ・写し先の中身はすべて消える。名前と容量を表示し、yes と入力するまで始めない
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
set -eu
DST="${1:-}"
say(){ echo "[sd-clone] $*"; }
die(){ echo "[sd-clone] 中止: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "sudo で実行してください"
[ -n "$DST" ] || die "写し先を指定してください（例: sudo bash $0 /dev/sda）。lsblk で確認できます"
[ -b "$DST" ] || die "$DST という装置がありません"
blockdev --getsz "$DST" >/dev/null 2>&1 || die "$DST にカードが入っていません（カードリーダーの空きの口かもしれません。lsblk で容量のある sdX を確認してください）"

# --- 元（今起動しているカード）を調べる ---------------------------------
ROOT_PART=$(findmnt -n -o SOURCE /)                       # 例: /dev/mmcblk0p2
SRC="/dev/$(lsblk -no PKNAME "$ROOT_PART")"               # 例: /dev/mmcblk0
BOOT_PART=$(lsblk -lnpo NAME "$SRC" | sed -n 2p)          # 例: /dev/mmcblk0p1（/boot/firmware が外れていても求められる）
[ "$SRC" != "$DST" ] || die "$DST は今起動に使っているカードです。写し先にはできません"
case "$DST" in /dev/sd[a-z]) ;; *) die "写し先は USB でつないだカード（/dev/sda など）に限ります";; esac
[ "$(lsblk -dno TRAN "$DST")" = "usb" ] || die "$DST は USB 接続ではありません"
command -v rsync >/dev/null || { say "rsync を導入します"; apt-get install -y -qq rsync >/dev/null; }

# /boot/firmware が元のカードの起動用区画に付いている状態に戻す
fix_boot(){
  local cur; cur=$(findmnt -n -o SOURCE /boot/firmware 2>/dev/null || true)
  [ "$cur" = "$BOOT_PART" ] && return 0
  [ -n "$cur" ] && umount /boot/firmware
  mount "$BOOT_PART" /boot/firmware && say "/boot/firmware を元のカード（$BOOT_PART）に付け直しました"
}
fix_boot

SRC_DISK=$(basename "$SRC")
P1_START=$(cat /sys/block/$SRC_DISK/$(basename "$BOOT_PART")/start)
P1_SIZE=$(cat /sys/block/$SRC_DISK/$(basename "$BOOT_PART")/size)
P2_START=$(cat /sys/block/$SRC_DISK/$(basename "$ROOT_PART")/start)
DISK_ID=$(sfdisk --disk-id "$SRC")
# 本体の区画の大きさ（既定は写し先の最後まで。sd-backup.sh はファイルを小さくするため GK_ROOT_MB で指定する）
P2_SIZE_SPEC=""; ROOT_NEED=$(( $(df --output=used -k / | tail -1) * 2 * 11 / 10 ))
if [ -n "${GK_ROOT_MB:-}" ]; then P2_SIZE_SPEC="size=$(( GK_ROOT_MB * 2048 )), "; ROOT_NEED=$(( GK_ROOT_MB * 2048 )); fi
DST_SECTORS=$(blockdev --getsz "$DST")
NEED_SECTORS=$(( P2_START + ROOT_NEED ))   # 使用量の1.1倍の余裕（または指定の大きさ）
[ "$DST_SECTORS" -gt "$NEED_SECTORS" ] || die "写し先が小さすぎます（必要 約$((NEED_SECTORS / 2 / 1024 / 1024))GB）"

echo "=================================================================="
echo " 元      : $SRC（起動中・$(lsblk -dno SIZE "$SRC")・使用 $(df -h --output=used / | tail -1 | tr -d ' ')）"
echo " 写し先  : $DST（$(lsblk -dno SIZE "$DST")・$(lsblk -dno MODEL "$DST")）"
echo " 写し先の今の中身:"
lsblk -o NAME,SIZE,FSTYPE,LABEL "$DST" | sed 's/^/   /'
echo " ★ 写し先 $DST の中身はすべて消えます ★"
echo "=================================================================="
read -r -p "よろしければ yes と入力: " ans
[ "$ans" = "yes" ] || die "取りやめました"

# --- 写し先を作る ---------------------------------------------------------
for m in $(lsblk -nlo MOUNTPOINT "$DST" | grep -v '^$' || true); do umount "$m"; done
fix_boot
say "区画を作っています（起動の ID は元と同じ $DISK_ID）"
printf 'label: dos\nlabel-id: %s\nunit: sectors\n\nstart=%s, size=%s, type=c\nstart=%s, %stype=83\n' \
  "$DISK_ID" "$P1_START" "$P1_SIZE" "$P2_START" "$P2_SIZE_SPEC" | sfdisk --wipe always --wipe-partitions always -q "$DST"
partprobe "$DST" 2>/dev/null || true; udevadm settle; sleep 2
mkfs.vfat -F 32 -n bootfs "${DST}1" >/dev/null
mkfs.ext4 -F -q -L rootfs "${DST}2"

T=$(mktemp -d); B=$(mktemp -d)
cleanup(){ umount "$B" 2>/dev/null; umount "$T/boot/firmware" 2>/dev/null; umount "$T" 2>/dev/null; rmdir "$T" "$B" 2>/dev/null; fix_boot || true; }
trap cleanup EXIT
mount "${DST}2" "$T"; mkdir -p "$T/boot/firmware"; mount "${DST}1" "$T/boot/firmware"
mount "$BOOT_PART" "$B"                                    # 起動用区画は元のカードから直接読む

# --- 中身を写す -----------------------------------------------------------
say "本体を写しています（数分〜20分。門番は動いたままです）"
sync
rsync -aHAXx --numeric-ids --info=progress2 --exclude=/lost+found --exclude='/home/*/monban-sd-*' / "$T/"
say "起動用の区画を写しています"
rsync -rt --info=progress2 "$B/" "$T/boot/firmware/"
sync

# --- 確かめる --------------------------------------------------------------
[ -f "$T/boot/firmware/cmdline.txt" ] && [ -f "$T/boot/firmware/config.txt" ] || die "起動用の区画が正しく写せませんでした（cmdline.txt / config.txt が無い）"
say "起動用の区画: $(ls "$T/boot/firmware" | wc -l) 個（元 $(ls "$B" | wc -l) 個）"
say "起動の設定: $(grep -o 'root=[^ ]*' "$T/boot/firmware/cmdline.txt")"
say "写し先の使用量: $(df -h --output=used "$T" | tail -1 | tr -d ' ')（元 $(df -h --output=used / | tail -1 | tr -d ' ')）"
cleanup; trap - EXIT
[ "$(findmnt -n -o SOURCE /boot/firmware)" = "$BOOT_PART" ] || die "/boot/firmware を元のカードに付け直せませんでした。sudo mount $BOOT_PART /boot/firmware を実行してください"
[ -n "${GK_FROM_BACKUP:-}" ] && { say "写し終わりました"; exit 0; }
say "完了しました。sudo poweroff で止めてから、元のカードを抜き、写したカードを本体に差して起動してください。"
say "（元と写しを同時に差したまま起動しないでください。使い終わったカードリーダーは Pi から外してください）"
