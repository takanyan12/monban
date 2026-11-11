#!/bin/bash
# =====================================================================
#  micro-monban: 配布物の SHA256SUMS.txt を作り直す（ファイルを直したら、配る前に必ず実行）
#    bash tools/make-sha256sums.sh
#  ・確かめるとき: sha256sum -c SHA256SUMS.txt （全部 OK なら正しい）
#  ・Git の管理ファイル（.git/）と SHA256SUMS.txt 自身は含めない
#  Copyright 2026 AiLab-Japan / Apache License 2.0
# =====================================================================
set -eu
cd "$(dirname "$0")/.."
find . -type f ! -path './.git/*' ! -name SHA256SUMS.txt -printf '%P\n' \
  | LC_ALL=C sort | while IFS= read -r f; do sha256sum "$f" | sed 's/ \*/  /'; done > SHA256SUMS.txt
echo "SHA256SUMS.txt を作り直しました（$(wc -l < SHA256SUMS.txt) ファイル）"
