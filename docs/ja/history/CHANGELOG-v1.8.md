# Gatekeeper v1.8 変更点 — 外部レビュー第2ラウンド対応（5項目）

## 1. [重大修正] IPv6無効化 × nginx listen [::] の衝突
- 問題: v1.7 の disable_ipv6=1 環境では、nginx の `listen [::]:80/443` の bind が
  EAFNOSUPPORT (97) で失敗し、nginx の起動・リロードが失敗する（門番全体が停止）
- 修正: IPv4専用アプライアンスとして **site設定から [::] listen を全廃**。
  併せて sshd も `AddressFamily inet`（sshd_config.d）で IPv4固定。
- --verify に「[::] 残存チェック」「sshd IPv4固定チェック」を追加。
- 選択理由: 「IPv6有効＋nftablesでv6 DROP」の代替案は将来のv6対応の道を残す利点があるが、
  IPv4専用装置としての整合（遮断迂回の根絶）を優先し [::] 廃止を採用。

## 2. [重大修正] setup-backend-linux.sh の ufw proto icmp 構文エラー
- 問題: `ufw allow ... proto icmp` は Invalid protocol となり、set -e でセットアップが異常終了
- 修正: 指定行を削除。ping許可は ufw 既定ルール (/etc/ufw/before.rules) に委ねる旨を明記。
  残る ufw 呼び出しにも `|| echo` のガードを追加（ufw異常でスクリプトが止まらない）。

## 3. A/B復旧のデバイス認識待ちとマウント検査
- sfdisk 直後に partprobe + udevadm settle + sleep を追加（デバイスノード生成遅延対策）
- do_recover: 書き戻し先がマウント済み（レスキューOSの自動マウント等）なら**実行を拒否**。
  ゴールデンSD自身を書き戻し先に指定した場合も拒否。v1.7の無意味な残留行を除去。

## 4. ssh_watch の死活監視・自動再起動
- journalctl プロセス終了（journald再起動等）時の沈黙を防ぐため、log_watcher と同じ
  p.poll() 監視＋自動再起動を実装。単体テストで「死んだプロセスから3回再spawn」を確認。

## 5. subs_filter の $1 後方参照について（指摘への検証結果）
- 指摘: 「subs_filter は $1 を展開できず、キー名が壊れる」
- 検証: 同梱モジュール（libnginx-mod-http-subs-filter 0.6.4、Debian/Raspberry Pi OS系）で
  実機再試験を実施。`"(password|secret|access_token)"...` → `"$1":"[REDACTED]"` の結果、
  **`"password":"[REDACTED]"` / `"secret":"[REDACTED]"` とキー名が保持され、リテラル $1 は出力されない**ことを確認。
- 結論: ルールは現状維持。ただしモジュールのビルド/版数依存の可能性を CHANGELOG と
  マニュアルに明記し、Chapter 9 の「マスキング試験」ボタンで各自の環境確認ができるよう案内。
  非対応ビルドの場合の代替（キー別の固定ルール）例も CHANGELOG に付記。

## 検証結果
- bash -n ×4 / py_compile / トークン展開漏れゼロ（@@BACKEND_IP@@ 含む）
- 回帰断言: 組込site設定に [::] なし / journalctl は -kf でなく -u ssh -u sshd /
  map+Upgrade 存在 / is_trusted は 3アドレス限定 / stats_gc_once・spawn_tail・spawn_ssh 存在 /
  DLP追加の ; 拒否 / ufw icmp 行の完全除去 / ab-recovery の settle・findmnt ガード
- 実機（IPv6無効のサンドボックス）: [::]付き旧設定は起動失敗（Address family not supported を
  error.logで確認）、[::]なし新設定は起動成功・HTTPS 200 — 衝突の実証と修正の有効性を確認
- 単体テスト: 既存19件＋IP抽出(from束縛)＋ssh_watch自動再起動＋着信/外向き判定 全PASS
- ライブ: /api/status?_=… 200 / DLP追加の ; 注入を拒否 / HTTPS経由DLP 200 / Upgrade要求 200

## 既知の残課題
- setup-ab-recovery.sh / setup-backend-linux.sh は引き続き理論上・未実機検証
- IPv6必須環境には未対応（将来版で v6 セット対応の予定）
