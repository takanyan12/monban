# 変更履歴 / Changelog

新しい版が上です。v1.9 以前の詳しい記録は [docs/ja/history/](docs/ja/history/) にあります。
Newest first. Detailed notes for v1.9 and earlier (Japanese) are in [docs/ja/history/](docs/ja/history/).

## v1.14.3 — 2026-11-11

- **紹介ページの「試してみる」で締め出されないように**: 見本のページ（`backend/demo-site/index.php`）の3つのリンクに `gk-demo=1` を付け、これとまったく同じ要求で門番が止めたもの（403/404）は、AI 振る舞い分析の点数に数えない。外の回線から何度も押しても、デモをした人が自動遮断されない。遮断そのものは今までどおり
  Demo "try it" requests (exact match, blocked) are not counted by the behavior analysis, so presenters are not auto-blocked

## v1.14.2 — 2026-11-11

- **管理画面の設定の欄が、保存前に元へ戻る不具合を修正**: 画面は2秒ごとに表示を更新しており、そのたびに「メール通知の有効」「検知時に自動IP遮断」「設定レポート」のチェックボックスを保存済みの値で上書きしていた。チェックを付けてからほかの欄を入力しているうちに戻り、「無効」のまま保存されることがあった。欄を触ったら「未保存の変更があります」と出し、保存するまで上書きしない
  Dashboard: form fields (checkboxes) were overwritten by the 2-second refresh before saving; now kept until saved, with an "unsaved changes" hint
- メール通知の欄に「通知: 有効／無効」を常に表示（テスト送信は「無効」でも届くため、気付きにくかった）。保存したときに、有効・無効と自動IP遮断の ON・OFF を知らせる
  The mail card always shows whether notifications are enabled

## v1.14.1 — 2026-11-11

- **隠しファイルの探りを 404**: `/.env`・`/.git/config`・`/.htaccess` など「/.」で始まるパスは、奥のサーバーへ渡さず門番が 404 を返す（`/.well-known/` は除く）。公開直後から自動巡回が探しに来るため。自己試験に項目を追加
  Hidden-file probes (`/.env`, `/.git/…`) now get 404 at the gatekeeper (except `/.well-known/`)
- **見本のページ** `backend/demo-site/index.php`: 製品の紹介と、門番が攻撃を止める様子を試せるリンク付きの1枚のページ（外部のファイルを使わない）
  Sample product page with "try it" links that demonstrate blocking
- nginx の「duplicate MIME type "text/html"」の注意を解消（`subs_filter_types` は text/html を最初から含むため）

## v1.14.0 — 2026-11-10

- **インターネット公開ウィザード A に「MyDNS の DNS」**: 持ち主の確認の方法を「80番（標準）」と「MyDNS の DNS（80番が外から届かないとき）」から選べる。MyDNS のマスターID・パスワードは管理画面で入れ、root だけが読める `/etc/letsencrypt/mydns.netrc` に保存（画面・記録には出さない）。確認用スクリプト `conf/le-mydns-hook.sh` を導入スクリプトが `/opt/gatekeeper/` に入れ、改竄監視の対象にする
  Wizard A can validate via MyDNS DNS (DNS-01) for ISPs that block inbound port 80; credentials stored root-only
- **更新の予行演習**ボタン（`certbot renew --dry-run`）と、カードに「更新の方法・自動更新の有無・期限・予行演習の結果」を表示。方法を切り替えたときは証明書を取り直し、自動更新も新しい方法にそろえる
  Renewal dry-run button and renewal status on the card; switching methods re-issues so renewal follows the new method
- 自己試験に「インターネット公開の証明書」（期限まで14日以上・certbot.timer・正規の証明書での応答・MyDNS の確認用スクリプトとログイン情報の権限）を追加
  Self-test: public certificate checks
- `uninstall.sh --purge` で MyDNS のログイン情報も消す

## v1.13.2 — 2026-11-10

- **MyDNS の DNS で証明書を取得**（`tools/le-mydns.sh`）: プロバイダが外からの 80 番を止めていてウィザード A が失敗するとき用。Let's Encrypt の DNS-01 を、MyDNS の DirectEdit で TXT を自動登録・削除して行う。試験取得 → 本番取得 → ウィザード A と同じ形でドメインを公開。更新も自動（certbot.timer）。MyDNS のログイン情報は `/etc/letsencrypt/mydns.netrc`（root のみ）。説明は [docs/ja/publish.md](docs/ja/publish.md) の A'
  Let's Encrypt via MyDNS DNS-01 (`tools/le-mydns.sh`) for ISPs that block inbound port 80
- ウィザード A の「外から 80 番に届いていません」の案内に、この方法を追加
  The wizard's port-80 failure message now points to this tool

## v1.13.1 — 2026-11-10

- **WAF の修正（パストラバーサル）**: 符号化した `../`（`%2e%2e%2f`・`..%2f`・`%2e%2e/`）、Windows 形式の `..\`（`..%5c`）、二重符号化（`%252e`・`%252f`）が素通りしていたのを修正。原因は nginx が引用符の中の `\\` を `\` に読み替えるため正規表現の区切りがずれていたこと。`\` は `\x5c` と書くように変更（`snippets/gatekeeper_https_body.conf` と 80番の server）
  WAF fix: encoded path traversal (`%2e%2e%2f`, `..%5c`, double encoding) was not detected because nginx unescapes `\\` inside quoted strings; the rule now uses `\x5c`
- 自己試験に、引数に入れた符号化パストラバーサルの項目を2つ追加（以前の項目は別の理由で 400 が返り、この穴を見逃していた）
  Self-test: two new checks for encoded traversal in query strings

## v1.13.0 — 2026-11-10

- **本体画面（HDMI タッチモニター）**: 本体のモニターに「ダッシュボード」（見るだけ）と「設定」（パスワード必須・5分で自動ロック）を表示。設定は Wi-Fi（60 秒以内に確認しないと元に戻る）・守りのスイッチ・遮断の解除・メール通知・パスワード・ネットワークの確認・自己試験・再起動。画面キーボード付き。詳しくは [docs/ja/kiosk.md](docs/ja/kiosk.md)
  On-device screen for an HDMI touch monitor: view-only dashboard and password-protected settings (Wi-Fi with 60-second auto-revert, switches, unblock, mail, password, self-test, reboot), on-screen keyboard
- **初期パスワード**: 導入時に作るパスワードは「初期パスワード」として扱い、本体画面では最初に新しいパスワードを決めるまで設定に進めない
  The generated password is treated as an initial password; the on-device screen forces a change before any other setting
- 新しいサービス `gatekeeper-kiosk`（127.0.0.1:9100 のみ）、表示設定 `tools/setup-kiosk.sh`。改竄検知と待ち受けポートの監視に追加。自己試験に本体画面の項目（Host・CSRF・未ログイン・待ち受け先）を追加
  New service `gatekeeper-kiosk` (loopback only) and `tools/setup-kiosk.sh`; added to tamper/port monitoring and the self-test
- **パスワードを忘れたとき**: `setup-gatekeeper.sh --reset-password`（新しい初期パスワードを作る・ほかの設定はそのまま）。本体画面のパスワード入力に「忘れたとき」の案内。説明書「困ったとき」に3段階（管理パスワード／門番のやり直し／Pi のパスワードも忘れた＝全初期化）
  Forgotten passwords: `--reset-password`, an on-screen guide, and a three-level recovery section in Troubleshooting

## v1.12.0 — 2026-11-08 （最初の公開版 / first public release）

- **インターネット公開ウィザード**: 管理画面から A. Let's Encrypt（事前確認＝試験環境での取得 → 本番取得、自動更新、失敗原因を日本語で表示）／B. Cloudflare Tunnel（cloudflared 導入 → トークンで接続）を選べる
  Internet publishing wizard (Let's Encrypt with dry-run pre-check / Cloudflare Tunnel with token)
- nginx を組み替え: 443 番の本体を `snippets/gatekeeper_https_body.conf` に分離、80 番に ACME 用の通り道、`CF-Connecting-IP` は 127.0.0.1 からのみ信頼、自動遮断 IP を nginx でも拒否
  nginx restructure: shared HTTPS body, ACME path, real-IP from local cloudflared only, deny-list sync
- 導入スクリプトを1本化（`install/setup-gatekeeper.sh`）。環境の値は `/opt/gatekeeper/config.json` に。取り外し `install/uninstall.sh` を追加
  Single installer, environment values in config.json, uninstall script
- Windows バッチ v1.12.0: 門番からだけ許可するファイアウォール、Ollama の待ち受け設定、`echo ->` のリダイレクト不具合を修正
  Windows script: gatekeeper-only firewall rules, Ollama binding, fixed an `echo ->` redirection bug
- 配布物の照合: `SHA256SUMS.txt` を同梱。導入スクリプトは始める前に照合し、不一致や Windows 形式の改行（CRLF）があれば止まる。`--verify` でも確認。作り直しは `tools/make-sha256sums.sh`
  Release checksums (`SHA256SUMS.txt`), verified by the installer and `--verify`; CRLF detection
- SD カードの予備づくり `tools/sd-clone.sh` と、PC に保管するイメージ作成 `tools/sd-backup.sh`（実験的）
  SD card clone and compressed image backup tools (experimental)

## v1.11.0 — 2026-11-08

- **設定レポート（引き継ぎ用）**: 状態を1文書にまとめ、毎週・設定変更時・手動でメール送信（本文=要約、添付=全文）。冒頭に「異常の見分け方と最初の一手」。秘密情報は含めない
  Handover report by email (weekly / on change / manual); no secrets included

## v1.10.0 — 2026-11-08

- **個人情報 一括持ち出しガード**（`pii_guard.py`）: 応答のメール・電話・カード（番号体系＋Luhn）・マイナンバー（検査用数字）・住所を数え、1回 5件・10分 30件を超えたら 403。管理画面に ON/OFF・記録のみ・件数設定・履歴
  PII bulk-exfiltration guard with dashboard switch
- rpcbind（111番）を停止（NFS 不使用時）

## v1.9.7 — 2026-11-08

- 管理画面の CSRF 対策（POST に専用ヘッダ必須）、nft に渡す IP の検証、管理スイッチの状態を保存して自動復元
  Dashboard CSRF protection, IP validation, persisted management switch
- DLP: HTML エスケープされた資格情報ルール（html_cred）、検査対象に CSV/XML/JavaScript 系を追加
- WAF: SQL インジェクション判定を作り直し（普通の文章の誤検知を解消、`sleep%28` などのすり抜けを修正）
  WAF SQLi regex rewritten (fewer false positives, fixed encoded bypasses)
- `proxy_hide_header X-Powered-By`、nftables の SSH 許可を `10.0.0.0/24` 表記に

## v1.9.6 以前 / earlier

| 版 | 主な内容 |
| --- | --- |
| v1.9.6 | 製品名 micro-monban。管理画面の各カードに説明と「？」ヘルプ |
| v1.9.5 | ダッシュボードのテンプレートを実機検証版と同期（JS のエスケープ崩れの恒久対策） |
| v1.9 | 出口防御（大量転送・個人情報の連続取得・5xx 連発）、緊急ブレーカー、メール通知、IPv4 専用化 |
| v1.8 | IPv6 無効環境での nginx 起動失敗を解消、sshd を IPv4 固定 |
| v1.7 | SSH 監視の修正、信頼する相手を 10.0.0.2 とループバックに限定、WebSocket/SSE 対応、IPv6 無効化 |
| v1.6 | SSH 総当たり対策、管理画面の HTTPS 化、Request Smuggling 対策、低速スキャン検知 |
| v1.5 | TLS（HTTPS）対応、ローカル認証局 |
| v1.4 | セルフ整合性監視、証拠ログの転送、読み取り専用モード |
| v1.3 | DLP ルールを管理画面で管理（14種） |
| v1.2 | 設定ブロック、外部側 IF の自動検出、`--verify` |
| v1.1 | 許可リストの自動復元、JSON ログ、Basic 認証 |
