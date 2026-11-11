# 導入ガイド

micro-monban を、まっさらな Raspberry Pi に導入する手順です。所要時間はおよそ30分〜1時間です（ネット回線の速さによります）。

## 0. 全体の形を決める

| 機器 | つなぎ方 | アドレス（初期値） |
| --- | --- | --- |
| 門番（Raspberry Pi）の外側 | Wi-Fi または USB-LAN でルーターへ | DHCP（ルーターの「DHCP 予約」で固定するのがおすすめ） |
| 門番の内側（`eth0`） | サーバー役PC と LAN ケーブル1本で直結 | 10.0.0.1 |
| サーバー役PC | 門番とだけ有線でつなぐ。**Wi-Fi は止める** | 10.0.0.2 |
| 作業用PC | 家庭 LAN（ルーター）につなぐ | 何でもよい |

> サーバー役PC の Wi-Fi を入れると、門番を通らない道ができてしまいます。必ず止めてください。

## 1. Raspberry Pi の準備

1. Raspberry Pi Imager で **Raspberry Pi OS（64-bit、Bookworm 以降）** を microSD に書き込みます。
   - 設定画面で、ユーザー名・パスワード、Wi-Fi（外側に Wi-Fi を使う場合）、**SSH を有効**にしておきます。
2. Pi を起動し、作業用PC から SSH で入れることを確かめます。
   ```bash
   ssh ユーザー名@raspberrypi.local
   ```
3. ルーターの管理画面で、Pi の外側（Wi-Fi など）に **DHCP 予約**で固定の IP を割り当てておくと、あとが楽です。

## 2. リポジトリを Pi に置く

Pi の上で:
```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/takanyan12/monban.git micro-monban
cd micro-monban
```

> Windows で ZIP を展開してから Pi にコピーした場合、改行コードが変わって動かないことがあります。できるだけ Pi の上で `git clone` してください（導入スクリプトは改行の異常を見つけると止まります）。
> ZIP で受け取った場合は、ZIP のまま Pi へ送り、Pi の上で `unzip` してください。

### 中身が正しいか確かめる（設定ブロックを書き換える前に）

```bash
sha256sum -c --quiet SHA256SUMS.txt && echo "すべて一致"
```

「すべて一致」と出れば、配布されたとおりの中身です。一致しないファイルが表示されたら、入手の途中で壊れたか書き換えられた可能性があるので、入手し直してください。
導入スクリプトも始める前に同じ照合をし、一致しなければ止まります（設定ブロックを書き換える `install/setup-gatekeeper.sh` 自身は照合から外し、改行だけを確かめます）。

## 3. 設定ブロックを自分の環境に合わせる

```bash
nano install/setup-gatekeeper.sh
```
冒頭の「★ 設定ブロック ★」だけを書き換えます。

| 項目 | 初期値 | 説明 |
| --- | --- | --- |
| `EXT_IF` | `auto` | 外側のインターフェース。自動で見つからないときは `wlan0` や `eth1` を指定（`ip -o link` で確認） |
| `EXT_IP` | `auto` | 外側の IP。`auto` は DHCP のまま |
| `HOME_NET` | `192.168.1.0/24` | **家庭 LAN の範囲。ルーターが 192.168.0.x なら `192.168.0.0/24` に必ず変更** |
| `INT_IF` / `INT_IP` | `eth0` / `10.0.0.1/24` | 内側（閉域）。ふつうはそのまま |
| `BACKEND_IP` / `BACKEND_PORT` | `10.0.0.2` / `8080` | サーバー役PC と Web アプリのポート |
| `DASH_PORT` | `9000` | 管理画面のポート |
| `DASH_MODE` | `switch` | `switch`: 管理画面を家庭 LAN 側へ一時的に開けるスイッチを使う／`port-forward-only`: 家庭 LAN 側からは常に閉じる（SSH 経由だけ） |

保存は `Ctrl+O` → `Enter`、終了は `Ctrl+X` です。

## 4. 導入スクリプトを実行

```bash
sudo bash install/setup-gatekeeper.sh
```

- OS の更新と必要なソフト（nginx、nftables、certbot など）の導入から始まります。
- 最後に **管理画面のパスワードが1回だけ表示されます。** パスワードマネージャーなどに控えてください。
  - あとで確認するとき: `sudo cat /opt/gatekeeper/secret.conf`
- 同じスクリプトを再実行すると、設定やパスワードを引き継いだまま更新できます。

### 自己診断

```bash
sudo bash install/setup-gatekeeper.sh --verify
```
`結果: 合格（FAIL 0 …）` と出れば成功です。サーバー役PC をまだ設定していなければ、「バックエンド無応答」の △ が出ますが問題ありません。

より詳しい健康診断（読み取りのみ）:
```bash
sudo bash tools/gk_check.sh
```

## 5. サーバー役PC を設定する

[サーバー役PCの設定](backend.md) を見てください。Windows なら `backend/setup-windows.bat` を**管理者として実行**します。

## 6. 証明書の鍵を退避する（大切）

門番は自分専用の小さな認証局（CA）を作り、その鍵 `ca.key` で証明書に署名しています。
`ca.key` があれば門番になりすました証明書を作れてしまうため、**装置の外へ退避して、Pi からは消します**（稼働には影響しません）。

1. Pi の上で、鍵を自分のホームフォルダへ一時的にコピーします。
   ```bash
   sudo install -m 600 -o "$(whoami)" /opt/gatekeeper/tls/ca.key ~/ca.key
   ```
2. 作業用PC で、鍵と証明書を受け取ります。
   ```bash
   scp ユーザー名@門番のIP:ca.key .
   scp ユーザー名@門番のIP:/opt/gatekeeper/tls/ca.crt .
   ```
3. `ca.key` を USB メモリなど、ネットにつながない場所へ移します。
4. Pi の上で、一時コピーと元の鍵を消します。
   ```bash
   rm ~/ca.key && sudo rm /opt/gatekeeper/tls/ca.key
   ```
5. `sudo bash install/setup-gatekeeper.sh --verify` で「ca.key: 装置内に無し」と出れば完了です。

### ブラウザの警告を消したい場合

`ca.crt` を、管理に使う端末に「信頼されたルート証明機関」として登録すると、門番の HTTPS で警告が出なくなります。
- Windows: `ca.crt` をダブルクリック →「証明書のインストール」→「ローカル コンピューター」→「証明書をすべて次のストアに配置する」→「信頼されたルート証明機関」

インターネットに公開する場合は、ドメイン用の正規の証明書を使います（[インターネット公開](publish.md)）。

## 7. 管理画面を開く

| どこから | 方法 |
| --- | --- |
| サーバー役PC（閉域側） | `https://10.0.0.1:9000/`（認証なし） |
| 作業用PC（ふだん） | SSH の転送を使う: `ssh -L 9000:localhost:9000 ユーザー名@門番のIP` を実行したまま `https://localhost:9000/` |
| 作業用PC（一時的に） | 管理画面のスイッチ「公開する」のあいだだけ `https://門番のIP:9000/`（ユーザー名 `admin`） |

### 管理画面のパスワードを変える

本体にモニターをつないでいれば、[本体画面](kiosk.md)の「パスワード」からも変えられます。SSH で変えるときは:

```bash
sudo nano /opt/gatekeeper/secret.conf          # GK_ADMIN_PASS= の右側を書き換える
sudo chmod 600 /opt/gatekeeper/secret.conf
sudo systemctl restart gatekeeper-dashboard
```

## 取り外し

```bash
sudo bash install/uninstall.sh            # 機能を外す（設定・証明書は残す）
sudo bash install/uninstall.sh --purge    # すべて消し、ファイアウォールを初期状態に戻す
```

## さらに強くする（任意・実験的）

- `tools/enable-readonly.sh`: 読み取り専用モード（書き込みはメモリ上だけ。改竄を検知すると自動で再起動し、元の状態に戻る）。動作確認は限られています。
- `tools/setup-ab-recovery.sh`: A/B 形式の復旧イメージ。**理論上の設計で未検証**です。
