<?php
// micro-monban 製品案内ページ（デモ用）。サーバー役PC の公開フォルダーに index.php として置く
//  ・外部の画像・フォント・スクリプトは使わない（このファイルだけで表示できる）
//  ・門番（10.0.0.1）を通って届いたかどうかを表示する
$via_gk = ($_SERVER['REMOTE_ADDR'] ?? '') === '10.0.0.1';
$now = date('Y-m-d H:i');
header('Content-Type: text/html; charset=utf-8');
?><!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>micro-monban 門番システム</title>
<meta name="description" content="Raspberry Pi 5 で作る、小さいけれど強い門番。サーバーの前に置いて、入口と出口を見張ります。">
<style>
:root { --bg:#f5f7fa; --card:#ffffff; --ink:#18202c; --sub:#5b6575; --line:#e1e6ed; --acc:#1f6feb; --ok:#13854a; --warn:#b45309; --hero1:#0f2a4a; --hero2:#16457a; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1318; --card:#171c23; --ink:#e7ebf0; --sub:#9aa4b2; --line:#29313b; --acc:#6ea8ff; --ok:#3fcf7f; --warn:#f0a43a; --hero1:#0b1d33; --hero2:#12345c; } }
* { box-sizing:border-box; }
body { margin:0; font-family:"Segoe UI","Hiragino Sans","Yu Gothic UI",Meiryo,sans-serif; background:var(--bg); color:var(--ink); line-height:1.7; }
a { color:var(--acc); }
.hero { background:linear-gradient(135deg,var(--hero1),var(--hero2)); color:#fff; padding:56px 16px 48px; }
.wrap { max-width:960px; margin:0 auto; padding:0 16px; }
.hero h1 { margin:0; font-size:clamp(26px,5vw,40px); letter-spacing:.02em; }
.hero p { margin:10px 0 0; font-size:clamp(15px,2.6vw,18px); opacity:.92; }
.badge { display:inline-flex; align-items:center; gap:8px; margin-top:22px; padding:6px 12px; border-radius:999px; background:rgba(255,255,255,.12); font-size:13px; }
.dot { width:9px; height:9px; border-radius:50%; background:#4ade80; box-shadow:0 0 0 3px rgba(74,222,128,.25); }
.dot.off { background:#fbbf24; box-shadow:0 0 0 3px rgba(251,191,36,.25); }
section { padding:40px 0 8px; }
h2 { font-size:20px; margin:0 0 16px; }
.lead { color:var(--sub); margin:-6px 0 20px; }
.flow { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.node { flex:1 1 140px; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; text-align:center; }
.node b { display:block; font-size:15px; }
.node span { font-size:12px; color:var(--sub); }
.node.gk { border:2px solid var(--acc); }
.arrow { color:var(--sub); font-size:20px; flex:0 0 auto; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; }
.card h3 { margin:0 0 6px; font-size:16px; }
.card p { margin:0; color:var(--sub); font-size:14px; }
.ico { font-size:22px; }
.demo a { display:inline-block; margin:6px 8px 0 0; padding:8px 14px; border-radius:8px; border:1px solid var(--line); background:var(--card); text-decoration:none; font-size:14px; }
.demo a:hover { border-color:var(--acc); }
.note { font-size:13px; color:var(--sub); }
footer { margin-top:48px; padding:24px 0 40px; border-top:1px solid var(--line); color:var(--sub); font-size:13px; }
@media (max-width:640px) { .arrow { transform:rotate(90deg); flex-basis:100%; text-align:center; } }
</style>
</head>
<body>
<header class="hero">
  <div class="wrap">
    <h1>🛡️ micro-monban 門番システム</h1>
    <p>Raspberry Pi 5 で作る、小さいけれど強い門番。<br>あなたのサーバーの前に立って、入口と出口を見張ります。</p>
    <div class="badge"><span class="dot<?= $via_gk ? '' : ' off' ?>"></span>
      <?= $via_gk ? 'このページは今、門番を通して届いています' : 'このページは門番を通らずに表示されています（試験用の直接アクセス）' ?>（<?= htmlspecialchars($now) ?>）</div>
  </div>
</header>

<main class="wrap">
  <section>
    <h2>しくみ</h2>
    <p class="lead">ルーターやファイアウォールの代わりではなく、その内側でサーバーを守る「もう一枚の壁」です。</p>
    <div class="flow">
      <div class="node"><b>インターネット</b><span>お客さま・攻撃者</span></div>
      <div class="arrow">→</div>
      <div class="node"><b>ルーター</b><span>家庭・事務所の入口</span></div>
      <div class="arrow">→</div>
      <div class="node gk"><b>門番（Raspberry Pi 5）</b><span>検査・遮断・記録</span></div>
      <div class="arrow">→</div>
      <div class="node"><b>サーバー</b><span>Web・AI など</span></div>
    </div>
  </section>

  <section>
    <h2>できること</h2>
    <div class="grid">
      <div class="card"><div class="ico">🚪</div><h3>入口の検査（WAF）</h3><p>SQL インジェクション、ディレクトリ外の読み出し、攻撃ツールの名乗りを、サーバーに届く前に止めます。</p></div>
      <div class="card"><div class="ico">🔏</div><h3>出口の検査（DLP）</h3><p>パスワード・鍵・トークン・エラー内容などが応答に混ざったら、伏せ字にしてから外へ出します。</p></div>
      <div class="card"><div class="ico">👥</div><h3>個人情報の持ち出しガード</h3><p>メール・電話・カード番号・住所などを数え、一度に大量に持ち出されそうになったら止めます。</p></div>
      <div class="card"><div class="ico">⛔</div><h3>自動遮断と緊急ブレーカー</h3><p>怪しい相手を自動で締め出し、いざというときはボタン1つで外からの入口を閉じられます。</p></div>
      <div class="card"><div class="ico">🔍</div><h3>改竄の見張り</h3><p>門番自身の大切な設定を5分ごとに点検し、書き換えや予定外の通信を見つけます。</p></div>
      <div class="card"><div class="ico">🔐</div><h3>正式な証明書</h3><p>Let's Encrypt の証明書を自動で取得・更新。80番が使えない回線でも、DNS で確認して取得できます。</p></div>
      <div class="card"><div class="ico">🖥️</div><h3>本体画面</h3><p>HDMI のタッチモニターで、状態の確認や Wi-Fi などの設定ができます。PC がなくてもメンテナンスできます。</p></div>
      <div class="card"><div class="ico">📨</div><h3>通知と引き継ぎ</h3><p>異常はメールで知らせ、設定の一覧を「引き継ぎ用レポート」として定期的に送ります。</p></div>
    </div>
  </section>

  <section class="demo">
    <h2>試してみる</h2>
    <p class="lead">下のリンクは、わざと攻撃に見える形で送ります。門番が止めると「Blocked by Gatekeeper WAF」と表示されます（サーバーには届きません）。</p>
    <a href="/?id=1+union+select+password+from+users&gk-demo=1" rel="nofollow">SQL インジェクションを送ってみる</a>
    <a href="/?file=..%2f..%2fetc%2fpasswd&gk-demo=1" rel="nofollow">ディレクトリ外を読もうとしてみる</a>
    <a href="/.env?gk-demo=1" rel="nofollow">隠しファイル（.env）を探してみる</a>
    <p class="note">戻るときは、ブラウザの「戻る」を押してください。</p>
  </section>

  <footer>
    micro-monban（門番システム）— AiLab-Japan ／ Apache License 2.0
  </footer>
</main>
</body>
</html>
