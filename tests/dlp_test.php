<?php
// 門番 DLP 試験ページ（値はすべて架空のダミー。試験が終わったら削除すること）
// 置き場所: C:\PHP\www\dlp_test.php
//   ?fmt=text（既定）/ html / json で Content-Type を切り替える
$fmt = $_GET['fmt'] ?? 'text';

$lines = [
    'T01 sqlstate     : PDOException SQLSTATE[42S02] Base table not found',
    'T02 sqlstate-lc  : error sqlstate[hy000] lower case',
    'T03 php_fatal    : Fatal error: Uncaught Exception in C:\\PHP\\www\\app.php:12',
    'T04 phone_jp     : TEL 03-1234-5678 / 090-1234-5678',
    'T05 stripe_key   : sk_live_TESTdummy0000KEY1234',
    'T06 jwt          : eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.dummySignature_123',
    'T07 aws_key      : AKIAIOSFODNN7EXAMPLE',
    'T08 github_token : ghp_DUMMYtoken0000000000000000000000AB',
    'T09 json_cred    : {"password":"dummy-pass-123","api_key":"dummy-key-456","user":"taro"}',
    'T10 db_conn      : mysql://appuser:dummypw@db.example.local:3306/app',
    'T11 private_key  : -----BEGIN RSA PRIVATE KEY-----',
    // 以下は既定で無効のルール（伏せ字にならないのが正しい）
    'T12 internal_ip  : backend 10.0.0.2 / 192.168.0.50',
    'T13 email        : contact dummy.user@example.com',
    'T14 credit_card  : card 4111111111111111',
    // 誤検知確認（伏せ字にならないのが正しい）
    'T15 normal       : version 8.5.12, date 2026-11-08, port 8080',
];

if ($fmt === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'password' => 'dummy-pass-123',
        'token' => 'dummy-token-789',
        'client_secret' => 'dummy-secret-000',
        'user' => 'taro',
        'tel' => '03-1234-5678',
        'aws' => 'AKIAIOSFODNN7EXAMPLE',
        'email' => 'dummy.user@example.com',
    ], JSON_UNESCAPED_SLASHES) . "\n";
} elseif ($fmt === 'html') {
    header('Content-Type: text/html; charset=utf-8');
    echo "<html><body><pre>\n" . implode("\n", array_map('htmlspecialchars', $lines)) . "\n</pre></body></html>\n";
} else {
    header('Content-Type: text/plain; charset=utf-8');
    echo implode("\n", $lines) . "\n";
}
