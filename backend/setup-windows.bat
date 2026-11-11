@echo off
chcp 932 >nul
setlocal
rem =====================================================================
rem  micro-monban Windows バックエンド初期設定 v1.12.0
rem  （閉域側のサーバー役PC 用。右クリック→「管理者として実行」）
rem  Copyright 2026 AiLab-Japan / Apache License 2.0
rem
rem  このバッチは CP932(Shift-JIS)・CRLF で保存しています。文字コードを変えて保存しないでください。
rem  （UTF-8 だと日本語版 Windows の netsh がアダプター名「イーサネット」を照合できません）
rem
rem  やること:
rem   1) 今のネットワーク設定をデスクトップに控える
rem   2) ファイアウォール: 門番(10.0.0.1)からだけ Web(8080) と Ollama(11434) と ping を許可
rem      PHP や Ollama を初めて動かしたときに自動で作られる「誰からでも許可」ルールは無効化
rem   3) 有線アダプターを 10.0.0.2 / 255.255.255.0（ゲートウェイ・DNS なし）に
rem   4) Ollama を 10.0.0.2 だけで待ち受けさせる（任意）
rem   5) 門番との疎通テスト
rem =====================================================================

rem ===== 設定（ふつうは変えなくてOK） =====
set DEFAULT_ADAPTER=イーサネット
set STATIC_IP=10.0.0.2
set SUBNET_MASK=255.255.255.0
set GATEKEEPER_IP=10.0.0.1
set WEB_PORT=8080

net session >nul 2>&1
if errorlevel 1 (
    echo  [NG] 管理者として実行してください（右クリック→「管理者として実行」）。
    pause
    exit /b 1
)

echo ===================================================
echo  micro-monban Windows バックエンド初期設定 v1.12.0
echo ===================================================

echo [1/5] 今のネットワーク設定をデスクトップへ控えています...
netsh interface ipv4 show addresses > "%USERPROFILE%\Desktop\micro-monban-net-backup.txt" 2>nul
if errorlevel 1 netsh interface ipv4 show addresses > micro-monban-net-backup.txt
echo        → micro-monban-net-backup.txt に保存しました（元に戻すときの参考に）

echo [2/5] ファイアウォールを設定しています（門番 %GATEKEEPER_IP% からだけ許可）...
rem 旧版（v1.7 まで）が作った「誰からでも許可」のルールを消す
netsh advfirewall firewall delete rule name="ICMPv4-Allow" >nul 2>&1
netsh advfirewall firewall delete rule name="PHP-8080-Allow" >nul 2>&1
rem 入れ替え用に、このバッチのルールも一度消す
netsh advfirewall firewall delete rule name="micro-monban backend from gatekeeper" >nul 2>&1
netsh advfirewall firewall delete rule name="micro-monban ping from gatekeeper" >nul 2>&1
netsh advfirewall firewall add rule name="micro-monban backend from gatekeeper" dir=in action=allow protocol=TCP localport=%WEB_PORT%,11434 remoteip=%GATEKEEPER_IP% >nul
netsh advfirewall firewall add rule name="micro-monban ping from gatekeeper" dir=in action=allow protocol=icmpv4:8,any remoteip=%GATEKEEPER_IP% >nul
rem php.exe / ollama.exe の初回起動時に作られる「誰からでも許可」ルールを無効化（削除ではないので戻せる）
powershell -NoProfile -Command "Get-NetFirewallApplicationFilter | Where-Object { $_.Program -like '*php*.exe' -or $_.Program -like '*ollama*' } | Get-NetFirewallRule | Disable-NetFirewallRule" >nul 2>&1
echo        → TCP %WEB_PORT%,11434 と ping を %GATEKEEPER_IP% からだけ許可しました

echo [3/5] 有線アダプターの固定IP設定
echo ---------------------------------------------------
echo  今のネットワークアダプター一覧:
netsh interface show interface
echo ---------------------------------------------------
set ADAPTER=%DEFAULT_ADAPTER%
set /p ADAPTER_INPUT=門番と直結した有線アダプター名を入力（そのまま Enter で「%DEFAULT_ADAPTER%」）:
if not "%ADAPTER_INPUT%"=="" set ADAPTER=%ADAPTER_INPUT%
echo.
echo  「%ADAPTER%」を IP %STATIC_IP% / %SUBNET_MASK%（ゲートウェイ・DNS なし）に設定します。
set DOIP=N
set /p DOIP_INPUT=実行しますか？ Y=自動設定 / N=手動で行う:
if /i "%DOIP_INPUT%"=="Y" set DOIP=Y
if /i "%DOIP%"=="Y" (
    netsh interface ipv4 set address name="%ADAPTER%" static %STATIC_IP% %SUBNET_MASK%
    netsh interface ipv4 set dnsservers name="%ADAPTER%" source=static address=none >nul 2>&1
    echo  → 固定IPを設定しました。
) else (
    echo  → 手動の場合は、アダプターの設定で
    echo     IP アドレス %STATIC_IP% / サブネット %SUBNET_MASK% / ゲートウェイ空欄 / DNS 空欄
    echo     にしてください。
)

echo [4/5] Ollama を %STATIC_IP% だけで待ち受けさせる（Ollama を使わない場合は N）
set DOOL=N
set /p DOOL_INPUT=設定しますか？ Y / N:
if /i "%DOOL_INPUT%"=="Y" set DOOL=Y
if /i "%DOOL%"=="Y" (
    setx OLLAMA_HOST %STATIC_IP%:11434 >nul
    echo  → ユーザー環境変数 OLLAMA_HOST=%STATIC_IP%:11434 を設定しました。
    echo     Ollama の Settings で「Expose Ollama to the network」を OFF にし、
    echo     タスクトレイから Ollama を終了して起動し直してください。
)

echo [5/5] 疎通テスト中...
ping -n 2 %GATEKEEPER_IP% | findstr /i "TTL" >nul
if not errorlevel 1 (
    echo  [OK] 門番 %GATEKEEPER_IP% と通信できます
) else (
    echo  [NG] %GATEKEEPER_IP% と通信できません。ケーブル接続と門番の起動を確認してください。
)
netsh interface ipv4 show addresses name="%ADAPTER%" 2>nul | findstr "%STATIC_IP%" >nul
if not errorlevel 1 (
    echo  [OK] アダプター「%ADAPTER%」に %STATIC_IP% が設定されています
) else (
    echo  [INFO] %STATIC_IP% が見つかりません。手動設定の場合は上の手順を確認してください。
)

echo ---------------------------------------------------
echo  完了しました。Web アプリは %STATIC_IP%:%WEB_PORT% で起動してください
echo  （PHP の例: php -S %STATIC_IP%:%WEB_PORT% -t C:\PHP\www）。
echo  外からは門番の https://（門番の外部側IP）/ で見られます。
echo  Wi-Fi は止めたままにしてください（門番を通らない道ができるため）。
echo ---------------------------------------------------
pause
