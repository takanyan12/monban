# Backend PC setup

The backend PC is connected to the gatekeeper's closed side (10.0.0.0/24) with one cable and accepts connections **only from the gatekeeper (10.0.0.1)**.

## Common rules

| Item | Required state |
| --- | --- |
| Wired adapter | IP `10.0.0.2` / `255.255.255.0`, **no gateway, no DNS** |
| Wi-Fi | **Off** (otherwise there is a path that bypasses the gatekeeper) |
| Web app | Listens on `10.0.0.2:8080` (listening on `localhost` only is unreachable from the gatekeeper) |
| Firewall | Allow the web app (8080) etc. **only from 10.0.0.1** |

## Windows

### Quick setup (batch file)

Right-click `backend/setup-windows.bat` → "**Run as administrator**". It will:

1. Save the current network settings to the desktop
2. Firewall: allow ports 8080 / 11434 and ping only from the gatekeeper (10.0.0.1), and disable the "allow from anyone" rules Windows creates when PHP or Ollama first runs
3. Set the wired adapter to 10.0.0.2 (asks first)
4. Make Ollama listen on 10.0.0.2 only (optional)
5. Test connectivity to the gatekeeper

> The batch file is saved in CP932 (Shift-JIS) with CRLF line endings, because Japanese Windows `netsh` needs it. Do not re-save it in another encoding. Its messages are in Japanese.

### Example: running PHP

1. Extract the Windows build from php.net (**VS17 x64 Non Thread Safe** ZIP) to `C:\PHP`
2. Copy `C:\PHP\php.ini-development` to `C:\PHP\php.ini`, uncomment the extensions you need (e.g. `extension=mbstring`), set `date.timezone`
3. Create the document root `C:\PHP\www`
4. Start it (runs while the window stays open):
   ```bat
   C:\PHP\php.exe -S 10.0.0.2:8080 -t C:\PHP\www
   ```

> `php -S` is a development server. For production, use Apache or nginx + PHP-FPM.

**Sample page**: `backend/demo-site/index.php` is a single page introducing the gatekeeper, with "試してみる" (try it) links that send deliberately malicious-looking requests so visitors can see the gatekeeper block them. Save it as `C:\PHP\www\index.php` for demos. It uses no external images or fonts.
Remove test pages (pages that return sample personal or secret data) from the document root **before publishing to the internet**.

### Using Ollama

1. Set the user environment variable `OLLAMA_HOST` to `10.0.0.2:11434` (step 4 of the batch file can do this)
2. In Ollama's Settings, turn **"Expose Ollama to the network" OFF** (when ON it overrides `OLLAMA_HOST` and listens on all addresses)
3. Quit Ollama from the system tray and start it again
4. `%LOCALAPPDATA%\Ollama\server.log` should show `Listening on 10.0.0.2:11434`

### Check

On the gatekeeper (Pi):
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://10.0.0.2:8080/      # e.g. 200
curl -s http://10.0.0.2:11434/api/version                            # if you use Ollama
```
- **Timeout** → the Windows firewall is silently dropping the connection
- **Immediate "connection refused"** → the app is not running, or listens on `localhost` only

### After updating PHP or Ollama

Updates may show the "allow access?" prompt again and create an "allow from anyone" rule. Run the batch file again.

## Linux (experimental)

`backend/setup-backend-linux.sh` is a **theoretical design and untested**. Read and understand it before use.
The idea is the same as on Windows: fixed 10.0.0.2, no gateway, firewall allows only 10.0.0.1, and the app listens on 10.0.0.2.
