# On-device screen (HDMI touch monitor)

Connect a monitor (ideally a touch screen) to the Raspberry Pi 5's HDMI port to **see the gatekeeper's status and change settings on the device itself**. You can maintain it without a PC or SSH — and if a network change locks you out of SSH, you can fix it right there.

> Since v1.13.0. Requires Raspberry Pi OS with desktop. The screen is in Japanese.

## Two screens

| Screen | Contents | Password |
| --- | --- | --- |
| **Dashboard** | Overall status (green / yellow / red), today's requests and denials, currently blocked IPs, PII guard events, component status, recent events, Wi-Fi and IPs | Not needed (view only) |
| **Settings** | Guided initial setup, Wi-Fi, protection switches, unblock, mail notifications, password, network (view and test), self-test, time and reboot | Required |

- Settings **lock automatically after 5 minutes** of inactivity and return to the dashboard. The lock button locks immediately.
- **Five wrong passwords in a row** pause logins for 60 seconds.
- Text is entered with the **on-screen keyboard** (a physical keyboard also works). "次の欄" moves to the next field; "決定" presses the screen's blue button.

## Initial password

- The installer generates a **per-device initial password** and shows it **once** at the end. It is shared by the web dashboard and the on-device screen.
- When you open the on-device settings with the initial password, **you must set a new password before anything else**. Then a guided setup follows (Wi-Fi → mail → backend PC → self-test).
- New passwords: 10+ characters, letters, digits and symbols (no quotes, backslash, dollar sign, backtick, # or spaces). Changing it also changes the web dashboard password.
- If you forget it: tap "忘れたとき" on the login screen, or see [Troubleshooting → Forgotten passwords](troubleshooting.md#forgotten-passwords). With SSH access, `sudo bash install/setup-gatekeeper.sh --reset-password` creates a new initial password.

## Showing it on the monitor

After running the installer (v1.13.0 or later):

```bash
sudo bash tools/setup-kiosk.sh
```

- Installs Chromium and Japanese fonts (`fonts-noto-cjk`) if missing.
- Opens the screen full-screen (Chromium kiosk mode) when the user logs in.
- Asks whether to log in to the desktop automatically at power-on — convenient for a monitor setup.
- Then `sudo reboot`.

To stop:
```bash
sudo bash tools/setup-kiosk.sh --remove
```

### You need
- An HDMI monitor (a 7-inch 800×480 touch screen is a good fit; larger monitors scale up)
- A **micro HDMI** cable or adapter (Raspberry Pi 5)
- For touch: the monitor's USB cable for the touch signal

## Switching Wi-Fi and the 60-second confirmation

- Settings → Wi-Fi lists nearby networks; pick one and enter its password.
- **If you don't press "このまま使う" (keep) within 60 seconds, it switches back automatically.** A mistake can't lock you out.
- If you move to a network with a different LAN range (e.g. 192.168.1.0/24), re-run the installer with matching settings (`HOME_NET`, etc.). Changing these from the screen is planned.

## Security notes

- The screen server (`gatekeeper-kiosk`) **listens on 127.0.0.1:9100 only** — invisible from the LAN and the internet.
- Requests with a foreign Host header, without the CSRF header, or without a login are rejected (covered by the self-test).
- **Anyone standing at the device can see the dashboard**, including blocked IPs. Mind where you put the monitor.
- The kiosk runs on an auto-logged-in desktop, so **a connected keyboard may be able to leave full-screen mode**. Use touch only and unplug the keyboard in normal operation.
- A Wi-Fi password is visible as an `nmcli` argument on the device for a few seconds while connecting (only to people logged in to the device).

## Not yet (planned)
- Changing the LAN range, inside IP, or backend IP/port from the screen (view and test only for now)
- Display on Raspberry Pi OS Lite (no desktop)
- Brightness and screen-off settings
