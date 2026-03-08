# Chimæra

Privacy-focused per-app Tor VPN for Android. Route selected apps through the Tor network — everything else goes direct.

## Features

- **Per-app Tor routing** — choose exactly which apps get Tor protection
- **Built-in Tor** — no Termux, no Orbot, no external dependencies
- **Kill switch** — selected apps get zero internet when VPN stops (packet-level drop)
- **Connection leak prevention** — force-stops selected apps on VPN start to kill pre-existing direct connections
- **DNS through Tor** — DNS queries intercepted at packet level, resolved via Tor (no system resolver leak)
- **New Identity** — switch Tor exit node with one tap (SIGNAL NEWNYM)
- **IP verification** — check your Tor exit IP vs real IP
- **Battery optimization** — Tor dormant mode when no traffic flows
- **Always-on VPN** support
- **Auto-start on boot**
- **Dual app / work profile** support
- **No ads, no analytics, no tracking, no data collection**

## How it works

Chimæra uses Android's `VpnService` to capture network traffic from selected apps at the IP packet level:

- **TCP** → routed through Tor via SOCKS5 proxy (port 9050)
- **UDP port 53 (DNS)** → intercepted, resolved through Tor via SOCKS5 to 8.8.8.8:53, response injected back as UDP
- **Other UDP** → dropped (prevents leaks)

The Tor binary is bundled via `info.guardianproject:tor-android` and runs as a native process managed by `TorManager`.

## Architecture

| File | Purpose |
|------|---------|
| `MainActivity.java` | UI: start/stop VPN, app selector, always-on toggle, IP check, new identity |
| `TorVpnService.java` | VPN service, packet parsing, SOCKS5 proxy, kill switch (drain loop) |
| `TorManager.java` | Manages bundled Tor process (start/stop/dormant/newIdentity via control port) |
| `ApiService.java` | HTTP API on localhost for automation |
| `BootReceiver.java` | Auto-start on boot |
| `Packet.java` | Raw IP/TCP/UDP packet parser/builder |

~2000 lines of Java. No frameworks, no SDKs beyond Tor itself. Fully auditable.

## Build

```bash
# Clone
git clone https://github.com/ihubanov/chimaera.git
cd chimaera

# Build debug APK
./gradlew assembleDebug

# Install
adb install app/build/outputs/apk/debug/app-debug.apk
adb shell pm grant com.torproxy android.permission.WRITE_SECURE_SETTINGS
```

Requires Android SDK with compileSdk 34 and Java 17.

## Why not Orbot?

| | Chimæra | Orbot |
|---|---|---|
| **Focus** | Per-app VPN, one purpose | Full Tor suite (bridges, onion services, proxy modes) |
| **Leak prevention** | Force-stops apps on VPN start | No force-stop |
| **Kill switch** | Packet-level drop (VPN tunnel stays up) | Relies on Android always-on lockdown |
| **Battery** | Tor dormant mode when idle | Always active |
| **Codebase** | ~2000 lines, audit in 30 min | Large codebase |
| **Complexity** | One screen, pick apps, press start | Many settings and modes |

Orbot is great if you need bridges, onion services, or full proxy support. Chimæra is for people who want a focused, minimal, leak-resistant per-app Tor VPN.

## Beta Testing

We're currently in Google Play closed testing. To help us reach production:

1. **[Join the closed test](https://play.google.com/apps/testing/com.torproxy)** (you'll need to be added as a tester first)
2. Install the app from the Play Store test track
3. Stay opted in for 14 days

We need 12 testers to unlock production access. If you'd like to help, [open an issue](https://github.com/ihubanov/chimaera/issues/new?title=Request+to+join+beta&body=I%27d+like+to+join+the+closed+beta+test.+My+Gmail+is:+) with your Gmail address (used for Google Play), and we'll add you to the test.

## Privacy Policy

[https://ihubanov.github.io/chimaera-privacy/](https://ihubanov.github.io/chimaera-privacy/)

## License

MIT
