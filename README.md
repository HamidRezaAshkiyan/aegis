# Aegis — Open-Source System-Wide Ad & Tracker Blocker

A minimal, lightweight, cross-platform (**Windows & macOS**) ad, tracker, and OS telemetry blocker written in Rust.

## Features
- **Local DNS Server** (`127.0.0.1:5353` / `:53`) with **DoH / UDP upstream** and **CNAME cloaking defense**.
- **HTTP/HTTPS Proxy** (`127.0.0.1:8080`) & **SOCKS5 Proxy** (`127.0.0.1:1080`) for browser, per-app, or system-wide filtering.
- **VPN & Proxy Manager Chaining**: forward allowed traffic directly or chain through an upstream **SOCKS5 / HTTP proxy** (Clash, Mihomo, Sing-box, V2Ray, Nekoray) with live hot-switching.
- **OS Telemetry & App Tracker Blocking**: ships with curated presets for **HaGeZi Multi PRO**, **Windows & Office Native Telemetry**, **Apple / macOS Telemetry**, **AdGuard DNS**, and **EasyPrivacy**, plus an offline baseline.
- **Scheduled Blocklist Auto-Updates**: background updater refreshes enabled lists on a configurable interval using `ETag` / `If-Modified-Since` conditional HTTP requests.
- **LAN / Pi-hole Mode & Dashboard Auth**: listen on `0.0.0.0` (`--lan`) with per-device/IP statistics and friendly device naming, plus optional password/token authentication (`--auth-token`).
- **Native System Tray / Menu Bar App**: lightweight macOS menu bar & Windows system tray icon with live blocked counter, 1-click Pause (5m / 15m / 1h), System Proxy toggle, Open Dashboard, and Quit (`--no-tray` for headless mode).
- **Crash-Safe OS Integration**: snapshots and restores macOS (`networksetup`) and Windows (`Registry` / PowerShell / `netsh`) **system proxy and system DNS** settings on exit or crash recovery.
- **Background Service / Launch at Login**: `aegis service install | uninstall | status` for macOS `launchd`, Windows Task Scheduler / Startup, and Linux `systemd --user`.
- **Real-Time Embedded Dashboard** (`http://127.0.0.1:4242`): live WebSocket traffic log, categorized counters, Devices (LAN) view, 1-click Allow/Block, Blocklist Manager, Quick Pause, and 1-click **Config & Rules Import/Export** (TOML/JSON).

## Quick Start

```bash
# Build & run (with automatic blocklist download on first launch)
cargo run --release -- --update-lists

# Open the dashboard in your browser:
# http://127.0.0.1:4242
```

### Default Endpoints
- **Web Dashboard & API**: `http://127.0.0.1:4242`
- **HTTP/HTTPS Proxy**: `127.0.0.1:8080`
- **SOCKS5 Proxy**: `127.0.0.1:1080`
- **Local DNS**: `127.0.0.1:5353` (pass `--dns-addr 127.0.0.1:53` with elevated privileges for standard port 53)

## Using Alongside a VPN or Proxy Manager
1. **Clash / Sing-box / V2Ray (Proxy Mode)**: Open the **Proxy & VPN** tab in the dashboard, choose **Chain via Upstream SOCKS5 Proxy**, and enter `127.0.0.1:7890` (Clash) or `127.0.0.1:10808` (V2Ray/Sing-box). Point apps or system proxy to Aegis (`127.0.0.1:8080` / `:1080`).
2. **WireGuard / OpenVPN**: Run Aegis DNS on port `53` (`sudo aegis --dns-addr 127.0.0.1:53`) and set `DNS = 127.0.0.1` in your VPN profile.

## Running Tests

```bash
cargo test --workspace
```
