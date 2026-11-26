# Aegis v1.0 — System-Wide Ad Blocker, DoH, Anti-DPI & Proxy

A minimal, lightweight, cross-platform (**macOS, Windows, and Linux/Docker**) ad, tracker, and malware blocker written in Rust with **local & upstream DoH**, **user-space Anti-DPI**, **hot-reloadable listeners**, **one-step PC/Mac/Phone setup**, and **upstream proxy / VPN chaining**.

## Features
- **Safe-by-Default Blocking & Protection Profiles**: ships with **Balanced (HaGeZi Multi Normal + Threat Intelligence Mini)** by default for near-zero false positives, plus 1-click **Minimal**, **Balanced**, and **Strict + OS Telemetry** profiles and a DNS-safe Adblock parser that ignores browser-scoped `$third-party` / `$domain=` rules.
- **Hot-Reloadable Listeners (No Restart Required)**: independently enable, disable, or change the bind address/port of **UDP DNS**, **Local DoH (`/dns-query`)**, **HTTP/HTTPS Proxy**, and **SOCKS5 Proxy** live from the dashboard (or pass `--no-dns`).
- **DNS-over-HTTPS (Upstream & Local RFC 8484)**:
  - **Upstream DoH** with presets (Cloudflare, Quad9, Google, AdGuard, Mullvad, or custom), **CNAME uncloaking**, and optional routing through your chained upstream proxy/VPN.
  - **Local DoH Server** at `http://<host>:4242/dns-query` (GET & POST RFC 8484), active even when UDP DNS is disabled.
- **Pure-Rust Anti-DPI Engine**: user-space **TLS ClientHello SNI Record Splitting** (parses the SNI extension and splits directly inside the hostname), **TCP Chunking**, and optional **HTTP Host Header Mix-Case** with per-domain bypass — zero root privileges or kernel drivers required.
- **Enhanced Upstream Proxy & VPN Chaining**: chain allowed traffic into **Clash, Mihomo, Sing-box, V2Ray, Hiddify, Nekoray, Tor, or SSH tunnels** with **1-click Local Proxy Scanner**, username/password auth, bypass domains, and a live **Connection & Latency Tester**.
- **One-Step Quick Setup (PC, Mac & Phone)**:
  - 1-click **System Proxy**, **System DNS**, and **Start at Login (Background Service)** toggles.
  - Auto-generated **PAC file** (`/proxy.pac`) + **offline SVG QR code** + step-by-step **iOS & Android** guides.
  - Downloadable one-step configurator scripts for **macOS** (`setup-aegis-macos.sh`) and **Windows PowerShell 7** (`setup-aegis-windows.ps1`), both with undo support.
- **Modern Embedded Dashboard** (`http://127.0.0.1:4242`): sidebar layout with Dark/Light theme, 24-hour traffic chart, real-time WebSocket activity stream with matched-rule attribution & 1-click Allow/Block, Domain Rule Tester, Devices (LAN) view, and TOML/JSON backup/restore.

## Quick Start

```bash
# Build & run (with automatic blocklist download on first launch)
cargo run --release -- --update-lists

# Open the dashboard in your browser:
# http://127.0.0.1:4242
```

### Default Endpoints
- **Web Dashboard & API**: `http://127.0.0.1:4242`
- **Proxy Auto-Config (PAC)**: `http://127.0.0.1:4242/proxy.pac`
- **Local DoH (RFC 8484)**: `http://127.0.0.1:4242/dns-query`
- **HTTP/HTTPS Proxy**: `127.0.0.1:8080`
- **SOCKS5 Proxy**: `127.0.0.1:1080`
- **Local UDP DNS**: `127.0.0.1:5353` (pass `--no-dns` to disable, or `--dns-addr 127.0.0.1:53` with elevated privileges)

## Using Alongside a VPN or Proxy Manager
1. **Clash / Sing-box / V2Ray / Hiddify / Tor**: Open **Proxy, DoH & Anti-DPI**, click **Scan Local Proxies**, pick your running proxy, click **Test Connection**, and click **Save & Apply Live**.
2. **WireGuard / Tailscale / Outline (TUN VPN)**: Either point your VPN's DNS to Aegis (`127.0.0.1` on port 53) or disable Aegis's UDP DNS listener live in the dashboard and use Aegis purely as a filtering/Anti-DPI proxy.

## Running with Docker

```bash
# Build the image
docker build -t aegis .

# Run as a LAN / Pi-hole DNS, DoH & proxy blocker with persistent /data volume
docker run -d --name aegis --restart unless-stopped \
  -p 53:53/udp \
  -p 8080:8080 \
  -p 1080:1080 \
  -p 4242:4242 \
  -v aegis-data:/data \
  aegis --lan --no-tray --data-dir /data --dns-addr 0.0.0.0:53 --update-lists
```

## Running Tests

```bash
cargo test --workspace
```
