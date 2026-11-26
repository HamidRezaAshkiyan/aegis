# AGENTS.md — Aegis

## Overview
**Aegis** is a lightweight, cross-platform (macOS, Windows, Linux/Docker) system-wide ad, tracker, and OS telemetry blocker written in Rust (`v0.2.2`). It combines a local DNS server (UDP/DoH upstream with CNAME cloaking defense), HTTP/HTTPS and SOCKS5 proxies with optional upstream VPN/proxy chaining, SQLite traffic analytics, crash-safe OS proxy/DNS integration, a native system tray/menu bar icon, and an embedded real-time WebSocket web dashboard.

## Tech Stack & Requirements
- **Language / Toolchain:** Rust (Edition 2021), Cargo workspace (`resolver = "2"`).
- **Async & Networking:** `tokio` (`full`), `hickory-proto` 0.24 (DNS), `reqwest` 0.12 (`rustls-tls`), `axum` 0.7 (`ws`), `tower-http` 0.5 (`cors`).
- **Storage & Config:** `rusqlite` 0.32 (`bundled` SQLite), `toml` 0.8, `serde` / `serde_json`, `directories` 5.
- **CLI & Logging:** `clap` 4 (`derive`), `tracing` + `tracing-subscriber` (`env-filter`), `anyhow`, `thiserror`.
- **Desktop Tray (macOS & Windows only):** `tray-icon` 0.19 + `tao` 0.30 (excluded on Linux/Docker).
- **Packaging:** `Dockerfile` (multi-stage Debian Bookworm) and `scripts/build-dmg.sh` (macOS DMG).

## Repository Structure
```text
aegis/
├── Cargo.toml                      # Workspace manifest (6 crates)
├── Dockerfile                      # Multi-stage Linux container (LAN / Pi-hole mode)
├── scripts/build-dmg.sh            # macOS arm64 DMG packager
└── crates/
    ├── core-engine/                # FilterEngine, AegisConfig, blocklist presets & ETag downloader
    │   └── src/{lib,config,engine,lists}.rs
    ├── core-dns/                   # Local DNS server (UDP/DoH upstream, CNAME cloaking defense)
    │   └── src/{lib,server}.rs
    ├── core-proxy/                 # HTTP/HTTPS & SOCKS5 proxies + upstream proxy chaining
    │   └── src/{lib,http_proxy,socks5_proxy,upstream}.rs
    ├── core-stats/                 # SQLite StatsStore & real-time traffic event stream
    │   └── src/{lib,events,store}.rs
    ├── core-os/                    # Crash-safe OS proxy/DNS toggles + background service installer
    │   └── src/{lib,macos,windows,service}.rs
    └── daemon/                     # Binary crate `aegis` (`aegis-daemon`)
        ├── src/main.rs             # CLI entry point, startup orchestration, tray vs headless loop
        ├── src/api.rs              # Axum REST + WebSocket dashboard API & auth
        ├── src/tray.rs             # macOS menu bar & Windows system tray integration
        └── ui/index.html           # Embedded single-file web dashboard
```

## Architecture & Key Flows
- **Entry Point (`crates/daemon/src/main.rs`):** Parses CLI flags (`--data-dir`, `--dns-addr`, `--http-addr`, `--socks5-addr`, `--api-addr`, `--update-lists`, `--lan`, `--auth-token`, `--no-tray`) or `aegis service <install|uninstall|status>`.
- **Crash Recovery:** On startup, calls `core_os::recover_if_dirty(&data_dir)` to restore OS system proxy/DNS snapshots if a previous process crashed without cleanup.
- **Core Services:** Loads `config.toml` into `AegisConfig`, initializes `FilterEngine` (domain/rule matching + curated blocklists) and `StatsStore` (SQLite), then concurrently runs:
  - **DNS Server** (`127.0.0.1:5353` default; `:53` with elevated privileges or Docker).
  - **HTTP/HTTPS Proxy** (`127.0.0.1:8080`) & **SOCKS5 Proxy** (`127.0.0.1:1080`), forwarding allowed traffic direct or chained through an upstream HTTP/SOCKS5 proxy (e.g., Clash, Sing-box, V2Ray).
  - **Dashboard & Control API** (`http://127.0.0.1:4242`) via Axum serving `ui/index.html`, REST endpoints (including `/api/auth/status`), and live WebSocket traffic logs.
- **Event Loop:** On macOS/Windows without `--no-tray`, `tao` owns the main thread for the native tray icon while Tokio runs background services.

## Development & Commands
```bash
# Run all workspace tests
cargo test --workspace

# Run in release mode (downloads enabled blocklists on startup)
cargo run --release -- --update-lists

# Run headless (no tray) on custom data dir
cargo run -- --no-tray --data-dir ./tmp-data

# Build release binary
cargo build --release --bin aegis

# Background service management (launchd / Task Scheduler / systemd --user)
aegis service install
aegis service status
aegis service uninstall

# Docker build & run (LAN / Pi-hole mode)
docker build -t aegis .
docker run -d --name aegis -p 53:53/udp -p 8080:8080 -p 1080:1080 -p 4242:4242 -v aegis-data:/data aegis
```

## Configuration & Environment
- **`config.toml`:** Created automatically under `<data_dir>/config.toml` (default OS app data dir via `directories`, or `--data-dir`). Stores listen addresses, blocklist URLs/schedules, allow/block rules, upstream proxy chaining, and auth settings.
- **`RUST_LOG`:** Standard `tracing-subscriber` filter (defaults to `info`).
- **`--auth-token <token>`:** Enables password/token auth for the dashboard & API (pass at runtime; never commit tokens).

## Conventions & Gotchas
- **Main-thread UI requirement on macOS:** `tao` / `tray-icon` must run on the main thread when tray mode is enabled; keep async network servers on a spawned Tokio runtime/tasks.
- **Platform-conditional crates:** `tray-icon` and `tao` are only compiled on `cfg(any(target_os = "macos", target_os = "windows"))`; ensure changes to `tray.rs` compile cleanly on Linux (`--no-tray` / Docker).
- **OS network state:** Modifying `core-os` (`macos.rs` via `networksetup`, `windows.rs` via Registry/`netsh`) affects host network settings—always preserve snapshot/restore and `recover_if_dirty` invariants.
- **Tracked `dist/` artifacts:** Prebuilt macOS archives exist under `dist/`; avoid accidentally modifying them unless running a release build (`scripts/build-dmg.sh`).
