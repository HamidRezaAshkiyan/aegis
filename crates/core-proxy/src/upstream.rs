use crate::anti_dpi::should_bypass;
use anyhow::{bail, Context};
use base64::Engine as _;
use core_engine::{ProxyConfig, UpstreamMode};
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Returns true if `target_host` should connect directly rather than via the upstream proxy.
pub fn is_direct_route(cfg: &ProxyConfig, target_host: &str) -> bool {
    if cfg.upstream_mode == UpstreamMode::Direct {
        return true;
    }
    should_bypass(target_host, &cfg.upstream_bypass)
}

/// Connect to `target_host:target_port` either directly or chained through an upstream
/// SOCKS5 or HTTP proxy (e.g., Clash, Sing-box, V2Ray, Nekoray, SSH tunnel).
pub async fn connect_outbound(
    cfg: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<TcpStream> {
    let timeout = Duration::from_secs(15);
    if is_direct_route(cfg, target_host) {
        let stream =
            tokio::time::timeout(timeout, TcpStream::connect((target_host, target_port)))
                .await
                .context("Direct connect timed out")?
                .with_context(|| {
                    format!("Direct connect failed to {target_host}:{target_port}")
                })?;
        let _ = stream.set_nodelay(true);
        return Ok(stream);
    }

    match cfg.upstream_mode {
        UpstreamMode::Direct => unreachable!(),
        UpstreamMode::Socks5 => {
            if cfg.upstream_addr.trim().is_empty() {
                bail!("Upstream SOCKS5 mode enabled but upstream_addr is empty");
            }
            tokio::time::timeout(
                timeout,
                connect_via_socks5(
                    &cfg.upstream_addr,
                    cfg.upstream_username.as_deref(),
                    cfg.upstream_password.as_deref(),
                    target_host,
                    target_port,
                ),
            )
            .await
            .context("Upstream SOCKS5 connect timed out")?
        }
        UpstreamMode::Http => {
            if cfg.upstream_addr.trim().is_empty() {
                bail!("Upstream HTTP mode enabled but upstream_addr is empty");
            }
            tokio::time::timeout(
                timeout,
                connect_via_http(
                    &cfg.upstream_addr,
                    cfg.upstream_username.as_deref(),
                    cfg.upstream_password.as_deref(),
                    target_host,
                    target_port,
                ),
            )
            .await
            .context("Upstream HTTP proxy connect timed out")?
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamTestResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub mode: UpstreamMode,
    pub upstream_addr: String,
    pub message: String,
}

/// Test connectivity through the configured outbound route (Direct, SOCKS5, or HTTP).
pub async fn test_upstream(cfg: &ProxyConfig) -> UpstreamTestResult {
    let started = Instant::now();
    // Temporarily clear bypass so we definitely test the configured upstream proxy
    let mut test_cfg = cfg.clone();
    test_cfg.upstream_bypass.clear();
    match tokio::time::timeout(
        Duration::from_secs(6),
        connect_outbound(&test_cfg, "1.1.1.1", 443),
    )
    .await
    {
        Ok(Ok(_stream)) => UpstreamTestResult {
            ok: true,
            latency_ms: started.elapsed().as_millis() as u64,
            mode: cfg.upstream_mode.clone(),
            upstream_addr: cfg.upstream_addr.clone(),
            message: "Connected successfully to 1.1.1.1:443".to_string(),
        },
        Ok(Err(e)) => UpstreamTestResult {
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            mode: cfg.upstream_mode.clone(),
            upstream_addr: cfg.upstream_addr.clone(),
            message: e.to_string(),
        },
        Err(_) => UpstreamTestResult {
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            mode: cfg.upstream_mode.clone(),
            upstream_addr: cfg.upstream_addr.clone(),
            message: "Connection test timed out after 6s".to_string(),
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectedProxy {
    pub name: String,
    pub mode: UpstreamMode,
    pub addr: String,
}

/// Probe well-known localhost proxy ports (Clash, V2Ray, Sing-box, Hiddify, Tor, etc.)
/// to help users chain Aegis in one click. Skips any ports owned by Aegis itself.
pub async fn scan_local_proxies(skip_ports: &[u16]) -> Vec<DetectedProxy> {
    let candidates: &[(&str, UpstreamMode, u16)] = &[
        ("Clash / Mihomo (Mixed)", UpstreamMode::Socks5, 7890),
        ("Clash Verge (Mixed)", UpstreamMode::Socks5, 7897),
        ("V2Ray / v2rayN (SOCKS5)", UpstreamMode::Socks5, 10808),
        ("V2Ray / v2rayN (HTTP)", UpstreamMode::Http, 10809),
        ("Sing-box / Nekoray (Mixed)", UpstreamMode::Socks5, 2080),
        ("Hiddify (Mixed)", UpstreamMode::Socks5, 12334),
        ("Tor (SOCKS5)", UpstreamMode::Socks5, 9050),
        ("Shadowsocks / SSH (SOCKS5)", UpstreamMode::Socks5, 1080),
        ("Local HTTP Proxy", UpstreamMode::Http, 8080),
        ("Local HTTP Proxy (8888)", UpstreamMode::Http, 8888),
    ];

    let mut handles = Vec::new();
    for &(name, ref mode, port) in candidates {
        if skip_ports.contains(&port) {
            continue;
        }
        let name = name.to_string();
        let mode = mode.clone();
        handles.push(tokio::spawn(async move {
            let addr = format!("127.0.0.1:{port}");
            let ok = tokio::time::timeout(
                Duration::from_millis(150),
                TcpStream::connect(&addr),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            if ok {
                Some(DetectedProxy { name, mode, addr })
            } else {
                None
            }
        }));
    }

    let mut found = Vec::new();
    for h in handles {
        if let Ok(Some(proxy)) = h.await {
            found.push(proxy);
        }
    }
    found
}

async fn connect_via_socks5(
    upstream_addr: &str,
    username: Option<&str>,
    password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("Failed to connect to upstream SOCKS5 at {upstream_addr}"))?;
    let _ = stream.set_nodelay(true);

    // 1. Greeting
    let has_auth = username.is_some_and(|u| !u.is_empty()) && password.is_some();
    if has_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;
    if method_resp[0] != 0x05 {
        bail!("Invalid SOCKS5 version from upstream");
    }

    match method_resp[1] {
        0x00 => {} // No auth
        0x02 => {
            let user = username.unwrap_or_default().as_bytes();
            let pass = password.unwrap_or_default().as_bytes();
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01);
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user);
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass);
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                bail!("Upstream SOCKS5 authentication failed");
            }
        }
        0xFF => bail!("Upstream SOCKS5 rejected all auth methods"),
        m => bail!("Unsupported SOCKS5 auth method from upstream: {m}"),
    }

    // 2. CONNECT request using ATYP = 0x03 (Domain) to avoid local DNS leaks
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        bail!("Target host too long for SOCKS5");
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    // 3. Read reply header
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        bail!("Upstream SOCKS5 CONNECT failed with code {}", hdr[1]);
    }

    // Drain BND.ADDR + BND.PORT
    match hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        other => bail!("Invalid ATYP in upstream SOCKS5 reply: {other}"),
    }

    Ok(stream)
}

async fn connect_via_http(
    upstream_addr: &str,
    username: Option<&str>,
    password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("Failed to connect to upstream HTTP proxy at {upstream_addr}"))?;
    let _ = stream.set_nodelay(true);

    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let (Some(u), Some(p)) = (username.filter(|s| !s.is_empty()), password) {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("Upstream HTTP proxy closed connection during CONNECT");
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            bail!("Upstream HTTP proxy response header too large");
        }
    }

    let header_str = String::from_utf8_lossy(&buf);
    let status_line = header_str.lines().next().unwrap_or_default();
    if !status_line.contains(" 200") {
        bail!("Upstream HTTP proxy rejected CONNECT: {status_line}");
    }

    Ok(stream)
}
