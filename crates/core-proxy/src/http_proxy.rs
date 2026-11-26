use crate::anti_dpi::{obfuscate_http_host_header, relay_tunnel, should_bypass};
use crate::upstream::{connect_outbound, is_direct_route};
use chrono::Utc;
use core_engine::{AntiDpiConfig, FilterDecision, FilterEngine, ProxyConfig};
use core_stats::{StatsStore, TrafficEvent, TrafficProtocol};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, info};

pub struct HttpProxyServer {
    config: Arc<RwLock<ProxyConfig>>,
    anti_dpi: Arc<RwLock<AntiDpiConfig>>,
    engine: Arc<FilterEngine>,
    stats: Arc<StatsStore>,
}

impl HttpProxyServer {
    pub fn new(
        config: Arc<RwLock<ProxyConfig>>,
        anti_dpi: Arc<RwLock<AntiDpiConfig>>,
        engine: Arc<FilterEngine>,
        stats: Arc<StatsStore>,
    ) -> Self {
        Self {
            config,
            anti_dpi,
            engine,
            stats,
        }
    }

    pub async fn bind(&self, listen_addr: &str) -> anyhow::Result<TcpListener> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!(addr = %listener.local_addr()?, "Aegis HTTP/HTTPS proxy listening");
        Ok(listener)
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("HTTP proxy shutting down");
                        break;
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let srv = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = srv.handle_client(stream, peer).await {
                                    debug!(error = %e, %peer, "HTTP proxy connection ended");
                                }
                            });
                        }
                        Err(e) => {
                            debug!(error = %e, "HTTP proxy accept error");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_client(&self, mut client: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
        let started = Instant::now();
        let _ = client.set_nodelay(true);

        // Read HTTP request headers up to \r\n\r\n
        let mut header_buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        let header_end;
        loop {
            let n = client.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            header_buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subsequence(&header_buf, b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
            if header_buf.len() > 32 * 1024 {
                let _ = client
                    .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                    .await;
                return Ok(());
            }
        }

        let header_text = String::from_utf8_lossy(&header_buf[..header_end]);
        let first_line = header_text.lines().next().unwrap_or_default();
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();

        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = parse_host_port(target, 443);
            let decision = self.engine.check_domain(&host);
            let latency_ms = started.elapsed().as_millis() as u64;

            if matches!(decision, FilterDecision::Block { .. }) {
                self.stats.record(TrafficEvent {
                    timestamp: Utc::now(),
                    protocol: TrafficProtocol::Https,
                    domain: host,
                    client: peer.ip().to_string(),
                    decision,
                    latency_ms,
                });
                let _ = client
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nX-Blocked-By: Aegis\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                return Ok(());
            }

            let cfg = self.config.read().unwrap().clone();
            let direct = is_direct_route(&cfg, &host);
            let mut outbound = match connect_outbound(&cfg, &host, port).await {
                Ok(s) => s,
                Err(_) => {
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                        .await;
                    return Ok(());
                }
            };

            self.stats.record(TrafficEvent {
                timestamp: Utc::now(),
                protocol: TrafficProtocol::Https,
                domain: host.clone(),
                client: peer.ip().to_string(),
                decision: FilterDecision::Allow,
                latency_ms,
            });

            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let dpi_cfg = self.anti_dpi.read().unwrap().clone();
            let buffered = if header_end < header_buf.len() {
                &header_buf[header_end..]
            } else {
                &[]
            };
            relay_tunnel(&mut client, &mut outbound, buffered, &dpi_cfg, &host, direct).await;
            return Ok(());
        }

        // Plain HTTP proxy request
        let (host, port) = extract_http_host(target, &header_text);
        if host.is_empty() {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }

        let decision = self.engine.check_domain(&host);
        let latency_ms = started.elapsed().as_millis() as u64;
        if matches!(decision, FilterDecision::Block { .. }) {
            self.stats.record(TrafficEvent {
                timestamp: Utc::now(),
                protocol: TrafficProtocol::Http,
                domain: host,
                client: peer.ip().to_string(),
                decision,
                latency_ms,
            });
            let _ = client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nX-Blocked-By: Aegis\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\n\r\nBlocked by Aegis",
                )
                .await;
            return Ok(());
        }

        let cfg = self.config.read().unwrap().clone();
        let direct = is_direct_route(&cfg, &host);
        let mut outbound = match connect_outbound(&cfg, &host, port).await {
            Ok(s) => s,
            Err(_) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        self.stats.record(TrafficEvent {
            timestamp: Utc::now(),
            protocol: TrafficProtocol::Http,
            domain: host.clone(),
            client: peer.ip().to_string(),
            decision: FilterDecision::Allow,
            latency_ms,
        });

        // Rewrite absolute-form URI (http://host/path -> /path) for origin server
        let mut rewritten = rewrite_http_request(&header_buf[..header_end], method, target);
        let dpi_cfg = self.anti_dpi.read().unwrap().clone();
        if direct
            && dpi_cfg.enabled
            && dpi_cfg.http_host_mix_case
            && !should_bypass(&host, &dpi_cfg.bypass_domains)
        {
            rewritten = obfuscate_http_host_header(&rewritten);
        }
        outbound.write_all(&rewritten).await?;
        if header_end < header_buf.len() {
            outbound.write_all(&header_buf[header_end..]).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut outbound).await;
        Ok(())
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_host_port(raw: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((ip, port_part)) = rest.split_once(']') {
            let port = port_part
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (ip.to_string(), port);
        }
    }
    if let Some((h, p)) = raw.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (raw.to_string(), default_port)
}

fn extract_http_host(target: &str, headers: &str) -> (String, u16) {
    if let Some(rest) = target.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or_default();
        return parse_host_port(authority, 80);
    }
    for line in headers.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                return parse_host_port(v.trim(), 80);
            }
        }
    }
    (String::new(), 80)
}

fn rewrite_http_request(header_bytes: &[u8], method: &str, target: &str) -> Vec<u8> {
    if let Some(rest) = target.strip_prefix("http://") {
        let path = match rest.find('/') {
            Some(idx) => &rest[idx..],
            None => "/",
        };
        let header_str = String::from_utf8_lossy(header_bytes);
        if let Some(first_crlf) = header_str.find("\r\n") {
            let first_line = &header_str[..first_crlf];
            let version = first_line.split_whitespace().nth(2).unwrap_or("HTTP/1.1");
            let mut out = format!("{method} {path} {version}\r\n");
            for line in header_str[first_crlf + 2..].split("\r\n") {
                if line.to_ascii_lowercase().starts_with("proxy-connection:") {
                    continue;
                }
                out.push_str(line);
                out.push_str("\r\n");
            }
            // Trim extra trailing \r\n added by split
            if out.ends_with("\r\n\r\n\r\n") {
                out.truncate(out.len() - 2);
            }
            return out.into_bytes();
        }
    }
    header_bytes.to_vec()
}
