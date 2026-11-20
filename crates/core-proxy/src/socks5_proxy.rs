use crate::upstream::connect_outbound;
use chrono::Utc;
use core_engine::{FilterDecision, FilterEngine, ProxyConfig};
use core_stats::{StatsStore, TrafficEvent, TrafficProtocol};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, info};

pub struct Socks5ProxyServer {
    config: Arc<RwLock<ProxyConfig>>,
    engine: Arc<FilterEngine>,
    stats: Arc<StatsStore>,
}

impl Socks5ProxyServer {
    pub fn new(
        config: Arc<RwLock<ProxyConfig>>,
        engine: Arc<FilterEngine>,
        stats: Arc<StatsStore>,
    ) -> Self {
        Self {
            config,
            engine,
            stats,
        }
    }

    pub async fn bind(&self, listen_addr: &str) -> anyhow::Result<TcpListener> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!(addr = %listener.local_addr()?, "Aegis SOCKS5 proxy listening");
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
                        info!("SOCKS5 proxy shutting down");
                        break;
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let srv = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = srv.handle_client(stream, peer).await {
                                    debug!(error = %e, %peer, "SOCKS5 connection ended");
                                }
                            });
                        }
                        Err(e) => {
                            debug!(error = %e, "SOCKS5 accept error");
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

        // 1. SOCKS5 Greeting: [VER, NMETHODS, METHODS...]
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Ok(());
        }
        let mut methods = vec![0u8; head[1] as usize];
        client.read_exact(&mut methods).await?;

        if !methods.contains(&0x00) {
            client.write_all(&[0x05, 0xFF]).await?;
            return Ok(());
        }
        client.write_all(&[0x05, 0x00]).await?;

        // 2. Request: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
        let mut req_hdr = [0u8; 4];
        client.read_exact(&mut req_hdr).await?;
        if req_hdr[0] != 0x05 || req_hdr[1] != 0x01 {
            // Only CONNECT (0x01) is supported
            client
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }

        let target_host = match req_hdr[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip).await?;
                Ipv4Addr::from(ip).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                client.read_exact(&mut domain).await?;
                String::from_utf8_lossy(&domain).to_string()
            }
            0x04 => {
                let mut ip = [0u8; 16];
                client.read_exact(&mut ip).await?;
                Ipv6Addr::from(ip).to_string()
            }
            _ => {
                client
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Ok(());
            }
        };

        let mut port_bytes = [0u8; 2];
        client.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);

        // 3. Check FilterEngine
        let decision = self.engine.check_domain(&target_host);
        let latency_ms = started.elapsed().as_millis() as u64;

        if matches!(decision, FilterDecision::Block { .. }) {
            self.stats.record(TrafficEvent {
                timestamp: Utc::now(),
                protocol: TrafficProtocol::Socks5,
                domain: target_host,
                client: peer.ip().to_string(),
                decision,
                latency_ms,
            });
            // 0x02 = Connection not allowed by ruleset
            let _ = client
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }

        // 4. Connect outbound (Direct or Chained Upstream Proxy)
        let cfg = self.config.read().unwrap().clone();
        let mut outbound = match connect_outbound(&cfg, &target_host, target_port).await {
            Ok(s) => s,
            Err(_) => {
                // 0x04 = Host unreachable
                let _ = client
                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Ok(());
            }
        };

        self.stats.record(TrafficEvent {
            timestamp: Utc::now(),
            protocol: TrafficProtocol::Socks5,
            domain: target_host,
            client: peer.ip().to_string(),
            decision: FilterDecision::Allow,
            latency_ms,
        });

        // Reply 0x00 = Succeeded
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let _ = tokio::io::copy_bidirectional(&mut client, &mut outbound).await;
        Ok(())
    }
}
