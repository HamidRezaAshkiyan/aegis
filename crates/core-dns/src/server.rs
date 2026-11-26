use chrono::Utc;
use core_engine::{DnsConfig, FilterDecision, FilterEngine, ProxyConfig, UpstreamMode};
use core_stats::{StatsStore, TrafficEvent, TrafficProtocol};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

pub struct DnsServer {
    config: Arc<RwLock<DnsConfig>>,
    proxy_config: Arc<RwLock<ProxyConfig>>,
    engine: Arc<FilterEngine>,
    stats: Arc<StatsStore>,
    direct_http_client: reqwest::Client,
}

impl DnsServer {
    pub fn new(
        config: Arc<RwLock<DnsConfig>>,
        proxy_config: Arc<RwLock<ProxyConfig>>,
        engine: Arc<FilterEngine>,
        stats: Arc<StatsStore>,
    ) -> Self {
        let direct_http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            config,
            proxy_config,
            engine,
            stats,
            direct_http_client,
        }
    }

    /// Bind the UDP socket on the specified address.
    pub async fn bind(&self, listen_addr: &str) -> anyhow::Result<UdpSocket> {
        let socket = UdpSocket::bind(listen_addr).await?;
        let upstream = self.config.read().unwrap().upstream.clone();
        info!(addr = %socket.local_addr()?, upstream = %upstream, "Aegis DNS server listening");
        Ok(socket)
    }

    pub async fn serve(
        self: Arc<Self>,
        socket: UdpSocket,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; 4096];

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("DNS server shutting down");
                        break;
                    }
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, peer)) => {
                            let packet = buf[..len].to_vec();
                            let srv = Arc::clone(&self);
                            let sock = Arc::clone(&socket);
                            tokio::spawn(async move {
                                if let Some(resp_bytes) = srv
                                    .handle_dns_wire(&packet, peer.ip().to_string(), TrafficProtocol::Dns)
                                    .await
                                {
                                    if let Err(e) = sock.send_to(&resp_bytes, peer).await {
                                        debug!(error = %e, %peer, "Failed to send DNS response");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "DNS recv_from error");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Process a raw DNS wire-format query packet (shared by UDP DNS and RFC 8484 DoH `/dns-query`).
    pub async fn handle_dns_wire(
        &self,
        packet: &[u8],
        client_ip: String,
        protocol: TrafficProtocol,
    ) -> Option<Vec<u8>> {
        let started = Instant::now();
        let request = match Message::from_vec(packet) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Invalid DNS packet");
                return None;
            }
        };

        let query = request.queries().first()?.clone();
        let domain = query.name().to_utf8().trim_end_matches('.').to_string();

        // 1. Check domain against filter engine
        let decision = self.engine.check_domain(&domain);
        if matches!(decision, FilterDecision::Block { .. }) {
            let latency_ms = started.elapsed().as_millis() as u64;
            self.stats.record(TrafficEvent {
                timestamp: Utc::now(),
                protocol,
                domain,
                client: client_ip,
                decision,
                latency_ms,
            });
            return build_blocked_response(&request).to_vec().ok();
        }

        let dns_cfg = self.config.read().unwrap().clone();

        // 2. Forward allowed query to upstream (DoH or UDP)
        let upstream_bytes = match self.forward_upstream(packet, &dns_cfg).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = %e, %domain, upstream = %dns_cfg.upstream, "Upstream DNS lookup failed");
                let mut servfail = Message::new();
                servfail
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_desired(request.recursion_desired())
                    .set_recursion_available(true)
                    .set_response_code(ResponseCode::ServFail)
                    .add_query(query);
                return servfail.to_vec().ok();
            }
        };

        // 3. Optional CNAME Uncloaking check on upstream response
        if dns_cfg.cname_uncloaking {
            if let Ok(upstream_msg) = Message::from_vec(&upstream_bytes) {
                for answer in upstream_msg.answers() {
                    if let Some(RData::CNAME(cname)) = answer.data() {
                        let target = cname.0.to_utf8().trim_end_matches('.').to_string();
                        let cname_decision = self.engine.check_domain(&target);
                        if matches!(cname_decision, FilterDecision::Block { .. }) {
                            let latency_ms = started.elapsed().as_millis() as u64;
                            debug!(%domain, cname = %target, "Blocked via CNAME uncloaking");
                            self.stats.record(TrafficEvent {
                                timestamp: Utc::now(),
                                protocol,
                                domain,
                                client: client_ip,
                                decision: cname_decision,
                                latency_ms,
                            });
                            return build_blocked_response(&request).to_vec().ok();
                        }
                    }
                }
            }
        }

        let latency_ms = started.elapsed().as_millis() as u64;
        self.stats.record(TrafficEvent {
            timestamp: Utc::now(),
            protocol,
            domain,
            client: client_ip,
            decision: FilterDecision::Allow,
            latency_ms,
        });

        Some(upstream_bytes)
    }

    fn build_doh_client(&self, dns_cfg: &DnsConfig) -> anyhow::Result<reqwest::Client> {
        if !dns_cfg.use_upstream_proxy {
            return Ok(self.direct_http_client.clone());
        }
        let pcfg = self.proxy_config.read().unwrap().clone();
        if pcfg.upstream_mode == UpstreamMode::Direct || pcfg.upstream_addr.trim().is_empty() {
            return Ok(self.direct_http_client.clone());
        }

        let scheme = match pcfg.upstream_mode {
            UpstreamMode::Socks5 => "socks5h",
            UpstreamMode::Http => "http",
            UpstreamMode::Direct => return Ok(self.direct_http_client.clone()),
        };

        let proxy_url = format!("{scheme}://{}", pcfg.upstream_addr.trim());
        let mut proxy = reqwest::Proxy::all(&proxy_url)?;
        if let (Some(u), Some(p)) = (
            pcfg.upstream_username.as_deref().filter(|s| !s.is_empty()),
            pcfg.upstream_password.as_deref(),
        ) {
            proxy = proxy.basic_auth(u, p);
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .proxy(proxy)
            .build()?;
        Ok(client)
    }

    async fn forward_upstream(&self, packet: &[u8], dns_cfg: &DnsConfig) -> anyhow::Result<Vec<u8>> {
        if dns_cfg.upstream.starts_with("https://") {
            let client = self.build_doh_client(dns_cfg)?;
            let resp = client
                .post(&dns_cfg.upstream)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(packet.to_vec())
                .send()
                .await?;
            if !resp.status().is_success() {
                anyhow::bail!("DoH upstream returned HTTP {}", resp.status());
            }
            Ok(resp.bytes().await?.to_vec())
        } else {
            let upstream_sock = UdpSocket::bind("0.0.0.0:0").await?;
            upstream_sock.connect(&dns_cfg.upstream).await?;
            upstream_sock.send(packet).await?;
            let mut resp = vec![0u8; 4096];
            let len = tokio::time::timeout(Duration::from_secs(4), upstream_sock.recv(&mut resp))
                .await??;
            resp.truncate(len);
            Ok(resp)
        }
    }
}

pub fn build_blocked_response(request: &Message) -> Message {
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true);

    if let Some(query) = request.queries().first() {
        response.add_query(query.clone());
        match query.query_type() {
            RecordType::A => {
                response.set_response_code(ResponseCode::NoError);
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A(Ipv4Addr::UNSPECIFIED)),
                ));
            }
            RecordType::AAAA => {
                response.set_response_code(ResponseCode::NoError);
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                ));
            }
            _ => {
                response.set_response_code(ResponseCode::NXDomain);
            }
        }
    } else {
        response.set_response_code(ResponseCode::NXDomain);
    }

    response
}
