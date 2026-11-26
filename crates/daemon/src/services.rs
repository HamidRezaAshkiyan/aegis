use core_dns::DnsServer;
use core_engine::{
    apply_lan_bind, AegisConfig, AntiDpiConfig, DnsConfig, FilterEngine, ProxyConfig,
};
use core_proxy::{HttpProxyServer, Socks5ProxyServer};
use core_stats::StatsStore;
use serde::Serialize;
use std::sync::{Arc, RwLock};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub enabled: bool,
    pub running: bool,
    pub listen_addr: String,
    pub bound_addr: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServicesSnapshot {
    pub dns: ServiceStatus,
    pub doh: ServiceStatus,
    pub http_proxy: ServiceStatus,
    pub socks5_proxy: ServiceStatus,
}

struct ManagedService {
    enabled: bool,
    running: bool,
    listen_addr: String,
    bound_addr: Option<String>,
    error: Option<String>,
    shutdown_tx: Option<watch::Sender<bool>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Default for ManagedService {
    fn default() -> Self {
        Self {
            enabled: false,
            running: false,
            listen_addr: String::new(),
            bound_addr: None,
            error: None,
            shutdown_tx: None,
            handle: None,
        }
    }
}

impl ManagedService {
    fn to_status(&self) -> ServiceStatus {
        ServiceStatus {
            enabled: self.enabled,
            running: self.running,
            listen_addr: self.listen_addr.clone(),
            bound_addr: self.bound_addr.clone(),
            error: self.error.clone(),
        }
    }

    async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        }
        self.running = false;
        self.bound_addr = None;
    }
}

pub struct ServiceManager {
    pub dns_config: Arc<RwLock<DnsConfig>>,
    pub proxy_config: Arc<RwLock<ProxyConfig>>,
    pub anti_dpi_config: Arc<RwLock<AntiDpiConfig>>,
    pub dns_server: Arc<DnsServer>,
    engine: Arc<FilterEngine>,
    stats: Arc<StatsStore>,
    dns: Mutex<ManagedService>,
    http: Mutex<ManagedService>,
    socks5: Mutex<ManagedService>,
}

impl ServiceManager {
    pub fn new(
        initial_cfg: &AegisConfig,
        engine: Arc<FilterEngine>,
        stats: Arc<StatsStore>,
    ) -> Self {
        let dns_config = Arc::new(RwLock::new(initial_cfg.dns.clone()));
        let proxy_config = Arc::new(RwLock::new(initial_cfg.proxy.clone()));
        let anti_dpi_config = Arc::new(RwLock::new(initial_cfg.anti_dpi.clone()));
        let dns_server = Arc::new(DnsServer::new(
            Arc::clone(&dns_config),
            Arc::clone(&proxy_config),
            Arc::clone(&engine),
            Arc::clone(&stats),
        ));

        Self {
            dns_config,
            proxy_config,
            anti_dpi_config,
            dns_server,
            engine,
            stats,
            dns: Mutex::new(ManagedService::default()),
            http: Mutex::new(ManagedService::default()),
            socks5: Mutex::new(ManagedService::default()),
        }
    }

    /// Hot-apply configuration changes: updates live shared configs and starts/stops/rebinds
    /// only the listeners whose enabled state or bind address changed.
    pub async fn apply_config(&self, cfg: &AegisConfig) {
        if let Ok(mut d) = self.dns_config.write() {
            *d = cfg.dns.clone();
        }
        if let Ok(mut p) = self.proxy_config.write() {
            *p = cfg.proxy.clone();
        }
        if let Ok(mut dpi) = self.anti_dpi_config.write() {
            *dpi = cfg.anti_dpi.clone();
        }

        let dns_bind = apply_lan_bind(&cfg.dns.listen_addr, cfg.lan_mode);
        let http_bind = apply_lan_bind(&cfg.proxy.http_listen, cfg.lan_mode);
        let socks5_bind = apply_lan_bind(&cfg.proxy.socks5_listen, cfg.lan_mode);

        self.reconcile_dns(cfg.dns.enabled, &dns_bind).await;
        self.reconcile_http(cfg.proxy.http_enabled, &http_bind)
            .await;
        self.reconcile_socks5(cfg.proxy.socks5_enabled, &socks5_bind)
            .await;
    }

    async fn reconcile_dns(&self, enabled: bool, bind_addr: &str) {
        let mut slot = self.dns.lock().await;
        let unchanged =
            slot.enabled == enabled && slot.listen_addr == bind_addr && (!enabled || slot.running);
        if unchanged {
            return;
        }

        slot.stop().await;
        slot.enabled = enabled;
        slot.listen_addr = bind_addr.to_string();
        slot.error = None;

        if !enabled {
            info!("UDP DNS listener disabled");
            return;
        }

        match self.dns_server.bind(bind_addr).await {
            Ok(sock) => {
                let bound = sock.local_addr().ok().map(|a| a.to_string());
                let (tx, rx) = watch::channel(false);
                let srv = Arc::clone(&self.dns_server);
                let handle = tokio::spawn(async move {
                    if let Err(e) = srv.serve(sock, rx).await {
                        warn!(error = %e, "DNS server stopped with error");
                    }
                });
                slot.running = true;
                slot.bound_addr = bound;
                slot.shutdown_tx = Some(tx);
                slot.handle = Some(handle);
            }
            Err(e) => {
                warn!(addr = %bind_addr, error = %e, "Could not bind UDP DNS server");
                slot.running = false;
                slot.error = Some(e.to_string());
            }
        }
    }

    async fn reconcile_http(&self, enabled: bool, bind_addr: &str) {
        let mut slot = self.http.lock().await;
        let unchanged =
            slot.enabled == enabled && slot.listen_addr == bind_addr && (!enabled || slot.running);
        if unchanged {
            return;
        }

        slot.stop().await;
        slot.enabled = enabled;
        slot.listen_addr = bind_addr.to_string();
        slot.error = None;

        if !enabled {
            info!("HTTP/HTTPS proxy listener disabled");
            return;
        }

        let http_srv = Arc::new(HttpProxyServer::new(
            Arc::clone(&self.proxy_config),
            Arc::clone(&self.anti_dpi_config),
            Arc::clone(&self.engine),
            Arc::clone(&self.stats),
        ));

        match http_srv.bind(bind_addr).await {
            Ok(listener) => {
                let bound = listener.local_addr().ok().map(|a| a.to_string());
                let (tx, rx) = watch::channel(false);
                let handle = tokio::spawn(async move {
                    let _ = http_srv.serve(listener, rx).await;
                });
                slot.running = true;
                slot.bound_addr = bound;
                slot.shutdown_tx = Some(tx);
                slot.handle = Some(handle);
            }
            Err(e) => {
                warn!(addr = %bind_addr, error = %e, "Could not bind HTTP proxy");
                slot.running = false;
                slot.error = Some(e.to_string());
            }
        }
    }

    async fn reconcile_socks5(&self, enabled: bool, bind_addr: &str) {
        let mut slot = self.socks5.lock().await;
        let unchanged =
            slot.enabled == enabled && slot.listen_addr == bind_addr && (!enabled || slot.running);
        if unchanged {
            return;
        }

        slot.stop().await;
        slot.enabled = enabled;
        slot.listen_addr = bind_addr.to_string();
        slot.error = None;

        if !enabled {
            info!("SOCKS5 proxy listener disabled");
            return;
        }

        let socks_srv = Arc::new(Socks5ProxyServer::new(
            Arc::clone(&self.proxy_config),
            Arc::clone(&self.anti_dpi_config),
            Arc::clone(&self.engine),
            Arc::clone(&self.stats),
        ));

        match socks_srv.bind(bind_addr).await {
            Ok(listener) => {
                let bound = listener.local_addr().ok().map(|a| a.to_string());
                let (tx, rx) = watch::channel(false);
                let handle = tokio::spawn(async move {
                    let _ = socks_srv.serve(listener, rx).await;
                });
                slot.running = true;
                slot.bound_addr = bound;
                slot.shutdown_tx = Some(tx);
                slot.handle = Some(handle);
            }
            Err(e) => {
                warn!(addr = %bind_addr, error = %e, "Could not bind SOCKS5 proxy");
                slot.running = false;
                slot.error = Some(e.to_string());
            }
        }
    }

    pub async fn status_snapshot(&self, cfg: &AegisConfig) -> ServicesSnapshot {
        let dns = self.dns.lock().await.to_status();
        let http_proxy = self.http.lock().await.to_status();
        let socks5_proxy = self.socks5.lock().await.to_status();
        let api_bind = apply_lan_bind(&cfg.api.listen_addr, cfg.lan_mode);
        let doh = ServiceStatus {
            enabled: cfg.dns.doh_server_enabled,
            running: cfg.dns.doh_server_enabled,
            listen_addr: format!("http://{api_bind}/dns-query"),
            bound_addr: if cfg.dns.doh_server_enabled {
                Some(format!("http://{api_bind}/dns-query"))
            } else {
                None
            },
            error: None,
        };
        ServicesSnapshot {
            dns,
            doh,
            http_proxy,
            socks5_proxy,
        }
    }

    pub async fn own_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for lock in [&self.dns, &self.http, &self.socks5] {
            let slot = lock.lock().await;
            if let Some(addr) = slot.bound_addr.as_deref() {
                if let Some((_, p)) = addr.rsplit_once(':') {
                    if let Ok(port) = p.parse::<u16>() {
                        ports.push(port);
                    }
                }
            }
        }
        ports
    }

    pub async fn stop_all(&self) {
        self.dns.lock().await.stop().await;
        self.http.lock().await.stop().await;
        self.socks5.lock().await.stop().await;
    }
}
