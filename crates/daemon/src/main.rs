mod api;

use api::{build_router, AppState};
use clap::Parser;
use core_dns::DnsServer;
use core_engine::{download_list, AegisConfig, FilterEngine};
use core_proxy::{HttpProxyServer, Socks5ProxyServer};
use core_stats::StatsStore;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "aegis", about = "Lightweight open-source system-wide ad & tracker blocker")]
struct Cli {
    /// Custom data directory for config, blocklists, and SQLite stats
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Override local DNS listen address (e.g. 127.0.0.1:5353 or 127.0.0.1:53)
    #[arg(long)]
    dns_addr: Option<String>,

    /// Override HTTP/HTTPS proxy listen address (e.g. 127.0.0.1:8080)
    #[arg(long)]
    http_addr: Option<String>,

    /// Override SOCKS5 proxy listen address (e.g. 127.0.0.1:1080)
    #[arg(long)]
    socks5_addr: Option<String>,

    /// Override Web Dashboard & Control API listen address (e.g. 127.0.0.1:4242)
    #[arg(long)]
    api_addr: Option<String>,

    /// Download/update all enabled blocklists on startup
    #[arg(long, default_value_t = false)]
    update_lists: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(AegisConfig::default_data_dir);
    std::fs::create_dir_all(&data_dir)?;

    // Crash-recovery: restore OS proxy settings if a previous run terminated unexpectedly
    core_os::recover_if_dirty(&data_dir);

    let config_path = data_dir.join("config.toml");
    let mut config = AegisConfig::load_or_create(&config_path)?;

    if let Some(addr) = cli.dns_addr {
        config.dns.listen_addr = addr;
    }
    if let Some(addr) = cli.http_addr {
        config.proxy.http_listen = addr;
    }
    if let Some(addr) = cli.socks5_addr {
        config.proxy.socks5_listen = addr;
    }
    if let Some(addr) = cli.api_addr {
        config.api.listen_addr = addr;
    }

    let stats = Arc::new(StatsStore::open(&data_dir.join("stats.db"))?);
    let engine = Arc::new(FilterEngine::new());
    let http_client = reqwest::Client::builder()
        .user_agent(format!("AegisBlocker/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    if cli.update_lists {
        info!("Updating enabled blocklists on startup...");
        for list in config.lists.iter_mut().filter(|l| l.enabled) {
            match download_list(&http_client, list, &data_dir).await {
                Ok(parsed) => {
                    list.rule_count = parsed.blocked.len();
                    list.last_updated = Some(chrono::Utc::now().to_rfc3339());
                }
                Err(e) => warn!(list = %list.name, error = %e, "Failed to update list"),
            }
        }
        let _ = config.save(&config_path);
    }

    let active_rules = engine.reload_from_config(&config, &data_dir);
    info!(active_rules, data_dir = %data_dir.display(), "Filter engine initialized");

    let proxy_config = Arc::new(RwLock::new(config.proxy.clone()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Start Local DNS Server
    if config.dns.enabled {
        let dns_srv = Arc::new(DnsServer::new(
            config.dns.clone(),
            Arc::clone(&engine),
            Arc::clone(&stats),
        ));
        match dns_srv.bind().await {
            Ok(sock) => {
                let rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    if let Err(e) = dns_srv.serve(sock, rx).await {
                        warn!(error = %e, "DNS server stopped with error");
                    }
                });
            }
            Err(e) => {
                warn!(addr = %config.dns.listen_addr, error = %e, "Could not bind DNS server (continuing without DNS)");
            }
        }
    }

    // 2. Start HTTP/HTTPS Proxy
    if config.proxy.http_enabled {
        let http_srv = Arc::new(HttpProxyServer::new(
            Arc::clone(&proxy_config),
            Arc::clone(&engine),
            Arc::clone(&stats),
        ));
        match http_srv.bind(&config.proxy.http_listen).await {
            Ok(listener) => {
                let rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    let _ = http_srv.serve(listener, rx).await;
                });
            }
            Err(e) => {
                warn!(addr = %config.proxy.http_listen, error = %e, "Could not bind HTTP proxy");
            }
        }
    }

    // 3. Start SOCKS5 Proxy
    if config.proxy.socks5_enabled {
        let socks_srv = Arc::new(Socks5ProxyServer::new(
            Arc::clone(&proxy_config),
            Arc::clone(&engine),
            Arc::clone(&stats),
        ));
        match socks_srv.bind(&config.proxy.socks5_listen).await {
            Ok(listener) => {
                let rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    let _ = socks_srv.serve(listener, rx).await;
                });
            }
            Err(e) => {
                warn!(addr = %config.proxy.socks5_listen, error = %e, "Could not bind SOCKS5 proxy");
            }
        }
    }

    // 4. Enable OS System Proxy if configured
    if config.system_proxy_enabled {
        if let Err(e) = core_os::enable_system_proxy(
            &data_dir,
            &config.proxy.http_listen,
            &config.proxy.socks5_listen,
        ) {
            warn!(error = %e, "Failed to enable system proxy on startup");
        }
    }

    // 5. Start Control API & Embedded Web Dashboard
    let api_addr = config.api.listen_addr.clone();
    let app_state = Arc::new(AppState {
        config: RwLock::new(config),
        config_path,
        data_dir: data_dir.clone(),
        proxy_config,
        engine,
        stats,
        http_client,
    });
    let app = build_router(app_state);
    let api_listener = TcpListener::bind(&api_addr).await?;
    info!("Aegis Dashboard & API available at http://{api_addr}");

    let shutdown_signal = async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("Shutdown signal received");
        let _ = shutdown_tx.send(true);
    };

    axum::serve(api_listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Always cleanly restore OS proxy settings on exit
    let _ = core_os::disable_system_proxy(&data_dir);
    info!("Aegis stopped cleanly");
    Ok(())
}
