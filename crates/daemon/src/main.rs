mod api;

use api::{build_router, refresh_enabled_lists, AppState};
use clap::{Parser, Subcommand};
use core_dns::DnsServer;
use core_engine::{download_list, AegisConfig, FilterEngine, ListDownloadOutcome};
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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage Aegis background service / launch at login
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Install and start Aegis as a background service (launch at login)
    Install,
    /// Stop and remove the Aegis background service
    Uninstall,
    /// Show whether the Aegis background service is installed and running
    Status,
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

    if let Some(Commands::Service { action }) = &cli.command {
        match action {
            ServiceAction::Install => {
                let exe = std::env::current_exe()?;
                let msg = core_os::service::install_service(&exe, cli.data_dir.as_deref())?;
                println!("{msg}");
            }
            ServiceAction::Uninstall => {
                let msg = core_os::service::uninstall_service()?;
                println!("{msg}");
            }
            ServiceAction::Status => {
                let st = core_os::service::service_status()?;
                println!("Platform:  {}", st.platform);
                println!("Installed: {}", if st.installed { "yes" } else { "no" });
                println!("Running:   {}", if st.running { "yes" } else { "no" });
                println!("Details:   {}", st.details);
            }
        }
        return Ok(());
    }

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
                Ok(ListDownloadOutcome::Updated {
                    parsed,
                    etag,
                    last_modified,
                }) => {
                    list.rule_count = parsed.blocked.len();
                    list.last_updated = Some(chrono::Utc::now().to_rfc3339());
                    list.etag = etag;
                    list.last_modified = last_modified;
                }
                Ok(ListDownloadOutcome::NotModified) => {
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

    // 4. Enable OS System Proxy & System DNS if configured
    if config.system_proxy_enabled {
        if let Err(e) = core_os::enable_system_proxy(
            &data_dir,
            &config.proxy.http_listen,
            &config.proxy.socks5_listen,
        ) {
            warn!(error = %e, "Failed to enable system proxy on startup");
        }
    }
    if config.system_dns_enabled {
        if let Err(e) = core_os::enable_system_dns(&data_dir, &config.dns.listen_addr) {
            warn!(error = %e, "Failed to enable system DNS on startup");
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

    // 4b. Background scheduled blocklist auto-updater
    {
        let updater_state = Arc::clone(&app_state);
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            // Skip immediate tick so startup stays snappy; first check happens after 60s
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let should_refresh = {
                            let cfg = updater_state.config.read().unwrap();
                            if !cfg.auto_update_enabled {
                                false
                            } else {
                                let interval_secs = (cfg.auto_update_interval_hours.max(1) as i64) * 3600;
                                let now = chrono::Utc::now();
                                cfg.lists.iter().filter(|l| l.enabled).any(|l| {
                                    match l.last_updated.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
                                        Some(ts) => (now - ts.with_timezone(&chrono::Utc)).num_seconds() >= interval_secs,
                                        None => true,
                                    }
                                })
                            }
                        };
                        if should_refresh {
                            info!("Scheduled blocklist auto-update triggered");
                            let _ = refresh_enabled_lists(&updater_state).await;
                        }
                    }
                }
            }
        });
    }

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

    // Always cleanly restore OS proxy & DNS settings on exit
    let _ = core_os::disable_system_proxy(&data_dir);
    let _ = core_os::disable_system_dns(&data_dir);
    info!("Aegis stopped cleanly");
    Ok(())
}
