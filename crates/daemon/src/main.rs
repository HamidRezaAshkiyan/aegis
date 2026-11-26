mod api;
mod services;
mod tray;

use api::{build_router, refresh_enabled_lists, AppState};
use clap::{Parser, Subcommand};
use core_engine::{download_list, AegisConfig, FilterEngine, ListDownloadOutcome};
use core_stats::StatsStore;
use services::ServiceManager;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "aegis",
    version,
    about = "Lightweight open-source system-wide ad & tracker blocker with DoH, Anti-DPI, and VPN chaining"
)]
struct Cli {
    /// Custom data directory for config, blocklists, and SQLite stats
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Override local DNS listen address (e.g. 127.0.0.1:5353 or 127.0.0.1:53)
    #[arg(long)]
    dns_addr: Option<String>,

    /// Disable the local UDP DNS listener on startup
    #[arg(long, default_value_t = false)]
    no_dns: bool,

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

    /// Listen on all LAN interfaces (0.0.0.0) for Pi-hole style whole-network protection
    #[arg(long, default_value_t = false)]
    lan: bool,

    /// Enable dashboard & API authentication with the specified password/token
    #[arg(long)]
    auth_token: Option<String>,

    /// Run headless without a native system tray / menu bar icon
    #[arg(long, default_value_t = false)]
    no_tray: bool,

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

fn main() -> anyhow::Result<()> {
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

    // Crash-recovery: restore OS proxy & DNS settings if a previous run terminated unexpectedly
    core_os::recover_if_dirty(&data_dir);

    let config_path = data_dir.join("config.toml");
    let mut config = AegisConfig::load_or_create(&config_path)?;

    if cli.no_dns {
        config.dns.enabled = false;
    }
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
    if cli.lan {
        config.lan_mode = true;
    }
    if let Some(token) = cli.auth_token {
        if !token.trim().is_empty() {
            config.api.auth_enabled = true;
            config.api.auth_token = Some(token.trim().to_string());
        }
    }

    let api_bind = core_engine::apply_lan_bind(&config.api.listen_addr, config.lan_mode);
    let dashboard_url = format!(
        "http://{}",
        if api_bind.starts_with("0.0.0.0:") {
            api_bind.replacen("0.0.0.0:", "127.0.0.1:", 1)
        } else {
            api_bind.clone()
        }
    );

    let stats = Arc::new(StatsStore::open(&data_dir.join("stats.db"))?);
    let engine = Arc::new(FilterEngine::new());
    let http_client = reqwest::Client::builder()
        .user_agent(format!("AegisBlocker/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let services = Arc::new(ServiceManager::new(
        &config,
        Arc::clone(&engine),
        Arc::clone(&stats),
    ));

    let app_state = Arc::new(AppState {
        config: RwLock::new(config),
        config_path,
        data_dir: data_dir.clone(),
        services,
        engine,
        stats,
        http_client,
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let update_lists = cli.update_lists;
    let use_tray = !cli.no_tray && cfg!(any(target_os = "macos", target_os = "windows"));

    if use_tray {
        let daemon_state = Arc::clone(&app_state);
        let daemon_tx = shutdown_tx.clone();
        let daemon_rx = shutdown_rx.clone();
        let handle = std::thread::Builder::new()
            .name("aegis-daemon".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                if let Err(e) = rt.block_on(run_daemon(
                    daemon_state,
                    update_lists,
                    api_bind,
                    daemon_tx,
                    daemon_rx,
                )) {
                    warn!(error = %e, "Aegis daemon exited with error");
                }
            })?;

        let tray_res = tray::run_tray_loop(tray::TrayContext {
            state: Arc::clone(&app_state),
            dashboard_url,
            shutdown_tx: shutdown_tx.clone(),
            shutdown_rx,
        });
        let _ = shutdown_tx.send(true);
        let _ = handle.join();
        tray_res
    } else {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(run_daemon(
            app_state,
            update_lists,
            api_bind,
            shutdown_tx,
            shutdown_rx,
        ))
    }
}

async fn run_daemon(
    app_state: Arc<AppState>,
    update_lists: bool,
    api_bind: String,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let data_dir = app_state.data_dir.clone();

    if update_lists {
        info!("Updating enabled blocklists on startup...");
        let lists = app_state
            .config
            .read()
            .unwrap()
            .lists
            .iter()
            .filter(|l| l.enabled)
            .cloned()
            .collect::<Vec<_>>();
        for list in lists {
            match download_list(&app_state.http_client, &list, &data_dir).await {
                Ok(ListDownloadOutcome::Updated {
                    parsed,
                    etag,
                    last_modified,
                }) => {
                    let mut cfg = app_state.config.write().unwrap();
                    if let Some(entry) = cfg.lists.iter_mut().find(|l| l.id == list.id) {
                        entry.rule_count = parsed.blocked.len();
                        entry.last_updated = Some(chrono::Utc::now().to_rfc3339());
                        entry.etag = etag;
                        entry.last_modified = last_modified;
                    }
                }
                Ok(ListDownloadOutcome::NotModified) => {
                    let mut cfg = app_state.config.write().unwrap();
                    if let Some(entry) = cfg.lists.iter_mut().find(|l| l.id == list.id) {
                        entry.last_updated = Some(chrono::Utc::now().to_rfc3339());
                    }
                }
                Err(e) => warn!(list = %list.name, error = %e, "Failed to update list"),
            }
        }
        app_state.save_config();
    }

    let config_snapshot = app_state.config.read().unwrap().clone();
    let active_rules = app_state
        .engine
        .reload_from_config(&config_snapshot, &data_dir);
    info!(active_rules, data_dir = %data_dir.display(), "Filter engine initialized");

    // 1. Start configured listeners (UDP DNS, HTTP/HTTPS Proxy, SOCKS5 Proxy) via ServiceManager
    app_state.services.apply_config(&config_snapshot).await;

    // 2. Enable OS System Proxy & System DNS if configured
    if config_snapshot.system_proxy_enabled {
        if let Err(e) = core_os::enable_system_proxy(
            &data_dir,
            &config_snapshot.proxy.http_listen,
            &config_snapshot.proxy.socks5_listen,
        ) {
            warn!(error = %e, "Failed to enable system proxy on startup");
        }
    }
    if config_snapshot.system_dns_enabled {
        if let Err(e) = core_os::enable_system_dns(&data_dir, &config_snapshot.dns.listen_addr) {
            warn!(error = %e, "Failed to enable system DNS on startup");
        }
    }

    // 3. Background scheduled blocklist auto-updater + hourly SQLite log pruner
    {
        let updater_state = Arc::clone(&app_state);
        let mut rx = shutdown_rx.clone();
        {
            let (days, max_rows) = {
                let cfg = updater_state.config.read().unwrap();
                (cfg.log_retention_days, cfg.log_max_rows)
            };
            if let Ok(deleted) = updater_state.stats.prune_logs(days, max_rows) {
                if deleted > 0 {
                    info!(deleted, "Pruned old query_log rows on startup");
                }
            }
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut minutes_elapsed: u64 = 0;
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        minutes_elapsed = minutes_elapsed.wrapping_add(1);
                        if minutes_elapsed % 60 == 0 {
                            let (days, max_rows) = {
                                let cfg = updater_state.config.read().unwrap();
                                (cfg.log_retention_days, cfg.log_max_rows)
                            };
                            match updater_state.stats.prune_logs(days, max_rows) {
                                Ok(deleted) if deleted > 0 => {
                                    info!(deleted, "Scheduled prune removed old query_log rows");
                                }
                                Err(e) => warn!(error = %e, "Scheduled query_log prune failed"),
                                _ => {}
                            }
                        }

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

    // 4. Start Control API, Local DoH (`/dns-query`), PAC (`/proxy.pac`) & Embedded Web Dashboard
    let app = build_router(Arc::clone(&app_state));
    let api_listener = TcpListener::bind(&api_bind).await?;
    info!("Aegis v{} Dashboard & API available at http://{api_bind}", env!("CARGO_PKG_VERSION"));

    let mut api_shutdown_rx = shutdown_rx.clone();
    let shutdown_signal = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received");
                let _ = shutdown_tx.send(true);
            }
            _ = async {
                while !*api_shutdown_rx.borrow() {
                    if api_shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            } => {
                info!("Shutdown signal received");
            }
        }
    };

    axum::serve(api_listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Cleanly stop managed listeners and restore OS proxy & DNS settings on exit
    app_state.services.stop_all().await;
    let _ = core_os::disable_system_proxy(&data_dir);
    let _ = core_os::disable_system_dns(&data_dir);
    info!("Aegis stopped cleanly");
    Ok(())
}
