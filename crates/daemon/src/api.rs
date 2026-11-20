use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path as AxumPath, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use core_engine::{
    download_list, AegisConfig, BlockCategory, FilterEngine, FilterListConfig, ProxyConfig,
    UpstreamMode,
};
use core_stats::StatsStore;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

const DASHBOARD_HTML: &str = include_str!("../ui/index.html");

pub struct AppState {
    pub config: RwLock<AegisConfig>,
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub proxy_config: Arc<RwLock<ProxyConfig>>,
    pub engine: Arc<FilterEngine>,
    pub stats: Arc<StatsStore>,
    pub http_client: reqwest::Client,
}

impl AppState {
    fn save_config(&self) {
        if let Ok(cfg) = self.config.read() {
            if let Err(e) = cfg.save(&self.config_path) {
                warn!(error = %e, "Failed to persist config.toml");
            }
        }
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/api/status", get(get_status))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/reset", post(reset_stats))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/ws", get(ws_logs))
        .route("/api/pause", post(set_pause))
        .route("/api/lists", get(get_lists).post(add_list))
        .route("/api/lists/update", post(update_lists))
        .route("/api/lists/:id", patch(toggle_list).delete(delete_list))
        .route("/api/rules", get(get_rules).delete(delete_rule))
        .route("/api/rules/allow", post(add_allow_rule))
        .route("/api/rules/deny", post(add_deny_rule))
        .route("/api/settings", get(get_settings).put(update_settings))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn index_html() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    active_rules: usize,
    paused_until: Option<String>,
    dns_listen: String,
    dns_upstream: String,
    http_proxy_listen: String,
    socks5_proxy_listen: String,
    upstream_mode: UpstreamMode,
    upstream_addr: String,
    system_proxy_enabled: bool,
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let cfg = state.config.read().unwrap().clone();
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        active_rules: state.engine.total_rules(),
        paused_until: state.engine.paused_until().map(|t| t.to_rfc3339()),
        dns_listen: cfg.dns.listen_addr,
        dns_upstream: cfg.dns.upstream,
        http_proxy_listen: cfg.proxy.http_listen,
        socks5_proxy_listen: cfg.proxy.socks5_listen,
        upstream_mode: cfg.proxy.upstream_mode,
        upstream_addr: cfg.proxy.upstream_addr,
        system_proxy_enabled: cfg.system_proxy_enabled,
    })
}

async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.stats.summary())
}

async fn reset_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.stats.reset_stats() {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_logs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.stats.recent_logs(200))
}

async fn ws_logs(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.stats.subscribe();
    loop {
        tokio::select! {
            Ok(ev) = rx.recv() => {
                if let Ok(json) = serde_json::to_string(&ev) {
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            msg = socket.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct PauseRequest {
    seconds: i64,
}

async fn set_pause(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PauseRequest>,
) -> impl IntoResponse {
    if req.seconds <= 0 {
        state.engine.resume();
    } else {
        state.engine.pause_for_seconds(req.seconds);
    }
    Json(serde_json::json!({
        "paused_until": state.engine.paused_until().map(|t| t.to_rfc3339())
    }))
}

async fn get_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let lists = state.config.read().unwrap().lists.clone();
    Json(lists)
}

#[derive(Deserialize)]
struct AddListRequest {
    name: String,
    url: String,
    category: BlockCategory,
}

async fn add_list(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddListRequest>,
) -> impl IntoResponse {
    let id = format!(
        "custom-{}",
        Utc::now().timestamp_millis()
    );
    let new_list = FilterListConfig {
        id,
        name: req.name,
        url: req.url,
        category: req.category,
        enabled: true,
        rule_count: 0,
        last_updated: None,
    };
    {
        let mut cfg = state.config.write().unwrap();
        cfg.lists.push(new_list.clone());
    }
    state.save_config();
    (StatusCode::CREATED, Json(new_list))
}

#[derive(Deserialize)]
struct ToggleListRequest {
    enabled: bool,
}

async fn toggle_list(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<ToggleListRequest>,
) -> impl IntoResponse {
    let found = {
        let mut cfg = state.config.write().unwrap();
        if let Some(list) = cfg.lists.iter_mut().find(|l| l.id == id) {
            list.enabled = req.enabled;
            true
        } else {
            false
        }
    };
    if !found {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.save_config();
    let cfg = state.config.read().unwrap().clone();
    let total = state.engine.reload_from_config(&cfg, &state.data_dir);
    Json(serde_json::json!({ "active_rules": total })).into_response()
}

async fn delete_list(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().unwrap();
        cfg.lists.retain(|l| l.id != id);
    }
    state.save_config();
    let cfg = state.config.read().unwrap().clone();
    let total = state.engine.reload_from_config(&cfg, &state.data_dir);
    Json(serde_json::json!({ "active_rules": total }))
}

async fn update_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let lists: Vec<FilterListConfig> = state
        .config
        .read()
        .unwrap()
        .lists
        .iter()
        .filter(|l| l.enabled)
        .cloned()
        .collect();

    let mut updated = 0usize;
    let mut errors = Vec::new();

    for list in lists {
        match download_list(&state.http_client, &list, &state.data_dir).await {
            Ok(parsed) => {
                updated += 1;
                let mut cfg = state.config.write().unwrap();
                if let Some(entry) = cfg.lists.iter_mut().find(|l| l.id == list.id) {
                    entry.rule_count = parsed.blocked.len();
                    entry.last_updated = Some(Utc::now().to_rfc3339());
                }
            }
            Err(e) => {
                warn!(list = %list.name, error = %e, "List download failed");
                errors.push(format!("{}: {}", list.name, e));
            }
        }
    }

    state.save_config();
    let cfg = state.config.read().unwrap().clone();
    let total_rules = state.engine.reload_from_config(&cfg, &state.data_dir);
    info!(updated, total_rules, "Blocklist refresh complete");

    Json(serde_json::json!({
        "updated_lists": updated,
        "active_rules": total_rules,
        "errors": errors
    }))
}

#[derive(Serialize)]
struct RulesResponse {
    allowlist: Vec<String>,
    denylist: Vec<String>,
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Json<RulesResponse> {
    let cfg = state.config.read().unwrap();
    Json(RulesResponse {
        allowlist: cfg.allowlist.clone(),
        denylist: cfg.denylist.clone(),
    })
}

#[derive(Deserialize)]
struct DomainRuleRequest {
    domain: String,
}

async fn add_allow_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DomainRuleRequest>,
) -> impl IntoResponse {
    let domain = req.domain.trim().to_ascii_lowercase();
    {
        let mut cfg = state.config.write().unwrap();
        cfg.denylist.retain(|d| d != &domain);
        if !cfg.allowlist.contains(&domain) {
            cfg.allowlist.push(domain.clone());
        }
    }
    state.engine.add_user_allow(&domain);
    state.save_config();
    StatusCode::NO_CONTENT
}

async fn add_deny_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DomainRuleRequest>,
) -> impl IntoResponse {
    let domain = req.domain.trim().to_ascii_lowercase();
    {
        let mut cfg = state.config.write().unwrap();
        cfg.allowlist.retain(|d| d != &domain);
        if !cfg.denylist.contains(&domain) {
            cfg.denylist.push(domain.clone());
        }
    }
    state.engine.add_user_deny(&domain);
    state.save_config();
    StatusCode::NO_CONTENT
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DomainRuleRequest>,
) -> impl IntoResponse {
    let domain = req.domain.trim().to_ascii_lowercase();
    {
        let mut cfg = state.config.write().unwrap();
        cfg.allowlist.retain(|d| d != &domain);
        cfg.denylist.retain(|d| d != &domain);
    }
    state.save_config();
    let cfg = state.config.read().unwrap().clone();
    state.engine.reload_from_config(&cfg, &state.data_dir);
    StatusCode::NO_CONTENT
}

#[derive(Serialize, Deserialize)]
struct SettingsPayload {
    upstream_mode: UpstreamMode,
    upstream_addr: String,
    upstream_username: Option<String>,
    upstream_password: Option<String>,
    system_proxy_enabled: bool,
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<SettingsPayload> {
    let cfg = state.config.read().unwrap();
    Json(SettingsPayload {
        upstream_mode: cfg.proxy.upstream_mode.clone(),
        upstream_addr: cfg.proxy.upstream_addr.clone(),
        upstream_username: cfg.proxy.upstream_username.clone(),
        upstream_password: cfg.proxy.upstream_password.clone(),
        system_proxy_enabled: cfg.system_proxy_enabled,
    })
}

async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SettingsPayload>,
) -> impl IntoResponse {
    let (http_listen, socks_listen, prev_sys_proxy) = {
        let mut cfg = state.config.write().unwrap();
        let prev = cfg.system_proxy_enabled;
        cfg.proxy.upstream_mode = req.upstream_mode.clone();
        cfg.proxy.upstream_addr = req.upstream_addr.clone();
        cfg.proxy.upstream_username = req.upstream_username.clone();
        cfg.proxy.upstream_password = req.upstream_password.clone();
        cfg.system_proxy_enabled = req.system_proxy_enabled;
        (
            cfg.proxy.http_listen.clone(),
            cfg.proxy.socks5_listen.clone(),
            prev,
        )
    };

    // Hot-update live proxy config
    if let Ok(mut pcfg) = state.proxy_config.write() {
        pcfg.upstream_mode = req.upstream_mode;
        pcfg.upstream_addr = req.upstream_addr;
        pcfg.upstream_username = req.upstream_username;
        pcfg.upstream_password = req.upstream_password;
    }

    // Toggle OS system proxy if changed
    if req.system_proxy_enabled != prev_sys_proxy {
        let res = if req.system_proxy_enabled {
            core_os::enable_system_proxy(&state.data_dir, &http_listen, &socks_listen)
        } else {
            core_os::disable_system_proxy(&state.data_dir)
        };
        if let Err(e) = res {
            warn!(error = %e, "Failed to update OS system proxy");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    state.save_config();
    StatusCode::NO_CONTENT.into_response()
}
