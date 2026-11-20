use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path as AxumPath, Query, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use core_engine::{
    download_list, AegisConfig, BlockCategory, FilterEngine, FilterListConfig,
    ListDownloadOutcome, ProxyConfig, UpstreamMode,
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
        .route("/api/export", get(export_config))
        .route("/api/import", post(import_config))
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
    system_dns_enabled: bool,
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
        system_dns_enabled: cfg.system_dns_enabled,
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
        etag: None,
        last_modified: None,
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

#[derive(Debug, Clone, Serialize)]
pub struct RefreshSummary {
    pub updated_lists: usize,
    pub not_modified_lists: usize,
    pub active_rules: usize,
    pub errors: Vec<String>,
}

/// Refresh all enabled blocklists using conditional HTTP requests (ETag / If-Modified-Since).
/// Reloads the filter engine if any list changed and persists config metadata.
pub async fn refresh_enabled_lists(state: &AppState) -> RefreshSummary {
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
    let mut not_modified = 0usize;
    let mut errors = Vec::new();

    for list in lists {
        match download_list(&state.http_client, &list, &state.data_dir).await {
            Ok(ListDownloadOutcome::Updated {
                parsed,
                etag,
                last_modified,
            }) => {
                updated += 1;
                let mut cfg = state.config.write().unwrap();
                if let Some(entry) = cfg.lists.iter_mut().find(|l| l.id == list.id) {
                    entry.rule_count = parsed.blocked.len();
                    entry.last_updated = Some(Utc::now().to_rfc3339());
                    entry.etag = etag;
                    entry.last_modified = last_modified;
                }
            }
            Ok(ListDownloadOutcome::NotModified) => {
                not_modified += 1;
                let mut cfg = state.config.write().unwrap();
                if let Some(entry) = cfg.lists.iter_mut().find(|l| l.id == list.id) {
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
    let total_rules = if updated > 0 {
        let cfg = state.config.read().unwrap().clone();
        state.engine.reload_from_config(&cfg, &state.data_dir)
    } else {
        state.engine.total_rules()
    };
    info!(
        updated,
        not_modified,
        total_rules,
        "Blocklist refresh complete"
    );

    RefreshSummary {
        updated_lists: updated,
        not_modified_lists: not_modified,
        active_rules: total_rules,
        errors,
    }
}

async fn update_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let summary = refresh_enabled_lists(&state).await;
    Json(summary)
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
    #[serde(default)]
    system_dns_enabled: bool,
    #[serde(default = "default_true")]
    auto_update_enabled: bool,
    #[serde(default = "default_interval_hours")]
    auto_update_interval_hours: u64,
}

fn default_true() -> bool {
    true
}

fn default_interval_hours() -> u64 {
    24
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<SettingsPayload> {
    let cfg = state.config.read().unwrap();
    Json(SettingsPayload {
        upstream_mode: cfg.proxy.upstream_mode.clone(),
        upstream_addr: cfg.proxy.upstream_addr.clone(),
        upstream_username: cfg.proxy.upstream_username.clone(),
        upstream_password: cfg.proxy.upstream_password.clone(),
        system_proxy_enabled: cfg.system_proxy_enabled,
        system_dns_enabled: cfg.system_dns_enabled,
        auto_update_enabled: cfg.auto_update_enabled,
        auto_update_interval_hours: cfg.auto_update_interval_hours,
    })
}

async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SettingsPayload>,
) -> impl IntoResponse {
    let interval_hours = req.auto_update_interval_hours.clamp(1, 168);
    let (http_listen, socks_listen, dns_listen, prev_sys_proxy, prev_sys_dns) = {
        let mut cfg = state.config.write().unwrap();
        let prev_proxy = cfg.system_proxy_enabled;
        let prev_dns = cfg.system_dns_enabled;
        cfg.proxy.upstream_mode = req.upstream_mode.clone();
        cfg.proxy.upstream_addr = req.upstream_addr.clone();
        cfg.proxy.upstream_username = req.upstream_username.clone();
        cfg.proxy.upstream_password = req.upstream_password.clone();
        cfg.system_proxy_enabled = req.system_proxy_enabled;
        cfg.system_dns_enabled = req.system_dns_enabled;
        cfg.auto_update_enabled = req.auto_update_enabled;
        cfg.auto_update_interval_hours = interval_hours;
        (
            cfg.proxy.http_listen.clone(),
            cfg.proxy.socks5_listen.clone(),
            cfg.dns.listen_addr.clone(),
            prev_proxy,
            prev_dns,
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

    // Toggle OS system DNS if changed
    if req.system_dns_enabled != prev_sys_dns {
        let res = if req.system_dns_enabled {
            core_os::enable_system_dns(&state.data_dir, &dns_listen)
        } else {
            core_os::disable_system_dns(&state.data_dir)
        };
        if let Err(e) = res {
            warn!(error = %e, "Failed to update OS system DNS");
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

#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default = "default_export_format")]
    format: String,
}

fn default_export_format() -> String {
    "toml".to_string()
}

async fn export_config(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ExportQuery>,
) -> impl IntoResponse {
    let cfg = state.config.read().unwrap().clone();
    let format = query.format.to_ascii_lowercase();
    let (body, content_type, filename) = if format == "json" {
        match serde_json::to_string_pretty(&cfg) {
            Ok(s) => (s, "application/json; charset=utf-8", "aegis-config.json"),
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
    } else {
        match toml::to_string_pretty(&cfg) {
            Ok(s) => (s, "application/toml; charset=utf-8", "aegis-config.toml"),
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }
    (StatusCode::OK, headers, body).into_response()
}

#[derive(Deserialize)]
struct ImportRequest {
    #[serde(default = "default_export_format")]
    format: String,
    #[serde(default = "default_import_mode")]
    mode: String,
    content: String,
}

fn default_import_mode() -> String {
    "merge".to_string()
}

pub fn apply_imported_config(
    current: &mut AegisConfig,
    imported: AegisConfig,
    replace: bool,
) {
    if replace {
        *current = imported;
    } else {
        for d in imported.allowlist {
            let norm = d.trim().to_ascii_lowercase();
            if !norm.is_empty() && !current.allowlist.contains(&norm) {
                current.denylist.retain(|x| x != &norm);
                current.allowlist.push(norm);
            }
        }
        for d in imported.denylist {
            let norm = d.trim().to_ascii_lowercase();
            if !norm.is_empty() && !current.denylist.contains(&norm) {
                current.allowlist.retain(|x| x != &norm);
                current.denylist.push(norm);
            }
        }
        for list in imported.lists {
            let exists = current
                .lists
                .iter()
                .any(|l| l.id == list.id || l.url == list.url);
            if !exists {
                current.lists.push(list);
            }
        }
    }
}

async fn import_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportRequest>,
) -> impl IntoResponse {
    let format = req.format.to_ascii_lowercase();
    let parsed: Result<AegisConfig, String> = if format == "json" {
        serde_json::from_str(&req.content).map_err(|e| format!("Invalid JSON config: {e}"))
    } else if format == "toml" {
        toml::from_str(&req.content).map_err(|e| format!("Invalid TOML config: {e}"))
    } else {
        // Auto-detect: try JSON first, then TOML
        serde_json::from_str(&req.content)
            .or_else(|_| toml::from_str(&req.content))
            .map_err(|e| format!("Could not parse config as JSON or TOML: {e}"))
    };

    let imported = match parsed {
        Ok(c) => c,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response();
        }
    };

    let replace = req.mode.eq_ignore_ascii_case("replace");
    let (allow_count, deny_count, lists_count, proxy_snapshot) = {
        let mut cfg = state.config.write().unwrap();
        apply_imported_config(&mut cfg, imported, replace);
        (
            cfg.allowlist.len(),
            cfg.denylist.len(),
            cfg.lists.len(),
            cfg.proxy.clone(),
        )
    };

    if replace {
        if let Ok(mut pcfg) = state.proxy_config.write() {
            *pcfg = proxy_snapshot;
        }
    }

    state.save_config();
    let cfg = state.config.read().unwrap().clone();
    let active_rules = state.engine.reload_from_config(&cfg, &state.data_dir);
    info!(replace, active_rules, allow_count, deny_count, lists_count, "Imported configuration");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active_rules": active_rules,
            "allowlist_count": allow_count,
            "denylist_count": deny_count,
            "lists_count": lists_count
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_merge_deduplicates_rules_and_lists() {
        let mut current = AegisConfig::default();
        current.allowlist.push("keep.example.com".to_string());
        current.denylist.push("bad.example.com".to_string());

        let mut imported = AegisConfig::default();
        imported.allowlist.push("keep.example.com".to_string());
        imported.allowlist.push("new-allow.example.com".to_string());
        imported.denylist.push("new-deny.example.com".to_string());
        imported.lists.push(FilterListConfig {
            id: "custom-extra".to_string(),
            name: "Extra".to_string(),
            url: "https://example.invalid/extra.txt".to_string(),
            category: BlockCategory::Malware,
            enabled: true,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        });

        let orig_lists = current.lists.len();
        apply_imported_config(&mut current, imported, false);

        assert_eq!(current.allowlist.len(), 2);
        assert_eq!(current.denylist.len(), 2);
        assert_eq!(current.lists.len(), orig_lists + 1);
    }

    #[test]
    fn import_replace_overwrites_full_config() {
        let mut current = AegisConfig::default();
        current.allowlist.push("old.example.com".to_string());

        let mut imported = AegisConfig::default();
        imported.allowlist.push("fresh.example.com".to_string());
        imported.proxy.upstream_mode = UpstreamMode::Socks5;
        imported.proxy.upstream_addr = "127.0.0.1:7890".to_string();

        // Round-trip via TOML
        let toml_str = toml::to_string_pretty(&imported).unwrap();
        let parsed: AegisConfig = toml::from_str(&toml_str).unwrap();
        apply_imported_config(&mut current, parsed, true);

        assert_eq!(current.allowlist, vec!["fresh.example.com".to_string()]);
        assert_eq!(current.proxy.upstream_mode, UpstreamMode::Socks5);
        assert_eq!(current.proxy.upstream_addr, "127.0.0.1:7890");
    }
}
