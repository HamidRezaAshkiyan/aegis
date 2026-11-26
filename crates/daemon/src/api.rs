use crate::services::{ServiceManager, ServicesSnapshot};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path as AxumPath, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post, put},
    Json, Router,
};
use base64::Engine as _;
use chrono::Utc;
use core_engine::{
    download_list, AegisConfig, AntiDpiConfig, BlockCategory, FilterEngine, FilterListConfig,
    ListDownloadOutcome, ProtectionProfile, ProxyConfig, UpstreamMode,
};
use core_proxy::{scan_local_proxies, test_upstream};
use core_stats::{StatsStore, TrafficProtocol};
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
    pub services: Arc<ServiceManager>,
    pub engine: Arc<FilterEngine>,
    pub stats: Arc<StatsStore>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub(crate) fn save_config(&self) {
        if let Ok(cfg) = self.config.read() {
            if let Err(e) = cfg.save(&self.config_path) {
                warn!(error = %e, "Failed to persist config.toml");
            }
        }
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let protected_api = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/timeline", get(get_stats_timeline))
        .route("/api/stats/reset", post(reset_stats))
        .route("/api/stats/prune", post(prune_stats_logs))
        .route("/api/clients", get(get_clients))
        .route("/api/clients/name", put(set_client_name))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/ws", get(ws_logs))
        .route("/api/pause", post(set_pause))
        .route("/api/lists", get(get_lists).post(add_list))
        .route("/api/lists/update", post(update_lists))
        .route("/api/lists/:id", patch(toggle_list).delete(delete_list))
        .route("/api/profiles/:profile", post(apply_profile))
        .route("/api/rules", get(get_rules).delete(delete_rule))
        .route("/api/rules/allow", post(add_allow_rule))
        .route("/api/rules/deny", post(add_deny_rule))
        .route("/api/rules/test", post(test_rule))
        .route("/api/settings", get(get_settings).put(update_settings))
        .route("/api/upstream/scan", get(scan_upstream_proxies))
        .route("/api/upstream/test", post(test_upstream_proxy))
        .route("/api/setup/info", get(get_setup_info))
        .route("/api/setup/script/macos", get(download_macos_script))
        .route("/api/setup/script/windows", get(download_windows_script))
        .route("/api/service/install", post(install_bg_service))
        .route("/api/service/uninstall", post(uninstall_bg_service))
        .route("/api/export", get(export_config))
        .route("/api/import", post(import_config))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ));

    Router::new()
        .route("/", get(index_html))
        .route("/api/auth/status", get(get_auth_status))
        .route("/dns-query", get(doh_get).post(doh_post))
        .route("/proxy.pac", get(serve_proxy_pac))
        .merge(protected_api)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

fn host_os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

fn parse_port(addr: &str, default_port: u16) -> u16 {
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(default_port)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_request_token(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            let trimmed = tok.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    if let Some(tok) = headers
        .get("x-aegis-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(tok.to_string());
    }
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "token" && !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn is_request_authorized(state: &AppState, headers: &HeaderMap, query: Option<&str>) -> bool {
    let cfg = state.config.read().unwrap();
    if !cfg.api.auth_enabled {
        return true;
    }
    let Some(expected) = cfg.api.auth_token.as_deref().filter(|s| !s.is_empty()) else {
        return true;
    };
    match extract_request_token(headers, query) {
        Some(provided) => constant_time_eq(&provided, expected),
        None => false,
    }
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if !is_request_authorized(&state, req.headers(), req.uri().query()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Authentication required" })),
        )
            .into_response();
    }
    next.run(req).await
}

async fn get_auth_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    let auth_enabled = {
        let cfg = state.config.read().unwrap();
        cfg.api.auth_enabled
            && cfg
                .api
                .auth_token
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
    };
    let authenticated = is_request_authorized(&state, &headers, uri.query());
    Json(serde_json::json!({
        "auth_enabled": auth_enabled,
        "authenticated": authenticated
    }))
}

fn detect_lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

fn client_ip_from_headers(headers: &HeaderMap) -> String {
    if let Some(fwd) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return fwd.to_string();
    }
    "doh-client".to_string()
}

async fn index_html() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

// ---------------------------------------------------------------------------
// RFC 8484 Local DNS-over-HTTPS (`/dns-query`)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DohQueryParams {
    dns: String,
}

async fn doh_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<DohQueryParams>,
) -> impl IntoResponse {
    if !state.config.read().unwrap().dns.doh_server_enabled {
        return (StatusCode::SERVICE_UNAVAILABLE, "Local DoH server is disabled").into_response();
    }
    let wire = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(params.dns.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(params.dns.trim()))
    {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url dns parameter").into_response(),
    };
    handle_doh_wire(state, &wire, client_ip_from_headers(&headers)).await
}

async fn doh_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !state.config.read().unwrap().dns.doh_server_enabled {
        return (StatusCode::SERVICE_UNAVAILABLE, "Local DoH server is disabled").into_response();
    }
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty DNS message").into_response();
    }
    handle_doh_wire(state, &body, client_ip_from_headers(&headers)).await
}

async fn handle_doh_wire(state: Arc<AppState>, wire: &[u8], client: String) -> Response {
    match state
        .services
        .dns_server
        .handle_dns_wire(wire, client, TrafficProtocol::Doh)
        .await
    {
        Some(resp) => {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/dns-message"),
            );
            resp_headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=60"),
            );
            (StatusCode::OK, resp_headers, resp).into_response()
        }
        None => (StatusCode::BAD_REQUEST, "Invalid DNS wire message").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Dynamic Proxy Auto-Config (`/proxy.pac`)
// ---------------------------------------------------------------------------

async fn serve_proxy_pac(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cfg = state.config.read().unwrap().clone();
    let host_from_header = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string());

    let proxy_host = match host_from_header {
        Some(h) if !h.is_empty() => h,
        _ => {
            if cfg.lan_mode {
                detect_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string())
            } else {
                "127.0.0.1".to_string()
            }
        }
    };

    let http_port = parse_port(&cfg.proxy.http_listen, 8080);
    let socks_port = parse_port(&cfg.proxy.socks5_listen, 1080);

    let proxy_directive = if cfg.proxy.http_enabled && cfg.proxy.socks5_enabled {
        format!("PROXY {proxy_host}:{http_port}; SOCKS5 {proxy_host}:{socks_port}; DIRECT")
    } else if cfg.proxy.http_enabled {
        format!("PROXY {proxy_host}:{http_port}; DIRECT")
    } else if cfg.proxy.socks5_enabled {
        format!("SOCKS5 {proxy_host}:{socks_port}; DIRECT")
    } else {
        "DIRECT".to_string()
    };

    let pac = format!(
        r#"// Aegis v{ver} Proxy Auto-Config (PAC)
function FindProxyForURL(url, host) {{
  if (
    isPlainHostName(host) ||
    shExpMatch(host, "*.local") ||
    shExpMatch(host, "*.lan") ||
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    isInNet(host, "10.0.0.0", "255.0.0.0") ||
    isInNet(host, "172.16.0.0", "255.240.0.0") ||
    isInNet(host, "192.168.0.0", "255.255.0.0")
  ) {{
    return "DIRECT";
  }}
  return "{proxy_directive}";
}}
"#,
        ver = env!("CARGO_PKG_VERSION"),
    );

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ns-proxy-autoconfig; charset=utf-8"),
    );
    (StatusCode::OK, resp_headers, pac)
}

// ---------------------------------------------------------------------------
// Status & Stats
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    os: &'static str,
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
    lan_mode: bool,
    lan_ip: Option<String>,
    auth_enabled: bool,
    anti_dpi_enabled: bool,
    doh_server_enabled: bool,
    baseline_rules_enabled: bool,
    services: ServicesSnapshot,
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let cfg = state.config.read().unwrap().clone();
    let services = state.services.status_snapshot(&cfg).await;
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        os: host_os_name(),
        active_rules: state.engine.total_rules(),
        paused_until: state.engine.paused_until().map(|t| t.to_rfc3339()),
        dns_listen: core_engine::apply_lan_bind(&cfg.dns.listen_addr, cfg.lan_mode),
        dns_upstream: cfg.dns.upstream,
        http_proxy_listen: core_engine::apply_lan_bind(&cfg.proxy.http_listen, cfg.lan_mode),
        socks5_proxy_listen: core_engine::apply_lan_bind(&cfg.proxy.socks5_listen, cfg.lan_mode),
        upstream_mode: cfg.proxy.upstream_mode,
        upstream_addr: cfg.proxy.upstream_addr,
        system_proxy_enabled: cfg.system_proxy_enabled,
        system_dns_enabled: cfg.system_dns_enabled,
        lan_mode: cfg.lan_mode,
        lan_ip: detect_lan_ip(),
        auth_enabled: cfg.api.auth_enabled,
        anti_dpi_enabled: cfg.anti_dpi.enabled,
        doh_server_enabled: cfg.dns.doh_server_enabled,
        baseline_rules_enabled: cfg.baseline_rules_enabled,
        services,
    })
}

#[derive(Deserialize)]
struct TimelineQuery {
    #[serde(default = "default_timeline_hours")]
    hours: u32,
}

fn default_timeline_hours() -> u32 {
    24
}

async fn get_stats_timeline(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimelineQuery>,
) -> impl IntoResponse {
    Json(state.stats.timeline_hourly(q.hours))
}

#[derive(Serialize)]
struct ClientView {
    client: String,
    name: Option<String>,
    total_requests: u64,
    blocked_requests: u64,
    block_rate_percent: f64,
    last_seen: String,
}

async fn get_clients(State(state): State<Arc<AppState>>) -> Json<Vec<ClientView>> {
    let names = state.config.read().unwrap().client_names.clone();
    let clients = state
        .stats
        .client_stats()
        .into_iter()
        .map(|c| ClientView {
            name: names.get(&c.client).cloned(),
            client: c.client,
            total_requests: c.total_requests,
            blocked_requests: c.blocked_requests,
            block_rate_percent: c.block_rate_percent,
            last_seen: c.last_seen,
        })
        .collect();
    Json(clients)
}

#[derive(Deserialize)]
struct ClientNameRequest {
    client: String,
    name: String,
}

async fn set_client_name(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ClientNameRequest>,
) -> impl IntoResponse {
    let client = req.client.trim().to_string();
    let name = req.name.trim().to_string();
    if client.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    {
        let mut cfg = state.config.write().unwrap();
        if name.is_empty() {
            cfg.client_names.remove(&client);
        } else {
            cfg.client_names.insert(client, name);
        }
    }
    state.save_config();
    StatusCode::NO_CONTENT
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

async fn prune_stats_logs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (days, max_rows) = {
        let cfg = state.config.read().unwrap();
        (cfg.log_retention_days, cfg.log_max_rows)
    };
    match state.stats.prune_logs(days, max_rows) {
        Ok(deleted_rows) => {
            let remaining_rows = state.stats.query_log_count();
            Json(serde_json::json!({
                "deleted_rows": deleted_rows,
                "remaining_rows": remaining_rows
            }))
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_logs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.stats.recent_logs(250))
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

// ---------------------------------------------------------------------------
// Lists, Profiles & Rules
// ---------------------------------------------------------------------------

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
    let id = format!("custom-{}", Utc::now().timestamp_millis());
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

async fn apply_profile(
    State(state): State<Arc<AppState>>,
    AxumPath(profile_name): AxumPath<String>,
) -> impl IntoResponse {
    let profile = match profile_name.to_ascii_lowercase().as_str() {
        "minimal" => ProtectionProfile::Minimal,
        "balanced" => ProtectionProfile::Balanced,
        "strict" => ProtectionProfile::Strict,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Unknown profile. Use minimal, balanced, or strict." })),
            )
                .into_response();
        }
    };

    let cfg_snapshot = {
        let mut cfg = state.config.write().unwrap();
        cfg.apply_profile(profile);
        cfg.clone()
    };
    state.save_config();
    let active_rules = state
        .engine
        .reload_from_config(&cfg_snapshot, &state.data_dir);
    info!(?profile, active_rules, "Applied protection profile");
    Json(serde_json::json!({
        "profile": profile,
        "active_rules": active_rules,
        "lists": cfg_snapshot.lists
    }))
    .into_response()
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshSummary {
    pub updated_lists: usize,
    pub not_modified_lists: usize,
    pub active_rules: usize,
    pub errors: Vec<String>,
}

/// Refresh all enabled blocklists using conditional HTTP requests (ETag / If-Modified-Since).
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

async fn test_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DomainRuleRequest>,
) -> impl IntoResponse {
    let domain = req.domain.trim().to_string();
    let decision = state.engine.check_domain(&domain);
    Json(serde_json::json!({
        "domain": domain,
        "decision": decision
    }))
}

// ---------------------------------------------------------------------------
// Upstream Scanner & Tester
// ---------------------------------------------------------------------------

async fn scan_upstream_proxies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let skip = state.services.own_ports().await;
    let found = scan_local_proxies(&skip).await;
    Json(found)
}

#[derive(Deserialize)]
struct UpstreamTestRequest {
    upstream_mode: Option<UpstreamMode>,
    upstream_addr: Option<String>,
    upstream_username: Option<String>,
    upstream_password: Option<String>,
}

async fn test_upstream_proxy(
    State(state): State<Arc<AppState>>,
    body: Option<Json<UpstreamTestRequest>>,
) -> impl IntoResponse {
    let mut pcfg: ProxyConfig = state.config.read().unwrap().proxy.clone();
    if let Some(Json(req)) = body {
        if let Some(m) = req.upstream_mode {
            pcfg.upstream_mode = m;
        }
        if let Some(a) = req.upstream_addr {
            pcfg.upstream_addr = a;
        }
        if req.upstream_username.is_some() {
            pcfg.upstream_username = req.upstream_username;
        }
        if req.upstream_password.is_some() {
            pcfg.upstream_password = req.upstream_password;
        }
    }
    let result = test_upstream(&pcfg).await;
    Json(result)
}

// ---------------------------------------------------------------------------
// Quick Setup Info, One-Step Scripts (macOS & Windows PS7) & Service Control
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SetupInfoResponse {
    os: &'static str,
    lan_ip: Option<String>,
    lan_mode: bool,
    dns_enabled: bool,
    dns_listen: String,
    dns_port: u16,
    dns_on_53: bool,
    doh_server_enabled: bool,
    http_enabled: bool,
    http_port: u16,
    socks5_enabled: bool,
    socks5_port: u16,
    api_port: u16,
    pac_url: String,
    doh_url: String,
    dashboard_url: String,
    system_proxy_enabled: bool,
    system_dns_enabled: bool,
    service_installed: bool,
    service_running: bool,
    service_details: String,
}

async fn get_setup_info(State(state): State<Arc<AppState>>) -> Json<SetupInfoResponse> {
    let cfg = state.config.read().unwrap().clone();
    let lan_ip = detect_lan_ip();
    let host_ip = lan_ip
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let dns_port = parse_port(&cfg.dns.listen_addr, 5353);
    let http_port = parse_port(&cfg.proxy.http_listen, 8080);
    let socks5_port = parse_port(&cfg.proxy.socks5_listen, 1080);
    let api_port = parse_port(&cfg.api.listen_addr, 4242);

    let svc = core_os::service::service_status().unwrap_or(core_os::service::ServiceStatus {
        platform: host_os_name(),
        installed: false,
        running: false,
        details: "Unavailable".to_string(),
    });

    Json(SetupInfoResponse {
        os: host_os_name(),
        lan_ip,
        lan_mode: cfg.lan_mode,
        dns_enabled: cfg.dns.enabled,
        dns_listen: core_engine::apply_lan_bind(&cfg.dns.listen_addr, cfg.lan_mode),
        dns_port,
        dns_on_53: dns_port == 53,
        doh_server_enabled: cfg.dns.doh_server_enabled,
        http_enabled: cfg.proxy.http_enabled,
        http_port,
        socks5_enabled: cfg.proxy.socks5_enabled,
        socks5_port,
        api_port,
        pac_url: format!("http://{host_ip}:{api_port}/proxy.pac"),
        doh_url: format!("http://{host_ip}:{api_port}/dns-query"),
        dashboard_url: format!("http://{host_ip}:{api_port}"),
        system_proxy_enabled: cfg.system_proxy_enabled,
        system_dns_enabled: cfg.system_dns_enabled,
        service_installed: svc.installed,
        service_running: svc.running,
        service_details: svc.details,
    })
}

async fn download_macos_script(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().unwrap().clone();
    let host = if cfg.lan_mode {
        detect_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string())
    } else {
        "127.0.0.1".to_string()
    };
    let http_port = parse_port(&cfg.proxy.http_listen, 8080);
    let socks_port = parse_port(&cfg.proxy.socks5_listen, 1080);
    let api_port = parse_port(&cfg.api.listen_addr, 4242);

    let script = format!(
        r#"#!/usr/bin/env bash
# Aegis One-Step macOS Network Configurator
# Usage:
#   bash setup-aegis-macos.sh          # Enable Aegis proxy on active Wi-Fi/Ethernet
#   bash setup-aegis-macos.sh --undo   # Restore normal network settings
set -euo pipefail

AEGIS_HOST="{host}"
HTTP_PORT="{http_port}"
SOCKS_PORT="{socks_port}"
PAC_URL="http://{host}:{api_port}/proxy.pac"

SERVICES=$(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*')

if [[ "${{1:-}}" == "--undo" ]]; then
  echo "Restoring macOS proxy settings..."
  while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    networksetup -setwebproxystate "$svc" off 2>/dev/null || true
    networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
    networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
    networksetup -setautoproxystate "$svc" off 2>/dev/null || true
    echo "  Restored: $svc"
  done <<< "$SERVICES"
  echo "Done! Aegis proxy removed."
  exit 0
fi

echo "Configuring macOS to use Aegis at $AEGIS_HOST (HTTP:$HTTP_PORT, SOCKS5:$SOCKS_PORT)..."
while IFS= read -r svc; do
  [[ -z "$svc" ]] && continue
  networksetup -setwebproxy "$svc" "$AEGIS_HOST" "$HTTP_PORT" 2>/dev/null || true
  networksetup -setsecurewebproxy "$svc" "$AEGIS_HOST" "$HTTP_PORT" 2>/dev/null || true
  networksetup -setsocksfirewallproxy "$svc" "$AEGIS_HOST" "$SOCKS_PORT" 2>/dev/null || true
  echo "  Configured: $svc"
done <<< "$SERVICES"

echo ""
echo "Aegis is now active on this Mac! (PAC URL: $PAC_URL)"
echo "To undo at any time, run: bash setup-aegis-macos.sh --undo"
"#
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"setup-aegis-macos.sh\""),
    );
    (StatusCode::OK, headers, script)
}

async fn download_windows_script(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().unwrap().clone();
    let host = if cfg.lan_mode {
        detect_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string())
    } else {
        "127.0.0.1".to_string()
    };
    let http_port = parse_port(&cfg.proxy.http_listen, 8080);
    let api_port = parse_port(&cfg.api.listen_addr, 4242);

    let script = format!(
        r#"#Requires -Version 7.0
<#
.SYNOPSIS
    Aegis One-Step Windows Network Configurator (PowerShell 7).
.EXAMPLE
    pwsh -File .\setup-aegis-windows.ps1
    pwsh -File .\setup-aegis-windows.ps1 -Undo
#>
param(
    [switch]$Undo
)

$ErrorActionPreference = 'Stop'
$RegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$ProxyServer = '{host}:{http_port}'
$PacUrl = 'http://{host}:{api_port}/proxy.pac'

if ($Undo) {{
    Write-Host 'Restoring Windows system proxy settings...' -ForegroundColor Yellow
    Set-ItemProperty -Path $RegPath -Name ProxyEnable -Value 0 -Type DWord
    Remove-ItemProperty -Path $RegPath -Name AutoConfigURL -ErrorAction SilentlyContinue
    Write-Host 'Done! Aegis proxy disabled.' -ForegroundColor Green
    exit 0
}}

Write-Host "Configuring Windows system proxy to Aegis ($ProxyServer)..." -ForegroundColor Cyan
Set-ItemProperty -Path $RegPath -Name ProxyServer -Value $ProxyServer -Type String
Set-ItemProperty -Path $RegPath -Name ProxyOverride -Value 'localhost;127.0.0.1;*.local;10.*;192.168.*;<local>' -Type String
Set-ItemProperty -Path $RegPath -Name ProxyEnable -Value 1 -Type DWord

Write-Host ''
Write-Host "Aegis is now active on Windows! (PAC URL: $PacUrl)" -ForegroundColor Green
Write-Host 'To undo at any time, run: pwsh -File .\setup-aegis-windows.ps1 -Undo' -ForegroundColor DarkGray
"#
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"setup-aegis-windows.ps1\""),
    );
    (StatusCode::OK, headers, script)
}

async fn install_bg_service(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    match core_os::service::install_service(&exe, Some(&state.data_dir)) {
        Ok(msg) => Json(serde_json::json!({ "ok": true, "message": msg })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn uninstall_bg_service() -> impl IntoResponse {
    match core_os::service::uninstall_service() {
        Ok(msg) => Json(serde_json::json!({ "ok": true, "message": msg })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Settings (Live Hot-Reload for Listeners, DoH, Proxy Chaining, Anti-DPI)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SettingsPayload {
    // Listeners & DNS
    #[serde(default = "default_true")]
    dns_enabled: bool,
    #[serde(default = "default_dns_listen")]
    dns_listen: String,
    #[serde(default = "default_dns_upstream")]
    dns_upstream: String,
    #[serde(default = "default_true")]
    cname_uncloaking: bool,
    #[serde(default = "default_true")]
    doh_server_enabled: bool,
    #[serde(default)]
    dns_use_upstream_proxy: bool,
    #[serde(default = "default_true")]
    http_enabled: bool,
    #[serde(default = "default_http_listen")]
    http_listen: String,
    #[serde(default = "default_true")]
    socks5_enabled: bool,
    #[serde(default = "default_socks5_listen")]
    socks5_listen: String,

    // Upstream Proxy / VPN Chaining
    upstream_mode: UpstreamMode,
    upstream_addr: String,
    upstream_username: Option<String>,
    upstream_password: Option<String>,
    #[serde(default)]
    upstream_bypass: Vec<String>,

    // Anti-DPI & Protection
    #[serde(default)]
    anti_dpi: AntiDpiConfig,
    #[serde(default = "default_true")]
    baseline_rules_enabled: bool,

    // OS & System
    system_proxy_enabled: bool,
    #[serde(default)]
    system_dns_enabled: bool,
    #[serde(default = "default_true")]
    auto_update_enabled: bool,
    #[serde(default = "default_interval_hours")]
    auto_update_interval_hours: u64,
    #[serde(default)]
    lan_mode: bool,
    #[serde(default)]
    auth_enabled: bool,
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default = "default_retention_days")]
    log_retention_days: u64,
    #[serde(default = "default_max_rows")]
    log_max_rows: u64,
}

fn default_true() -> bool {
    true
}
fn default_dns_listen() -> String {
    "127.0.0.1:5353".to_string()
}
fn default_dns_upstream() -> String {
    "https://1.1.1.1/dns-query".to_string()
}
fn default_http_listen() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}
fn default_interval_hours() -> u64 {
    24
}
fn default_retention_days() -> u64 {
    7
}
fn default_max_rows() -> u64 {
    50_000
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<SettingsPayload> {
    let cfg = state.config.read().unwrap();
    Json(SettingsPayload {
        dns_enabled: cfg.dns.enabled,
        dns_listen: cfg.dns.listen_addr.clone(),
        dns_upstream: cfg.dns.upstream.clone(),
        cname_uncloaking: cfg.dns.cname_uncloaking,
        doh_server_enabled: cfg.dns.doh_server_enabled,
        dns_use_upstream_proxy: cfg.dns.use_upstream_proxy,
        http_enabled: cfg.proxy.http_enabled,
        http_listen: cfg.proxy.http_listen.clone(),
        socks5_enabled: cfg.proxy.socks5_enabled,
        socks5_listen: cfg.proxy.socks5_listen.clone(),
        upstream_mode: cfg.proxy.upstream_mode.clone(),
        upstream_addr: cfg.proxy.upstream_addr.clone(),
        upstream_username: cfg.proxy.upstream_username.clone(),
        upstream_password: cfg.proxy.upstream_password.clone(),
        upstream_bypass: cfg.proxy.upstream_bypass.clone(),
        anti_dpi: cfg.anti_dpi.clone(),
        baseline_rules_enabled: cfg.baseline_rules_enabled,
        system_proxy_enabled: cfg.system_proxy_enabled,
        system_dns_enabled: cfg.system_dns_enabled,
        auto_update_enabled: cfg.auto_update_enabled,
        auto_update_interval_hours: cfg.auto_update_interval_hours,
        lan_mode: cfg.lan_mode,
        auth_enabled: cfg.api.auth_enabled,
        auth_token: None,
        log_retention_days: cfg.log_retention_days,
        log_max_rows: cfg.log_max_rows,
    })
}

async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SettingsPayload>,
) -> impl IntoResponse {
    let interval_hours = req.auto_update_interval_hours.clamp(1, 168);
    let (
        http_listen,
        socks_listen,
        dns_listen,
        prev_sys_proxy,
        prev_sys_dns,
        prev_baseline,
        cfg_snapshot,
    ) = {
        let mut cfg = state.config.write().unwrap();
        let prev_proxy = cfg.system_proxy_enabled;
        let prev_dns = cfg.system_dns_enabled;
        let prev_base = cfg.baseline_rules_enabled;

        cfg.dns.enabled = req.dns_enabled;
        if !req.dns_listen.trim().is_empty() {
            cfg.dns.listen_addr = req.dns_listen.trim().to_string();
        }
        if !req.dns_upstream.trim().is_empty() {
            cfg.dns.upstream = req.dns_upstream.trim().to_string();
        }
        cfg.dns.cname_uncloaking = req.cname_uncloaking;
        cfg.dns.doh_server_enabled = req.doh_server_enabled;
        cfg.dns.use_upstream_proxy = req.dns_use_upstream_proxy;

        cfg.proxy.http_enabled = req.http_enabled;
        if !req.http_listen.trim().is_empty() {
            cfg.proxy.http_listen = req.http_listen.trim().to_string();
        }
        cfg.proxy.socks5_enabled = req.socks5_enabled;
        if !req.socks5_listen.trim().is_empty() {
            cfg.proxy.socks5_listen = req.socks5_listen.trim().to_string();
        }
        cfg.proxy.upstream_mode = req.upstream_mode.clone();
        cfg.proxy.upstream_addr = req.upstream_addr.trim().to_string();
        cfg.proxy.upstream_username = req
            .upstream_username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        cfg.proxy.upstream_password = req
            .upstream_password
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        cfg.proxy.upstream_bypass = req
            .upstream_bypass
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        cfg.anti_dpi = req.anti_dpi;
        cfg.baseline_rules_enabled = req.baseline_rules_enabled;

        cfg.system_proxy_enabled = req.system_proxy_enabled;
        cfg.system_dns_enabled = req.system_dns_enabled;
        cfg.auto_update_enabled = req.auto_update_enabled;
        cfg.auto_update_interval_hours = interval_hours;
        cfg.lan_mode = req.lan_mode;
        cfg.api.auth_enabled = req.auth_enabled;
        cfg.log_retention_days = req.log_retention_days.min(3650);
        cfg.log_max_rows = req.log_max_rows;
        if let Some(tok) = req
            .auth_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.api.auth_token = Some(tok.to_string());
        }

        (
            cfg.proxy.http_listen.clone(),
            cfg.proxy.socks5_listen.clone(),
            cfg.dns.listen_addr.clone(),
            prev_proxy,
            prev_dns,
            prev_base,
            cfg.clone(),
        )
    };

    // Hot-reload listeners (DNS, HTTP proxy, SOCKS5 proxy), DoH config, Proxy config & Anti-DPI
    state.services.apply_config(&cfg_snapshot).await;

    // Reload FilterEngine if baseline rules toggle changed
    if req.baseline_rules_enabled != prev_baseline {
        state
            .engine
            .reload_from_config(&cfg_snapshot, &state.data_dir);
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
    let services = state.services.status_snapshot(&cfg_snapshot).await;
    (StatusCode::OK, Json(serde_json::json!({ "services": services }))).into_response()
}

// ---------------------------------------------------------------------------
// Export / Import
// ---------------------------------------------------------------------------

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

pub fn apply_imported_config(current: &mut AegisConfig, imported: AegisConfig, replace: bool) {
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
    let (allow_count, deny_count, lists_count, cfg_snapshot) = {
        let mut cfg = state.config.write().unwrap();
        apply_imported_config(&mut cfg, imported, replace);
        (
            cfg.allowlist.len(),
            cfg.denylist.len(),
            cfg.lists.len(),
            cfg.clone(),
        )
    };

    if replace {
        state.services.apply_config(&cfg_snapshot).await;
    }

    state.save_config();
    let active_rules = state
        .engine
        .reload_from_config(&cfg_snapshot, &state.data_dir);
    info!(
        replace,
        active_rules, allow_count, deny_count, lists_count, "Imported configuration"
    );

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

        let toml_str = toml::to_string_pretty(&imported).unwrap();
        let parsed: AegisConfig = toml::from_str(&toml_str).unwrap();
        apply_imported_config(&mut current, parsed, true);

        assert_eq!(current.allowlist, vec!["fresh.example.com".to_string()]);
        assert_eq!(current.proxy.upstream_mode, UpstreamMode::Socks5);
        assert_eq!(current.proxy.upstream_addr, "127.0.0.1:7890");
    }

    #[test]
    fn auth_token_extraction_and_constant_time_check() {
        assert!(constant_time_eq("secret-123", "secret-123"));
        assert!(!constant_time_eq("secret-123", "secret-124"));
        assert!(!constant_time_eq("short", "longer"));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token"),
        );
        assert_eq!(
            extract_request_token(&headers, None).as_deref(),
            Some("my-token")
        );

        let empty = HeaderMap::new();
        assert_eq!(
            extract_request_token(&empty, Some("foo=1&token=ws-tok")).as_deref(),
            Some("ws-tok")
        );
    }

    #[test]
    fn lan_bind_converts_loopback_only_when_enabled() {
        assert_eq!(
            core_engine::apply_lan_bind("127.0.0.1:5353", false),
            "127.0.0.1:5353"
        );
        assert_eq!(
            core_engine::apply_lan_bind("127.0.0.1:5353", true),
            "0.0.0.0:5353"
        );
        assert_eq!(
            core_engine::apply_lan_bind("192.168.1.5:53", true),
            "192.168.1.5:53"
        );
    }

    #[tokio::test]
    async fn service_manager_hot_toggles_and_rebinds_dns() {
        let mut cfg = AegisConfig::default();
        cfg.dns.enabled = true;
        cfg.dns.listen_addr = "127.0.0.1:0".to_string();
        cfg.proxy.http_enabled = false;
        cfg.proxy.socks5_enabled = false;

        let engine = Arc::new(FilterEngine::new());
        let stats = Arc::new(StatsStore::in_memory().unwrap());
        let mgr = ServiceManager::new(&cfg, engine, stats);

        // Start DNS
        mgr.apply_config(&cfg).await;
        let snap1 = mgr.status_snapshot(&cfg).await;
        assert!(snap1.dns.running);
        assert!(snap1.dns.bound_addr.is_some());
        assert!(!snap1.http_proxy.running);

        // Disable DNS live
        cfg.dns.enabled = false;
        mgr.apply_config(&cfg).await;
        let snap2 = mgr.status_snapshot(&cfg).await;
        assert!(!snap2.dns.running);
        assert!(snap2.dns.bound_addr.is_none());

        mgr.stop_all().await;
    }

    #[tokio::test]
    async fn v1_endpoints_pac_doh_scripts_profiles_and_rule_tester() {
        use tokio::net::TcpListener;

        let tmp = std::env::temp_dir().join(format!(
            "aegis-v1-api-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut cfg = AegisConfig::default();
        cfg.dns.enabled = false;
        cfg.proxy.http_enabled = true;
        cfg.proxy.http_listen = "127.0.0.1:8080".to_string();
        cfg.proxy.socks5_enabled = false;

        let stats = Arc::new(StatsStore::in_memory().unwrap());
        let engine = Arc::new(FilterEngine::new());
        let services = Arc::new(ServiceManager::new(&cfg, Arc::clone(&engine), Arc::clone(&stats)));
        let state = Arc::new(AppState {
            config: RwLock::new(cfg),
            config_path: tmp.join("config.toml"),
            data_dir: tmp.clone(),
            services,
            engine,
            stats,
            http_client: reqwest::Client::new(),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(Arc::clone(&state));
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let base = format!("http://{addr}");

        // 1. /proxy.pac
        let pac = client.get(format!("{base}/proxy.pac")).send().await.unwrap();
        assert_eq!(pac.status(), StatusCode::OK);
        let pac_text = pac.text().await.unwrap();
        assert!(pac_text.contains("FindProxyForURL"));
        assert!(pac_text.contains("PROXY "));

        // 2. /api/setup/info + macOS & Windows PS7 scripts
        let setup_info_text = client
            .get(format!("{base}/api/setup/info"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let setup_info: serde_json::Value = serde_json::from_str(&setup_info_text).unwrap();
        assert!(setup_info["pac_url"].as_str().unwrap().ends_with("/proxy.pac"));

        let mac_sh = client
            .get(format!("{base}/api/setup/script/macos"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(mac_sh.contains("networksetup"));
        assert!(mac_sh.contains("--undo"));

        let win_ps1 = client
            .get(format!("{base}/api/setup/script/windows"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(win_ps1.contains("#Requires -Version 7.0"));
        assert!(win_ps1.contains("-Undo"));

        // 3. /api/rules/test
        let test_res_text = client
            .post(format!("{base}/api/rules/test"))
            .header("Content-Type", "application/json")
            .body(r#"{"domain":"ads.doubleclick.net"}"#)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let test_res: serde_json::Value = serde_json::from_str(&test_res_text).unwrap();
        assert_eq!(test_res["decision"]["action"], "block");

        // 4. /api/profiles/minimal
        let prof_res_text = client
            .post(format!("{base}/api/profiles/minimal"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let prof_res: serde_json::Value = serde_json::from_str(&prof_res_text).unwrap();
        assert_eq!(prof_res["profile"], "minimal");

        // 5. /dns-query (POST RFC 8484 DoH for blocked ad domain)
        // Minimal valid DNS A query for "ads.doubleclick.net"
        let dns_query: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            3, b'a', b'd', b's',
            11, b'd', b'o', b'u', b'b', b'l', b'e', b'c', b'l', b'i', b'c', b'k',
            3, b'n', b'e', b't', 0,
            0x00, 0x01, 0x00, 0x01,
        ];
        let doh_resp = client
            .post(format!("{base}/dns-query"))
            .header("Content-Type", "application/dns-message")
            .body(dns_query)
            .send()
            .await
            .unwrap();
        assert_eq!(doh_resp.status(), StatusCode::OK);
        assert_eq!(
            doh_resp.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
        let body_bytes = doh_resp.bytes().await.unwrap();
        assert_eq!(&body_bytes[0..2], &[0x12, 0x34]);

        srv.abort();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
