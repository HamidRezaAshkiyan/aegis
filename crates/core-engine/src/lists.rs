use crate::config::{BlockCategory, FilterListConfig};
use anyhow::Context;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ParsedRules {
    pub blocked: Vec<String>,
    pub allowed: Vec<String>,
}

/// Normalize a domain string: lowercase, strip trailing dot, trim whitespace.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    if s == "localhost"
        || s == "localhost.localdomain"
        || s == "broadcasthost"
        || s == "local"
        || s == "0.0.0.0"
        || s == "127.0.0.1"
    {
        return None;
    }
    // Must contain at least one dot and only valid hostname chars
    if !s.contains('.') {
        return None;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }
    Some(s)
}

/// Check whether an Adblock `$options` string is safe for whole-domain DNS/proxy blocking.
/// Rules with browser-only or scoped modifiers (`$third-party`, `$domain=...`, `$script`,
/// `$ping`, `$image`, `$xmlhttprequest`, `$badfilter`, etc.) must NOT be converted into
/// global domain blocks because they cause severe false positives.
fn is_dns_safe_adblock_options(opts: &str) -> bool {
    let trimmed = opts.trim();
    if trimmed.is_empty() {
        return true;
    }
    for part in trimmed.split(',') {
        let opt = part.trim().to_ascii_lowercase();
        if opt.is_empty() {
            continue;
        }
        // Only allow pure DNS-compatible global modifiers
        if matches!(opt.as_str(), "important" | "all") {
            continue;
        }
        return false;
    }
    true
}

/// Extract a pure whole-domain target from an Adblock `||...` rule body.
/// Rejects path-scoped rules (`/ads.js`), wildcard rules (`*`), and rules with
/// non-DNS `$options` so browser filter lists never over-block legitimate domains.
fn extract_dns_safe_adblock_domain(rest: &str) -> Option<String> {
    let (pattern, opts) = match rest.split_once('$') {
        Some((p, o)) => (p, Some(o)),
        None => (rest, None),
    };

    if let Some(o) = opts {
        if !is_dns_safe_adblock_options(o) {
            return None;
        }
    }

    // Reject wildcards or URL paths that are not pure domain rules
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('|') {
        return None;
    }

    let cleaned = pattern.trim_end_matches('^');
    if cleaned.contains('/') || cleaned.contains('^') {
        return None;
    }

    normalize_domain(cleaned)
}

/// Parse a filter list supporting Adblock/AdGuard (`||domain^`, `@@||domain^`),
/// Hosts (`0.0.0.0 domain`), and plain domain list formats.
pub fn parse_filter_list(content: &str) -> ParsedRules {
    let mut blocked = Vec::new();
    let mut allowed = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }
        // Skip cosmetic/element-hiding rules
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") {
            continue;
        }

        // Adblock exception rule: @@||domain.com^
        if let Some(rest) = line.strip_prefix("@@||") {
            if let Some(domain) = extract_dns_safe_adblock_domain(rest) {
                allowed.push(domain);
            }
            continue;
        }

        // Adblock domain rule: ||domain.com^
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(domain) = extract_dns_safe_adblock_domain(rest) {
                blocked.push(domain);
            }
            continue;
        }

        // Strip inline comments
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }

        // Hosts format: 0.0.0.0 domain.com [domain2.com ...]
        let mut parts = line.split_whitespace();
        if let Some(first) = parts.next() {
            if first == "0.0.0.0" || first == "127.0.0.1" || first == "::" || first == "::1" {
                for host in parts {
                    if let Some(domain) = normalize_domain(host) {
                        blocked.push(domain);
                    }
                }
                continue;
            }
            // Plain domain list (single token on line)
            if parts.next().is_none() {
                if let Some(domain) = normalize_domain(first) {
                    blocked.push(domain);
                }
            }
        }
    }

    ParsedRules { blocked, allowed }
}

/// Built-in offline baseline rules so Aegis immediately protects against
/// top ad networks, trackers, Windows telemetry, and macOS telemetry even offline.
/// Kept conservative to avoid false positives on legitimate apps.
pub fn builtin_baseline_rules() -> Vec<(BlockCategory, &'static str, &'static str)> {
    vec![
        // Ads
        (BlockCategory::Ad, "doubleclick.net", "Built-in Baseline"),
        (BlockCategory::Ad, "googlesyndication.com", "Built-in Baseline"),
        (BlockCategory::Ad, "googleadservices.com", "Built-in Baseline"),
        (BlockCategory::Ad, "adservice.google.com", "Built-in Baseline"),
        (BlockCategory::Ad, "ads.youtube.com", "Built-in Baseline"),
        (BlockCategory::Ad, "adnxs.com", "Built-in Baseline"),
        (BlockCategory::Ad, "taboola.com", "Built-in Baseline"),
        (BlockCategory::Ad, "outbrain.com", "Built-in Baseline"),
        (BlockCategory::Ad, "criteo.com", "Built-in Baseline"),
        (BlockCategory::Ad, "pubmatic.com", "Built-in Baseline"),
        (BlockCategory::Ad, "rubiconproject.com", "Built-in Baseline"),
        (BlockCategory::Ad, "ads-twitter.com", "Built-in Baseline"),
        // Trackers
        (BlockCategory::Tracker, "google-analytics.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "analytics.google.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "hotjar.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "mixpanel.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "segment.io", "Built-in Baseline"),
        (BlockCategory::Tracker, "amplitude.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "scorecardresearch.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "pixel.facebook.com", "Built-in Baseline"),
        (BlockCategory::Tracker, "clarity.ms", "Built-in Baseline"),
        // Windows Telemetry
        (BlockCategory::WindowsTelemetry, "vortex.data.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "telemetry.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "settings-win.data.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "watson.telemetry.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "umwatsonc.events.data.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "self.events.data.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "mobile.events.data.microsoft.com", "Built-in Windows Telemetry"),
        (BlockCategory::WindowsTelemetry, "diagnostics.support.microsoft.com", "Built-in Windows Telemetry"),
        // macOS / Apple Telemetry
        (BlockCategory::MacOSTelemetry, "metrics.icloud.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "metrics.apple.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "xp.apple.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "iadsdk.apple.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "securemetrics.apple.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "supportmetrics.apple.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "stocks-analytics-events.apple.com", "Built-in Apple Telemetry"),
        (BlockCategory::MacOSTelemetry, "weather-analytics-events.apple.com", "Built-in Apple Telemetry"),
    ]
}

pub fn list_cache_path(data_dir: &Path, list_id: &str) -> PathBuf {
    let safe_id: String = list_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    data_dir.join("lists").join(format!("{safe_id}.txt"))
}

#[derive(Debug, Clone)]
pub enum ListDownloadOutcome {
    Updated {
        parsed: ParsedRules,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    NotModified,
}

/// Download a filter list from its URL and cache it on disk.
/// Sends `If-None-Match` / `If-Modified-Since` conditional headers when a cached copy
/// and previous validation headers are present, returning `NotModified` on HTTP 304.
pub async fn download_list(
    client: &reqwest::Client,
    list: &FilterListConfig,
    data_dir: &Path,
) -> anyhow::Result<ListDownloadOutcome> {
    let path = list_cache_path(data_dir, &list.id);
    let has_cache = path.exists();

    info!(list = %list.name, url = %list.url, "Checking filter list for updates");
    let mut req = client
        .get(&list.url)
        .timeout(std::time::Duration::from_secs(30));

    if has_cache {
        if let Some(etag) = list.etag.as_deref().filter(|s| !s.is_empty()) {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(lm) = list.last_modified.as_deref().filter(|s| !s.is_empty()) {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm);
        }
    }

    let resp = req
        .send()
        .await
        .with_context(|| format!("Failed to fetch {}", list.url))?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        info!(list = %list.name, "Filter list not modified (HTTP 304)");
        return Ok(ListDownloadOutcome::NotModified);
    }

    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} fetching {}", resp.status(), list.url);
    }

    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let last_modified = resp
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp.text().await?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, &body).await?;

    let parsed = parse_filter_list(&body);
    info!(
        list = %list.name,
        blocked = parsed.blocked.len(),
        allowed = parsed.allowed.len(),
        "Filter list updated"
    );
    Ok(ListDownloadOutcome::Updated {
        parsed,
        etag,
        last_modified,
    })
}

/// Load a cached filter list from disk if available.
pub fn load_cached_list(list: &FilterListConfig, data_dir: &Path) -> Option<ParsedRules> {
    let path = list_cache_path(data_dir, &list.id);
    match std::fs::read_to_string(&path) {
        Ok(content) => Some(parse_filter_list(&content)),
        Err(_) => {
            warn!(list = %list.name, "No cached copy found on disk yet");
            None
        }
    }
}
