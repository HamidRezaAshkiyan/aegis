use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BlockCategory {
    Ad,
    Tracker,
    WindowsTelemetry,
    MacOSTelemetry,
    Malware,
    Custom,
}

impl BlockCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockCategory::Ad => "ad",
            BlockCategory::Tracker => "tracker",
            BlockCategory::WindowsTelemetry => "windows_telemetry",
            BlockCategory::MacOSTelemetry => "macos_telemetry",
            BlockCategory::Malware => "malware",
            BlockCategory::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    Direct,
    Socks5,
    Http,
}

impl Default for UpstreamMode {
    fn default() -> Self {
        Self::Direct
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AntiDpiMode {
    /// Splits the TLS ClientHello handshake record into 2+ RFC-compliant TLS records.
    TlsRecordSplit,
    /// Sends the TLS ClientHello in small TCP segments with TCP_NODELAY.
    TcpChunk,
    /// Applies both TLS record splitting and TCP chunking.
    Both,
}

impl Default for AntiDpiMode {
    fn default() -> Self {
        Self::TlsRecordSplit
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionProfile {
    /// Built-in ad baseline only, zero breakage.
    Minimal,
    /// HaGeZi Multi Normal + Threat Intelligence Mini (recommended daily driver).
    Balanced,
    /// HaGeZi Multi PRO + Threat Intelligence + Windows/Apple OS telemetry.
    Strict,
}

fn default_true() -> bool {
    true
}

fn default_anti_dpi_chunk_size() -> usize {
    40
}

fn default_anti_dpi_delay_ms() -> u64 {
    2
}

fn default_upstream_bypass() -> Vec<String> {
    vec![
        "localhost".to_string(),
        "local".to_string(),
        "lan".to_string(),
        "internal".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDpiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: AntiDpiMode,
    /// Parse the TLS ClientHello SNI extension and split directly inside the hostname.
    #[serde(default = "default_true")]
    pub split_at_sni: bool,
    /// Chunk size (bytes) used for TCP chunking or fallback TLS split offset.
    #[serde(default = "default_anti_dpi_chunk_size")]
    pub chunk_size: usize,
    /// Inter-chunk delay in milliseconds (0-50ms).
    #[serde(default = "default_anti_dpi_delay_ms")]
    pub delay_ms: u64,
    /// Randomize `Host:` header casing (`hOsT:`) for plain HTTP requests.
    #[serde(default)]
    pub http_host_mix_case: bool,
    /// Domains that should bypass Anti-DPI fragmentation.
    #[serde(default)]
    pub bypass_domains: Vec<String>,
}

impl Default for AntiDpiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: AntiDpiMode::TlsRecordSplit,
            split_at_sni: true,
            chunk_size: default_anti_dpi_chunk_size(),
            delay_ms: default_anti_dpi_delay_ms(),
            http_host_mix_case: false,
            bypass_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub listen_addr: String,
    /// Upstream DNS: either an IP:port (e.g. "1.1.1.1:53") or a DoH URL (e.g. "https://1.1.1.1/dns-query")
    pub upstream: String,
    #[serde(default = "default_true")]
    pub cname_uncloaking: bool,
    /// Expose an RFC 8484 local DNS-over-HTTPS endpoint at `/dns-query` on the API port.
    #[serde(default = "default_true")]
    pub doh_server_enabled: bool,
    /// Route upstream DoH requests through the configured upstream SOCKS5/HTTP proxy.
    #[serde(default)]
    pub use_upstream_proxy: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "127.0.0.1:5353".to_string(),
            upstream: "https://1.1.1.1/dns-query".to_string(),
            cname_uncloaking: true,
            doh_server_enabled: true,
            use_upstream_proxy: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_true")]
    pub http_enabled: bool,
    pub http_listen: String,
    #[serde(default = "default_true")]
    pub socks5_enabled: bool,
    pub socks5_listen: String,
    #[serde(default)]
    pub upstream_mode: UpstreamMode,
    /// Upstream proxy address when chaining with Clash/V2Ray/Sing-box/VPN (e.g. "127.0.0.1:7890")
    #[serde(default)]
    pub upstream_addr: String,
    #[serde(default)]
    pub upstream_username: Option<String>,
    #[serde(default)]
    pub upstream_password: Option<String>,
    /// Domains or suffixes that bypass the upstream proxy and connect Direct.
    #[serde(default = "default_upstream_bypass")]
    pub upstream_bypass: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            http_enabled: true,
            http_listen: "127.0.0.1:8080".to_string(),
            socks5_enabled: true,
            socks5_listen: "127.0.0.1:1080".to_string(),
            upstream_mode: UpstreamMode::Direct,
            upstream_addr: String::new(),
            upstream_username: None,
            upstream_password: None,
            upstream_bypass: default_upstream_bypass(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_addr: String,
    #[serde(default)]
    pub auth_enabled: bool,
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:4242".to_string(),
            auth_enabled: false,
            auth_token: None,
        }
    }
}

/// Convert a loopback bind address (e.g. `127.0.0.1:5353`) to `0.0.0.0:5353` when LAN mode is enabled.
pub fn apply_lan_bind(addr: &str, lan_mode: bool) -> String {
    if !lan_mode {
        return addr.to_string();
    }
    if let Some((_, port)) = addr.rsplit_once(':') {
        if addr.starts_with("127.0.0.1:") || addr.starts_with("localhost:") {
            return format!("0.0.0.0:{port}");
        }
    }
    addr.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterListConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub category: BlockCategory,
    pub enabled: bool,
    #[serde(default)]
    pub rule_count: usize,
    #[serde(default)]
    pub last_updated: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
}

fn default_auto_update_enabled() -> bool {
    true
}

fn default_auto_update_interval_hours() -> u64 {
    24
}

fn default_log_retention_days() -> u64 {
    7
}

fn default_log_max_rows() -> u64 {
    50_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub anti_dpi: AntiDpiConfig,
    #[serde(default = "default_true")]
    pub baseline_rules_enabled: bool,
    #[serde(default = "default_filter_lists")]
    pub lists: Vec<FilterListConfig>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub denylist: Vec<String>,
    #[serde(default)]
    pub system_proxy_enabled: bool,
    #[serde(default)]
    pub system_dns_enabled: bool,
    #[serde(default)]
    pub lan_mode: bool,
    #[serde(default)]
    pub client_names: HashMap<String, String>,
    #[serde(default = "default_auto_update_enabled")]
    pub auto_update_enabled: bool,
    #[serde(default = "default_auto_update_interval_hours")]
    pub auto_update_interval_hours: u64,
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: u64,
    #[serde(default = "default_log_max_rows")]
    pub log_max_rows: u64,
}

/// Safe-by-default DNS blocklists designed for near-zero false positives.
pub fn default_filter_lists() -> Vec<FilterListConfig> {
    vec![
        FilterListConfig {
            id: "hagezi-normal".to_string(),
            name: "HaGeZi Multi Normal (Balanced Ads & Trackers)".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt"
                .to_string(),
            category: BlockCategory::Ad,
            enabled: true,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        },
        FilterListConfig {
            id: "hagezi-tif-mini".to_string(),
            name: "HaGeZi Threat Intelligence Mini (Malware & Phishing)".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt"
                .to_string(),
            category: BlockCategory::Malware,
            enabled: true,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        },
        FilterListConfig {
            id: "hagezi-pro".to_string(),
            name: "HaGeZi Multi PRO (Strict Ads & Trackers)".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
                .to_string(),
            category: BlockCategory::Ad,
            enabled: false,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        },
        FilterListConfig {
            id: "adguard-dns".to_string(),
            name: "AdGuard DNS Filter".to_string(),
            url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt".to_string(),
            category: BlockCategory::Ad,
            enabled: false,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        },
        FilterListConfig {
            id: "hagezi-windows".to_string(),
            name: "HaGeZi Windows & Office Telemetry".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt"
                .to_string(),
            category: BlockCategory::WindowsTelemetry,
            enabled: false,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        },
        FilterListConfig {
            id: "hagezi-apple".to_string(),
            name: "HaGeZi Apple / macOS Telemetry".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt"
                .to_string(),
            category: BlockCategory::MacOSTelemetry,
            enabled: false,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        },
    ]
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            dns: DnsConfig::default(),
            proxy: ProxyConfig::default(),
            api: ApiConfig::default(),
            anti_dpi: AntiDpiConfig::default(),
            baseline_rules_enabled: true,
            lists: default_filter_lists(),
            allowlist: Vec::new(),
            denylist: Vec::new(),
            system_proxy_enabled: false,
            system_dns_enabled: false,
            lan_mode: false,
            client_names: HashMap::new(),
            auto_update_enabled: default_auto_update_enabled(),
            auto_update_interval_hours: default_auto_update_interval_hours(),
            log_retention_days: default_log_retention_days(),
            log_max_rows: default_log_max_rows(),
        }
    }
}

impl AegisConfig {
    pub fn default_data_dir() -> PathBuf {
        if let Some(proj) = directories::ProjectDirs::from("io", "aegis", "aegis-blocker") {
            proj.data_local_dir().to_path_buf()
        } else {
            PathBuf::from(".aegis-data")
        }
    }

    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let cfg: Self = toml::from_str(&content)?;
            Ok(cfg)
        } else {
            let cfg = Self::default();
            cfg.save(path)?;
            Ok(cfg)
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Apply a built-in protection profile, ensuring preset lists exist and enabling
    /// the appropriate subset while disabling overly aggressive lists like `easyprivacy`.
    pub fn apply_profile(&mut self, profile: ProtectionProfile) {
        for preset in default_filter_lists() {
            if !self.lists.iter().any(|l| l.id == preset.id) {
                self.lists.push(preset);
            }
        }

        self.baseline_rules_enabled = true;

        for list in &mut self.lists {
            list.enabled = match profile {
                ProtectionProfile::Minimal => list.id == "hagezi-tif-mini",
                ProtectionProfile::Balanced => {
                    matches!(list.id.as_str(), "hagezi-normal" | "hagezi-tif-mini")
                }
                ProtectionProfile::Strict => matches!(
                    list.id.as_str(),
                    "hagezi-pro" | "hagezi-tif-mini" | "hagezi-windows" | "hagezi-apple"
                ),
            };
        }
    }
}
