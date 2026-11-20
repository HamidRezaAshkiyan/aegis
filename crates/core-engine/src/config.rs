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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen_addr: String,
    /// Upstream DNS: either an IP:port (e.g. "1.1.1.1:53") or a DoH URL (e.g. "https://1.1.1.1/dns-query")
    pub upstream: String,
    pub cname_uncloaking: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "127.0.0.1:5353".to_string(),
            upstream: "https://1.1.1.1/dns-query".to_string(),
            cname_uncloaking: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub http_enabled: bool,
    pub http_listen: String,
    pub socks5_enabled: bool,
    pub socks5_listen: String,
    pub upstream_mode: UpstreamMode,
    /// Upstream proxy address when chaining with Clash/V2Ray/Sing-box/VPN (e.g. "127.0.0.1:7890")
    pub upstream_addr: String,
    pub upstream_username: Option<String>,
    pub upstream_password: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub api: ApiConfig,
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
}

pub fn default_filter_lists() -> Vec<FilterListConfig> {
    vec![
        FilterListConfig {
            id: "hagezi-pro".to_string(),
            name: "HaGeZi Multi PRO (Ads & Trackers)".to_string(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
                .to_string(),
            category: BlockCategory::Ad,
            enabled: true,
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
            enabled: true,
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
            enabled: true,
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
            id: "easyprivacy".to_string(),
            name: "EasyPrivacy Trackers".to_string(),
            url: "https://easylist.to/easylist/easyprivacy.txt".to_string(),
            category: BlockCategory::Tracker,
            enabled: true,
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
            lists: default_filter_lists(),
            allowlist: Vec::new(),
            denylist: Vec::new(),
            system_proxy_enabled: false,
            system_dns_enabled: false,
            lan_mode: false,
            client_names: HashMap::new(),
            auto_update_enabled: default_auto_update_enabled(),
            auto_update_interval_hours: default_auto_update_interval_hours(),
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
}
