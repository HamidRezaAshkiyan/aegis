use chrono::{DateTime, Utc};
use core_engine::FilterDecision;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficProtocol {
    Dns,
    Http,
    Https,
    Socks5,
}

impl TrafficProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrafficProtocol::Dns => "dns",
            TrafficProtocol::Http => "http",
            TrafficProtocol::Https => "https",
            TrafficProtocol::Socks5 => "socks5",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEvent {
    pub timestamp: DateTime<Utc>,
    pub protocol: TrafficProtocol,
    pub domain: String,
    pub client: String,
    pub decision: FilterDecision,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatsSummary {
    pub total_requests: u64,
    pub total_blocked: u64,
    pub ads_blocked: u64,
    pub trackers_blocked: u64,
    pub windows_telemetry_blocked: u64,
    pub macos_telemetry_blocked: u64,
    pub malware_blocked: u64,
    pub custom_blocked: u64,
    pub block_rate_percent: f64,
    pub top_blocked_domains: Vec<DomainCount>,
}
