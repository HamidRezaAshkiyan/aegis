pub mod events;
pub mod store;

pub use events::{ClientStats, DomainCount, StatsSummary, TrafficEvent, TrafficProtocol};
pub use store::StatsStore;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_engine::{BlockCategory, FilterDecision};

    #[test]
    fn records_and_aggregates_stats() {
        let store = StatsStore::in_memory().unwrap();

        store.record(TrafficEvent {
            timestamp: Utc::now(),
            protocol: TrafficProtocol::Dns,
            domain: "doubleclick.net".to_string(),
            client: "127.0.0.1".to_string(),
            decision: FilterDecision::Block {
                category: BlockCategory::Ad,
                matched_rule: "doubleclick.net".to_string(),
                list_name: "Built-in".to_string(),
            },
            latency_ms: 1,
        });

        store.record(TrafficEvent {
            timestamp: Utc::now(),
            protocol: TrafficProtocol::Socks5,
            domain: "vortex.data.microsoft.com".to_string(),
            client: "127.0.0.1".to_string(),
            decision: FilterDecision::Block {
                category: BlockCategory::WindowsTelemetry,
                matched_rule: "vortex.data.microsoft.com".to_string(),
                list_name: "Windows".to_string(),
            },
            latency_ms: 2,
        });

        store.record(TrafficEvent {
            timestamp: Utc::now(),
            protocol: TrafficProtocol::Https,
            domain: "github.com".to_string(),
            client: "127.0.0.1".to_string(),
            decision: FilterDecision::Allow,
            latency_ms: 15,
        });

        let summary = store.summary();
        assert_eq!(summary.total_requests, 3);
        assert_eq!(summary.total_blocked, 2);
        assert_eq!(summary.ads_blocked, 1);
        assert_eq!(summary.windows_telemetry_blocked, 1);
        assert_eq!(store.recent_logs(10).len(), 3);

        let clients = store.client_stats();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].client, "127.0.0.1");
        assert_eq!(clients[0].total_requests, 3);
        assert_eq!(clients[0].blocked_requests, 2);
    }

    #[test]
    fn prunes_query_log_by_age_and_row_cap() {
        let store = StatsStore::in_memory().unwrap();
        let old_ts = Utc::now() - chrono::Duration::days(10);
        let now_ts = Utc::now();

        // 3 old rows (10 days old)
        for i in 0..3 {
            store.record(TrafficEvent {
                timestamp: old_ts,
                protocol: TrafficProtocol::Dns,
                domain: format!("old-{i}.example.com"),
                client: "127.0.0.1".to_string(),
                decision: FilterDecision::Allow,
                latency_ms: 1,
            });
        }
        // 6 recent rows
        for i in 0..6 {
            store.record(TrafficEvent {
                timestamp: now_ts,
                protocol: TrafficProtocol::Dns,
                domain: format!("new-{i}.example.com"),
                client: "127.0.0.1".to_string(),
                decision: FilterDecision::Allow,
                latency_ms: 1,
            });
        }
        assert_eq!(store.query_log_count(), 9);

        // Age-based prune (7 days) removes the 3 old rows
        let deleted_age = store.prune_logs(7, 0).unwrap();
        assert_eq!(deleted_age, 3);
        assert_eq!(store.query_log_count(), 6);

        // Row-cap prune (max 4 rows) removes 2 oldest remaining rows
        let deleted_cap = store.prune_logs(0, 4).unwrap();
        assert_eq!(deleted_cap, 2);
        assert_eq!(store.query_log_count(), 4);
    }
}
