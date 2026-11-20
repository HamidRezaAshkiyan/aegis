pub mod config;
pub mod engine;
pub mod lists;

pub use config::{AegisConfig, BlockCategory, DnsConfig, FilterListConfig, ProxyConfig, UpstreamMode};
pub use engine::{FilterDecision, FilterEngine};
pub use lists::{download_list, parse_filter_list, ParsedRules};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_adblock_hosts_and_plain_domains() {
        let sample = r#"
            ! Comment line
            # Another comment
            [Adblock Plus 2.0]
            ||ads.example.com^
            ||tracker.example.org^$third-party
            @@||safe.ads.example.com^
            0.0.0.0 telemetry.vendor.com
            127.0.0.1 localhost
            metrics.app.io
            example.com##.ad-banner
        "#;

        let parsed = parse_filter_list(sample);
        assert!(parsed.blocked.contains(&"ads.example.com".to_string()));
        assert!(parsed.blocked.contains(&"tracker.example.org".to_string()));
        assert!(parsed.blocked.contains(&"telemetry.vendor.com".to_string()));
        assert!(parsed.blocked.contains(&"metrics.app.io".to_string()));
        assert!(!parsed.blocked.contains(&"localhost".to_string()));
        assert!(parsed.allowed.contains(&"safe.ads.example.com".to_string()));
    }

    #[test]
    fn engine_blocks_subdomains_and_respects_allowlist() {
        let engine = FilterEngine::new();
        // Built-in baseline should block doubleclick.net and its subdomains
        match engine.check_domain("pagead2.doubleclick.net") {
            FilterDecision::Block { category, .. } => assert_eq!(category, BlockCategory::Ad),
            FilterDecision::Allow => panic!("Expected doubleclick subdomain to be blocked"),
        }

        // Built-in Windows & Apple telemetry
        match engine.check_domain("vortex.data.microsoft.com.") {
            FilterDecision::Block { category, .. } => {
                assert_eq!(category, BlockCategory::WindowsTelemetry)
            }
            FilterDecision::Allow => panic!("Expected Windows telemetry to be blocked"),
        }
        match engine.check_domain("metrics.icloud.com:443") {
            FilterDecision::Block { category, .. } => {
                assert_eq!(category, BlockCategory::MacOSTelemetry)
            }
            FilterDecision::Allow => panic!("Expected macOS telemetry to be blocked"),
        }

        // User allowlist overrides blocklist
        engine.add_user_allow("pagead2.doubleclick.net");
        assert_eq!(engine.check_domain("pagead2.doubleclick.net"), FilterDecision::Allow);

        // Allowed normal domain
        assert_eq!(engine.check_domain("github.com"), FilterDecision::Allow);
    }

    #[test]
    fn engine_pause_and_resume() {
        let engine = FilterEngine::new();
        engine.pause_for_seconds(60);
        assert_eq!(engine.check_domain("doubleclick.net"), FilterDecision::Allow);
        engine.resume();
        assert!(matches!(
            engine.check_domain("doubleclick.net"),
            FilterDecision::Block { .. }
        ));
    }
}
