pub mod config;
pub mod engine;
pub mod lists;

pub use config::{
    apply_lan_bind, AegisConfig, ApiConfig, BlockCategory, DnsConfig, FilterListConfig,
    ProxyConfig, UpstreamMode,
};
pub use engine::{FilterDecision, FilterEngine};
pub use lists::{download_list, parse_filter_list, ListDownloadOutcome, ParsedRules};

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

    #[tokio::test]
    async fn download_list_uses_etag_and_handles_304() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let has_etag = req.to_ascii_lowercase().contains("if-none-match: \"v1\"");
                if has_etag {
                    let resp = "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 0\r\n\r\n";
                    sock.write_all(resp.as_bytes()).await.unwrap();
                } else {
                    let body = "||ads.test.invalid^\n";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nLast-Modified: Wed, 21 Oct 2025 07:28:00 GMT\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    sock.write_all(resp.as_bytes()).await.unwrap();
                }
            }
        });

        let tmp = std::env::temp_dir().join(format!(
            "aegis-etag-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let client = reqwest::Client::new();
        let mut list = FilterListConfig {
            id: "test-list".to_string(),
            name: "Test List".to_string(),
            url: format!("http://{addr}/list.txt"),
            category: BlockCategory::Ad,
            enabled: true,
            rule_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        };

        // First download: 200 OK with ETag + Last-Modified
        let first = download_list(&client, &list, &tmp).await.unwrap();
        match first {
            ListDownloadOutcome::Updated {
                parsed,
                etag,
                last_modified,
            } => {
                assert_eq!(parsed.blocked, vec!["ads.test.invalid".to_string()]);
                assert_eq!(etag.as_deref(), Some("\"v1\""));
                assert_eq!(
                    last_modified.as_deref(),
                    Some("Wed, 21 Oct 2025 07:28:00 GMT")
                );
                list.etag = etag;
                list.last_modified = last_modified;
            }
            ListDownloadOutcome::NotModified => panic!("Expected 200 Updated on first fetch"),
        }

        // Second download: sends If-None-Match and receives 304 Not Modified
        let second = download_list(&client, &list, &tmp).await.unwrap();
        assert!(matches!(second, ListDownloadOutcome::NotModified));

        let _ = server.await;
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
