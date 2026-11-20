pub mod server;

pub use server::{build_blocked_response, DnsServer};

#[cfg(test)]
mod tests {
    use super::*;
    use core_engine::{DnsConfig, FilterEngine};
    use core_stats::StatsStore;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::watch;

    #[tokio::test]
    async fn dns_server_blocks_ad_domain_with_zero_ip() {
        let engine = Arc::new(FilterEngine::new());
        let stats = Arc::new(StatsStore::in_memory().unwrap());
        let cfg = DnsConfig {
            enabled: true,
            listen_addr: "127.0.0.1:0".to_string(),
            upstream: "1.1.1.1:53".to_string(),
            cname_uncloaking: true,
        };

        let srv = Arc::new(DnsServer::new(cfg, engine, Arc::clone(&stats)));
        let sock = srv.bind().await.unwrap();
        let bound_addr = sock.local_addr().unwrap();

        let (tx, rx) = watch::channel(false);
        let srv_handle = tokio::spawn(srv.serve(sock, rx));

        // Send a DNS query for doubleclick.net
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut req = Message::new();
        req.set_id(1234).set_recursion_desired(true).add_query(Query::query(
            Name::from_str("ads.doubleclick.net.").unwrap(),
            RecordType::A,
        ));
        client.send_to(&req.to_vec().unwrap(), bound_addr).await.unwrap();

        let mut buf = vec![0u8; 512];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        let resp = Message::from_vec(&buf[..len]).unwrap();

        assert_eq!(resp.id(), 1234);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            Some(RData::A(ip)) => assert_eq!(ip.0, Ipv4Addr::UNSPECIFIED),
            other => panic!("Expected 0.0.0.0 A record, got {:?}", other),
        }

        let summary = stats.summary();
        assert_eq!(summary.ads_blocked, 1);

        let _ = tx.send(true);
        let _ = srv_handle.await;
    }
}
