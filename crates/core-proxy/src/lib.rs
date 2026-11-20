pub mod http_proxy;
pub mod socks5_proxy;
pub mod upstream;

pub use http_proxy::HttpProxyServer;
pub use socks5_proxy::Socks5ProxyServer;
pub use upstream::connect_outbound;

#[cfg(test)]
mod tests {
    use super::*;
    use core_engine::{FilterEngine, ProxyConfig, UpstreamMode};
    use core_stats::StatsStore;
    use std::sync::{Arc, RwLock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;

    #[tokio::test]
    async fn http_proxy_blocks_ads_with_403() {
        let engine = Arc::new(FilterEngine::new());
        let stats = Arc::new(StatsStore::in_memory().unwrap());
        let cfg = Arc::new(RwLock::new(ProxyConfig::default()));

        let srv = Arc::new(HttpProxyServer::new(cfg, engine, Arc::clone(&stats)));
        let listener = srv.bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(srv.serve(listener, rx));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT ads.doubleclick.net:443 HTTP/1.1\r\nHost: ads.doubleclick.net:443\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 256];
        let n = client.read(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp[..n]);
        assert!(text.contains("403 Forbidden"), "Got: {text}");
        assert_eq!(stats.summary().ads_blocked, 1);

        let _ = tx.send(true);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn socks5_proxy_blocks_telemetry_and_chains_allowed_upstream() {
        // 1. Start a local echo server as final destination
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        // 2. Start a second SOCKS5 proxy acting as an "upstream VPN/Clash proxy"
        let upstream_engine = Arc::new(FilterEngine::new());
        let upstream_stats = Arc::new(StatsStore::in_memory().unwrap());
        let upstream_cfg = Arc::new(RwLock::new(ProxyConfig::default()));
        let upstream_srv = Arc::new(Socks5ProxyServer::new(
            upstream_cfg,
            upstream_engine,
            upstream_stats,
        ));
        let upstream_listener = upstream_srv.bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (utx, urx) = watch::channel(false);
        tokio::spawn(upstream_srv.serve(upstream_listener, urx));

        // 3. Start Aegis SOCKS5 proxy configured to chain into upstream SOCKS5
        let engine = Arc::new(FilterEngine::new());
        let stats = Arc::new(StatsStore::in_memory().unwrap());
        let mut pcfg = ProxyConfig::default();
        pcfg.upstream_mode = UpstreamMode::Socks5;
        pcfg.upstream_addr = upstream_addr.to_string();
        let cfg = Arc::new(RwLock::new(pcfg));

        let srv = Arc::new(Socks5ProxyServer::new(cfg, engine, Arc::clone(&stats)));
        let listener = srv.bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(srv.serve(listener, rx));

        // 3a. Verify blocked macOS telemetry domain gets 0x02
        {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            c.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x00]);

            let host = b"metrics.icloud.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&443u16.to_be_bytes());
            c.write_all(&req).await.unwrap();

            let mut rep = [0u8; 10];
            c.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x02, "Expected SOCKS5 ruleset block 0x02");
        }

        // 3b. Verify allowed destination chains through upstream SOCKS5 to echo server!
        {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            c.read_exact(&mut m).await.unwrap();

            let host = b"127.0.0.1";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&echo_port.to_be_bytes());
            c.write_all(&req).await.unwrap();

            let mut rep = [0u8; 10];
            c.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x00, "Expected SOCKS5 chained connect success");

            c.write_all(b"hello-aegis").await.unwrap();
            let mut echo = [0u8; 11];
            c.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"hello-aegis");
        }

        assert_eq!(stats.summary().macos_telemetry_blocked, 1);
        assert_eq!(stats.summary().total_requests, 2);

        let _ = tx.send(true);
        let _ = utx.send(true);
        let _ = handle.await;
    }
}
