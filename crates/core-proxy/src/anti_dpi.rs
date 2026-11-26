use core_engine::{AntiDpiConfig, AntiDpiMode};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Check whether `host` matches any entry in `bypass_domains` (exact or subdomain suffix).
pub fn should_bypass(host: &str, bypass_domains: &[String]) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    for entry in bypass_domains {
        let e = entry
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if e.is_empty() {
            continue;
        }
        if h == e || h.ends_with(&format!(".{e}")) {
            return true;
        }
    }
    false
}

/// Returns true if `data` starts with a TLS Handshake record (`0x16 0x03 0x00..=0x04`)
/// containing a ClientHello (`0x01`) handshake message.
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 6
        && data[0] == 0x16
        && data[1] == 0x03
        && data[2] <= 0x04
        && data[5] == 0x01
}

/// Parse a TLS ClientHello record and return the midpoint byte offset of the SNI hostname
/// *relative to the TLS record payload* (i.e. after the 5-byte TLS record header).
pub fn find_sni_payload_midpoint(record: &[u8]) -> Option<usize> {
    if !is_tls_client_hello(record) || record.len() < 43 {
        return None;
    }
    let rec_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let payload_end = (5 + rec_len).min(record.len());
    let payload = &record[5..payload_end];

    // Handshake header: 1 byte type (0x01) + 3 bytes length = 4 bytes
    // ClientHello body: 2 bytes version + 32 bytes random = 34 bytes -> offset 38
    let mut pos = 38usize;
    if pos >= payload.len() {
        return None;
    }

    // Session ID
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > payload.len() {
        return None;
    }

    // Cipher Suites
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > payload.len() {
        return None;
    }

    // Compression Methods
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > payload.len() {
        return None;
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(payload.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        // Extension 0x0000 = server_name (SNI)
        if ext_type == 0x0000 && ext_len >= 5 {
            // server_name_list_length (2) + name_type (1, 0x00=host_name) + name_length (2)
            let name_type = payload[pos + 2];
            let name_len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
            let name_start = pos + 5;
            if name_type == 0x00 && name_len >= 2 && name_start + name_len <= pos + ext_len {
                return Some(name_start + name_len / 2);
            }
        }
        pos += ext_len;
    }

    None
}

/// Split a single TLS Handshake record into 2 RFC-compliant TLS records at `payload_split_at`.
/// Any trailing bytes after the first TLS record are preserved unchanged.
pub fn split_tls_record(data: &[u8], payload_split_at: usize) -> Vec<Vec<u8>> {
    if data.len() < 7 || data[0] != 0x16 || data[1] != 0x03 {
        return vec![data.to_vec()];
    }
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + rec_len > data.len() || rec_len < 2 {
        return vec![data.to_vec()];
    }

    let split_at = payload_split_at.clamp(1, rec_len - 1);
    let ver_hi = data[1];
    let ver_lo = data[2];
    let payload = &data[5..5 + rec_len];
    let trailing = &data[5 + rec_len..];

    let part1 = &payload[..split_at];
    let part2 = &payload[split_at..];

    let mut r1 = Vec::with_capacity(5 + part1.len());
    r1.extend_from_slice(&[0x16, ver_hi, ver_lo]);
    r1.extend_from_slice(&(part1.len() as u16).to_be_bytes());
    r1.extend_from_slice(part1);

    let mut r2 = Vec::with_capacity(5 + part2.len() + trailing.len());
    r2.extend_from_slice(&[0x16, ver_hi, ver_lo]);
    r2.extend_from_slice(&(part2.len() as u16).to_be_bytes());
    r2.extend_from_slice(part2);
    r2.extend_from_slice(trailing);

    vec![r1, r2]
}

/// Randomize `Host:` header casing (`hOsT:`) for plain HTTP Anti-DPI evasion.
pub fn obfuscate_http_host_header(header_bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(header_bytes);
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split("\r\n").enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case("host:") {
            out.push_str("hOsT:");
            out.push_str(&line[5..]);
        } else {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

/// Write an initial tunnel payload (typically TLS ClientHello) to `outbound` with Anti-DPI
/// fragmentation when enabled and applicable.
pub async fn write_initial_payload(
    outbound: &mut TcpStream,
    payload: &[u8],
    cfg: &AntiDpiConfig,
    host: &str,
) -> std::io::Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    if !cfg.enabled || should_bypass(host, &cfg.bypass_domains) || !is_tls_client_hello(payload) {
        outbound.write_all(payload).await?;
        return Ok(());
    }

    let _ = outbound.set_nodelay(true);
    let delay = Duration::from_millis(cfg.delay_ms.min(50));
    let chunk_size = cfg.chunk_size.clamp(1, 512);

    let split_offset = if cfg.split_at_sni {
        find_sni_payload_midpoint(payload).unwrap_or(chunk_size)
    } else {
        chunk_size
    };

    match cfg.mode {
        AntiDpiMode::TlsRecordSplit => {
            let records = split_tls_record(payload, split_offset);
            for (idx, rec) in records.iter().enumerate() {
                outbound.write_all(rec).await?;
                outbound.flush().await?;
                if idx + 1 < records.len() && !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
        AntiDpiMode::TcpChunk => {
            // First write up to split_offset (plus 5-byte TLS header) or chunk_size
            let first_cut = if cfg.split_at_sni {
                (5 + split_offset).min(payload.len())
            } else {
                chunk_size.min(payload.len())
            };
            outbound.write_all(&payload[..first_cut]).await?;
            outbound.flush().await?;
            if first_cut < payload.len() {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                for chunk in payload[first_cut..].chunks(chunk_size) {
                    outbound.write_all(chunk).await?;
                    outbound.flush().await?;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        AntiDpiMode::Both => {
            let records = split_tls_record(payload, split_offset);
            for rec in &records {
                for chunk in rec.chunks(chunk_size) {
                    outbound.write_all(chunk).await?;
                    outbound.flush().await?;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Relay a tunnel (`client` <-> `outbound`), intercepting only the first client packet
/// to apply Anti-DPI fragmentation when enabled.
pub async fn relay_tunnel(
    client: &mut TcpStream,
    outbound: &mut TcpStream,
    initial_buffered: &[u8],
    cfg: &AntiDpiConfig,
    host: &str,
    is_direct: bool,
) {
    if is_direct && cfg.enabled && !should_bypass(host, &cfg.bypass_domains) {
        if !initial_buffered.is_empty() {
            if write_initial_payload(outbound, initial_buffered, cfg, host)
                .await
                .is_err()
            {
                return;
            }
        } else {
            let mut first_buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(2), client.read(&mut first_buf)).await {
                Ok(Ok(0)) => return,
                Ok(Ok(n)) => {
                    if write_initial_payload(outbound, &first_buf[..n], cfg, host)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(Err(_)) => return,
                Err(_) => {
                    // Server-speaks-first protocol; fall through to normal bidirectional copy
                }
            }
        }
    } else if !initial_buffered.is_empty() && outbound.write_all(initial_buffered).await.is_err() {
        return;
    }

    let _ = tokio::io::copy_bidirectional(client, outbound).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid TLS 1.2 ClientHello record containing an SNI extension for `hostname`.
    fn build_test_client_hello(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        // SNI extension body: list_len (2) + type 0x00 (1) + name_len (2) + name
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_body.push(0x00);
        sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(name);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI ext type
        ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_body);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch_body.extend_from_slice(&[0xAA; 32]); // random
        ch_body.push(0x00); // session_id len
        ch_body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.push(0x01); // compression len
        ch_body.push(0x00); // null compression
        ch_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let hs_len = ch_body.len();
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&ch_body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn finds_sni_midpoint_and_splits_tls_record_losslessly() {
        let ch = build_test_client_hello("example.org");
        assert!(is_tls_client_hello(&ch));

        let mid = find_sni_payload_midpoint(&ch).expect("SNI midpoint should be found");
        // Verify the midpoint actually lands inside "example.org"
        let payload = &ch[5..];
        let name_pos = payload
            .windows(b"example.org".len())
            .position(|w| w == b"example.org")
            .unwrap();
        assert!(mid > name_pos && mid < name_pos + b"example.org".len());

        let records = split_tls_record(&ch, mid);
        assert_eq!(records.len(), 2);
        // Both records are valid TLS Handshake records whose payloads reassemble identically
        let mut reassembled = Vec::new();
        for rec in &records {
            assert_eq!(rec[0], 0x16);
            assert_eq!(&rec[1..3], &[0x03, 0x01]);
            let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert_eq!(len, rec.len() - 5);
            reassembled.extend_from_slice(&rec[5..]);
        }
        assert_eq!(reassembled, &ch[5..]);
    }

    #[test]
    fn bypass_matches_exact_and_subdomains() {
        let bypass = vec!["example.com".to_string(), "*.local".to_string()];
        assert!(should_bypass("example.com", &bypass));
        assert!(should_bypass("sub.example.com", &bypass));
        assert!(should_bypass("printer.local", &bypass));
        assert!(!should_bypass("notexample.com", &bypass));
    }

    #[test]
    fn obfuscates_http_host_header() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let out = String::from_utf8(obfuscate_http_host_header(raw)).unwrap();
        assert!(out.contains("hOsT: example.com"));
        assert!(out.contains("User-Agent: test"));
    }
}
