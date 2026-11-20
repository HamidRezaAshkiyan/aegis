pub mod macos;
pub mod windows;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RestoreState {
    enabled: bool,
    services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsInterfaceSnapshot {
    pub interface: String,
    pub previous_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsRestoreState {
    enabled: bool,
    interfaces: Vec<DnsInterfaceSnapshot>,
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("restore_state.json")
}

fn dns_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("dns_restore_state.json")
}

/// Enable OS system proxy and write a crash-recovery snapshot.
pub fn enable_system_proxy(
    data_dir: &Path,
    http_listen: &str,
    socks_listen: &str,
) -> anyhow::Result<()> {
    let (http_host, http_port) = split_addr(http_listen, 8080);
    let (socks_host, socks_port) = split_addr(socks_listen, 1080);

    #[allow(unused_mut, unused_assignments)]
    let mut services = Vec::new();

    #[cfg(target_os = "macos")]
    {
        services = macos::enable_system_proxy(&http_host, http_port, &socks_host, socks_port)?;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = (&socks_host, socks_port);
        windows::enable_system_proxy(&http_host, http_port)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (&http_host, http_port, &socks_host, socks_port);
        warn!("System proxy auto-configuration is only supported on macOS and Windows");
    }

    let snapshot = RestoreState {
        enabled: true,
        services,
    };
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(state_path(data_dir), serde_json::to_string_pretty(&snapshot)?)?;
    Ok(())
}

/// Disable OS system proxy and remove the crash-recovery snapshot.
pub fn disable_system_proxy(data_dir: &Path) -> anyhow::Result<()> {
    let path = state_path(data_dir);
    let services = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<RestoreState>(&s).ok())
            .map(|r| r.services)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    #[cfg(target_os = "macos")]
    {
        macos::disable_system_proxy(&services)?;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = services;
        windows::disable_system_proxy()?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = services;
    }

    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// Extract a local DNS IP address from a listen address (e.g. `0.0.0.0:53` -> `127.0.0.1`).
pub fn extract_local_dns_ip(dns_listen: &str) -> String {
    let (host, _) = split_addr(dns_listen, 53);
    if host.is_empty() || host == "0.0.0.0" || host == "::" || host == "[::]" {
        "127.0.0.1".to_string()
    } else {
        host.trim_matches(|c| c == '[' || c == ']').to_string()
    }
}

/// Enable OS system DNS pointing to Aegis and write a crash-recovery snapshot of previous DNS servers.
pub fn enable_system_dns(data_dir: &Path, dns_listen: &str) -> anyhow::Result<()> {
    let dns_ip = extract_local_dns_ip(dns_listen);

    #[allow(unused_mut, unused_assignments)]
    let mut interfaces = Vec::new();

    #[cfg(target_os = "macos")]
    {
        interfaces = macos::enable_system_dns(&dns_ip)?;
    }

    #[cfg(target_os = "windows")]
    {
        interfaces = windows::enable_system_dns(&dns_ip)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = &dns_ip;
        warn!("System DNS auto-configuration is only supported on macOS and Windows");
    }

    let snapshot = DnsRestoreState {
        enabled: true,
        interfaces,
    };
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(
        dns_state_path(data_dir),
        serde_json::to_string_pretty(&snapshot)?,
    )?;
    Ok(())
}

/// Restore OS system DNS to the previously snapshotted servers (or DHCP) and remove the snapshot.
pub fn disable_system_dns(data_dir: &Path) -> anyhow::Result<()> {
    let path = dns_state_path(data_dir);
    let interfaces = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<DnsRestoreState>(&s).ok())
            .map(|r| r.interfaces)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    #[cfg(target_os = "macos")]
    {
        macos::disable_system_dns(&interfaces)?;
    }

    #[cfg(target_os = "windows")]
    {
        windows::disable_system_dns(&interfaces)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = interfaces;
    }

    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// Called on daemon startup: if a previous run crashed while system proxy or system DNS was enabled,
/// cleanly restore OS settings so the user is never left without internet.
pub fn recover_if_dirty(data_dir: &Path) {
    let path = state_path(data_dir);
    if path.exists() {
        warn!("Detected stale system proxy state from a previous ungraceful exit; restoring OS proxy settings");
        if let Err(e) = disable_system_proxy(data_dir) {
            warn!(error = %e, "Failed to restore stale system proxy state");
        } else {
            info!("Recovered OS proxy settings cleanly");
        }
    }

    let dns_path = dns_state_path(data_dir);
    if dns_path.exists() {
        warn!("Detected stale system DNS state from a previous ungraceful exit; restoring OS DNS settings");
        if let Err(e) = disable_system_dns(data_dir) {
            warn!(error = %e, "Failed to restore stale system DNS state");
        } else {
            info!("Recovered OS DNS settings cleanly");
        }
    }
}

fn split_addr(addr: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = addr.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (addr.to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_local_dns_ip_maps_wildcard_to_loopback() {
        assert_eq!(extract_local_dns_ip("0.0.0.0:53"), "127.0.0.1");
        assert_eq!(extract_local_dns_ip("127.0.0.1:5353"), "127.0.0.1");
        assert_eq!(extract_local_dns_ip("192.168.1.10:53"), "192.168.1.10");
    }

    #[test]
    fn parses_macos_dns_output_variants() {
        assert!(macos::parse_dns_servers_output("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert_eq!(
            macos::parse_dns_servers_output("1.1.1.1\n8.8.8.8\n"),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }

    #[test]
    fn dns_restore_state_round_trip() {
        let state = DnsRestoreState {
            enabled: true,
            interfaces: vec![DnsInterfaceSnapshot {
                interface: "Wi-Fi".to_string(),
                previous_servers: vec!["1.1.1.1".to_string()],
            }],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: DnsRestoreState = serde_json::from_str(&json).unwrap();
        assert!(parsed.enabled);
        assert_eq!(parsed.interfaces, state.interfaces);
    }
}
