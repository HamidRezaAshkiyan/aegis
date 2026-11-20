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

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("restore_state.json")
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

/// Called on daemon startup: if a previous run crashed while system proxy was enabled,
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
}

fn split_addr(addr: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = addr.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (addr.to_string(), default_port)
}
