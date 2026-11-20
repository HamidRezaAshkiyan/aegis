#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use tracing::{info, warn};

#[cfg(target_os = "macos")]
pub fn list_active_services() -> anyhow::Result<Vec<String>> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let services = text
        .lines()
        .skip(1)
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(|l| l.to_string())
        .collect();
    Ok(services)
}

#[cfg(target_os = "macos")]
pub fn enable_system_proxy(http_host: &str, http_port: u16, socks_host: &str, socks_port: u16) -> anyhow::Result<Vec<String>> {
    let services = list_active_services()?;
    let mut modified = Vec::new();
    for svc in &services {
        let ok1 = Command::new("networksetup")
            .args(["-setwebproxy", svc, http_host, &http_port.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let ok2 = Command::new("networksetup")
            .args(["-setsecurewebproxy", svc, http_host, &http_port.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let ok3 = Command::new("networksetup")
            .args(["-setsocksfirewallproxy", svc, socks_host, &socks_port.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok1 || ok2 || ok3 {
            modified.push(svc.clone());
            info!(service = %svc, "Enabled macOS system proxy");
        } else {
            warn!(service = %svc, "Could not set macOS system proxy (may require elevation)");
        }
    }
    Ok(modified)
}

#[cfg(target_os = "macos")]
pub fn disable_system_proxy(services: &[String]) -> anyhow::Result<()> {
    let list = if services.is_empty() {
        list_active_services().unwrap_or_default()
    } else {
        services.to_vec()
    };
    for svc in list {
        let _ = Command::new("networksetup")
            .args(["-setwebproxystate", &svc, "off"])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsecurewebproxystate", &svc, "off"])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", &svc, "off"])
            .status();
        info!(service = %svc, "Disabled macOS system proxy");
    }
    Ok(())
}

/// Parse `networksetup -getdnsservers <service>` output into a list of DNS server IPs.
/// Returns an empty Vec when DHCP / no static DNS servers are configured.
pub fn parse_dns_servers_output(output: &str) -> Vec<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed.contains("There aren't any DNS Servers") {
        return Vec::new();
    }
    trimmed
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.contains("There aren't any"))
        .map(|l| l.to_string())
        .collect()
}

#[cfg(target_os = "macos")]
pub fn enable_system_dns(dns_ip: &str) -> anyhow::Result<Vec<crate::DnsInterfaceSnapshot>> {
    let services = list_active_services()?;
    let mut snapshots = Vec::new();
    for svc in services {
        let prev_out = Command::new("networksetup")
            .args(["-getdnsservers", &svc])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let previous_servers = parse_dns_servers_output(&prev_out);

        let ok = Command::new("networksetup")
            .args(["-setdnsservers", &svc, dns_ip])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if ok {
            info!(service = %svc, dns = %dns_ip, "Enabled macOS system DNS");
            snapshots.push(crate::DnsInterfaceSnapshot {
                interface: svc,
                previous_servers,
            });
        } else {
            warn!(service = %svc, "Could not set macOS system DNS (may require elevation)");
        }
    }
    Ok(snapshots)
}

#[cfg(target_os = "macos")]
pub fn disable_system_dns(snapshots: &[crate::DnsInterfaceSnapshot]) -> anyhow::Result<()> {
    if snapshots.is_empty() {
        for svc in list_active_services().unwrap_or_default() {
            let _ = Command::new("networksetup")
                .args(["-setdnsservers", &svc, "empty"])
                .status();
            info!(service = %svc, "Reset macOS system DNS to DHCP");
        }
        return Ok(());
    }

    for snap in snapshots {
        let mut cmd = Command::new("networksetup");
        cmd.args(["-setdnsservers", &snap.interface]);
        if snap.previous_servers.is_empty() {
            cmd.arg("empty");
        } else {
            for srv in &snap.previous_servers {
                cmd.arg(srv);
            }
        }
        let _ = cmd.status();
        info!(service = %snap.interface, restored = ?snap.previous_servers, "Restored macOS system DNS");
    }
    Ok(())
}
