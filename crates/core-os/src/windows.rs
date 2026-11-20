#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use tracing::{info, warn};

#[cfg(target_os = "windows")]
const REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(target_os = "windows")]
pub fn enable_system_proxy(http_host: &str, http_port: u16) -> anyhow::Result<()> {
    let proxy_server = format!("{http_host}:{http_port}");
    Command::new("reg")
        .args(["add", REG_PATH, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])
        .status()?;
    Command::new("reg")
        .args(["add", REG_PATH, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &proxy_server, "/f"])
        .status()?;
    info!(proxy = %proxy_server, "Enabled Windows system proxy");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn disable_system_proxy() -> anyhow::Result<()> {
    Command::new("reg")
        .args(["add", REG_PATH, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])
        .status()?;
    info!("Disabled Windows system proxy");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn enable_system_dns(dns_ip: &str) -> anyhow::Result<Vec<crate::DnsInterfaceSnapshot>> {
    // Snapshot active adapters and their current IPv4 DNS servers via PowerShell
    let ps_list = r#"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $alias = $_.Name; $dns = (Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ','; Write-Output "$alias|$dns" }"#;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_list])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut snapshots = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((alias, dns_csv)) = line.split_once('|') else {
            continue;
        };
        let alias = alias.trim().to_string();
        let previous_servers: Vec<String> = dns_csv
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let escaped_alias = alias.replace('\'', "''");
        let ps_set = format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses '{}'",
            escaped_alias, dns_ip
        );
        let ok = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_set])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
            || Command::new("netsh")
                .args(["interface", "ip", "set", "dns", &alias, "static", dns_ip])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

        if ok {
            info!(interface = %alias, dns = %dns_ip, "Enabled Windows system DNS");
            snapshots.push(crate::DnsInterfaceSnapshot {
                interface: alias,
                previous_servers,
            });
        } else {
            warn!(interface = %alias, "Could not set Windows system DNS (may require Administrator privileges)");
        }
    }
    Ok(snapshots)
}

#[cfg(target_os = "windows")]
pub fn disable_system_dns(snapshots: &[crate::DnsInterfaceSnapshot]) -> anyhow::Result<()> {
    for snap in snapshots {
        let escaped_alias = snap.interface.replace('\'', "''");
        if snap.previous_servers.is_empty() {
            let ps_reset = format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
                escaped_alias
            );
            let ok = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_reset])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                let _ = Command::new("netsh")
                    .args(["interface", "ip", "set", "dns", &snap.interface, "dhcp"])
                    .status();
            }
        } else {
            let addrs = snap
                .previous_servers
                .iter()
                .map(|s| format!("'{}'", s.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",");
            let ps_restore = format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
                escaped_alias, addrs
            );
            let _ = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_restore])
                .status();
        }
        info!(interface = %snap.interface, restored = ?snap.previous_servers, "Restored Windows system DNS");
    }
    Ok(())
}
