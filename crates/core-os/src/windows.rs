#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use tracing::info;

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
