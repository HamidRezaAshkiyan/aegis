use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub platform: &'static str,
    pub details: String,
}

pub const MACOS_LABEL: &str = "io.aegis.blocker";
pub const WINDOWS_TASK_NAME: &str = "AegisBlocker";
pub const LINUX_SERVICE_NAME: &str = "aegis.service";

/// Render the macOS LaunchAgent `.plist` XML content.
pub fn render_macos_plist(exe_path: &Path, data_dir: Option<&Path>, log_path: &Path) -> String {
    let mut args = vec![xml_escape(&exe_path.display().to_string())];
    if let Some(dir) = data_dir {
        args.push("--data-dir".to_string());
        args.push(xml_escape(&dir.display().to_string()));
    }
    let args_xml: String = args
        .into_iter()
        .map(|a| format!("        <string>{a}</string>"))
        .collect::<Vec<_>>()
        .join("\n");
    let log_esc = xml_escape(&log_path.display().to_string());

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{MACOS_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_esc}</string>
    <key>StandardErrorPath</key>
    <string>{log_esc}</string>
</dict>
</plist>
"#
    )
}

/// Render the Linux user `systemd` service unit content.
pub fn render_systemd_unit(exe_path: &Path, data_dir: Option<&Path>) -> String {
    let exec_start = match data_dir {
        Some(dir) => format!("\"{}\" --data-dir \"{}\"", exe_path.display(), dir.display()),
        None => format!("\"{}\"", exe_path.display()),
    };
    format!(
        r#"[Unit]
Description=Aegis Ad & Tracker Blocker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"#
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn macos_plist_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("Could not determine HOME directory"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn macos_uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "501".to_string())
}

#[cfg(target_os = "linux")]
fn linux_unit_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("Could not determine HOME directory"))?;
    Ok(home
        .join(".config")
        .join("systemd")
        .join("user")
        .join(LINUX_SERVICE_NAME))
}

/// Install and start Aegis as a background / launch-at-login service for the current OS.
pub fn install_service(exe_path: &Path, data_dir: Option<&Path>) -> anyhow::Result<String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let plist_path = macos_plist_path()?;
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log_dir = data_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir());
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("aegis-service.log");

        let plist = render_macos_plist(exe_path, data_dir, &log_path);
        std::fs::write(&plist_path, plist)?;

        let uid = macos_uid();
        let domain = format!("gui/{uid}");
        // Unload first if already present
        let _ = Command::new("launchctl")
            .args(["bootout", &domain, &plist_path.display().to_string()])
            .status();

        let loaded = Command::new("launchctl")
            .args(["bootstrap", &domain, &plist_path.display().to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
            || Command::new("launchctl")
                .args(["load", "-w", &plist_path.display().to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

        if !loaded {
            return Ok(format!(
                "Installed LaunchAgent plist at {} (run `launchctl load -w {}` if not started automatically)",
                plist_path.display(),
                plist_path.display()
            ));
        }
        Ok(format!(
            "Installed and started macOS LaunchAgent ({MACOS_LABEL}) at {}",
            plist_path.display()
        ))
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let mut cmd_str = format!("\"{}\"", exe_path.display());
        if let Some(dir) = data_dir {
            cmd_str.push_str(&format!(" --data-dir \"{}\"", dir.display()));
        }

        let task_ok = Command::new("schtasks")
            .args([
                "/Create",
                "/TN",
                WINDOWS_TASK_NAME,
                "/SC",
                "ONLOGON",
                "/TR",
                &cmd_str,
                "/F",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if task_ok {
            let _ = Command::new("schtasks")
                .args(["/Run", "/TN", WINDOWS_TASK_NAME])
                .status();
            return Ok(format!(
                "Installed and started Windows login task ({WINDOWS_TASK_NAME})"
            ));
        }

        // Fallback to HKCU Run registry key
        let status = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                WINDOWS_TASK_NAME,
                "/t",
                "REG_SZ",
                "/d",
                &cmd_str,
                "/f",
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("Failed to install Windows startup entry");
        }
        Ok(format!(
            "Installed Windows startup registry entry ({WINDOWS_TASK_NAME})"
        ))
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let unit_path = linux_unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let unit = render_systemd_unit(exe_path, data_dir);
        std::fs::write(&unit_path, unit)?;

        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let ok = Command::new("systemctl")
            .args(["--user", "enable", "--now", LINUX_SERVICE_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if ok {
            Ok(format!(
                "Installed and started systemd user service ({LINUX_SERVICE_NAME}) at {}",
                unit_path.display()
            ))
        } else {
            Ok(format!(
                "Wrote systemd user unit to {} (enable with: systemctl --user enable --now {LINUX_SERVICE_NAME})",
                unit_path.display()
            ))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (exe_path, data_dir);
        anyhow::bail!("Background service installation is not supported on this platform")
    }
}

/// Stop and remove the Aegis background / launch-at-login service.
pub fn uninstall_service() -> anyhow::Result<String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let plist_path = macos_plist_path()?;
        let uid = macos_uid();
        let domain = format!("gui/{uid}");
        let _ = Command::new("launchctl")
            .args(["bootout", &domain, &plist_path.display().to_string()])
            .status();
        let _ = Command::new("launchctl")
            .args(["unload", "-w", &plist_path.display().to_string()])
            .status();
        if plist_path.exists() {
            std::fs::remove_file(&plist_path)?;
        }
        Ok(format!(
            "Uninstalled macOS LaunchAgent ({MACOS_LABEL})"
        ))
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let _ = Command::new("schtasks")
            .args(["/End", "/TN", WINDOWS_TASK_NAME])
            .status();
        let _ = Command::new("schtasks")
            .args(["/Delete", "/TN", WINDOWS_TASK_NAME, "/F"])
            .status();
        let _ = Command::new("reg")
            .args([
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                WINDOWS_TASK_NAME,
                "/f",
            ])
            .status();
        Ok(format!(
            "Uninstalled Windows background service ({WINDOWS_TASK_NAME})"
        ))
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", LINUX_SERVICE_NAME])
            .status();
        let unit_path = linux_unit_path()?;
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
        }
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        Ok(format!(
            "Uninstalled systemd user service ({LINUX_SERVICE_NAME})"
        ))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        anyhow::bail!("Background service uninstallation is not supported on this platform")
    }
}

/// Query installation and running status of the Aegis background service.
pub fn service_status() -> anyhow::Result<ServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let plist_path = macos_plist_path()?;
        let installed = plist_path.exists();
        let out = Command::new("launchctl")
            .args(["list", MACOS_LABEL])
            .output();
        let running = out
            .as_ref()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let details = if installed {
            format!("LaunchAgent plist: {}", plist_path.display())
        } else {
            "Not installed".to_string()
        };
        Ok(ServiceStatus {
            installed,
            running,
            platform: "macOS (launchd)",
            details,
        })
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let out = Command::new("schtasks")
            .args(["/Query", "/TN", WINDOWS_TASK_NAME, "/FO", "LIST"])
            .output();
        let (installed, running, details) = match out {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                let is_running = text.to_ascii_lowercase().contains("running");
                (true, is_running, format!("Scheduled Task: {WINDOWS_TASK_NAME}"))
            }
            _ => {
                let reg_ok = Command::new("reg")
                    .args([
                        "query",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v",
                        WINDOWS_TASK_NAME,
                    ])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if reg_ok {
                    (true, false, format!("Startup Registry Key: {WINDOWS_TASK_NAME}"))
                } else {
                    (false, false, "Not installed".to_string())
                }
            }
        };
        Ok(ServiceStatus {
            installed,
            running,
            platform: "Windows (Task Scheduler / Startup)",
            details,
        })
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let unit_path = linux_unit_path()?;
        let installed = unit_path.exists();
        let running = Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", LINUX_SERVICE_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let details = if installed {
            format!("systemd unit: {}", unit_path.display())
        } else {
            "Not installed".to_string()
        };
        Ok(ServiceStatus {
            installed,
            running,
            platform: "Linux (systemd --user)",
            details,
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Ok(ServiceStatus {
            installed: false,
            running: false,
            platform: "Unsupported",
            details: "Background service not supported on this OS".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_macos_plist() {
        let plist = render_macos_plist(
            Path::new("/usr/local/bin/aegis"),
            Some(Path::new("/tmp/aegis-data")),
            Path::new("/tmp/aegis-data/aegis-service.log"),
        );
        assert!(plist.contains("<string>io.aegis.blocker</string>"));
        assert!(plist.contains("<string>/usr/local/bin/aegis</string>"));
        assert!(plist.contains("<string>--data-dir</string>"));
        assert!(plist.contains("<string>/tmp/aegis-data</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
    }

    #[test]
    fn renders_valid_systemd_unit() {
        let unit = render_systemd_unit(
            Path::new("/usr/bin/aegis"),
            Some(Path::new("/var/lib/aegis")),
        );
        assert!(unit.contains("ExecStart=\"/usr/bin/aegis\" --data-dir \"/var/lib/aegis\""));
        assert!(unit.contains("WantedBy=default.target"));
    }
}
