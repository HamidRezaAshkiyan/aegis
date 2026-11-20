use crate::api::AppState;
use std::sync::Arc;
use tokio::sync::watch;

pub struct TrayContext {
    pub state: Arc<AppState>,
    pub dashboard_url: String,
    pub shutdown_tx: watch::Sender<bool>,
    pub shutdown_rx: watch::Receiver<bool>,
}

/// Generate a crisp 32x32 RGBA shield icon programmatically so no external asset is required.
pub fn build_shield_icon_rgba() -> (Vec<u8>, u32, u32) {
    let size: u32 = 32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let nx = (x as f32 - 15.5) / 13.0;
            let ny = (y as f32 - 15.5) / 14.0;

            // Classic shield silhouette
            let inside = if ny < -0.75 || ny > 0.92 {
                false
            } else if ny < 0.05 {
                nx.abs() <= 0.85
            } else {
                let t = (ny - 0.05) / 0.87;
                let max_x = 0.85 * (1.0 - t * t);
                nx.abs() <= max_x
            };

            if inside {
                let idx = ((y * size + x) * 4) as usize;
                // Inner border vs fill gradient (blue -> cyan)
                let grad = ((y as f32) / (size as f32)).clamp(0.0, 1.0);
                let r = (37.0 * (1.0 - grad) + 6.0 * grad) as u8;
                let g = (99.0 * (1.0 - grad) + 182.0 * grad) as u8;
                let b = (235.0 * (1.0 - grad) + 212.0 * grad) as u8;
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 255;
            }
        }
    }

    (rgba, size, size)
}

pub fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn run_tray_loop(ctx: TrayContext) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};
    use tao::event::Event;
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    #[cfg(target_os = "macos")]
    use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
    use tracing::{info, warn};
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut event_loop = EventLoopBuilder::new().build();
    #[cfg(target_os = "macos")]
    event_loop.set_activation_policy(ActivationPolicy::Accessory);

    let (rgba, width, height) = build_shield_icon_rgba();
    let icon = Icon::from_rgba(rgba, width, height)?;

    let initial_sys_proxy = ctx.state.config.read().unwrap().system_proxy_enabled;

    let item_status = MenuItem::new("Aegis Active — 0 blocked", false, None);
    let item_open = MenuItem::new("Open Dashboard", true, None);
    let item_pause_5 = MenuItem::new("Pause 5 minutes", true, None);
    let item_pause_15 = MenuItem::new("Pause 15 minutes", true, None);
    let item_pause_60 = MenuItem::new("Pause 1 hour", true, None);
    let item_resume = MenuItem::new("Resume Protection", true, None);
    let item_sys_proxy = CheckMenuItem::new("System Proxy", true, initial_sys_proxy, None);
    let item_quit = MenuItem::new("Quit Aegis", true, None);

    let menu = Menu::new();
    menu.append(&item_status)?;
    menu.append(&item_open)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_pause_5)?;
    menu.append(&item_pause_15)?;
    menu.append(&item_pause_60)?;
    menu.append(&item_resume)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_sys_proxy)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_quit)?;

    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Aegis — Ad & Tracker Blocker")
        .with_icon(icon)
        .build()?;

    let id_open = item_open.id().clone();
    let id_pause_5 = item_pause_5.id().clone();
    let id_pause_15 = item_pause_15.id().clone();
    let id_pause_60 = item_pause_60.id().clone();
    let id_resume = item_resume.id().clone();
    let id_sys_proxy = item_sys_proxy.id().clone();
    let id_quit = item_quit.id().clone();

    let menu_rx = MenuEvent::receiver();
    let mut last_refresh = Instant::now() - Duration::from_secs(10);

    info!("Aegis system tray / menu bar icon initialized");

    event_loop.run(move |event, _, control_flow| {
        // Keep the tray icon alive for the lifetime of the event loop
        let _ = &tray_icon;

        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(250));

        if *ctx.shutdown_rx.borrow() {
            *control_flow = ControlFlow::Exit;
            return;
        }

        if let Event::MainEventsCleared = event {
            // Drain tray menu events
            while let Ok(ev) = menu_rx.try_recv() {
                if ev.id == id_open {
                    open_in_browser(&ctx.dashboard_url);
                } else if ev.id == id_pause_5 {
                    ctx.state.engine.pause_for_seconds(300);
                    last_refresh = Instant::now() - Duration::from_secs(10);
                } else if ev.id == id_pause_15 {
                    ctx.state.engine.pause_for_seconds(900);
                    last_refresh = Instant::now() - Duration::from_secs(10);
                } else if ev.id == id_pause_60 {
                    ctx.state.engine.pause_for_seconds(3600);
                    last_refresh = Instant::now() - Duration::from_secs(10);
                } else if ev.id == id_resume {
                    ctx.state.engine.resume();
                    last_refresh = Instant::now() - Duration::from_secs(10);
                } else if ev.id == id_sys_proxy {
                    let want = item_sys_proxy.is_checked();
                    let (http_listen, socks_listen) = {
                        let cfg = ctx.state.config.read().unwrap();
                        (
                            cfg.proxy.http_listen.clone(),
                            cfg.proxy.socks5_listen.clone(),
                        )
                    };
                    let res = if want {
                        core_os::enable_system_proxy(&ctx.state.data_dir, &http_listen, &socks_listen)
                    } else {
                        core_os::disable_system_proxy(&ctx.state.data_dir)
                    };
                    match res {
                        Ok(()) => {
                            ctx.state.config.write().unwrap().system_proxy_enabled = want;
                            ctx.state.save_config();
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to toggle OS system proxy from tray");
                            item_sys_proxy.set_checked(!want);
                        }
                    }
                } else if ev.id == id_quit {
                    info!("Quit requested from system tray");
                    let _ = ctx.shutdown_tx.send(true);
                    *control_flow = ControlFlow::Exit;
                    return;
                }
            }

            // Periodically refresh blocked count, pause state, and system proxy checkmark
            if last_refresh.elapsed() >= Duration::from_secs(2) {
                last_refresh = Instant::now();
                let summary = ctx.state.stats.summary();
                let paused = ctx.state.engine.paused_until().is_some();
                let label = if paused {
                    format!("Aegis Paused — {} blocked", summary.total_blocked)
                } else {
                    format!("Aegis Active — {} blocked", summary.total_blocked)
                };
                item_status.set_text(&label);
                let _ = tray_icon.set_tooltip(Some(&label));

                let sys_proxy_on = ctx.state.config.read().unwrap().system_proxy_enabled;
                if item_sys_proxy.is_checked() != sys_proxy_on {
                    item_sys_proxy.set_checked(sys_proxy_on);
                }
            }
        }
    });
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn run_tray_loop(mut ctx: TrayContext) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let _ = ctx.shutdown_rx.changed().await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shield_icon_has_expected_dimensions_and_non_empty_pixels() {
        let (rgba, w, h) = build_shield_icon_rgba();
        assert_eq!(w, 32);
        assert_eq!(h, 32);
        assert_eq!(rgba.len(), (w * h * 4) as usize);
        let opaque_pixels = rgba.chunks_exact(4).filter(|px| px[3] == 255).count();
        assert!(opaque_pixels > 100);
    }
}
