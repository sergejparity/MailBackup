#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;
use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};

/// The port of a server the window may show: a running MailBackup server of
/// this user that proves itself (see `mailbackup_server::runtime`), else one
/// started here. A process holding the port that can't prove itself is never
/// shown; the embedded server then runs on a free port instead.
fn genuine_server(port: u16) -> Result<u16, String> {
    let config_path = mailbackup_core::config::default_config_path();
    let config_dir = config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    if mailbackup_server::runtime::verify_genuine(&config_dir, port).is_some() {
        println!("Using the MailBackup server already running on port {}", port);
        return Ok(port);
    }
    let bound = match start_embedded_server(port) {
        Ok(bound) => bound,
        Err(e) => {
            eprintln!(
                "Port {} is in use by a process that isn't a verified MailBackup server ({}). Starting on a free port instead.",
                port, e
            );
            start_embedded_server(0)?
        }
    };
    mailbackup_server::runtime::verify_genuine(&config_dir, bound)
        .map(|_| bound)
        .ok_or_else(|| format!("The server on port {} couldn't be verified", bound))
}

/// Starts the server on its own thread; returns the port it bound (`0` binds
/// a free one) or why it couldn't start.
fn start_embedded_server(port: u16) -> Result<u16, String> {
    println!("Starting embedded background server on port {}...", port);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for background server");
        rt.block_on(async move {
            if let Err(e) = mailbackup_server::run_server(Some(port), None, Some(ready_tx)).await {
                eprintln!("Background server error: {}", e);
            }
        });
    });
    ready_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| "the server didn't start in time".to_string())?
}

fn show_main_window<R: tauri::Runtime>(manager: &impl Manager<R>) {
    if let Some(window) = manager.get_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn main() {
    let mut is_headless = false;
    let mut force_gui = false;
    let mut port: Option<u16> = None;
    let mut config_path: Option<std::path::PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--service" | "--headless" => {
                is_headless = true;
            }
            "--config" | "-c" => {
                is_headless = true;
                if let Some(val) = args.next() {
                    config_path = Some(std::path::PathBuf::from(val));
                }
            }
            "--port" | "-p" => {
                if let Some(val) = args.next() {
                    if let Ok(p) = val.parse::<u16>() {
                        port = Some(p);
                    }
                }
            }
            "--gui" => {
                force_gui = true;
            }
            "--help" | "-h" => {
                println!("MailBackup Studio");
                println!();
                println!("Usage: mailbackup-gui [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --service, --headless    Run in headless background service mode (no GUI)");
                println!("  -c, --config <PATH>      Path to config.yaml configuration file");
                println!("  -p, --port <PORT>        Override HTTP/REST API web port (default: 8765)");
                println!("  --gui                    Force GUI desktop window mode");
                println!("  -h, --help               Display this help message");
                return;
            }
            _ => {}
        }
    }

    // Windows safety check: if running as SYSTEM account or inside systemprofile,
    // Session 0 isolation prevents GUI display and Edge WebView2 cannot initialize.
    // Force headless mode in this context.
    #[cfg(windows)]
    let is_system_account = {
        std::env::var("USERNAME")
            .map(|u| u.eq_ignore_ascii_case("SYSTEM"))
            .unwrap_or(false)
            || dirs::home_dir()
                .map(|p| p.to_string_lossy().to_lowercase().contains("systemprofile"))
                .unwrap_or(false)
    };
    #[cfg(not(windows))]
    let is_system_account = false;

    if (is_headless || is_system_account) && !force_gui {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();

        println!("MailBackup Studio starting in headless service mode...");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for headless service");

        if let Err(e) = rt.block_on(async {
            mailbackup_server::start_server_with_options(port, config_path).await
        }) {
            eprintln!("Headless service error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let port_num = port.unwrap_or(8765);
    let server = genuine_server(port_num);
    if let Err(e) = &server {
        eprintln!("Not showing the MailBackup UI: {}", e);
    }

    // Sync OS autostart registration if configured
    if let Ok(cfg) = mailbackup_core::config::AppConfig::load_or_create(None) {
        if cfg.settings.autostart {
            let _ = mailbackup_core::autostart::set_autostart(true);
        }
    }

    let quit = CustomMenuItem::new("quit".to_string(), "Quit MailBackup");
    let show = CustomMenuItem::new("show".to_string(), "Open Studio");
    let sync = CustomMenuItem::new("sync".to_string(), "Sync Now");
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(sync)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);

    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .setup(move |app| {
            // The window is created here, only for the verified server
            let builder = match server {
                Ok(port) => {
                    let origin = format!("http://127.0.0.1:{}", port);
                    let url = format!("{}/", origin).parse().expect("valid URL");
                    tauri::WindowBuilder::new(app, "main", tauri::WindowUrl::External(url))
                        // Never leave the verified server
                        .on_navigation(move |url| url.origin().ascii_serialization() == origin)
                }
                Err(_) => tauri::WindowBuilder::new(app, "main", tauri::WindowUrl::App("gui-error.html".into())),
            };
            builder.title("MailBackup Studio").inner_size(1280.0, 840.0).resizable(true).build()?;
            Ok(())
        })
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                show_main_window(app);
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    std::process::exit(0);
                }
                "show" => {
                    show_main_window(app);
                }
                "sync" => {
                    println!("Sync triggered from system tray");
                }
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                let close_to_tray = mailbackup_core::config::AppConfig::load_or_create(None)
                    .map(|cfg| cfg.settings.close_to_tray)
                    .unwrap_or(true);

                if close_to_tray {
                    api.prevent_close();
                    let _ = event.window().hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}


