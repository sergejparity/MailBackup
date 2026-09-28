#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::time::Duration;
use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};

fn is_server_running(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_millis(200),
    )
    .is_ok()
}

fn start_background_server(port: u16) {
    if is_server_running(port) {
        println!("MailBackup Studio server already running on port {}", port);
        return;
    }

    println!("Starting embedded background server on port {}...", port);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for background server");

        rt.block_on(async move {
            if let Err(e) = mailbackup_server::start_server(Some(port)).await {
                eprintln!("Background server error: {}", e);
            }
        });
    });

    // Wait until port is ready (up to 4 seconds)
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(100));
        if is_server_running(port) {
            println!("Background server is ready!");
            break;
        }
    }
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
    start_background_server(port_num);

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


