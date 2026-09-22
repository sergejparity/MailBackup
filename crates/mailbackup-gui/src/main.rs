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
    let port = 8765;
    start_background_server(port);

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


