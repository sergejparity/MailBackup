#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

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

/// Downloads in the window (attachments, .eml, mbox, logs): only from the
/// verified server at `origin`, saved where the webview proposes (the
/// Downloads folder, with ` (1)` etc. added rather than overwriting), and
/// reported in the window. Without a handler the webview has no destination
/// on Linux and the download is lost or lands in the working directory.
fn handle_download<R: tauri::Runtime>(webview: &tauri::Webview<R>, event: DownloadEvent<'_>, origin: &str) -> bool {
    match event {
        DownloadEvent::Requested { url, destination } => {
            let allowed = url.origin().ascii_serialization() == origin;
            if !allowed {
                eprintln!("Refused a download from outside the MailBackup server: {}", url);
            } else if dirs::download_dir().is_none() {
                // No Downloads folder (Linux without XDG user dirs): the
                // webview would fall back to the working directory
                if let (Some(home), Some(name)) = (dirs::home_dir(), destination.file_name()) {
                    *destination = unused_path(&home, &name.to_string_lossy());
                }
            }
            allowed
        }
        DownloadEvent::Finished { path, success, .. } => {
            let message = match (success, path.as_deref()) {
                (true, Some(path)) => format!("Saved {}", path.display()),
                (true, None) => "Download saved".to_string(),
                (false, _) => "The download failed".to_string(),
            };
            let js = format!("typeof showToast === 'function' && showToast({}, 6000)", serde_json::Value::from(message));
            let _ = webview.eval(&js);
            true
        }
        _ => true,
    }
}

/// `dir/name`, or `dir/name (1)`, `dir/name (2)`… (before the extension)
/// when that exists, the way the webviews name downloads.
fn unused_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{}", ext)),
        _ => (name, String::new()),
    };
    let mut path = dir.join(name);
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("{} ({}){}", stem, n, ext));
        n += 1;
    }
    path
}

fn show_main_window<R: tauri::Runtime>(manager: &impl Manager<R>) {
    if let Some(window) = manager.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Tray "Sync Now": presses the window's own Sync Now button, which syncs
/// every account that isn't a read-only archive through the verified server
/// the window shows (embedded or already running) with the UI's token. The
/// window keeps running while hidden in the tray. On the error page there is
/// no server to sync with, so the window is shown instead.
fn sync_from_tray<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    // The UI is served from 127.0.0.1; the error page is an app page
    // (tauri://localhost, or http://tauri.localhost on Windows)
    let on_server = window.url().is_ok_and(|url| url.host_str() == Some("127.0.0.1"));
    if !on_server {
        show_main_window(app);
        return;
    }
    if let Err(e) = window.eval("document.getElementById('btn-sync-all')?.click()") {
        eprintln!("Couldn't start the sync from the tray: {}", e);
    }
}

/// The tray icon and its menu. Built in `setup`, never declared in
/// tauri.conf.json: a configured tray is created before plugins run, so a
/// second instance would show one before single-instance hands it off.
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Open Studio").build(app)?;
    let sync = MenuItemBuilder::with_id("sync", "Sync Now").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit MailBackup").build(app)?;
    let menu = MenuBuilder::new(app).items(&[&show, &sync]).separator().item(&quit).build()?;
    TrayIconBuilder::with_id("main")
        .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .menu(&menu)
        // Left click opens the window; the menu is on right click
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "quit" => app.exit(0),
            "show" => show_main_window(app),
            "sync" => sync_from_tray(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
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
                if let Some(val) = args.next()
                    && let Ok(p) = val.parse::<u16>() {
                    port = Some(p);
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

    // Nothing with side effects (server, config, autostart, tray) may run
    // before the single-instance check, or a second launch would do it too
    // before handing off. Tauri runs plugin setup (in `Builder::build`)
    // before `setup` below, and creates a tray declared in the config before
    // plugins, so all of it lives in `setup`, which a second instance never
    // reaches (the plugin exits it).
    tauri::Builder::default()
        // One desktop instance per user: a later launch (desktop link, Start
        // menu, autostart) hands off to the running one, which shows its
        // window, and then exits without opening a window of its own.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }))
        .setup(move |app| {
            let server = genuine_server(port_num);
            if let Err(e) = &server {
                eprintln!("Not showing the MailBackup UI: {}", e);
            }

            // Sync OS autostart registration if configured
            if let Ok(cfg) = mailbackup_core::config::AppConfig::load_or_create(None)
                && cfg.settings.autostart {
                let _ = mailbackup_core::autostart::set_autostart(true);
            }

            build_tray(app)?;

            // The window is created here, only for the verified server. It
            // gets no capabilities (no IPC): the UI only talks HTTP to it.
            let builder = match server {
                Ok(port) => {
                    let origin = format!("http://127.0.0.1:{}", port);
                    let url = format!("{}/", origin).parse().expect("valid URL");
                    let download_origin = origin.clone();
                    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                        // Never leave the verified server
                        .on_navigation(move |url| url.origin().ascii_serialization() == origin)
                        .on_download(move |webview, event| handle_download(&webview, event, &download_origin))
                }
                // The error page downloads nothing
                Err(_) => WebviewWindowBuilder::new(app, "main", WebviewUrl::App("gui-error.html".into()))
                    .on_download(|_, _| false),
            };
            builder
                // Nor through window.open / target=_blank: the UI opens no
                // windows, so every request is refused
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .title("MailBackup Studio")
                .inner_size(1280.0, 840.0)
                .resizable(true)
                .build()?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let close_to_tray = mailbackup_core::config::AppConfig::load_or_create(None)
                    .map(|cfg| cfg.settings.close_to_tray)
                    .unwrap_or(true);

                if close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::unused_path;

    #[test]
    fn unused_path_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("mailbackup-gui-unused-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unused_path(&dir, "résumé.pdf"), dir.join("résumé.pdf"));
        std::fs::write(dir.join("résumé.pdf"), b"").unwrap();
        assert_eq!(unused_path(&dir, "résumé.pdf"), dir.join("résumé (1).pdf"));
        std::fs::write(dir.join("résumé (1).pdf"), b"").unwrap();
        assert_eq!(unused_path(&dir, "résumé.pdf"), dir.join("résumé (2).pdf"));
        std::fs::write(dir.join("README"), b"").unwrap();
        assert_eq!(unused_path(&dir, "README"), dir.join("README (1)"));
        std::fs::write(dir.join(".hidden"), b"").unwrap();
        assert_eq!(unused_path(&dir, ".hidden"), dir.join(".hidden (1)"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
