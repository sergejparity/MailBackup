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
/// verified server at `origin`, and reported in the window. Without a
/// handler the webview has no destination on Linux and the download is lost.
///
/// Where they go (issue #65): with `ask_download_location`, where the user
/// picks in a native Save dialog (cancel cancels the download); otherwise,
/// or with no dialog available, in the download folder (see
/// `download_folder`) under a name no other file or running download has.
fn handle_download<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    event: DownloadEvent<'_>,
    origin: &str,
    reservations: &Reservations,
) -> bool {
    match event {
        DownloadEvent::Requested { url, destination } => {
            if url.origin().ascii_serialization() != origin {
                eprintln!("Refused a download from outside the MailBackup server: {}", url);
                reservations.refuse(url.as_str());
                return false;
            }
            // Read on each download, so a change in Settings applies at once
            let settings = mailbackup_core::config::AppConfig::load_or_create(None)
                .map(|cfg| cfg.settings)
                .unwrap_or_default();
            let dir = download_folder(settings.download_dir.as_deref(), destination);
            let name = destination.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "download".into());
            if settings.ask_download_location {
                match save_dialog(&dir, &name) {
                    SaveChoice::Chosen(path) => {
                        *destination = reservations.reserve_chosen(path, url.as_str());
                        return true;
                    }
                    SaveChoice::Cancelled => {
                        reservations.refuse(url.as_str());
                        toast(webview, "Download cancelled");
                        return false;
                    }
                    SaveChoice::Unavailable => eprintln!("No Save dialog available; saving to {}", dir.display()),
                }
            }
            *destination = reservations.reserve(&dir, &name, url.as_str());
            true
        }
        DownloadEvent::Finished { url, path, success } => {
            let message = match reservations.finish(url.as_str(), path, success) {
                // Refused or cancelled above, which said so already
                Finish::Refused => return true,
                Finish::Saved(Some(path)) => format!("Saved {}", path.display()),
                Finish::Saved(None) => "Download saved".to_string(),
                Finish::Failed => "The download failed".to_string(),
            };
            toast(webview, &message);
            true
        }
        _ => true,
    }
}

/// Shows `message` in the window for 6 seconds.
fn toast<R: tauri::Runtime>(webview: &tauri::Webview<R>, message: &str) {
    let js = format!("typeof showToast === 'function' && showToast({}, 6000)", serde_json::Value::from(message));
    let _ = webview.eval(&js);
}

/// The folder downloads go to: the configured one while it is a folder,
/// else the one the webview proposes (Downloads), else the home folder
/// (Linux without XDG user dirs, where the webview would use the working
/// directory).
fn download_folder(configured: Option<&std::path::Path>, proposed: &std::path::Path) -> std::path::PathBuf {
    if let Some(dir) = configured {
        if dir.is_dir() {
            return dir.to_path_buf();
        }
        eprintln!("The download folder {} doesn't exist; using the default", dir.display());
    }
    match proposed.parent() {
        Some(dir) if proposed.is_absolute() && dirs::download_dir().is_some() => dir.to_path_buf(),
        _ => mailbackup_core::config::default_download_dir(),
    }
}

enum SaveChoice {
    Chosen(std::path::PathBuf),
    Cancelled,
    /// No dialog could be shown (e.g. no zenity/kdialog on Linux)
    Unavailable,
}

/// A native Save dialog starting at `dir/name`. Blocks until it closes, so
/// the window waits like for any modal dialog. `dir` and `name` reach the
/// helper only as arguments or environment variables, never as script text.
fn save_dialog(dir: &std::path::Path, name: &str) -> SaveChoice {
    let chosen = |out: std::process::Output| match out.status.code() {
        Some(0) => {
            // PowerShell may start UTF-8 output with a byte order mark
            let path = std::path::PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().trim_start_matches('\u{feff}'));
            if path.is_absolute() { SaveChoice::Chosen(path) } else { SaveChoice::Unavailable }
        }
        Some(1) => SaveChoice::Cancelled,
        _ => SaveChoice::Unavailable,
    };
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; \
            Add-Type -AssemblyName System.Windows.Forms; \
            $d = New-Object System.Windows.Forms.SaveFileDialog; \
            $d.Title = 'Save download'; $d.InitialDirectory = $env:MAILBACKUP_SAVE_DIR; \
            $d.FileName = $env:MAILBACKUP_SAVE_NAME; $d.OverwritePrompt = $true; \
            $owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true }; \
            if ($d.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.FileName; exit 0 } else { exit 1 }";
        match std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("MAILBACKUP_SAVE_DIR", dir)
            .env("MAILBACKUP_SAVE_NAME", name)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            Ok(out) => chosen(out),
            Err(_) => SaveChoice::Unavailable,
        }
    }
    #[cfg(target_os = "macos")]
    {
        let script = "on run argv\n\
            POSIX path of (choose file name with prompt \"Save download\" default name (item 2 of argv) default location (POSIX file (item 1 of argv)))\n\
            end run";
        match std::process::Command::new("osascript").arg("-e").arg(script).arg(dir).arg(name).output() {
            // Cancel is AppleScript error -128
            Ok(out) if !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("-128") => SaveChoice::Cancelled,
            Ok(out) if out.status.success() => chosen(out),
            _ => SaveChoice::Unavailable,
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let start = dir.join(name);
        let attempts: [(&str, Vec<std::ffi::OsString>); 2] = [
            ("zenity", vec![
                "--file-selection".into(),
                "--save".into(),
                // Asks before replacing a file (zenity 3; zenity 4 always asks)
                "--confirm-overwrite".into(),
                "--title=Save download".into(),
                { let mut a = std::ffi::OsString::from("--filename="); a.push(&start); a },
            ]),
            ("kdialog", vec!["--title".into(), "Save download".into(), "--getsavefilename".into(), start.clone().into()]),
        ];
        for (program, args) in attempts {
            if let Ok(out) = std::process::Command::new(program).args(&args).output() {
                return chosen(out);
            }
        }
        SaveChoice::Unavailable
    }
}

/// Downloads in progress, by download URL (each carries its own single-use
/// ticket, so URLs don't repeat). The webviews only avoid names already on
/// disk, so two downloads of the same name started together would otherwise
/// get the same destination.
#[derive(Default)]
struct Reservations(std::sync::Mutex<std::collections::HashMap<String, Download>>);

enum Download {
    /// Being written to `path`; with `replaces`, a file the user chose to
    /// replace, which `path` (a `.part` file next to it) replaces once the
    /// download succeeds. The webviews won't write over a file, and the
    /// original stays intact if the download fails.
    Running { path: std::path::PathBuf, replaces: Option<std::path::PathBuf> },
    /// Refused or cancelled: its end isn't reported again
    Refused,
}

enum Finish {
    Refused,
    Saved(Option<std::path::PathBuf>),
    Failed,
}

impl Reservations {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Download>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn taken(downloads: &std::collections::HashMap<String, Download>, path: &std::path::Path) -> bool {
        path.exists()
            || downloads.values().any(|d| match d {
                Download::Running { path: p, replaces } => p == path || replaces.as_deref() == Some(path),
                Download::Refused => false,
            })
    }

    fn free_path(downloads: &std::collections::HashMap<String, Download>, dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let (stem, ext) = match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{}", ext)),
            _ => (name, String::new()),
        };
        let mut path = dir.join(name);
        let mut n = 1;
        while Self::taken(downloads, &path) {
            path = dir.join(format!("{} ({}){}", stem, n, ext));
            n += 1;
        }
        path
    }

    /// `dir/name`, or `dir/name (1)`, `dir/name (2)`… (before the extension)
    /// when that exists or another download has it.
    fn reserve(&self, dir: &std::path::Path, name: &str, key: &str) -> std::path::PathBuf {
        let mut downloads = self.lock();
        let path = Self::free_path(&downloads, dir, name);
        downloads.insert(key.to_string(), Download::Running { path: path.clone(), replaces: None });
        path
    }

    /// Where to write a download the user chose to save as `chosen`: there,
    /// or, when that file exists (the dialog asked before replacing it), a
    /// `.part` file next to it that replaces it on success.
    fn reserve_chosen(&self, chosen: std::path::PathBuf, key: &str) -> std::path::PathBuf {
        let mut downloads = self.lock();
        let (path, replaces) = match (chosen.exists(), chosen.parent(), chosen.file_name()) {
            (true, Some(dir), Some(name)) => {
                let part = format!("{}.part", name.to_string_lossy());
                (Self::free_path(&downloads, dir, &part), Some(chosen))
            }
            _ => (chosen, None),
        };
        downloads.insert(key.to_string(), Download::Running { path: path.clone(), replaces });
        path
    }

    fn refuse(&self, key: &str) {
        self.lock().insert(key.to_string(), Download::Refused);
    }

    /// Ends the download `key`; `path` and `success` are what the webview
    /// reports.
    fn finish(&self, key: &str, path: Option<std::path::PathBuf>, success: bool) -> Finish {
        let entry = self.lock().remove(key);
        match entry {
            Some(Download::Refused) => Finish::Refused,
            Some(Download::Running { path: part, replaces: Some(target) }) => {
                if success && std::fs::rename(&part, &target).is_ok() {
                    Finish::Saved(Some(target))
                } else {
                    let _ = std::fs::remove_file(&part);
                    Finish::Failed
                }
            }
            _ if success => Finish::Saved(path),
            _ => Finish::Failed,
        }
    }
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
                    let reservations = Reservations::default();
                    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                        // Never leave the verified server
                        .on_navigation(move |url| url.origin().ascii_serialization() == origin)
                        .on_download(move |webview, event| handle_download(&webview, event, &download_origin, &reservations))
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
    use super::{Finish, Reservations};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mailbackup-gui-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_on_disk_are_never_reused() {
        let dir = temp_dir("on-disk");
        let r = Reservations::default();
        std::fs::write(dir.join("résumé.pdf"), b"").unwrap();
        std::fs::write(dir.join("résumé (1).pdf"), b"").unwrap();
        assert_eq!(r.reserve(&dir, "résumé.pdf", "a"), dir.join("résumé (2).pdf"));
        std::fs::write(dir.join("README"), b"").unwrap();
        assert_eq!(r.reserve(&dir, "README", "b"), dir.join("README (1)"));
        std::fs::write(dir.join(".hidden"), b"").unwrap();
        assert_eq!(r.reserve(&dir, ".hidden", "c"), dir.join(".hidden (1)"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_downloads_of_one_name_get_distinct_destinations() {
        let dir = temp_dir("concurrent");
        let r = std::sync::Arc::new(Reservations::default());
        // Many downloads of the same name start before any file exists
        let paths: Vec<_> = (0..8)
            .map(|i| {
                let (r, dir) = (r.clone(), dir.clone());
                std::thread::spawn(move || r.reserve(&dir, "report.pdf", &format!("url-{}", i)))
            })
            .map(|t| t.join().unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(unique.len(), 8, "{:?}", paths);
        assert!(paths.contains(&dir.join("report.pdf")) && paths.contains(&dir.join("report (7).pdf")));

        // A finished download keeps its name taken through its file
        std::fs::write(dir.join("report.pdf"), b"").unwrap();
        let first = paths.iter().position(|p| *p == dir.join("report.pdf")).unwrap();
        assert!(matches!(r.finish(&format!("url-{}", first), Some(dir.join("report.pdf")), true), Finish::Saved(Some(_))));
        assert_eq!(r.reserve(&dir, "report.pdf", "late"), dir.join("report (8).pdf"));
        // A failed download (no file) frees its name for the next one
        let failed = paths.iter().position(|p| *p == dir.join("report (3).pdf")).unwrap();
        assert!(matches!(r.finish(&format!("url-{}", failed), None, false), Finish::Failed));
        assert_eq!(r.reserve(&dir, "report.pdf", "retry"), dir.join("report (3).pdf"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_chosen_existing_file_is_replaced_only_by_a_complete_download() {
        let dir = temp_dir("replace");
        let r = Reservations::default();
        let target = dir.join("notes.txt");
        // A new file: written in place
        assert_eq!(r.reserve_chosen(target.clone(), "new"), target);
        std::fs::write(&target, b"old").unwrap();
        assert!(matches!(r.finish("new", Some(target.clone()), true), Finish::Saved(Some(_))));

        // Replacing it: written next to it, then moved over it
        let part = r.reserve_chosen(target.clone(), "ok");
        assert_eq!(part, dir.join("notes.txt.part"));
        // Meanwhile nothing else may take the target's name
        assert_eq!(r.reserve(&dir, "notes.txt", "other"), dir.join("notes (1).txt"));
        std::fs::write(&part, b"new").unwrap();
        assert!(matches!(r.finish("ok", Some(part.clone()), true), Finish::Saved(Some(p)) if p == target));
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!part.exists());

        // A failed replacement leaves the original as it was
        let part = r.reserve_chosen(target.clone(), "fail");
        std::fs::write(&part, b"partial").unwrap();
        assert!(matches!(r.finish("fail", None, false), Finish::Failed));
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!part.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refused_downloads_end_silently() {
        let r = Reservations::default();
        r.refuse("cancelled");
        assert!(matches!(r.finish("cancelled", None, false), Finish::Refused));
        // Unknown downloads are reported as the webview says
        assert!(matches!(r.finish("unknown", None, false), Finish::Failed));
    }
}
