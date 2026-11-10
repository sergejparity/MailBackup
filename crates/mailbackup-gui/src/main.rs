#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

/// The private protocol the window loads the UI through when the server
/// runs in this process (issue #66): no socket, so nothing else can reach it.
const PROTOCOL: &str = "mailbackup";

/// The origin of [`PROTOCOL`] pages, which differs by platform (Tauri maps
/// custom protocols to `http://<name>.localhost` on Windows).
#[cfg(windows)]
const PROTOCOL_ORIGIN: &str = "http://mailbackup.localhost";
#[cfg(not(windows))]
const PROTOCOL_ORIGIN: &str = "mailbackup://localhost";

/// The server built in this process, for the protocol handler.
static SERVER: std::sync::OnceLock<std::sync::Arc<mailbackup_server::Server>> = std::sync::OnceLock::new();

/// The URL the window shows: a running MailBackup server of this user on
/// `port` that proves itself (the background service; see
/// `mailbackup_server::runtime`), shown over loopback so two schedulers
/// never share one archive; else a server built here, shown through
/// [`PROTOCOL`] and listening on `port` only while `web_server_enabled`.
fn ui_url(port: u16) -> Result<tauri::Url, String> {
    let config_path = mailbackup_core::config::default_config_path();
    let config_dir = config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    if mailbackup_server::runtime::verify_genuine(&config_dir, port).is_some() {
        println!("Using the MailBackup server already running on port {}", port);
        // Logged in for the user with a single-use ticket, only after the
        // server proved itself (issue #70); without one the window shows the
        // login page
        let path = mailbackup_server::runtime::desktop_login_path(&config_dir, port).unwrap_or_else(|| "/".to_string());
        return format!("http://127.0.0.1:{}{}", port, path).parse().map_err(|e| format!("{}", e));
    }
    let server = tauri::async_runtime::block_on(mailbackup_server::Server::build(None, Some(port), false))
        .map_err(|e| e.to_string())?;
    let web_enabled = mailbackup_core::config::AppConfig::load_or_create(None)
        .map(|cfg| cfg.settings.web_server_enabled)
        .unwrap_or(true);
    if web_enabled {
        // Browser access only; the window doesn't need the port
        if let Err(e) = tauri::async_runtime::block_on(server.web().start()) {
            eprintln!("Browser access is unavailable: port {} couldn't be opened ({})", port, e);
        }
    } else {
        println!("Web server off: no port is opened");
    }
    let _ = SERVER.set(server);
    format!("{}/", PROTOCOL_ORIGIN).parse().map_err(|e| format!("{}", e))
}

/// Answers a [`PROTOCOL`] request from the in-process server.
fn serve_protocol_request(request: tauri::http::Request<Vec<u8>>, responder: tauri::UriSchemeResponder) {
    let Some(server) = SERVER.get().cloned() else {
        let mut res = tauri::http::Response::new(b"MailBackup isn't running in this window".to_vec());
        *res.status_mut() = tauri::http::StatusCode::SERVICE_UNAVAILABLE;
        responder.respond(res);
        return;
    };
    tauri::async_runtime::spawn(async move {
        responder.respond(server.handle_in_process(request, PROTOCOL_ORIGIN).await);
    });
}

/// Whether `url` belongs to the UI at `ui` (same scheme, host and port;
/// `Url::origin` can't compare custom-protocol URLs, which are opaque).
fn same_origin(url: &tauri::Url, ui: &tauri::Url) -> bool {
    url.scheme() == ui.scheme() && url.host_str() == ui.host_str() && url.port_or_known_default() == ui.port_or_known_default()
}

/// The URL of the UI the window shows, for checks outside the window
/// builder (tray).
struct UiUrl(tauri::Url);

/// Downloads in the window (attachments, .eml, mbox, logs): only from the
/// UI at `ui` (the verified or in-process server), and reported in the
/// window. Without a
/// handler the webview has no destination on Linux and the download is lost.
///
/// Where they go (issue #65): with `ask_download_location`, where the user
/// picks in a native Save dialog (cancel cancels the download); otherwise,
/// or with no dialog available, in the download folder (see
/// `download_folder`) under a name no other file or running download has.
fn handle_download<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    event: DownloadEvent<'_>,
    ui: &tauri::Url,
    reservations: &Reservations,
) -> bool {
    match event {
        DownloadEvent::Requested { url, destination } => {
            if !same_origin(&url, ui) {
                eprintln!("Refused a download from outside the MailBackup server: {}", url);
                reservations.refuse(url.as_str());
                return false;
            }
            let name = destination.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "download".into());
            match choose_destination(&name, Some(destination), reservations, url.as_str()) {
                Some(path) => {
                    *destination = path;
                    true
                }
                None => {
                    let _ = webview.eval(toast_script("Download cancelled"));
                    false
                }
            }
        }
        DownloadEvent::Finished { url, path, success } => {
            let finish = reservations.finish(url.as_str(), path, success);
            let mark = mark_saved(url.path(), &finish);
            if let Some(message) = finish_message(finish, mark) {
                let _ = webview.eval(toast_script(&message));
            }
            true
        }
        _ => true,
    }
}

/// Where a download named `name` goes, reserved for `key` (see the
/// settings in `handle_download`); `None` when the user cancelled the Save
/// dialog (then `key` is refused). May show a modal dialog. `proposed` is
/// the webview's own choice, if any.
fn choose_destination(
    name: &str,
    proposed: Option<&std::path::Path>,
    reservations: &Reservations,
    key: &str,
) -> Option<std::path::PathBuf> {
    // Read on each download, so a change in Settings applies at once
    let settings = mailbackup_core::config::AppConfig::load_or_create(None)
        .map(|cfg| cfg.settings)
        .unwrap_or_default();
    let dir = download_folder(settings.download_dir.as_deref(), proposed);
    if settings.ask_download_location {
        match save_dialog(&dir, name) {
            SaveChoice::Chosen(path) => return Some(reservations.reserve_chosen(path, key)),
            SaveChoice::Cancelled => {
                reservations.refuse(key);
                return None;
            }
            SaveChoice::Unavailable => eprintln!("No Save dialog available; saving to {}", dir.display()),
        }
    }
    Some(reservations.reserve(&dir, name, key))
}

/// Marks a saved attachment or message as downloaded from the internet
/// (issue #75), on the final file (after a `.part` was renamed over the
/// one it replaces). Returns a warning for the toast if marking failed; an
/// unsupported file system only gets a log line.
fn mark_saved(url_path: &str, finish: &Finish) -> Option<String> {
    let Finish::Saved(Some(path)) = finish else { return None };
    if !mailbackup_core::download_mark::is_mail_content(url_path) {
        return None;
    }
    match mailbackup_core::download_mark::mark_from_internet(path) {
        Ok(mailbackup_core::download_mark::Mark::Unsupported(why)) => {
            eprintln!("{} can't be marked as downloaded from the internet: {}", path.display(), why);
            None
        }
        Ok(_) => None,
        Err(e) => Some(format!("it couldn't be marked as downloaded from the internet ({}); open it with care", e)),
    }
}

/// The toast for a download's end; none for a refused or cancelled one,
/// which said so already. `warning` is added to a successful save.
fn finish_message(finish: Finish, warning: Option<String>) -> Option<String> {
    let warning = warning.map(|w| format!("; {}", w)).unwrap_or_default();
    match finish {
        Finish::Refused => None,
        Finish::Saved(Some(path)) => Some(format!("Saved {}{}", path.display(), warning)),
        Finish::Saved(None) => Some(format!("Download saved{}", warning)),
        Finish::Failed => Some("The download failed".to_string()),
    }
}

/// Script showing `message` in the window for 6 seconds.
fn toast_script(message: &str) -> String {
    format!("typeof showToast === 'function' && showToast({}, 6000)", serde_json::Value::from(message))
}

/// A download of the in-process UI (issue #66): WebKitGTK can't download
/// from a custom protocol, so the window's navigation to a download URL is
/// stopped and the file fetched from the in-process server here, then saved
/// like any download (folder, Save dialog, free names, toast).
fn download_in_process<R: tauri::Runtime>(app: tauri::AppHandle<R>, url: tauri::Url, reservations: std::sync::Arc<Reservations>) {
    tauri::async_runtime::spawn(async move {
        let notify = |message: &str| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.eval(toast_script(message));
            }
        };
        let Some(server) = SERVER.get().cloned() else {
            return;
        };
        let request = match tauri::http::Request::get(url.as_str()).body(Vec::new()) {
            Ok(request) => request,
            Err(_) => return,
        };
        // Authorized (and its ticket used up) now, before the Save dialog;
        // the body streams to the file afterwards, never all in memory (issue #78)
        let response = server.handle_in_process_streaming(request, PROTOCOL_ORIGIN).await;
        if !response.status().is_success() {
            eprintln!("Download of {} failed: {}", url.path(), response.status());
            notify("The download failed");
            return;
        }
        let name = response
            .headers()
            .get(tauri::http::header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .and_then(disposition_filename)
            .unwrap_or_else(|| "download".to_string());
        let key = url.as_str().to_string();
        // The Save dialog blocks, so not on the async runtime
        let chosen = {
            let (reservations, key) = (reservations.clone(), key.clone());
            tauri::async_runtime::spawn_blocking(move || choose_destination(&name, None, &reservations, &key)).await
        };
        let Ok(Some(path)) = chosen else {
            // Dropping the response stops whatever was producing it
            reservations.finish(&key, None, false);
            notify("Download cancelled");
            return;
        };
        match mailbackup_server::streaming::save_body(response.into_body(), &path).await {
            Ok(()) => {
                let finish = reservations.finish(&key, Some(path), true);
                let mark = mark_saved(url.path(), &finish);
                if let Some(message) = finish_message(finish, mark) {
                    notify(&message);
                }
            }
            Err(e) => {
                eprintln!("Couldn't save {}: {}", path.display(), e);
                // Whatever is at `path` now isn't ours to remove
                reservations.abandon(&key);
                notify("The download failed");
            }
        }
    });
}

/// What the #68 regression tests write through: the production path
/// (`streaming::save_body`), which creates the file exclusively and removes
/// only a file it created.
#[cfg(test)]
fn write_new_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    tauri::async_runtime::block_on(mailbackup_server::streaming::save_body(bytes.to_vec().into(), path))
}

/// The file name a `Content-Disposition` header gives (`filename*` in
/// UTF-8 first, then `filename`), reduced to a plain name: no folders.
fn disposition_filename(value: &str) -> Option<String> {
    let param = |key: &str| {
        value.split(';').map(str::trim).find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim().eq_ignore_ascii_case(key).then(|| v.trim().to_string())
        })
    };
    let decoded = param("filename*")
        .and_then(|v| {
            let encoded = v.strip_prefix("UTF-8''").or_else(|| v.strip_prefix("utf-8''"))?.to_string();
            percent_decode(&encoded)
        })
        .or_else(|| param("filename").map(|v| v.trim_matches('"').to_string()))?;
    let name = decoded.rsplit(['/', '\\']).next().unwrap_or("").trim().to_string();
    (!name.is_empty() && name != "." && name != "..").then_some(name)
}

fn percent_decode(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The folder downloads go to: the configured one while it is a folder,
/// else the one the webview proposes (Downloads), else the default
/// (Downloads, or the home folder on Linux without XDG user dirs, where the
/// webview would use the working directory).
fn download_folder(configured: Option<&std::path::Path>, proposed: Option<&std::path::Path>) -> std::path::PathBuf {
    if let Some(dir) = configured {
        if dir.is_dir() {
            return dir.to_path_buf();
        }
        eprintln!("The download folder {} doesn't exist; using the default", dir.display());
    }
    match proposed.and_then(|p| p.parent().filter(|_| p.is_absolute())) {
        Some(dir) if dirs::download_dir().is_some() => dir.to_path_buf(),
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
        let Ok(powershell) = mailbackup_core::service::trusted_program("powershell") else {
            return SaveChoice::Unavailable;
        };
        match std::process::Command::new(powershell)
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
        let Ok(osascript) = mailbackup_core::service::trusted_program("osascript") else {
            return SaveChoice::Unavailable;
        };
        match std::process::Command::new(osascript).arg("-e").arg(script).arg(dir).arg(name).output() {
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
            // From fixed system folders only, never from PATH (issue #75)
            let Ok(program) = mailbackup_core::service::trusted_program(program) else { continue };
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

    /// Where to write a download the user chose to save as `chosen`: there;
    /// when another running download has that name, the next free name
    /// (the dialog couldn't ask about a file that didn't exist yet); when
    /// the file exists (the dialog asked before replacing it), a `.part`
    /// file next to it that replaces it on success.
    fn reserve_chosen(&self, chosen: std::path::PathBuf, key: &str) -> std::path::PathBuf {
        let mut downloads = self.lock();
        let in_flight = downloads.values().any(|d| match d {
            Download::Running { path, replaces } => *path == chosen || replaces.as_ref() == Some(&chosen),
            Download::Refused => false,
        });
        let (path, replaces) = match (chosen.parent(), chosen.file_name()) {
            (Some(dir), Some(name)) if in_flight => (Self::free_path(&downloads, dir, &name.to_string_lossy()), None),
            (Some(dir), Some(name)) if chosen.exists() => {
                let part = format!("{}.part", name.to_string_lossy());
                (Self::free_path(&downloads, dir, &part), Some(chosen))
            }
            _ => (chosen, None),
        };
        downloads.insert(key.to_string(), Download::Running { path: path.clone(), replaces });
        path
    }

    /// Ends the download `key` without touching any file: none of them is
    /// known to be its own (it couldn't create its file).
    fn abandon(&self, key: &str) {
        self.lock().remove(key);
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
                // On failure the `.part` file is left alone: whoever wrote it
                // removes their own partial file (the webviews do, and
                // `streaming::save_body` does), and if the failure was that another
                // program had created it first, it isn't ours
                if success && std::fs::rename(&part, &target).is_ok() {
                    Finish::Saved(Some(target))
                } else {
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
    // Not on the error page (an app page: tauri://localhost, or
    // http://tauri.localhost on Windows)
    let on_server = match (window.url(), app.try_state::<UiUrl>()) {
        (Ok(url), Some(ui)) => same_origin(&url, &ui.0),
        _ => false,
    };
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
        // Answered only once `setup` built the server (else 503)
        .register_asynchronous_uri_scheme_protocol(PROTOCOL, |_ctx, request, responder| {
            serve_protocol_request(request, responder)
        })
        .setup(move |app| {
            let ui = ui_url(port_num);
            if let Err(e) = &ui {
                eprintln!("Not showing the MailBackup UI: {}", e);
            }

            // Sync OS autostart registration if configured
            if let Ok(cfg) = mailbackup_core::config::AppConfig::load_or_create(None)
                && cfg.settings.autostart {
                let _ = mailbackup_core::autostart::set_autostart(true);
            }

            build_tray(app)?;

            // The window is created here, only for the verified or in-process
            // server. It gets no capabilities (no IPC): the UI only talks
            // HTTP (or the private protocol) to it.
            let builder = match ui {
                Ok(url) => {
                    app.manage(UiUrl(url.clone()));
                    let (nav_ui, download_ui) = (url.clone(), url.clone());
                    let reservations = std::sync::Arc::new(Reservations::default());
                    let nav_reservations = reservations.clone();
                    let in_process = SERVER.get().is_some();
                    let handle = app.handle().clone();
                    let window_url = if in_process { WebviewUrl::CustomProtocol(url) } else { WebviewUrl::External(url) };
                    WebviewWindowBuilder::new(app, "main", window_url)
                        // Never leave the UI; the in-process UI's downloads
                        // are done here (see `download_in_process`)
                        .on_navigation(move |url| {
                            // The mail body's sandboxed iframe (srcdoc): WebKitGTK
                            // asks for frames too, and these load nothing
                            if url.as_str() == "about:srcdoc" || url.as_str() == "about:blank" {
                                return true;
                            }
                            if !same_origin(url, &nav_ui) {
                                return false;
                            }
                            if in_process && mailbackup_server::tickets::is_download_path(url.path()) {
                                download_in_process(handle.clone(), url.clone(), nav_reservations.clone());
                                return false;
                            }
                            true
                        })
                        .on_download(move |webview, event| handle_download(&webview, event, &download_ui, &reservations))
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

        // A failed replacement leaves the original as it was, and doesn't
        // remove a `.part` file it can't know to be its own
        let part = r.reserve_chosen(target.clone(), "fail");
        std::fs::write(&part, b"another program's").unwrap();
        assert!(matches!(r.finish("fail", None, false), Finish::Failed));
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::read(&part).unwrap(), b"another program's");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_chosen_name_another_download_has_gets_the_next_free_name() {
        let dir = temp_dir("chosen-in-flight");
        let r = Reservations::default();
        let target = dir.join("notes.txt");
        // Two Save dialogs pick the same new name before either file exists
        assert_eq!(r.reserve_chosen(target.clone(), "first"), target);
        assert_eq!(r.reserve_chosen(target.clone(), "second"), dir.join("notes (1).txt"));
        // Nor may a chosen name collide with an automatically named download
        assert_eq!(r.reserve(&dir, "notes.txt", "auto"), dir.join("notes (2).txt"));
        assert_eq!(r.reserve_chosen(dir.join("notes (2).txt"), "third"), dir.join("notes (2) (1).txt"));

        // While a download replaces an existing file, another choosing it gets a free name
        std::fs::write(dir.join("old.txt"), b"old").unwrap();
        let part = r.reserve_chosen(dir.join("old.txt"), "replace");
        assert_eq!(part, dir.join("old.txt.part"));
        assert_eq!(r.reserve_chosen(dir.join("old.txt"), "again"), dir.join("old (1).txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn file_names_from_content_disposition() {
        use super::disposition_filename as name;
        assert_eq!(name("attachment; filename=\"r_sum_.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf").as_deref(), Some("résumé.pdf"));
        assert_eq!(name("attachment; filename=\"1.eml\"").as_deref(), Some("1.eml"));
        assert_eq!(name("attachment; filename*=UTF-8''..%2F..%2Fevil.sh").as_deref(), Some("evil.sh"));
        assert_eq!(name("attachment; filename=\"a\\\\b.txt\"").as_deref(), Some("b.txt"));
        assert_eq!(name("attachment; filename*=UTF-8''%2E%2E").as_deref(), None);
        assert_eq!(name("attachment").as_deref(), None);
        assert_eq!(name("attachment; filename*=UTF-8''%ZZ; filename=\"x.bin\"").as_deref(), Some("x.bin"));
    }

    #[test]
    fn a_download_never_removes_a_file_it_did_not_create() {
        use super::write_new_file;
        let dir = temp_dir("write-new");
        let r = Reservations::default();
        // Reserved, but another program creates the name before the write
        let path = r.reserve(&dir, "report.pdf", "key");
        std::fs::write(&path, b"someone else's").unwrap();
        let err = write_new_file(&path, b"ours").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        r.abandon("key");
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's", "left as it was");
        // Its reservation is gone; the name stays taken through the file
        assert_eq!(r.reserve(&dir, "report.pdf", "next"), dir.join("report (1).pdf"));

        // The same for a `.part` file replacing a chosen file
        std::fs::write(dir.join("keep.txt"), b"original").unwrap();
        let part = r.reserve_chosen(dir.join("keep.txt"), "replace");
        std::fs::write(&part, b"another program's").unwrap();
        assert!(write_new_file(&part, b"ours").is_err());
        r.abandon("replace");
        assert_eq!(std::fs::read(&part).unwrap(), b"another program's");
        assert_eq!(std::fs::read(dir.join("keep.txt")).unwrap(), b"original");

        // A new file is written whole
        let fresh = r.reserve(&dir, "new.bin", "fresh");
        write_new_file(&fresh, b"content").unwrap();
        assert_eq!(std::fs::read(&fresh).unwrap(), b"content");
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
