use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mail_parser::MessageParser;
use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::{AdvancedSearchFilter, Database};
use mailbackup_core::imap::ImapSyncEngine;
use mailbackup_core::keyring::CredentialStore;
use mailbackup_core::mbox::MboxExporter;
use mailbackup_core::retention::RetentionManager;
use mailbackup_core::config::system_export_locations;
use mailbackup_core::safe_paths::{normalize_dir, PathPolicy};
use mailbackup_core::scheduler::BackupScheduler;
use mailbackup_core::storage::StorageEngine;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::{Mutex, RwLock};
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub account_id: String,
    pub account_name: String,
    pub is_syncing: bool,
    pub current_folder: String,
    pub total_messages: u32,
    pub processed_messages: u32,
    pub downloaded_bytes: u64,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub config_path: PathBuf,
    pub db: Database,
    pub storage: StorageEngine,
    pub credentials: Arc<CredentialStore>,
    pub scheduler: Arc<Mutex<BackupScheduler>>,
    pub active_syncs: Arc<StdRwLock<HashMap<String, SyncStatus>>>,
    /// Per-process secret that every `/api/*` request must present in the
    /// `X-MailBackup-Token` header (plain download links use a `ticket` instead).
    pub api_token: Arc<str>,
    /// Single-use tickets for download links (see `tickets`).
    pub download_tickets: Arc<tickets::DownloadTickets>,
    /// Handshake secret proving to the desktop GUI that this is a genuine
    /// server (see `runtime`), with the port it listens on. Never sent to
    /// clients.
    pub identity: Arc<StdRwLock<runtime::ServerIdentity>>,
    /// Logins and sessions of browsers (see `access`).
    pub access: Arc<access::Access>,
    /// The HTTP listener, which the desktop app turns on and off with the
    /// `web_server_enabled` setting; `None` when nothing can switch it
    /// (tests).
    pub web: Option<Arc<WebListener>>,
}

/// Marks a request the desktop app handed to [`Server::handle_in_process`]:
/// its own window's, through a private protocol, never from the network
/// (extensions can't be set by a client). `origin` is that protocol's
/// origin, the only one such a request may send.
#[derive(Clone, Debug)]
pub struct InProcess {
    pub origin: String,
}

pub mod access;
pub mod runtime;
pub mod streaming;
pub mod tickets;

pub const API_TOKEN_HEADER: &str = "x-mailbackup-token";
/// On a `401` of an API route: the browser has no (more) session.
pub const LOGIN_REQUIRED_HEADER: &str = "x-mailbackup-login";

/// `Content-Disposition: attachment` for `filename`, valid for any input:
/// `filename=` carries an ASCII-only copy (quotes, backslashes, control and
/// non-ASCII characters replaced with `_`), `filename*=` the exact name
/// percent-encoded as UTF-8 (RFC 6266 / RFC 5987).
fn attachment_disposition(filename: &str) -> HeaderValue {
    let ascii: String = filename
        .chars()
        .map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' })
        .collect();
    let encoded: String = filename
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect();
    HeaderValue::from_str(&format!("attachment; filename=\"{}\"; filename*=UTF-8''{}", ascii, encoded))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

/// HTTP status for an error from the core library: bad input is the
/// client's (400), a missing item 404, anything else the server's (500).
fn error_status(e: &mailbackup_core::Error) -> StatusCode {
    match e {
        mailbackup_core::Error::InvalidInput(_) | mailbackup_core::Error::AccountArchived(_) => StatusCode::BAD_REQUEST,
        mailbackup_core::Error::NotFound(_) | mailbackup_core::Error::AccountNotFound(_) => StatusCode::NOT_FOUND,
        mailbackup_core::Error::AccountExists(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Scripts may only come from this server's own files: no inline or injected
/// scripts. Remote styles/fonts/images are allowed here only because the
/// sandboxed srcdoc iframe showing archived HTML mail inherits this policy and
/// "Load remote content" needs them. By default the viewer adds a stricter
/// per-message policy that blocks all remote content (see `renderEmailBody` in
/// `app.js`).
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
    script-src 'self'; \
    style-src 'self' 'unsafe-inline' https:; \
    font-src 'self' data: https:; \
    img-src 'self' data: blob: cid: https: http:; \
    connect-src 'self'; \
    object-src 'none'; \
    base-uri 'none'; \
    form-action 'self'; \
    frame-ancestors 'self'";
const API_TOKEN_PLACEHOLDER: &str = "__MAILBACKUP_API_TOKEN__";

/// Generates a random 256-bit API token (hex encoded) from the OS CSPRNG.
pub fn generate_api_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/stats", get(api_stats))
        .route("/api/handshake", get(api_handshake))
        .route("/login", get(login_page_or_ticket))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/web-key", get(api_web_key))
        .route("/api/web-key/regenerate", post(api_web_key_regenerate))
        .route("/api/download-ticket", post(api_download_ticket))
        .route("/api/accounts", get(api_get_accounts).post(api_add_account))
        .route("/api/accounts/import-csv", post(api_import_accounts_csv))
        .route("/api/accounts/csv-template", get(api_accounts_csv_template))
        .route(
            "/api/accounts/{id}",
            get(api_get_account)
                .put(api_update_account)
                .delete(api_delete_account),
        )
        .route("/api/accounts/test-direct", post(api_test_direct))
        .route("/api/accounts/{id}/folders", get(api_get_folders))
        .route("/api/accounts/{id}/server-ids", get(api_get_server_id_states))
        .route("/api/folders/{id}/messages", get(api_get_messages))
        .route("/api/messages/{id}", get(api_get_message_detail))
        .route("/api/messages/{id}/download", get(api_download_eml))
        .route("/api/messages/{id}/attachments/{index}", get(api_download_attachment))
        .route("/api/search", get(api_search))
        .route("/api/sync/status", get(api_get_sync_status))
        .route("/api/scheduler/status", get(api_scheduler_status))
        .route("/api/skipped", get(api_skipped_messages))
        .route("/api/accounts/{id}/skipped/retry", post(api_retry_skipped))
        .route("/api/sync/{account_id}", post(api_sync_account))
        .route("/api/export/mbox", post(api_export_mbox))
        .route("/api/export/mbox/download", get(api_download_mbox))
        .route("/api/export/locations", get(api_export_locations))
        .route("/api/export/check-path", get(api_export_check_path))
        .route("/api/dialog/pick-directory", post(api_pick_directory))
        .route("/api/settings", get(api_get_settings).put(api_update_settings))
        .route("/api/version", get(api_get_version))
        .route("/api/service/status", get(api_service_status))
        .route("/api/service/toggle", post(api_service_toggle))
        .route("/api/logs", get(api_get_logs))
        .route("/api/logs/download", get(api_download_logs))
        .route("/api/logs/clear", post(api_clear_logs))
        .route("/api/logs/rotate", post(api_rotate_logs))
        .route("/api/logs/files", get(api_list_log_files))
        .route("/{*file}", get(serve_static))
        .layer(middleware::from_fn_with_state(state.clone(), api_guard))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Rejects requests that could come from another web origin or from the network:
/// - `Host` must be an IP literal, `localhost` or a configured `allowed_hosts` entry,
///   which defeats DNS rebinding.
/// - `Origin`, when sent, must be `http(s)://<Host>` (no cross-origin callers; CORS is
///   not enabled). `https` covers a TLS-terminating reverse proxy.
/// - `/api/*` requests must carry the per-process API token in the header, or
///   (only `GET` of a download route) a single-use ticket issued for exactly
///   that request (see `tickets`).
async fn api_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let headers = req.headers();

    // The desktop window through its private protocol: no Host to check,
    // and only its own origin (token and tickets are still required below)
    if let Some(in_process) = req.extensions().get::<InProcess>() {
        let own_origin = headers
            .get(header::ORIGIN)
            .is_none_or(|o| o.to_str().is_ok_and(|o| o.eq_ignore_ascii_case(&in_process.origin)));
        if !own_origin {
            return (StatusCode::FORBIDDEN, "Cross-origin request rejected").into_response();
        }
        return guarded(&state, req, next).await;
    }

    let (allowed, require_login) = {
        let cfg = state.config.read().await;
        let host = match headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
            Some(h) if is_allowed_host(h, &cfg.settings.allowed_hosts) => Some(h.to_string()),
            _ => None,
        };
        (host, cfg.settings.require_login)
    };
    let host = match allowed {
        Some(h) => h,
        None => return (StatusCode::FORBIDDEN, "Forbidden host").into_response(),
    };

    if let Some(origin) = headers.get(header::ORIGIN) {
        let same_origin = origin
            .to_str()
            .map(|o| {
                // Browsers send a lowercase Origin; a client or proxy may send a mixed-case Host.
                o.eq_ignore_ascii_case(&format!("http://{}", host))
                    || o.eq_ignore_ascii_case(&format!("https://{}", host))
            })
            .unwrap_or(false);
        if !same_origin {
            return (StatusCode::FORBIDDEN, "Cross-origin request rejected").into_response();
        }
    }

    // Everything but the login page and what it needs takes a session
    // (issue #70). Only exact public paths pass: aliases of the app page
    // (`/index.html`, encoded spellings) are refused like any other path
    if require_login && !is_public_path(req.uri().path()) {
        let session = headers
            .get(header::COOKIE)
            .and_then(|c| c.to_str().ok())
            .and_then(access::session_from_cookies)
            .is_some_and(|token| state.access.session_valid(token));
        if !session {
            let res = if req.uri().path().starts_with("/api/") {
                // The header tells the app's page to go back to the login page
                (StatusCode::UNAUTHORIZED, [(LOGIN_REQUIRED_HEADER, "1")], "Login required").into_response()
            } else {
                login_page()
            };
            return with_security_headers(res);
        }
    }

    guarded(&state, req, next).await
}

/// Paths a browser without a session may request: the login page, its
/// script and images, logging in, and the server handshake. Exact matches.
fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/login"
            | "/login.js"
            | "/theme-init.js"
            | "/logo-mark.png"
            | "/favicon.png"
            | "/favicon-64.png"
            | "/favicon.ico"
            | "/apple-touch-icon.png"
            | "/api/login"
            | "/api/handshake"
    )
}

fn login_page() -> Response {
    serve_file("login.html", "")
}

fn with_security_headers(mut res: Response) -> Response {
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

/// The API token (or ticket) check and the security headers, for requests
/// whose Host and Origin passed.
async fn guarded(state: &AppState, req: Request, next: Next) -> Response {
    let headers = req.headers();
    // The handshake proves the server's identity to a client that has no
    // credentials yet (see `runtime`); Host/Origin checks above still apply
    // So does logging in, which a browser does before it has the token
    if req.uri().path().starts_with("/api/") && !matches!(req.uri().path(), "/api/handshake" | "/api/login") {
        let valid = headers
            .get(API_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| constant_time_eq(t.as_bytes(), state.api_token.as_bytes()));
        if !valid && !ticket_authorizes(state, &req) {
            return (StatusCode::UNAUTHORIZED, "Missing or invalid API token").into_response();
        }
    }

    with_security_headers(next.run(req).await)
}

/// Whether `req` is a `GET` of a download route carrying a live ticket issued
/// for exactly this path and query. The ticket is used up either way.
fn ticket_authorizes(state: &AppState, req: &Request) -> bool {
    let path = req.uri().path();
    if req.method() != axum::http::Method::GET || !tickets::is_download_path(path) {
        return false;
    }
    match tickets::Target::of_request(path, req.uri().query()) {
        Some((target, ticket)) => state.download_tickets.redeem(&ticket, &target),
        None => false,
    }
}

#[derive(Deserialize)]
struct DownloadTicketRequest {
    /// Relative URL of the download, exactly as it will be requested.
    url: String,
}

/// Issues a single-use ticket for one download (see `tickets`).
async fn api_download_ticket(State(state): State<AppState>, Json(req): Json<DownloadTicketRequest>) -> Response {
    let Some(target) = tickets::Target::for_url(&req.url) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Not a download URL" }))).into_response();
    };
    match state.download_tickets.mint(target) {
        Ok(ticket) => Json(serde_json::json!({
            "ticket": ticket,
            "expires_in": state.download_tickets.ttl().as_secs(),
        }))
        .into_response(),
        Err(tickets::MintError::TooMany) => {
            (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "Too many pending downloads" })))
                .into_response()
        }
    }
}

fn is_allowed_host(host: &str, extra_hosts: &[String]) -> bool {
    // Strip the port: "[::1]:8765" -> "[::1]", "127.0.0.1:8765" -> "127.0.0.1"
    let name = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[1..end],
            None => return false,
        }
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    name.eq_ignore_ascii_case("localhost")
        || name.parse::<IpAddr>().is_ok()
        || extra_hosts.iter().any(|h| h.trim().eq_ignore_ascii_case(name))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn resolve_bind_ip(raw: &str) -> IpAddr {
    match raw.trim().parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            tracing::warn!("Invalid bind_address '{}', falling back to 127.0.0.1", raw);
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    }
}

pub async fn start_server(port_override: Option<u16>) -> Result<()> {
    start_server_with_options(port_override, None).await
}

pub async fn start_server_with_options(
    port_override: Option<u16>,
    config_path_override: Option<PathBuf>,
) -> Result<()> {
    run_server(port_override, config_path_override, None).await
}

/// Runs the server. Once it listens and has published its runtime file
/// (see [`runtime`]), the bound port is sent on `ready` (port `0` binds a
/// free one); a bind failure is sent there too.
pub async fn run_server(
    port_override: Option<u16>,
    config_path_override: Option<PathBuf>,
    ready: Option<std::sync::mpsc::Sender<std::result::Result<u16, String>>>,
) -> Result<()> {
    let report = |result: std::result::Result<u16, String>| {
        if let Some(ready) = &ready {
            let _ = ready.send(result);
        }
    };
    match serve(port_override, config_path_override, &report).await {
        Ok(()) => Ok(()),
        Err(e) => {
            report(Err(e.to_string()));
            Err(e)
        }
    }
}

/// Runs the server for headless/service mode: it always listens (a process
/// without a window is reachable only this way) until Ctrl-C/SIGTERM.
async fn serve(
    port_override: Option<u16>,
    config_path_override: Option<PathBuf>,
    report: &dyn Fn(std::result::Result<u16, String>),
) -> Result<()> {
    let server = Server::build(config_path_override, port_override, true).await?;
    let port = server.web().start().await?;
    report(Ok(port));
    shutdown_signal().await;
    server.web().stop().await;
    Ok(())
}

/// A MailBackup server: catalog, archive, credentials, the backup scheduler
/// and the router for the web UI and REST API. The router is reached over
/// HTTP through [`Server::web`] and, in the desktop app, in-process through
/// [`Server::handle_in_process`].
pub struct Server {
    router: Router,
    web: Arc<WebListener>,
}

impl Server {
    /// Opens the configuration (`config_path`, else the default) and starts
    /// the scheduler. Doesn't listen yet. `port` overrides the configured
    /// port; `always_listen` (headless/service mode) makes the listener
    /// ignore `web_server_enabled`.
    pub async fn build(config_path: Option<PathBuf>, port: Option<u16>, always_listen: bool) -> Result<Arc<Server>> {
        let config_path = config_path.unwrap_or_else(mailbackup_core::config::default_config_path);
        let config = AppConfig::load_or_create(Some(&config_path))?;
        mailbackup_core::private_fs::tighten_at_startup(&config_path, &config.settings, true);
        let db = Database::open(&config.db_path)?;
        let storage = StorageEngine::new(&config.data_dir);
        // Same store as the CLI and the background service for this config
        let credentials = Arc::new(CredentialStore::for_config(&config_path, &config.settings));
        // Settle "start a new archive" switches a crash left half-done
        match mailbackup_core::archive::recover(&db, &credentials, &config_path) {
            Ok(0) => {}
            Ok(n) => info!("Settled {} interrupted account archive switch(es)", n),
            Err(e) => error!("Couldn't check for interrupted account archive switches: {}", e),
        }
        let port = port.unwrap_or(config.settings.web_port);
        let bind_ip = resolve_bind_ip(&config.settings.bind_address);
        let identity = Arc::new(StdRwLock::new(runtime::ServerIdentity::new(port)));

        let config_arc = Arc::new(RwLock::new(config.clone()));
        let active_syncs = Arc::new(StdRwLock::new(HashMap::new()));

        // Initialize and start background scheduler
        let mut scheduler = BackupScheduler::new(
            Arc::new(config),
            db.clone(),
            storage.clone(),
            credentials.clone(),
        )
        .await?
        .with_config_path(&config_path);

    let active_syncs_for_sched = active_syncs.clone();
    scheduler.set_status_listener(Some(Arc::new(
        move |acc_id: &str, acc_name: &str, status: &str, progress: Option<&mailbackup_core::imap::SyncProgress>, err: Option<&str>| {
            if let Ok(mut syncs) = active_syncs_for_sched.write() {
                match status {
                    "started" => {
                        syncs.insert(
                            acc_id.to_string(),
                            SyncStatus {
                                account_id: acc_id.to_string(),
                                account_name: acc_name.to_string(),
                                is_syncing: true,
                                current_folder: "Starting...".to_string(),
                                total_messages: 0,
                                processed_messages: 0,
                                downloaded_bytes: 0,
                                status: "syncing".to_string(),
                                error: None,
                            },
                        );
                    }
                    "syncing" => {
                        if let Some(p) = progress {
                            syncs.insert(
                                acc_id.to_string(),
                                SyncStatus {
                                    account_id: acc_id.to_string(),
                                    account_name: acc_name.to_string(),
                                    is_syncing: true,
                                    current_folder: p.current_folder.clone(),
                                    total_messages: p.total_messages,
                                    processed_messages: p.processed_messages,
                                    downloaded_bytes: p.downloaded_bytes,
                                    status: "syncing".to_string(),
                                    error: None,
                                },
                            );
                        }
                    }
                    "completed" => {
                        if let Some(p) = progress {
                            syncs.insert(
                                acc_id.to_string(),
                                SyncStatus {
                                    account_id: acc_id.to_string(),
                                    account_name: acc_name.to_string(),
                                    is_syncing: false,
                                    current_folder: "Finished".to_string(),
                                    total_messages: p.total_messages,
                                    processed_messages: p.processed_messages,
                                    downloaded_bytes: p.downloaded_bytes,
                                    status: "completed".to_string(),
                                    error: None,
                                },
                            );
                        }
                    }
                    "error" => {
                        syncs.insert(
                            acc_id.to_string(),
                            SyncStatus {
                                account_id: acc_id.to_string(),
                                account_name: acc_name.to_string(),
                                is_syncing: false,
                                current_folder: "Failed".to_string(),
                                total_messages: 0,
                                processed_messages: 0,
                                downloaded_bytes: 0,
                                status: "failed".to_string(),
                                error: err.map(|s| s.to_string()),
                            },
                        );
                    }
                    _ => {}
                }
            }
        },
    )));

    match scheduler.start().await {
            Ok(()) => info!("Background backup scheduler successfully activated"),
            Err(e) => error!("Failed to start backup scheduler: {}", e),
        }

        let config_dir = config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
        let web = Arc::new(WebListener {
            router: std::sync::OnceLock::new(),
            bind_ip,
            port,
            always: always_listen,
            config_dir,
            identity: identity.clone(),
            running: Mutex::new(None),
        });
        // The browser access key exists from the start, so the desktop app
        // and `mailbackup web-key` find it (issue #70)
        if let Err(e) = mailbackup_core::web_access::load_or_create_key(&web.config_dir) {
            error!("Couldn't create the browser access key in {}: {}", web.config_dir.display(), e);
        }
        if !config_arc.read().await.settings.require_login {
            tracing::warn!(
                "settings.require_login is off: anyone who can reach the web port can use the whole API without logging in"
            );
        }
        let state = AppState {
            access: Arc::new(access::Access::new(web.config_dir.clone())),
            config: config_arc,
            config_path,
            db,
            storage,
            credentials,
            scheduler: Arc::new(Mutex::new(scheduler)),
            active_syncs,
            api_token: Arc::from(generate_api_token()),
            download_tickets: Arc::new(tickets::DownloadTickets::default()),
            identity,
            web: Some(web.clone()),
        };
        let router = create_router(state);
        let _ = web.router.set(router.clone());
        Ok(Arc::new(Server { router, web }))
    }

    /// The HTTP listener.
    pub fn web(&self) -> &Arc<WebListener> {
        &self.web
    }

    /// Answers a request of the desktop window's private protocol, whose
    /// origin is `origin`, without any socket (see [`InProcess`]). The
    /// response body is collected whole: the protocol takes no streams.
    pub async fn handle_in_process(
        &self,
        req: axum::http::Request<Vec<u8>>,
        origin: &str,
    ) -> axum::http::Response<Vec<u8>> {
        let mut req = req.map(Body::from);
        req.extensions_mut().insert(InProcess { origin: origin.to_string() });
        let res = match tower::ServiceExt::oneshot(self.router.clone(), req).await {
            Ok(res) => res,
            Err(never) => match never {},
        };
        collect_limited(res, IN_PROCESS_RESPONSE_LIMIT).await
    }

    /// Like [`Server::handle_in_process`] for a download: the response with
    /// its body still streaming (see `streaming::save_body`), so a large
    /// download never has to fit in memory. The request passes the same
    /// guard: the download ticket is checked and used up here, before the
    /// caller asks where to save.
    pub async fn handle_in_process_streaming(
        &self,
        req: axum::http::Request<Vec<u8>>,
        origin: &str,
    ) -> axum::http::Response<Body> {
        let mut req = req.map(Body::from);
        req.extensions_mut().insert(InProcess { origin: origin.to_string() });
        match tower::ServiceExt::oneshot(self.router.clone(), req).await {
            Ok(res) => res,
            Err(never) => match never {},
        }
    }
}

/// Largest response the desktop window's protocol collects in memory: the
/// app's pages and API answers. The biggest is a message's detail: its HTML
/// (at most the size of the message, `imap::DEFAULT_LIMITS.max_message_bytes`)
/// plus inlined images (at most `html_view::MAX_INLINE_TOTAL_BYTES` before
/// base64). Downloads are streamed instead (`handle_in_process_streaming`).
pub const IN_PROCESS_RESPONSE_LIMIT: usize = 512 * 1024 * 1024;

/// The response with its body collected, or a clear error if the body is
/// larger than `limit` (never a silently truncated one).
async fn collect_limited(res: axum::http::Response<Body>, limit: usize) -> axum::http::Response<Vec<u8>> {
    let (parts, body) = res.into_parts();
    match axum::body::to_bytes(body, limit).await {
        Ok(bytes) => axum::http::Response::from_parts(parts, bytes.to_vec()),
        Err(e) => {
            error!("Couldn't read a response for the window: {}", e);
            let message = format!("The response is too large to show in the window (over {} MB)", limit / (1024 * 1024));
            let mut res = axum::http::Response::new(message.into_bytes());
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            res
        }
    }
}

/// The server's HTTP listener on `bind_address:port`, started and stopped
/// at runtime. While it listens, the runtime file proving the server's
/// identity (see `runtime`) is published for its port.
pub struct WebListener {
    router: std::sync::OnceLock<Router>,
    bind_ip: IpAddr,
    port: u16,
    always: bool,
    config_dir: PathBuf,
    identity: Arc<StdRwLock<runtime::ServerIdentity>>,
    running: Mutex<Option<Listening>>,
}

struct Listening {
    port: u16,
    stop: tokio::sync::oneshot::Sender<()>,
    /// Fires when the listening socket is closed (see [`ClosingListener`])
    closed: tokio::sync::oneshot::Receiver<()>,
}

/// The listening socket, with the runtime file published for it: both go
/// away together when axum drops the listener, which it does as soon as a
/// graceful shutdown starts, before open connections finish. That moment
/// is reported on `closed`, so a stop needn't wait for requests in progress
/// (one of which may be the request asking for the stop).
struct ClosingListener {
    /// Always `Some` until dropped
    inner: Option<tokio::net::TcpListener>,
    published: Option<runtime::PublishedRuntime>,
    closed: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ClosingListener {
    fn drop(&mut self) {
        // Fields are dropped only after this returns, so close the socket and
        // remove the runtime file first: once `closed` fires, the port is free
        // and a new runtime file for it can't be removed by this one
        drop(self.inner.take());
        drop(self.published.take());
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}

/// The peer address of a connection to the [`ClosingListener`], available
/// to handlers as `ConnectInfo<PeerAddr>` (failed logins are limited per peer).
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, ClosingListener>> for PeerAddr {
    fn connect_info(stream: axum::serve::IncomingStream<'_, ClosingListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

impl axum::serve::Listener for ClosingListener {
    type Io = tokio::net::TcpStream;
    type Addr = SocketAddr;

    fn accept(&mut self) -> impl std::future::Future<Output = (Self::Io, Self::Addr)> + Send {
        axum::serve::Listener::accept(self.inner.as_mut().expect("open until dropped"))
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.as_ref().expect("open until dropped").local_addr()
    }
}

impl WebListener {
    /// Starts listening (if not yet) and returns the bound port (a
    /// configured port `0` binds a free one).
    pub async fn start(&self) -> Result<u16> {
        let mut running = self.running.lock().await;
        if let Some(listening) = running.as_ref() {
            return Ok(listening.port);
        }
        let router = self.router.get().cloned().ok_or_else(|| mailbackup_core::Error::Other("server not built".into()))?;
        // Bind before anything is published, so a taken port fails fast and
        // never replaces another instance's runtime file
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(self.bind_ip, self.port)).await?;
        let port = listener.local_addr()?.port();
        let identity = {
            let mut identity = self.identity.write().unwrap_or_else(|e| e.into_inner());
            *identity = identity.with_port(port);
            identity.clone()
        };
        let addr = SocketAddr::new(self.bind_ip, port);
        if !self.bind_ip.is_loopback() {
            tracing::warn!(
                "Web UI / REST API is exposed on {} (bind_address). It is reachable from other machines on the network over plain HTTP: the access key, the session and your mail travel unencrypted. Put a TLS reverse proxy in front of it.",
                addr
            );
        }
        info!("🚀 MailBackup Studio running on http://127.0.0.1:{} (listening on {})", port, addr);
        // Published only now that the port is ours; removed again on stop
        let published = match runtime::PublishedRuntime::publish(&self.config_dir, &identity) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!("Couldn't publish the server runtime file in {}: {}", self.config_dir.display(), e);
                None
            }
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (closed_tx, closed) = tokio::sync::oneshot::channel::<()>();
        let listener = ClosingListener { inner: Some(listener), published, closed: Some(closed_tx) };
        // Requests in progress finish in this task after the socket closed
        tokio::spawn(async move {
            let shutdown = async move {
                let _ = stopped.await;
            };
            // Peer addresses, for limiting failed logins per peer
            let service = router.into_make_service_with_connect_info::<PeerAddr>();
            if let Err(e) = axum::serve(listener, service).with_graceful_shutdown(shutdown).await {
                error!("The web server stopped: {}", e);
            }
        });
        *running = Some(Listening { port, stop, closed });
        Ok(port)
    }

    /// Stops listening: returns once the port is closed and free again.
    /// Requests in progress still finish, in the background; a request may
    /// therefore stop the listener it came through. Holds the same lock as
    /// [`WebListener::start`] throughout, so on/off changes apply in order.
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(listening) = running.take() {
            let _ = listening.stop.send(());
            let _ = listening.closed.await;
            info!("Web server on port {} stopped", listening.port);
        }
    }

    /// The port it listens on, if it does.
    pub async fn port(&self) -> Option<u16> {
        self.running.lock().await.as_ref().map(|l| l.port)
    }

    /// Whether it listens whatever `web_server_enabled` says (headless and
    /// service mode).
    pub fn always_on(&self) -> bool {
        self.always
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[derive(Deserialize)]
struct HandshakeQuery {
    nonce: String,
}

/// Proves to the desktop GUI that this server holds the handshake secret
/// from its runtime file (see `runtime`). Needs no API token: the GUI must not
/// disclose anything to a server it hasn't verified yet.
async fn api_handshake(State(state): State<AppState>, Query(query): Query<HandshakeQuery>) -> impl IntoResponse {
    let identity = state.identity.read().unwrap_or_else(|e| e.into_inner()).clone();
    match identity.proof(&query.nonce) {
        Some(proof) => Json(serde_json::json!({
            "proof": proof,
            "port": identity.port,
            "version": env!("CARGO_PKG_VERSION"),
        }))
        .into_response(),
        None => (StatusCode::BAD_REQUEST, "Invalid nonce").into_response(),
    }
}

// ---- Logging in (issue #70; see `access`) ----

#[derive(Deserialize)]
struct LoginRequest {
    key: String,
    /// Answer with a single-use login ticket instead of a session cookie
    /// (the desktop app, which hands the ticket to its window)
    #[serde(default)]
    ticket: bool,
}

const MAX_LOGIN_BODY: usize = 4 * 1024;

/// `POST /api/login` with `{"key": …}`: a session cookie for the access key.
/// JSON only, so a cross-origin form can't send it (and the guard already
/// refused other origins); failures are limited per peer address.
async fn api_login(State(state): State<AppState>, req: Request) -> Response {
    let json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json")));
    if !json {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Expected application/json").into_response();
    }
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<PeerAddr>>()
        .map(|info| info.0.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let secure = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok())
        .is_some_and(|o| o.to_ascii_lowercase().starts_with("https://"));
    let Ok(body) = axum::body::to_bytes(req.into_body(), MAX_LOGIN_BODY).await else {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request too large").into_response();
    };
    let Ok(login) = serde_json::from_slice::<LoginRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "Expected {\"key\": \"…\"}").into_response();
    };
    let access = state.access.clone();
    let result = if login.ticket { access.login_ticket(&peer, &login.key) } else { access.login(&peer, &login.key) };
    match result {
        Ok(ticket) if login.ticket => {
            Json(serde_json::json!({ "ticket": ticket, "expires_in": access::TICKET_TTL.as_secs() })).into_response()
        }
        Ok(session) => {
            info!("Browser logged in from {}", peer);
            let mut res = StatusCode::NO_CONTENT.into_response();
            if let Ok(cookie) = HeaderValue::from_str(&access::session_cookie(&session, secure)) {
                res.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            res
        }
        Err(access::LoginError::WrongKey) => {
            tracing::warn!("Failed login from {}", peer);
            (StatusCode::UNAUTHORIZED, "Wrong access key").into_response()
        }
        Err(access::LoginError::TooMany(wait)) => {
            tracing::warn!("Too many failed logins from {}", peer);
            let mut res = (StatusCode::TOO_MANY_REQUESTS, "Too many failed logins; try again later").into_response();
            if let Ok(secs) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
                res.headers_mut().insert(header::RETRY_AFTER, secs);
            }
            res
        }
        Err(access::LoginError::Unavailable(e)) => {
            error!("The access key can't be read: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "The access key can't be read").into_response()
        }
    }
}

#[derive(Deserialize)]
struct LoginTicketQuery {
    ticket: Option<String>,
}

/// `GET /login`: the login page, or with `?ticket=` (the desktop app) a
/// session for a single-use login ticket and a redirect to the app.
async fn login_page_or_ticket(State(state): State<AppState>, Query(query): Query<LoginTicketQuery>) -> Response {
    let Some(ticket) = query.ticket.filter(|t| !t.is_empty()) else {
        return login_page();
    };
    match state.access.redeem_ticket(&ticket) {
        Some(session) => {
            let mut res = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
            if let Ok(cookie) = HeaderValue::from_str(&access::session_cookie(&session, false)) {
                res.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        None => login_page(),
    }
}

async fn api_logout(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    if let Some(token) = headers.get(header::COOKIE).and_then(|c| c.to_str().ok()).and_then(access::session_from_cookies) {
        state.access.logout(token);
    }
    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(cookie) = HeaderValue::from_str(&access::expired_cookie()) {
        res.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    res
}

/// The access key, for a user who is already in (a session or the desktop
/// window), so they can open the UI in a browser.
async fn api_web_key(State(state): State<AppState>) -> Response {
    match state.access.key() {
        Ok(key) => Json(serde_json::json!({
            "key": key,
            "path": mailbackup_core::web_access::key_path(&state.config_path.parent().map(std::path::Path::to_path_buf).unwrap_or_default()),
            "require_login": state.config.read().await.settings.require_login,
        }))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// A new access key: every browser session ends, this one included.
async fn api_web_key_regenerate(State(state): State<AppState>) -> Response {
    match state.access.regenerate() {
        Ok(key) => {
            mailbackup_core::event_log::log_event("WEB_KEY_REGENERATED", "Browser access key regenerated; all browser sessions ended");
            let mut res = Json(serde_json::json!({ "key": key })).into_response();
            if let Ok(cookie) = HeaderValue::from_str(&access::expired_cookie()) {
                res.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            res
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

// Static Assets Handler
async fn serve_index(State(state): State<AppState>) -> impl IntoResponse {
    serve_file("index.html", &state.api_token)
}

async fn serve_static(State(state): State<AppState>, Path(path): Path<String>, headers: axum::http::HeaderMap) -> Response {
    // The embedded files change only with a new build: answer a matching
    // If-None-Match with 304 (issue #79). Pages that carry the token are
    // never cached.
    let clean = path.trim_start_matches('/');
    if !matches!(clean, "index.html" | "login.html")
        && let Some(file) = Assets::get(clean) {
        let etag = format!("\"{}\"", hex::encode(file.metadata.sha256_hash()));
        let matches = headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
        if matches {
            let mut res = StatusCode::NOT_MODIFIED.into_response();
            if let Ok(value) = HeaderValue::from_str(&etag) {
                res.headers_mut().insert(header::ETAG, value);
            }
            return res;
        }
        let mut res = serve_file(clean, &state.api_token);
        if let Ok(value) = HeaderValue::from_str(&etag) {
            res.headers_mut().insert(header::ETAG, value);
        }
        res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        return res;
    }
    serve_file(&path, &state.api_token)
}

fn serve_file(path: &str, api_token: &str) -> Response {
    let clean_path = path.trim_start_matches('/');
    match Assets::get(clean_path) {
        Some(content) => {
            let mime = mime_guess::from_path(clean_path).first_or_octet_stream();
            let body = if clean_path == "index.html" {
                // Hand the API token to the UI. Only same-origin pages can read this
                // response: CORS is off and the Host check blocks DNS rebinding.
                let html = String::from_utf8_lossy(&content.data).replace(API_TOKEN_PLACEHOLDER, api_token);
                Body::from(html)
            } else {
                Body::from(content.data)
            };
            let mut res = Response::new(body);
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")),
            );
            if clean_path == "index.html" || clean_path == "login.html" {
                res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
            res
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

/// Reloads the scheduler with `cfg`. A failed reload leaves the previous
/// jobs running (see `BackupScheduler::reload`); the returned text tells
/// the user so, to be appended to the response of the change that caused it.
async fn reload_scheduler(state: &AppState, cfg: &AppConfig) -> Option<String> {
    match state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await {
        Ok(()) => None,
        Err(e) => {
            error!("Scheduler reload failed: {}", e);
            Some(format!(" Warning: scheduled backups still follow the previous settings ({}).", e))
        }
    }
}

/// `schedule` as it may be stored for an account; an error (reported as
/// 400) if the scheduler couldn't run it (issue #71).
fn checked_schedule(schedule: &str) -> mailbackup_core::Result<String> {
    mailbackup_core::scheduler::validate_schedule(schedule).map(|_| schedule.trim().to_string())
}

/// Messages that are not backed up because of their size (issue #72), of
/// every account.
async fn api_skipped_messages(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.skipped_messages(None) {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// The account's skipped messages are fetched on its next sync, whatever
/// the size limit.
async fn api_retry_skipped(State(state): State<AppState>, Path(account_id): Path<String>) -> impl IntoResponse {
    if state.config.read().await.account_by_id(&account_id).is_none() {
        return (StatusCode::NOT_FOUND, "Account not found").into_response();
    }
    match state.db.request_skipped_retry(&account_id) {
        Ok(marked) => Json(serde_json::json!({ "marked": marked })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Which accounts have a scheduled backup, as of the scheduler's last
/// (re)start. Read-only: asking logs nothing.
async fn api_scheduler_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.scheduler.lock().await.status().clone()).into_response()
}

// REST Handlers
async fn api_stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_storage_stats() {
        Ok(stats) => Json(stats).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn api_get_accounts(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.read().await;
    Json(&cfg.accounts).into_response()
}

async fn api_get_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let cfg = state.config.read().await;
    match cfg.account_by_id(&account_id) {
        Some(acc) => Json(acc).into_response(),
        None => (StatusCode::NOT_FOUND, "Account not found").into_response(),
    }
}

#[derive(Deserialize)]
struct AddAccountPayload {
    provider: String,
    name: String,
    email: String,
    server: String,
    port: u16,
    username: String,
    password: String,
    retention_days: Option<u32>,
    schedule: Option<String>,
}

async fn api_add_account(
    State(state): State<AppState>,
    Json(payload): Json<AddAccountPayload>,
) -> impl IntoResponse {
    let provider = match payload.provider.to_lowercase().as_str() {
        "gmail" => ProviderType::Gmail,
        "outlook" => ProviderType::Outlook,
        "icloud" => ProviderType::ICloud,
        "yahoo" => ProviderType::Yahoo,
        _ => ProviderType::GenericImap,
    };

    let schedule = match payload.schedule.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(checked_schedule) {
        Some(Ok(s)) => Some(s),
        Some(Err(e)) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        None => None,
    };

    let mut cfg = state.config.write().await;
    // Refuses an address that already has an account; never reuses another
    // account's id, files or password (issue #74)
    let account = match mailbackup_core::accounts::create(
        &mut cfg,
        &state.config_path,
        &state.db,
        &state.storage,
        &state.credentials,
        mailbackup_core::accounts::NewAccount {
            name: payload.name,
            email: payload.email,
            provider,
            imap_server: payload.server,
            imap_port: payload.port,
            username: payload.username,
            password: payload.password,
            schedule,
            retention_days: payload.retention_days,
            requested_id: None,
        },
    ) {
        Ok(account) => account,
        Err(e) => return (error_status(&e), format!("Account not added: {}", e)).into_response(),
    };
    let acc_name_log = account.name.clone();
    let acc_email_log = account.email.clone();
    let acc_provider_log = format!("{:?}", account.provider);

    // Reload scheduler with new account
    let warning = reload_scheduler(&state, &cfg).await;

    mailbackup_core::event_log::log_event(
        "ACCOUNT_ADDED",
        &format!("Account '{}' ({}) added [Provider: {}]", acc_name_log, acc_email_log, acc_provider_log),
    );

    (StatusCode::OK, format!("Account created.{}", warning.unwrap_or_default())).into_response()
}

#[derive(Deserialize)]
struct ImportAccountsCsvPayload {
    #[serde(alias = "csv_data")]
    csv_content: String,
    #[serde(default)]
    dry_run: bool,
    /// Rows whose address already has an account update that account
    /// instead of being refused (issue #74)
    #[serde(default)]
    update_existing: bool,
}

#[derive(Serialize)]
struct ImportAccountsCsvResponse {
    valid_count: usize,
    error_count: usize,
    accounts: Vec<ImportedAccountPreview>,
    valid_accounts: Vec<ImportedAccountPreview>,
    errors: Vec<mailbackup_core::csv_import::CsvRowError>,
    imported: bool,
    imported_count: usize,
    /// Of the valid rows, how many update an existing account
    #[serde(default)]
    update_count: usize,
}

#[derive(Clone, Serialize)]
struct ImportedAccountPreview {
    id: String,
    email: String,
    name: String,
    provider: String,
    imap_server: String,
    server: String,
    imap_port: u16,
    port: u16,
    username: String,
    schedule: Option<String>,
    /// "create" or "update"
    action: &'static str,
}

async fn api_accounts_csv_template() -> impl IntoResponse {
    let template = mailbackup_core::csv_import::generate_csv_template();
    let mut res = Response::new(Body::from(template));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    res.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"mailbackup_accounts_template.csv\""),
    );
    res
}

async fn api_import_accounts_csv(
    State(state): State<AppState>,
    Json(payload): Json<ImportAccountsCsvPayload>,
) -> impl IntoResponse {
    let mut report = mailbackup_core::csv_import::parse_accounts_csv(&payload.csv_content);
    // The whole file is checked against the accounts (and itself) before
    // anything is written
    let mut cfg = state.config.write().await;
    let (plan, conflicts) = mailbackup_core::accounts::plan_import(&cfg, &report.valid_accounts, payload.update_existing);
    report.errors.extend(conflicts);
    report.errors.sort_by_key(|e| e.line);

    let previews: Vec<ImportedAccountPreview> = plan
        .iter()
        .map(|(i, action)| {
            let acc = &report.valid_accounts[*i];
            ImportedAccountPreview {
                id: match action {
                    mailbackup_core::accounts::ImportAction::Update(id) => id.clone(),
                    mailbackup_core::accounts::ImportAction::Create => acc.id.clone(),
                },
                email: acc.email.clone(),
                name: acc.name.clone(),
                provider: format!("{:?}", acc.provider),
                imap_server: acc.imap_server.clone(),
                server: acc.imap_server.clone(),
                imap_port: acc.imap_port,
                port: acc.imap_port,
                username: acc.username.clone(),
                schedule: acc.schedule.clone(),
                action: match action {
                    mailbackup_core::accounts::ImportAction::Update(_) => "update",
                    mailbackup_core::accounts::ImportAction::Create => "create",
                },
            }
        })
        .collect();

    let valid_count = plan.len();
    let update_count = plan.iter().filter(|(_, a)| matches!(a, mailbackup_core::accounts::ImportAction::Update(_))).count();

    if payload.dry_run || valid_count == 0 {
        let status = if payload.dry_run { StatusCode::OK } else { StatusCode::BAD_REQUEST };
        return (
            status,
            Json(ImportAccountsCsvResponse {
                valid_count,
                error_count: report.errors.len(),
                accounts: previews.clone(),
                valid_accounts: previews,
                errors: report.errors,
                imported: false,
                imported_count: 0,
                update_count,
            }),
        )
            .into_response();
    }

    // One account at a time, each saved on its own: a failure stops the
    // import and reports what was done before it
    let mut imported_count = 0;
    for (i, action) in &plan {
        let row = &report.valid_accounts[*i];
        let result = match action {
            mailbackup_core::accounts::ImportAction::Create => mailbackup_core::accounts::create(
                &mut cfg,
                &state.config_path,
                &state.db,
                &state.storage,
                &state.credentials,
                mailbackup_core::accounts::new_account_from_row(row),
            ),
            mailbackup_core::accounts::ImportAction::Update(id) => mailbackup_core::accounts::update_from_row(
                &mut cfg,
                &state.config_path,
                &state.credentials,
                id,
                row,
            ),
        };
        if let Err(e) = result {
            error!("CSV import stopped at line {} ({}): {}", row.line, row.email, e);
            let _ = reload_scheduler(&state, &cfg).await;
            return (
                error_status(&e),
                format!(
                    "Import stopped at line {} ({}): {}. {} account(s) were imported before it.",
                    row.line, row.email, e, imported_count
                ),
            )
                .into_response();
        }
        imported_count += 1;
    }
    let error_count = report.errors.len();

    // Reload scheduler with updated accounts
    let _ = reload_scheduler(&state, &cfg).await;

    mailbackup_core::event_log::log_event(
        "ACCOUNTS_BULK_IMPORTED",
        &format!(
            "Bulk imported {} account(s) via CSV ({} updated, {} rows skipped)",
            imported_count, update_count, error_count
        ),
    );

    (
        StatusCode::OK,
        Json(ImportAccountsCsvResponse {
            valid_count,
            error_count,
            accounts: previews.clone(),
            valid_accounts: previews,
            errors: report.errors,
            imported: true,
            imported_count,
            update_count,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct UpdateAccountPayload {
    name: Option<String>,
    server: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    retention_days: Option<u32>,
    schedule: Option<String>,
    enabled: Option<bool>,
    /// What a changed server, port or username does to the mail archived so
    /// far: `"rescan"` (default) keeps it in this account and re-scans,
    /// `"new_archive"` retires it as a read-only archive account.
    #[serde(default)]
    on_connection_change: Option<String>,
    /// Re-bind by the server's message ids on same-server re-scans instead
    /// of downloading again (opt-in; see `AccountConfig::trust_server_ids`).
    #[serde(default)]
    trust_server_ids: Option<bool>,
}

async fn api_update_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(payload): Json<UpdateAccountPayload>,
) -> impl IntoResponse {
    // Nothing is changed for a schedule that can't run (issue #71)
    let mut payload = payload;
    if let Some(schedule) = payload.schedule.take() {
        payload.schedule = match checked_schedule(&schedule) {
            Ok(s) => Some(s),
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };
    }

    let mut cfg = state.config.write().await;
    let acc = match cfg.account_by_id_mut(&account_id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, "Account not found").into_response(),
    };

    // A read-only archive can only be renamed
    if acc.is_archive() {
        let changes_more = payload.server.as_deref().is_some_and(|s| !s.trim().eq_ignore_ascii_case(acc.imap_server.trim()))
            || payload.port.is_some_and(|p| p != acc.imap_port)
            || payload.username.as_deref().is_some_and(|u| u.trim() != acc.username.trim())
            || payload.password.as_deref().is_some_and(|p| !p.is_empty())
            || payload.schedule.is_some()
            || payload.retention_days.is_some()
            || payload.enabled == Some(true)
            || payload.trust_server_ids == Some(true);
        if changes_more {
            return (StatusCode::BAD_REQUEST, "This account is a read-only archive; only its name can be changed.")
                .into_response();
        }
        if let Some(n) = payload.name {
            acc.name = n;
        }
        if let Err(e) = cfg.save(&state.config_path) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save config: {}", e)).into_response();
        }
        return (StatusCode::OK, "Account updated").into_response();
    }

    // The UI always sends server/port/username, so compare values rather than
    // presence. A change of connection needs the password again: the stored one
    // was entered for the old server and must not be sent to a new one.
    let new_server = payload
        .server
        .as_deref()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| acc.imap_server.clone());
    let new_port = payload.port.unwrap_or(acc.imap_port);
    let new_username = payload
        .username
        .as_deref()
        .map(|u| u.trim().to_string())
        .unwrap_or_else(|| acc.username.clone());
    let connection_changed = !new_server.eq_ignore_ascii_case(acc.imap_server.trim())
        || new_port != acc.imap_port
        || new_username != acc.username.trim();
    let new_password = payload.password.filter(|pw| !pw.is_empty());
    if connection_changed && new_password.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "Enter the account password to change the server, port or username.",
        )
            .into_response();
    }
    let new_archive = match payload.on_connection_change.as_deref() {
        None | Some("rescan") => false,
        Some("new_archive") => connection_changed,
        Some(other) => {
            return (StatusCode::BAD_REQUEST, format!("Unknown on_connection_change '{}'", other)).into_response();
        }
    };

    // Start a new archive: retire the archive as it is, then apply the rest
    // of the edit to the live account. The gate stays held until the
    // scheduler runs with the new config.
    let mut archived = None;
    if new_archive {
        let busy = state.active_syncs.read().map(|s| s.get(&account_id).is_some_and(|st| st.is_syncing)).unwrap_or(false);
        if busy {
            return (StatusCode::CONFLICT, "A sync of this account is running; try again when it has finished.")
                .into_response();
        }
        let conn = mailbackup_core::archive::NewConnection {
            server: &new_server,
            port: new_port,
            username: &new_username,
            password: new_password.as_deref().unwrap_or_default(),
        };
        match mailbackup_core::archive::start_new_archive(
            &state.db,
            &state.credentials,
            &mut cfg,
            &state.config_path,
            &account_id,
            &conn,
        ) {
            Ok(switched) => archived = Some(switched),
            Err(e) => {
                let status = match e {
                    mailbackup_core::Error::AccountBusy(_) => StatusCode::CONFLICT,
                    mailbackup_core::Error::InvalidInput(_) | mailbackup_core::Error::AccountArchived(_) => {
                        StatusCode::BAD_REQUEST
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                return (status, format!("Couldn't start a new archive: {}", e)).into_response();
            }
        }
    }

    let acc = match cfg.account_by_id_mut(&account_id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, "Account not found").into_response(),
    };
    if let Some(n) = payload.name {
        acc.name = n;
    }
    if archived.is_none() {
        acc.imap_server = new_server;
        acc.imap_port = new_port;
        acc.username = new_username;
    }
    acc.retention_days = payload.retention_days;
    if let Some(sch) = payload.schedule {
        acc.schedule = Some(sch);
    }
    if let Some(e) = payload.enabled {
        acc.enabled = e;
    }
    if let Some(trust) = payload.trust_server_ids {
        acc.trust_server_ids = trust;
    }

    if archived.is_none()
        && let Some(pw) = new_password
            && let Err(e) = state.credentials.set_account_password(acc, &pw) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update secret: {}", e)).into_response();
        }

    let updated_name = acc.name.clone();
    let updated_email = acc.email.clone();

    if let Err(e) = cfg.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save config: {}", e)).into_response();
    }

    // Reload scheduler (still holding the gate after a switch)
    let warning = reload_scheduler(&state, &cfg).await;

    let message = match &archived {
        Some(switched) => format!(
            "Account '{}' ({}) moved to a new connection; the mail archived so far is now the read-only archive '{}' ({})",
            updated_name, updated_email, switched.archive.name, switched.archive.id
        ),
        None if connection_changed => format!(
            "Account '{}' ({}) configuration updated; connection changed and password re-entered",
            updated_name, updated_email
        ),
        None => format!("Account '{}' ({}) configuration updated", updated_name, updated_email),
    };
    mailbackup_core::event_log::log_event(
        if archived.is_some() { "ACCOUNT_ARCHIVED" } else { "ACCOUNT_MODIFIED" },
        &message,
    );
    drop(archived);

    (StatusCode::OK, format!("Account updated.{}", warning.unwrap_or_default())).into_response()
}

async fn api_delete_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let mut cfg = state.config.write().await;
    let target = cfg.accounts.iter().find(|a| a.id == account_id).cloned();
    let target_name = target.as_ref().map(|a| a.name.clone()).unwrap_or_else(|| account_id.clone());
    cfg.accounts.retain(|a| a.id != account_id);
    // Archives have no password of their own
    if let Some(acc) = target.as_ref().filter(|a| !a.is_archive()) {
        let _ = state.credentials.delete_password(acc.credential_ref());
    }
    let _ = cfg.save(&state.config_path);

    // Reload scheduler
    let _ = reload_scheduler(&state, &cfg).await;

    mailbackup_core::event_log::log_event(
        "ACCOUNT_DELETED",
        &format!("Account '{}' (ID: {}) deleted", target_name, account_id),
    );

    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct TestDirectPayload {
    email: String,
    server: String,
    port: u16,
    username: String,
    password: String,
}

async fn api_test_direct(Json(payload): Json<TestDirectPayload>) -> impl IntoResponse {
    let dummy_acc = AccountConfig {
        id: "test".to_string(),
        name: "Test".to_string(),
        email: payload.email,
        provider: ProviderType::GenericImap,
        imap_server: payload.server.trim().to_string(),
        imap_port: payload.port,
        use_tls: true,
        auth_type: AuthType::Password,
        username: payload.username.trim().to_string(),
        schedule: None,
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
        storage_namespace: None,
        credential_ref: None,
        archive: None,
        trust_server_ids: false,
    };

    let connect = ImapSyncEngine::connect(&dummy_acc, &payload.password);
    match tokio::time::timeout(TEST_CONNECTION_TIMEOUT, connect).await {
        Ok(Ok(mut session)) => {
            let _ = session.logout().await;
            (StatusCode::OK, "Success").into_response()
        }
        Ok(Err(e)) => {
            info!("Test connection to {}:{} failed: {}", dummy_acc.imap_server, dummy_acc.imap_port, e);
            (StatusCode::BAD_REQUEST, test_connection_message(Some(&e), &dummy_acc)).into_response()
        }
        Err(_) => {
            info!("Test connection to {}:{} timed out", dummy_acc.imap_server, dummy_acc.imap_port);
            (StatusCode::BAD_REQUEST, test_connection_message(None, &dummy_acc)).into_response()
        }
    }
}

const TEST_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// User-facing result of a failed connection test. Raw errors (connection
/// refused vs. TLS failure vs. timeout) would show whether a port is open, so
/// they are folded into one "could not connect" message and only logged.
/// `None` means the attempt timed out.
fn test_connection_message(err: Option<&mailbackup_core::Error>, acc: &AccountConfig) -> String {
    match err {
        Some(mailbackup_core::Error::AuthFailed(..)) => {
            "Login failed. Check the username and password.".to_string()
        }
        Some(mailbackup_core::Error::Tls(msg)) if msg.to_lowercase().contains("certificate") => {
            format!("The TLS certificate of {} isn't valid for this host.", acc.imap_server)
        }
        _ => format!(
            "Could not connect to {}:{}. Check the host and port, and that the server accepts TLS (IMAPS).",
            acc.imap_server, acc.imap_port
        ),
    }
}

async fn api_get_folders(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_folders(&account_id) {
        Ok(folders) => Json(folders).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// The account's server id sources that are distrusted (inconsistent ids)
/// or disabled (unparseable responses); see issue #33.
async fn api_get_server_id_states(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    match state.db.server_id_states(&account_id) {
        Ok(states) => Json(states).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn api_get_messages(
    State(state): State<AppState>,
    Path(folder_id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_messages_for_folder(&folder_id) {
        Ok(messages) => Json(messages).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct MessageDetailResponse {
    id: String,
    account_id: String,
    folder_id: String,
    subject: Option<String>,
    from_addr: Option<String>,
    to_addrs: Option<String>,
    date: Option<chrono::DateTime<chrono::Utc>>,
    body_html: Option<String>,
    body_text: Option<String>,
    attachments: Vec<AttachmentDetail>,
}

#[derive(Serialize)]
struct AttachmentDetail {
    filename: String,
    mime_type: String,
    size_bytes: u64,
}

async fn api_get_message_detail(
    State(state): State<AppState>,
    Path(message_id): Path<String>,
) -> impl IntoResponse {
    let msg_rec = match state.db.get_message_by_id(&message_id) {
        Ok(Some(m)) => m,
        _ => return (StatusCode::NOT_FOUND, "Message not found").into_response(),
    };

    let eml_bytes = match state.storage.read_eml(&msg_rec.relative_path) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read .eml file: {}", e)).into_response(),
    };

    let parsed = MessageParser::default().parse(&eml_bytes);
    let (html, text, attachments) = if let Some(p) = parsed {
        // Inline images (`cid:`) as data: URIs; the viewer blocks remote content
        let html_content = p.body_html(0).map(|s| mailbackup_core::html_view::inline_cid_images(&s, &p));
        let text_content = p.body_text(0).map(|s| s.to_string());

        let atts = mailbackup_core::attachments::summaries(&p)
            .into_iter()
            .map(|(filename, mime_type, size_bytes)| AttachmentDetail { filename, mime_type, size_bytes })
            .collect();
        (html_content, text_content, atts)
    } else {
        (None, None, Vec::new())
    };

    let resp = MessageDetailResponse {
        id: msg_rec.id,
        account_id: msg_rec.account_id,
        folder_id: msg_rec.folder_id,
        subject: msg_rec.subject,
        from_addr: msg_rec.from_addr,
        to_addrs: msg_rec.to_addrs,
        date: msg_rec.date,
        body_html: html,
        body_text: text,
        attachments,
    };

    Json(resp).into_response()
}

async fn api_download_eml(
    State(state): State<AppState>,
    Path(message_id): Path<String>,
) -> impl IntoResponse {
    let msg = match state.db.get_message_by_id(&message_id) {
        Ok(Some(m)) => m,
        _ => return (StatusCode::NOT_FOUND, "Message not found").into_response(),
    };

    match state.storage.read_eml(&msg.relative_path) {
        Ok(bytes) => {
            let filename = format!("{}.eml", msg.uid);
            let mut res = Response::new(Body::from(bytes));
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("message/rfc822"),
            );
            res.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                attachment_disposition(&filename),
            );
            res
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// One attachment of an archived message, decoded: the `index`-th entry of
/// the message detail's `attachments` (`mailbackup_core::attachments`).
/// Always a download (`application/octet-stream`, `Content-Disposition:
/// attachment`), so no attachment is ever rendered on this origin.
async fn api_download_attachment(
    State(state): State<AppState>,
    Path((message_id, index)): Path<(String, usize)>,
) -> Response {
    let msg = match state.db.get_message_by_id(&message_id) {
        Ok(Some(m)) => m,
        _ => return (StatusCode::NOT_FOUND, "Message not found").into_response(),
    };
    let eml = match state.storage.read_eml(&msg.relative_path) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let Some(parsed) = MessageParser::default().parse(&eml) else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };
    let Some(part) = mailbackup_core::attachments::parts(&parsed).nth(index) else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };
    let filename = attachment_filename(part.attachment_name(), part.content_type().as_ref(), index);
    let mut res = Response::new(Body::from(part.decoded().into_owned()));
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    res.headers_mut().insert(header::CONTENT_DISPOSITION, attachment_disposition(&filename));
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// The name an attachment is saved under: its own name (without any
/// directory part), else `attachment-<n>` with an extension for its type.
fn attachment_filename(name: Option<&str>, ctype: Option<&mail_parser::ContentType<'_>>, index: usize) -> String {
    let own = name
        .map(|n| n.rsplit(['/', '\\']).next().unwrap_or("").trim())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..");
    if let Some(own) = own {
        return own.to_string();
    }
    let ext = ctype.and_then(|c| {
        let essence = format!("{}/{}", c.ctype(), c.subtype()?).to_ascii_lowercase();
        if essence == "message/rfc822" {
            return Some("eml");
        }
        mime_guess::get_mime_extensions_str(&essence)?.first().copied()
    });
    match ext {
        Some(ext) => format!("attachment-{}.{}", index + 1, ext),
        None => format!("attachment-{}", index + 1),
    }
}

#[derive(Deserialize, Default)]
struct SearchParams {
    q: Option<String>,
    exclude: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cc: Option<String>,
    subject: Option<String>,
    date_from: Option<String>,
    date_to: Option<String>,
    account_id: Option<String>,
    folder_id: Option<String>,
    has_attachments: Option<bool>,
    att_name: Option<String>,
    att_type: Option<String>,
    min_size_mb: Option<f64>,
    include_deleted: Option<bool>,
    limit: Option<u32>,
}

async fn api_search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let min_size_bytes = params.min_size_mb.map(|mb| (mb * 1024.0 * 1024.0) as u64);

    let filter = AdvancedSearchFilter {
        query: params.q,
        exclude_words: params.exclude,
        from: params.from,
        to: params.to,
        cc: params.cc,
        subject: params.subject,
        date_from: params.date_from,
        date_to: params.date_to,
        account_id: params.account_id,
        folder_id: params.folder_id,
        has_attachments: params.has_attachments,
        attachment_name: params.att_name,
        attachment_type: params.att_type,
        min_size_bytes,
        include_deleted: params.include_deleted,
        limit: params.limit.or(Some(50)),
    };

    match state.db.search_advanced(&filter) {
        Ok(results) => Json(results).into_response(),
        Err(e) => (error_status(&e), e.to_string()).into_response(),
    }
}

async fn api_get_sync_status(State(state): State<AppState>) -> impl IntoResponse {
    let syncs = state.active_syncs.read().unwrap();
    let list: Vec<SyncStatus> = syncs.values().cloned().collect();
    Json(list).into_response()
}

async fn api_sync_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let cfg = state.config.read().await;
    let acc = match cfg.account_by_id(&account_id) {
        Some(a) => a.clone(),
        None => return (StatusCode::NOT_FOUND, "Account not found").into_response(),
    };
    let limits = mailbackup_core::imap::Limits::from_settings(&cfg.settings);
    drop(cfg);
    if acc.is_archive() {
        return (StatusCode::CONFLICT, "This account is a read-only archive and isn't synced").into_response();
    }

    // Early feedback; the sync itself reads the password again under the gate
    if let Err(e) = state.credentials.get_account_password(&acc) {
        return (StatusCode::BAD_REQUEST, format!("No credentials: {}", e)).into_response();
    }

    let config_path = state.config_path.clone();
    let credentials = state.credentials.clone();
    let db = state.db.clone();
    let storage = state.storage.clone();
    let active_syncs = state.active_syncs.clone();

    // Register initial syncing state
    {
        let mut syncs = active_syncs.write().unwrap();
        syncs.insert(
            acc.id.clone(),
            SyncStatus {
                account_id: acc.id.clone(),
                account_name: acc.name.clone(),
                is_syncing: true,
                current_folder: "Connecting to IMAP...".to_string(),
                total_messages: 0,
                processed_messages: 0,
                downloaded_bytes: 0,
                status: "connecting".to_string(),
                error: None,
            },
        );
    }

    mailbackup_core::event_log::log_event(
        "SYNC_STARTED",
        &format!("Sync started for account '{}' ({})", acc.name, acc.email),
    );

    tokio::spawn(async move {
        // Hold the account's sync gate for the whole sync, and sync the
        // account as the config on disk has it once the gate is ours: a change
        // of its connection may have finished while this request waited
        let gated = match mailbackup_core::sync_gate::begin_account_sync(&db, &credentials, &config_path, &acc.id).await {
            Ok((gate, current)) => credentials.get_account_password(&current).map(|pw| (gate, current, pw)),
            Err(e) => Err(e),
        };
        let (_gate, acc, password) = match gated {
            Ok(g) => g,
            Err(e) => {
                let err_msg = e.to_string();
                mailbackup_core::event_log::log_event(
                    "SYNC_ERROR",
                    &format!("Account '{}' sync not started: {}", acc.name, err_msg),
                );
                if let Ok(mut syncs) = active_syncs.write() {
                    syncs.insert(
                        acc.id.clone(),
                        SyncStatus {
                            account_id: acc.id.clone(),
                            account_name: acc.name.clone(),
                            is_syncing: false,
                            current_folder: "Failed".to_string(),
                            total_messages: 0,
                            processed_messages: 0,
                            downloaded_bytes: 0,
                            status: "failed".to_string(),
                            error: Some(err_msg),
                        },
                    );
                }
                return;
            }
        };
        let sync_engine = ImapSyncEngine::new(db.clone(), storage.clone()).with_limits(limits);
        let active_syncs_cb = active_syncs.clone();
        let acc_id_cb = acc.id.clone();
        let acc_name_cb = acc.name.clone();

        let progress_cb = move |p: &mailbackup_core::imap::SyncProgress| {
            if let Ok(mut syncs) = active_syncs_cb.write() {
                syncs.insert(
                    acc_id_cb.clone(),
                    SyncStatus {
                        account_id: acc_id_cb.clone(),
                        account_name: acc_name_cb.clone(),
                        is_syncing: true,
                        current_folder: p.current_folder.clone(),
                        total_messages: p.total_messages,
                        processed_messages: p.processed_messages,
                        downloaded_bytes: p.downloaded_bytes,
                        status: "syncing".to_string(),
                        error: None,
                    },
                );
            }
        };

        // A sync that stopped part-way, or left messages out for their size,
        // is incomplete: reported as an error
        let result = match sync_engine.sync_account(&acc, &password, Some(progress_cb)).await {
            Ok(p) if p.incomplete_reason().is_some() => Err(mailbackup_core::Error::Other(format!(
                "incomplete after {} message(s): {}",
                p.processed_messages,
                p.incomplete_reason().unwrap_or_default()
            ))),
            other => other,
        };
        match result {
            Ok(p) => {
                let mb = (p.downloaded_bytes as f64) / (1024.0 * 1024.0);
                mailbackup_core::event_log::log_event(
                    "SYNC_SUCCESS",
                    &format!(
                        "Account '{}' sync completed: {} message(s), {:.2} MB downloaded",
                        acc.name, p.processed_messages, mb
                    ),
                );

                if let Ok(mut syncs) = active_syncs.write() {
                    syncs.insert(
                        acc.id.clone(),
                        SyncStatus {
                            account_id: acc.id.clone(),
                            account_name: acc.name.clone(),
                            is_syncing: false,
                            current_folder: "Finished".to_string(),
                            total_messages: p.total_messages,
                            processed_messages: p.processed_messages,
                            downloaded_bytes: p.downloaded_bytes,
                            status: "completed".to_string(),
                            error: None,
                        },
                    );
                }
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!("Background sync error for {}: {}", acc.id, err_msg);
                mailbackup_core::event_log::log_event(
                    "SYNC_ERROR",
                    &format!("Account '{}' sync error: {}", acc.name, err_msg),
                );

                if let Ok(mut syncs) = active_syncs.write() {
                    syncs.insert(
                        acc.id.clone(),
                        SyncStatus {
                            account_id: acc.id.clone(),
                            account_name: acc.name.clone(),
                            is_syncing: false,
                            current_folder: "Failed".to_string(),
                            total_messages: 0,
                            processed_messages: 0,
                            downloaded_bytes: 0,
                            status: "failed".to_string(),
                            error: Some(err_msg),
                        },
                    );
                }
            }
        }

        // Enforce retention
        let retention = RetentionManager::new(&db, &storage);
        let _ = retention.enforce_retention(&acc.id, acc.retention_days);
    });

    (StatusCode::ACCEPTED, "Sync started").into_response()
}

#[derive(Deserialize)]
struct ExportMboxPayload {
    account_id: String,
    folder_id: Option<String>,
    output_path: String,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Serialize)]
struct ExportResult {
    exported_count: usize,
    /// Messages whose file couldn't be read, so they are not in the export
    skipped_count: usize,
    output_path: String,
}

#[derive(Serialize)]
struct ExportConflictResponse {
    error: String,
    message: String,
    existing_path: String,
    suggested_path: String,
}

async fn api_export_mbox(
    State(state): State<AppState>,
    Json(payload): Json<ExportMboxPayload>,
) -> impl IntoResponse {
    let requested = mailbackup_core::config::resolve_export_path(&payload.output_path);
    let target = {
        let cfg = state.config.read().await;
        PathPolicy::for_exports(&cfg).validate_export_target(&requested)
    };
    let target = match target {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let folder = payload.folder_id.as_deref().map(str::trim).filter(|f| !f.is_empty() && *f != "ALL");
    let paths = match state.db.message_paths(&payload.account_id, folder) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let final_output_path = target.path;

    if !payload.overwrite && target.exists {
        let suggested = mailbackup_core::config::find_available_path(&final_output_path);
        let path_str = final_output_path.to_string_lossy().to_string();
        return (
            StatusCode::CONFLICT,
            Json(ExportConflictResponse {
                error: "FILE_EXISTS".to_string(),
                message: format!("A file already exists at '{}'. Overwrite?", path_str),
                existing_path: path_str,
                suggested_path: suggested.to_string_lossy().to_string(),
            }),
        )
            .into_response();
    }

    let storage = state.storage.clone();
    let output = final_output_path.clone();
    let exported = tokio::task::spawn_blocking(move || {
        MboxExporter::new(&storage).export_to_mbox_counted(&paths, &output, payload.overwrite)
    })
    .await
    .unwrap_or_else(|e| Err(mailbackup_core::Error::Other(format!("export task failed: {}", e))));
    match exported {
        Ok(count) => {
            let path_str = final_output_path.to_string_lossy().to_string();
            mailbackup_core::event_log::log_event(
                "ARCHIVE_EXPORTED",
                &format!(
                    "Exported {} message(s) to .mbox archive: {}{}",
                    count.written,
                    path_str,
                    if count.skipped > 0 { format!(" ({} could not be read and are missing)", count.skipped) } else { String::new() }
                ),
            );
            Json(ExportResult {
                exported_count: count.written,
                skipped_count: count.skipped,
                output_path: path_str,
            })
            .into_response()
        }
        Err(e) => {
            let err_msg = format!("Failed to export to {}: {}", final_output_path.display(), e);
            mailbackup_core::event_log::log_event("EXPORT_ERROR", &err_msg);
            (StatusCode::INTERNAL_SERVER_ERROR, err_msg).into_response()
        }
    }
}

#[derive(Serialize)]
struct ExportLocationItem {
    name: String,
    path: String,
}

#[derive(Serialize)]
struct ExportLocationsResponse {
    default_dir: String,
    locations: Vec<ExportLocationItem>,
}

async fn api_export_locations(State(state): State<AppState>) -> impl IntoResponse {
    let default_dir = mailbackup_core::config::default_export_dir()
        .to_string_lossy()
        .to_string();
    let locs = system_export_locations();
    let system: Vec<PathBuf> = locs.iter().filter_map(|(_, p)| normalize_dir(p)).collect();
    let approved: Vec<PathBuf> = state
        .config
        .read()
        .await
        .settings
        .approved_dirs
        .iter()
        .filter(|p| normalize_dir(p).map(|n| !system.contains(&n)).unwrap_or(true))
        .cloned()
        .collect();
    let locations = locs
        .into_iter()
        .map(|(name, path)| ExportLocationItem {
            name: name.to_string(),
            path: path.to_string_lossy().to_string(),
        })
        .chain(approved.into_iter().map(|path| ExportLocationItem {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.to_string_lossy().to_string()),
            path: path.to_string_lossy().to_string(),
        }))
        .collect();

    Json(ExportLocationsResponse {
        default_dir,
        locations,
    })
}

#[derive(Deserialize)]
struct CheckPathQuery {
    path: String,
}

#[derive(Serialize)]
struct CheckPathResponse {
    exists: bool,
    resolved_path: String,
    suggested_path: String,
}

async fn api_export_check_path(
    State(state): State<AppState>,
    Query(query): Query<CheckPathQuery>,
) -> impl IntoResponse {
    let requested = mailbackup_core::config::resolve_export_path(&query.path);
    let target = {
        let cfg = state.config.read().await;
        PathPolicy::for_exports(&cfg).validate_export_target(&requested)
    };
    let target = match target {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let suggested = if target.exists {
        mailbackup_core::config::find_available_path(&target.path)
    } else {
        target.path.clone()
    };

    Json(CheckPathResponse {
        exists: target.exists,
        resolved_path: target.path.to_string_lossy().to_string(),
        suggested_path: suggested.to_string_lossy().to_string(),
    })
    .into_response()
}

#[derive(Serialize)]
struct PickDirectoryResponse {
    selected: bool,
    path: Option<String>,
}

/// Opens the native folder dialog. A folder the user picks there becomes an
/// approved location for exports and storage (`settings.approved_dirs`): only a
/// person clicking in the OS dialog can add one, not an API caller.
async fn api_pick_directory(State(state): State<AppState>) -> impl IntoResponse {
    let res = tokio::task::spawn_blocking(pick_directory_native)
        .await
        .unwrap_or(None);

    // Canonical form drops the trailing slash osascript adds and resolves symlinks.
    let res = res.map(|p| normalize_dir(&p).unwrap_or(p));
    if let Some(ref path) = res {
        let mut cfg = state.config.write().await;
        let already_allowed = system_export_locations()
            .into_iter()
            .map(|(_, p)| p)
            .chain(cfg.settings.approved_dirs.iter().cloned())
            .any(|p| normalize_dir(&p).as_ref() == Some(path));
        if !already_allowed {
            cfg.settings.approved_dirs.push(path.clone());
            if let Err(e) = cfg.save(&state.config_path) {
                error!("Failed to save approved folder {}: {}", path.display(), e);
            }
        }
    }

    match res {
        Some(path) => Json(PickDirectoryResponse {
            selected: true,
            path: Some(path.to_string_lossy().to_string()),
        }),
        None => Json(PickDirectoryResponse {
            selected: false,
            path: None,
        }),
    }
}

/// Helper programs (dialogs) come from fixed system folders, never from
/// `PATH` (issue #75): `None` if there is no trusted copy.
fn system_helper(name: &str) -> Option<PathBuf> {
    match mailbackup_core::service::trusted_program(name) {
        Ok(path) => Some(path),
        Err(e) => {
            tracing::debug!("{}", e);
            None
        }
    }
}

fn pick_directory_native() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new(system_helper("osascript")?)
            .arg("-e")
            .arg("POSIX path of (choose folder with prompt \"Select Export Destination Folder:\")")
            .output()
            .ok()?;
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                return Some(PathBuf::from(path_str));
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let script = "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.Description = 'Select Export Destination Folder'; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }";
        let output = std::process::Command::new(system_helper("powershell")?)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .ok()?;
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                return Some(PathBuf::from(path_str));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(zenity) = system_helper("zenity")
            && let Ok(output) = std::process::Command::new(zenity)
            .args(["--file-selection", "--directory", "--title=Select Export Destination Folder"])
            .output()
            && output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                return Some(PathBuf::from(path_str));
            }
        }
    }
    None
}

#[derive(Deserialize)]
struct DownloadMboxQuery {
    account_id: String,
    folder_id: Option<String>,
}

async fn api_download_mbox(
    State(state): State<AppState>,
    Query(query): Query<DownloadMboxQuery>,
) -> impl IntoResponse {
    let folder = query.folder_id.as_deref().map(str::trim).filter(|f| !f.is_empty() && *f != "ALL");
    let paths = match state.db.message_paths(&query.account_id, folder) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Streamed (issue #78): produced while the client reads, a few chunks at
    // a time, and stopped when the client goes away
    let (writer, body) = streaming::channel();
    let storage = state.storage.clone();
    tokio::task::spawn_blocking(move || {
        let mut writer = writer;
        let exporter = MboxExporter::new(&storage);
        match exporter.export_counted(&paths, &mut writer) {
            Ok(count) => mailbackup_core::event_log::log_event(
                "ARCHIVE_EXPORTED",
                &format!(
                    "Downloaded .mbox archive containing {} message(s){}",
                    count.written,
                    if count.skipped > 0 { format!("; {} could not be read and are missing", count.skipped) } else { String::new() }
                ),
            ),
            Err(_) if writer.is_closed() => info!(".mbox download stopped: the client went away"),
            Err(e) => {
                let why = format!(".mbox download failed after it started: {}", e);
                mailbackup_core::event_log::log_event("EXPORT_ERROR", &why);
                // The client sees a failed transfer, not a short file that looks complete
                writer.fail(why);
            }
        }
    });

    let timestamp = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let filename = format!("backup_{}.mbox", timestamp);
    let mut res = Response::new(body);
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/mbox"));
    res.headers_mut().insert(header::CONTENT_DISPOSITION, attachment_disposition(&filename));
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.into_response()
}

#[derive(Serialize)]
pub struct SettingsResponse {
    pub data_dir: String,
    pub db_path: String,
    pub default_schedule: String,
    pub default_retention_days: Option<u32>,
    pub notifications_enabled: bool,
    pub web_port: u16,
    pub close_to_tray: bool,
    pub autostart: bool,
    pub run_as_service: bool,
    pub log_retention_days: Option<u32>,
    pub service_status: mailbackup_core::service::ServiceStatus,
    pub default_export_dir: String,
    /// The desktop app's download folder; empty for the system Downloads folder
    pub download_dir: String,
    /// The folder downloads go to when `download_dir` is empty
    pub default_download_dir: String,
    pub ask_download_location: bool,
    /// The `web_server_enabled` setting
    pub web_server_enabled: bool,
    /// The port the web server listens on right now, if it does
    pub web_server_port: Option<u16>,
    /// The web server can't be turned off here: this is the headless or
    /// background-service server
    pub web_server_always_on: bool,
    pub version: String,
}

async fn api_get_version() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION")
    })).into_response()
}

async fn api_get_settings(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.read().await;
    let res = SettingsResponse {
        data_dir: cfg.data_dir.to_string_lossy().to_string(),
        db_path: state.db.path().to_string_lossy().to_string(),
        default_schedule: cfg.settings.default_schedule.clone(),
        default_retention_days: cfg.settings.default_retention_days,
        notifications_enabled: cfg.settings.notifications_enabled,
        web_port: cfg.settings.web_port,
        close_to_tray: cfg.settings.close_to_tray,
        autostart: cfg.settings.autostart,
        run_as_service: cfg.settings.run_as_service,
        log_retention_days: cfg.settings.log_retention_days,
        service_status: mailbackup_core::service::get_service_status(),
        default_export_dir: mailbackup_core::config::default_export_dir().to_string_lossy().to_string(),
        download_dir: cfg.settings.download_dir.as_deref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        default_download_dir: mailbackup_core::config::default_download_dir().to_string_lossy().to_string(),
        ask_download_location: cfg.settings.ask_download_location,
        web_server_enabled: cfg.settings.web_server_enabled,
        web_server_port: match &state.web {
            Some(web) => web.port().await,
            None => None,
        },
        web_server_always_on: state.web.as_ref().is_some_and(|w| w.always_on()),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Json(res).into_response()
}

#[derive(Deserialize)]
pub struct UpdateSettingsPayload {
    pub data_dir: Option<String>,
    pub move_existing: Option<bool>,
    pub db_path: Option<String>,
    pub move_db_existing: Option<bool>,
    pub close_to_tray: Option<bool>,
    pub autostart: Option<bool>,
    pub run_as_service: Option<bool>,
    pub log_retention_days: Option<u32>,
    /// The desktop app's download folder; empty resets it to Downloads
    pub download_dir: Option<String>,
    pub ask_download_location: Option<bool>,
    /// Turn the web server (browser access) on or off; see
    /// `GlobalSettings::web_server_enabled`
    pub web_server_enabled: Option<bool>,
}

#[derive(Serialize)]
pub struct UpdateSettingsResponse {
    pub success: bool,
    pub data_dir: String,
    pub db_path: String,
    pub migrated_files: u64,
    pub close_to_tray: bool,
    pub autostart: bool,
    pub run_as_service: bool,
    pub log_retention_days: Option<u32>,
    pub download_dir: String,
    pub ask_download_location: bool,
    pub web_server_enabled: bool,
    pub service_status: mailbackup_core::service::ServiceStatus,
    pub message: String,
}

async fn api_update_settings(
    State(state): State<AppState>,
    Json(payload): Json<UpdateSettingsPayload>,
) -> impl IntoResponse {
    let mut migrated_files = 0u64;
    let mut resolved_storage_path = None;
    let mut resolved_db_path = None;

    // 0. Validate requested locations before changing anything
    let non_empty = |raw: &Option<String>| {
        raw.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(mailbackup_core::config::resolve_path)
    };
    let current_db = state.db.path();
    let move_db = payload.move_db_existing.unwrap_or(true);
    let (requested_dir, requested_db) = {
        let cfg = state.config.read().await;
        let policy = PathPolicy::for_storage(&cfg);
        let move_existing = payload.move_existing.unwrap_or(true);
        let dir = non_empty(&payload.data_dir).map(|p| policy.validate_data_dir(&p, &cfg.data_dir, move_existing));
        let db = non_empty(&payload.db_path).map(|p| policy.validate_db_path(&p, &current_db, move_db));
        (dir.transpose(), db.transpose())
    };
    let (requested_dir, requested_db) = match (requested_dir, requested_db) {
        (Ok(dir), Ok(db)) => (dir, db),
        (Err(e), _) | (_, Err(e)) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // Some(None): back to the Downloads folder
    let requested_download_dir = match payload.download_dir.as_deref().map(str::trim) {
        None => None,
        Some("") => Some(None),
        Some(raw) => {
            let cfg = state.config.read().await;
            match PathPolicy::for_exports(&cfg).validate_download_dir(&mailbackup_core::config::resolve_path(raw)) {
                Ok(dir) => Some(Some(dir)),
                Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
            }
        }
    };

    // 1. Move the archive data directory if requested
    if let Some(target_path) = requested_dir {
        let current_dir = {
            let cfg = state.config.read().await;
            cfg.data_dir.clone()
        };

        if target_path != current_dir {
            let move_existing = payload.move_existing.unwrap_or(true);
            // Copy and switch in one step, with no archiver or pruning
            // between them (issue #79)
            match state.storage.relocate(&target_path, move_existing) {
                Ok(count) => migrated_files = count,
                Err(e) => {
                    let what = if move_existing { "migrate storage data" } else { "create the storage directory" };
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to {} at {}: {}", what, target_path.display(), e),
                    )
                        .into_response();
                }
            }
            mailbackup_core::event_log::log_event(
                "STORAGE_MOVED",
                &format!("Archive storage directory changed to {}", target_path.display()),
            );
            resolved_storage_path = Some(target_path);
        }
    }

    // 2. Relocate the database catalog if requested
    if let Some(target_db) = requested_db
        && target_db != current_db {
        if let Err(e) = state.db.relocate(&target_db, move_db) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to relocate database: {}", e),
            )
                .into_response();
        }
        mailbackup_core::event_log::log_event(
            "DATABASE_MOVED",
            &format!("Database catalog relocated from {} to {}", current_db.display(), target_db.display()),
        );
        resolved_db_path = Some(target_db);
    }

    let current_data_dir_str;
    let current_db_path_str;
    let current_close_to_tray;
    let current_autostart;
    let current_run_as_service;
    let current_log_retention;
    let current_download_dir;
    let current_ask_download;
    let current_web_server;

    // 3. Update config and save to disk
    {
        let mut cfg = state.config.write().await;

        if let Some(new_path) = resolved_storage_path.as_ref() {
            cfg.data_dir = new_path.clone();
        }

        if let Some(new_db) = resolved_db_path.as_ref() {
            cfg.db_path = new_db.clone();
        }

        if let Some(close_tray) = payload.close_to_tray {
            cfg.settings.close_to_tray = close_tray;
            mailbackup_core::event_log::log_event(
                "SETTINGS_UPDATED",
                &format!("Close to system tray set to {}", close_tray),
            );
        }

        if let Some(autostart_val) = payload.autostart {
            let _ = mailbackup_core::autostart::set_autostart(autostart_val);
            cfg.settings.autostart = autostart_val;
            mailbackup_core::event_log::log_event(
                "SETTINGS_UPDATED",
                &format!("OS autostart set to {}", autostart_val),
            );
        }

        if let Some(service_val) = payload.run_as_service {
            let account_ids: Vec<String> = cfg.accounts.iter().map(|a| a.id.clone()).collect();
            if let Err(e) = set_service_with_credentials(&state, service_val, &account_ids) {
                // A partial install keeps run_as_service on disk; don't overwrite it later
                cfg.settings.run_as_service = persisted_run_as_service(&state.config_path, cfg.settings.run_as_service);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to configure system service: {}", e),
                )
                    .into_response();
            }
            cfg.settings.run_as_service = service_val;
            let action = if service_val { "installed and started" } else { "uninstalled and stopped" };
            mailbackup_core::event_log::log_event(
                if service_val { "SERVICE_INSTALLED" } else { "SERVICE_REMOVED" },
                &format!("System background service {}", action),
            );
        }

        if let Some(dir) = requested_download_dir {
            mailbackup_core::event_log::log_event(
                "SETTINGS_UPDATED",
                &format!(
                    "Download folder set to {}",
                    dir.as_deref().map(|d| d.display().to_string()).unwrap_or_else(|| "the Downloads folder".to_string())
                ),
            );
            cfg.settings.download_dir = dir;
        }

        if let Some(enabled) = payload.web_server_enabled
            && enabled != cfg.settings.web_server_enabled {
            if let Some(web) = state.web.as_ref().filter(|w| !w.always_on()) {
                if enabled {
                    if let Err(e) = web.start().await {
                        return (
                            StatusCode::CONFLICT,
                            format!("Couldn't start the web server on port {}: {}", cfg.settings.web_port, e),
                        )
                            .into_response();
                    }
                } else {
                    // Returns once the port is closed, without waiting for
                    // requests in progress (this one may use the listener)
                    web.stop().await;
                }
            }
            cfg.settings.web_server_enabled = enabled;
            mailbackup_core::event_log::log_event(
                "SETTINGS_UPDATED",
                &format!("Web server (browser access) {}", if enabled { "turned on" } else { "turned off" }),
            );
        }

        if let Some(ask) = payload.ask_download_location {
            cfg.settings.ask_download_location = ask;
            mailbackup_core::event_log::log_event(
                "SETTINGS_UPDATED",
                &format!("Ask where to save each download set to {}", ask),
            );
        }

        if let Some(log_retention) = payload.log_retention_days {
            cfg.settings.log_retention_days = if log_retention == 0 { None } else { Some(log_retention) };
            let _ = mailbackup_core::event_log::prune_logs(cfg.settings.log_retention_days);
            mailbackup_core::event_log::log_event(
                "SETTINGS_UPDATED",
                &format!(
                    "Log retention policy set to {}",
                    cfg.settings.log_retention_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "Forever".to_string())
                ),
            );
        }

        if let Err(e) = cfg.save(&state.config_path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save config: {}", e),
            )
                .into_response();
        }

        current_data_dir_str = cfg.data_dir.to_string_lossy().to_string();
        current_db_path_str = cfg.db_path.to_string_lossy().to_string();
        current_close_to_tray = cfg.settings.close_to_tray;
        current_autostart = cfg.settings.autostart;
        current_run_as_service = cfg.settings.run_as_service;
        current_log_retention = cfg.settings.log_retention_days;
        current_download_dir = cfg.settings.download_dir.as_deref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        current_ask_download = cfg.settings.ask_download_location;
        current_web_server = cfg.settings.web_server_enabled;
    }

    // 4. If storage or db location changed, reload scheduler
    if resolved_storage_path.is_some() || resolved_db_path.is_some() {
        let mut sched = state.scheduler.lock().await;
        let cfg = state.config.read().await;
        if let Err(e) = sched.reload(Arc::new(cfg.clone())).await {
            tracing::warn!("Failed to reload scheduler after location change: {}", e);
        }
    }

    let mut messages = Vec::new();
    if let Some(ref p) = resolved_storage_path {
        messages.push(format!("Storage moved to {} ({} files migrated).", p.display(), migrated_files));
    }
    if let Some(ref db) = resolved_db_path {
        messages.push(format!("Database catalog relocated to {}.", db.display()));
    }
    if messages.is_empty() {
        messages.push("Settings updated successfully.".to_string());
    }

    Json(UpdateSettingsResponse {
        success: true,
        data_dir: current_data_dir_str,
        db_path: current_db_path_str,
        migrated_files,
        close_to_tray: current_close_to_tray,
        autostart: current_autostart,
        run_as_service: current_run_as_service,
        log_retention_days: current_log_retention,
        download_dir: current_download_dir,
        ask_download_location: current_ask_download,
        web_server_enabled: current_web_server,
        service_status: mailbackup_core::service::get_service_status(),
        message: messages.join(" "),
    })
    .into_response()
}

// Service Management Endpoints
#[derive(Deserialize)]
pub struct ServiceTogglePayload {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct ServiceToggleResponse {
    pub success: bool,
    pub enabled: bool,
    pub service_status: mailbackup_core::service::ServiceStatus,
    pub message: String,
}

/// Installs or removes the background service together with moving the
/// passwords where it can read them: enabling copies them to the local store
/// (verified) before installing; disabling uninstalls first, then moves them
/// back into the keyring (verified), leaving on disk what the keyring can't take.
fn set_service_with_credentials(state: &AppState, enabled: bool, account_ids: &[String]) -> mailbackup_core::Result<()> {
    set_service_with_credentials_using(
        state,
        enabled,
        account_ids,
        mailbackup_core::service::set_service_enabled,
        || mailbackup_core::service::get_service_status().installed,
    )
}

/// `settings.run_as_service` as saved in the config file (`fallback` if it
/// can't be read).
fn persisted_run_as_service(config_path: &std::path::Path, fallback: bool) -> bool {
    if !config_path.exists() {
        return fallback;
    }
    AppConfig::load_or_create(Some(config_path)).map(|cfg| cfg.settings.run_as_service).unwrap_or(fallback)
}

/// Sets `settings.run_as_service` in the config file on disk, leaving the
/// rest of the file as it is there.
fn persist_run_as_service(config_path: &std::path::Path, enabled: bool) -> mailbackup_core::Result<()> {
    let mut on_disk = AppConfig::load_or_create(Some(config_path))?;
    on_disk.settings.run_as_service = enabled;
    on_disk.save(config_path)
}

/// [`set_service_with_credentials`] with the install/uninstall step injected.
/// When enabling, `run_as_service: true` is written to the config before the
/// service is installed (installing starts it, and the service must start in
/// disk storage mode), and written back to `false` if the install fails.
fn set_service_with_credentials_using(
    state: &AppState,
    enabled: bool,
    account_ids: &[String],
    set_enabled: impl Fn(bool, &std::path::Path) -> mailbackup_core::Result<()>,
    still_installed: impl Fn() -> bool,
) -> mailbackup_core::Result<()> {
    let config_path = state.config_path.clone();
    if enabled {
        let change = state.credentials.switch_to_disk_storage(
            account_ids,
            || {
                persist_run_as_service(&config_path, true)?;
                set_enabled(true, &config_path)
            },
            // A failed install may have registered the service anyway: remove
            // it, and undo disk storage only once it's confirmed gone
            || {
                if let Err(e) = set_enabled(false, &config_path) {
                    tracing::warn!("Couldn't remove the partly installed service: {}", e);
                }
                if still_installed() {
                    mailbackup_core::event_log::log_event(
                        "SERVICE_PARTIAL_INSTALL",
                        "The background service may still be installed; its passwords stay in the local store",
                    );
                    return false;
                }
                if let Err(e) = persist_run_as_service(&config_path, false) {
                    tracing::warn!("Couldn't reset run_as_service after a failed install: {}", e);
                }
                true
            },
        )?;
        if !change.skipped_accounts.is_empty() {
            mailbackup_core::event_log::log_event(
                "SERVICE_CREDENTIALS",
                &format!("No saved password to copy for: {}", change.skipped_accounts.join(", ")),
            );
        }
    } else {
        let moved = state.credentials.switch_to_keyring_storage(
            || set_enabled(false, &config_path),
            still_installed,
        )?;
        persist_run_as_service(&config_path, false)?;
        if !moved.kept.is_empty() {
            mailbackup_core::event_log::log_event(
                "SERVICE_CREDENTIALS",
                &format!(
                    "{} saved passwords stay in the local encrypted store{}",
                    moved.kept.len(),
                    moved.reason.map(|r| format!(": {}", r)).unwrap_or_default()
                ),
            );
        }
    }
    Ok(())
}

async fn api_service_status() -> impl IntoResponse {
    let status = mailbackup_core::service::get_service_status();
    Json(status).into_response()
}

async fn api_service_toggle(
    State(state): State<AppState>,
    Json(payload): Json<ServiceTogglePayload>,
) -> impl IntoResponse {
    let account_ids: Vec<String> = state.config.read().await.accounts.iter().map(|a| a.id.clone()).collect();
    let res = set_service_with_credentials(&state, payload.enabled, &account_ids);
    match res {
        Ok(_) => {
            {
                let mut cfg = state.config.write().await;
                cfg.settings.run_as_service = payload.enabled;
                let _ = cfg.save(&state.config_path);
            }
            let action = if payload.enabled { "installed and started" } else { "uninstalled and stopped" };
            mailbackup_core::event_log::log_event(
                if payload.enabled { "SERVICE_INSTALLED" } else { "SERVICE_REMOVED" },
                &format!("System background service {}", action),
            );
            let status = mailbackup_core::service::get_service_status();
            (
                StatusCode::OK,
                Json(ServiceToggleResponse {
                    success: true,
                    enabled: payload.enabled,
                    service_status: status,
                    message: format!("System service {} successfully", action),
                }),
            )
                .into_response()
        }
        Err(e) => {
            {
                // A partial install keeps run_as_service on disk; don't overwrite it later
                let mut cfg = state.config.write().await;
                cfg.settings.run_as_service = persisted_run_as_service(&state.config_path, cfg.settings.run_as_service);
            }
            let status = mailbackup_core::service::get_service_status();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ServiceToggleResponse {
                    success: false,
                    enabled: !payload.enabled,
                    service_status: status,
                    message: format!("Failed to configure service: {}", e),
                }),
            )
                .into_response()
        }
    }
}

// Log Viewer Endpoints
#[derive(Serialize)]
pub struct LogsResponse {
    pub logs: Vec<mailbackup_core::event_log::LogEntry>,
    pub raw: String,
    pub path: String,
    pub log_retention_days: Option<u32>,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub files: Vec<mailbackup_core::event_log::LogFileInfo>,
}

#[derive(Deserialize)]
pub struct DownloadLogQuery {
    pub file: Option<String>,
}

async fn api_get_logs(State(state): State<AppState>) -> impl IntoResponse {
    let logs = mailbackup_core::event_log::get_recent_logs(200).unwrap_or_default();
    let raw = mailbackup_core::event_log::get_raw_log().unwrap_or_default();
    let path = mailbackup_core::event_log::log_file_path().to_string_lossy().to_string();
    let files = mailbackup_core::event_log::list_log_files().unwrap_or_default();
    let total_files = files.len();
    let total_size_bytes = files.iter().map(|f| f.size_bytes).sum();
    let log_retention_days = {
        let cfg = state.config.read().await;
        cfg.settings.log_retention_days
    };

    Json(LogsResponse {
        logs,
        raw,
        path,
        log_retention_days,
        total_files,
        total_size_bytes,
        files,
    }).into_response()
}

async fn api_list_log_files() -> impl IntoResponse {
    let files = mailbackup_core::event_log::list_log_files().unwrap_or_default();
    Json(files).into_response()
}

async fn api_download_logs(Query(query): Query<DownloadLogQuery>) -> impl IntoResponse {
    let (filename, content) = if let Some(ref name) = query.file {
        match mailbackup_core::event_log::get_log_file_content(name) {
            Ok(c) => (name.clone(), c),
            Err(e) => return (error_status(&e), e.to_string()).into_response(),
        }
    } else {
        ("mailbackup-events.log".to_string(), mailbackup_core::event_log::get_raw_log().unwrap_or_default())
    };

    let mut res = Response::new(Body::from(content));
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    res.headers_mut().insert(header::CONTENT_DISPOSITION, attachment_disposition(&filename));
    res.into_response()
}

async fn api_rotate_logs(State(state): State<AppState>) -> impl IntoResponse {
    let retention = {
        let cfg = state.config.read().await;
        cfg.settings.log_retention_days
    };
    match mailbackup_core::event_log::rotate_and_prune_logs(retention) {
        Ok(report) => {
            if report.rotated {
                let name = report.rotated_filename.as_deref().unwrap_or("events-daily.log");
                mailbackup_core::event_log::log_event(
                    "LOG_ROTATION",
                    &format!("Manual log rotation: rotated to {}", name),
                );
            }
            Json(serde_json::json!({
                "success": true,
                "rotated": report.rotated,
                "rotated_filename": report.rotated_filename,
                "pruned_files": report.pruned_files,
                "reclaimed_bytes": report.reclaimed_bytes,
            })).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to rotate logs: {}", e)).into_response()
        }
    }
}

async fn api_clear_logs() -> impl IntoResponse {
    match mailbackup_core::event_log::clear_log() {
        Ok(_) => (StatusCode::OK, "Logs cleared").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;
    use mailbackup_core::server_ids::ServerIdKind;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn test_router(dir: &std::path::Path) -> Router {
        test_router_with(dir, Vec::new()).await
    }

    async fn test_router_with(dir: &std::path::Path, extra_approved: Vec<PathBuf>) -> Router {
        create_router(test_state(dir, extra_approved).await)
    }

    async fn test_state(dir: &std::path::Path, extra_approved: Vec<PathBuf>) -> AppState {
        std::fs::create_dir_all(dir.join("exports")).unwrap();
        let mut config = AppConfig {
            data_dir: dir.join("state/data"),
            db_path: dir.join("state/catalog.db"),
            ..AppConfig::default()
        };
        config.settings.approved_dirs = vec![dir.join("exports")];
        config.settings.approved_dirs.extend(extra_approved);
        let db = Database::open_in_memory().unwrap();
        let storage = StorageEngine::new(&config.data_dir);
        let credentials = Arc::new(
            CredentialStore::with_paths(dir.join(".credentials_store.json"), dir.join(".credentials_key"))
                .with_passphrase(None)
                .with_keyring(Arc::new(mailbackup_core::keyring::NoKeyring)),
        );
        let scheduler = BackupScheduler::new(
            Arc::new(config.clone()),
            db.clone(),
            storage.clone(),
            credentials.clone(),
        )
        .await
        .unwrap();
        // These tests are about other things; the login is tested on its own
        // with it turned on (see `login_state`)
        config.settings.require_login = false;
        AppState {
            access: Arc::new(access::Access::new(dir.to_path_buf())),
            config: Arc::new(RwLock::new(config)),
            config_path: dir.join("config.yaml"),
            db,
            storage,
            credentials,
            scheduler: Arc::new(Mutex::new(scheduler)),
            active_syncs: Arc::new(StdRwLock::new(HashMap::new())),
            api_token: Arc::from(TOKEN),
            download_tickets: Arc::new(tickets::DownloadTickets::default()),
            identity: Arc::new(StdRwLock::new(runtime::ServerIdentity::new(8765))),
            web: None,
        }
    }

    #[tokio::test]
    async fn the_service_starts_with_disk_storage_already_saved() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        state.config.read().await.save(&state.config_path).unwrap();
        state.credentials.set_password("a", "pw").unwrap();

        set_service_with_credentials_using(&state, true, &["a".to_string()], |enabled, path| {
            assert!(enabled);
            // What the service process reads when the install starts it
            let on_disk = AppConfig::load_or_create(Some(path)).unwrap();
            assert!(on_disk.settings.run_as_service, "saved before the service starts");
            let service = CredentialStore::for_config(path, &on_disk.settings)
                .with_passphrase(None)
                .with_keyring(Arc::new(mailbackup_core::keyring::NoKeyring));
            assert!(service.disk_storage());
            assert_eq!(service.get_password("a").unwrap(), "pw");
            Ok(())
        }, || unreachable!())
        .unwrap();
        assert!(state.credentials.disk_storage());

        // Still installed: nothing changes on disk
        let err = set_service_with_credentials_using(&state, false, &[], |_, _| Ok(()), || true).unwrap_err();
        assert!(err.to_string().contains("still installed"));
        assert!(AppConfig::load_or_create(Some(&state.config_path)).unwrap().settings.run_as_service);

        set_service_with_credentials_using(&state, false, &[], |enabled, _| {
            assert!(!enabled);
            Ok(())
        }, || false)
        .unwrap();
        assert!(!AppConfig::load_or_create(Some(&state.config_path)).unwrap().settings.run_as_service);
    }

    #[tokio::test]
    async fn a_failed_service_install_resets_run_as_service() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        state.config.read().await.save(&state.config_path).unwrap();
        state.credentials.set_password("a", "pw").unwrap();

        let err = set_service_with_credentials_using(&state, true, &["a".to_string()], |_, _| {
            Err(mailbackup_core::Error::Other("authorization dismissed".into()))
        }, || false)
        .unwrap_err();
        assert!(err.to_string().contains("authorization dismissed"));
        assert!(!AppConfig::load_or_create(Some(&state.config_path)).unwrap().settings.run_as_service);
        assert!(!state.credentials.disk_storage());
        assert_eq!(state.credentials.get_password("a").unwrap(), "pw");
    }

    #[tokio::test]
    async fn a_partly_installed_service_keeps_disk_storage_and_its_setting() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        state.config.read().await.save(&state.config_path).unwrap();
        state.credentials.set_password("a", "pw").unwrap();

        // Like Linux: the unit is installed and enabled, then starting it is
        // refused, and removing it is refused too
        let installed = std::sync::atomic::AtomicBool::new(false);
        let removal_attempts = std::sync::atomic::AtomicUsize::new(0);
        let err = set_service_with_credentials_using(
            &state,
            true,
            &["a".to_string()],
            |enabled, _| {
                if enabled {
                    installed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err(mailbackup_core::Error::Other("restart authorization dismissed".into()))
                } else {
                    removal_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(mailbackup_core::Error::Other("removal authorization dismissed".into()))
                }
            },
            || installed.load(std::sync::atomic::Ordering::SeqCst),
        )
        .unwrap_err();
        assert!(err.to_string().contains("may still be installed"), "{}", err);
        assert_eq!(removal_attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        // The boot service can still start in disk mode and read the password
        let on_disk = AppConfig::load_or_create(Some(&state.config_path)).unwrap();
        assert!(on_disk.settings.run_as_service);
        assert!(state.credentials.disk_storage());
        let service = CredentialStore::for_config(&state.config_path, &on_disk.settings)
            .with_passphrase(None)
            .with_keyring(Arc::new(mailbackup_core::keyring::NoKeyring));
        assert_eq!(service.get_password("a").unwrap(), "pw");
        assert!(persisted_run_as_service(&state.config_path, false), "handlers sync the in-memory flag from this");
    }

    async fn status(router: &Router, req: HttpRequest<Body>) -> StatusCode {
        router.clone().oneshot(req).await.unwrap().status()
    }

    fn get(uri: &str, host: &str) -> axum::http::request::Builder {
        HttpRequest::builder().uri(uri).header(header::HOST, host)
    }

    #[tokio::test]
    async fn api_requires_token() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;

        let no_token = get("/api/version", "127.0.0.1:8765").body(Body::empty()).unwrap();
        assert_eq!(status(&router, no_token).await, StatusCode::UNAUTHORIZED);

        let wrong = get("/api/version", "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, "nope")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, wrong).await, StatusCode::UNAUTHORIZED);

        let header_ok = get("/api/version", "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, header_ok).await, StatusCode::OK);

        // The token is never accepted from the URL, on any route
        for uri in [
            format!("/api/version?token={}", TOKEN),
            format!("/api/logs/download?token={}", TOKEN),
            format!("/api/accounts/csv-template?token={}", TOKEN),
        ] {
            let query = get(&uri, "localhost:8765").body(Body::empty()).unwrap();
            assert_eq!(status(&router, query).await, StatusCode::UNAUTHORIZED, "{}", uri);
        }
    }

    #[tokio::test]
    async fn rejects_rebound_host_and_foreign_origin() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;

        // DNS rebinding: attacker domain resolving to 127.0.0.1
        let rebound = get("/", "evil.example:8765").body(Body::empty()).unwrap();
        assert_eq!(status(&router, rebound).await, StatusCode::FORBIDDEN);

        let foreign = get("/api/version", "127.0.0.1:8765")
            .header(header::ORIGIN, "https://evil.example")
            .header(API_TOKEN_HEADER, TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, foreign).await, StatusCode::FORBIDDEN);

        let mixed_case = get("/api/version", "LocalHost:8765")
            .header(header::ORIGIN, "http://localhost:8765")
            .header(API_TOKEN_HEADER, TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, mixed_case).await, StatusCode::OK);

        for origin in ["http://127.0.0.1:8765", "https://127.0.0.1:8765"] {
            let same_origin = get("/api/version", "127.0.0.1:8765")
                .header(header::ORIGIN, origin)
                .header(API_TOKEN_HEADER, TOKEN)
                .body(Body::empty())
                .unwrap();
            assert_eq!(status(&router, same_origin).await, StatusCode::OK, "{origin}");
        }
    }

    #[tokio::test]
    async fn no_cors_headers_and_index_carries_token() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;

        let preflight = HttpRequest::builder()
            .method("OPTIONS")
            .uri("/api/accounts")
            .header(header::HOST, "127.0.0.1:8765")
            .header(header::ORIGIN, "https://evil.example")
            .header("access-control-request-method", "PUT")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(preflight).await.unwrap();
        assert!(res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

        let index = get("/", "127.0.0.1:8765").body(Body::empty()).unwrap();
        let res = router.clone().oneshot(index).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains(TOKEN));
        assert!(!html.contains(API_TOKEN_PLACEHOLDER));
    }

    #[tokio::test]
    async fn responses_carry_csp_without_inline_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;

        let res = router
            .clone()
            .oneshot(get("/", "127.0.0.1:8765").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let csp = res.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap().to_string();
        let script_src = csp.split(';').map(str::trim).find(|d| d.starts_with("script-src")).unwrap();
        assert_eq!(script_src, "script-src 'self'");
        assert_eq!(res.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");

        // The served UI must not rely on inline scripts or inline event handlers.
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(!html.contains("<script>"), "inline <script> would be blocked by the CSP");
        assert!(!html.contains(" onclick="));
        let app_js = Assets::get("app.js").unwrap();
        assert!(!String::from_utf8_lossy(&app_js.data).contains(" onclick="));
    }

    fn authed_get(uri: &str) -> HttpRequest<Body> {
        get(uri, "127.0.0.1:8765").header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn malformed_search_dates_are_rejected_not_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        // Byte 10 of "123456789é" is inside the 'é'
        for query in [
            "date_from=123456789%C3%A9",
            "date_to=123456789%C3%A9",
            "date_to=2026-13-45",
            "date_from=yesterday",
            "date_from=2026-01-01junk",
        ] {
            let res = router.clone().oneshot(authed_get(&format!("/api/search?{}", query))).await.unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{}", query);
        }
        for query in ["date_from=2026-01-01", "date_to=2026-01-01T12:00:00Z", "date_from="] {
            let res = router.clone().oneshot(authed_get(&format!("/api/search?{}", query))).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{}", query);
        }
    }

    #[tokio::test]
    async fn log_download_names_are_validated_not_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        for name in ["%0d%0aevil.log", "evil%0A.log", "events.log%0d%0aSet-Cookie:%20x", "..%2Fsecret", "notes.txt"] {
            let res = router.clone().oneshot(authed_get(&format!("/api/logs/download?file={}", name))).await.unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{}", name);
        }
        let missing = router.clone().oneshot(authed_get("/api/logs/download?file=events-2000-01-01.log")).await.unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        // Service logs listed by the viewer stay downloadable
        let service_log = mailbackup_core::event_log::log_dir().join("service_err.log");
        let created = !service_log.exists();
        if created {
            std::fs::create_dir_all(service_log.parent().unwrap()).unwrap();
            std::fs::write(&service_log, "warning").unwrap();
        }
        let res = router.clone().oneshot(authed_get("/api/logs/download?file=service_err.log")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        if created {
            let _ = std::fs::remove_file(&service_log);
        }

        let active = router.clone().oneshot(authed_get("/api/logs/download")).await.unwrap();
        assert_eq!(active.status(), StatusCode::OK);
        let disposition = active.headers().get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap();
        assert!(disposition.starts_with("attachment; filename=\"mailbackup-events.log\""), "{}", disposition);
    }

    #[test]
    fn attachment_disposition_is_valid_for_any_name() {
        for name in ["a\r\nSet-Cookie: x", "quote\"and\\slash", "zürich 📬.mbox", "\u{7f}\u{0}", ""] {
            let value = attachment_disposition(name);
            let text = value.to_str().expect("visible ASCII only");
            assert!(text.starts_with("attachment; filename=\""), "{}", text);
            assert!(!text.contains('\r') && !text.contains('\n'));
            // filename= holds exactly one quoted string
            let quoted = text.trim_start_matches("attachment; filename=\"");
            let end = quoted.find('"').unwrap();
            assert!(!quoted[..end].contains('\\'));
        }
        let value = attachment_disposition("zürich.mbox");
        assert_eq!(
            value.to_str().unwrap(),
            "attachment; filename=\"z_rich.mbox\"; filename*=UTF-8''z%C3%BCrich.mbox"
        );
    }

    fn json_request(method: &str, uri: &str, body: serde_json::Value) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, TOKEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn export_request(path: &std::path::Path, overwrite: bool) -> HttpRequest<Body> {
        json_request(
            "POST",
            "/api/export/mbox",
            serde_json::json!({ "account_id": "acc", "output_path": path, "overwrite": overwrite }),
        )
    }

    #[tokio::test]
    async fn export_is_confined_to_allowed_folders() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let inside = dir.path().join("exports/archive.mbox");
        assert_eq!(status(&router, export_request(&inside, false)).await, StatusCode::OK);
        assert!(inside.exists());

        // Existing file: conflict unless overwrite is requested
        assert_eq!(status(&router, export_request(&inside, false)).await, StatusCode::CONFLICT);
        assert_eq!(status(&router, export_request(&inside, true)).await, StatusCode::OK);

        for bad in [
            outside.join("a.mbox"),
            dir.path().join("exports/../outside/a.mbox"),
            dir.path().join("exports/.hidden/a.mbox"),
            dir.path().join("exports/startup.sh"),
        ] {
            assert_eq!(status(&router, export_request(&bad, true)).await, StatusCode::BAD_REQUEST, "{}", bad.display());
        }
        assert!(!outside.join("a.mbox").exists());
    }

    #[tokio::test]
    async fn check_path_only_answers_for_allowed_targets() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;

        let uri = |p: &std::path::Path| format!("/api/export/check-path?path={}", p.display());
        let ok = get(&uri(&dir.path().join("exports/a.mbox")), "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, ok).await, StatusCode::OK);

        let outside = get(&uri(std::path::Path::new("/etc/passwd")), "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, outside).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn export_locations_skip_duplicate_approved_folders() {
        let dir = tempfile::tempdir().unwrap();
        let home = system_export_locations().into_iter().find(|(n, _)| *n == "Home").unwrap().1;
        // Home is a system location; osascript reports picked folders with a trailing slash
        let router = test_router_with(dir.path(), vec![PathBuf::from(format!("{}/", home.display()))]).await;

        let res = router
            .clone()
            .oneshot(
                get("/api/export/locations", "127.0.0.1:8765")
                    .header(API_TOKEN_HEADER, TOKEN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let home_canonical = normalize_dir(&home).unwrap();
        let home_entries = json["locations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|l| normalize_dir(std::path::Path::new(l["path"].as_str().unwrap())).as_ref() == Some(&home_canonical))
            .count();
        assert_eq!(home_entries, 1, "{json}");
    }

    #[tokio::test]
    async fn settings_locations_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let put = |body| json_request("PUT", "/api/settings", body);
        assert_eq!(
            status(&router, put(serde_json::json!({ "data_dir": outside.join("data") }))).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(&router, put(serde_json::json!({ "db_path": dir.path().join("exports/catalog.txt") }))).await,
            StatusCode::BAD_REQUEST
        );
        // A rejected db_path must not leave a half-applied data_dir move behind
        let new_data = dir.path().join("exports/archive-data");
        assert_eq!(
            status(&router, put(serde_json::json!({ "data_dir": new_data, "db_path": outside.join("x.db") }))).await,
            StatusCode::BAD_REQUEST
        );
        assert!(!new_data.exists());

        assert_eq!(
            status(&router, put(serde_json::json!({ "data_dir": new_data, "move_existing": false }))).await,
            StatusCode::OK
        );
        assert!(new_data.is_dir());
    }

    #[tokio::test]
    async fn download_settings_round_trip_and_are_confined() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        let settings = |router: Router| async move {
            let res = router.oneshot(authed("GET", "/api/settings", None)).await.unwrap();
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };
        let initial = settings(router.clone()).await;
        assert_eq!(initial["download_dir"], "");
        assert_eq!(initial["ask_download_location"], false);
        assert!(!initial["default_download_dir"].as_str().unwrap().is_empty());

        let put = |body| json_request("PUT", "/api/settings", body);
        // Only existing folders inside the allowed locations (here `exports`)
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        for bad in [outside.clone(), dir.path().join("exports/missing"), PathBuf::from("relative")] {
            assert_eq!(
                status(&router, put(serde_json::json!({ "download_dir": bad }))).await,
                StatusCode::BAD_REQUEST,
                "{}",
                bad.display()
            );
        }
        let target = dir.path().join("exports/mail");
        std::fs::create_dir_all(&target).unwrap();
        assert_eq!(
            status(&router, put(serde_json::json!({ "download_dir": target, "ask_download_location": true }))).await,
            StatusCode::OK
        );
        let after = settings(router.clone()).await;
        assert_eq!(after["download_dir"], target.canonicalize().unwrap().to_string_lossy().as_ref());
        assert_eq!(after["ask_download_location"], true);
        // Saved for the desktop app, which reads the config file
        let saved = AppConfig::load_or_create(Some(&dir.path().join("config.yaml"))).unwrap();
        assert_eq!(saved.settings.download_dir, Some(target.canonicalize().unwrap()));
        assert!(saved.settings.ask_download_location);

        // A rejected folder changes nothing else in the same request
        assert_eq!(
            status(&router, put(serde_json::json!({ "download_dir": outside, "ask_download_location": false }))).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(settings(router.clone()).await["ask_download_location"], true);

        // Empty: back to Downloads
        assert_eq!(
            status(&router, put(serde_json::json!({ "download_dir": "", "ask_download_location": false }))).await,
            StatusCode::OK
        );
        let reset = settings(router.clone()).await;
        assert_eq!(reset["download_dir"], "");
        assert_eq!(reset["ask_download_location"], false);
    }

    async fn get_account_json(router: &Router, id: &str) -> serde_json::Value {
        let res = router
            .clone()
            .oneshot(
                get(&format!("/api/accounts/{}", id), "127.0.0.1:8765")
                    .header(API_TOKEN_HEADER, TOKEN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn connection_changes_require_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        let creds = CredentialStore::with_paths(dir.path().join(".credentials_store.json"), dir.path().join(".credentials_key"))
            .with_keyring(Arc::new(mailbackup_core::keyring::NoKeyring));
        // Unique address so a real OS keyring on a developer machine isn't touched by a fixed key
        let email = format!("reauth-{}@example.com", getrandom_suffix());
        let id = StorageEngine::sanitize_slug(&email);

        let add = json_request(
            "POST",
            "/api/accounts",
            serde_json::json!({ "provider": "generic", "name": "A", "email": email, "server": " imap.example.com ",
                                "port": 993, "username": " user ", "password": "old-pw" }),
        );
        assert_eq!(status(&router, add).await, StatusCode::OK);
        let acc = get_account_json(&router, &id).await;
        assert_eq!(acc["imap_server"], "imap.example.com");
        assert_eq!(acc["username"], "user");

        let put = |body: serde_json::Value| json_request("PUT", &format!("/api/accounts/{}", id), body);
        let base = serde_json::json!({ "name": "A", "server": "imap.example.com", "port": 993, "username": "user" });
        let with = |patch: serde_json::Value| {
            let mut b = base.clone();
            b.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
            b
        };

        // Server, port or username change without a password: rejected, nothing saved
        for patch in [
            serde_json::json!({ "server": "imap.attacker.example" }),
            serde_json::json!({ "port": 1993 }),
            serde_json::json!({ "username": "other" }),
            serde_json::json!({ "server": "imap.attacker.example", "password": "" }),
        ] {
            assert_eq!(status(&router, put(with(patch.clone()))).await, StatusCode::BAD_REQUEST, "{patch}");
        }
        let acc = get_account_json(&router, &id).await;
        assert_eq!(acc["imap_server"], "imap.example.com");
        assert_eq!(acc["imap_port"], 993);
        let acc_cfg: AccountConfig = serde_json::from_value(acc).unwrap();
        assert_eq!(creds.get_account_password(&acc_cfg).unwrap(), "old-pw");

        // Case/whitespace-only server change and other fields: no password needed
        assert_eq!(
            status(&router, put(with(serde_json::json!({ "server": "  IMAP.Example.com ", "name": "Renamed", "enabled": false })))).await,
            StatusCode::OK
        );
        let acc = get_account_json(&router, &id).await;
        assert_eq!(acc["name"], "Renamed");
        assert_eq!(acc["imap_server"], "IMAP.Example.com");

        // With the password: accepted, and the secret is rebound to the new server
        assert_eq!(
            status(&router, put(with(serde_json::json!({ "server": " imap.new.example ", "password": "new-pw" })))).await,
            StatusCode::OK
        );
        let acc_cfg: AccountConfig = serde_json::from_value(get_account_json(&router, &id).await).unwrap();
        assert_eq!(acc_cfg.imap_server, "imap.new.example");
        assert_eq!(creds.get_account_password(&acc_cfg).unwrap(), "new-pw");

        let _ = creds.delete_password(&id);
    }

    fn getrandom_suffix() -> String {
        generate_api_token()[..12].to_string()
    }

    #[tokio::test]
    async fn test_connection_hides_raw_errors() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        // A port with nothing listening
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let res = router
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/accounts/test-direct",
                serde_json::json!({ "email": "a@b.c", "server": " 127.0.0.1 ", "port": port, "username": " u ", "password": "p" }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with("Could not connect to 127.0.0.1:"), "{text}");
        assert!(!text.to_lowercase().contains("refused"), "{text}");
    }

    #[test]
    fn test_connection_messages() {
        let acc = AccountConfig {
            id: "t".into(),
            name: "t".into(),
            email: "t@example.com".into(),
            provider: ProviderType::GenericImap,
            imap_server: "imap.example.com".into(),
            imap_port: 993,
            use_tls: true,
            auth_type: AuthType::Password,
            username: "t".into(),
            schedule: None,
            retention_days: None,
            folder_filter: FolderFilter::default(),
            gmail_smart_labels: true,
            enabled: true,
            storage_namespace: None,
            credential_ref: None,
            archive: None,
            trust_server_ids: false,
        };
        use mailbackup_core::Error as E;
        let generic = "Could not connect to imap.example.com:993. Check the host and port, and that the server accepts TLS (IMAPS).";
        assert_eq!(test_connection_message(Some(&E::Imap("Failed to connect to TCP: refused".into())), &acc), generic);
        assert_eq!(test_connection_message(Some(&E::Tls("TLS handshake failed: received corrupt message".into())), &acc), generic);
        assert_eq!(test_connection_message(None, &acc), generic);
        assert!(test_connection_message(Some(&E::Tls("invalid peer certificate: NotValidForName".into())), &acc).contains("certificate"));
        assert!(test_connection_message(Some(&E::AuthFailed("t".into(), "NO".into())), &acc).starts_with("Login failed"));
    }

    #[test]
    fn host_allowlist() {
        assert!(is_allowed_host("127.0.0.1:8765", &[]));
        assert!(is_allowed_host("localhost:8765", &[]));
        assert!(is_allowed_host("[::1]:8765", &[]));
        assert!(is_allowed_host("192.168.1.20:8765", &[]));
        assert!(!is_allowed_host("evil.example:8765", &[]));
        assert!(!is_allowed_host("localhost.evil.example", &[]));
        assert!(!is_allowed_host("[::1", &[]));

        let proxy = vec!["mail.example.org".to_string()];
        assert!(is_allowed_host("mail.example.org", &proxy));
        assert!(is_allowed_host("MAIL.example.org:443", &proxy));
        assert!(!is_allowed_host("evil.example", &proxy));
    }

    #[test]
    fn api_token_is_256_bit_hex() {
        let a = generate_api_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, generate_api_token());
    }

    #[test]
    fn bind_address_defaults_to_loopback() {
        assert!(resolve_bind_ip(&AppConfig::default().settings.bind_address).is_loopback());
        assert!(resolve_bind_ip("not-an-ip").is_loopback());
    }

    // --- Download tickets (issue #15) ---------------------------------------

    fn authed(method: &str, uri: &str, body: Option<serde_json::Value>) -> HttpRequest<Body> {
        let builder = HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, TOKEN);
        match body {
            Some(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    // --- In-process requests and the web listener (issue #66) ---------------

    const APP_ORIGIN: &str = "mailbackup://localhost";

    fn in_process(mut req: HttpRequest<Body>) -> HttpRequest<Body> {
        req.extensions_mut().insert(InProcess { origin: APP_ORIGIN.to_string() });
        req
    }

    #[tokio::test]
    async fn in_process_requests_need_no_host_but_their_own_origin_and_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        let build = |token: bool, origin: Option<&str>| {
            let mut b = HttpRequest::builder().uri("mailbackup://localhost/api/version");
            if token {
                b = b.header(API_TOKEN_HEADER, TOKEN);
            }
            if let Some(origin) = origin {
                b = b.header(header::ORIGIN, origin);
            }
            b.body(Body::empty()).unwrap()
        };
        // No Host at all, as the private protocol sends
        assert_eq!(status(&router, in_process(build(true, None))).await, StatusCode::OK);
        assert_eq!(status(&router, in_process(build(true, Some(APP_ORIGIN)))).await, StatusCode::OK);
        assert_eq!(status(&router, in_process(build(true, Some("MAILBACKUP://LOCALHOST")))).await, StatusCode::OK);
        // Still a token (or ticket) for the API, and only its own origin
        assert_eq!(status(&router, in_process(build(false, None))).await, StatusCode::UNAUTHORIZED);
        assert_eq!(status(&router, in_process(build(true, Some("http://evil.example")))).await, StatusCode::FORBIDDEN);
        assert_eq!(status(&router, in_process(build(true, Some("http://127.0.0.1:8765")))).await, StatusCode::FORBIDDEN);
        // Security headers as for network requests
        let res = router.clone().oneshot(in_process(build(true, None))).await.unwrap();
        assert!(res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        // The same request from the network (no marker) is held to Host/Origin
        assert_eq!(status(&router, build(true, None)).await, StatusCode::FORBIDDEN);
        assert_eq!(
            status(&router, HttpRequest::builder().uri("/api/version").header(header::HOST, "127.0.0.1:8765")
                .header(header::ORIGIN, APP_ORIGIN).header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap()).await,
            StatusCode::FORBIDDEN,
            "a browser page can't claim the app's origin"
        );
    }

    /// A router whose state has a web listener on a free port.
    async fn router_with_listener(dir: &std::path::Path, always: bool) -> (Router, Arc<WebListener>) {
        router_with_listener_on(dir, always, 0).await
    }

    async fn router_with_listener_on(dir: &std::path::Path, always: bool, port: u16) -> (Router, Arc<WebListener>) {
        let mut state = test_state(dir, Vec::new()).await;
        let web = Arc::new(WebListener {
            router: std::sync::OnceLock::new(),
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            always,
            config_dir: dir.to_path_buf(),
            identity: state.identity.clone(),
            running: Mutex::new(None),
        });
        state.web = Some(web.clone());
        let router = create_router(state);
        let _ = web.router.set(router.clone());
        (router, web)
    }

    async fn settings_json(router: &Router) -> serde_json::Value {
        let res = router.clone().oneshot(authed("GET", "/api/settings", None)).await.unwrap();
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    // Multi-threaded: the handshake check blocks while the listener answers
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn web_access_turns_the_listener_on_and_off() {
        let dir = tempfile::tempdir().unwrap();
        let (router, web) = router_with_listener(dir.path(), false).await;
        let port = web.start().await.unwrap();
        assert_eq!(settings_json(&router).await["web_server_port"], port);
        // Published for the GUI's verification while it listens
        assert!(runtime::verify_genuine(dir.path(), port).is_some());

        let put = |enabled: bool| json_request("PUT", "/api/settings", serde_json::json!({ "web_server_enabled": enabled }));
        assert_eq!(status(&router, put(false)).await, StatusCode::OK);
        // Closed by the time the request returns
        assert_eq!(web.port().await, None);
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err(), "nothing listens");
        assert!(!runtime::runtime_path(dir.path(), port).exists(), "runtime file removed");
        let off = settings_json(&router).await;
        assert_eq!(off["web_server_enabled"], false);
        assert!(off["web_server_port"].is_null());
        let saved = AppConfig::load_or_create(Some(&dir.path().join("config.yaml"))).unwrap();
        assert!(!saved.settings.web_server_enabled);

        assert_eq!(status(&router, put(true)).await, StatusCode::OK);
        let port = web.port().await.expect("listening again");
        assert!(runtime::verify_genuine(dir.path(), port).is_some(), "the handshake proves the new port");
        assert_eq!(settings_json(&router).await["web_server_port"], port);
        web.stop().await;
    }

    // Multi-threaded: the handshake check blocks while the listener answers
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rapid_off_and_on_end_in_the_last_state_on_the_same_port() {
        let dir = tempfile::tempdir().unwrap();
        // A fixed port, so each start must rebind the one the stop released
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (router, web) = router_with_listener_on(dir.path(), false, port).await;
        assert_eq!(web.start().await.unwrap(), port);

        // "Off" over real HTTP through the listener it turns off: returns,
        // rather than waiting for itself
        let off_over_http = move || {
            use std::io::{Read, Write};
            let body = r#"{"web_server_enabled":false}"#;
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            write!(
                stream,
                "PUT /api/settings HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{}: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                port, API_TOKEN_HEADER, TOKEN, body.len(), body
            )
            .unwrap();
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            response.lines().next().unwrap_or_default().to_string()
        };
        let on = || json_request("PUT", "/api/settings", serde_json::json!({ "web_server_enabled": true }));
        for round in 0..5 {
            let status_line = tokio::task::spawn_blocking(off_over_http).await.unwrap();
            assert!(status_line.contains("200"), "round {}: {}", round, status_line);
            // Immediately on again: the port is already free
            assert_eq!(status(&router, on()).await, StatusCode::OK, "round {}", round);
            assert_eq!(web.port().await, Some(port), "round {}", round);
            assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(), "round {}: listening", round);
        }

        // Concurrent requests: whichever runs last decides, and the listener
        // matches the saved setting
        let put = |enabled: bool| json_request("PUT", "/api/settings", serde_json::json!({ "web_server_enabled": enabled }));
        for _ in 0..5 {
            let (a, b) = tokio::join!(status(&router, put(false)), status(&router, put(true)));
            assert_eq!((a, b), (StatusCode::OK, StatusCode::OK));
            let enabled = settings_json(&router).await["web_server_enabled"].as_bool().unwrap();
            assert_eq!(web.port().await.is_some(), enabled, "the listener matches the saved setting");
        }
        web.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_closed_signal_comes_after_the_socket_and_runtime_file_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..20 {
            let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            let identity = runtime::ServerIdentity::new(port);
            let published = runtime::PublishedRuntime::publish(dir.path(), &identity).unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let listener = ClosingListener { inner: Some(socket), published: Some(published), closed: Some(tx) };
            // Dropped on another thread while this one waits for the signal
            let dropper = std::thread::spawn(move || drop(listener));
            rx.await.unwrap();
            assert!(!runtime::runtime_path(dir.path(), port).exists(), "runtime file gone before the signal");
            assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(), "port free before the signal");
            dropper.join().unwrap();
        }
    }

    // Multi-threaded: the handshake check blocks while the listener answers
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_service_listener_ignores_the_setting() {
        let dir = tempfile::tempdir().unwrap();
        let (router, web) = router_with_listener(dir.path(), true).await;
        let port = web.start().await.unwrap();
        assert_eq!(settings_json(&router).await["web_server_always_on"], true);
        let off = json_request("PUT", "/api/settings", serde_json::json!({ "web_server_enabled": false }));
        assert_eq!(status(&router, off).await, StatusCode::OK);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(web.port().await, Some(port), "still listening");
        web.stop().await;
    }

    fn anonymous(method: &str, uri: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:8765")
            .body(Body::empty())
            .unwrap()
    }

    /// Mints a ticket for `url` (with the header token) and returns it.
    async fn ticket_for(router: &Router, url: &str) -> String {
        let res = router
            .clone()
            .oneshot(authed("POST", "/api/download-ticket", Some(serde_json::json!({ "url": url }))))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "minting for {}", url);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["expires_in"], 60);
        json["ticket"].as_str().unwrap().to_string()
    }

    fn with_ticket(url: &str, ticket: &str) -> String {
        format!("{}{}ticket={}", url, if url.contains('?') { "&" } else { "?" }, ticket)
    }

    async fn get_with_ticket(router: &Router, url: &str, ticket: &str) -> Response {
        router.clone().oneshot(anonymous("GET", &with_ticket(url, ticket))).await.unwrap()
    }

    /// A router with one archived message; returns the router and its id.
    async fn router_with_message(dir: &std::path::Path, ttl: std::time::Duration) -> (Router, String) {
        let mut state = test_state(dir, Vec::new()).await;
        state.download_tickets = Arc::new(tickets::DownloadTickets::with_ttl(ttl));
        let raw = b"From: a@example.com\r\nSubject: ticketed\r\n\r\nbody\r\n";
        let stored = state.storage.store_eml("acc1", "INBOX", 1, None, raw).unwrap();
        state.db.upsert_account("acc1", "A", "a@example.com", "generic_imap").unwrap();
        let folder = state.db.get_or_create_folder("acc1", "INBOX", "inbox", Some(1)).unwrap();
        let id = state
            .db
            .insert_message(
                "acc1",
                &folder.id,
                1,
                None,
                Some("ticketed"),
                Some("a@example.com"),
                None,
                None,
                None,
                raw.len() as u64,
                &stored.relative_path.to_string_lossy(),
                &stored.sha256,
                None,
                &[],
            )
            .unwrap();
        (create_router(state), id)
    }

    #[tokio::test]
    async fn a_ticket_downloads_its_target_once() {
        let dir = tempfile::tempdir().unwrap();
        let (router, id) = router_with_message(dir.path(), tickets::TICKET_TTL).await;
        let eml = format!("/api/messages/{}/download", id);

        let ticket = ticket_for(&router, &eml).await;
        let res = get_with_ticket(&router, &eml, &ticket).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"From: a@example.com"), "the handler's own output");
        assert_eq!(get_with_ticket(&router, &eml, &ticket).await.status(), StatusCode::UNAUTHORIZED, "reused");

        for url in ["/api/accounts/csv-template", "/api/logs/download"] {
            let ticket = ticket_for(&router, url).await;
            assert_eq!(get_with_ticket(&router, url, &ticket).await.status(), StatusCode::OK, "{}", url);
        }
        // mbox: the handler runs (an unknown account is the handler's 404, not 401)
        let mbox = "/api/export/mbox/download?account_id=acc1&folder_id=";
        let ticket = ticket_for(&router, mbox).await;
        assert_ne!(get_with_ticket(&router, mbox, &ticket).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn attachments_download_decoded_under_their_names_and_never_render() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let raw = "From: a@example.com\r\nSubject: atts\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nSee attached\r\n\
                   --B\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n\
                   --B\r\nContent-Type: text/html; name=\"..\\\\evil\\\\page.html\"\r\nContent-Disposition: attachment; filename=\"..\\\\evil\\\\page.html\"\r\n\r\n<script>alert(1)</script>\r\n\
                   --B\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQ=\r\n\
                   --B--\r\n";
        let stored = state.storage.store_eml("acc1", "INBOX", 1, None, raw.as_bytes()).unwrap();
        state.db.upsert_account("acc1", "A", "a@example.com", "generic_imap").unwrap();
        let folder = state.db.get_or_create_folder("acc1", "INBOX", "inbox", Some(1)).unwrap();
        let id = state
            .db
            .insert_message(
                "acc1", &folder.id, 1, None, Some("atts"), Some("a@example.com"), None, None, None,
                raw.len() as u64, &stored.relative_path.to_string_lossy(), &stored.sha256, None, &[],
            )
            .unwrap();
        let router = create_router(state);

        // The detail lists them in the order the download indexes use
        let res = router.clone().oneshot(authed("GET", &format!("/api/messages/{}", id), None)).await.unwrap();
        let detail: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        let names: Vec<&str> = detail["attachments"].as_array().unwrap().iter().map(|a| a["filename"].as_str().unwrap()).collect();
        assert_eq!(names, ["unnamed", "..\\evil\\page.html", "résumé.pdf"]);

        let expected: [(&str, &[u8]); 3] = [
            ("attachment; filename=\"attachment-1.png\"; filename*=UTF-8''attachment-1.png", b"\x89PNG\r\n\x1a\n"),
            ("attachment; filename=\"page.html\"; filename*=UTF-8''page.html", b"<script>alert(1)</script>"),
            ("attachment; filename=\"r_sum_.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf", b"%PDF-1.4"),
        ];
        for (index, (disposition, bytes)) in expected.iter().enumerate() {
            let url = format!("/api/messages/{}/attachments/{}", id, index);
            assert_eq!(
                router.clone().oneshot(anonymous("GET", &url)).await.unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "no ticket, no download"
            );
            let ticket = ticket_for(&router, &url).await;
            let res = get_with_ticket(&router, &url, &ticket).await;
            assert_eq!(res.status(), StatusCode::OK, "{}", url);
            assert_eq!(res.headers()[header::CONTENT_TYPE], "application/octet-stream");
            assert_eq!(res.headers()[header::CONTENT_DISPOSITION], *disposition);
            assert_eq!(res.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            assert_eq!(&body[..], *bytes, "{}", url);
        }

        for url in [format!("/api/messages/{}/attachments/3", id), "/api/messages/missing/attachments/0".to_string()] {
            let ticket = ticket_for(&router, &url).await;
            assert_eq!(get_with_ticket(&router, &url, &ticket).await.status(), StatusCode::NOT_FOUND, "{}", url);
        }
    }

    #[tokio::test]
    async fn a_ticket_is_bound_to_the_complete_target() {
        let dir = tempfile::tempdir().unwrap();
        let (router, id) = router_with_message(dir.path(), tickets::TICKET_TTL).await;
        let eml = format!("/api/messages/{}/download", id);
        let mbox = "/api/export/mbox/download?account_id=acc1&folder_id=f1".to_string();
        let log = "/api/logs/download?file=events.log".to_string();
        let cases: Vec<(String, String)> = vec![
            (eml.clone(), "/api/messages/other-id/download".into()),
            (mbox.clone(), "/api/export/mbox/download?account_id=acc2&folder_id=f1".into()),
            (mbox.clone(), "/api/export/mbox/download?account_id=acc1&folder_id=f2".into()),
            (mbox.clone(), "/api/export/mbox/download?account_id=acc1".into()),
            (mbox.clone(), format!("{}&extra=1", mbox)),
            (mbox.clone(), "/api/export/mbox/download?folder_id=f1&account_id=acc1".into()),
            (log.clone(), "/api/logs/download?file=service.log".into()),
            (log.clone(), "/api/logs/download".into()),
            ("/api/accounts/csv-template".into(), "/api/logs/download".into()),
        ];
        for (issued_for, used_on) in cases {
            let ticket = ticket_for(&router, &issued_for).await;
            assert_eq!(
                get_with_ticket(&router, &used_on, &ticket).await.status(),
                StatusCode::UNAUTHORIZED,
                "ticket for {} used on {}",
                issued_for,
                used_on
            );
            assert_eq!(
                get_with_ticket(&router, &issued_for, &ticket).await.status(),
                StatusCode::UNAUTHORIZED,
                "a mismatched use burns the ticket for {}",
                issued_for
            );
        }
    }

    #[tokio::test]
    async fn tickets_never_authorize_other_routes_or_methods() {
        let dir = tempfile::tempdir().unwrap();
        let (router, id) = router_with_message(dir.path(), tickets::TICKET_TTL).await;
        let eml = format!("/api/messages/{}/download", id);
        // A ticket for a real download, presented elsewhere
        for (method, uri) in [
            ("GET", "/api/version"),
            ("GET", "/api/settings"),
            ("PUT", "/api/settings"),
            ("POST", "/api/logs/clear"),
            ("POST", "/api/sync/acc1"),
            ("POST", "/api/download-ticket"),
            ("HEAD", eml.as_str()),
            ("POST", eml.as_str()),
        ] {
            let ticket = ticket_for(&router, &eml).await;
            let res = router.clone().oneshot(anonymous(method, &with_ticket(uri, &ticket))).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{} {}", method, uri);
            // Not consumed by those attempts: they never reach the store
            assert_eq!(get_with_ticket(&router, &eml, &ticket).await.status(), StatusCode::OK, "{} {}", method, uri);
        }
    }

    #[tokio::test]
    async fn malformed_ticket_parameters_are_rejected_not_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let (router, id) = router_with_message(dir.path(), tickets::TICKET_TTL).await;
        for uri in [
            "/api/logs/download?ticket".to_string(),
            "/api/logs/download?file=events.log&ticket".to_string(),
            "/api/logs/download?ticket=".to_string(),
            "/api/logs/download?file=events.log&ticket=".to_string(),
            "/api/accounts/csv-template?ticket".to_string(),
            "/api/export/mbox/download?account_id=acc1&ticket".to_string(),
            format!("/api/messages/{}/download?ticket", id),
        ] {
            assert_eq!(status(&router, anonymous("GET", &uri)).await, StatusCode::UNAUTHORIZED, "{}", uri);
        }
    }

    #[tokio::test]
    async fn tickets_expire() {
        let dir = tempfile::tempdir().unwrap();
        let (router, _) = router_with_message(dir.path(), std::time::Duration::from_millis(50)).await;
        let res = router
            .clone()
            .oneshot(authed("POST", "/api/download-ticket", Some(serde_json::json!({ "url": "/api/logs/download" }))))
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let ticket = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["ticket"].as_str().unwrap().to_string();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert_eq!(get_with_ticket(&router, "/api/logs/download", &ticket).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn concurrent_uses_of_one_ticket_succeed_once() {
        let dir = tempfile::tempdir().unwrap();
        let (router, id) = router_with_message(dir.path(), tickets::TICKET_TTL).await;
        let eml = format!("/api/messages/{}/download", id);
        let ticket = ticket_for(&router, &eml).await;
        let uri = with_ticket(&eml, &ticket);
        let requests = (0..16).map(|_| {
            let (router, uri) = (router.clone(), uri.clone());
            tokio::spawn(async move { router.oneshot(anonymous("GET", &uri)).await.unwrap().status() })
        });
        let statuses: Vec<StatusCode> = futures_util::future::join_all(requests).await.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1, "{:?}", statuses);
        assert!(statuses.iter().all(|s| *s == StatusCode::OK || *s == StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn minting_needs_the_header_and_a_download_url() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        let anonymous_mint = HttpRequest::builder()
            .method("POST")
            .uri("/api/download-ticket")
            .header(header::HOST, "127.0.0.1:8765")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"url":"/api/logs/download"}"#))
            .unwrap();
        assert_eq!(status(&router, anonymous_mint).await, StatusCode::UNAUTHORIZED);

        for url in [
            "/api/version",
            "/api/settings",
            "/api/download-ticket",
            "//evil.example/api/logs/download",
            "http://127.0.0.1:8765/api/logs/download",
            "/api/logs/download#frag",
            "/api/logs/download?ticket=x",
            "/",
        ] {
            let req = authed("POST", "/api/download-ticket", Some(serde_json::json!({ "url": url })));
            assert_eq!(status(&router, req).await, StatusCode::BAD_REQUEST, "{}", url);
        }
    }

    #[tokio::test]
    async fn live_tickets_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let router = test_router(dir.path()).await;
        for _ in 0..tickets::MAX_LIVE_TICKETS {
            ticket_for(&router, "/api/logs/download").await;
        }
        let req = authed("POST", "/api/download-ticket", Some(serde_json::json!({ "url": "/api/logs/download" })));
        assert_eq!(status(&router, req).await, StatusCode::TOO_MANY_REQUESTS);
    }

    // --- Start a new archive (issue #31) --------------------------------------

    /// A state whose config (on disk too) has account `acc` on
    /// `imap.old.example` with password "old" and one archived message.
    async fn archive_state(dir: &std::path::Path) -> AppState {
        let state = test_state(dir, Vec::new()).await;
        let acc = AccountConfig {
            id: "acc".into(),
            name: "Acc".into(),
            email: "a@example.com".into(),
            provider: ProviderType::GenericImap,
            imap_server: "imap.old.example".into(),
            imap_port: 993,
            use_tls: true,
            auth_type: AuthType::Password,
            username: "user".into(),
            schedule: None,
            retention_days: None,
            folder_filter: FolderFilter::default(),
            gmail_smart_labels: false,
            enabled: true,
            storage_namespace: None,
            credential_ref: None,
            archive: None,
            trust_server_ids: false,
        };
        state.config.write().await.accounts.push(acc.clone());
        state.config.read().await.save(&state.config_path).unwrap();
        state.credentials.set_account_password(&acc, "old").unwrap();
        let raw = b"From: a@example.com\r\nSubject: Archived one\r\n\r\nbody\r\n";
        let stored = state.storage.store_eml("acc", "INBOX", 1, None, raw).unwrap();
        let folder = state.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), &acc.remote_identity()).unwrap().folder;
        state
            .db
            .insert_message(
                "acc", &folder.id, 1, None, Some("Archived one"), None, None, None, None, raw.len() as u64,
                &stored.relative_path.to_string_lossy(), &stored.sha256, Some("body"), &[],
            )
            .unwrap();
        state
    }

    fn edit(server: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::json!({
            "name": "Acc", "server": server, "port": 993, "username": "user", "password": "new",
            "retention_days": null, "schedule": "0 0 * * *", "enabled": true
        });
        if let (Some(obj), Some(more)) = (body.as_object_mut(), extra.as_object()) {
            obj.extend(more.clone());
        }
        body
    }

    async fn archived_ids(state: &AppState) -> Vec<String> {
        state.config.read().await.accounts.iter().filter(|a| a.is_archive()).map(|a| a.id.clone()).collect()
    }

    #[tokio::test]
    async fn starting_a_new_archive_retires_the_mail_so_far() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        let router = create_router(state.clone());
        let body = edit("imap.new.example", serde_json::json!({ "on_connection_change": "new_archive" }));
        let res = router.clone().oneshot(authed("PUT", "/api/accounts/acc", Some(body))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let archives = archived_ids(&state).await;
        assert_eq!(archives.len(), 1);
        let archive_id = &archives[0];
        assert!(archive_id.starts_with("acc~archive-") && archive_id.ends_with("-1"), "{}", archive_id);
        // The mail moved to the archive; the live account is empty on the new server
        assert_eq!(state.db.get_folders(archive_id).unwrap().len(), 1);
        assert!(state.db.get_folders("acc").unwrap().is_empty());
        let cfg = state.config.read().await.clone();
        let live = cfg.get_account("acc").unwrap();
        assert_eq!((live.imap_server.as_str(), live.storage_namespace()), ("imap.new.example", "acc~1"));
        assert_eq!(state.credentials.get_account_password(live).unwrap(), "new");
        // Saved: the config on disk is the same
        let disk = AppConfig::load_existing(&state.config_path).unwrap().unwrap();
        assert_eq!(disk.accounts, cfg.accounts);

        // Listed with its archive info
        let res = router.clone().oneshot(authed("GET", "/api/accounts", None)).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        let entry = list.as_array().unwrap().iter().find(|a| a["id"] == archive_id.as_str()).unwrap();
        assert_eq!(entry["archive"]["retired_from"], "acc");
        assert_eq!(entry["archive"]["last_source"], "imap.old.example:993:user");
        assert_eq!(entry["enabled"], false);
    }

    #[tokio::test]
    async fn trusting_server_ids_is_an_opt_in_setting_with_visible_state() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        let router = create_router(state.clone());
        let on_disk = || AppConfig::load_existing(&state.config_path).unwrap().unwrap().accounts.into_iter().find(|a| a.id == "acc").unwrap();
        assert!(!on_disk().trust_server_ids, "off by default");

        let turn = |on: bool| edit("imap.old.example", serde_json::json!({ "password": null, "trust_server_ids": on }));
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(turn(true)))).await, StatusCode::OK);
        assert!(on_disk().trust_server_ids);
        let res = router.clone().oneshot(authed("GET", "/api/accounts/acc", None)).await.unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["trust_server_ids"], true);
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(turn(false)))).await, StatusCode::OK);
        assert!(!on_disk().trust_server_ids);

        // Distrusted sources are listed for the edit dialog's note
        state.db.record_server_id_distrust("acc", "imap.old.example:993:user", ServerIdKind::EmailId, "reused").unwrap();
        let res = router.clone().oneshot(authed("GET", "/api/accounts/acc/server-ids", None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let states: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(states[0]["distrusted"], true);
        assert_eq!(states[0]["source"], "imap.old.example:993:user");

        // An archive can't opt in
        let switch = edit("imap.new.example", serde_json::json!({ "on_connection_change": "new_archive" }));
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(switch))).await, StatusCode::OK);
        let archive_id = archived_ids(&state).await.remove(0);
        let opt_in = serde_json::json!({ "name": "Old", "trust_server_ids": true });
        let uri = format!("/api/accounts/{}", archive_id);
        assert_eq!(status(&router, authed("PUT", &uri, Some(opt_in))).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn keep_and_rescan_stays_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        let router = create_router(state.clone());
        for extra in [serde_json::json!({}), serde_json::json!({ "on_connection_change": "rescan" })] {
            let res = router.clone().oneshot(authed("PUT", "/api/accounts/acc", Some(edit("imap.new.example", extra)))).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }
        assert!(archived_ids(&state).await.is_empty());
        assert_eq!(state.db.get_folders("acc").unwrap().len(), 1, "the archive stays in the account");
        let bad = edit("imap.other.example", serde_json::json!({ "on_connection_change": "explode" }));
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(bad))).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_running_sync_blocks_the_switch() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        let router = create_router(state.clone());
        let body = || edit("imap.new.example", serde_json::json!({ "on_connection_change": "new_archive" }));

        // Reported as running
        state.active_syncs.write().unwrap().insert(
            "acc".into(),
            SyncStatus {
                account_id: "acc".into(),
                account_name: "Acc".into(),
                is_syncing: true,
                current_folder: "INBOX".into(),
                total_messages: 0,
                processed_messages: 0,
                downloaded_bytes: 0,
                status: "syncing".into(),
                error: None,
            },
        );
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(body()))).await, StatusCode::CONFLICT);
        state.active_syncs.write().unwrap().clear();

        // Holding the gate (e.g. another process syncing it)
        let held = mailbackup_core::sync_gate::SyncGate::try_acquire(&state.config_path, "acc").unwrap().unwrap();
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(body()))).await, StatusCode::CONFLICT);
        drop(held);
        assert!(archived_ids(&state).await.is_empty());
        assert_eq!(state.db.get_folders("acc").unwrap().len(), 1, "nothing moved");
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(body()))).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn archives_are_read_only_but_searchable_exportable_and_survive_their_account() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        let router = create_router(state.clone());
        let body = edit("imap.new.example", serde_json::json!({ "on_connection_change": "new_archive" }));
        assert_eq!(status(&router, authed("PUT", "/api/accounts/acc", Some(body))).await, StatusCode::OK);
        let archive_id = archived_ids(&state).await.remove(0);

        // Never synced, only renamed
        assert_eq!(status(&router, authed("POST", &format!("/api/sync/{}", archive_id), None)).await, StatusCode::CONFLICT);
        for change in [
            serde_json::json!({ "server": "imap.x.example", "port": 993, "username": "user", "password": "p" }),
            serde_json::json!({ "retention_days": 30 }),
            serde_json::json!({ "schedule": "0 1 * * *" }),
            serde_json::json!({ "enabled": true }),
        ] {
            let res = authed("PUT", &format!("/api/accounts/{}", archive_id), Some(change.clone()));
            assert_eq!(status(&router, res).await, StatusCode::BAD_REQUEST, "{}", change);
        }
        let rename = authed("PUT", &format!("/api/accounts/{}", archive_id), Some(serde_json::json!({ "name": "Old mailbox" })));
        assert_eq!(status(&router, rename).await, StatusCode::OK);
        assert_eq!(state.config.read().await.accounts.iter().find(|a| a.id == archive_id).unwrap().name, "Old mailbox");

        // Exported like any account
        let res = router
            .clone()
            .oneshot(authed("GET", &format!("/api/export/mbox/download?account_id={}&folder_id=ALL", archive_id), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let mbox = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&mbox).contains("Subject: Archived one"));
        // Searchable
        assert_eq!(state.db.search_fts("body", 10).unwrap().len(), 1);

        // Deleting the live account leaves the archive alone
        assert_eq!(status(&router, authed("DELETE", "/api/accounts/acc", None)).await, StatusCode::NO_CONTENT);
        assert!(state.config.read().await.accounts.iter().any(|a| a.id == archive_id));
        assert_eq!(state.db.get_folders(&archive_id).unwrap().len(), 1);
    }

    // ---- Schedules that can't run (issue #71) ----

    async fn send(router: &Router, method: &str, uri: &str, body: serde_json::Value) -> (StatusCode, String) {
        let req = HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:8765")
            .header(API_TOKEN_HEADER, TOKEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn new_account(email: &str, schedule: &str) -> serde_json::Value {
        serde_json::json!({
            "provider": "generic", "name": "N", "email": email, "server": "imap.example.com",
            "port": 993, "username": email, "password": "pw", "schedule": schedule,
        })
    }

    #[tokio::test]
    async fn an_account_with_an_invalid_schedule_is_refused_and_nothing_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());

        let (status, body) = send(&router, "POST", "/api/accounts", new_account("a@example.com", "every 6h")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
        assert!(body.contains("every 6h"), "{}", body);
        assert!(state.config.read().await.accounts.is_empty());
        assert!(!state.config_path.exists(), "the config wasn't written");
        assert!(state.credentials.get_password("a_example_com").is_err(), "no password was stored");

        let (status, body) = send(&router, "POST", "/api/accounts", new_account("a@example.com", "0 */6 * * *")).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert!(!body.contains("Warning"), "{}", body);
    }

    #[tokio::test]
    async fn an_invalid_schedule_in_an_update_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());
        let (status, _) = send(&router, "POST", "/api/accounts", new_account("a@example.com", "0 1 * * *")).await;
        assert_eq!(status, StatusCode::OK);
        let id = state.config.read().await.accounts[0].id.clone();
        let saved = std::fs::read_to_string(&state.config_path).unwrap();

        for bad in ["daily at noon", ""] {
            let update = serde_json::json!({ "name": "Renamed", "schedule": bad });
            let (status, body) = send(&router, "PUT", &format!("/api/accounts/{}", id), update).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
        }
        let cfg = state.config.read().await;
        assert_eq!(cfg.accounts[0].name, "N", "no part of the refused update was applied");
        assert_eq!(cfg.accounts[0].schedule.as_deref(), Some("0 1 * * *"));
        assert_eq!(std::fs::read_to_string(&state.config_path).unwrap(), saved);
    }

    #[tokio::test]
    async fn the_scheduler_status_names_accounts_without_a_scheduled_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());
        let (status, _) = send(&router, "POST", "/api/accounts", new_account("good@example.com", "0 1 * * *")).await;
        assert_eq!(status, StatusCode::OK);
        // A schedule that got into the config another way (edited by hand)
        {
            let mut cfg = state.config.write().await;
            let mut broken = cfg.accounts[0].clone();
            broken.id = "broken".to_string();
            broken.email = "broken@example.com".to_string();
            broken.schedule = Some("whenever".to_string());
            cfg.accounts.push(broken);
        }
        // Any later change reloads the scheduler: it must keep the good account
        let (status, body) = send(&router, "POST", "/api/accounts", new_account("third@example.com", "@daily")).await;
        assert_eq!(status, StatusCode::OK, "{}", body);

        let (status, body) = send(&router, "GET", "/api/scheduler/status", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::OK);
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(report["running"], true, "{}", body);
        assert_eq!(report["scheduled_accounts"], 2, "{}", body);
        assert_eq!(report["skipped"].as_array().unwrap().len(), 1, "{}", body);
        assert_eq!(report["skipped"][0]["account_id"], "broken");
    }

    #[tokio::test]
    async fn a_csv_row_with_an_invalid_schedule_is_a_row_error() {
        let csv = "email,password,schedule\nok@example.com,pw,0 2 * * *\nbad@example.com,pw,every 6h\n";
        let report = mailbackup_core::csv_import::parse_accounts_csv(csv);
        assert_eq!(report.valid_accounts.len(), 1);
        assert_eq!(report.valid_accounts[0].email, "ok@example.com");
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].error.contains("every 6h") && report.errors[0].error.contains("bad@example.com"));
    }

    // ---- Adding never replaces an account (issue #74) ----

    #[tokio::test]
    async fn adding_an_existing_address_is_a_conflict_and_a_colliding_slug_gets_a_new_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());
        let (status, body) = send(&router, "POST", "/api/accounts", new_account("a.b@example.com", "0 1 * * *")).await;
        assert_eq!(status, StatusCode::OK, "{}", body);

        let (status, body) = send(&router, "POST", "/api/accounts", new_account("A.B@example.com", "0 2 * * *")).await;
        assert_eq!(status, StatusCode::CONFLICT, "{}", body);
        assert_eq!(state.config.read().await.accounts[0].schedule.as_deref(), Some("0 1 * * *"), "the account is unchanged");

        let (status, body) = send(&router, "POST", "/api/accounts", new_account("a_b@example.com", "0 3 * * *")).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let cfg = state.config.read().await;
        let ids: Vec<&str> = cfg.accounts.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["a_bexample_com", "a_bexample_com-2"]);
        assert_eq!(cfg.accounts[0].email, "a.b@example.com");
    }

    #[tokio::test]
    async fn account_routes_take_ids_not_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());
        send(&router, "POST", "/api/accounts", new_account("me@example.com", "0 1 * * *")).await;
        let (status, _) = send(&router, "GET", "/api/accounts/me@example.com", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = send(&router, "GET", "/api/accounts/meexample_com", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn csv_import_refuses_existing_addresses_unless_asked_to_update_them() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());
        send(&router, "POST", "/api/accounts", new_account("old@example.com", "0 1 * * *")).await;
        let csv = "email,password,name\nold@example.com,changed,Renamed\nnew@example.com,pw,New\n";

        let (status, body) = send(&router, "POST", "/api/accounts/import-csv", serde_json::json!({ "csv_data": csv })).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(report["imported_count"], 1, "{}", body);
        assert_eq!(report["errors"].as_array().unwrap().len(), 1, "{}", body);
        {
            let cfg = state.config.read().await;
            assert_eq!(cfg.account_by_id("oldexample_com").unwrap().name, "N", "not replaced");
            assert_eq!(state.credentials.get_account_password(cfg.account_by_id("oldexample_com").unwrap()).unwrap(), "pw");
        }

        let csv = "email,password,name\nold@example.com,changed,Renamed\n";
        let request = serde_json::json!({ "csv_data": csv, "update_existing": true, "dry_run": true });
        let (_, body) = send(&router, "POST", "/api/accounts/import-csv", request).await;
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(report["valid_accounts"][0]["action"], "update", "{}", body);

        let request = serde_json::json!({ "csv_data": csv, "update_existing": true });
        let (status, body) = send(&router, "POST", "/api/accounts/import-csv", request).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let cfg = state.config.read().await;
        assert_eq!(cfg.accounts.len(), 2);
        let old = cfg.account_by_id("oldexample_com").unwrap();
        assert_eq!(old.name, "Renamed");
        assert_eq!(state.credentials.get_account_password(old).unwrap(), "changed");
    }

    // ---- Skipped messages (issue #72) ----

    #[tokio::test]
    async fn skipped_messages_are_listed_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        let router = create_router(state.clone());
        send(&router, "POST", "/api/accounts", new_account("me@example.com", "0 1 * * *")).await;
        let folder = state.db.get_or_create_folder("meexample_com", "INBOX", "INBOX", Some(1)).unwrap();
        state.db.record_skipped("meexample_com", &folder.id, 0, 7, "over_size_limit", 900, 100).unwrap();

        let (status, body) = send(&router, "GET", "/api/skipped", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::OK);
        let list: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list[0]["uid"], 7, "{}", body);
        assert_eq!(list[0]["folder_name"], "INBOX");

        let (status, body) = send(&router, "POST", "/api/accounts/meexample_com/skipped/retry", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert!(body.contains("\"marked\":1"), "{}", body);
        assert!(state.db.skipped_messages(None).unwrap()[0].retry_requested);

        let (status, _) = send(&router, "POST", "/api/accounts/nobody/skipped/retry", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ---- Logging in (issue #70) ----

    async fn login_state(dir: &std::path::Path) -> AppState {
        let state = test_state(dir, Vec::new()).await;
        state.config.write().await.settings.require_login = true;
        state
    }

    /// A request as a browser on this machine sends it.
    fn browser(method: &str, uri: &str) -> axum::http::request::Builder {
        HttpRequest::builder().method(method).uri(uri).header(header::HOST, "127.0.0.1:8765")
    }

    async fn call(router: &Router, req: HttpRequest<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let res = router.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, headers, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn login_request(key: &str, peer: &str) -> HttpRequest<Body> {
        let mut req = browser("POST", "/api/login")
            .header(header::ORIGIN, "http://127.0.0.1:8765")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({ "key": key }).to_string()))
            .unwrap();
        let addr: SocketAddr = format!("{}:50000", peer).parse().unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(PeerAddr(addr)));
        req
    }

    /// Logs in and returns the `Cookie` header value of the session.
    async fn logged_in(router: &Router, state: &AppState) -> String {
        let key = state.access.key().unwrap();
        let (status, headers, body) = call(router, login_request(&key, "127.0.0.1")).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{}", body);
        let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        cookie.split(';').next().unwrap().to_string()
    }

    /// Every route registered in `create_router` (read from this file, so a
    /// route added later is covered too), with path parameters filled in.
    fn registered_routes() -> Vec<String> {
        let source = include_str!("lib.rs");
        let body = &source[source.find("pub fn create_router").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let mut routes = Vec::new();
        for part in body.split(".route(").skip(1) {
            let path = part.split('"').nth(1).unwrap();
            let filled: String = path
                .split('/')
                .map(|seg| match seg {
                    "{*file}" => "index.html",
                    s if s.starts_with('{') => "1",
                    s => s,
                })
                .collect::<Vec<_>>()
                .join("/");
            routes.push(filled);
        }
        assert!(routes.len() > 30, "found the routes: {:?}", routes);
        routes
    }

    #[tokio::test]
    async fn without_a_session_no_route_but_the_public_ones_answers() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(dir.path()).await;
        let router = create_router(state.clone());
        let mut paths = registered_routes();
        // Aliases of the app page and assets
        paths.extend(["/index.html", "/%69ndex.html", "/./index.html", "/app.js", "/styles.css", "/fonts/fonts.css"].map(String::from));
        for path in paths {
            if is_public_path(&path) {
                continue;
            }
            for method in ["GET", "POST", "PUT", "DELETE"] {
                let req = browser(method, &path).header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap();
                let (status, headers, body) = call(&router, req).await;
                assert!(!body.contains(TOKEN), "{} {} leaked the token", method, path);
                if path.starts_with("/api/") {
                    assert_eq!(status, StatusCode::UNAUTHORIZED, "{} {}", method, path);
                    assert!(headers.contains_key(LOGIN_REQUIRED_HEADER), "{} {}", method, path);
                } else {
                    assert!(body.contains("login-form"), "{} {}: the login page", method, path);
                }
            }
        }
        // The handshake stays open and minimal
        let handshake = format!("/api/handshake?nonce={}", "ab".repeat(32));
        let (status, _, _) = call(&router, browser("GET", &handshake).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_session_gets_the_page_with_the_token_but_api_calls_still_need_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(dir.path()).await;
        let router = create_router(state.clone());
        let cookie = logged_in(&router, &state).await;

        let (status, headers, page) = call(&router, browser("GET", "/").header(header::COOKIE, &cookie).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains(TOKEN), "the app page, with its token");
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");

        // The cookie alone doesn't make a request the app's own (CSRF)
        let req = browser("POST", "/api/logs/clear").header(header::COOKIE, &cookie).body(Body::empty()).unwrap();
        assert_eq!(call(&router, req).await.0, StatusCode::UNAUTHORIZED);
        let req = browser("GET", "/api/stats").header(header::COOKIE, &cookie).header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap();
        assert_eq!(call(&router, req).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn logins_are_checked_and_limited_per_peer() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(dir.path()).await;
        let router = create_router(state.clone());
        let key = state.access.key().unwrap();

        // Another origin, or not JSON: refused before the key is looked at
        let req = browser("POST", "/api/login")
            .header(header::ORIGIN, "http://evil.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({ "key": key }).to_string()))
            .unwrap();
        assert_eq!(call(&router, req).await.0, StatusCode::FORBIDDEN);
        let req = browser("POST", "/api/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("key={}", key)))
            .unwrap();
        assert_eq!(call(&router, req).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        for _ in 0..access::MAX_FAILURES {
            let (status, headers, _) = call(&router, login_request(&"0".repeat(64), "10.0.0.9")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(headers.get(header::SET_COOKIE).is_none());
        }
        let (status, headers, _) = call(&router, login_request(&key, "10.0.0.9")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "even the right key waits");
        assert!(headers.contains_key(header::RETRY_AFTER));
        let (status, _, _) = call(&router, login_request(&key, "10.0.0.10")).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "another peer is not affected");
    }

    #[tokio::test]
    async fn a_new_key_and_a_logout_end_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(dir.path()).await;
        let router = create_router(state.clone());
        let get_stats = |cookie: &str| {
            browser("GET", "/api/stats").header(header::COOKIE, cookie).header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap()
        };

        let first = logged_in(&router, &state).await;
        let second = logged_in(&router, &state).await;
        let regenerate = browser("POST", "/api/web-key/regenerate")
            .header(header::COOKIE, &first)
            .header(API_TOKEN_HEADER, TOKEN)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = call(&router, regenerate).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert_eq!(call(&router, get_stats(&first)).await.0, StatusCode::UNAUTHORIZED, "the session that asked too");
        assert_eq!(call(&router, get_stats(&second)).await.0, StatusCode::UNAUTHORIZED);

        let third = logged_in(&router, &state).await;
        assert_eq!(call(&router, get_stats(&third)).await.0, StatusCode::OK);
        let logout = browser("POST", "/api/logout").header(header::COOKIE, &third).header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap();
        let (_, headers, _) = call(&router, logout).await;
        assert!(headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().contains("Max-Age=0"));
        assert_eq!(call(&router, get_stats(&third)).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_login_ticket_opens_one_session_once() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(dir.path()).await;
        let router = create_router(state.clone());
        let key = state.access.key().unwrap();
        let req = browser("POST", "/api/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({ "key": key, "ticket": true }).to_string()))
            .unwrap();
        let (status, headers, body) = call(&router, req).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert!(headers.get(header::SET_COOKIE).is_none(), "a ticket, not a session");
        let ticket = serde_json::from_str::<serde_json::Value>(&body).unwrap()["ticket"].as_str().unwrap().to_string();

        let redeem = || browser("GET", &format!("/login?ticket={}", ticket)).body(Body::empty()).unwrap();
        let (status, headers, _) = call(&router, redeem()).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers.get(header::LOCATION).unwrap(), "/");
        let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
        let (status, _, page) = call(&router, browser("GET", "/").header(header::COOKIE, &cookie).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains(TOKEN));

        let (status, headers, page) = call(&router, redeem()).await;
        assert_eq!(status, StatusCode::OK, "used up: the login page");
        assert!(headers.get(header::SET_COOKIE).is_none());
        assert!(page.contains("login-form"));
    }

    #[tokio::test]
    async fn the_desktop_window_needs_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(dir.path()).await;
        let router = create_router(state.clone());
        let req = in_process(HttpRequest::builder().uri("/api/stats").header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap());
        assert_eq!(call(&router, req).await.0, StatusCode::OK);
        let req = in_process(HttpRequest::builder().uri("/").body(Body::empty()).unwrap());
        assert!(call(&router, req).await.2.contains(TOKEN));
        // ...and it can show the key, so the user can log in elsewhere
        let req = in_process(HttpRequest::builder().uri("/api/web-key").header(API_TOKEN_HEADER, TOKEN).body(Body::empty()).unwrap());
        let (status, _, body) = call(&router, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(&state.access.key().unwrap()));
    }

    #[tokio::test]
    async fn with_login_turned_off_the_page_is_served_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), Vec::new()).await;
        assert!(!state.config.read().await.settings.require_login);
        let router = create_router(state);
        let (status, _, page) = call(&router, browser("GET", "/").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains(TOKEN));
    }

    // ---- Large downloads (issue #78) ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_streamed_mbox_download_is_byte_for_byte_the_export() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        // A few more messages, so the stream has several chunks
        let folder = state.db.get_folders("acc").unwrap().remove(0);
        for uid in 2..40u32 {
            let raw = format!("From: a@example.com\r\nSubject: m{}\r\n\r\n{}\r\nFrom the start\r\n", uid, "x".repeat(20_000)).into_bytes();
            let stored = state.storage.store_eml("acc", "INBOX", uid, None, &raw).unwrap();
            state
                .db
                .insert_message(
                    "acc", &folder.id, uid, None, Some("m"), None, None, None, None, raw.len() as u64,
                    &stored.relative_path.to_string_lossy(), &stored.sha256, None, &[],
                )
                .unwrap();
        }
        let router = create_router(state.clone());
        let (status, body) = send(&router, "GET", "/api/export/mbox/download?account_id=acc&folder_id=ALL", serde_json::json!(null)).await;
        assert_eq!(status, StatusCode::OK);

        let paths = state.db.message_paths("acc", None).unwrap();
        assert_eq!(paths.len(), 39);
        let mut expected = Vec::new();
        MboxExporter::new(&state.storage).export_to_writer(&paths, &mut expected).unwrap();
        assert!(expected.len() > 2 * streaming::CHUNK_BYTES, "spans several chunks");
        assert_eq!(body.as_bytes(), expected.as_slice());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_export_reports_messages_it_couldnt_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = archive_state(dir.path()).await;
        let path = state.db.message_paths("acc", None).unwrap().remove(0);
        std::fs::remove_file(state.storage.base_dir().join(&path)).unwrap();
        let router = create_router(state.clone());
        let out = dir.path().join("exports").join("out.mbox");
        let request = serde_json::json!({ "account_id": "acc", "output_path": out.to_string_lossy() });
        let (status, body) = send(&router, "POST", "/api/export/mbox", request).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let result: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(result["exported_count"], 0);
        assert_eq!(result["skipped_count"], 1, "visible, not silently missing");
    }

    #[tokio::test]
    async fn in_process_responses_over_the_limit_are_a_clear_error() {
        let small = collect_limited(axum::http::Response::new(Body::from(vec![1u8; 100])), 1000).await;
        assert_eq!(small.status(), StatusCode::OK);
        assert_eq!(small.body().len(), 100);
        let big = collect_limited(axum::http::Response::new(Body::from(vec![1u8; 2000])), 1000).await;
        assert_eq!(big.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(String::from_utf8_lossy(big.body()).contains("too large"), "not a truncated body");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_desktop_download_uses_its_ticket_before_the_body_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        AppConfig { data_dir: dir.path().join("data"), db_path: dir.path().join("c.db"), ..AppConfig::default() }
            .save(&config_path)
            .unwrap();
        let server = Server::build(Some(config_path), Some(0), false).await.unwrap();
        let token = {
            let page = server.handle_in_process(HttpRequest::get("/").body(Vec::new()).unwrap(), APP_ORIGIN).await;
            let page = String::from_utf8_lossy(page.body()).to_string();
            page.split("mailbackup-api-token\" content=\"").nth(1).unwrap()[..64].to_string()
        };
        let url = "/api/logs/download";
        let mint = HttpRequest::post("/api/download-ticket")
            .header(API_TOKEN_HEADER, &token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({ "url": url }).to_string().into_bytes())
            .unwrap();
        let minted = server.handle_in_process(mint, APP_ORIGIN).await;
        let ticket = serde_json::from_slice::<serde_json::Value>(minted.body()).unwrap()["ticket"].as_str().unwrap().to_string();
        let download = || HttpRequest::get(format!("{}?ticket={}", url, ticket)).body(Vec::new()).unwrap();

        let first = server.handle_in_process_streaming(download(), APP_ORIGIN).await;
        assert_eq!(first.status(), StatusCode::OK);
        // The body isn't read yet (a Save dialog could be open): the ticket is already used
        let second = server.handle_in_process_streaming(download(), APP_ORIGIN).await;
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);

        let saved = dir.path().join("events.log");
        streaming::save_body(first.into_body(), &saved).await.unwrap();
        assert!(saved.exists());
    }

    #[tokio::test]
    async fn embedded_assets_answer_if_none_match_and_token_pages_are_never_cached() {
        let dir = tempfile::tempdir().unwrap();
        let router = create_router(test_state(dir.path(), Vec::new()).await);
        let get = |uri: &str, etag: Option<&str>| {
            let mut req = HttpRequest::builder().uri(uri).header(header::HOST, "127.0.0.1:8765");
            if let Some(tag) = etag {
                req = req.header(header::IF_NONE_MATCH, tag);
            }
            req.body(Body::empty()).unwrap()
        };
        let res = router.clone().oneshot(get("/app.js", None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let etag = res.headers().get(header::ETAG).expect("an ETag").to_str().unwrap().to_string();
        let res = router.clone().oneshot(get("/app.js", Some(&etag))).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
        let res = router.clone().oneshot(get("/app.js", Some("\"other\""))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        for page in ["/", "/index.html"] {
            let res = router.clone().oneshot(get(page, Some("*"))).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{}", page);
            assert!(res.headers().get(header::ETAG).is_none(), "{}", page);
            assert_eq!(res.headers().get(header::CACHE_CONTROL).unwrap(), "no-store", "{}", page);
        }
    }
}
