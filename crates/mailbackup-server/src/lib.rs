use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mail_parser::{MessageParser, MimeHeaders};
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
    /// Per-process secret that every `/api/*` request must present, either in the
    /// `X-MailBackup-Token` header or (for plain downloads) the `token` query parameter.
    pub api_token: Arc<str>,
}

pub const API_TOKEN_HEADER: &str = "x-mailbackup-token";

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
    getrandom::getrandom(&mut bytes).expect("OS random number generator unavailable");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/stats", get(api_stats))
        .route("/api/accounts", get(api_get_accounts).post(api_add_account))
        .route("/api/accounts/import-csv", post(api_import_accounts_csv))
        .route("/api/accounts/csv-template", get(api_accounts_csv_template))
        .route(
            "/api/accounts/:id",
            get(api_get_account)
                .put(api_update_account)
                .delete(api_delete_account),
        )
        .route("/api/accounts/test-direct", post(api_test_direct))
        .route("/api/accounts/:id/folders", get(api_get_folders))
        .route("/api/folders/:id/messages", get(api_get_messages))
        .route("/api/messages/:id", get(api_get_message_detail))
        .route("/api/messages/:id/download", get(api_download_eml))
        .route("/api/search", get(api_search))
        .route("/api/sync/status", get(api_get_sync_status))
        .route("/api/sync/:account_id", post(api_sync_account))
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
        .route("/*file", get(serve_static))
        .layer(middleware::from_fn_with_state(state.clone(), api_guard))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Rejects requests that could come from another web origin or from the network:
/// - `Host` must be an IP literal, `localhost` or a configured `allowed_hosts` entry,
///   which defeats DNS rebinding.
/// - `Origin`, when sent, must be `http(s)://<Host>` (no cross-origin callers; CORS is
///   not enabled). `https` covers a TLS-terminating reverse proxy.
/// - `/api/*` requests must carry the per-process API token.
async fn api_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let headers = req.headers();

    let allowed = {
        let cfg = state.config.read().await;
        match headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
            Some(h) if is_allowed_host(h, &cfg.settings.allowed_hosts) => Some(h.to_string()),
            _ => None,
        }
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

    if req.uri().path().starts_with("/api/") {
        let presented = request_token(headers, req.uri().query());
        let valid = presented
            .map(|t| constant_time_eq(t.as_bytes(), state.api_token.as_bytes()))
            .unwrap_or(false);
        if !valid {
            return (StatusCode::UNAUTHORIZED, "Missing or invalid API token").into_response();
        }
    }

    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

fn request_token<'a>(headers: &'a HeaderMap, query: Option<&'a str>) -> Option<&'a str> {
    if let Some(t) = headers.get(API_TOKEN_HEADER).and_then(|v| v.to_str().ok()) {
        return Some(t);
    }
    // Tokens are hex, so no percent-decoding is needed.
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
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
    let config_path = config_path_override.unwrap_or_else(mailbackup_core::config::default_config_path);
    let config = AppConfig::load_or_create(Some(&config_path))?;
    mailbackup_core::private_fs::tighten_at_startup(&config_path, &config.settings, true);
    let db = Database::open(&config.db_path)?;
    let storage = StorageEngine::new(&config.data_dir);
    // Same store as the CLI and the background service for this config
    let credentials = Arc::new(CredentialStore::for_config(&config_path, &config.settings));
    let port = port_override.unwrap_or(config.settings.web_port);
    let bind_ip = resolve_bind_ip(&config.settings.bind_address);

    let config_arc = Arc::new(RwLock::new(config.clone()));
    let active_syncs = Arc::new(StdRwLock::new(HashMap::new()));

    // Initialize and start background scheduler
    let mut scheduler = BackupScheduler::new(
        Arc::new(config),
        db.clone(),
        storage.clone(),
        credentials.clone(),
    )
    .await?;

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

    if let Err(e) = scheduler.start().await {
        error!("Failed to start backup scheduler: {}", e);
    } else {
        info!("Background backup scheduler successfully activated");
    }

    let scheduler_arc = Arc::new(Mutex::new(scheduler));

    let state = AppState {
        config: config_arc,
        config_path,
        db,
        storage,
        credentials,
        scheduler: scheduler_arc,
        active_syncs,
        api_token: Arc::from(generate_api_token()),
    };

    let app = create_router(state);
    let addr = SocketAddr::new(bind_ip, port);
    if !bind_ip.is_loopback() {
        tracing::warn!(
            "Web UI / REST API is exposed on {} (bind_address). It is reachable from other machines on the network.",
            addr
        );
    }
    info!("🚀 MailBackup Studio running on http://127.0.0.1:{} (listening on {})", port, addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// Static Assets Handler
async fn serve_index(State(state): State<AppState>) -> impl IntoResponse {
    serve_file("index.html", &state.api_token)
}

async fn serve_static(State(state): State<AppState>, Path(path): Path<String>) -> impl IntoResponse {
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
                HeaderValue::from_str(mime.as_ref()).unwrap(),
            );
            if clean_path == "index.html" {
                res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
            res
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
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
    match cfg.get_account(&account_id) {
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

    let id = StorageEngine::sanitize_slug(&payload.email);
    let account = AccountConfig {
        id: id.clone(),
        name: payload.name,
        email: payload.email.clone(),
        provider,
        imap_server: payload.server.trim().to_string(),
        imap_port: payload.port,
        use_tls: true,
        auth_type: AuthType::Password,
        username: payload.username.trim().to_string(),
        schedule: payload.schedule,
        retention_days: payload.retention_days,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
    };

    if let Err(e) = state.credentials.set_account_password(&account, &payload.password) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save secret: {}", e)).into_response();
    }

    let acc_name_log = account.name.clone();
    let acc_email_log = account.email.clone();
    let acc_provider_log = format!("{:?}", account.provider);

    let mut cfg = state.config.write().await;
    cfg.accounts.retain(|a| a.id != id);
    cfg.accounts.push(account);

    if let Err(e) = cfg.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save config: {}", e)).into_response();
    }

    // Reload scheduler with new account
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

    mailbackup_core::event_log::log_event(
        "ACCOUNT_ADDED",
        &format!("Account '{}' ({}) added [Provider: {}]", acc_name_log, acc_email_log, acc_provider_log),
    );

    (StatusCode::OK, "Account created").into_response()
}

#[derive(Deserialize)]
struct ImportAccountsCsvPayload {
    #[serde(alias = "csv_data")]
    csv_content: String,
    #[serde(default)]
    dry_run: bool,
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
    let report = mailbackup_core::csv_import::parse_accounts_csv(&payload.csv_content);

    let previews: Vec<ImportedAccountPreview> = report
        .valid_accounts
        .iter()
        .map(|acc| ImportedAccountPreview {
            id: acc.id.clone(),
            email: acc.email.clone(),
            name: acc.name.clone(),
            provider: format!("{:?}", acc.provider),
            imap_server: acc.imap_server.clone(),
            server: acc.imap_server.clone(),
            imap_port: acc.imap_port,
            port: acc.imap_port,
            username: acc.username.clone(),
            schedule: acc.schedule.clone(),
        })
        .collect();

    let valid_count = report.valid_accounts.len();
    let error_count = report.errors.len();

    if payload.dry_run {
        return (
            StatusCode::OK,
            Json(ImportAccountsCsvResponse {
                valid_count,
                error_count,
                accounts: previews.clone(),
                valid_accounts: previews,
                errors: report.errors,
                imported: false,
                imported_count: 0,
            }),
        )
            .into_response();
    }

    if valid_count == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ImportAccountsCsvResponse {
                valid_count: 0,
                error_count,
                accounts: vec![],
                valid_accounts: vec![],
                errors: report.errors,
                imported: false,
                imported_count: 0,
            }),
        )
            .into_response();
    }

    // Save credentials and update config
    let mut saved_accounts = Vec::new();
    for acc in &report.valid_accounts {
        let cfg_acc = acc.to_account_config();
        if let Err(e) = state.credentials.set_account_password(&cfg_acc, &acc.password) {
            error!("Failed to save secret for account '{}': {}", acc.email, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save secret for account '{}': {}", acc.email, e),
            )
                .into_response();
        }
        saved_accounts.push(cfg_acc);
    }

    let mut cfg = state.config.write().await;
    for acc in saved_accounts {
        let acc_id = acc.id.clone();
        cfg.accounts.retain(|a| a.id != acc_id);
        cfg.accounts.push(acc);
    }

    if let Err(e) = cfg.save(&state.config_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save config: {}", e),
        )
            .into_response();
    }

    // Reload scheduler with updated accounts
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

    mailbackup_core::event_log::log_event(
        "ACCOUNTS_BULK_IMPORTED",
        &format!(
            "Bulk imported {} account(s) via CSV ({} invalid rows skipped)",
            valid_count, error_count
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
            imported_count: valid_count,
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
}

async fn api_update_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(payload): Json<UpdateAccountPayload>,
) -> impl IntoResponse {
    let mut cfg = state.config.write().await;
    let acc = match cfg.get_account_mut(&account_id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, "Account not found").into_response(),
    };

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

    if let Some(n) = payload.name {
        acc.name = n;
    }
    acc.imap_server = new_server;
    acc.imap_port = new_port;
    acc.username = new_username;
    acc.retention_days = payload.retention_days;
    if let Some(sch) = payload.schedule {
        acc.schedule = Some(sch);
    }
    if let Some(e) = payload.enabled {
        acc.enabled = e;
    }

    if let Some(pw) = new_password {
        if let Err(e) = state.credentials.set_account_password(acc, &pw) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update secret: {}", e)).into_response();
        }
    }

    let updated_name = acc.name.clone();
    let updated_email = acc.email.clone();

    if let Err(e) = cfg.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save config: {}", e)).into_response();
    }

    // Reload scheduler
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

    mailbackup_core::event_log::log_event(
        "ACCOUNT_MODIFIED",
        &if connection_changed {
            format!(
                "Account '{}' ({}) configuration updated; connection changed and password re-entered",
                updated_name, updated_email
            )
        } else {
            format!("Account '{}' ({}) configuration updated", updated_name, updated_email)
        },
    );

    (StatusCode::OK, "Account updated").into_response()
}

async fn api_delete_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let mut cfg = state.config.write().await;
    let target_name = cfg.get_account(&account_id).map(|a| a.name.clone()).unwrap_or_else(|| account_id.clone());
    cfg.accounts.retain(|a| a.id != account_id);
    let _ = state.credentials.delete_password(&account_id);
    let _ = cfg.save(&state.config_path);

    // Reload scheduler
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

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

        let mut atts = Vec::new();
        for att in p.attachments() {
            atts.push(AttachmentDetail {
                filename: att.attachment_name().unwrap_or("unnamed").to_string(),
                mime_type: att.content_type().map(|c| c.ctype().to_string()).unwrap_or_else(|| "application/octet-stream".to_string()),
                size_bytes: att.contents().len() as u64,
            });
        }
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
                HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)).unwrap(),
            );
            res
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
    let acc = match cfg.get_account(&account_id) {
        Some(a) => a.clone(),
        None => return (StatusCode::NOT_FOUND, "Account not found").into_response(),
    };

    let password = match state.credentials.get_account_password(&acc) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("No credentials: {}", e)).into_response(),
    };

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
        let sync_engine = ImapSyncEngine::new(db.clone(), storage.clone());
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

        match sync_engine.sync_account(&acc, &password, Some(progress_cb)).await {
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

    let folders = match state.db.get_folders(&payload.account_id) {
        Ok(f) => f,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let target_folders: Vec<_> = if let Some(ref fid) = payload.folder_id {
        if fid == "ALL" || fid.trim().is_empty() {
            folders
        } else {
            folders.into_iter().filter(|f| f.id == *fid).collect()
        }
    } else {
        folders
    };

    let mut paths = Vec::new();
    for f in target_folders {
        if let Ok(msgs) = state.db.get_messages_for_folder(&f.id) {
            for m in msgs {
                paths.push(m.relative_path);
            }
        }
    }

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

    let exporter = MboxExporter::new(&state.storage);
    match exporter.export_to_mbox_with(&paths, &final_output_path, payload.overwrite) {
        Ok(count) => {
            let path_str = final_output_path.to_string_lossy().to_string();
            mailbackup_core::event_log::log_event(
                "ARCHIVE_EXPORTED",
                &format!("Exported {} message(s) to .mbox archive: {}", count, path_str),
            );
            Json(ExportResult {
                exported_count: count,
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

fn pick_directory_native() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("osascript")
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
        let output = std::process::Command::new("powershell")
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
        if let Ok(output) = std::process::Command::new("zenity")
            .args(["--file-selection", "--directory", "--title=Select Export Destination Folder"])
            .output()
        {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path_str.is_empty() {
                    return Some(PathBuf::from(path_str));
                }
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
    let folders = match state.db.get_folders(&query.account_id) {
        Ok(f) => f,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let target_folders: Vec<_> = if let Some(ref fid) = query.folder_id {
        if fid == "ALL" || fid.trim().is_empty() {
            folders
        } else {
            folders.into_iter().filter(|f| f.id == *fid).collect()
        }
    } else {
        folders
    };

    let mut paths = Vec::new();
    for f in target_folders {
        if let Ok(msgs) = state.db.get_messages_for_folder(&f.id) {
            for m in msgs {
                paths.push(m.relative_path);
            }
        }
    }

    let mut buffer = Vec::new();
    let exporter = MboxExporter::new(&state.storage);
    let count = match exporter.export_to_writer(&paths, &mut buffer) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let timestamp = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let filename = format!("backup_{}.mbox", timestamp);

    mailbackup_core::event_log::log_event(
        "ARCHIVE_EXPORTED",
        &format!("Downloaded .mbox archive containing {} message(s)", count),
    );

    Response::builder()
        .header(header::CONTENT_TYPE, "application/mbox")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(buffer))
        .unwrap()
        .into_response()
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

    // 1. Move the archive data directory if requested
    if let Some(target_path) = requested_dir {
        let current_dir = {
            let cfg = state.config.read().await;
            cfg.data_dir.clone()
        };

        if target_path != current_dir {
            let move_existing = payload.move_existing.unwrap_or(true);
            if move_existing {
                match state.storage.migrate_data(&target_path) {
                    Ok(count) => migrated_files = count,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to migrate storage data: {}", e),
                        )
                            .into_response();
                    }
                }
            } else if let Err(e) = mailbackup_core::private_fs::create_dir_all(&target_path) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Failed to create storage directory {}: {}",
                        target_path.display(),
                        e
                    ),
                )
                    .into_response();
            }

            // Update storage engine runtime path
            state.storage.set_base_dir(&target_path);
            mailbackup_core::event_log::log_event(
                "STORAGE_MOVED",
                &format!("Archive storage directory changed to {}", target_path.display()),
            );
            resolved_storage_path = Some(target_path);
        }
    }

    // 2. Relocate the database catalog if requested
    if let Some(target_db) = requested_db {
        if target_db != current_db {
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
    }

    let current_data_dir_str;
    let current_db_path_str;
    let current_close_to_tray;
    let current_autostart;
    let current_run_as_service;
    let current_log_retention;

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
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("Invalid log file: {}", e)).into_response();
            }
        }
    } else {
        ("mailbackup-events.log".to_string(), mailbackup_core::event_log::get_raw_log().unwrap_or_default())
    };

    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(content))
        .unwrap()
        .into_response()
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
        AppState {
            config: Arc::new(RwLock::new(config)),
            config_path: dir.join("config.yaml"),
            db,
            storage,
            credentials,
            scheduler: Arc::new(Mutex::new(scheduler)),
            active_syncs: Arc::new(StdRwLock::new(HashMap::new())),
            api_token: Arc::from(TOKEN),
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

        let query_ok = get(&format!("/api/version?token={}", TOKEN), "localhost:8765")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&router, query_ok).await, StatusCode::OK);
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
}
