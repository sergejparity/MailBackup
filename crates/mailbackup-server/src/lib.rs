use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
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
use mailbackup_core::scheduler::BackupScheduler;
use mailbackup_core::storage::StorageEngine;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::CorsLayer;
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
        .route("/*file", get(serve_static))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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
    let db = Database::open(&config.db_path)?;
    let storage = StorageEngine::new(&config.data_dir);
    let credentials = Arc::new(CredentialStore::new());
    let port = port_override.unwrap_or(config.settings.web_port);

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
    };

    let app = create_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("🚀 MailBackup Studio running on http://127.0.0.1:{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// Static Assets Handler
async fn serve_index() -> impl IntoResponse {
    serve_file("index.html")
}

async fn serve_static(Path(path): Path<String>) -> impl IntoResponse {
    serve_file(&path)
}

fn serve_file(path: &str) -> Response {
    let clean_path = path.trim_start_matches('/');
    match Assets::get(clean_path) {
        Some(content) => {
            let mime = mime_guess::from_path(clean_path).first_or_octet_stream();
            let mut res = Response::new(Body::from(content.data));
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref()).unwrap(),
            );
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
        imap_server: payload.server,
        imap_port: payload.port,
        use_tls: true,
        auth_type: AuthType::Password,
        username: payload.username,
        schedule: payload.schedule,
        retention_days: payload.retention_days,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
    };

    if let Err(e) = state.credentials.set_password(&id, &payload.password) {
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
        if let Err(e) = state.credentials.set_password(&acc.id, &acc.password) {
            error!("Failed to save secret for account '{}': {}", acc.email, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save secret for account '{}': {}", acc.email, e),
            )
                .into_response();
        }
        saved_accounts.push(acc.to_account_config());
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

    if let Some(n) = payload.name {
        acc.name = n;
    }
    if let Some(s) = payload.server {
        acc.imap_server = s;
    }
    if let Some(p) = payload.port {
        acc.imap_port = p;
    }
    if let Some(u) = payload.username {
        acc.username = u;
    }
    acc.retention_days = payload.retention_days;
    if let Some(sch) = payload.schedule {
        acc.schedule = Some(sch);
    }
    if let Some(e) = payload.enabled {
        acc.enabled = e;
    }

    if let Some(pw) = payload.password {
        if !pw.is_empty() {
            if let Err(e) = state.credentials.set_password(&account_id, &pw) {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update secret: {}", e)).into_response();
            }
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
        &format!("Account '{}' ({}) configuration updated", updated_name, updated_email),
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
        imap_server: payload.server,
        imap_port: payload.port,
        use_tls: true,
        auth_type: AuthType::Password,
        username: payload.username,
        schedule: None,
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
    };

    match ImapSyncEngine::connect(&dummy_acc, &payload.password).await {
        Ok(mut session) => {
            let _ = session.logout().await;
            (StatusCode::OK, "Success").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
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
        let html_content = p.body_html(0).map(|s| s.to_string());
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

    let password = match state.credentials.get_password(&acc.id) {
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

    let final_output_path = mailbackup_core::config::resolve_export_path(&payload.output_path);

    if !payload.overwrite && final_output_path.exists() {
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
    match exporter.export_to_mbox(&paths, &final_output_path) {
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

async fn api_export_locations() -> impl IntoResponse {
    let default_dir = mailbackup_core::config::default_export_dir()
        .to_string_lossy()
        .to_string();
    let locs = mailbackup_core::config::system_export_locations();
    let locations = locs
        .into_iter()
        .map(|(name, path)| ExportLocationItem {
            name: name.to_string(),
            path: path.to_string_lossy().to_string(),
        })
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
    Query(query): Query<CheckPathQuery>,
) -> impl IntoResponse {
    let resolved = mailbackup_core::config::resolve_export_path(&query.path);
    let exists = resolved.exists();
    let suggested = if exists {
        mailbackup_core::config::find_available_path(&resolved)
    } else {
        resolved.clone()
    };

    Json(CheckPathResponse {
        exists,
        resolved_path: resolved.to_string_lossy().to_string(),
        suggested_path: suggested.to_string_lossy().to_string(),
    })
}

#[derive(Serialize)]
struct PickDirectoryResponse {
    selected: bool,
    path: Option<String>,
}

async fn api_pick_directory() -> impl IntoResponse {
    let res = tokio::task::spawn_blocking(pick_directory_native)
        .await
        .unwrap_or(None);

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

    // 1. Check if new data directory is requested
    if let Some(ref raw_dir) = payload.data_dir {
        let trimmed = raw_dir.trim();
        if !trimmed.is_empty() {
            let target_path = mailbackup_core::config::resolve_path(trimmed);
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
                } else if let Err(e) = std::fs::create_dir_all(&target_path) {
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
    }

    // 2. Check if new database path is requested
    if let Some(ref raw_db) = payload.db_path {
        let trimmed_db = raw_db.trim();
        if !trimmed_db.is_empty() {
            let target_db = mailbackup_core::config::resolve_path(trimmed_db);
            let current_db = state.db.path();

            if target_db != current_db {
                let move_db = payload.move_db_existing.unwrap_or(true);
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
    }

    let current_data_dir_str;
    let current_db_path_str;
    let current_close_to_tray;
    let current_autostart;
    let current_run_as_service;

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
            if let Err(e) = mailbackup_core::service::set_service_enabled(service_val) {
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

async fn api_service_status() -> impl IntoResponse {
    let status = mailbackup_core::service::get_service_status();
    Json(status).into_response()
}

async fn api_service_toggle(
    State(state): State<AppState>,
    Json(payload): Json<ServiceTogglePayload>,
) -> impl IntoResponse {
    let res = mailbackup_core::service::set_service_enabled(payload.enabled);
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
}

async fn api_get_logs() -> impl IntoResponse {
    let logs = mailbackup_core::event_log::get_recent_logs(200).unwrap_or_default();
    let raw = mailbackup_core::event_log::get_raw_log().unwrap_or_default();
    let path = mailbackup_core::event_log::log_file_path().to_string_lossy().to_string();
    Json(LogsResponse { logs, raw, path }).into_response()
}

async fn api_download_logs() -> impl IntoResponse {
    let raw = mailbackup_core::event_log::get_raw_log().unwrap_or_default();
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"mailbackup-events.log\"",
        )
        .body(Body::from(raw))
        .unwrap()
}

async fn api_clear_logs() -> impl IntoResponse {
    match mailbackup_core::event_log::clear_log() {
        Ok(_) => (StatusCode::OK, "Logs cleared").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

