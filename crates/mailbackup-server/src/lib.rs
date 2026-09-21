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
use mailbackup_core::db::Database;
use mailbackup_core::imap::ImapSyncEngine;
use mailbackup_core::keyring::CredentialStore;
use mailbackup_core::mbox::MboxExporter;
use mailbackup_core::retention::RetentionManager;
use mailbackup_core::scheduler::BackupScheduler;
use mailbackup_core::storage::StorageEngine;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub config_path: PathBuf,
    pub db: Database,
    pub storage: StorageEngine,
    pub credentials: Arc<CredentialStore>,
    pub scheduler: Arc<Mutex<BackupScheduler>>,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/stats", get(api_stats))
        .route("/api/accounts", get(api_get_accounts).post(api_add_account))
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
        .route("/api/sync/:account_id", post(api_sync_account))
        .route("/api/export/mbox", post(api_export_mbox))
        .route("/api/settings", get(api_get_settings).put(api_update_settings))
        .route("/*file", get(serve_static))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn start_server(port_override: Option<u16>) -> Result<()> {
    let config_path = mailbackup_core::config::default_config_path();
    let config = AppConfig::load_or_create(Some(&config_path))?;
    let db = Database::open(&config.db_path)?;
    let storage = StorageEngine::new(&config.data_dir);
    let credentials = Arc::new(CredentialStore::new());
    let port = port_override.unwrap_or(config.settings.web_port);

    let config_arc = Arc::new(RwLock::new(config.clone()));

    // Initialize and start background scheduler
    let mut scheduler = BackupScheduler::new(
        Arc::new(config),
        db.clone(),
        storage.clone(),
        credentials.clone(),
    )
    .await?;

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

    let mut cfg = state.config.write().await;
    cfg.accounts.retain(|a| a.id != id);
    cfg.accounts.push(account);

    if let Err(e) = cfg.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save config: {}", e)).into_response();
    }

    // Reload scheduler with new account
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

    (StatusCode::OK, "Account created").into_response()
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

    if let Err(e) = cfg.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save config: {}", e)).into_response();
    }

    // Reload scheduler
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

    (StatusCode::OK, "Account updated").into_response()
}

async fn api_delete_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let mut cfg = state.config.write().await;
    cfg.accounts.retain(|a| a.id != account_id);
    let _ = state.credentials.delete_password(&account_id);
    let _ = cfg.save(&state.config_path);

    // Reload scheduler
    let _ = state.scheduler.lock().await.reload(Arc::new(cfg.clone())).await;

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

#[derive(Deserialize)]
struct SearchParams {
    q: String,
}

async fn api_search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    match state.db.search_fts(&params.q, 30) {
        Ok(results) => Json(results).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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

    tokio::spawn(async move {
        let sync_engine = ImapSyncEngine::new(db.clone(), storage.clone());
        if let Err(e) = sync_engine.sync_account(&acc, &password, None::<fn(&_)>).await {
            error!("Background sync error for {}: {}", acc.id, e);
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
}

#[derive(Serialize)]
struct ExportResult {
    exported_count: usize,
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
        folders.into_iter().filter(|f| f.id == *fid).collect()
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

    let exporter = MboxExporter::new(&state.storage);
    match exporter.export_to_mbox(&paths, PathBuf::from(&payload.output_path)) {
        Ok(count) => Json(ExportResult { exported_count: count }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
}

async fn api_get_settings(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.read().await;
    let res = SettingsResponse {
        data_dir: cfg.data_dir.to_string_lossy().to_string(),
        db_path: cfg.db_path.to_string_lossy().to_string(),
        default_schedule: cfg.settings.default_schedule.clone(),
        default_retention_days: cfg.settings.default_retention_days,
        notifications_enabled: cfg.settings.notifications_enabled,
        web_port: cfg.settings.web_port,
        close_to_tray: cfg.settings.close_to_tray,
    };
    Json(res).into_response()
}

#[derive(Deserialize)]
pub struct UpdateSettingsPayload {
    pub data_dir: Option<String>,
    pub move_existing: Option<bool>,
    pub close_to_tray: Option<bool>,
}

#[derive(Serialize)]
pub struct UpdateSettingsResponse {
    pub success: bool,
    pub data_dir: String,
    pub migrated_files: u64,
    pub close_to_tray: bool,
    pub message: String,
}

async fn api_update_settings(
    State(state): State<AppState>,
    Json(payload): Json<UpdateSettingsPayload>,
) -> impl IntoResponse {
    let mut migrated_files = 0u64;
    let mut resolved_storage_path = None;

    // Check if new data directory is requested
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
                resolved_storage_path = Some(target_path);
            }
        }
    }

    let current_data_dir_str;
    let current_close_to_tray;

    // Update config and save to disk
    {
        let mut cfg = state.config.write().await;

        if let Some(new_path) = resolved_storage_path.as_ref() {
            cfg.data_dir = new_path.clone();
        }

        if let Some(close_tray) = payload.close_to_tray {
            cfg.settings.close_to_tray = close_tray;
        }

        if let Err(e) = cfg.save(&state.config_path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save config: {}", e),
            )
                .into_response();
        }

        current_data_dir_str = cfg.data_dir.to_string_lossy().to_string();
        current_close_to_tray = cfg.settings.close_to_tray;
    }

    // If storage location changed, reload scheduler
    if resolved_storage_path.is_some() {
        let mut sched = state.scheduler.lock().await;
        let cfg = state.config.read().await;
        if let Err(e) = sched.reload(Arc::new(cfg.clone())).await {
            tracing::warn!("Failed to reload scheduler after storage path change: {}", e);
        }
    }

    let message = if let Some(ref p) = resolved_storage_path {
        format!(
            "Storage location updated to {}. Migrated {} file(s).",
            p.display(),
            migrated_files
        )
    } else {
        "Settings updated successfully.".to_string()
    };

    Json(UpdateSettingsResponse {
        success: true,
        data_dir: current_data_dir_str,
        migrated_files,
        close_to_tray: current_close_to_tray,
        message,
    })
    .into_response()
}

