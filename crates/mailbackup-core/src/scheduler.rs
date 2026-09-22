use crate::config::AppConfig;
use crate::db::Database;
use crate::error::{Error, Result};
use crate::imap::ImapSyncEngine;
use crate::keyring::CredentialStore;
use crate::retention::RetentionManager;
use crate::storage::StorageEngine;
use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, warn};

pub fn normalize_cron(expr: &str) -> String {
    let trimmed = expr.trim();
    if trimmed.starts_with("every ") || trimmed.starts_with('@') {
        return trimmed.to_string();
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() == 5 {
        // Prepend 0 seconds for 6-field scheduler
        format!("0 {}", trimmed)
    } else {
        trimmed.to_string()
    }
}

pub type SchedulerStatusCallback = Arc<
    dyn Fn(
            &str, // account_id
            &str, // account_name
            &str, // event: "started" | "syncing" | "completed" | "error"
            Option<&crate::imap::SyncProgress>,
            Option<&str>, // error message if any
        ) + Send
        + Sync,
>;

pub struct BackupScheduler {
    scheduler: JobScheduler,
    config: Arc<AppConfig>,
    db: Database,
    storage: StorageEngine,
    credentials: Arc<CredentialStore>,
    status_listener: Option<SchedulerStatusCallback>,
}

impl BackupScheduler {
    pub async fn new(
        config: Arc<AppConfig>,
        db: Database,
        storage: StorageEngine,
        credentials: Arc<CredentialStore>,
    ) -> Result<Self> {
        let scheduler = JobScheduler::new().await.map_err(|e| {
            Error::Other(format!("Failed to create job scheduler: {}", e))
        })?;

        Ok(Self {
            scheduler,
            config,
            db,
            storage,
            credentials,
            status_listener: None,
        })
    }

    pub fn set_status_listener(&mut self, listener: Option<SchedulerStatusCallback>) {
        self.status_listener = listener;
    }

    pub async fn start(&mut self) -> Result<()> {
        self.register_jobs().await?;
        self.scheduler.start().await.map_err(|e| {
            Error::Other(format!("Failed to start scheduler: {}", e))
        })?;
        info!("Backup scheduler is running");
        Ok(())
    }

    async fn register_jobs(&self) -> Result<()> {
        for account in &self.config.accounts {
            if !account.enabled {
                continue;
            }

            let raw_cron = account
                .schedule
                .as_deref()
                .unwrap_or(&self.config.settings.default_schedule);

            let cron_expr = normalize_cron(raw_cron);

            let account_clone = account.clone();
            let db_clone = self.db.clone();
            let storage_clone = self.storage.clone();
            let creds_clone = self.credentials.clone();
            let status_listener_clone = self.status_listener.clone();

            info!(
                "Registering scheduled backup for account '{}' ({}) with cron: '{}' (normalized: '{}')",
                account.id, account.email, raw_cron, cron_expr
            );

            let job = Job::new_async(&cron_expr, move |_uuid, _lock| {
                let acc = account_clone.clone();
                let db = db_clone.clone();
                let storage = storage_clone.clone();
                let creds = creds_clone.clone();
                let status_listener = status_listener_clone.clone();

                Box::pin(async move {
                    info!("Starting scheduled backup for account '{}' ({})", acc.name, acc.email);
                    crate::event_log::log_event(
                        "SYNC_STARTED",
                        &format!("Scheduled background sync started for account '{}' ({})", acc.name, acc.email),
                    );

                    if let Some(ref l) = status_listener {
                        l(&acc.id, &acc.name, "started", None, None);
                    }

                    let password = match creds.get_password(&acc.id) {
                        Ok(p) => p,
                        Err(e) => {
                            let err_msg = format!("Scheduled backup failed for account '{}': cannot retrieve password ({})", acc.name, e);
                            error!("{}", err_msg);
                            crate::event_log::log_event("SYNC_ERROR", &err_msg);
                            if let Some(ref l) = status_listener {
                                l(&acc.id, &acc.name, "error", None, Some(&err_msg));
                            }
                            return;
                        }
                    };

                    let sync_engine = ImapSyncEngine::new(db.clone(), storage.clone());
                    let listener_cb = status_listener.clone();
                    let acc_id_cb = acc.id.clone();
                    let acc_name_cb = acc.name.clone();

                    let progress_cb = move |p: &crate::imap::SyncProgress| {
                        if let Some(ref l) = listener_cb {
                            l(&acc_id_cb, &acc_name_cb, "syncing", Some(p), None);
                        }
                    };

                    match sync_engine.sync_account(&acc, &password, Some(progress_cb)).await {
                        Ok(progress) => {
                            let mb = (progress.downloaded_bytes as f64) / (1024.0 * 1024.0);
                            let msg = format!(
                                "Scheduled background sync completed for account '{}': {} message(s), {:.2} MB downloaded",
                                acc.name, progress.processed_messages, mb
                            );
                            info!("{}", msg);
                            crate::event_log::log_event("SYNC_SUCCESS", &msg);

                            if let Some(ref l) = status_listener {
                                l(&acc.id, &acc.name, "completed", Some(&progress), None);
                            }
                        }
                        Err(e) => {
                            let err_msg = format!("Scheduled background sync error for account '{}': {}", acc.name, e);
                            error!("{}", err_msg);
                            crate::event_log::log_event("SYNC_ERROR", &err_msg);

                            if let Some(ref l) = status_listener {
                                l(&acc.id, &acc.name, "error", None, Some(&err_msg));
                            }
                        }
                    }

                    // Enforce retention policy
                    let retention = RetentionManager::new(&db, &storage);
                    match retention.enforce_retention(&acc.id, acc.retention_days) {
                        Ok(report) => {
                            if report.pruned_count > 0 {
                                let mb = (report.reclaimed_bytes as f64) / (1024.0 * 1024.0);
                                crate::event_log::log_event(
                                    "RETENTION_CLEANUP",
                                    &format!(
                                        "Retention cleanup for account '{}': pruned {} message(s), {:.2} MB reclaimed",
                                        acc.name, report.pruned_count, mb
                                    ),
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Scheduled retention cleanup failed for '{}': {}", acc.id, e);
                        }
                    }
                })
            }).map_err(|e| Error::Other(format!("Invalid cron expression '{}' (raw: '{}'): {}", cron_expr, raw_cron, e)))?;

            self.scheduler.add(job).await.map_err(|e| {
                Error::Other(format!("Failed to add job to scheduler: {}", e))
            })?;
        }
        Ok(())
    }

    pub async fn reload(&mut self, new_config: Arc<AppConfig>) -> Result<()> {
        let listener = self.status_listener.clone();
        let _ = self.scheduler.shutdown().await;
        self.config = new_config;
        self.scheduler = JobScheduler::new().await.map_err(|e| {
            Error::Other(format!("Failed to recreate job scheduler: {}", e))
        })?;
        self.status_listener = listener;
        self.start().await?;
        info!("Backup scheduler reloaded with updated account configurations");
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.scheduler.shutdown().await.map_err(|e| {
            Error::Other(format!("Failed to stop scheduler: {}", e))
        })?;
        Ok(())
    }
}
