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

pub struct BackupScheduler {
    scheduler: JobScheduler,
    config: Arc<AppConfig>,
    db: Database,
    storage: StorageEngine,
    credentials: Arc<CredentialStore>,
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
        })
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

            info!(
                "Registering scheduled backup for account '{}' ({}) with cron: '{}' (normalized: '{}')",
                account.id, account.email, raw_cron, cron_expr
            );

            let job = Job::new_async(&cron_expr, move |_uuid, _lock| {
                let acc = account_clone.clone();
                let db = db_clone.clone();
                let storage = storage_clone.clone();
                let creds = creds_clone.clone();

                Box::pin(async move {
                    info!("Starting scheduled backup for account '{}'", acc.id);
                    let password = match creds.get_password(&acc.id) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Scheduled backup failed for '{}': cannot retrieve password ({})", acc.id, e);
                            return;
                        }
                    };

                    let sync_engine = ImapSyncEngine::new(db.clone(), storage.clone());
                    match sync_engine.sync_account(&acc, &password, None::<fn(&_)>).await {
                        Ok(progress) => {
                            info!(
                                "Scheduled backup completed for '{}': {} messages ({} bytes)",
                                acc.id, progress.processed_messages, progress.downloaded_bytes
                            );
                        }
                        Err(e) => {
                            error!("Scheduled backup error for '{}': {}", acc.id, e);
                        }
                    }

                    // Enforce retention policy
                    let retention = RetentionManager::new(&db, &storage);
                    if let Err(e) = retention.enforce_retention(&acc.id, acc.retention_days) {
                        warn!("Scheduled retention cleanup failed for '{}': {}", acc.id, e);
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
        let _ = self.scheduler.shutdown().await;
        self.config = new_config;
        self.scheduler = JobScheduler::new().await.map_err(|e| {
            Error::Other(format!("Failed to recreate job scheduler: {}", e))
        })?;
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
