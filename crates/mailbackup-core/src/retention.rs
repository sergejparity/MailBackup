use crate::db::Database;
use crate::error::Result;
use crate::storage::StorageEngine;
use chrono::{Duration, Utc};
use tracing::info;

#[derive(Debug, Clone, Default)]
pub struct RetentionReport {
    pub account_id: String,
    pub pruned_count: u32,
    pub reclaimed_bytes: u64,
}

/// Rows deleted per transaction and per hold of the storage lock.
pub const BATCH: usize = 500;

pub struct RetentionManager<'a> {
    db: &'a Database,
    storage: &'a StorageEngine,
}

impl<'a> RetentionManager<'a> {
    pub fn new(db: &'a Database, storage: &'a StorageEngine) -> Self {
        Self { db, storage }
    }

    /// Enforces local retention policy for an account: messages archived
    /// more than `retention_days` ago are removed (issue #73: counted from
    /// when MailBackup backed them up, not from the date the mail claims).
    /// If retention_days is None, no messages are deleted (kept forever).
    pub fn enforce_retention(
        &self,
        account_id: &str,
        retention_days: Option<u32>,
    ) -> Result<RetentionReport> {
        self.enforce_retention_as_of(account_id, retention_days, Utc::now())
    }

    /// [`Self::enforce_retention`] with `now` as the current time.
    pub fn enforce_retention_as_of(
        &self,
        account_id: &str,
        retention_days: Option<u32>,
        now: chrono::DateTime<Utc>,
    ) -> Result<RetentionReport> {
        let mut report = RetentionReport {
            account_id: account_id.to_string(),
            pruned_count: 0,
            reclaimed_bytes: 0,
        };

        let days = match retention_days {
            Some(d) if d > 0 => d,
            _ => return Ok(report), // Retain forever
        };

        let cutoff_date = now - Duration::days(days as i64);
        let expired_messages = self.db.get_messages_archived_before(account_id, cutoff_date)?;

        // In batches (issue #79): each batch's rows go in one transaction,
        // then each file that no row in the whole catalog still names is
        // removed. Both happen under the exclusive storage lock, so no
        // archiver (in any process) can be between choosing one of these
        // files and committing a row for it.
        for batch in expired_messages.chunks(BATCH) {
            let _lock = self.storage.lock_exclusive()?;
            let ids: Vec<String> = batch.iter().map(|m| m.id.clone()).collect();
            match self.db.delete_message_records(&ids) {
                Ok(n) => report.pruned_count += n as u32,
                Err(e) => {
                    tracing::warn!("Failed to delete {} expired records: {}", ids.len(), e);
                    continue;
                }
            }
            let mut checked = std::collections::HashSet::new();
            for msg in batch {
                if !checked.insert(msg.relative_path.as_str()) {
                    continue;
                }
                match self.db.is_path_referenced(&msg.relative_path) {
                    Ok(false) => match self.storage.delete_eml(&msg.relative_path) {
                        Ok(()) => report.reclaimed_bytes += msg.size_bytes,
                        Err(e) => tracing::warn!("Failed to delete expired file {}: {}", msg.relative_path, e),
                    },
                    Ok(true) => tracing::debug!("Keeping {}: still referenced", msg.relative_path),
                    Err(e) => tracing::warn!("Keeping {}: couldn't check references: {}", msg.relative_path, e),
                }
            }
        }

        if report.pruned_count > 0 {
            info!(
                "Retention policy for account '{}': pruned {} messages backed up more than {} days ago (reclaimed {} bytes)",
                account_id, report.pruned_count, days, report.reclaimed_bytes
            );
        }

        Ok(report)
    }
}
