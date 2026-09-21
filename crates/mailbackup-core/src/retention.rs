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

pub struct RetentionManager<'a> {
    db: &'a Database,
    storage: &'a StorageEngine,
}

impl<'a> RetentionManager<'a> {
    pub fn new(db: &'a Database, storage: &'a StorageEngine) -> Self {
        Self { db, storage }
    }

    /// Enforces local retention policy for an account.
    /// If retention_days is None, no messages are deleted (kept forever).
    pub fn enforce_retention(
        &self,
        account_id: &str,
        retention_days: Option<u32>,
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

        let cutoff_date = Utc::now() - Duration::days(days as i64);
        let expired_messages = self.db.get_messages_older_than(account_id, cutoff_date)?;

        for msg in expired_messages {
            // Delete file from storage
            if let Err(e) = self.storage.delete_eml(&msg.relative_path) {
                tracing::warn!("Failed to delete expired file {}: {}", msg.relative_path, e);
            }

            // Delete database record and FTS index
            if let Err(e) = self.db.delete_message_record(&msg.id) {
                tracing::warn!("Failed to delete DB record {}: {}", msg.id, e);
            } else {
                report.pruned_count += 1;
                report.reclaimed_bytes += msg.size_bytes;
            }
        }

        if report.pruned_count > 0 {
            info!(
                "Retention policy for account '{}': pruned {} messages older than {} days (reclaimed {} bytes)",
                account_id, report.pruned_count, days, report.reclaimed_bytes
            );
        }

        Ok(report)
    }
}
