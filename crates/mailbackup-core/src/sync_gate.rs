//! Per-account sync gate (issue #31).
//!
//! Every sync of an account and every change of its connection ("start a new
//! archive") holds the account's gate: an exclusive lock on
//! `<config dir>/.sync-locks/<account>.lock`. It works across processes, so
//! the server, its scheduler, the CLI and a separate daemon or service all
//! exclude each other.
//!
//! A sync takes the gate and only then reads the account from the config on
//! disk (the commit point of changes), so a sync that waited for a change uses
//! the account as changed, or is refused if it became an archive or was
//! removed. It never connects with a stale snapshot.

use crate::config::{AccountConfig, AppConfig};
use crate::db::Database;
use crate::error::{Error, Result};
use crate::keyring::CredentialStore;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Held for as long as the sync (or change) runs; dropping it releases the
/// account.
#[derive(Debug)]
pub struct SyncGate {
    _file: File,
    account_id: String,
}

impl SyncGate {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    fn path(config_path: &Path, account_id: &str) -> PathBuf {
        let dir = config_path.parent().map(Path::to_path_buf).unwrap_or_default();
        // Hex keeps any account id a distinct, valid file name
        dir.join(".sync-locks").join(format!("{}.lock", hex::encode(account_id.as_bytes())))
    }

    fn open(config_path: &Path, account_id: &str) -> Result<File> {
        let path = Self::path(config_path, account_id);
        if let Some(parent) = path.parent() {
            crate::private_fs::create_dir_all(parent)?;
        }
        let mut options = crate::private_fs::options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            // Never follow a symlink planted at the lock path
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        Ok(options.open(&path)?)
    }

    /// Waits for the account's gate. Blocking: use [`acquire_async`] from
    /// async code.
    pub fn acquire(config_path: &Path, account_id: &str) -> Result<SyncGate> {
        let file = Self::open(config_path, account_id)?;
        file.lock()?;
        Ok(SyncGate { _file: file, account_id: account_id.to_string() })
    }

    /// The account's gate if it is free right now.
    pub fn try_acquire(config_path: &Path, account_id: &str) -> Result<Option<SyncGate>> {
        let file = Self::open(config_path, account_id)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(SyncGate { _file: file, account_id: account_id.to_string() })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

/// [`SyncGate::acquire`] without blocking the async runtime.
pub async fn acquire_async(config_path: PathBuf, account_id: String) -> Result<SyncGate> {
    tokio::task::spawn_blocking(move || SyncGate::acquire(&config_path, &account_id))
        .await
        .map_err(|e| Error::Other(format!("sync gate task failed: {}", e)))?
}

/// Starts a sync of `account_id`: waits for its gate, settles a change of
/// the account's connection that crashed half-way (another process may have
/// died mid-switch while this one was running), then reads the account from
/// the config on disk. Refused if the account is gone, a read-only archive,
/// or has a change that couldn't be settled; the caller decides what else to
/// check (e.g. `enabled`).
pub async fn begin_account_sync(
    db: &Database,
    credentials: &CredentialStore,
    config_path: &Path,
    account_id: &str,
) -> Result<(SyncGate, AccountConfig)> {
    let gate = acquire_async(config_path.to_path_buf(), account_id.to_string()).await?;
    crate::archive::settle_pending(db, credentials, config_path, account_id)?;
    let account = current_account(config_path, account_id)?;
    Ok((gate, account))
}

/// The account as the config on disk has it, for a sync: `AccountNotFound`
/// if it's not there, `AccountArchived` if it is a read-only archive.
pub fn current_account(config_path: &Path, account_id: &str) -> Result<AccountConfig> {
    let config = AppConfig::load_existing(config_path)?.ok_or_else(|| Error::AccountNotFound(account_id.to_string()))?;
    match config.accounts.into_iter().find(|a| a.id == account_id) {
        None => Err(Error::AccountNotFound(account_id.to_string())),
        Some(a) if a.is_archive() => Err(Error::AccountArchived(account_id.to_string())),
        Some(a) => Ok(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let held = SyncGate::try_acquire(&config, "a").unwrap().expect("free");
        assert!(SyncGate::try_acquire(&config, "a").unwrap().is_none(), "held");
        assert!(SyncGate::try_acquire(&config, "b").unwrap().is_some(), "per account");
        drop(held);
        assert!(SyncGate::try_acquire(&config, "a").unwrap().is_some(), "released");
    }

    #[test]
    fn ids_map_to_distinct_lock_files() {
        let config = Path::new("/x/config.yaml");
        assert_ne!(SyncGate::path(config, "a~1"), SyncGate::path(config, "a1"));
        assert_ne!(SyncGate::path(config, "../a"), SyncGate::path(config, "a"));
    }
}
