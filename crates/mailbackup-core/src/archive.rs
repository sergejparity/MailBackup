//! "Start a new archive" (issue #31): when an account moves to another
//! server, retire what it has archived so far as a read-only archive account
//! and let the account start empty on the new connection.
//!
//! The switch is a small commit protocol, run while holding the account's
//! sync gate (no sync of it can start or run meanwhile):
//! 1. **prepare** (one DB transaction): record the transition, move the
//!    account's folders and messages to the archive id, fence in-flight
//!    sessions by starting new UID generations;
//! 2. **stage** the new password under a fresh credential ref (the old
//!    password is left untouched);
//! 3. **commit**: save the config with the archive entry and the live entry
//!    pointing at the new connection, storage namespace and credential ref;
//! 4. **finish**: mark the transition done and delete the old password.
//!
//! A failure before the commit undoes 1–2; after it, the switch stands.
//! A crash leaves the transition `prepared`; it is settled the same way (the
//! config on disk decides) by [`recover`] at startup and by [`settle_pending`]
//! under the gate before any later sync or switch of the account, so a
//! process that was already running never syncs over a half-done switch.

use crate::config::{AccountConfig, AppConfig, ArchiveInfo};
use crate::db::{Database, NewTransition};
use crate::error::{Error, Result};
use crate::keyring::CredentialStore;
use crate::sync_gate::SyncGate;
use chrono::{DateTime, Utc};
use std::path::Path;
use tracing::warn;

/// The new connection for the live account.
pub struct NewConnection<'a> {
    pub server: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub password: &'a str,
}

/// The result of a switch. `gate` is still held: publish the new config
/// (e.g. reload the scheduler) before dropping it.
pub struct Switched {
    pub live: AccountConfig,
    pub archive: AccountConfig,
    pub gate: SyncGate,
}

/// Retires `account_id`'s archive and moves the account to `conn`, saving the
/// config to `config_path`. `config` is the caller's in-memory config; it is
/// updated only if the switch commits.
pub fn start_new_archive(
    db: &Database,
    credentials: &CredentialStore,
    config: &mut AppConfig,
    config_path: &Path,
    account_id: &str,
    conn: &NewConnection<'_>,
) -> Result<Switched> {
    start_new_archive_with(db, credentials, config, config_path, account_id, conn, Utc::now(), |c| c.save(config_path))
}

/// [`start_new_archive`] with the time and the config save given (tests use
/// them to inject failures).
#[allow(clippy::too_many_arguments)]
pub fn start_new_archive_with(
    db: &Database,
    credentials: &CredentialStore,
    config: &mut AppConfig,
    config_path: &Path,
    account_id: &str,
    conn: &NewConnection<'_>,
    now: DateTime<Utc>,
    save: impl FnOnce(&AppConfig) -> Result<()>,
) -> Result<Switched> {
    let gate = SyncGate::try_acquire(config_path, account_id)?.ok_or_else(|| Error::AccountBusy(account_id.to_string()))?;
    // A switch that crashed half-way is settled before this one starts (if
    // it had committed, the check below sees the account changed on disk)
    settle_pending(db, credentials, config_path, account_id)?;

    // Revalidate under the gate: the account as the caller sees it must be
    // the one on disk, live, and actually changing connection
    let live = config.get_account(account_id).filter(|a| a.id == account_id).cloned().ok_or_else(|| Error::AccountNotFound(account_id.to_string()))?;
    if live.is_archive() {
        return Err(Error::AccountArchived(account_id.to_string()));
    }
    let on_disk = AppConfig::load_existing(config_path)?
        .and_then(|c| c.accounts.into_iter().find(|a| a.id == account_id))
        .ok_or_else(|| Error::AccountNotFound(account_id.to_string()))?;
    if on_disk != live {
        return Err(Error::Other("The account was changed elsewhere meanwhile; reload and try again.".into()));
    }
    let mut moved = live.clone();
    moved.imap_server = conn.server.trim().to_string();
    moved.imap_port = conn.port;
    moved.username = conn.username.trim().to_string();
    if moved.remote_identity() == live.remote_identity() {
        return Err(Error::InvalidInput("The server, port and username are unchanged; there is nothing to archive.".into()));
    }
    if conn.password.is_empty() {
        return Err(Error::InvalidInput("Enter the account password to change the server, port or username.".into()));
    }

    // A number never used for this account, durably: the catalog keeps every
    // attempt, the config every archive
    let seq = db.last_transition_seq(account_id)?.max(highest_seq_in_config(config, account_id)) + 1;
    let archive_id = format!("{}~archive-{}-{}", account_id, now.format("%Y%m%d"), seq);
    let staged_ref = format!("{}~cred-{}", account_id, seq);
    let namespace = format!("{}~{}", account_id, seq);
    let old_ref = live.credential_ref().to_string();
    let last_source = db.last_remote_identity(account_id)?;

    // 1. prepare
    let transition = db.prepare_account_transition(&NewTransition {
        live_id: account_id,
        archive_id: &archive_id,
        seq,
        old_credential_ref: &old_ref,
        staged_credential_ref: &staged_ref,
    })?;

    // 2. stage the new password; the old one stays until the switch stands
    moved.credential_ref = Some(staged_ref.clone());
    moved.storage_namespace = Some(namespace);
    if let Err(e) = credentials.set_account_password(&moved, conn.password) {
        undo(db, credentials, transition, &staged_ref);
        return Err(e);
    }

    // 3. commit
    let archive = AccountConfig {
        id: archive_id.clone(),
        name: format!("{} (archived {})", live.name, now.format("%Y-%m-%d")),
        enabled: false,
        schedule: None,
        retention_days: None,
        storage_namespace: Some(live.storage_namespace().to_string()),
        credential_ref: None,
        archive: Some(ArchiveInfo { archived_at: now, retired_from: account_id.to_string(), last_source }),
        ..live.clone()
    };
    let mut next = config.clone();
    for a in next.accounts.iter_mut().filter(|a| a.id == account_id) {
        *a = moved.clone();
    }
    next.accounts.push(archive.clone());
    if let Err(e) = save(&next) {
        undo(db, credentials, transition, &staged_ref);
        return Err(e);
    }
    *config = next;

    // 4. finish; if this fails, recovery finishes it at the next start
    finish(db, credentials, transition, &old_ref);
    Ok(Switched { live: moved, archive, gate })
}

/// Settles transitions a crash left `prepared`: finished if the config on
/// disk has the archive (the commit happened), undone otherwise. Run at
/// startup, before any sync. A transition whose account gate is held is
/// still running (e.g. in the server while the CLI starts) and is left alone.
pub fn recover(db: &Database, credentials: &CredentialStore, config_path: &Path) -> Result<usize> {
    let mut settled = 0;
    let mut accounts: Vec<String> = db.prepared_transitions()?.into_iter().map(|t| t.live_id).collect();
    accounts.sort();
    accounts.dedup();
    for account_id in accounts {
        let Some(_gate) = SyncGate::try_acquire(config_path, &account_id)? else {
            continue;
        };
        settled += settle_pending(db, credentials, config_path, &account_id)?;
    }
    Ok(settled)
}

/// Settles `account_id`'s transitions left `prepared` by a crash: finished if
/// the config on disk has the archive (the commit happened), undone
/// otherwise. The caller must hold the account's gate, so none of them is
/// still running. Fails if one couldn't be settled: syncing or switching the
/// account on top of it isn't safe.
pub fn settle_pending(db: &Database, credentials: &CredentialStore, config_path: &Path, account_id: &str) -> Result<usize> {
    let pending = db.prepared_transitions_of(account_id)?;
    if pending.is_empty() {
        return Ok(0);
    }
    let config = AppConfig::load_existing(config_path)?;
    for t in &pending {
        let committed = config.as_ref().is_some_and(|c| c.accounts.iter().any(|a| a.id == t.archive_id));
        if committed {
            finish(db, credentials, t.id, &t.old_credential_ref);
        } else {
            undo(db, credentials, t.id, &t.staged_credential_ref);
        }
    }
    if !db.prepared_transitions_of(account_id)?.is_empty() {
        return Err(Error::Other(format!("A change of account '{}' couldn't be completed or undone; see the log", account_id)));
    }
    Ok(pending.len())
}

fn undo(db: &Database, credentials: &CredentialStore, transition: i64, staged_ref: &str) {
    if let Err(e) = db.abort_account_transition(transition) {
        warn!("Couldn't undo account transition {}: {}; it will be undone at the next start", transition, e);
        return;
    }
    if let Err(e) = credentials.delete_password(staged_ref) {
        if !e.is_not_found() {
            warn!("Couldn't delete the staged password {}: {}", staged_ref, e);
        }
    }
}

fn finish(db: &Database, credentials: &CredentialStore, transition: i64, old_ref: &str) {
    if let Err(e) = db.finish_account_transition(transition) {
        warn!("Couldn't record account transition {} as done: {}; it will be at the next start", transition, e);
        return;
    }
    if let Err(e) = credentials.delete_password(old_ref) {
        if !e.is_not_found() {
            warn!("Couldn't delete the replaced password {}: {}", old_ref, e);
        }
    }
}

/// The highest transition number visible in the config for `account_id`:
/// in archive ids, storage namespaces and credential refs derived from it.
fn highest_seq_in_config(config: &AppConfig, account_id: &str) -> u32 {
    let archive_prefix = format!("{}~archive-", account_id);
    let plain_prefix = format!("{}~", account_id);
    let mut highest = 0;
    for a in &config.accounts {
        let mut names: Vec<&str> = vec![a.id.as_str()];
        names.extend(a.storage_namespace.as_deref());
        names.extend(a.credential_ref.as_deref());
        for name in names {
            let n = if let Some(rest) = name.strip_prefix(&archive_prefix) {
                rest.rsplit('-').next().and_then(|n| n.parse().ok())
            } else if let Some(rest) = name.strip_prefix(&plain_prefix) {
                rest.strip_prefix("cred-").unwrap_or(rest).parse().ok()
            } else {
                None
            };
            highest = highest.max(n.unwrap_or(0));
        }
    }
    highest
}
