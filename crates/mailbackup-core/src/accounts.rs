//! Creating accounts without ever replacing one (issue #74).
//!
//! An account's id names its catalog rows, its archive folder and its stored
//! password, so two accounts must never share one. Ids are derived from the
//! address ([`StorageEngine::sanitize_slug`]), and different addresses can
//! give the same slug (`a.b@x.org` and `a_b@x.org`). [`create`] therefore:
//!
//! - refuses an address that already has an account (`Error::AccountExists`);
//! - gives an address whose slug is taken a free id (`<slug>-2`, …), where
//!   "taken" covers everything that id could collide with (see
//!   [`is_name_taken`]);
//! - saves the password only under that new, unused name, and removes it
//!   again if the config can't be saved.
//!
//! The whole step runs under one cross-process lock, so two creations (in
//! this process or another) can't choose the same id.

use crate::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use crate::db::Database;
use crate::error::{Error, Result};
use crate::keyring::CredentialStore;
use crate::storage::StorageEngine;
use crate::sync_gate::SyncGate;
use std::path::Path;

/// Name of the lock held while an account is created. Not a valid account id
/// (ids never contain `~` unless a transition added it), and lock files are
/// named by the hex of the name, so it can't clash with an account's gate.
const CREATE_LOCK: &str = "~create-account~";

/// What the user entered for a new account.
#[derive(Debug, Clone)]
pub struct NewAccount {
    pub name: String,
    pub email: String,
    pub provider: ProviderType,
    pub imap_server: String,
    pub imap_port: u16,
    pub username: String,
    pub password: String,
    pub schedule: Option<String>,
    pub retention_days: Option<u32>,
    /// An id chosen by the user (CLI `--id`); it must be free.
    pub requested_id: Option<String>,
}

/// Addresses compare without surrounding space and case.
pub fn same_address(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The live account that already uses `email`, if any. Read-only archives
/// keep the address of the account they were retired from and don't count:
/// an address whose live account was removed can be added again (under a
/// new id, since the archive still owns the old names).
pub fn find_by_address<'a>(config: &'a AppConfig, email: &str) -> Option<&'a AccountConfig> {
    config.accounts.iter().find(|a| !a.is_archive() && same_address(&a.email, email))
}

/// Whether `name` is in use as an account id, storage namespace or credential
/// name, by anything at all:
/// - an account in `configs` (live or a read-only archive): its id, storage
///   namespace or credential name;
/// - an account transition in the catalog, finished or not;
/// - catalog rows of an account with that id;
/// - a folder of that name in the data directory;
/// - a stored password of that name. If the credential store can't be read,
///   that error is returned: no name is handed out that can't be checked.
pub fn is_name_taken(
    name: &str,
    configs: &[&AppConfig],
    db: &Database,
    storage: &StorageEngine,
    credentials: &CredentialStore,
) -> Result<bool> {
    let in_config = configs.iter().flat_map(|c| &c.accounts).any(|a| {
        a.id == name || a.storage_namespace.as_deref() == Some(name) || a.credential_ref.as_deref() == Some(name)
    });
    if in_config || db.account_name_in_use(name)? {
        return Ok(true);
    }
    if std::fs::symlink_metadata(storage.base_dir().join(name)).is_ok() {
        return Ok(true);
    }
    match credentials.get_password(name) {
        Ok(_) => Ok(true),
        Err(e) if e.is_not_found() => Ok(false),
        Err(e) => Err(e),
    }
}

/// A free id for `email`: its slug, or the slug with the lowest free
/// `-<n>` suffix.
fn free_id(
    email: &str,
    configs: &[&AppConfig],
    db: &Database,
    storage: &StorageEngine,
    credentials: &CredentialStore,
) -> Result<String> {
    let slug = StorageEngine::sanitize_slug(email);
    if !is_name_taken(&slug, configs, db, storage, credentials)? {
        return Ok(slug);
    }
    for n in 2..10_000u32 {
        let candidate = format!("{}-{}", slug, n);
        if !is_name_taken(&candidate, configs, db, storage, credentials)? {
            return Ok(candidate);
        }
    }
    Err(Error::Other(format!("No free account id for '{}'", email)))
}

/// Adds a new account to `config` and saves it to `config_path`, with its
/// password stored. See the module docs for what is guaranteed. `config` is
/// the caller's (locked) copy; accounts another process added to the file
/// meanwhile are taken into account for the checks, and the caller's copy is
/// what is saved, as with every other change it makes.
///
/// On any error `config`, the config file and the credential store are as
/// they were.
pub fn create(
    config: &mut AppConfig,
    config_path: &Path,
    db: &Database,
    storage: &StorageEngine,
    credentials: &CredentialStore,
    new: NewAccount,
) -> Result<AccountConfig> {
    let email = new.email.trim().to_string();
    if email.is_empty() {
        return Err(Error::InvalidInput("The account needs an email address".to_string()));
    }
    if let Some(schedule) = &new.schedule {
        crate::scheduler::validate_schedule(schedule)?;
    }

    // One creation at a time, in any process
    let _lock = SyncGate::acquire(config_path, CREATE_LOCK)?;
    let on_disk = AppConfig::load_existing(config_path)?;
    let mut configs: Vec<&AppConfig> = vec![&*config];
    configs.extend(on_disk.as_ref());

    if let Some(existing) = configs.iter().find_map(|c| find_by_address(c, &email)) {
        return Err(Error::AccountExists(format!(
            "An account for {} already exists ('{}'). Edit that account instead of adding it again.",
            email, existing.name
        )));
    }
    let id = match new.requested_id.as_deref().map(str::trim).filter(|i| !i.is_empty()) {
        Some(requested) => {
            if is_name_taken(requested, &configs, db, storage, credentials)? {
                return Err(Error::AccountExists(format!("The account id '{}' is already in use", requested)));
            }
            requested.to_string()
        }
        None => free_id(&email, &configs, db, storage, credentials)?,
    };
    drop(configs);

    let account = AccountConfig {
        id,
        name: new.name,
        email,
        provider: new.provider,
        imap_server: new.imap_server.trim().to_string(),
        imap_port: new.imap_port,
        use_tls: true,
        auth_type: AuthType::Password,
        username: new.username.trim().to_string(),
        schedule: new.schedule.map(|s| s.trim().to_string()),
        retention_days: new.retention_days,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
        storage_namespace: None,
        credential_ref: None,
        archive: None,
        trust_server_ids: false,
    };

    // The name was just found unused, so this can't overwrite a password
    let undo_password = |why: &Error| {
        if let Err(e) = credentials.delete_password(account.credential_ref())
            && !e.is_not_found() {
            tracing::warn!("Couldn't remove the password of the account that wasn't created ({}): {}", why, e);
        }
    };
    if let Err(e) = credentials.set_account_password(&account, &new.password) {
        undo_password(&e);
        return Err(e);
    }
    config.accounts.push(account.clone());
    if let Err(e) = config.save(config_path) {
        config.accounts.pop();
        undo_password(&e);
        return Err(e);
    }
    Ok(account)
}

// ---------------------------------------------------------------------------
// CSV import
// ---------------------------------------------------------------------------

/// What importing one valid CSV row does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportAction {
    /// A new account (its id is chosen when it is created).
    Create,
    /// Updates the existing account with this id ("update existing accounts").
    Update(String),
}

/// Checks a whole CSV import against `config` before anything is written:
/// a row whose address already has an account is an error, unless
/// `update_existing` makes it an update of that account; two rows with the
/// same address are both errors. Returns the action for each row of `rows`
/// that may be imported, and the errors for the others.
pub fn plan_import(
    config: &AppConfig,
    rows: &[crate::csv_import::ValidImportAccount],
    update_existing: bool,
) -> (Vec<(usize, ImportAction)>, Vec<crate::csv_import::CsvRowError>) {
    let mut plan = Vec::new();
    let mut errors = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let error = |message: String| crate::csv_import::CsvRowError {
            line: row.line,
            raw_content: row.email.clone(),
            error: message,
        };
        let others: Vec<usize> = rows
            .iter()
            .filter(|other| !std::ptr::eq(*other, row) && same_address(&other.email, &row.email))
            .map(|other| other.line)
            .collect();
        if !others.is_empty() {
            let lines: Vec<String> = others.iter().map(usize::to_string).collect();
            errors.push(error(format!("{} appears more than once in the file (also line {})", row.email, lines.join(", "))));
            continue;
        }
        match find_by_address(config, &row.email) {
            None => plan.push((i, ImportAction::Create)),
            Some(existing) if update_existing => plan.push((i, ImportAction::Update(existing.id.clone()))),
            Some(existing) => errors.push(error(format!(
                "An account for {} already exists ('{}'); turn on \"update existing accounts\" to change it",
                row.email, existing.name
            ))),
        }
    }
    (plan, errors)
}

/// The import's [`NewAccount`] for a row.
pub fn new_account_from_row(row: &crate::csv_import::ValidImportAccount) -> NewAccount {
    NewAccount {
        name: row.name.clone(),
        email: row.email.clone(),
        provider: row.provider.clone(),
        imap_server: row.imap_server.clone(),
        imap_port: row.imap_port,
        username: row.username.clone(),
        password: row.password.clone(),
        schedule: row.schedule.clone(),
        retention_days: row.retention_days,
        requested_id: None,
    }
}

/// Applies a CSV row to the existing live account `id` ("update existing
/// accounts"). Changes only the name, connection, schedule, retention and
/// password; never the storage namespace, credential name, archive status,
/// server-id trust, folder filter or `enabled`. The row always carries a
/// password, so a changed connection gets the password entered for it.
///
/// If the config can't be saved, the previous password is put back.
pub fn update_from_row(
    config: &mut AppConfig,
    config_path: &Path,
    credentials: &CredentialStore,
    id: &str,
    row: &crate::csv_import::ValidImportAccount,
) -> Result<AccountConfig> {
    if let Some(schedule) = &row.schedule {
        crate::scheduler::validate_schedule(schedule)?;
    }
    let current = config.account_by_id(id).cloned().ok_or_else(|| Error::AccountNotFound(id.to_string()))?;
    if current.is_archive() {
        return Err(Error::AccountArchived(id.to_string()));
    }
    let mut updated = current.clone();
    updated.name = row.name.clone();
    updated.imap_server = row.imap_server.trim().to_string();
    updated.imap_port = row.imap_port;
    updated.username = row.username.trim().to_string();
    if row.schedule.is_some() {
        updated.schedule = row.schedule.clone();
    }
    if row.retention_days.is_some() {
        updated.retention_days = row.retention_days;
    }

    let previous = match credentials.get_password(current.credential_ref()) {
        Ok(pw) => Some(pw),
        Err(e) if e.is_not_found() => None,
        Err(e) => return Err(e),
    };
    credentials.set_account_password(&updated, &row.password)?;
    let slot = config.account_by_id_mut(id).expect("checked above");
    *slot = updated.clone();
    if let Err(e) = config.save(config_path) {
        *config.account_by_id_mut(id).expect("checked above") = current.clone();
        let restored = match &previous {
            Some(pw) => credentials.set_account_password(&current, pw),
            None => credentials.delete_password(current.credential_ref()),
        };
        if let Err(restore) = restored {
            tracing::warn!("Couldn't restore the previous password of '{}': {}", id, restore);
        }
        return Err(e);
    }
    Ok(updated)
}
