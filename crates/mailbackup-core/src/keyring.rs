//! Account passwords: the OS keyring plus an encrypted local store.
//!
//! The local store (`.credentials_store.json`) is a versioned envelope:
//!
//! ```json
//! { "version": 2,
//!   "kdf": null | { "alg": "argon2id", "version": 19, "m_cost": …, "t_cost": …, "p_cost": …, "salt": "<hex>" },
//!   "check": "enc:v1:…",
//!   "entries": { "account:<id>": "enc:v1:<nonce hex>:<ciphertext hex>", … } }
//! ```
//!
//! Each value is AES-256-GCM. The key is either a random key kept in the key
//! file (`.credentials_key`, and the keyring when available) or, with `kdf`
//! set, derived with Argon2id from the `MAILBACKUP_MASTER_KEY` passphrase.
//! `check` holds a known value, so a wrong key is told apart from damage.
//!
//! Rules:
//! - Only `NotFound` means "no secret". A store that can't be read, parsed or
//!   decrypted is reported as such and never overwritten.
//! - Older formats (a flat map, possibly in `credentials_store.json`) are read
//!   with the keys older versions used, including the passphrase's plain
//!   SHA-256 and the path-derived key, and rewritten as version 2. Those legacy
//!   keys are only ever used to decrypt, and never for a version 2 store.
//! - Writers hold an exclusive lock on `<store>.lock`, files are replaced
//!   atomically after the new content is verified, and the key file is created
//!   exclusively.

use crate::config::AccountConfig;
use crate::error::{CredentialErrorKind as Kind, Error, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SERVICE_NAME: &str = "mailbackup";
const ENC_PREFIX: &str = "enc:v1:";
const MASTER_KEY_ENTRY: &str = "master_encryption_key";
const PASSPHRASE_VARS: [&str; 2] = ["MAILBACKUP_MASTER_KEY", "MAILBACKUP_ENCRYPTION_KEY"];
const STORE_VERSION: u32 = 2;
const CHECK_VALUE: &str = "mailbackup:credential-store:v2";

// Argon2id parameters for new stores (OWASP: 19 MiB, 2 passes, 1 lane), and
// the limits accepted when reading one, checked before any memory is allocated.
const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;
const ARGON2_MAX_M_COST_KIB: u32 = 256 * 1024;
const ARGON2_MAX_T_COST: u32 = 10;
const ARGON2_MAX_P_COST: u32 = 4;
const SALT_LEN: usize = 16;
const SALT_LEN_RANGE: std::ops::RangeInclusive<usize> = 16..=64;

/// Where secrets are kept besides the local store. The OS keyring by default;
/// tests and tools can supply their own.
pub trait SecretBackend: Send + Sync {
    /// Errors: `NotFound` (no entry), `Locked`, `Unavailable`.
    fn get(&self, key: &str) -> Result<String>;
    fn set(&self, key: &str, secret: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// The platform keyring through the `keyring` crate.
pub struct OsKeyring;

impl SecretBackend for OsKeyring {
    fn get(&self, key: &str) -> Result<String> {
        keyring_entry(key)?.get_password().map_err(keyring_error)
    }

    fn set(&self, key: &str, secret: &str) -> Result<()> {
        keyring_entry(key)?.set_password(secret).map_err(keyring_error)
    }

    fn delete(&self, key: &str) -> Result<()> {
        keyring_entry(key)?.delete_credential().map_err(keyring_error)
    }
}

fn keyring_entry(key: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE_NAME, key).map_err(keyring_error)
}

fn keyring_error(e: keyring::Error) -> Error {
    match e {
        keyring::Error::NoEntry => Error::credential(Kind::NotFound, "No entry in the OS keyring"),
        keyring::Error::NoStorageAccess(err) => {
            Error::credential(Kind::Locked, format!("The OS keyring is locked or refused access: {}", err))
        }
        other => Error::credential(Kind::Unavailable, format!("The OS keyring is unavailable: {}", other)),
    }
}

/// No keyring: every call is `Unavailable`. Used when `MAILBACKUP_KEYRING=none`
/// (headless machines, tests) and to check what the background service sees.
pub struct NoKeyring;

impl SecretBackend for NoKeyring {
    fn get(&self, _: &str) -> Result<String> {
        Err(Error::credential(Kind::Unavailable, "The OS keyring is turned off"))
    }
    fn set(&self, _: &str, _: &str) -> Result<()> {
        Err(Error::credential(Kind::Unavailable, "The OS keyring is turned off"))
    }
    fn delete(&self, _: &str) -> Result<()> {
        Err(Error::credential(Kind::Unavailable, "The OS keyring is turned off"))
    }
}

/// The OS keyring, unless `MAILBACKUP_KEYRING` is `none`, `off` or `disabled`.
fn default_keyring() -> Arc<dyn SecretBackend> {
    match std::env::var("MAILBACKUP_KEYRING").map(|v| v.trim().to_ascii_lowercase()) {
        Ok(v) if matches!(v.as_str(), "none" | "off" | "disabled" | "0" | "false") => Arc::new(NoKeyring),
        _ => Arc::new(OsKeyring),
    }
}

/// What a switch to disk storage added, so a failed service install can undo it.
#[derive(Debug, Default)]
pub struct DiskStorageChange {
    /// Keys written to the local store that weren't there before.
    pub added: Vec<String>,
    /// Accounts without a saved password (nothing to copy).
    pub skipped_accounts: Vec<String>,
}

/// What a switch back to keyring storage did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KeyringMove {
    /// Moved into the keyring (verified) and removed from the local store.
    pub moved: Vec<String>,
    /// Left in the local store: the keyring couldn't take or confirm them.
    pub kept: Vec<String>,
    /// Why entries were kept, if any.
    pub reason: Option<String>,
}

/// Account passwords and their connection bindings.
///
/// By default the OS keyring holds them and the local encrypted store is the
/// fallback for machines without a keyring. With disk storage on (the
/// background service, which can't open the keyring when it starts at boot),
/// the local store holds them. See [`CredentialStore::for_config`].
pub struct CredentialStore {
    fallback_path: PathBuf,
    key_path: PathBuf,
    passphrase: Option<String>,
    keyring: Arc<dyn SecretBackend>,
    /// Keep secrets in the local store (background service mode).
    disk_storage: std::sync::atomic::AtomicBool,
    /// Older locations of this config's store, read (and cleaned on delete)
    /// but otherwise left alone.
    legacy_stores: Vec<CredentialStore>,
    /// Last Argon2 result: (fingerprint of passphrase + parameters, key)
    derived: Mutex<Option<([u8; 32], [u8; 32])>>,
}

impl CredentialStore {
    /// The store for the default config (`~/.mailbackup`).
    pub fn new() -> Self {
        Self::for_config(&crate::config::default_config_path(), &crate::config::GlobalSettings::default())
    }

    /// The store every process uses for `config_path`: the CLI, the server and
    /// the background service (the server run with `--config`) all resolve the
    /// same config to `<config folder>/.credentials_store.json` and
    /// `.credentials_key`. Disk storage follows `settings.run_as_service`.
    ///
    /// Versions before 0.3.0 of the CLI kept credentials for a custom
    /// `--config` in `~/.mailbackup`, which is also the default config's
    /// store. It stays readable as a legacy location: secrets found there are
    /// copied on first use, and a delete removes only a copy with the same
    /// value. Nothing else in it changes.
    pub fn for_config(config_path: &Path, settings: &crate::config::GlobalSettings) -> Self {
        let (store, key) = Self::paths_for_config(config_path);
        let mut credentials = Self::with_paths(store.clone(), key);
        let (legacy_store, _) = Self::paths_for_config(&crate::config::default_config_path());
        if legacy_store != store {
            let legacy_key = legacy_store.with_file_name(".credentials_key");
            credentials.legacy_stores.push(Self::with_paths(legacy_store, legacy_key).with_keyring(Arc::new(NoKeyring)));
        }
        credentials.set_disk_storage(settings.run_as_service);
        credentials
    }

    /// Where [`for_config`](Self::for_config) keeps the store and key for `config_path`.
    ///
    /// The config's folder is resolved to its real path (so `./config.yaml`,
    /// `../x/config.yaml` and a symlinked folder all give the same store), or
    /// cleaned up lexically if it doesn't exist yet.
    pub fn paths_for_config(config_path: &Path) -> (PathBuf, PathBuf) {
        let absolute = std::path::absolute(config_path).unwrap_or_else(|_| config_path.to_path_buf());
        let dir = absolute.parent().map(Path::to_path_buf).unwrap_or_else(crate::config::default_base_dir);
        let dir = resolve_existing_prefix(&normalize_lexically(&dir));
        (dir.join(".credentials_store.json"), dir.join(".credentials_key"))
    }

    /// The local store and key file this store uses.
    pub fn store_paths(&self) -> (&Path, &Path) {
        (&self.fallback_path, &self.key_path)
    }

    pub fn with_fallback_path(fallback_path: PathBuf) -> Self {
        let key_path = fallback_path.with_extension("key");
        Self::with_paths(fallback_path, key_path)
    }

    /// A store at the given paths, using the OS keyring and the passphrase
    /// from `MAILBACKUP_MASTER_KEY` / `MAILBACKUP_ENCRYPTION_KEY` if set.
    pub fn with_paths(fallback_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            fallback_path,
            key_path,
            passphrase: passphrase_from_env(),
            keyring: default_keyring(),
            disk_storage: std::sync::atomic::AtomicBool::new(false),
            legacy_stores: Vec::new(),
            derived: Mutex::new(None),
        }
    }

    /// Turns disk storage on or off (see [`switch_to_disk_storage`](Self::switch_to_disk_storage)
    /// for doing it safely around a service install).
    pub fn with_disk_storage(self, on: bool) -> Self {
        self.set_disk_storage(on);
        self
    }

    pub fn set_disk_storage(&self, on: bool) {
        self.disk_storage.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn disk_storage(&self) -> bool {
        self.disk_storage.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Adds an older location to read from (see [`for_config`](Self::for_config)).
    pub fn with_legacy_store(mut self, fallback_path: PathBuf, key_path: PathBuf) -> Self {
        let passphrase = self.passphrase.clone();
        self.legacy_stores.push(
            Self::with_paths(fallback_path, key_path).with_passphrase(passphrase).with_keyring(Arc::new(NoKeyring)),
        );
        self
    }

    /// Replaces the passphrase taken from the environment.
    pub fn with_passphrase(mut self, passphrase: Option<String>) -> Self {
        self.passphrase = passphrase.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
        for legacy in &mut self.legacy_stores {
            legacy.passphrase = self.passphrase.clone();
        }
        self
    }

    /// Replaces the OS keyring.
    pub fn with_keyring(mut self, keyring: Arc<dyn SecretBackend>) -> Self {
        self.keyring = keyring;
        self
    }

    pub fn set_password(&self, account_id: &str, secret: &str) -> Result<()> {
        self.set_secret(&format!("account:{}", account_id), secret)
    }

    pub fn get_password(&self, account_id: &str) -> Result<String> {
        self.get_secret(&format!("account:{}", account_id))
    }

    /// Deletes the password and its binding; both are attempted even if the
    /// first fails, and the first error is returned.
    pub fn delete_password(&self, account_id: &str) -> Result<()> {
        let password = self.delete_secret(&format!("account:{}", account_id));
        let binding = self.delete_secret(&binding_key(account_id));
        password.and(binding)
    }

    /// Stores an account's password together with a fingerprint of the
    /// server/port/username it was entered for (see [`connection_binding`]).
    pub fn set_account_password(&self, account: &AccountConfig, secret: &str) -> Result<()> {
        self.set_password(&account.id, secret)?;
        self.set_secret(&binding_key(&account.id), &connection_binding(account))
    }

    /// Returns an account's password only if it was entered for the account's
    /// current server/port/username, so a changed config (through the API or an
    /// edit on disk) never sends the old password to a different server.
    ///
    /// Passwords saved before bindings existed are bound to the current settings
    /// on first use (trust on first use), so existing scheduled backups keep
    /// working. That only happens when the binding is certainly missing, never
    /// when it couldn't be read.
    pub fn get_account_password(&self, account: &AccountConfig) -> Result<String> {
        let secret = self.get_password(&account.id)?;
        let expected = connection_binding(account);
        match self.get_secret(&binding_key(&account.id)) {
            Ok(stored) if stored == expected => Ok(secret),
            Ok(_) => Err(Error::CredentialMismatch(account.id.clone())),
            Err(e) if e.is_not_found() => {
                self.set_secret(&binding_key(&account.id), &expected)?;
                Ok(secret)
            }
            Err(e) => Err(e),
        }
    }

    fn set_secret(&self, key: &str, secret: &str) -> Result<()> {
        if self.disk_storage() {
            return self.set_local(key, secret);
        }
        match self.keyring.set(key, secret) {
            Ok(()) => {
                // The keyring has it now; drop an older local copy
                if let Err(e) = self.update_fallback(|entries| entries.remove(key).is_some()) {
                    tracing::warn!("Saved '{}' in the keyring but couldn't remove the local copy: {}", key, e);
                }
                Ok(())
            }
            // No keyring on this machine: the local store is the fallback
            Err(e) if e.credential_kind() == Some(Kind::Unavailable) => self.set_local(key, secret),
            // Locked or refused: never quietly put it on disk instead
            Err(e) => Err(e),
        }
    }

    fn set_local(&self, key: &str, secret: &str) -> Result<()> {
        self.update_fallback(|entries| entries.insert(key.to_string(), secret.to_string()) != Some(secret.to_string()))
    }

    fn get_secret(&self, key: &str) -> Result<String> {
        if self.disk_storage() {
            return match self.get_local(key) {
                Err(e) if e.is_not_found() => match self.keyring.get(key) {
                    Ok(secret) => Ok(secret),
                    Err(k) if k.credential_kind() == Some(Kind::Locked) => Err(k),
                    Err(_) => Err(e),
                },
                other => other,
            };
        }
        let keyring_error = match self.keyring.get(key) {
            Ok(secret) => return Ok(secret),
            Err(e) => e,
        };
        match self.get_local(key) {
            Ok(secret) => {
                // The keyring works but doesn't have it yet: move it there
                if keyring_error.is_not_found() {
                    self.move_to_keyring(key, &secret);
                }
                Ok(secret)
            }
            // A locked keyring may hold the secret: say so rather than "not found"
            Err(e) if e.is_not_found() && keyring_error.credential_kind() == Some(Kind::Locked) => Err(keyring_error),
            Err(e) => Err(e),
        }
    }

    /// The local store, then the legacy locations. A secret found only in a
    /// legacy location is copied into the local store.
    fn get_local(&self, key: &str) -> Result<String> {
        let primary = match self.get_fallback(key) {
            Err(e) if e.is_not_found() => e,
            other => return other,
        };
        for legacy in &self.legacy_stores {
            match legacy.get_fallback(key) {
                Ok(secret) => {
                    if let Err(e) = self.set_local(key, &secret) {
                        tracing::warn!("Couldn't copy '{}' from {}: {}", key, legacy.fallback_path.display(), e);
                    }
                    return Ok(secret);
                }
                Err(e) if e.is_not_found() => {}
                Err(e) => tracing::warn!("Skipping the old credential store {}: {}", legacy.fallback_path.display(), e),
            }
        }
        Err(primary)
    }

    /// Puts `secret` in the keyring, reads it back, and only then removes the
    /// local copy (if it still holds the same value). Failures leave it local.
    fn move_to_keyring(&self, key: &str, secret: &str) -> bool {
        let verified = self.keyring.set(key, secret).is_ok() && self.keyring.get(key).ok().as_deref() == Some(secret);
        if !verified {
            return false;
        }
        let removed = self.update_fallback(|entries| {
            if entries.get(key).map(String::as_str) == Some(secret) {
                entries.remove(key);
                true
            } else {
                false
            }
        });
        if let Err(e) = removed {
            tracing::warn!("Moved '{}' to the keyring but couldn't remove the local copy: {}", key, e);
        }
        true
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        // Local stores first: if one can't be updated, the keyring copy stays too
        let mut deleted = None;
        self.update_fallback(|entries| {
            deleted = entries.remove(key);
            deleted.is_some()
        })?;
        // A legacy location may also be another config's store (`~/.mailbackup`
        // is the default config's): only remove the copy migrated from there
        if let Some(value) = &deleted {
            for legacy in &self.legacy_stores {
                legacy.update_fallback(|entries| {
                    if entries.get(key) == Some(value) {
                        entries.remove(key);
                        true
                    } else {
                        false
                    }
                })?;
            }
        }
        match self.keyring.delete(key) {
            Err(e) if e.credential_kind() == Some(Kind::Locked) => Err(e),
            _ => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // Background service transitions
    // -----------------------------------------------------------------------

    /// Switches to disk storage for the background service, then runs
    /// `install`. Before anything is installed, every account's password and
    /// binding is copied to the local store in one verified write, and read
    /// back by a reader without keyring access, as the service will be.
    ///
    /// If `install` fails, disk storage is turned off again and the copies are
    /// removed, but only those whose keyring copy reads back equal: the only
    /// copy of a secret is never removed.
    pub fn switch_to_disk_storage(
        &self,
        account_ids: &[String],
        install: impl FnOnce() -> Result<()>,
    ) -> Result<DiskStorageChange> {
        if self.passphrase.is_some() {
            return Err(Error::credential(
                Kind::NoKey,
                "The credential store is protected by MAILBACKUP_MASTER_KEY, which the background service doesn't receive. Unset it and save the passwords again before enabling the service.",
            ));
        }
        let mut wanted = BTreeMap::new();
        let mut change = DiskStorageChange::default();
        for id in account_ids {
            let password_key = format!("account:{}", id);
            match self.get_secret(&password_key) {
                Ok(secret) => {
                    wanted.insert(password_key, secret);
                }
                Err(e) if e.is_not_found() => {
                    change.skipped_accounts.push(id.clone());
                    continue;
                }
                Err(e) => return Err(e),
            }
            match self.get_secret(&binding_key(id)) {
                Ok(binding) => {
                    wanted.insert(binding_key(id), binding);
                }
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
        }

        let mut added = Vec::new();
        self.update_fallback(|entries| {
            let mut changed = false;
            for (k, v) in &wanted {
                match entries.insert(k.clone(), v.clone()) {
                    None => {
                        added.push(k.clone());
                        changed = true;
                    }
                    Some(old) if &old != v => changed = true,
                    Some(_) => {}
                }
            }
            changed
        })?;
        change.added = added;

        // What the service will see: the files only, no keyring, no passphrase
        let service_view = Self::with_paths(self.fallback_path.clone(), self.key_path.clone())
            .with_passphrase(None)
            .with_keyring(Arc::new(NoKeyring))
            .with_disk_storage(true);
        for (k, v) in &wanted {
            if service_view.get_fallback(k).ok().as_ref() != Some(v) {
                self.undo_disk_copies(&change.added);
                return Err(Error::credential(
                    Kind::Unavailable,
                    format!("Couldn't verify the copy of '{}' in {}. The service wasn't installed.", k, self.fallback_path.display()),
                ));
            }
        }

        self.set_disk_storage(true);
        if let Err(e) = install() {
            self.set_disk_storage(false);
            self.undo_disk_copies(&change.added);
            return Err(e);
        }
        Ok(change)
    }

    /// Removes the given local copies whose keyring copy reads back equal.
    fn undo_disk_copies(&self, keys: &[String]) {
        let safe: Vec<(String, String)> = keys
            .iter()
            .filter_map(|k| self.keyring.get(k).ok().map(|v| (k.clone(), v)))
            .collect();
        if safe.is_empty() {
            return;
        }
        let result = self.update_fallback(|entries| {
            let mut changed = false;
            for (k, v) in &safe {
                if entries.get(k) == Some(v) {
                    entries.remove(k);
                    changed = true;
                }
            }
            changed
        });
        if let Err(e) = result {
            tracing::warn!("Couldn't remove the local copies after a failed service install: {}", e);
        }
    }

    /// Runs `uninstall`, checks with `still_installed` that the service is
    /// gone, then switches back to keyring storage: each local secret is put
    /// in the keyring and read back, and only verified ones (still holding the
    /// same value) are removed from the local store. Secrets the keyring can't
    /// take (no keyring, locked, mismatch) stay on disk and are reported.
    pub fn switch_to_keyring_storage(
        &self,
        uninstall: impl FnOnce() -> Result<()>,
        still_installed: impl FnOnce() -> bool,
    ) -> Result<KeyringMove> {
        uninstall()?;
        if still_installed() {
            return Err(Error::Other(
                "The background service is still installed, so its passwords were left on disk.".to_string(),
            ));
        }
        self.set_disk_storage(false);

        let entries = {
            let _lock = self.lock()?;
            match self.load()? {
                Some(loaded) => loaded.entries,
                None => return Ok(KeyringMove::default()),
            }
        };
        let mut result = KeyringMove::default();
        let mut verified = Vec::new();
        for (k, v) in &entries {
            if result.reason.is_some() {
                result.kept.push(k.clone());
                continue;
            }
            match self.keyring.set(k, v) {
                Ok(()) if self.keyring.get(k).ok().as_ref() == Some(v) => verified.push((k.clone(), v.clone())),
                Ok(()) => {
                    result.kept.push(k.clone());
                }
                Err(e) => {
                    result.reason = Some(e.to_string());
                    result.kept.push(k.clone());
                }
            }
        }
        self.update_fallback(|current| {
            let mut changed = false;
            for (k, v) in &verified {
                if current.get(k) == Some(v) {
                    current.remove(k);
                    result.moved.push(k.clone());
                    changed = true;
                } else {
                    result.kept.push(k.clone());
                }
            }
            changed
        })?;
        result.kept.sort();
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Local store
    // -----------------------------------------------------------------------

    fn undotted_path(&self) -> PathBuf {
        self.fallback_path.with_file_name("credentials_store.json")
    }

    fn lock_path(&self) -> PathBuf {
        let name = self.fallback_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        self.fallback_path.with_file_name(format!("{}.lock", name))
    }

    /// Exclusive lock serializing all writers of this store, across threads
    /// and processes (server, CLI, service). Released when dropped.
    fn lock(&self) -> Result<std::fs::File> {
        let path = self.lock_path();
        if let Some(parent) = path.parent() {
            crate::private_fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        let mut options = crate::private_fs::options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            // Never follow a symlink planted at the lock path
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&path).map_err(|e| io_error(&path, e))?;
        file.lock().map_err(|e| io_error(&path, e))?;
        Ok(file)
    }

    fn get_fallback(&self, key: &str) -> Result<String> {
        // Reads don't need the lock (files are replaced atomically), but a
        // migration does; without a lock (read-only folder) just read.
        let lock = self.lock().ok();
        let Some(loaded) = self.load()? else { return Err(not_found(key)) };
        if loaded.needs_migration && lock.is_some() {
            if let Err(e) = self.save(&loaded.entries, Some(&loaded)) {
                tracing::warn!("Couldn't upgrade the credential store (left unchanged): {}", e);
            }
        }
        loaded.entries.get(key).cloned().ok_or_else(|| not_found(key))
    }

    /// Read-modify-write under the lock. `change` returns whether it changed
    /// anything. Errors reading the store abort before anything is written.
    fn update_fallback(&self, change: impl FnOnce(&mut BTreeMap<String, String>) -> bool) -> Result<()> {
        let _lock = self.lock()?;
        let loaded = self.load()?;
        let mut entries = loaded.as_ref().map(|l| l.entries.clone()).unwrap_or_default();
        let changed = change(&mut entries);
        let migrate = loaded.as_ref().map(|l| l.needs_migration).unwrap_or(false);
        // A key-file store with a passphrase now set is rekeyed on any write
        let rekey = self.passphrase.is_some()
            && loaded.as_ref().and_then(|l| l.current.as_ref()).is_some_and(|k| k.kdf.is_none());
        if !changed && !migrate && !rekey {
            return Ok(());
        }
        self.save(&entries, loaded.as_ref())
    }

    /// Reads and decrypts the store. `Ok(None)` only if there is no store file.
    fn load(&self) -> Result<Option<Loaded>> {
        let path = if exists(&self.fallback_path)? {
            self.fallback_path.clone()
        } else if self.undotted_path() != self.fallback_path && exists(&self.undotted_path())? {
            self.undotted_path()
        } else {
            return Ok(None);
        };
        let data = std::fs::read(&path).map_err(|e| io_error(&path, e))?;
        let value: serde_json::Value = serde_json::from_slice(&data).map_err(|e| {
            corrupt(format!("The credential store {} isn't valid JSON ({}). It was left unchanged.", path.display(), e))
        })?;
        let in_place = path == self.fallback_path;

        let Some(object) = value.as_object() else {
            return Err(corrupt(format!("The credential store {} has an unknown format. It was left unchanged.", path.display())));
        };
        if object.contains_key("version") {
            let file: StoreFile = serde_json::from_value(value.clone()).map_err(|e| {
                corrupt(format!("The credential store {} is damaged ({}). It was left unchanged.", path.display(), e))
            })?;
            if file.version != STORE_VERSION {
                return Err(corrupt(format!(
                    "The credential store {} has version {}, which this version of MailBackup can't read. It was left unchanged.",
                    path.display(),
                    file.version
                )));
            }
            let store_key = self.key_for_v2(&file, &path)?;
            let entries = decrypt_v2(&file, &store_key.key, &path)?;
            Ok(Some(Loaded { entries, current: Some(store_key), legacy_path: (!in_place).then_some(path), needs_migration: !in_place }))
        } else if object.values().all(|v| v.is_string()) {
            let map: BTreeMap<String, String> =
                object.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect();
            let entries = self.decrypt_legacy(&map, &path)?;
            Ok(Some(Loaded { entries, current: None, legacy_path: Some(path), needs_migration: true }))
        } else {
            Err(corrupt(format!("The credential store {} has an unknown format. It was left unchanged.", path.display())))
        }
    }

    /// The key a version 2 store says it uses: the passphrase (when `kdf` is
    /// set) or the key file / keyring key. No legacy keys.
    fn key_for_v2(&self, file: &StoreFile, path: &Path) -> Result<StoreKey> {
        if let Some(kdf) = &file.kdf {
            let salt = kdf.validate()?;
            let passphrase = self.passphrase.as_deref().ok_or_else(|| {
                Error::credential(
                    Kind::NoKey,
                    format!(
                        "The credential store {} is protected by a passphrase. Set MAILBACKUP_MASTER_KEY to read it.",
                        path.display()
                    ),
                )
            })?;
            let key = self.derive(passphrase, kdf, &salt)?;
            if decrypt_secret(&file.check, &key).ok().as_deref() != Some(CHECK_VALUE) {
                return Err(Error::credential(
                    Kind::WrongKey,
                    format!("The passphrase doesn't unlock the credential store {}. It was left unchanged.", path.display()),
                ));
            }
            return Ok(StoreKey { key, kdf: Some(kdf.clone()) });
        }

        let (candidates, blocker) = self.file_key_candidates();
        if let Some(key) = candidates.into_iter().find(|k| decrypt_secret(&file.check, k).ok().as_deref() == Some(CHECK_VALUE)) {
            return Ok(StoreKey { key, kdf: None });
        }
        Err(blocker.unwrap_or_else(|| {
            Error::credential(
                Kind::WrongKey,
                format!(
                    "The credential store {} doesn't decrypt with the key in {} or the OS keyring. It was left unchanged.",
                    path.display(),
                    self.key_path.display()
                ),
            )
        }))
    }

    /// Decrypts a legacy flat map. Encrypted values are tried with the current
    /// keys and then, read-only, with the keys older versions derived: the
    /// passphrase's plain SHA-256 and the key-file path.
    fn decrypt_legacy(&self, map: &BTreeMap<String, String>, path: &Path) -> Result<BTreeMap<String, String>> {
        let Some((_, sample)) = map.iter().find(|(_, v)| v.starts_with(ENC_PREFIX)) else {
            return Ok(map.clone()); // plaintext only
        };
        let (mut candidates, blocker) = self.file_key_candidates();
        if let Some(passphrase) = &self.passphrase {
            candidates.push(legacy_passphrase_key(passphrase));
        }
        candidates.push(legacy_path_key(&self.key_path));
        let key = candidates.into_iter().find(|k| decrypt_secret(sample, k).is_ok()).ok_or_else(|| {
            blocker.unwrap_or_else(|| {
                Error::credential(
                    Kind::WrongKey,
                    format!("The credential store {} doesn't decrypt with any known key. It was left unchanged.", path.display()),
                )
            })
        })?;
        map.iter()
            .map(|(k, v)| {
                let plain = if v.starts_with(ENC_PREFIX) {
                    decrypt_secret(v, &key).map_err(|_| {
                        corrupt(format!("The entry '{}' in {} is damaged. The store was left unchanged.", k, path.display()))
                    })?
                } else {
                    v.clone()
                };
                Ok((k.clone(), plain))
            })
            .collect()
    }

    /// Writes `entries` as a version 2 store, replacing the file only after the
    /// new content has been read back and verified. A legacy file is removed
    /// only after that.
    fn save(&self, entries: &BTreeMap<String, String>, loaded: Option<&Loaded>) -> Result<()> {
        let store_key = self.key_for_writing(loaded)?;
        let file = StoreFile {
            version: STORE_VERSION,
            kdf: store_key.kdf.clone(),
            check: encrypt_secret(CHECK_VALUE, &store_key.key)?,
            entries: entries
                .iter()
                .map(|(k, v)| Ok((k.clone(), encrypt_secret(v, &store_key.key)?)))
                .collect::<Result<_>>()?,
        };
        let data = serde_json::to_vec_pretty(&file).map_err(|e| Error::Serialization(e.to_string()))?;

        let path = &self.fallback_path;
        if let Some(parent) = path.parent() {
            crate::private_fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        // Temp files of an interrupted write; we hold the writers' lock
        for stale in crate::private_fs::stale_temp_files(path) {
            let _ = std::fs::remove_file(stale);
        }
        crate::private_fs::write_atomic_verified(path, &data, |temp| {
            let written: StoreFile = serde_json::from_slice(&std::fs::read(temp)?)
                .map_err(|e| std::io::Error::other(format!("written store doesn't parse: {}", e)))?;
            match decrypt_v2(&written, &store_key.key, temp) {
                Ok(read_back) if &read_back == entries => Ok(()),
                _ => Err(std::io::Error::other("written store doesn't read back")),
            }
        })
        .map_err(|e| io_error(path, e))?;

        if let Some(legacy) = loaded.and_then(|l| l.legacy_path.as_ref()) {
            if legacy != path {
                let _ = std::fs::remove_file(legacy);
            }
        }
        Ok(())
    }

    /// The key a save uses: the passphrase if one is set (keeping the salt of a
    /// store already protected by it), else the key file / keyring key, created
    /// if there is none. Never a legacy key.
    fn key_for_writing(&self, loaded: Option<&Loaded>) -> Result<StoreKey> {
        let current = loaded.and_then(|l| l.current.as_ref());
        match &self.passphrase {
            Some(passphrase) => {
                if let Some(current @ StoreKey { kdf: Some(_), .. }) = current {
                    return Ok(current.clone());
                }
                let kdf = KdfParams::generate();
                let salt = kdf.validate()?;
                let key = self.derive(passphrase, &kdf, &salt)?;
                Ok(StoreKey { key, kdf: Some(kdf) })
            }
            None => {
                if let Some(current @ StoreKey { kdf: None, .. }) = current {
                    return Ok(current.clone());
                }
                Ok(StoreKey { key: self.file_key_for_writing()?, kdf: None })
            }
        }
    }

    /// Keys from the keyring and the key file, plus the error that kept one of
    /// them from being read (locked keyring, unreadable or damaged key file).
    fn file_key_candidates(&self) -> (Vec<[u8; 32]>, Option<Error>) {
        let mut keys = Vec::new();
        let mut blocker = None;
        match read_key_file(&self.key_path) {
            Ok(Some(key)) => keys.push(key),
            Ok(None) => {}
            Err(e) => blocker = Some(e),
        }
        match self.keyring.get(MASTER_KEY_ENTRY) {
            Ok(hex_key) => match parse_key(&hex_key) {
                Some(key) if !keys.contains(&key) => keys.push(key),
                Some(_) => {}
                None => {
                    blocker.get_or_insert_with(|| corrupt("The credential key in the OS keyring is damaged.".to_string()));
                }
            },
            Err(e) if e.credential_kind() == Some(Kind::Locked) => {
                blocker.get_or_insert(e);
            }
            Err(_) => {}
        }
        if keys.is_empty() && blocker.is_none() {
            blocker = Some(Error::credential(
                Kind::NoKey,
                format!("The credential key file {} is missing.", self.key_path.display()),
            ));
        }
        (keys, blocker)
    }

    /// The key file's key; if there's none, the keyring's (copied to the key
    /// file so the background service can read it), else a new random key.
    /// A key file that exists but can't be read is an error, never replaced.
    fn file_key_for_writing(&self) -> Result<[u8; 32]> {
        if let Some(key) = read_key_file(&self.key_path)? {
            return Ok(key);
        }
        let from_keyring = self.keyring.get(MASTER_KEY_ENTRY).ok().and_then(|hex_key| parse_key(&hex_key));
        let key = from_keyring.unwrap_or_else(|| {
            let generated = Aes256Gcm::generate_key(&mut OsRng);
            let mut key = [0u8; 32];
            key.copy_from_slice(generated.as_slice());
            key
        });
        if let Some(parent) = self.key_path.parent() {
            crate::private_fs::create_dir_all(parent).map_err(|e| key_file_error(&self.key_path, e))?;
        }
        match crate::private_fs::create_new_atomic(&self.key_path, hex::encode(key).as_bytes()) {
            Ok(()) => {}
            // Someone else created it first: use theirs
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return read_key_file(&self.key_path)?.ok_or_else(|| {
                    Error::credential(Kind::Unavailable, format!("The credential key file {} vanished.", self.key_path.display()))
                });
            }
            Err(e) => return Err(key_file_error(&self.key_path, e)),
        }
        if from_keyring.is_none() {
            let _ = self.keyring.set(MASTER_KEY_ENTRY, &hex::encode(key));
        }
        Ok(key)
    }

    /// Argon2id key for `passphrase`, cached for the last parameter set.
    fn derive(&self, passphrase: &str, kdf: &KdfParams, salt: &[u8]) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let fingerprint: [u8; 32] = Sha256::new()
            .chain_update(passphrase.as_bytes())
            .chain_update([0u8])
            .chain_update(serde_json::to_vec(kdf).unwrap_or_default())
            .finalize()
            .into();
        if let Some((cached, key)) = *self.derived.lock().unwrap() {
            if cached == fingerprint {
                return Ok(key);
            }
        }
        let params = argon2::Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
            .map_err(|e| corrupt(format!("Invalid key derivation parameters: {}", e)))?;
        let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| Error::credential(Kind::Unavailable, format!("Key derivation failed: {}", e)))?;
        *self.derived.lock().unwrap() = Some((fingerprint, key));
        Ok(key)
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The store as read: plaintext entries and how to write it back.
struct Loaded {
    entries: BTreeMap<String, String>,
    /// The key the file on disk uses (`None` for legacy formats).
    current: Option<StoreKey>,
    /// The file read, when it isn't a version 2 store at the current path.
    legacy_path: Option<PathBuf>,
    needs_migration: bool,
}

#[derive(Clone)]
struct StoreKey {
    key: [u8; 32],
    kdf: Option<KdfParams>,
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    kdf: Option<KdfParams>,
    check: String,
    entries: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct KdfParams {
    alg: String,
    version: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

impl KdfParams {
    fn generate() -> Self {
        use aes_gcm::aead::rand_core::RngCore;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            alg: "argon2id".to_string(),
            version: 0x13,
            m_cost: ARGON2_M_COST_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            salt: hex::encode(salt),
        }
    }

    /// Checks the parameters against fixed limits (so a tampered store can't
    /// make us allocate gigabytes) and returns the salt.
    fn validate(&self) -> Result<Vec<u8>> {
        let bad = |what: &str| corrupt(format!("The credential store's key derivation settings are invalid ({}).", what));
        if self.alg != "argon2id" {
            return Err(bad("algorithm"));
        }
        if self.version != 0x13 {
            return Err(bad("Argon2 version"));
        }
        if !(1..=ARGON2_MAX_P_COST).contains(&self.p_cost) {
            return Err(bad("parallelism"));
        }
        if !(1..=ARGON2_MAX_T_COST).contains(&self.t_cost) {
            return Err(bad("iterations"));
        }
        if !(8 * self.p_cost..=ARGON2_MAX_M_COST_KIB).contains(&self.m_cost) {
            return Err(bad("memory"));
        }
        let salt = hex::decode(&self.salt).map_err(|_| bad("salt"))?;
        if !SALT_LEN_RANGE.contains(&salt.len()) {
            return Err(bad("salt length"));
        }
        Ok(salt)
    }
}

fn decrypt_v2(file: &StoreFile, key: &[u8; 32], path: &Path) -> Result<BTreeMap<String, String>> {
    if decrypt_secret(&file.check, key).ok().as_deref() != Some(CHECK_VALUE) {
        return Err(Error::credential(Kind::WrongKey, format!("The credential store {} doesn't decrypt with its key.", path.display())));
    }
    file.entries
        .iter()
        .map(|(k, v)| {
            if !v.starts_with(ENC_PREFIX) {
                return Err(corrupt(format!("The entry '{}' in {} isn't encrypted. The store was left unchanged.", k, path.display())));
            }
            let plain = decrypt_secret(v, key).map_err(|_| {
                corrupt(format!("The entry '{}' in {} is damaged. The store was left unchanged.", k, path.display()))
            })?;
            Ok((k.clone(), plain))
        })
        .collect()
}

/// `path` with its deepest existing ancestor resolved to the real path and the
/// missing rest appended, so a folder that doesn't exist yet resolves the same
/// way it will once created (`/var` vs `/private/var` on macOS).
fn resolve_existing_prefix(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&current) {
            return rest.iter().rev().fold(real, |acc: PathBuf, name: &std::ffi::OsString| acc.join(name));
        }
        match (current.file_name().map(|n| n.to_os_string()), current.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                current = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Removes `.` and resolves `..` without touching the file system.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn passphrase_from_env() -> Option<String> {
    PASSPHRASE_VARS
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

/// How versions before 0.2.20 turned the passphrase into a key (unsalted
/// SHA-256). Only used to read their stores.
fn legacy_passphrase_key(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(passphrase.trim().as_bytes()).into()
}

/// The key versions before 0.2.20 used when no key could be saved, derived
/// from the key file's path alone. Only used to read their stores.
fn legacy_path_key(key_path: &Path) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"mailbackup:fallback:seed:");
    hasher.update(key_path.to_string_lossy().as_bytes());
    hasher.finalize().into()
}

fn parse_key(hex_key: &str) -> Option<[u8; 32]> {
    hex::decode(hex_key.trim()).ok().and_then(|bytes| bytes.try_into().ok())
}

/// `Ok(None)` if there's no key file; an error if it can't be read or isn't a key.
fn read_key_file(path: &Path) -> Result<Option<[u8; 32]>> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_key(&content).map(Some).ok_or_else(|| {
            corrupt(format!("The credential key file {} is damaged. It was left unchanged.", path.display()))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(key_file_error(path, e)),
    }
}

fn exists(path: &Path) -> Result<bool> {
    path.try_exists().map_err(|e| io_error(path, e))
}

fn not_found(key: &str) -> Error {
    Error::credential(Kind::NotFound, format!("Secret not found for key '{}'", key))
}

fn corrupt(message: String) -> Error {
    Error::credential(Kind::Corrupt, message)
}

fn io_error(path: &Path, e: std::io::Error) -> Error {
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound => Kind::NotFound,
        std::io::ErrorKind::PermissionDenied => Kind::PermissionDenied,
        _ => Kind::Unavailable,
    };
    Error::credential(kind, format!("Credential store {}: {}", path.display(), e))
}

fn key_file_error(path: &Path, e: std::io::Error) -> Error {
    let kind = if e.kind() == std::io::ErrorKind::PermissionDenied { Kind::PermissionDenied } else { Kind::Unavailable };
    Error::credential(kind, format!("Can't use the credential key file {}: {}", path.display(), e))
}

fn binding_key(account_id: &str) -> String {
    format!("account:{}:binding", account_id)
}

/// Fingerprint of the connection a password belongs to: SHA-256 over the
/// server (trimmed, lowercase), port and username (trimmed).
pub fn connection_binding(account: &AccountConfig) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(account.imap_server.trim().to_lowercase().as_bytes());
    hasher.update([0u8]);
    hasher.update(account.imap_port.to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(account.username.trim().as_bytes());
    hex::encode(hasher.finalize())
}

fn encrypt_secret(secret: &str, master_key: &[u8; 32]) -> Result<String> {
    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .map_err(|e| Error::Keyring(format!("Encryption error: {}", e)))?;

    Ok(format!("{}{}:{}", ENC_PREFIX, hex::encode(nonce), hex::encode(ciphertext)))
}

fn decrypt_secret(encoded: &str, master_key: &[u8; 32]) -> Result<String> {
    let payload = encoded
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| Error::Keyring("Not an encrypted credential".to_string()))?;
    let (nonce_hex, ciphertext_hex) = payload
        .split_once(':')
        .ok_or_else(|| Error::Keyring("Malformed encrypted credential format".to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| Error::Keyring(format!("Invalid nonce hex: {}", e)))?;
    let ciphertext_bytes =
        hex::decode(ciphertext_hex).map_err(|e| Error::Keyring(format!("Invalid ciphertext hex: {}", e)))?;
    if nonce_bytes.len() != 12 {
        return Err(Error::Keyring("Invalid nonce length for AES-GCM".to_string()));
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
    let decrypted_bytes = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext_bytes.as_ref())
        .map_err(|e| Error::Keyring(format!("Decryption failed: {}", e)))?;

    String::from_utf8(decrypted_bytes).map_err(|e| Error::Keyring(format!("Corrupted UTF-8 secret: {}", e)))
}

#[cfg(test)]
mod tests;
