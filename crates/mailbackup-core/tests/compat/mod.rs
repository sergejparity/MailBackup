//! Shared by the compatibility fixture tests (issue #40) and their one-time
//! generator: where the fixtures live, the synthetic accounts and secrets they
//! hold, and small helpers.
//!
//! Everything here is synthetic. No real passwords, keys or mail.
#![allow(dead_code)]

pub mod catalog;

use mailbackup_core::config::{AccountConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::error::{CredentialErrorKind as Kind, Error, Result};
use mailbackup_core::keyring::SecretBackend;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Root of the committed fixtures. Written once by `generate_compat_fixtures`
/// with the pre-upgrade code; tests only ever read (copies of) them.
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("compat")
}

pub const PASSPHRASE: &str = "synthetic fixture passphrase";
pub const IDENTITY: &str = "imap.example.test:993:live@example.test";

/// An account as the config holds it; only what the credential store and
/// the catalog look at matters.
pub fn account(id: &str, server: &str, username: &str, credential_ref: Option<&str>) -> AccountConfig {
    AccountConfig {
        id: id.to_string(),
        name: format!("Fixture {}", id),
        email: format!("{}@example.test", id),
        provider: ProviderType::GenericImap,
        imap_server: server.to_string(),
        imap_port: 993,
        use_tls: true,
        auth_type: AuthType::Password,
        username: username.to_string(),
        schedule: None,
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
        storage_namespace: None,
        credential_ref: credential_ref.map(str::to_string),
        archive: None,
        trust_server_ids: false,
    }
}

/// The live account (its password is stored under its id).
pub fn live_account() -> AccountConfig {
    account("acct-live", "imap.example.test", "live@example.test", None)
}

/// The live account after "start a new archive" staged a new password for a
/// new server under `<id>~cred-<seq>` (see `archive::start_new_archive_with`).
pub fn staged_account() -> AccountConfig {
    account("acct-live", "new.example.test", "live@new.example.test", Some("acct-live~cred-1"))
}

/// Saved before connection bindings existed: a password, no binding.
pub const PRE_BINDING_ID: &str = "acct-old";
pub const LIVE_PW: &str = "synthetic-live-password";
pub const STAGED_PW: &str = "synthetic-staged-password";
pub const PRE_BINDING_PW: &str = "synthetic-pre-binding-password";
/// Held only by the legacy (`~/.mailbackup`) location and adopted from there.
pub const ADOPTED_ID: &str = "acct-adopted";
pub const ADOPTED_PW: &str = "synthetic-adopted-password";
/// Held by the legacy location, deleted by this config: must stay deleted.
pub const DELETED_ID: &str = "acct-deleted";
pub const DELETED_PW: &str = "synthetic-deleted-password";
/// Kept in the OS keyring (keyring scenario).
pub const KEYRING_ID: &str = "acct-keyring";
pub const KEYRING_PW: &str = "synthetic-keyring-password";

/// In-memory keyring; one instance survives "restarts" of the stores built
/// with it.
#[derive(Default)]
pub struct MemoryKeyring(pub Mutex<HashMap<String, String>>);

impl MemoryKeyring {
    pub fn with(entries: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(Mutex::new(entries.into_iter().collect()))
    }
    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.0.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl SecretBackend for MemoryKeyring {
    fn get(&self, key: &str) -> Result<String> {
        self.0.lock().unwrap().get(key).cloned().ok_or_else(|| Error::credential(Kind::NotFound, "no entry"))
    }
    fn set(&self, key: &str, secret: &str) -> Result<()> {
        self.0.lock().unwrap().insert(key.to_string(), secret.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key).map(|_| ()).ok_or_else(|| Error::credential(Kind::NotFound, "no entry"))
    }
}

/// A keyring that fails every call with `kind` (locked, unavailable, …).
pub struct FailingKeyring(pub Kind);

impl SecretBackend for FailingKeyring {
    fn get(&self, _: &str) -> Result<String> {
        Err(Error::credential(self.0, "synthetic keyring failure"))
    }
    fn set(&self, _: &str, _: &str) -> Result<()> {
        Err(Error::credential(self.0, "synthetic keyring failure"))
    }
    fn delete(&self, _: &str) -> Result<()> {
        Err(Error::credential(self.0, "synthetic keyring failure"))
    }
}

/// Copies `from` (recursively) into a fresh temp dir and returns it, so a
/// test never touches the committed fixture.
pub fn copy_fixture(from: &Path) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_dir(from, dir.path());
    dir
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap_or_else(|e| panic!("fixture {} missing: {}", from.display(), e)) {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Every file under `dir` with its bytes, to show a failed operation left
/// everything as it was.
pub fn snapshot_files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(base, &path, out);
            } else {
                out.insert(path.strip_prefix(base).unwrap().to_path_buf(), std::fs::read(&path).unwrap());
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

/// Like [`snapshot_files`], without the writers' lock file: opening it is
/// how every reader starts, and it never holds data.
pub fn snapshot_data_files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    snapshot_files(dir)
        .into_iter()
        .filter(|(p, _)| !p.to_string_lossy().ends_with(".lock"))
        .collect()
}

pub fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e))).unwrap()
}

pub fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
