use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    GenericImap,
    Gmail,
    Outlook,
    ICloud,
    Yahoo,
}

impl ProviderType {
    pub fn default_server(&self) -> (&'static str, u16, bool) {
        match self {
            ProviderType::GenericImap => ("imap.example.com", 993, true),
            ProviderType::Gmail => ("imap.gmail.com", 993, true),
            ProviderType::Outlook => ("outlook.office365.com", 993, true),
            ProviderType::ICloud => ("imap.mail.me.com", 993, true),
            ProviderType::Yahoo => ("imap.mail.yahoo.com", 993, true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Password, // Stored in OS Keyring or fallback file
    OAuth2,   // XOAUTH2 with refresh token
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FolderFilter {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Default for FolderFilter {
    fn default() -> Self {
        Self {
            include: vec![],
            exclude: vec![
                "Trash".to_string(),
                "[Gmail]/Trash".to_string(),
                "[Gmail]/Spam".to_string(),
                "Junk".to_string(),
                "Spam".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountConfig {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(default = "default_provider")]
    pub provider: ProviderType,
    pub imap_server: String,
    #[serde(default = "default_port")]
    pub imap_port: u16,
    #[serde(default = "default_true")]
    pub use_tls: bool,
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    pub username: String,
    pub schedule: Option<String>,
    pub retention_days: Option<u32>, // None = retain forever
    #[serde(default)]
    pub folder_filter: FolderFilter,
    #[serde(default = "default_true")]
    pub gmail_smart_labels: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directory under the data dir that new message files of this account go
    /// to; `None` means the account id. A fresh namespace after "start a new
    /// archive" keeps new files apart from the retired archive's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_namespace: Option<String>,
    /// Name the account's password (and its connection binding) is stored
    /// under; `None` means the account id. Switching it at a config commit
    /// lets a new password be staged without touching the old one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Set on read-only archives retired by "start a new archive".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<ArchiveInfo>,
    /// Re-bind archived copies by the server's message ids (EMAILID or
    /// X-GM-MSGID) on same-server re-scans instead of downloading them again
    /// (issue #33). Off by default: it accepts the server's promise that an
    /// id never names other content, instead of verifying every body.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trust_server_ids: bool,
}

/// A read-only archive: the mail an account had archived when it moved to
/// another server and the user chose to start a new archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub archived_at: chrono::DateTime<chrono::Utc>,
    /// The live account it was retired from.
    pub retired_from: String,
    /// The connection (`server:port:username`) the archive's folders were
    /// last synced from, when the catalog recorded one. Nothing is known about
    /// earlier sources, so nothing more is claimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_source: Option<String>,
}

impl AccountConfig {
    pub fn storage_namespace(&self) -> &str {
        self.storage_namespace.as_deref().unwrap_or(&self.id)
    }

    pub fn credential_ref(&self) -> &str {
        self.credential_ref.as_deref().unwrap_or(&self.id)
    }

    /// Read-only archives are never synced, edited (except the name) or
    /// pruned by retention.
    pub fn is_archive(&self) -> bool {
        self.archive.is_some()
    }

    /// Which remote mailbox store this account's UIDs come from: server
    /// (case-insensitive), port and username, normalized the way the API
    /// decides that an account's connection changed.
    pub fn remote_identity(&self) -> String {
        format!("{}:{}:{}", self.imap_server.trim().to_ascii_lowercase(), self.imap_port, self.username.trim())
    }
}

fn default_provider() -> ProviderType {
    ProviderType::GenericImap
}
fn default_port() -> u16 {
    993
}
fn default_true() -> bool {
    true
}
fn default_auth_type() -> AuthType {
    AuthType::Password
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    #[serde(default = "default_schedule")]
    pub default_schedule: String,
    pub default_retention_days: Option<u32>,
    pub max_attachment_size_mb: Option<u64>,
    pub rate_limit_kbps: Option<u64>,
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,
    #[serde(default = "default_server_port")]
    pub web_port: u16,
    /// Interface the web UI / REST API listens on. Loopback by default; set to
    /// "0.0.0.0" only to deliberately expose the API on the local network.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Extra host names (besides IP literals and `localhost`) the web UI may be
    /// reached by, e.g. a reverse proxy's domain. Each entry re-allows that name
    /// past the DNS-rebinding check, so list only names you control.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Folders the user picked in the native folder dialog. Together with the
    /// standard user folders they are the only places the web API may export to
    /// or move the archive/catalog to (see `safe_paths`).
    #[serde(default)]
    pub approved_dirs: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub run_as_service: bool,
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: Option<u32>,
    /// At startup, remove other users' access from MailBackup's existing files
    /// (see `private_fs::tighten_at_startup`). Turn off only for an archive
    /// deliberately shared with a group. New files are always owner-only.
    #[serde(default = "default_true")]
    pub tighten_permissions: bool,
    /// Where the desktop app saves downloads (attachments, .eml, mbox, logs);
    /// `None` is the system Downloads folder. Set through the API only to an
    /// export location (see `safe_paths::PathPolicy::validate_download_dir`).
    /// Like `ask_download_location`, written only when set, so configs that
    /// don't use it are saved exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_dir: Option<PathBuf>,
    /// The desktop app asks where to save each download.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ask_download_location: bool,
    /// The desktop app's web server listens on `bind_address:web_port`, so
    /// the UI and API are reachable from a browser. Off, the desktop app
    /// opens no port and serves its window in-process. Headless/service
    /// mode always listens. Written only when off.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub web_server_enabled: bool,
    /// Limits of IMAP connections (issue #72; see `imap::Limits`). Unset
    /// keeps the default; each is written only when set. Seconds for each
    /// connection step (TCP, TLS, greeting + login), default 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_connect_timeout_secs: Option<u64>,
    /// Seconds without any data before a connection counts as dead, default 120.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_idle_timeout_secs: Option<u64>,
    /// Seconds one command may take, default 60; body fetches also get time
    /// for their size at 4 KB/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_command_timeout_secs: Option<u64>,
    /// Largest message fetched, in MB, default 256. Larger messages are
    /// recorded as not backed up instead of being fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_max_message_mb: Option<u64>,    /// Browsers must log in with the access key before they get the web UI
    /// or API (issue #70). Turning it off restores the old behaviour, where
    /// anyone who can reach the port can use the API. Written only when off.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub require_login: bool,
}

/// Longest any IMAP timeout may be set to.
pub const MAX_IMAP_TIMEOUT_SECS: u64 = 3600;
/// Largest `imap_max_message_mb`: the IMAP library refuses responses over
/// 512 MiB, so a larger message could never be fetched.
pub const MAX_IMAP_MESSAGE_MB: u64 = 500;

impl GlobalSettings {
    /// Refuses limits that would mean "no limit" or nonsense: zero, or more
    /// than [`MAX_IMAP_TIMEOUT_SECS`] / [`MAX_IMAP_MESSAGE_MB`].
    pub fn validate(&self) -> Result<()> {
        let timeouts = [
            ("imap_connect_timeout_secs", self.imap_connect_timeout_secs),
            ("imap_idle_timeout_secs", self.imap_idle_timeout_secs),
            ("imap_command_timeout_secs", self.imap_command_timeout_secs),
        ];
        for (name, value) in timeouts {
            if let Some(v) = value
                && !(1..=MAX_IMAP_TIMEOUT_SECS).contains(&v) {
                return Err(Error::Config(format!(
                    "settings.{} must be between 1 and {} seconds, not {}",
                    name, MAX_IMAP_TIMEOUT_SECS, v
                )));
            }
        }
        if let Some(mb) = self.imap_max_message_mb
            && !(1..=MAX_IMAP_MESSAGE_MB).contains(&mb) {
            return Err(Error::Config(format!(
                "settings.imap_max_message_mb must be between 1 and {}, not {}",
                MAX_IMAP_MESSAGE_MB, mb
            )));
        }
        Ok(())
    }
}

fn is_true(value: &bool) -> bool {
    *value
}

fn default_schedule() -> String {
    "0 0 * * *".to_string() // Daily midnight
}
fn default_server_port() -> u16 {
    8765
}
fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}
fn default_log_retention_days() -> Option<u32> {
    Some(30) // Default 30 days log retention
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            default_schedule: default_schedule(),
            default_retention_days: None,
            max_attachment_size_mb: None,
            rate_limit_kbps: None,
            notifications_enabled: true,
            web_port: default_server_port(),
            bind_address: default_bind_address(),
            allowed_hosts: Vec::new(),
            approved_dirs: Vec::new(),
            close_to_tray: true,
            autostart: false,
            run_as_service: false,
            log_retention_days: default_log_retention_days(),
            tighten_permissions: true,
            download_dir: None,
            ask_download_location: false,
            web_server_enabled: true,
            imap_connect_timeout_secs: None,
            imap_idle_timeout_secs: None,
            imap_command_timeout_secs: None,
            imap_max_message_mb: None,
            require_login: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    #[serde(default)]
    pub settings: GlobalSettings,
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let base_dir = default_base_dir();
        Self {
            data_dir: base_dir.join("data"),
            db_path: base_dir.join("mailbackup.db"),
            settings: GlobalSettings::default(),
            accounts: Vec::new(),
        }
    }
}

pub fn default_base_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".mailbackup")
    } else {
        PathBuf::from(".mailbackup")
    }
}

pub fn default_config_path() -> PathBuf {
    default_base_dir().join("config.yaml")
}

pub fn resolve_path(input: &str) -> PathBuf {
    let trimmed = input.trim();
    if (trimmed.starts_with("~/") || trimmed == "~")
        && let Some(home) = dirs::home_dir() {
        if trimmed == "~" {
            return home;
        } else {
            return home.join(&trimmed[2..]);
        }
    }
    PathBuf::from(trimmed)
}

/// Where the desktop app saves downloads unless `settings.download_dir` says
/// otherwise: the Downloads folder, else the home folder.
pub fn default_download_dir() -> PathBuf {
    dirs::download_dir().or_else(dirs::home_dir).unwrap_or_default()
}

pub fn default_export_dir() -> PathBuf {
    dirs::download_dir()
        .or_else(dirs::document_dir)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| default_base_dir().join("exports"))
}

pub fn resolve_export_path(input: &str) -> PathBuf {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d").to_string();
        return default_export_dir().join(format!("backup_{}.mbox", timestamp));
    }

    let resolved = resolve_path(trimmed);
    if resolved.is_relative() {
        default_export_dir().join(resolved)
    } else {
        resolved
    }
}

pub fn find_available_path(target: &Path) -> PathBuf {
    if !target.exists() {
        return target.to_path_buf();
    }

    let parent = target.parent().unwrap_or_else(|| Path::new(""));
    let stem = target
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("backup");
    let ext = target
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("mbox");

    let mut counter = 1;
    loop {
        let candidate_filename = format!("{} ({}).{}", stem, counter, ext);
        let candidate = if parent.as_os_str().is_empty() {
            PathBuf::from(candidate_filename)
        } else {
            parent.join(candidate_filename)
        };

        if !candidate.exists() || counter > 999 {
            return candidate;
        }
        counter += 1;
    }
}

pub fn system_export_locations() -> Vec<(&'static str, PathBuf)> {
    let mut locs = Vec::new();
    if let Some(p) = dirs::download_dir() {
        locs.push(("Downloads", p));
    }
    if let Some(p) = dirs::document_dir() {
        locs.push(("Documents", p));
    }
    if let Some(p) = dirs::desktop_dir() {
        locs.push(("Desktop", p));
    }
    if let Some(p) = dirs::home_dir() {
        locs.push(("Home", p));
    }
    locs
}

/// The lock every writer of a config file holds, in every process (the
/// server, the desktop app, the CLI and the background service), from reading
/// the file to saving it. A writer that changed a copy read earlier would
/// otherwise save over what another process saved meanwhile (review of #83).
///
/// Not reentrant: code holding it must not call anything that takes it again
/// ([`AppConfig::update`], [`crate::accounts::create`],
/// [`crate::accounts::update_from_row`]).
#[derive(Debug)]
pub struct ConfigLock {
    _gate: crate::sync_gate::SyncGate,
}

/// The name the config lock is held under (a lock file next to the
/// accounts' sync gates). Never an account id: ids contain no `#`.
const CONFIG_LOCK_NAME: &str = "#config#";

impl ConfigLock {
    /// Waits for the lock of the config file at `config_path`. Blocking: use
    /// [`ConfigLock::acquire_async`] from async code.
    pub fn acquire(config_path: &Path) -> Result<ConfigLock> {
        Ok(ConfigLock { _gate: crate::sync_gate::SyncGate::acquire(config_path, CONFIG_LOCK_NAME)? })
    }

    /// [`ConfigLock::acquire`] without blocking the async runtime.
    pub async fn acquire_async(config_path: PathBuf) -> Result<ConfigLock> {
        tokio::task::spawn_blocking(move || ConfigLock::acquire(&config_path))
            .await
            .map_err(|e| Error::Other(format!("config lock task failed: {}", e)))?
    }
}

impl AppConfig {
    /// Replaces `self` with the config file at `path` as it is now, if there
    /// is one. Called under the config lock, so what is then changed and
    /// saved starts from what every other process saved.
    pub fn reload_from(&mut self, path: &Path, _lock: &ConfigLock) -> Result<()> {
        if let Some(on_disk) = Self::load_existing(path)? {
            *self = on_disk;
        }
        Ok(())
    }

    /// Changes the config file at `path` as one step under the config lock:
    /// reads it, applies `change`, checks the settings and saves it. Returns
    /// the saved config (callers keep it as their copy) and `change`'s
    /// result. If `change` or the save fails, the file is left as it was.
    /// With no file yet, `change` starts from the defaults.
    pub fn update<R>(path: &Path, change: impl FnOnce(&mut AppConfig) -> Result<R>) -> Result<(AppConfig, R)> {
        let _lock = ConfigLock::acquire(path)?;
        let mut config = Self::load_existing(path)?.unwrap_or_default();
        let result = change(&mut config)?;
        config.settings.validate().map_err(|e| Error::Config(format!("{}: {}", path.display(), e)))?;
        config.save(path)?;
        Ok((config, result))
    }

    pub fn load_or_create(path: Option<&Path>) -> Result<Self> {
        let config_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_config_path(),
        };

        if !config_path.exists() {
            let default_config = Self::default();
            default_config.save(&config_path)?;
            default_config.ensure_dirs()?;
            return Ok(default_config);
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| Error::Config(format!("Failed to read config file {}: {}", config_path.display(), e)))?;
        let config: AppConfig = serde_norway::from_str(&content)
            .map_err(|e| Error::Serialization(format!("Failed to parse config {}: {}", config_path.display(), e)))?;
        config.settings.validate().map_err(|e| Error::Config(format!("{}: {}", config_path.display(), e)))?;

        config.ensure_dirs()?;
        Ok(config)
    }

    /// The config at `path` as it is on disk, without creating anything;
    /// `None` if there is no config file.
    pub fn load_existing(path: &Path) -> Result<Option<Self>> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Config(format!("Failed to read config file {}: {}", path.display(), e))),
        };
        serde_norway::from_str(&content)
            .map(Some)
            .map_err(|e| Error::Serialization(format!("Failed to parse config {}: {}", path.display(), e)))
    }

    /// Creates the data folder and the catalog's folder (owner-only) if missing,
    /// on first run as well as later ones.
    fn ensure_dirs(&self) -> Result<()> {
        crate::private_fs::create_dir_all(&self.data_dir)?;
        if let Some(parent) = self.db_path.parent() {
            // `create_dir_all` ignores the empty parent of a bare "catalog.db"
            crate::private_fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.exists() {
            crate::private_fs::create_dir_all(parent)?;
        }
        let yaml = serde_norway::to_string(self)
            .map_err(|e| Error::Serialization(format!("Failed to serialize config: {}", e)))?;
        crate::private_fs::write_atomic(path, yaml.as_bytes())?;
        Ok(())
    }

    /// The account with exactly this id.
    pub fn account_by_id(&self, id: &str) -> Option<&AccountConfig> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn account_by_id_mut(&mut self, id: &str) -> Option<&mut AccountConfig> {
        self.accounts.iter_mut().find(|a| a.id == id)
    }

    /// Index of the account named by an id, or else by an email address:
    /// the only live account with it, or else the only account with it. An
    /// id always wins; an address that still names several accounts names
    /// none of them.
    fn position(&self, id_or_email: &str) -> Option<usize> {
        if let Some(i) = self.accounts.iter().position(|a| a.id == id_or_email) {
            return Some(i);
        }
        let only = |live_only: bool| {
            let mut found = self
                .accounts
                .iter()
                .enumerate()
                .filter(|(_, a)| a.email == id_or_email && !(live_only && a.is_archive()));
            match (found.next(), found.next()) {
                (Some((i, _)), None) => Some(i),
                _ => None,
            }
        };
        only(true).or_else(|| only(false))
    }

    /// The account with this id, or else the only account with this email
    /// address (a convenience for the command line; the API uses
    /// [`Self::account_by_id`]).
    pub fn get_account(&self, id_or_email: &str) -> Option<&AccountConfig> {
        self.position(id_or_email).map(|i| &self.accounts[i])
    }

    pub fn get_account_mut(&mut self, id_or_email: &str) -> Option<&mut AccountConfig> {
        self.position(id_or_email).map(|i| &mut self.accounts[i])
    }
}
