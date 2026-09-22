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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default)]
    pub autostart: bool,
}

fn default_schedule() -> String {
    "0 0 * * *".to_string() // Daily midnight
}
fn default_server_port() -> u16 {
    8765
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
            close_to_tray: true,
            autostart: false,
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
    if trimmed.starts_with("~/") || trimmed == "~" {
        if let Some(home) = dirs::home_dir() {
            if trimmed == "~" {
                return home;
            } else {
                return home.join(&trimmed[2..]);
            }
        }
    }
    PathBuf::from(trimmed)
}

impl AppConfig {
    pub fn load_or_create(path: Option<&Path>) -> Result<Self> {
        let config_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_config_path(),
        };

        if !config_path.exists() {
            let default_config = Self::default();
            default_config.save(&config_path)?;
            return Ok(default_config);
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| Error::Config(format!("Failed to read config file {}: {}", config_path.display(), e)))?;
        let config: AppConfig = serde_yaml::from_str(&content)
            .map_err(|e| Error::Serialization(format!("Failed to parse config {}: {}", config_path.display(), e)))?;

        // Ensure directories exist
        if !config.data_dir.exists() {
            std::fs::create_dir_all(&config.data_dir)?;
        }
        if let Some(parent) = config.db_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| Error::Serialization(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, yaml)?;
        Ok(())
    }

    pub fn get_account(&self, id_or_email: &str) -> Option<&AccountConfig> {
        self.accounts.iter().find(|a| a.id == id_or_email || a.email == id_or_email)
    }

    pub fn get_account_mut(&mut self, id_or_email: &str) -> Option<&mut AccountConfig> {
        self.accounts.iter_mut().find(|a| a.id == id_or_email || a.email == id_or_email)
    }
}
