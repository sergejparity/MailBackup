use crate::error::{Error, Result};
use std::path::PathBuf;


const SERVICE_NAME: &str = "mailbackup";

pub struct CredentialStore {
    fallback_path: PathBuf,
}

impl CredentialStore {
    pub fn new() -> Self {
        let fallback_path = crate::config::default_base_dir().join(".credentials_store.json");
        Self { fallback_path }
    }

    pub fn with_fallback_path(fallback_path: PathBuf) -> Self {
        Self { fallback_path }
    }

    pub fn set_password(&self, account_id: &str, secret: &str) -> Result<()> {
        let key = format!("account:{}", account_id);
        
        // Always persist to local fallback store
        self.set_fallback(&key, secret)?;

        // Also persist to OS Keyring if available
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, &key) {
            let _ = entry.set_password(secret);
        }
        Ok(())
    }

    pub fn get_password(&self, account_id: &str) -> Result<String> {
        let key = format!("account:{}", account_id);

        // Try OS Keyring first
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, &key) {
            if let Ok(secret) = entry.get_password() {
                return Ok(secret);
            }
        }

        // Try fallback store
        self.get_fallback(&key)
    }

    pub fn delete_password(&self, account_id: &str) -> Result<()> {
        let key = format!("account:{}", account_id);
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, &key) {
            let _ = entry.delete_credential();
        }
        let _ = self.delete_fallback(&key);
        Ok(())
    }

    fn read_fallback_map(&self) -> std::collections::HashMap<String, String> {
        if !self.fallback_path.exists() {
            return std::collections::HashMap::new();
        }
        if let Ok(data) = std::fs::read(&self.fallback_path) {
            if let Ok(map) = serde_json::from_slice(&data) {
                return map;
            }
        }
        std::collections::HashMap::new()
    }

    fn write_fallback_map(&self, map: &std::collections::HashMap<String, String>) -> Result<()> {
        if let Some(parent) = self.fallback_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = serde_json::to_vec_pretty(map)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        std::fs::write(&self.fallback_path, data)?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.fallback_path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    fn set_fallback(&self, key: &str, secret: &str) -> Result<()> {
        let mut map = self.read_fallback_map();
        map.insert(key.to_string(), secret.to_string());
        self.write_fallback_map(&map)
    }

    fn get_fallback(&self, key: &str) -> Result<String> {
        let map = self.read_fallback_map();
        map.get(key)
            .cloned()
            .ok_or_else(|| Error::Keyring(format!("Secret not found for key '{}'", key)))
    }

    fn delete_fallback(&self, key: &str) -> Result<()> {
        let mut map = self.read_fallback_map();
        map.remove(key);
        self.write_fallback_map(&map)
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}
