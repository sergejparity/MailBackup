use crate::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SERVICE_NAME: &str = "mailbackup";
const ENC_PREFIX: &str = "enc:v1:";

pub struct CredentialStore {
    fallback_path: PathBuf,
    key_path: PathBuf,
}

impl CredentialStore {
    pub fn new() -> Self {
        let base_dir = crate::config::default_base_dir();
        let fallback_path = base_dir.join(".credentials_store.json");
        let key_path = base_dir.join(".credentials_key");
        Self {
            fallback_path,
            key_path,
        }
    }

    pub fn with_fallback_path(fallback_path: PathBuf) -> Self {
        let key_path = fallback_path.with_extension("key");
        Self {
            fallback_path,
            key_path,
        }
    }

    pub fn with_paths(fallback_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            fallback_path,
            key_path,
        }
    }

    pub fn set_password(&self, account_id: &str, secret: &str) -> Result<()> {
        let key = format!("account:{}", account_id);

        // Persist to encrypted local fallback store
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

        // Try encrypted fallback store
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

    pub fn get_master_key(&self) -> [u8; 32] {
        resolve_or_init_master_key(&self.key_path)
    }

    fn get_active_store_path(&self) -> PathBuf {
        if self.fallback_path.exists() {
            return self.fallback_path.clone();
        }
        let undotted = self.fallback_path.with_file_name("credentials_store.json");
        if undotted.exists() {
            return undotted;
        }
        self.fallback_path.clone()
    }

    fn read_decrypted_map(&self) -> (HashMap<String, String>, bool) {
        let path = self.get_active_store_path();
        if !path.exists() {
            return (HashMap::new(), false);
        }

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => return (HashMap::new(), false),
        };

        let raw_map: HashMap<String, String> = match serde_json::from_slice(&data) {
            Ok(m) => m,
            Err(_) => return (HashMap::new(), false),
        };

        let master_key = self.get_master_key();
        let mut decrypted_map = HashMap::new();
        let mut had_plaintext = false;

        for (k, v) in raw_map {
            if !v.starts_with(ENC_PREFIX) {
                // Detected legacy plain text
                had_plaintext = true;
                decrypted_map.insert(k, v);
            } else {
                match decrypt_secret(&v, &master_key) {
                    Ok(plain) => {
                        decrypted_map.insert(k, plain);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to decrypt credential for key '{}': {}", k, e);
                    }
                }
            }
        }

        let is_undotted = path.file_name() != self.fallback_path.file_name();
        let needs_migration = had_plaintext || is_undotted;

        (decrypted_map, needs_migration)
    }

    fn write_encrypted_map(&self, map: &HashMap<String, String>) -> Result<()> {
        if let Some(parent) = self.fallback_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let master_key = self.get_master_key();
        let mut encrypted_map = HashMap::new();

        for (k, v) in map {
            let enc_val = encrypt_secret(v, &master_key)?;
            encrypted_map.insert(k.clone(), enc_val);
        }

        let data = serde_json::to_vec_pretty(&encrypted_map)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        std::fs::write(&self.fallback_path, data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.fallback_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }

        Ok(())
    }

    fn set_fallback(&self, key: &str, secret: &str) -> Result<()> {
        let (mut map, _) = self.read_decrypted_map();
        map.insert(key.to_string(), secret.to_string());
        self.write_encrypted_map(&map)?;

        // If legacy undotted file exists and differs from fallback_path, remove it
        let undotted = self.fallback_path.with_file_name("credentials_store.json");
        if undotted.exists() && undotted != self.fallback_path {
            let _ = std::fs::remove_file(undotted);
        }

        Ok(())
    }

    fn get_fallback(&self, key: &str) -> Result<String> {
        let (map, needs_migration) = self.read_decrypted_map();
        if needs_migration {
            let _ = self.write_encrypted_map(&map);
            let undotted = self.fallback_path.with_file_name("credentials_store.json");
            if undotted.exists() && undotted != self.fallback_path {
                let _ = std::fs::remove_file(undotted);
            }
        }

        map.get(key)
            .cloned()
            .ok_or_else(|| Error::Keyring(format!("Secret not found for key '{}'", key)))
    }

    fn delete_fallback(&self, key: &str) -> Result<()> {
        let (mut map, _) = self.read_decrypted_map();
        map.remove(key);
        self.write_encrypted_map(&map)?;

        let undotted = self.fallback_path.with_file_name("credentials_store.json");
        if undotted.exists() && undotted != self.fallback_path {
            let _ = std::fs::remove_file(undotted);
        }

        Ok(())
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

fn encrypt_secret(secret: &str, master_key: &[u8; 32]) -> Result<String> {
    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .map_err(|e| Error::Keyring(format!("Encryption error: {}", e)))?;

    Ok(format!(
        "{}{}:{}",
        ENC_PREFIX,
        hex::encode(nonce),
        hex::encode(ciphertext)
    ))
}

fn decrypt_secret(encoded: &str, master_key: &[u8; 32]) -> Result<String> {
    if !encoded.starts_with(ENC_PREFIX) {
        return Ok(encoded.to_string());
    }

    let payload = &encoded[ENC_PREFIX.len()..];
    let parts: Vec<&str> = payload.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(Error::Keyring(
            "Malformed encrypted credential format".to_string(),
        ));
    }

    let nonce_bytes =
        hex::decode(parts[0]).map_err(|e| Error::Keyring(format!("Invalid nonce hex: {}", e)))?;
    let ciphertext_bytes = hex::decode(parts[1])
        .map_err(|e| Error::Keyring(format!("Invalid ciphertext hex: {}", e)))?;

    if nonce_bytes.len() != 12 {
        return Err(Error::Keyring("Invalid nonce length for AES-GCM".to_string()));
    }

    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|e| Error::Keyring(format!("Decryption failed: {}", e)))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| Error::Keyring(format!("Corrupted UTF-8 secret: {}", e)))
}

fn resolve_or_init_master_key(key_file_path: &Path) -> [u8; 32] {
    // 1. Environment variable override
    if let Ok(env_key) = std::env::var("MAILBACKUP_MASTER_KEY")
        .or_else(|_| std::env::var("MAILBACKUP_ENCRYPTION_KEY"))
    {
        if !env_key.trim().is_empty() {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(env_key.trim().as_bytes());
            return hasher.finalize().into();
        }
    }

    // 2. OS Keyring entry for master key
    if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, "master_encryption_key") {
        if let Ok(saved_hex) = entry.get_password() {
            if let Ok(bytes) = hex::decode(saved_hex.trim()) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return key;
                }
            }
        }
    }

    // 3. Key file on disk (e.g. .credentials_key)
    if key_file_path.exists() {
        if let Ok(content) = std::fs::read_to_string(key_file_path) {
            let trimmed = content.trim();
            if let Ok(bytes) = hex::decode(trimmed) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return key;
                }
            }
        }
    }

    // 4. Generate a new cryptographically secure 256-bit key
    let generated = Aes256Gcm::generate_key(&mut OsRng);
    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(generated.as_slice());
    let hex_key = hex::encode(new_key);

    // Save to OS keyring if accessible
    if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, "master_encryption_key") {
        let _ = entry.set_password(&hex_key);
    }

    // Save to key file
    if let Some(parent) = key_file_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(()) = std::fs::write(key_file_path, &hex_key) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(key_file_path, std::fs::Permissions::from_mode(0o600));
        }
        return new_key;
    }

    // 5. Deterministic fallback seed if disk is read-only
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"mailbackup:fallback:seed:");
    hasher.update(key_file_path.to_string_lossy().as_bytes());
    hasher.finalize().into()
}
