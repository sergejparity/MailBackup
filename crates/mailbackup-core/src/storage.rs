use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StorageEngine {
    base_dir: Arc<RwLock<PathBuf>>,
}

#[derive(Debug, Clone)]
pub struct StoredMessageInfo {
    pub relative_path: PathBuf,
    pub absolute_path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

impl StorageEngine {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: Arc::new(RwLock::new(base_dir.as_ref().to_path_buf())),
        }
    }

    pub fn base_dir(&self) -> PathBuf {
        self.base_dir.read().unwrap().clone()
    }

    pub fn set_base_dir(&self, new_dir: impl AsRef<Path>) {
        let mut w = self.base_dir.write().unwrap();
        *w = new_dir.as_ref().to_path_buf();
    }

    pub fn get_absolute_path(&self, relative_path: impl AsRef<Path>) -> PathBuf {
        self.base_dir().join(relative_path)
    }

    /// Migrates existing backup data from current base_dir to new_base_dir.
    /// Returns the number of files migrated.
    pub fn migrate_data(&self, new_base_dir: impl AsRef<Path>) -> Result<u64> {
        let old_base = self.base_dir();
        let new_base = new_base_dir.as_ref().to_path_buf();

        if old_base == new_base {
            return Ok(0);
        }

        crate::private_fs::create_dir_all(&new_base)?;

        if !old_base.exists() {
            return Ok(0);
        }

        let mut copied_count = 0u64;

        fn copy_dir_recursive(src: &Path, dst: &Path, copied: &mut u64) -> Result<()> {
            if !dst.exists() {
                crate::private_fs::create_dir_all(dst)?;
            }
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                let file_name = entry.file_name();

                // Skip temporary staging directory
                if file_name == ".staging" {
                    continue;
                }

                let src_path = entry.path();
                let dst_path = dst.join(&file_name);

                if file_type.is_dir() {
                    copy_dir_recursive(&src_path, &dst_path, copied)?;
                } else if file_type.is_file() {
                    crate::private_fs::copy(&src_path, &dst_path)?;
                    *copied += 1;
                }
            }
            Ok(())
        }

        copy_dir_recursive(&old_base, &new_base, &mut copied_count)?;
        Ok(copied_count)
    }

    pub fn sanitize_slug(input: &str) -> String {
        let mut slug = String::new();
        for c in input.chars() {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                slug.push(c);
            } else if (c == '/' || c == '.' || c == ' ') && !slug.ends_with('_') {
                slug.push('_');
            }
        }
        let trimmed = slug.trim_matches('_');
        if trimmed.is_empty() {
            "root".to_string()
        } else {
            trimmed.to_string()
        }
    }

    pub fn compute_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Atomically stores raw EML content to the account's folder directory
    pub fn store_eml(
        &self,
        account_id: &str,
        folder_name: &str,
        uid: u32,
        date: Option<DateTime<Utc>>,
        raw_bytes: &[u8],
    ) -> Result<StoredMessageInfo> {
        self.store_eml_in_generation(account_id, folder_name, uid, 0, date, raw_bytes)
    }

    /// Like [`Self::store_eml`] for a message fetched as `uid` of a folder's
    /// UID `generation`. Later generations put the generation in the file
    /// name: archived copies re-bound to a new UID keep their old file, which
    /// may already carry this UID's name, and two catalog rows must never
    /// share a file (retention deletes each row's file).
    pub fn store_eml_in_generation(
        &self,
        account_id: &str,
        folder_name: &str,
        uid: u32,
        generation: u32,
        date: Option<DateTime<Utc>>,
        raw_bytes: &[u8],
    ) -> Result<StoredMessageInfo> {
        let folder_slug = Self::sanitize_slug(folder_name);
        let date_time = date.unwrap_or_else(Utc::now);
        let year_str = date_time.format("%Y").to_string();
        let month_str = date_time.format("%m").to_string();

        let sha256 = Self::compute_sha256(raw_bytes);
        let size_bytes = raw_bytes.len() as u64;

        // Target file name: <uid>_<sha256_prefix>.eml, or
        // <uid>_g<generation>_<sha256_prefix>.eml after a re-scan
        let file_name = if generation == 0 {
            format!("{}_{}.eml", uid, &sha256[..12])
        } else {
            format!("{}_g{}_{}.eml", uid, generation, &sha256[..12])
        };
        let relative_path = PathBuf::from(account_id)
            .join(&folder_slug)
            .join(&year_str)
            .join(&month_str)
            .join(&file_name);

        let base = self.base_dir();
        let absolute_path = base.join(&relative_path);

        // If target already exists and size matches, verify hash
        if absolute_path.exists() {
            if let Ok(existing_bytes) = std::fs::read(&absolute_path) {
                let existing_hash = Self::compute_sha256(&existing_bytes);
                if existing_hash == sha256 {
                    debug!("File {} already exists and matches checksum", absolute_path.display());
                    return Ok(StoredMessageInfo {
                        relative_path,
                        absolute_path,
                        sha256,
                        size_bytes,
                    });
                }
            }
        }

        // Staging directory for atomic rename
        let staging_dir = base.join(".staging");
        crate::private_fs::create_dir_all(&staging_dir)?;
        let temp_filename = format!("{}.tmp", Uuid::new_v4());
        let temp_path = staging_dir.join(temp_filename);

        // Write to temporary file (owner-only from creation)
        {
            use std::io::Write;
            let mut file = crate::private_fs::options().write(true).create_new(true).open(&temp_path)?;
            file.write_all(raw_bytes)?;
        }

        // Ensure target directory exists
        if let Some(parent) = absolute_path.parent() {
            crate::private_fs::create_dir_all(parent)?;
        }

        // Atomic move
        if let Err(e) = std::fs::rename(&temp_path, &absolute_path) {
            // Fallback for cross-device or permission quirks
            warn!("Failed to rename {} to {}: {}. Attempting copy fallback.", temp_path.display(), absolute_path.display(), e);
            crate::private_fs::copy(&temp_path, &absolute_path)?;
            let _ = std::fs::remove_file(&temp_path);
        }

        Ok(StoredMessageInfo {
            relative_path,
            absolute_path,
            sha256,
            size_bytes,
        })
    }

    pub fn read_eml(&self, relative_path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let path = self.base_dir().join(relative_path);
        std::fs::read(&path).map_err(Error::Io)
    }

    pub fn delete_eml(&self, relative_path: impl AsRef<Path>) -> Result<()> {
        let path = self.base_dir().join(relative_path);
        if path.exists() {
            std::fs::remove_file(&path).map_err(Error::Io)?;
        }
        Ok(())
    }

    pub fn verify_checksum(&self, relative_path: impl AsRef<Path>, expected_sha256: &str) -> Result<bool> {
        let path = self.base_dir().join(relative_path);
        if !path.exists() {
            return Ok(false);
        }
        let bytes = std::fs::read(&path)?;
        let hash = Self::compute_sha256(&bytes);
        Ok(hash.eq_ignore_ascii_case(expected_sha256))
    }
}
