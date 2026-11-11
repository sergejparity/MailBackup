//! The access key for browser access to the web UI (issue #70).
//!
//! A random 256-bit key, hex-encoded, kept owner-only next to `config.yaml`
//! (`.web_access_key`). A browser must present it once to log in; the server
//! then gives that browser a session. The file is the key's only home: it is
//! never logged and never put in a URL.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

pub const KEY_FILE: &str = ".web_access_key";
const KEY_HEX_LEN: usize = 64;

/// `<config folder>/.web_access_key`
pub fn key_path(config_dir: &Path) -> PathBuf {
    config_dir.join(KEY_FILE)
}

fn new_key() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| Error::Other(format!("random number generator unavailable: {}", e)))?;
    Ok(hex::encode(bytes))
}

fn valid(key: &str) -> bool {
    key.len() == KEY_HEX_LEN && key.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The key in the file, if there is a valid one.
pub fn read_key(config_dir: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(key_path(config_dir)) {
        Ok(text) => {
            let key = text.trim().to_ascii_lowercase();
            if valid(&key) {
                Ok(Some(key))
            } else {
                Err(Error::Config(format!("{} doesn't hold a valid access key", key_path(config_dir).display())))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The key, created if there is none yet. Two processes starting at once end
/// up with the same key: the file is created exclusively, and the one that
/// loses reads the winner's.
pub fn load_or_create_key(config_dir: &Path) -> Result<String> {
    if let Some(key) = read_key(config_dir)? {
        return Ok(key);
    }
    crate::private_fs::create_dir_all(config_dir)?;
    let key = new_key()?;
    match crate::private_fs::create_new_atomic(&key_path(config_dir), key.as_bytes()) {
        Ok(()) => Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read_key(config_dir)?.ok_or_else(|| Error::Config("the access key file vanished".to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Replaces the key with a new one (atomically, owner-only) and returns it.
/// Servers notice the change on their next request and end every session.
pub fn regenerate_key(config_dir: &Path) -> Result<String> {
    crate::private_fs::create_dir_all(config_dir)?;
    let key = new_key()?;
    crate::private_fs::write_atomic(&key_path(config_dir), key.as_bytes())?;
    Ok(key)
}

/// Compares two keys without leaking where they differ.
pub fn keys_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim().as_bytes(), b.trim().as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase())) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_created_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_key(dir.path()).unwrap(), None);
        let key = load_or_create_key(dir.path()).unwrap();
        assert_eq!(key.len(), 64);
        assert_eq!(load_or_create_key(dir.path()).unwrap(), key);
        let regenerated = regenerate_key(dir.path()).unwrap();
        assert_ne!(regenerated, key);
        assert_eq!(read_key(dir.path()).unwrap().as_deref(), Some(regenerated.as_str()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(key_path(dir.path())).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "owner-only");
        }
    }

    #[test]
    fn concurrent_first_starts_agree_on_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let keys: Vec<String> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || load_or_create_key(&path).unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(keys.iter().all(|k| *k == keys[0]), "{:?}", keys);
    }

    #[test]
    fn a_damaged_key_file_is_an_error_not_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(key_path(dir.path()), "short").unwrap();
        assert!(read_key(dir.path()).is_err());
        assert!(load_or_create_key(dir.path()).is_err());
    }

    #[test]
    fn keys_compare_case_insensitively_and_by_length() {
        assert!(keys_equal("ab", "AB"));
        assert!(!keys_equal("ab", "abc"));
        assert!(!keys_equal("ab", "ac"));
    }
}
