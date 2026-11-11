//! Marks a saved file as downloaded from the internet (issue #75), the way
//! browsers do, so the operating system's protections apply when it is
//! opened: Windows SmartScreen and Office Protected View read the
//! `Zone.Identifier` stream, macOS Gatekeeper the `com.apple.quarantine`
//! attribute. Attachments come from whoever sent the mail.

use std::io;
use std::path::Path;

/// What marking did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mark {
    Marked,
    /// The file system can't carry the mark (e.g. FAT, some network shares);
    /// expected, not an error.
    Unsupported(String),
    /// This platform has no such mark.
    NotApplicable,
}

/// Marks `path` (an existing, complete file). An error is a failure the
/// caller should report; an unsupported file system is not one.
pub fn mark_from_internet(path: &Path) -> io::Result<Mark> {
    #[cfg(windows)]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        match std::fs::write(std::path::PathBuf::from(stream), "[ZoneTransfer]\r\nZoneId=3\r\n") {
            Ok(()) => Ok(Mark::Marked),
            // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER,
            // ERROR_INVALID_NAME: no alternate data streams on this volume
            Err(e) if matches!(e.raw_os_error(), Some(1 | 50 | 87 | 123)) => Ok(Mark::Unsupported(e.to_string())),
            Err(e) => Err(e),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let xattr = crate::service::trusted_program("xattr").map_err(io::Error::other)?;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        // flags;time;agent; as Safari writes it (0083: downloaded, user-approved off)
        let value = format!("0083;{:x};MailBackup;", secs);
        let out = std::process::Command::new(xattr)
            .args(["-w", "com.apple.quarantine", &value])
            .arg(path)
            .output()?;
        if out.status.success() {
            return Ok(Mark::Marked);
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if stderr.to_ascii_lowercase().contains("not supported") {
            Ok(Mark::Unsupported(stderr.trim().to_string()))
        } else {
            Err(io::Error::other(format!("xattr failed: {}", stderr.trim())))
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = path;
        Ok(Mark::NotApplicable)
    }
}

/// Whether a download of `url_path` is mail content (an attachment or a
/// whole message) that gets the mark; exports and logs are the user's own.
pub fn is_mail_content(url_path: &str) -> bool {
    url_path.starts_with("/api/messages/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mail_content_is_marked() {
        assert!(is_mail_content("/api/messages/abc/attachments/0"));
        assert!(is_mail_content("/api/messages/abc/download"));
        assert!(!is_mail_content("/api/export/mbox/download"));
        assert!(!is_mail_content("/api/logs/download"));
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn other_platforms_have_no_mark() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.pdf");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(mark_from_internet(&file).unwrap(), Mark::NotApplicable);
    }
}
