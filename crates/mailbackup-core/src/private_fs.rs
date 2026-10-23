//! Owner-only file creation for everything MailBackup writes: mail, the
//! catalog, configuration, credentials, logs and exports.
//!
//! On unix, new folders are created `0700` and new files `0600` from the start
//! (no open-then-chmod window). Existing folders are never changed by these
//! helpers, so creating `<somewhere>/mailbackup.db` can't loosen or tighten
//! `/var/lib`, Documents or a home folder. Existing *files* are tightened only
//! through [`restrict`], on paths MailBackup has identified as its own.
//!
//! On other platforms the helpers fall back to the standard library and the
//! folder ACLs (e.g. the user profile on Windows) apply.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Mode bits granting access to anyone but the owner.
#[cfg(unix)]
const GROUP_OTHER: u32 = 0o077;

/// Creates `path` and missing parents; folders created here are owner-only.
/// Folders that already exist are left exactly as they are.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// `OpenOptions` whose newly created files are owner-only (`0600`). Opening an
/// existing file keeps its mode.
pub fn options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Creates or truncates `path` and writes `data` to it. A new file is created
/// owner-only; an existing one we own is made owner-only (through the open
/// handle) before anything is written.
pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = options().write(true).create(true).truncate(true).open(path)?;
    restrict_handle(&file)?;
    file.write_all(data)
}

/// Opens `path` for appending, creating it owner-only. An existing file we own
/// is made owner-only through the handle.
pub fn open_append(path: &Path) -> io::Result<File> {
    let file = options().create(true).append(true).open(path)?;
    restrict_handle(&file)?;
    Ok(file)
}

/// Replaces `path` atomically with `data`: the content goes to an owner-only
/// temp file next to it, is flushed to disk and renamed over the target, so
/// readers see the old or the new file, never a partial one.
///
/// A symlinked target (e.g. a config kept in a dotfiles repository) is written
/// through instead, so the link isn't replaced by a regular file.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return write(path, data);
    }
    let temp = temp_path_for(path)?;
    let result = (|| {
        let mut file = options().write(true).create_new(true).open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Copies `src` to `dst`. Unlike `std::fs::copy`, which gives the copy the
/// source's mode, the copy is owner-only. Returns the number of bytes copied.
pub fn copy(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut input = File::open(src)?;
    let mut output = options().write(true).create(true).truncate(true).open(dst)?;
    restrict_handle(&output)?;
    let copied = io::copy(&mut input, &mut output)?;
    output.flush()?;
    Ok(copied)
}

/// Removes group/other access from one existing path that MailBackup has
/// identified as its own. Nothing happens to missing paths, symlinks (never
/// followed) or paths owned by another user. Returns whether the mode changed.
pub fn restrict(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        if meta.file_type().is_symlink() || meta.uid() != effective_uid() {
            return Ok(false);
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & GROUP_OTHER == 0 {
            return Ok(false);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & !GROUP_OTHER))?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
    }
}

/// [`restrict`] for a file opened by MailBackup: changes the mode through the
/// handle (no path lookup to race with), only if we own the file.
fn restrict_handle(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = file.metadata()?;
        let mode = meta.permissions().mode() & 0o7777;
        if meta.uid() == effective_uid() && mode & GROUP_OTHER != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(mode & !GROUP_OTHER))?;
        }
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn temp_path_for(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("'{}' has no file name", path.display()))
    })?;
    let temp_name = format!(".{}.{}.tmp", name.to_string_lossy(), uuid::Uuid::new_v4());
    Ok(path.with_file_name(temp_name))
}

/// The existing paths tightened at startup: exactly MailBackup's own files
/// (see [`crate::service::ownership_candidates`]: the config, the credential
/// store and key, the service logs, the catalog with its `-wal`/`-shm`/`-journal`
/// files, and archive entries matching MailBackup's exact layout), plus the app
/// folder `~/.mailbackup`, its `logs` folder and the event logs in it.
///
/// Never included: a custom config folder, the folder holding a custom
/// `db_path`, or a data folder that holds anything but MailBackup's archive.
/// Ownership alone doesn't make a folder MailBackup's.
pub fn startup_candidates(config_path: &Path) -> Vec<PathBuf> {
    startup_candidates_in(config_path, &crate::config::default_base_dir())
}

/// [`startup_candidates`] with the app folder given explicitly.
pub fn startup_candidates_in(config_path: &Path, base: &Path) -> Vec<PathBuf> {
    let mut paths = crate::service::ownership_candidates(config_path);
    let base = base.to_path_buf();
    let log_dir = base.join("logs");
    if let Ok(entries) = std::fs::read_dir(&log_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("events") && name.ends_with(".log") {
                paths.push(entry.path());
            }
        }
    }
    paths.push(log_dir);
    paths.push(base);
    paths.sort();
    paths.dedup();
    paths
}

/// Tightens [`startup_candidates`] that are ours and still open to others.
/// Returns how many paths were changed; per-path failures are skipped.
pub fn tighten_existing(config_path: &Path) -> usize {
    tighten(&startup_candidates(config_path))
}

/// [`restrict`]s each path; returns how many changed. Failures are skipped.
pub fn tighten(paths: &[PathBuf]) -> usize {
    paths
        .iter()
        .filter(|p| restrict(p).unwrap_or(false))
        .count()
}

/// Runs [`tighten_existing`] on a background thread, unless the user turned it
/// off with `settings.tighten_permissions: false`. Walking a large archive takes
/// a moment, so startup doesn't wait for it.
pub fn tighten_existing_in_background(config_path: &Path, settings: &crate::config::GlobalSettings) {
    if !cfg!(unix) || !settings.tighten_permissions {
        return;
    }
    let config_path = config_path.to_path_buf();
    let _ = std::thread::Builder::new().name("tighten-permissions".into()).spawn(move || {
        let changed = tighten_existing(&config_path);
        if changed > 0 {
            crate::event_log::log_event(
                "PERMISSIONS_TIGHTENED",
                &format!("Removed other users' access from {} MailBackup files and folders", changed),
            );
        }
    });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn create_dir_all_makes_new_folders_private_and_keeps_existing_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = tmp.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        set_mode(&existing, 0o755);

        create_dir_all(&existing.join("a/b")).unwrap();
        assert_eq!(mode(&existing), 0o755, "existing parent must not change");
        assert_eq!(mode(&existing.join("a")), 0o700);
        assert_eq!(mode(&existing.join("a/b")), 0o700);
        create_dir_all(&existing).unwrap();
        assert_eq!(mode(&existing), 0o755);
    }

    #[test]
    fn writes_create_private_files_and_tighten_own_existing_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let new = tmp.path().join("new");
        write(&new, b"x").unwrap();
        assert_eq!(mode(&new), 0o600);

        let old = tmp.path().join("old");
        std::fs::write(&old, b"old").unwrap();
        set_mode(&old, 0o644);
        write(&old, b"new").unwrap();
        assert_eq!(mode(&old), 0o600);
        assert_eq!(std::fs::read(&old).unwrap(), b"new");

        let log = tmp.path().join("log");
        std::fs::write(&log, b"a").unwrap();
        set_mode(&log, 0o664);
        open_append(&log).unwrap().write_all(b"b").unwrap();
        assert_eq!(mode(&log), 0o600);
        assert_eq!(std::fs::read(&log).unwrap(), b"ab");
    }

    #[test]
    fn copy_does_not_inherit_the_source_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::write(&src, b"mail").unwrap();
        set_mode(&src, 0o644);
        let dst = tmp.path().join("dst");
        assert_eq!(copy(&src, &dst).unwrap(), 4);
        assert_eq!(mode(&dst), 0o600);
        assert_eq!(mode(&src), 0o644);
    }

    #[test]
    fn write_atomic_replaces_private_and_writes_through_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("config.yaml");
        std::fs::write(&target, b"old").unwrap();
        set_mode(&target, 0o644);
        write_atomic(&target, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(mode(&target), 0o600);
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());

        let real = tmp.path().join("real.yaml");
        std::fs::write(&real, b"old").unwrap();
        let link = tmp.path().join("link.yaml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_atomic(&link, b"via link").unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&real).unwrap(), b"via link");
    }

    #[test]
    fn restrict_skips_symlinks_and_missing_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        set_mode(&file, 0o644);
        let link = tmp.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        assert!(!restrict(&link).unwrap());
        assert_eq!(mode(&file), 0o644, "symlink target must not change");
        assert!(!restrict(&tmp.path().join("missing")).unwrap());
        assert!(restrict(&file).unwrap());
        assert_eq!(mode(&file), 0o600);
        assert!(!restrict(&file).unwrap(), "already private");

        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o755);
        assert!(restrict(&dir).unwrap());
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn restrict_skips_paths_owned_by_someone_else() {
        if effective_uid() != 0 {
            return; // needs root to create a file owned by another user
        }
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("theirs");
        std::fs::write(&file, b"x").unwrap();
        set_mode(&file, 0o644);
        let c_path = std::ffi::CString::new(file.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path; uid/gid 65534 is `nobody`.
        assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 65534, 65534) }, 0);
        assert!(!restrict(&file).unwrap());
        assert_eq!(mode(&file), 0o644);
    }
}
