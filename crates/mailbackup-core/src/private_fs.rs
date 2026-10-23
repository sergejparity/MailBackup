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
    write_atomic_verified(path, data, |_| Ok(()))
}

/// [`write_atomic`] that runs `verify` on the fully written temp file before
/// it replaces `path`. If writing or verifying fails, `path` is untouched and
/// the temp file is removed. Symlinked targets are replaced, not followed.
pub fn write_atomic_verified(
    path: &Path,
    data: &[u8],
    verify: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let temp = temp_path_for(path)?;
    let result = (|| {
        let mut file = options().write(true).create_new(true).open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        verify(&temp)?;
        std::fs::rename(&temp, path)?;
        sync_parent(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Creates `path` with `data` only if it doesn't exist yet, and never leaves a
/// partially written file at `path`: the data is written to a temp file and
/// hard-linked into place, which fails with `AlreadyExists` if another writer
/// got there first. On file systems without hard links (FAT/exFAT) it falls
/// back to an exclusive create.
pub fn create_new_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let temp = temp_path_for(path)?;
    let mut file = options().write(true).create_new(true).open(&temp)?;
    let written = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);
    let result = written.and_then(|_| std::fs::hard_link(&temp, path));
    let _ = std::fs::remove_file(&temp);
    match result {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists && std::fs::symlink_metadata(path).is_err() => {
            // No hard links here: exclusive create, then write
            let mut file = options().write(true).create_new(true).open(path)?;
            file.write_all(data)?;
            file.sync_all()?;
        }
        other => other?,
    }
    sync_parent(path);
    Ok(())
}

/// Temp files left next to `path` by an interrupted [`write_atomic`] (a crash
/// between writing and renaming). Only safe to delete while holding whatever
/// lock serializes writers of `path`.
pub fn stale_temp_files(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else { return Vec::new() };
    let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    let prefix = format!(".{}.", name.to_string_lossy());
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.starts_with(&prefix) && n.ends_with(".tmp")
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}

/// Flushes the rename/link of `path` itself to disk (best effort, unix).
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let dir = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
        if let Ok(dir) = File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
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
///
/// The last component is opened without following symlinks, and the checks
/// and the change go through that one handle, so a symlink swapped in at any
/// moment is never followed. See [`restrict_beneath`] for whole paths.
pub fn restrict(path: &Path) -> io::Result<bool> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
            restrict_beneath(parent, Path::new(name))
        }
        _ => restrict_beneath(path, Path::new("")),
    }
}

/// [`restrict`] for `anchor/rel`, where no component of `rel` may be a
/// symlink: each folder is opened relative to the previous one with
/// `O_NOFOLLOW`, so swapping a folder for a symlink can't redirect the change
/// outside `anchor`. The anchor itself (a folder from the configuration) is
/// trusted; an empty `rel` restricts the anchor, which must not be a symlink.
pub fn restrict_beneath(anchor: &Path, rel: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut names = Vec::new();
        for component in rel.components() {
            match component {
                std::path::Component::Normal(name) => names.push(name.to_os_string()),
                std::path::Component::CurDir => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("'{}' must be a relative path inside the folder", rel.display()),
                    ))
                }
            }
        }
        let file = match nofollow::open_beneath(anchor, &names) {
            Ok(Some(file)) => file,
            Ok(None) => return Ok(false),
            Err(e) if nofollow::is_skippable(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        let file_type = meta.file_type();
        if !(file_type.is_file() || file_type.is_dir()) || meta.uid() != effective_uid() {
            return Ok(false);
        }
        let mode = meta.mode() & 0o7777;
        if mode & GROUP_OTHER == 0 {
            return Ok(false);
        }
        // fchmod on the handle that was checked
        file.set_permissions(std::fs::Permissions::from_mode(mode & !GROUP_OTHER))?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = (anchor, rel);
        Ok(false)
    }
}

#[cfg(unix)]
mod nofollow {
    use std::ffi::{CString, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    /// Missing, a symlink, not a folder where one is expected, or unreadable:
    /// nothing to tighten.
    pub fn is_skippable(e: &io::Error) -> bool {
        matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied)
            || matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK) | Some(libc::ENOTDIR))
    }

    /// Opens `anchor/names…` without following a symlink in any of `names`
    /// (or in `anchor` itself when `names` is empty). `Ok(None)` for anything
    /// but a regular file or folder, which is never opened (FIFOs, devices).
    pub fn open_beneath(anchor: &Path, names: &[OsString]) -> io::Result<Option<File>> {
        let leaf_flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        let Some((last, folders)) = names.split_last() else {
            let meta = std::fs::symlink_metadata(anchor)?;
            if !(meta.is_file() || meta.is_dir()) {
                return Ok(None);
            }
            return std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(anchor).map(Some);
        };
        let mut dir = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(anchor)?;
        for name in folders {
            dir = openat(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)?;
        }
        let c_last = c_name(last)?;
        // SAFETY: zeroed stat is a valid out-parameter; the fd and name are valid.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir.as_raw_fd(), c_last.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let kind = st.st_mode & libc::S_IFMT;
        if kind != libc::S_IFREG && kind != libc::S_IFDIR {
            return Ok(None);
        }
        openat(&dir, last, leaf_flags).map(Some)
    }

    fn openat(dir: &File, name: &OsString, flags: libc::c_int) -> io::Result<File> {
        let c = c_name(name)?;
        // SAFETY: valid directory fd and NUL-terminated name; the new fd is owned by the File.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn c_name(name: &OsString) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in file name"))
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

/// An existing path to tighten: `rel` inside the folder `anchor`, opened
/// without following symlinks below `anchor` (see [`restrict_beneath`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub anchor: PathBuf,
    pub rel: PathBuf,
}

impl Target {
    fn new(anchor: &Path, rel: impl Into<PathBuf>) -> Self {
        Self { anchor: anchor.to_path_buf(), rel: rel.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.anchor.join(&self.rel)
    }
}

/// MailBackup's sensitive files and its own folders: a short, fixed list
/// tightened synchronously at startup.
/// - next to the config: `config.yaml`, the credential store and key, the
///   service logs;
/// - the catalog and its `-wal`/`-shm`/`-journal` files;
/// - the app folder (`~/.mailbackup`), the store and key the CLI keeps there,
///   its `logs` folder and the `events*.log` files in it.
///
/// Never included: a custom config folder, the folder holding a custom
/// `db_path`, or anything else that merely sits next to these files.
pub fn sensitive_targets(config_path: &Path) -> Vec<Target> {
    sensitive_targets_in(config_path, &crate::config::default_base_dir())
}

/// [`sensitive_targets`] with the app folder given explicitly.
pub fn sensitive_targets_in(config_path: &Path, base: &Path) -> Vec<Target> {
    const STORE_FILES: [&str; 3] = [".credentials_store.json", "credentials_store.json", ".credentials_key"];
    let mut targets = Vec::new();
    if let (Some(dir), Some(name)) = (config_path.parent(), config_path.file_name()) {
        let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
        targets.push(Target::new(dir, name));
        targets.extend(STORE_FILES.iter().map(|f| Target::new(dir, f)));
        let (out_log, err_log) = crate::service::service_log_paths(config_path);
        for log in [out_log, err_log] {
            if let Ok(rel) = log.strip_prefix(dir) {
                targets.push(Target::new(dir, rel));
            }
        }
    }
    if let Some(cfg) = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|text| serde_yaml::from_str::<crate::config::AppConfig>(&text).ok())
    {
        if let (Some(dir), Some(name)) = (cfg.db_path.parent(), cfg.db_path.file_name()) {
            let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
            let name = name.to_string_lossy();
            for suffix in ["", "-wal", "-shm", "-journal"] {
                targets.push(Target::new(dir, format!("{}{}", name, suffix)));
            }
        }
    }
    targets.push(Target::new(base, ""));
    targets.extend(STORE_FILES.iter().map(|f| Target::new(base, f)));
    targets.push(Target::new(base, "logs"));
    if let Ok(entries) = std::fs::read_dir(base.join("logs")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("events") && name.ends_with(".log") {
                targets.push(Target::new(base, Path::new("logs").join(name)));
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

/// Archive entries that follow MailBackup's exact layout
/// ([`crate::service::archive_entries`]); the data folder itself only if it
/// holds nothing else. Walking a large archive takes a while.
pub fn archive_targets(config_path: &Path) -> Vec<Target> {
    let Some(cfg) = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|text| serde_yaml::from_str::<crate::config::AppConfig>(&text).ok())
    else {
        return Vec::new();
    };
    let data_dir = cfg.data_dir;
    crate::service::archive_entries(&data_dir)
        .into_iter()
        .filter_map(|p| p.strip_prefix(&data_dir).ok().map(|rel| Target::new(&data_dir, rel)))
        .collect()
}

/// [`restrict_beneath`]s each target; returns how many changed. Failures are skipped.
pub fn tighten(targets: &[Target]) -> usize {
    targets
        .iter()
        .filter(|t| restrict_beneath(&t.anchor, &t.rel).unwrap_or(false))
        .count()
}

/// Startup tightening of existing files, unless the user turned it off with
/// `settings.tighten_permissions: false`:
/// - the [`sensitive_targets`] synchronously, so they're private before this
///   returns, even for a CLI command that exits right away;
/// - with `include_archive`, the [`archive_targets`] on a background thread
///   (for long-running processes: the server and the daemon).
pub fn tighten_at_startup(config_path: &Path, settings: &crate::config::GlobalSettings, include_archive: bool) {
    if !cfg!(unix) || !settings.tighten_permissions {
        return;
    }
    log_tightened(tighten(&sensitive_targets(config_path)));
    if include_archive {
        let config_path = config_path.to_path_buf();
        let _ = std::thread::Builder::new()
            .name("tighten-archive".into())
            .spawn(move || log_tightened(tighten(&archive_targets(&config_path))));
    }
}

fn log_tightened(changed: usize) {
    if changed > 0 {
        crate::event_log::log_event(
            "PERMISSIONS_TIGHTENED",
            &format!("Removed other users' access from {} MailBackup files and folders", changed),
        );
    }
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
