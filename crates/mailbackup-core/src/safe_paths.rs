//! Validation for filesystem paths that arrive through the web API.
//!
//! The REST API lets a caller choose where `.mbox` exports are written and where the
//! archive and catalog live. Those paths are confined to "allowed roots": the usual
//! user folders, folders the user picked in the native folder dialog, and (for
//! storage) the folders already in use. The CLI runs as the local user and does not
//! go through these checks.

use crate::config::{system_export_locations, AppConfig};
use crate::error::{Error, Result};
use std::path::{Component, Path, PathBuf};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// OS metadata files that don't make a folder "non-empty".
const IGNORABLE_FILES: &[&str] = &[".DS_Store", "Thumbs.db", "desktop.ini"];

/// Bounds for recognising an existing archive folder (`<account>/<folder>/<yyyy>/<mm>/*.eml`).
const ARCHIVE_SCAN_DEPTH: usize = 5;
const ARCHIVE_SCAN_MAX_ENTRIES: usize = 10_000;

/// A set of canonicalized folders that API-supplied paths must stay inside.
#[derive(Debug, Clone)]
pub struct PathPolicy {
    roots: Vec<PathBuf>,
}

/// A validated export destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportTarget {
    pub path: PathBuf,
    /// The target already exists as a regular file (never a symlink or folder).
    pub exists: bool,
}

impl PathPolicy {
    /// Builds a policy from candidate roots. Roots that don't exist yet (e.g. a
    /// removed `~/.mailbackup`) are kept, resolved through their nearest existing
    /// ancestor, so paths below them stay allowed.
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut canonical: Vec<PathBuf> = roots.into_iter().filter_map(|r| normalize_dir(&r)).collect();
        canonical.sort();
        canonical.dedup();
        Self { roots: canonical }
    }

    /// Roots for `.mbox` exports: Downloads, Documents, Desktop, Home and the
    /// folders approved through the native folder picker.
    pub fn for_exports(config: &AppConfig) -> Self {
        Self::new(
            system_export_locations()
                .into_iter()
                .map(|(_, p)| p)
                .chain(config.settings.approved_dirs.iter().cloned()),
        )
    }

    /// Roots for relocating the archive / catalog: the export roots plus the
    /// default base folder and the locations currently in use.
    pub fn for_storage(config: &AppConfig) -> Self {
        let mut roots: Vec<PathBuf> = system_export_locations().into_iter().map(|(_, p)| p).collect();
        roots.extend(config.settings.approved_dirs.iter().cloned());
        roots.push(crate::config::default_base_dir());
        roots.push(config.data_dir.clone());
        if let Some(parent) = config.db_path.parent() {
            roots.push(parent.to_path_buf());
        }
        Self::new(roots)
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The most specific root containing `canonical_path`.
    fn root_for(&self, canonical_path: &Path) -> Option<&Path> {
        self.roots
            .iter()
            .filter(|r| canonical_path.starts_with(r))
            .max_by_key(|r| r.components().count())
            .map(PathBuf::as_path)
    }

    /// Resolves `dir` (which may not exist yet) to a canonical path inside a root,
    /// with no hidden components below that root.
    fn confine_dir(&self, dir: &Path) -> Result<PathBuf> {
        reject_parent_components(dir)?;
        let (existing, rest) = split_existing_ancestor(dir)?;
        let canonical = canonicalize(&existing)?.join(rest);
        let root = self.root_for(&canonical).ok_or_else(|| {
            invalid(format!(
                "'{}' is outside the allowed folders. Choose this folder with Browse… to allow it.",
                dir.display()
            ))
        })?;
        let below_root = canonical.strip_prefix(root).unwrap_or(Path::new(""));
        if below_root.components().any(|c| is_hidden(c.as_os_str())) {
            return Err(invalid(format!(
                "'{}' is inside a hidden folder, which isn't allowed.",
                dir.display()
            )));
        }
        Ok(canonical)
    }

    /// Validates an export destination file. `path` must already be absolute
    /// (see [`crate::config::resolve_export_path`]).
    pub fn validate_export_target(&self, path: &Path) -> Result<ExportTarget> {
        let file_name = checked_file_name(path)?;
        if !has_extension(&file_name, "mbox") {
            return Err(invalid("Export files must end in .mbox.".to_string()));
        }
        let parent = path.parent().ok_or_else(|| invalid("Export path has no folder.".to_string()))?;
        let target = self.confine_dir(parent)?.join(&file_name);
        let exists = existing_regular_file(&target)?;
        Ok(ExportTarget { path: target, exists })
    }

    /// Validates a new archive data folder. It must be the current folder, not
    /// exist yet, or be empty (ignoring OS metadata files). An existing MailBackup
    /// archive is also accepted when it is used in place (`move_existing == false`).
    pub fn validate_data_dir(&self, path: &Path, current: &Path, move_existing: bool) -> Result<PathBuf> {
        require_absolute(path)?;
        if same_location(path, current) {
            return Ok(current.to_path_buf());
        }
        let dir = self.confine_dir(path)?;
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if !meta.is_dir() => {
                Err(invalid(format!("'{}' exists and is not a folder.", dir.display())))
            }
            Ok(_) if is_effectively_empty(&dir)? => Ok(dir),
            Ok(_) if !move_existing && looks_like_archive(&dir) => Ok(dir),
            Ok(_) => Err(invalid(format!(
                "'{}' is not empty. Choose a new or empty folder, or an existing MailBackup \
                 archive with \"Move existing backup files\" unticked.",
                dir.display()
            ))),
            Err(_) => Ok(dir),
        }
    }

    /// Validates a new catalog database path. An existing file is only accepted
    /// when it is opened in place (`move_existing == false`) and is a SQLite file.
    pub fn validate_db_path(&self, path: &Path, current: &Path, move_existing: bool) -> Result<PathBuf> {
        require_absolute(path)?;
        if same_location(path, current) {
            return Ok(current.to_path_buf());
        }
        let file_name = checked_file_name(path)?;
        if !has_extension(&file_name, "db") {
            return Err(invalid("The database file must end in .db.".to_string()));
        }
        let parent = path.parent().ok_or_else(|| invalid("Database path has no folder.".to_string()))?;
        let target = self.confine_dir(parent)?.join(&file_name);
        if existing_regular_file(&target)? {
            if move_existing {
                return Err(invalid(format!(
                    "'{}' already exists. Choose a new file name, or untick \"Migrate existing database\" to open it.",
                    target.display()
                )));
            }
            if !is_sqlite_file(&target) {
                return Err(invalid(format!("'{}' is not a SQLite database.", target.display())));
            }
        }
        Ok(target)
    }
}

/// Resolves a folder path to canonical form, including folders that don't exist
/// yet (via their nearest existing ancestor). Also strips trailing separators, so
/// `/Users/me/Downloads/` and `/Users/me/Downloads` compare equal.
pub fn normalize_dir(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    let (existing, rest) = split_existing_ancestor(path).ok()?;
    let canonical = canonicalize(&existing).ok()?;
    if !canonical.is_dir() {
        return None;
    }
    Some(canonical.join(rest))
}

fn is_ignorable(name: &std::ffi::OsStr) -> bool {
    name.to_str().map(|n| IGNORABLE_FILES.contains(&n)).unwrap_or(false)
}

fn is_effectively_empty(dir: &Path) -> Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        if !is_ignorable(&entry?.file_name()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// True if `dir` has the layout of a MailBackup data folder: only sub-folders at
/// the top (plus OS metadata files) and at least one `.eml` file within the
/// expected depth. The scan is bounded so a huge unrelated folder stays cheap.
pub fn looks_like_archive(dir: &Path) -> bool {
    let Ok(top) = std::fs::read_dir(dir) else { return false };
    for entry in top.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir && !is_ignorable(&entry.file_name()) {
            return false;
        }
    }

    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((current, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else { continue };
        for entry in entries.flatten() {
            seen += 1;
            if seen > ARCHIVE_SCAN_MAX_ENTRIES {
                return false;
            }
            let Ok(file_type) = entry.file_type() else { continue };
            let path = entry.path();
            if file_type.is_file() && has_extension(&entry.file_name().to_string_lossy(), "eml") {
                return true;
            }
            if file_type.is_dir() && depth + 1 < ARCHIVE_SCAN_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    false
}

fn invalid(msg: String) -> Error {
    Error::InvalidPath(msg)
}

fn require_absolute(path: &Path) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(invalid(format!("'{}' must be an absolute path.", path.display())))
    }
}

fn reject_parent_components(path: &Path) -> Result<()> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid("Paths may not contain '..'.".to_string()));
    }
    Ok(())
}

fn checked_file_name(path: &Path) -> Result<String> {
    reject_parent_components(path)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("A file name is required.".to_string()))?;
    if is_hidden(name.as_ref()) {
        return Err(invalid("File names may not start with '.'.".to_string()));
    }
    Ok(name.to_string())
}

fn has_extension(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

fn is_hidden(name: &std::ffi::OsStr) -> bool {
    name.to_str().map(|s| s.starts_with('.')).unwrap_or(false)
}

/// Splits `path` into its deepest existing ancestor and the remaining components.
fn split_existing_ancestor(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return Err(invalid(format!("'{}' has no existing parent folder.", path.display()))),
        }
    }
    let rest: PathBuf = rest.into_iter().rev().collect();
    Ok((existing, rest))
}

/// `Ok(true)` for an existing regular file, `Ok(false)` if nothing is there, and an
/// error for symlinks, folders or anything else (links are never followed).
fn existing_regular_file(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Err(invalid(format!(
            "'{}' exists and is not a regular file.",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn is_sqlite_file(path: &Path) -> bool {
    use std::io::Read;
    let mut header = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .map(|_| &header == SQLITE_HEADER)
        .unwrap_or(false)
}

fn same_location(a: &Path, b: &Path) -> bool {
    a == b || matches!((canonicalize(a), canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

/// `fs::canonicalize`, without the `\\?\` prefix Windows adds to drive paths.
fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    #[cfg(windows)]
    {
        let s = canonical.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if rest.as_bytes().get(1) == Some(&b':') {
                return Ok(PathBuf::from(rest));
            }
        }
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, PathPolicy, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Downloads");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(tmp.path().join("outside")).unwrap();
        let policy = PathPolicy::new([root.clone()]);
        let root = canonicalize(&root).unwrap();
        (tmp, policy, root)
    }

    fn rejected(r: Result<impl std::fmt::Debug>) -> String {
        match r {
            Err(Error::InvalidPath(msg)) => msg,
            other => panic!("expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn export_inside_root_is_accepted() {
        let (_tmp, policy, root) = setup();
        let t = policy.validate_export_target(&root.join("backup.mbox")).unwrap();
        assert_eq!(t, ExportTarget { path: root.join("backup.mbox"), exists: false });

        let nested = policy.validate_export_target(&root.join("new/sub/a.MBOX")).unwrap();
        assert_eq!(nested.path, root.join("new/sub/a.MBOX"));

        std::fs::write(root.join("old.mbox"), b"x").unwrap();
        assert!(policy.validate_export_target(&root.join("old.mbox")).unwrap().exists);
    }

    #[test]
    fn export_outside_root_or_bad_name_is_rejected() {
        let (tmp, policy, root) = setup();
        rejected(policy.validate_export_target(&tmp.path().join("outside/a.mbox")));
        rejected(policy.validate_export_target(&root.join("../outside/a.mbox")));
        rejected(policy.validate_export_target(&root.join("profile")));
        rejected(policy.validate_export_target(&root.join("a.mbox.sh")));
        rejected(policy.validate_export_target(&root.join(".hidden.mbox")));
        rejected(policy.validate_export_target(&root.join(".config/a.mbox")));
        std::fs::create_dir(root.join("dir.mbox")).unwrap();
        rejected(policy.validate_export_target(&root.join("dir.mbox")));
    }

    #[cfg(unix)]
    #[test]
    fn export_through_symlinks_is_rejected() {
        let (tmp, policy, root) = setup();
        let outside = tmp.path().join("outside");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        rejected(policy.validate_export_target(&root.join("link/a.mbox")));

        std::os::unix::fs::symlink(outside.join("victim"), root.join("a.mbox")).unwrap();
        rejected(policy.validate_export_target(&root.join("a.mbox")));
    }

    #[test]
    fn approved_dirs_extend_the_roots() {
        let (tmp, _policy, root) = setup();
        let ext = tmp.path().join("outside");
        let policy = PathPolicy::new([root, ext.clone()]);
        assert!(policy.validate_export_target(&ext.join("a.mbox")).is_ok());
    }

    #[test]
    fn data_dir_rules() {
        let (tmp, policy, root) = setup();
        let current = root.join("current");
        assert_eq!(policy.validate_data_dir(&current, &current, true).unwrap(), current);
        assert_eq!(policy.validate_data_dir(&root.join("new"), &current, true).unwrap(), root.join("new"));

        std::fs::create_dir(root.join("empty")).unwrap();
        std::fs::write(root.join("empty/.DS_Store"), b"x").unwrap();
        assert!(policy.validate_data_dir(&root.join("empty"), &current, true).is_ok());

        std::fs::create_dir(root.join("full")).unwrap();
        std::fs::write(root.join("full/file"), b"x").unwrap();
        rejected(policy.validate_data_dir(&root.join("full"), &current, true));
        rejected(policy.validate_data_dir(&root.join("full"), &current, false));
        rejected(policy.validate_data_dir(&tmp.path().join("outside/new"), &current, true));
        rejected(policy.validate_data_dir(Path::new("relative/dir"), &current, true));
    }

    #[test]
    fn existing_archive_is_accepted_only_in_place() {
        let (_tmp, policy, root) = setup();
        let current = root.join("current");
        let archive = root.join("archive");
        std::fs::create_dir_all(archive.join("acc/inbox/2026/10")).unwrap();
        std::fs::write(archive.join("acc/inbox/2026/10/1_abc.eml"), b"Subject: x").unwrap();
        std::fs::write(archive.join(".DS_Store"), b"x").unwrap();

        assert_eq!(policy.validate_data_dir(&archive, &current, false).unwrap(), archive);
        rejected(policy.validate_data_dir(&archive, &current, true));

        // Folders without any .eml files are not an archive
        std::fs::create_dir_all(root.join("photos/2026")).unwrap();
        std::fs::write(root.join("photos/2026/a.jpg"), b"x").unwrap();
        rejected(policy.validate_data_dir(&root.join("photos"), &current, false));
    }

    #[test]
    fn missing_roots_are_kept() {
        let (tmp, _policy, root) = setup();
        let base = root.join(".mailbackup"); // does not exist
        let policy = PathPolicy::new([root.clone(), base.clone()]);
        let current = tmp.path().join("elsewhere/data");
        assert_eq!(policy.validate_data_dir(&base.join("data"), &current, true).unwrap(), base.join("data"));
        assert!(policy.validate_db_path(&base.join("mailbackup.db"), &current, true).is_ok());
        // ...while other hidden folders below Home stay blocked
        rejected(policy.validate_data_dir(&root.join(".ssh/data"), &current, true));
    }

    #[test]
    fn normalize_dir_strips_trailing_separator() {
        let (_tmp, _policy, root) = setup();
        let with_slash = PathBuf::from(format!("{}/", root.display()));
        assert_eq!(normalize_dir(&with_slash).unwrap(), root);
        assert!(normalize_dir(Path::new("relative")).is_none());
    }

    #[test]
    fn db_path_rules() {
        let (_tmp, policy, root) = setup();
        let current = root.join("current.db");
        assert!(policy.validate_db_path(&root.join("new.db"), &current, true).is_ok());
        rejected(policy.validate_db_path(&root.join("new.sqlite"), &current, true));

        std::fs::write(root.join("text.db"), b"not a database").unwrap();
        rejected(policy.validate_db_path(&root.join("text.db"), &current, false));
        rejected(policy.validate_db_path(&root.join("text.db"), &current, true));

        let mut sqlite = SQLITE_HEADER.to_vec();
        sqlite.extend_from_slice(&[0u8; 84]);
        std::fs::write(root.join("real.db"), sqlite).unwrap();
        assert!(policy.validate_db_path(&root.join("real.db"), &current, false).is_ok());
    }
}
