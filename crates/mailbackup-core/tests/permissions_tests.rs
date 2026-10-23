//! Owner-only permissions for MailBackup's files (unix).
#![cfg(unix)]

use mailbackup_core::config::AppConfig;
use mailbackup_core::db::Database;
use mailbackup_core::mbox::MboxExporter;
use mailbackup_core::private_fs;
use mailbackup_core::storage::StorageEngine;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A temp dir whose own mode is 0755, standing in for a shared parent such as
/// `/var/lib` or Documents.
fn shared_parent() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    set_mode(tmp.path(), 0o755);
    tmp
}

#[test]
fn stored_mail_and_its_folders_are_owner_only() {
    let tmp = shared_parent();
    let base = tmp.path().join("data");
    let storage = StorageEngine::new(&base);
    let info = storage.store_eml("acc", "INBOX", 7, None, b"Subject: hi\r\n\r\nbody").unwrap();

    assert_eq!(mode(&info.absolute_path), 0o600);
    let mut dir = info.absolute_path.parent().unwrap().to_path_buf();
    while dir != tmp.path() {
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
        dir = dir.parent().unwrap().to_path_buf();
    }
    assert_eq!(mode(&base.join(".staging")), 0o700);
    assert_eq!(mode(tmp.path()), 0o755, "existing parent must not change");
}

#[test]
fn migrated_mail_does_not_keep_loose_modes() {
    let tmp = shared_parent();
    let old = tmp.path().join("old");
    let storage = StorageEngine::new(&old);
    let info = storage.store_eml("acc", "INBOX", 1, None, b"Subject: x\r\n\r\n").unwrap();
    set_mode(&info.absolute_path, 0o644);

    let new = tmp.path().join("new");
    assert_eq!(storage.migrate_data(&new).unwrap(), 1);
    let copied = new.join(&info.relative_path);
    assert_eq!(mode(&copied), 0o600);
    assert_eq!(mode(&new), 0o700);
    assert_eq!(mode(copied.parent().unwrap()), 0o700);
}

#[test]
fn config_save_is_owner_only_and_keeps_existing_parents() {
    let tmp = shared_parent();
    let path = tmp.path().join("cfg/config.yaml");
    let config = AppConfig::default();
    config.save(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);

    set_mode(&path, 0o644);
    config.save(&path).unwrap();
    assert_eq!(mode(&path), 0o600, "re-saving replaces a loose config");
    assert_eq!(mode(tmp.path()), 0o755);
}

#[test]
fn new_database_and_wal_are_owner_only_and_missing_folder_is_created() {
    let tmp = shared_parent();
    let path = tmp.path().join("missing/catalog.db");
    let db = Database::open(&path).unwrap();
    db.upsert_account("a", "A", "a@example.com", "custom").unwrap();

    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let shm = PathBuf::from(format!("{}-shm", path.display()));
    assert!(wal.exists(), "WAL mode should create a -wal file");
    assert_eq!(mode(&wal), 0o600);
    assert_eq!(mode(&shm), 0o600);
    assert_eq!(mode(tmp.path()), 0o755);
}

#[test]
fn existing_loose_database_is_tightened_before_sqlite_opens_it() {
    let tmp = shared_parent();
    let path = tmp.path().join("catalog.db");
    {
        let db = Database::open(&path).unwrap();
        db.upsert_account("a", "A", "a@example.com", "custom").unwrap();
    }
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let journal = PathBuf::from(format!("{}-journal", path.display()));
    std::fs::write(&journal, b"").unwrap();
    for p in [&path, &journal] {
        set_mode(p, 0o644);
    }
    if wal.exists() {
        set_mode(&wal, 0o644);
    }

    let db = Database::open(&path).unwrap();
    db.upsert_account("b", "B", "b@example.com", "custom").unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&journal), 0o600);
    assert_eq!(mode(&wal), 0o600, "a WAL created after tightening inherits 0600");
}

#[test]
fn relocated_database_is_owner_only() {
    let tmp = shared_parent();
    let db = Database::open(tmp.path().join("a.db")).unwrap();
    db.upsert_account("a", "A", "a@example.com", "custom").unwrap();
    set_mode(&tmp.path().join("a.db"), 0o644);

    let target = tmp.path().join("moved/b.db");
    db.relocate(&target, true).unwrap();
    assert_eq!(mode(&target), 0o600);
    assert_eq!(mode(target.parent().unwrap()), 0o700);
}

#[test]
fn mbox_exports_are_owner_only() {
    let tmp = shared_parent();
    let storage = StorageEngine::new(tmp.path().join("data"));
    let info = storage.store_eml("acc", "INBOX", 1, None, b"Subject: x\r\n\r\nbody\r\n").unwrap();
    let rel = info.relative_path.to_string_lossy().to_string();
    let out = tmp.path().join("exports/out.mbox");
    MboxExporter::new(&storage).export_to_mbox_with(std::slice::from_ref(&rel), &out, false).unwrap();
    assert_eq!(mode(&out), 0o600);
    assert_eq!(mode(out.parent().unwrap()), 0o700);

    set_mode(&out, 0o644);
    MboxExporter::new(&storage).export_to_mbox_with(&[rel], &out, true).unwrap();
    // Overwriting keeps the existing file's mode: the user may have chosen it
    assert_eq!(mode(&out), 0o644);
}

/// An install as left by an older version: everything world-readable, a custom
/// db folder and a data folder that also holds unrelated files.
struct LooseInstall {
    _tmp: tempfile::TempDir,
    config_dir: PathBuf,
    config_path: PathBuf,
    base: PathBuf,
    db_dir: PathBuf,
    db_path: PathBuf,
    data_dir: PathBuf,
    eml: PathBuf,
}

fn loose_install(foreign_in_data: bool) -> LooseInstall {
    let tmp = shared_parent();
    let root = tmp.path().to_path_buf();
    let config_dir = root.join("custom-config");
    let base = root.join("home/.mailbackup");
    let db_dir = root.join("var-lib");
    let data_dir = root.join("archive");
    for d in [&config_dir, &base.join("logs"), &db_dir, &data_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    let config_path = config_dir.join("config.yaml");
    let db_path = db_dir.join("catalog.db");
    let config = AppConfig { data_dir: data_dir.clone(), db_path: db_path.clone(), ..Default::default() };
    std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    std::fs::write(&db_path, b"").unwrap();
    std::fs::write(config_dir.join(".credentials_store.json"), b"{}").unwrap();
    std::fs::write(config_dir.join(".credentials_key"), b"00").unwrap();
    std::fs::write(base.join("logs/events.log"), b"x").unwrap();
    std::fs::write(base.join("logs/events-2026-01-01.log"), b"x").unwrap();
    std::fs::write(base.join("logs/notes.txt"), b"x").unwrap();

    let month = data_dir.join("acc/INBOX/2026/10");
    std::fs::create_dir_all(&month).unwrap();
    let eml = month.join("12_0123456789ab.eml");
    std::fs::write(&eml, b"Subject: x").unwrap();
    if foreign_in_data {
        std::fs::write(data_dir.join("holiday.jpg"), b"x").unwrap();
    }

    for entry in walk(&root) {
        let is_dir = entry.is_dir();
        set_mode(&entry, if is_dir { 0o755 } else { 0o644 });
    }
    LooseInstall { _tmp: tmp, config_dir, config_path, base, db_dir, db_path, data_dir, eml }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        }
        out.push(path);
    }
    out
}

#[test]
fn startup_tightening_changes_only_mailbackups_own_paths() {
    let install = loose_install(false);
    let candidates = private_fs::startup_candidates_in(&install.config_path, &install.base);
    assert!(private_fs::tighten(&candidates) > 0);

    for file in [
        install.config_path.clone(),
        install.config_dir.join(".credentials_store.json"),
        install.config_dir.join(".credentials_key"),
        install.db_path.clone(),
        install.base.join("logs/events.log"),
        install.base.join("logs/events-2026-01-01.log"),
        install.eml.clone(),
    ] {
        assert_eq!(mode(&file), 0o600, "{}", file.display());
    }
    for dir in [install.base.clone(), install.base.join("logs"), install.data_dir.clone(), install.eml.parent().unwrap().to_path_buf()] {
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    }
    // Folders not dedicated to MailBackup are left alone
    assert_eq!(mode(&install.config_dir), 0o755, "custom config folder");
    assert_eq!(mode(&install.db_dir), 0o755, "folder of a custom db_path");
    assert_eq!(mode(install.base.parent().unwrap()), 0o755, "home folder");
    assert_eq!(mode(&install.base.join("logs/notes.txt")), 0o644, "unknown file in logs");

    assert_eq!(private_fs::tighten(&candidates), 0, "second run changes nothing");
}

#[test]
fn startup_tightening_leaves_a_shared_data_folder_and_foreign_files_alone() {
    let install = loose_install(true);
    let candidates = private_fs::startup_candidates_in(&install.config_path, &install.base);
    private_fs::tighten(&candidates);

    assert_eq!(mode(&install.data_dir), 0o755, "data folder holding other files");
    assert_eq!(mode(&install.data_dir.join("holiday.jpg")), 0o644);
    // MailBackup's own subtree inside it is still made private
    assert_eq!(mode(&install.eml), 0o600);
    assert_eq!(mode(&install.data_dir.join("acc")), 0o700);
}

#[test]
fn startup_tightening_never_follows_symlinks() {
    let install = loose_install(false);
    let outside = install.db_dir.join("elsewhere.txt");
    std::fs::write(&outside, b"x").unwrap();
    set_mode(&outside, 0o644);
    std::fs::remove_file(install.config_dir.join(".credentials_key")).unwrap();
    std::os::unix::fs::symlink(&outside, install.config_dir.join(".credentials_key")).unwrap();

    let candidates = private_fs::startup_candidates_in(&install.config_path, &install.base);
    private_fs::tighten(&candidates);
    assert_eq!(mode(&outside), 0o644);
}

#[test]
fn startup_tightening_can_be_turned_off() {
    let yaml = "data_dir: /x\ndb_path: /x.db\nsettings:\n  tighten_permissions: false\n";
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(!config.settings.tighten_permissions);
    assert!(AppConfig::default().settings.tighten_permissions);
    let legacy: AppConfig = serde_yaml::from_str("data_dir: /x\ndb_path: /x.db\n").unwrap();
    assert!(legacy.settings.tighten_permissions, "older configs default to on");
}
