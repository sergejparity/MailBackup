//! First start with a fresh home folder (issue #13). The test body runs in a
//! child process of this test binary that starts with `HOME` pointing at a
//! temp folder (unix: `dirs` reads the home folder from `HOME` there), so the
//! environment is never changed while other threads may read it.
#![cfg(unix)]

use mailbackup_core::config::AppConfig;
use mailbackup_core::db::Database;
use std::path::PathBuf;

/// Set in the child process: the temp folder its parent prepared.
const CHILD_DIR: &str = "MAILBACKUP_TEST_CHILD_DIR";

#[test]
fn first_start_with_a_new_config_outside_the_default_folder() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "first_start_with_a_new_config_outside_the_default_folder", "--nocapture"])
            .env(CHILD_DIR, tmp.path())
            .env("HOME", &home)
            .status()
            .unwrap();
        assert!(status.success(), "the test body failed in the child process");
        return;
    };
    let tmp = PathBuf::from(dir);
    let home = tmp.join("home");

    // The config lives elsewhere, so saving it doesn't create ~/.mailbackup
    let config_path = tmp.join("etc/config.yaml");
    let config = AppConfig::load_or_create(Some(&config_path)).unwrap();
    assert!(config.db_path.starts_with(&home), "{}", config.db_path.display());
    assert!(config.data_dir.is_dir());
    assert!(config.db_path.parent().unwrap().is_dir());
    Database::open(&config.db_path).unwrap();

    // A catalog in a folder that doesn't exist yet, and a bare relative file name
    Database::open(tmp.join("new/deeper/catalog.db")).unwrap();
    std::env::set_current_dir(&tmp).unwrap();
    Database::open("catalog.db").unwrap();
    assert!(tmp.join("catalog.db").is_file());
}
