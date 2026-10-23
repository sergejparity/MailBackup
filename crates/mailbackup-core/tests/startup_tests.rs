//! First start with a fresh home folder (issue #13). This binary holds a single
//! test because it points `HOME` at a temp folder for the whole process (unix:
//! `dirs` reads the home folder from `HOME` there).
#![cfg(unix)]

use mailbackup_core::config::AppConfig;
use mailbackup_core::db::Database;

#[test]
fn first_start_with_a_new_config_outside_the_default_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::env::set_var("HOME", &home);

    // The config lives elsewhere, so saving it doesn't create ~/.mailbackup
    let config_path = tmp.path().join("etc/config.yaml");
    let config = AppConfig::load_or_create(Some(&config_path)).unwrap();
    assert!(config.db_path.starts_with(&home), "{}", config.db_path.display());
    assert!(config.data_dir.is_dir());
    assert!(config.db_path.parent().unwrap().is_dir());
    Database::open(&config.db_path).unwrap();

    // A catalog in a folder that doesn't exist yet, and a bare relative file name
    Database::open(tmp.path().join("new/deeper/catalog.db")).unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();
    Database::open("catalog.db").unwrap();
    assert!(tmp.path().join("catalog.db").is_file());
}
