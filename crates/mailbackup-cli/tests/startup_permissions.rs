//! A short CLI command must leave existing credentials private when it exits
//! (startup tightening isn't left to a thread the process may never wait for).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn loosen(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn account_list_secures_existing_credentials_before_exiting() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let base = home.join(".mailbackup");
    let config_dir = tmp.path().join("cfg");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    let config_path = config_dir.join("config.yaml");
    let yaml = format!(
        "data_dir: {}\ndb_path: {}\n",
        tmp.path().join("data").display(),
        tmp.path().join("db/catalog.db").display()
    );
    std::fs::write(&config_path, yaml).unwrap();
    // Left world-readable by an older version
    let files = [
        config_path.clone(),
        config_dir.join(".credentials_store.json"),
        config_dir.join(".credentials_key"),
        base.join(".credentials_store.json"),
        base.join(".credentials_key"),
    ];
    for file in &files[1..] {
        std::fs::write(file, b"{}").unwrap();
    }
    for file in &files {
        loosen(file, 0o644);
    }
    loosen(&base, 0o755);

    let status = Command::new(env!("CARGO_BIN_EXE_mailbackup"))
        .args(["--config", config_path.to_str().unwrap(), "account", "list"])
        .env("HOME", &home)
        .env_remove("MAILBACKUP_MASTER_KEY")
        .env_remove("MAILBACKUP_ENCRYPTION_KEY")
        .status()
        .unwrap();
    assert!(status.success());

    for file in &files {
        assert_eq!(mode(file), 0o600, "{}", file.display());
    }
    assert_eq!(mode(&base), 0o700);
    assert_eq!(mode(&config_dir), 0o755, "a custom config folder is left alone");
}
