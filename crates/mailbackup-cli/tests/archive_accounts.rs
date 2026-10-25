//! Read-only archive accounts (issue #31) from the CLI: never synced, and
//! removing an account by email doesn't take its archives along.

use mailbackup_core::config::{AccountConfig, AppConfig, ArchiveInfo, AuthType, FolderFilter, ProviderType};
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn account(id: &str, archive: bool) -> AccountConfig {
    AccountConfig {
        id: id.into(),
        name: id.into(),
        email: "me@example.com".into(),
        provider: ProviderType::GenericImap,
        imap_server: "127.0.0.1".into(),
        imap_port: 1,
        use_tls: false,
        auth_type: AuthType::Password,
        username: "me".into(),
        schedule: None,
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: false,
        enabled: !archive,
        storage_namespace: None,
        credential_ref: None,
        archive: archive.then(|| ArchiveInfo { archived_at: chrono::Utc::now(), retired_from: "live".into(), last_source: None }),
        trust_server_ids: false,
    }
}

fn run(home: &Path, config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mailbackup"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env("HOME", home)
        .env("MAILBACKUP_KEYRING", "none")
        .env_remove("MAILBACKUP_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn setup(accounts: Vec<AccountConfig>) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    AppConfig {
        data_dir: dir.path().join("data"),
        db_path: dir.path().join("catalog.db"),
        accounts,
        ..Default::default()
    }
    .save(&config_path)
    .unwrap();
    (dir, config_path)
}

#[test]
fn archives_are_never_synced() {
    let (dir, config) = setup(vec![account("live~archive-20261024-1", true)]);
    let explicit = run(dir.path(), &config, &["sync", "--account", "live~archive-20261024-1"]);
    assert!(!explicit.status.success());
    assert!(String::from_utf8_lossy(&explicit.stderr).contains("read-only archive"), "{}", String::from_utf8_lossy(&explicit.stderr));

    let all = run(dir.path(), &config, &["sync"]);
    assert!(all.status.success(), "{}", String::from_utf8_lossy(&all.stderr));
    assert!(String::from_utf8_lossy(&all.stdout).contains("No enabled accounts"), "{}", String::from_utf8_lossy(&all.stdout));
}

#[test]
fn removing_an_account_by_email_keeps_its_archives() {
    let (dir, config) = setup(vec![account("live", false), account("live~archive-20261024-1", true)]);
    let out = run(dir.path(), &config, &["account", "remove", "me@example.com"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let left: Vec<String> = AppConfig::load_existing(&config).unwrap().unwrap().accounts.into_iter().map(|a| a.id).collect();
    assert_eq!(left, ["live~archive-20261024-1"]);
}
