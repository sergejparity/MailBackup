//! `mailbackup account import-csv` creates accounts like `account add`:
//! an address that already has an account is refused, a colliding slug gets
//! an id of its own, and no existing account is ever replaced (issue #74).

use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use std::process::{Command, Stdio};

fn existing() -> AccountConfig {
    AccountConfig {
        id: "a_bexample_com".into(),
        name: "Original".into(),
        email: "a.b@example.com".into(),
        provider: ProviderType::GenericImap,
        imap_server: "imap.original.example".into(),
        imap_port: 993,
        use_tls: true,
        auth_type: AuthType::Password,
        username: "a.b@example.com".into(),
        schedule: None,
        retention_days: Some(30),
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: false,
        enabled: true,
        storage_namespace: None,
        credential_ref: None,
        archive: None,
        trust_server_ids: true,
    }
}

#[test]
fn an_import_never_replaces_an_account() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    AppConfig {
        data_dir: dir.path().join("data"),
        db_path: dir.path().join("catalog.db"),
        accounts: vec![existing()],
        ..Default::default()
    }
    .save(&config_path)
    .unwrap();
    let csv = dir.path().join("accounts.csv");
    std::fs::write(
        &csv,
        "email,password,name,server,port,username\n\
         a.b@example.com,pw1,Again,imap.other.example,993,a.b@example.com\n\
         a_b@example.com,pw2,Underscore,imap.example.com,993,a_b@example.com\n\
         new@example.com,pw3,New,imap.example.com,993,new@example.com\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_mailbackup"))
        .arg("--config")
        .arg(&config_path)
        .args(["account", "import-csv"])
        .arg(&csv)
        .env("HOME", dir.path())
        .env("MAILBACKUP_KEYRING", "none")
        .env_remove("MAILBACKUP_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}\n{}", stdout, String::from_utf8_lossy(&out.stderr));

    let saved = AppConfig::load_existing(&config_path).unwrap().unwrap();
    let mut ids: Vec<_> = saved.accounts.iter().map(|a| a.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["a_bexample_com", "a_bexample_com-2", "newexample_com"], "{}", stdout);
    let original = saved.account_by_id("a_bexample_com").unwrap();
    assert_eq!(original, &existing(), "the existing account is untouched");
    assert!(stdout.contains("Line 2"), "the repeated address is reported: {}", stdout);
}
