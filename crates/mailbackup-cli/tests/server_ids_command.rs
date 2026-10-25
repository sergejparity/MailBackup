//! `mailbackup account server-ids` (issue #33): turning the opt-in on and
//! off, showing distrusted sources, and resetting them.

use mailbackup_core::config::{AccountConfig, AppConfig, ArchiveInfo, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::Database;
use mailbackup_core::server_ids::ServerIdKind;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn account(id: &str, archive: bool) -> AccountConfig {
    AccountConfig {
        id: id.into(),
        name: id.into(),
        email: "me@example.com".into(),
        provider: ProviderType::GenericImap,
        imap_server: "imap.example".into(),
        imap_port: 993,
        use_tls: true,
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

fn trusted(config: &Path, id: &str) -> bool {
    AppConfig::load_existing(config).unwrap().unwrap().accounts.into_iter().find(|a| a.id == id).unwrap().trust_server_ids
}

#[test]
fn the_opt_in_and_the_reset() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let db_path = dir.path().join("catalog.db");
    AppConfig {
        data_dir: dir.path().join("data"),
        db_path: db_path.clone(),
        accounts: vec![account("live", false), account("live~archive-20261024-1", true)],
        ..Default::default()
    }
    .save(&config)
    .unwrap();

    let out = run(dir.path(), &config, &["account", "server-ids", "live", "--trust", "on"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(trusted(&config, "live"));
    let out = run(dir.path(), &config, &["account", "server-ids", "me@example.com", "--trust", "off"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!trusted(&config, "live"), "by email: the live account, not the archive");

    let refused = run(dir.path(), &config, &["account", "server-ids", "live~archive-20261024-1", "--trust", "on"]);
    assert!(!refused.status.success());
    assert!(!trusted(&config, "live~archive-20261024-1"));

    let source = "imap.example:993:me";
    Database::open(&db_path).unwrap().record_server_id_distrust("live", source, ServerIdKind::EmailId, "reused id").unwrap();
    let shown = run(dir.path(), &config, &["account", "server-ids", "live"]);
    let text = String::from_utf8_lossy(&shown.stdout);
    assert!(text.contains("Distrusted") && text.contains(source) && text.contains("reused id"), "{}", text);

    let reset = run(dir.path(), &config, &["account", "server-ids", "live", "--reset"]);
    assert!(reset.status.success(), "{}", String::from_utf8_lossy(&reset.stderr));
    assert!(String::from_utf8_lossy(&reset.stdout).contains("Cleared 1"));
    assert!(Database::open(&db_path).unwrap().server_id_states("live").unwrap().is_empty());
}
