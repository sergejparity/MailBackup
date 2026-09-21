use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::Database;
use mailbackup_core::keyring::CredentialStore;
use mailbackup_core::mbox::MboxExporter;
use mailbackup_core::retention::RetentionManager;
use mailbackup_core::storage::StorageEngine;
use chrono::{Duration, Utc};
use tempfile::tempdir;
use tokio_cron_scheduler::Job;

#[test]
fn test_cron_syntax() {
    use mailbackup_core::scheduler::normalize_cron;

    // 5-field every minute
    let cron_every_min = "*/1 * * * *";
    let normalized = normalize_cron(cron_every_min);
    assert_eq!(normalized, "0 */1 * * * *");
    let res = Job::new_async(&normalized, |_uuid, _lock| Box::pin(async {}));
    assert!(res.is_ok(), "Failed for */1 * * * *: {:?}", res.err());

    // * * * * * (also every minute)
    let cron_star = "* * * * *";
    let norm_star = normalize_cron(cron_star);
    assert_eq!(norm_star, "0 * * * * *");
    let res_star = Job::new_async(&norm_star, |_uuid, _lock| Box::pin(async {}));
    assert!(res_star.is_ok(), "Failed for * * * * *: {:?}", res_star.err());
}

#[test]
fn test_config_serialization() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");

    let mut config = AppConfig::default();
    config.accounts.push(AccountConfig {
        id: "test-account".to_string(),
        name: "Test Account".to_string(),
        email: "test@example.com".to_string(),
        provider: ProviderType::GenericImap,
        imap_server: "imap.example.com".to_string(),
        imap_port: 993,
        use_tls: true,
        auth_type: AuthType::Password,
        username: "testuser".to_string(),
        schedule: Some("0 */6 * * *".to_string()),
        retention_days: Some(90),
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
    });

    config.save(&config_path).unwrap();
    assert!(config_path.exists());

    let loaded = AppConfig::load_or_create(Some(&config_path)).unwrap();
    assert_eq!(loaded.accounts.len(), 1);
    assert_eq!(loaded.accounts[0].email, "test@example.com");
    assert_eq!(loaded.accounts[0].retention_days, Some(90));
}

#[test]
fn test_credential_fallback_store() {
    let dir = tempdir().unwrap();
    let cred_file = dir.path().join("secrets.json");
    let store = CredentialStore::with_fallback_path(cred_file);

    store.set_password("acc1", "supersecret123").unwrap();
    let retrieved = store.get_password("acc1").unwrap();
    assert_eq!(retrieved, "supersecret123");

    store.delete_password("acc1").unwrap();
    assert!(store.get_password("acc1").is_err());
}

#[test]
fn test_storage_engine_atomic_write_and_checksum() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::new(dir.path());

    let raw_eml = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello World";
    let stored = storage.store_eml(
        "acc1",
        "INBOX",
        101,
        Some(Utc::now()),
        raw_eml,
    ).unwrap();

    assert!(stored.absolute_path.exists());
    assert_eq!(stored.size_bytes, raw_eml.len() as u64);

    // Verify checksum
    let is_valid = storage.verify_checksum(&stored.relative_path, &stored.sha256).unwrap();
    assert!(is_valid);

    // Read back
    let read_back = storage.read_eml(&stored.relative_path).unwrap();
    assert_eq!(read_back, raw_eml);
}

#[test]
fn test_database_and_fts5_search() {
    let db = Database::open_in_memory().unwrap();

    db.upsert_account("acc1", "Alice", "alice@example.com", "generic_imap").unwrap();
    let folder = db.get_or_create_folder("acc1", "INBOX", "inbox", Some(12345)).unwrap();
    assert_eq!(folder.remote_name, "INBOX");

    let now = Utc::now();
    let msg_id = db.insert_message(
        "acc1",
        &folder.id,
        1,
        Some("<msg001@example.com>"),
        Some("Urgent Financial Report"),
        Some("cfo@company.com"),
        Some("alice@example.com"),
        None,
        Some(now),
        1024,
        "acc1/inbox/2026/09/1_hash.eml",
        "mockhash123",
        Some("Please review the attached quarterly earnings spreadsheet immediately."),
        &[("report.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 50000)],
    ).unwrap();

    assert!(!msg_id.is_empty());
    assert!(db.message_exists_by_uid(&folder.id, 1).unwrap());
    assert!(!db.message_exists_by_uid(&folder.id, 999).unwrap());

    // Search FTS5
    let results = db.search_fts("Financial", 10).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].subject, "Urgent Financial Report");
    assert!(results[0].snippet.contains("Financial"));

    // Search body content
    let results_body = db.search_fts("quarterly earnings", 10).unwrap();
    assert_eq!(results_body.len(), 1);

    // Search attachment name
    let results_att = db.search_fts("report.xlsx", 10).unwrap();
    assert_eq!(results_att.len(), 1);
}

#[test]
fn test_retention_policy_pruning() {
    let dir = tempdir().unwrap();
    let db = Database::open_in_memory().unwrap();
    let storage = StorageEngine::new(dir.path());

    db.upsert_account("acc1", "Alice", "alice@example.com", "generic_imap").unwrap();
    let folder = db.get_or_create_folder("acc1", "INBOX", "inbox", Some(1)).unwrap();

    let old_date = Utc::now() - Duration::days(120);
    let raw_eml = b"Subject: Old message\r\n\r\nExpired";

    let stored = storage.store_eml("acc1", "INBOX", 1, Some(old_date), raw_eml).unwrap();

    db.insert_message(
        "acc1",
        &folder.id,
        1,
        Some("<old@example.com>"),
        Some("Old message"),
        Some("sender@example.com"),
        Some("alice@example.com"),
        None,
        Some(old_date),
        stored.size_bytes,
        &stored.relative_path.to_string_lossy(),
        &stored.sha256,
        Some("Expired"),
        &[],
    ).unwrap();

    assert!(stored.absolute_path.exists());

    // Enforce 90-day retention
    let retention = RetentionManager::new(&db, &storage);
    let report = retention.enforce_retention("acc1", Some(90)).unwrap();

    assert_eq!(report.pruned_count, 1);
    assert!(!stored.absolute_path.exists()); // Physical file deleted
    assert!(!db.message_exists_by_uid(&folder.id, 1).unwrap()); // DB record deleted
}

#[test]
fn test_mbox_export() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::new(dir.path());

    let raw_eml1 = b"From: alice@example.com\r\nSubject: First\r\n\r\nHello from message 1\r\nFrom somewhere";
    let raw_eml2 = b"From: bob@example.com\r\nSubject: Second\r\n\r\nHello from message 2";

    let stored1 = storage.store_eml("acc1", "INBOX", 1, Some(Utc::now()), raw_eml1).unwrap();
    let stored2 = storage.store_eml("acc1", "INBOX", 2, Some(Utc::now()), raw_eml2).unwrap();

    let mbox_path = dir.path().join("export.mbox");
    let exporter = MboxExporter::new(&storage);

    let paths = vec![
        stored1.relative_path.to_string_lossy().to_string(),
        stored2.relative_path.to_string_lossy().to_string(),
    ];

    let count = exporter.export_to_mbox(&paths, &mbox_path).unwrap();
    assert_eq!(count, 2);
    assert!(mbox_path.exists());

    let mbox_content = std::fs::read_to_string(&mbox_path).unwrap();
    assert!(mbox_content.contains("From "));
    assert!(mbox_content.contains(">From somewhere")); // Escaped
    assert!(mbox_content.contains("Subject: First"));
    assert!(mbox_content.contains("Subject: Second"));
}
