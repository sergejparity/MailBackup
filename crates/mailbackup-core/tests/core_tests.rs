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

#[test]
fn test_storage_location_update_and_migration() {
    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();

    let storage = StorageEngine::new(dir1.path());
    assert_eq!(storage.base_dir(), dir1.path());

    // Store a message in location 1
    let raw_eml = b"From: test@example.com\r\nSubject: Test Migrate\r\n\r\nHello World";
    let stored = storage.store_eml("acc1", "INBOX", 1, Some(Utc::now()), raw_eml).unwrap();
    assert!(stored.absolute_path.exists());

    // Migrate from location 1 to location 2
    let migrated_count = storage.migrate_data(dir2.path()).unwrap();
    assert_eq!(migrated_count, 1);

    // Update storage base_dir
    storage.set_base_dir(dir2.path());
    assert_eq!(storage.base_dir(), dir2.path());

    // Verify message can be read from location 2
    let read_bytes = storage.read_eml(&stored.relative_path).unwrap();
    assert_eq!(read_bytes, raw_eml);

    let abs_in_loc2 = storage.get_absolute_path(&stored.relative_path);
    assert!(abs_in_loc2.exists());
    assert_eq!(abs_in_loc2, dir2.path().join(&stored.relative_path));
}

#[test]
fn test_close_to_tray_setting_and_compatibility() {
    // 1. Default value should be true
    let default_config = AppConfig::default();
    assert!(default_config.settings.close_to_tray);

    // 2. Backward compatibility: YAML without close_to_tray should deserialize with close_to_tray = true
    let legacy_yaml = r#"
data_dir: /tmp/mailbackup/data
db_path: /tmp/mailbackup/mailbackup.db
settings:
  default_schedule: "0 0 * * *"
  web_port: 8765
accounts: []
"#;
    let loaded: AppConfig = serde_yaml::from_str(legacy_yaml).unwrap();
    assert!(loaded.settings.close_to_tray);

    // 3. Explicit false should deserialize properly
    let explicit_false_yaml = r#"
data_dir: /tmp/mailbackup/data
db_path: /tmp/mailbackup/mailbackup.db
settings:
  default_schedule: "0 0 * * *"
  web_port: 8765
  close_to_tray: false
accounts: []
"#;
    let loaded_false: AppConfig = serde_yaml::from_str(explicit_false_yaml).unwrap();
    assert!(!loaded_false.settings.close_to_tray);

    // 4. Save and reload preserves setting
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let mut modified = AppConfig::default();
    modified.settings.close_to_tray = false;
    modified.save(&config_path).unwrap();

    let reloaded = AppConfig::load_or_create(Some(&config_path)).unwrap();
    assert!(!reloaded.settings.close_to_tray);
}

#[test]
fn test_database_relocate_and_swap() {
    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();

    let db1_path = dir1.path().join("db1.sqlite");
    let db2_path = dir2.path().join("db2.sqlite");

    let db = Database::open(&db1_path).unwrap();
    assert_eq!(db.path(), db1_path);

    // Insert an account and folder in db1
    db.upsert_account("acc1", "Account One", "acc1@example.com", "gmail").unwrap();
    db.get_or_create_folder("acc1", "INBOX", "inbox", None).unwrap();
    let stats = db.get_storage_stats().unwrap();
    assert_eq!(stats.total_accounts, 1);
    assert_eq!(stats.total_folders, 1);

    // Relocate database to db2_path
    db.relocate(&db2_path, true).unwrap();
    assert_eq!(db.path(), db2_path);
    assert!(db2_path.exists());

    // Verify existing data survived relocation
    let stats_after = db.get_storage_stats().unwrap();
    assert_eq!(stats_after.total_accounts, 1);
    assert_eq!(stats_after.total_folders, 1);
    let folders = db.get_folders("acc1").unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].remote_name, "INBOX");

    // Insert a new folder into relocated db
    db.get_or_create_folder("acc1", "Sent", "sent", None).unwrap();
    let stats_final = db.get_storage_stats().unwrap();
    assert_eq!(stats_final.total_folders, 2);
}

#[test]
fn test_event_log_operations() {
    use mailbackup_core::event_log::{clear_log, get_raw_log, get_recent_logs, log_event};

    clear_log().unwrap();

    log_event("ACCOUNT_ADDED", "Account 'Work' (work@corp.com) added");
    log_event("SYNC_SUCCESS", "Account 'Work': Synced 42 messages");

    let entries = get_recent_logs(10).unwrap();
    assert!(entries.len() >= 2);
    assert_eq!(entries[0].event_type, "SYNC_SUCCESS");
    assert!(entries[0].details.contains("42 messages"));

    let raw = get_raw_log().unwrap();
    assert!(raw.contains("[ACCOUNT_ADDED]"));
    assert!(raw.contains("[SYNC_SUCCESS]"));

    clear_log().unwrap();
}

#[test]
fn test_autostart_config_defaults() {
    let default_config = AppConfig::default();
    assert!(!default_config.settings.autostart);

    let yaml = r#"
data_dir: /tmp/mailbackup/data
db_path: /tmp/mailbackup/mailbackup.db
settings:
  default_schedule: "0 0 * * *"
  web_port: 8765
accounts: []
"#;
    let loaded: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(!loaded.settings.autostart);
    assert!(!loaded.settings.run_as_service);
}

#[test]
fn test_service_status_and_config() {
    use mailbackup_core::service::{find_server_executable, get_manual_install_command, get_manual_uninstall_command, get_service_status};
    use std::path::Path;

    let default_config = AppConfig::default();
    assert!(!default_config.settings.run_as_service);

    let status = get_service_status();
    assert!(!status.service_type.is_empty());
    assert!(!status.manual_install_cmd.is_empty());
    assert!(!status.manual_uninstall_cmd.is_empty());

    let exe = find_server_executable();
    let cmd = get_manual_install_command(&exe, Path::new("/custom/config.yaml"));
    assert!(cmd.contains("config.yaml"));

    let uninst = get_manual_uninstall_command();
    assert!(!uninst.is_empty());
}

#[tokio::test]
async fn test_scheduler_event_logging_and_listener() {
    use mailbackup_core::config::{AccountConfig, AuthType, FolderFilter, ProviderType};
    use mailbackup_core::db::Database;
    use mailbackup_core::event_log::clear_log;
    use mailbackup_core::keyring::CredentialStore;
    use mailbackup_core::scheduler::BackupScheduler;
    use mailbackup_core::storage::StorageEngine;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::tempdir;

    clear_log().unwrap();

    let dir = tempdir().unwrap();
    let db = Database::open(&dir.path().join("test.db")).unwrap();
    let storage = StorageEngine::new(&dir.path().join("storage"));
    let creds = Arc::new(CredentialStore::new());

    let mut config = AppConfig::default();
    config.accounts.push(AccountConfig {
        id: "acc_sched_test".to_string(),
        name: "Scheduled Test Acc".to_string(),
        email: "sched@example.com".to_string(),
        provider: ProviderType::GenericImap,
        imap_server: "127.0.0.1".to_string(),
        imap_port: 9993,
        use_tls: false,
        auth_type: AuthType::Password,
        username: "sched@example.com".to_string(),
        schedule: Some("0 0 1 1 *".to_string()), // Yearly, won't fire during test unless manual
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: false,
        enabled: true,
    });

    let mut scheduler = BackupScheduler::new(Arc::new(config), db, storage, creds).await.unwrap();
    let listener_invoked = Arc::new(AtomicBool::new(false));
    let listener_invoked_clone = listener_invoked.clone();

    scheduler.set_status_listener(Some(Arc::new(move |_id, _name, _status, _prog, _err| {
        listener_invoked_clone.store(true, Ordering::SeqCst);
    })));

    scheduler.start().await.unwrap();

    // Verify scheduler started without errors
    scheduler.shutdown().await.unwrap();
}




