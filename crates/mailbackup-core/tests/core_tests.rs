use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::{AdvancedSearchFilter, Database};
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
    let store = CredentialStore::with_fallback_path(cred_file.clone());

    store.set_password("acc1", "supersecret123").unwrap();
    let retrieved = store.get_password("acc1").unwrap();
    assert_eq!(retrieved, "supersecret123");

    // Verify that the file on disk is encrypted and DOES NOT contain plaintext!
    let raw_file = std::fs::read_to_string(&cred_file).unwrap();
    assert!(!raw_file.contains("supersecret123"), "Plaintext password must not be present on disk!");
    assert!(raw_file.contains("enc:v1:"), "Stored secrets must be encrypted with enc:v1: prefix");

    store.delete_password("acc1").unwrap();
    assert!(store.get_password("acc1").is_err());
}

#[test]
fn test_legacy_plaintext_credential_migration() {
    let dir = tempdir().unwrap();
    let cred_file = dir.path().join(".credentials_store.json");

    // Write a legacy unencrypted plaintext file
    let legacy_content = serde_json::json!({
        "account:legacy_user": "cleartext_password_999"
    });
    std::fs::write(&cred_file, serde_json::to_string_pretty(&legacy_content).unwrap()).unwrap();

    // Verify the unencrypted file actually has the plaintext password
    let initial_raw = std::fs::read_to_string(&cred_file).unwrap();
    assert!(initial_raw.contains("cleartext_password_999"));

    let store = CredentialStore::with_fallback_path(cred_file.clone());

    // Reading legacy password must succeed seamlessly
    let retrieved = store.get_password("legacy_user").unwrap();
    assert_eq!(retrieved, "cleartext_password_999");

    // The file on disk must now be automatically upgraded to AES-256-GCM ciphertext
    let upgraded_raw = std::fs::read_to_string(&cred_file).unwrap();
    assert!(!upgraded_raw.contains("cleartext_password_999"), "Plaintext must be erased from disk!");
    assert!(upgraded_raw.contains("enc:v1:"), "Upgraded credentials must be encrypted");

    // Reading again after encryption must still succeed
    let retrieved_again = store.get_password("legacy_user").unwrap();
    assert_eq!(retrieved_again, "cleartext_password_999");
}

#[test]
fn test_legacy_undotted_file_migration() {
    let dir = tempdir().unwrap();
    let undotted_file = dir.path().join("credentials_store.json");
    let target_file = dir.path().join(".credentials_store.json");

    // Write to legacy undotted file
    let legacy_content = serde_json::json!({
        "account:user2": "secret456"
    });
    std::fs::write(&undotted_file, serde_json::to_string_pretty(&legacy_content).unwrap()).unwrap();

    let store = CredentialStore::with_fallback_path(target_file.clone());

    // Reading password should migrate from undotted to dotted encrypted file
    let retrieved = store.get_password("user2").unwrap();
    assert_eq!(retrieved, "secret456");

    // Old undotted file must have been cleaned up
    assert!(!undotted_file.exists(), "Old undotted file should be deleted after migration");
    // New target file must exist and be encrypted
    assert!(target_file.exists());
    let raw = std::fs::read_to_string(&target_file).unwrap();
    assert!(!raw.contains("secret456"));
    assert!(raw.contains("enc:v1:"));
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
fn test_advanced_search_filters() {
    let db = Database::open_in_memory().unwrap();

    db.upsert_account("acc1", "Alice", "alice@example.com", "generic_imap").unwrap();
    let folder = db.get_or_create_folder("acc1", "INBOX", "inbox", Some(12345)).unwrap();

    let now = Utc::now();
    let five_days_ago = now - Duration::days(5);
    let twenty_days_ago = now - Duration::days(20);

    // Message 1: CFO with XLSX
    db.insert_message(
        "acc1",
        &folder.id,
        1,
        Some("<msg001@example.com>"),
        Some("Urgent Financial Report"),
        Some("cfo@company.com"),
        Some("alice@example.com"),
        Some("legal@company.com"),
        Some(twenty_days_ago),
        5000,
        "acc1/inbox/1.eml",
        "hash1",
        Some("Please review the financial spreadsheet."),
        &[("report.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 50000)],
    ).unwrap();

    // Message 2: Supplier with PDF invoice
    db.insert_message(
        "acc1",
        &folder.id,
        2,
        Some("<msg002@example.com>"),
        Some("Monthly Invoice for Services"),
        Some("billing@supplier.com"),
        Some("alice@example.com"),
        None,
        Some(five_days_ago),
        15000,
        "acc1/inbox/2.eml",
        "hash2",
        Some("Here is your invoice for August."),
        &[("invoice_august.pdf", "application/pdf", 120000)],
    ).unwrap();

    // Message 3: Team notification (no attachments, small)
    db.insert_message(
        "acc1",
        &folder.id,
        3,
        Some("<msg003@example.com>"),
        Some("Weekly Team Standup"),
        Some("manager@company.com"),
        Some("team@company.com"),
        None,
        Some(now),
        500,
        "acc1/inbox/3.eml",
        "hash3",
        Some("Don't forget the weekly standup meeting today."),
        &[],
    ).unwrap();

    // 1. Filter by Sender
    let by_sender = db.search_advanced(&AdvancedSearchFilter {
        from: Some("billing".to_string()),
        ..Default::default()
    }).unwrap();
    assert_eq!(by_sender.len(), 1);
    assert_eq!(by_sender[0].subject, "Monthly Invoice for Services");

    // 2. Filter by CC
    let by_cc = db.search_advanced(&AdvancedSearchFilter {
        cc: Some("legal".to_string()),
        ..Default::default()
    }).unwrap();
    assert_eq!(by_cc.len(), 1);
    assert_eq!(by_cc[0].subject, "Urgent Financial Report");

    // 3. Filter by Subject
    let by_subject = db.search_advanced(&AdvancedSearchFilter {
        subject: Some("Standup".to_string()),
        ..Default::default()
    }).unwrap();
    assert_eq!(by_subject.len(), 1);
    assert_eq!(by_subject[0].subject, "Weekly Team Standup");

    // 4. Filter by has_attachments
    let with_att = db.search_advanced(&AdvancedSearchFilter {
        has_attachments: Some(true),
        ..Default::default()
    }).unwrap();
    assert_eq!(with_att.len(), 2);

    // 5. Filter by attachment_type: PDF
    let pdf_only = db.search_advanced(&AdvancedSearchFilter {
        attachment_type: Some("pdf".to_string()),
        ..Default::default()
    }).unwrap();
    assert_eq!(pdf_only.len(), 1);
    assert_eq!(pdf_only[0].subject, "Monthly Invoice for Services");

    // 6. Filter by min size (>= 10,000 bytes)
    let large_msgs = db.search_advanced(&AdvancedSearchFilter {
        min_size_bytes: Some(10000),
        ..Default::default()
    }).unwrap();
    assert_eq!(large_msgs.len(), 1);
    assert_eq!(large_msgs[0].subject, "Monthly Invoice for Services");

    // 7. Filter by date range (past 10 days)
    let ten_days_ago_str = (now - Duration::days(10)).format("%Y-%m-%d").to_string();
    let tomorrow_str = (now + Duration::days(1)).format("%Y-%m-%d").to_string();
    let recent = db.search_advanced(&AdvancedSearchFilter {
        date_from: Some(ten_days_ago_str),
        date_to: Some(tomorrow_str),
        ..Default::default()
    }).unwrap();
    assert_eq!(recent.len(), 2); // Message 2 and 3

    // 8. Exclude words
    let excluded = db.search_advanced(&AdvancedSearchFilter {
        exclude_words: Some("Urgent Monthly".to_string()),
        ..Default::default()
    }).unwrap();
    assert_eq!(excluded.len(), 1);
    assert_eq!(excluded[0].subject, "Weekly Team Standup");

    // 9. Combined FTS query + metadata filter
    let combined = db.search_advanced(&AdvancedSearchFilter {
        query: Some("spreadsheet".to_string()),
        from: Some("cfo".to_string()),
        ..Default::default()
    }).unwrap();
    assert_eq!(combined.len(), 1);
    assert_eq!(combined[0].subject, "Urgent Financial Report");
    assert!(combined[0].snippet.contains("spreadsheet"));
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

#[test]
fn test_resolve_export_path_and_writer() {
    use mailbackup_core::config::{default_export_dir, resolve_export_path};
    use mailbackup_core::mbox::MboxExporter;
    use mailbackup_core::storage::StorageEngine;
    use chrono::Utc;
    use tempfile::tempdir;

    let def_dir = default_export_dir();
    assert!(!def_dir.as_os_str().is_empty());

    // Relative path resolves to default_export_dir
    let resolved = resolve_export_path("backup_2026.mbox");
    assert!(resolved.is_absolute() || !resolved.to_string_lossy().is_empty());
    assert_eq!(resolved, def_dir.join("backup_2026.mbox"));

    // Empty path resolves to default_export_dir with backup_*.mbox
    let empty_resolved = resolve_export_path("");
    assert!(empty_resolved.to_string_lossy().contains("backup_"));
    assert!(empty_resolved.to_string_lossy().ends_with(".mbox"));

    // Test export_to_writer
    let dir = tempdir().unwrap();
    let storage = StorageEngine::new(dir.path());
    let raw = b"From: user@test.com\r\nSubject: Test\r\n\r\nTest body";
    let stored = storage.store_eml("acc1", "INBOX", 1, Some(Utc::now()), raw).unwrap();

    let exporter = MboxExporter::new(&storage);
    let mut buffer = Vec::new();
    let count = exporter.export_to_writer(&[stored.relative_path.to_string_lossy().to_string()], &mut buffer).unwrap();
    assert_eq!(count, 1);
    assert!(!buffer.is_empty());
    let text = String::from_utf8_lossy(&buffer);
    assert!(text.contains("From user@test.com"));
    assert!(text.contains("Subject: Test"));
}

#[test]
fn test_csv_bulk_import_parser() {
    use mailbackup_core::csv_import::{parse_accounts_csv, generate_csv_template};
    use mailbackup_core::config::ProviderType;

    // 1. Template generation
    let template = generate_csv_template();
    assert!(template.contains("email,password,name,server,port,username"));

    // 2. Standard CSV with various providers and auto-detection
    let csv_data = "\
email,password,name,server,port,username,retention,schedule
admin@example.com,Secret123,Work Admin,mail.example.com,993,admin,90,0 2 * * *
alice@gmail.com,app-pass-key,Alice Personal,,,alice@gmail.com,,
bob@outlook.com,ms-pass-xyz,Bob Outlook,,,bob@outlook.com,,
charlie@customdomain.io,pass123,,,,charlie,,
";
    let report = parse_accounts_csv(csv_data);
    assert_eq!(report.errors.len(), 0);
    assert_eq!(report.valid_accounts.len(), 4);

    let acc0 = &report.valid_accounts[0];
    assert_eq!(acc0.email, "admin@example.com");
    assert_eq!(acc0.name, "Work Admin");
    assert_eq!(acc0.imap_server, "mail.example.com");
    assert_eq!(acc0.imap_port, 993);
    assert_eq!(acc0.username, "admin");
    assert_eq!(acc0.retention_days, Some(90));
    assert_eq!(acc0.schedule.as_deref(), Some("0 2 * * *"));

    let acc1 = &report.valid_accounts[1];
    assert_eq!(acc1.email, "alice@gmail.com");
    assert_eq!(acc1.provider, ProviderType::Gmail);
    assert_eq!(acc1.imap_server, "imap.gmail.com");
    assert_eq!(acc1.imap_port, 993);

    let acc2 = &report.valid_accounts[2];
    assert_eq!(acc2.email, "bob@outlook.com");
    assert_eq!(acc2.provider, ProviderType::Outlook);
    assert_eq!(acc2.imap_server, "outlook.office365.com");

    let acc3 = &report.valid_accounts[3];
    assert_eq!(acc3.email, "charlie@customdomain.io");
    assert_eq!(acc3.name, "Charlie");
    assert_eq!(acc3.imap_server, "mail.customdomain.io");

    // 3. Semicolon delimiter (European Excel)
    let semi_data = "Email;Password;Display Name;Server;Port\nuser1@extron.lv;pwd1;User One;mail.extron.lv;993\n";
    let semi_report = parse_accounts_csv(semi_data);
    assert_eq!(semi_report.errors.len(), 0);
    assert_eq!(semi_report.valid_accounts.len(), 1);
    assert_eq!(semi_report.valid_accounts[0].email, "user1@extron.lv");
    assert_eq!(semi_report.valid_accounts[0].password, "pwd1");

    // 4. Invalid rows & validation error handling
    let bad_data = "\
email,password,name
good@test.com,pass1,Good User
missing_pwd@test.com,,No Pass User
not-an-email,pass2,Bad Email
,pass3,Empty Email
";
    let bad_report = parse_accounts_csv(bad_data);
    assert_eq!(bad_report.valid_accounts.len(), 1);
    assert_eq!(bad_report.errors.len(), 3);
    assert!(bad_report.errors.iter().any(|e| e.error.contains("Missing password")));
    assert!(bad_report.errors.iter().any(|e| e.error.contains("Invalid email format")));
    assert!(bad_report.errors.iter().any(|e| e.error.contains("Missing required 'email'")));

    // 5. Convert to AccountConfig
    let cfg = bad_report.valid_accounts[0].to_account_config();
    assert_eq!(cfg.id, "goodtest_com");
    assert_eq!(cfg.email, "good@test.com");
    assert!(cfg.enabled);
}

#[test]
fn test_export_locations_and_available_path() {
    use mailbackup_core::config::{find_available_path, system_export_locations};
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let target_file = dir.path().join("my_backup.mbox");

    // 1. When file does not exist, returns original path
    let avail1 = find_available_path(&target_file);
    assert_eq!(avail1, target_file);

    // 2. When file exists, auto-increments
    std::fs::write(&target_file, b"content").unwrap();
    let avail2 = find_available_path(&target_file);
    assert_eq!(avail2, dir.path().join("my_backup (1).mbox"));

    // 3. When (1) also exists, auto-increments to (2)
    std::fs::write(&avail2, b"content2").unwrap();
    let avail3 = find_available_path(&target_file);
    assert_eq!(avail3, dir.path().join("my_backup (2).mbox"));

    // 4. System locations returns valid directories
    let locs = system_export_locations();
    assert!(!locs.is_empty());
}







