//! Schedules that don't parse (issue #71): they are refused on input, cost
//! only their own account its scheduled backup, and never stop a scheduler
//! that is already running.

use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::Database;
use mailbackup_core::keyring::{CredentialStore, NoKeyring};
use mailbackup_core::scheduler::{validate_schedule, BackupScheduler, FALLBACK_SCHEDULE};
use mailbackup_core::storage::StorageEngine;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NEVER: &str = "0 0 1 1 *";
const EVERY_SECOND: &str = "* * * * * *";

fn account(id: &str, schedule: Option<&str>) -> AccountConfig {
    AccountConfig {
        id: id.to_string(),
        name: format!("Account {}", id),
        email: format!("{}@example.com", id),
        provider: ProviderType::GenericImap,
        imap_server: "127.0.0.1".to_string(),
        imap_port: 9,
        use_tls: true,
        auth_type: AuthType::Password,
        username: id.to_string(),
        schedule: schedule.map(str::to_string),
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: false,
        enabled: true,
        storage_namespace: None,
        credential_ref: None,
        archive: None,
        trust_server_ids: false,
    }
}

fn config(dir: &std::path::Path, accounts: Vec<AccountConfig>) -> AppConfig {
    AppConfig { data_dir: dir.join("data"), db_path: dir.join("catalog.db"), accounts, ..AppConfig::default() }
}

async fn scheduler(dir: &std::path::Path, config: AppConfig) -> BackupScheduler {
    let db = Database::open_in_memory().unwrap();
    let storage = StorageEngine::new(&config.data_dir);
    let credentials = Arc::new(
        CredentialStore::with_paths(dir.join(".credentials_store.json"), dir.join(".credentials_key"))
            .with_passphrase(None)
            .with_keyring(Arc::new(NoKeyring)),
    );
    BackupScheduler::new(Arc::new(config), db, storage, credentials).await.unwrap()
}

/// How often each account's job has started, counted by a status listener.
type Starts = Arc<Mutex<HashMap<String, usize>>>;

fn count_starts(scheduler: &mut BackupScheduler) -> Starts {
    let starts: Starts = Arc::default();
    let counted = starts.clone();
    scheduler.set_status_listener(Some(Arc::new(move |id, _name, event, _progress, _error| {
        if event == "started" {
            *counted.lock().unwrap().entry(id.to_string()).or_default() += 1;
        }
    })));
    starts
}

async fn wait_for_start(starts: &Starts, account: &str, more_than: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while starts.lock().unwrap().get(account).copied().unwrap_or(0) <= more_than {
        assert!(std::time::Instant::now() < deadline, "the job of '{}' didn't fire", account);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn schedules_are_validated_with_the_schedulers_parser() {
    assert_eq!(validate_schedule("0 3 * * *").unwrap(), "0 0 3 * * *");
    assert_eq!(validate_schedule(" */15 * * * * ").unwrap(), "0 */15 * * * *");
    assert_eq!(validate_schedule(EVERY_SECOND).unwrap(), EVERY_SECOND);
    assert!(validate_schedule(FALLBACK_SCHEDULE).is_ok());
    for bad in ["", "   ", "daily", "99 99 * * *", "0 0 * *", "* * * * * * * *", "0 0 * * mon-xyz"] {
        let e = validate_schedule(bad).unwrap_err();
        assert!(matches!(e, mailbackup_core::Error::InvalidInput(_)), "{:?}: {:?}", bad, e);
    }
}

#[tokio::test]
async fn one_invalid_schedule_leaves_the_other_accounts_scheduled() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        vec![account("first", Some(NEVER)), account("broken", Some("not a schedule")), account("last", Some(EVERY_SECOND))],
    );
    let mut scheduler = scheduler(dir.path(), cfg).await;
    let starts = count_starts(&mut scheduler);

    scheduler.start().await.expect("the scheduler starts without the broken account");
    let status = scheduler.status().clone();
    assert!(status.running);
    assert_eq!(status.scheduled_accounts, 2);
    assert_eq!(status.skipped.len(), 1);
    assert_eq!(status.skipped[0].account_id, "broken");
    assert_eq!(status.skipped[0].schedule, "not a schedule");
    assert!(status.default_schedule_error.is_none());

    // The account registered after the broken one really runs
    wait_for_start(&starts, "last", 0).await;
    assert!(!starts.lock().unwrap().contains_key("broken"));
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_invalid_default_schedule_falls_back_for_the_accounts_inheriting_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), vec![account("inherits", None), account("own", Some(NEVER))]);
    cfg.settings.default_schedule = "every now and then".to_string();
    let mut scheduler = scheduler(dir.path(), cfg).await;

    scheduler.start().await.unwrap();
    let status = scheduler.status();
    assert!(status.running);
    assert_eq!(status.scheduled_accounts, 2, "the inheriting account runs on the fallback");
    assert!(status.skipped.is_empty());
    assert!(status.default_schedule_error.as_deref().is_some_and(|e| e.contains("every now and then")));
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabled_accounts_and_archives_are_neither_scheduled_nor_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut off = account("off", Some("garbage"));
    off.enabled = false;
    let mut scheduler = scheduler(dir.path(), config(dir.path(), vec![off, account("on", Some(NEVER))])).await;
    scheduler.start().await.unwrap();
    assert_eq!(scheduler.status().scheduled_accounts, 1);
    assert!(scheduler.status().skipped.is_empty());
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_reload_that_brings_an_invalid_schedule_keeps_the_valid_jobs_running() {
    let dir = tempfile::tempdir().unwrap();
    let mut scheduler = scheduler(dir.path(), config(dir.path(), vec![account("steady", Some(EVERY_SECOND))])).await;
    let starts = count_starts(&mut scheduler);
    scheduler.start().await.unwrap();
    wait_for_start(&starts, "steady", 0).await;

    let changed = config(dir.path(), vec![account("steady", Some(EVERY_SECOND)), account("broken", Some("@nonsense"))]);
    scheduler.reload(Arc::new(changed)).await.expect("an invalid expression doesn't fail the reload");
    let status = scheduler.status().clone();
    assert!(status.running);
    assert_eq!(status.scheduled_accounts, 1);
    assert_eq!(status.skipped.iter().map(|s| s.account_id.as_str()).collect::<Vec<_>>(), ["broken"]);
    assert!(status.last_reload_error.is_none());

    // Still firing after the reload
    let before = starts.lock().unwrap()["steady"];
    wait_for_start(&starts, "steady", before + 1).await;

    // Fixing the schedule clears the report
    let fixed = config(dir.path(), vec![account("steady", Some(EVERY_SECOND)), account("broken", Some(NEVER))]);
    scheduler.reload(Arc::new(fixed)).await.unwrap();
    assert!(scheduler.status().skipped.is_empty());
    assert_eq!(scheduler.status().scheduled_accounts, 2);
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn reading_the_status_writes_no_events() {
    let dir = tempfile::tempdir().unwrap();
    let mut scheduler = scheduler(dir.path(), config(dir.path(), vec![account("broken", Some("nope"))])).await;
    scheduler.start().await.unwrap();
    let logged = || mailbackup_core::event_log::get_raw_log().unwrap_or_default().matches("Account 'Account broken'").count();
    let after_start = logged();
    for _ in 0..50 {
        assert_eq!(scheduler.status().skipped.len(), 1);
    }
    assert_eq!(logged(), after_start);
    scheduler.shutdown().await.unwrap();
}

/// The edit form used to suggest "every 6h", which the scheduler can't parse
#[test]
fn shorthands_the_parser_knows_are_accepted_and_english_phrases_are_not() {
    for ok in ["@daily", "@hourly", "0 */6 * * *"] {
        assert!(validate_schedule(ok).is_ok(), "{:?}", ok);
    }
    for bad in ["every 6h", "every 6 hours", "every 30 minutes"] {
        let message = validate_schedule(bad).unwrap_err().to_string();
        assert!(message.contains(bad) && message.contains("0 3 * * *"), "{}", message);
    }
}
