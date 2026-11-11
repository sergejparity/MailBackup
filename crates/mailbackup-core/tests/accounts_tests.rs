//! Adding accounts never replaces one (issue #74).

use mailbackup_core::accounts::{self, ImportAction, NewAccount};
use mailbackup_core::config::{AppConfig, ArchiveInfo, ProviderType};
use mailbackup_core::csv_import::parse_accounts_csv;
use mailbackup_core::db::Database;
use mailbackup_core::keyring::{CredentialStore, NoKeyring};
use mailbackup_core::storage::StorageEngine;
use mailbackup_core::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
    db: Database,
    storage: StorageEngine,
    credentials: Arc<CredentialStore>,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let credentials = Arc::new(
        CredentialStore::with_paths(root.join(".credentials_store.json"), root.join(".credentials_key"))
            .with_passphrase(None)
            .with_keyring(Arc::new(NoKeyring)),
    );
    Env {
        config_path: root.join("config.yaml"),
        db: Database::open(root.join("catalog.db")).unwrap(),
        storage: StorageEngine::new(root.join("data")),
        credentials,
        root,
        _dir: dir,
    }
}

fn config(root: &Path) -> AppConfig {
    AppConfig { data_dir: root.join("data"), db_path: root.join("catalog.db"), ..AppConfig::default() }
}

fn new(email: &str, password: &str) -> NewAccount {
    NewAccount {
        name: email.to_string(),
        email: email.to_string(),
        provider: ProviderType::GenericImap,
        imap_server: "imap.example.com".to_string(),
        imap_port: 993,
        username: email.to_string(),
        password: password.to_string(),
        schedule: None,
        retention_days: None,
        requested_id: None,
    }
}

fn create(e: &Env, cfg: &mut AppConfig, account: NewAccount) -> mailbackup_core::Result<mailbackup_core::config::AccountConfig> {
    accounts::create(cfg, &e.config_path, &e.db, &e.storage, &e.credentials, account)
}

fn password_of(e: &Env, cfg: &AppConfig, id: &str) -> String {
    e.credentials.get_account_password(cfg.account_by_id(id).unwrap()).unwrap()
}

#[test]
fn addresses_with_the_same_slug_get_different_accounts() {
    let e = env();
    let mut cfg = config(&e.root);
    let first = create(&e, &mut cfg, new("a.b@example.com", "first-pw")).unwrap();
    let second = create(&e, &mut cfg, new("a_b@example.com", "second-pw")).unwrap();
    let third = create(&e, &mut cfg, new("a.b+x@example.com", "x")).unwrap();
    let fourth = create(&e, &mut cfg, new("a.bx@example.com", "y")).unwrap();

    assert_eq!(first.id, "a_bexample_com");
    assert_eq!(second.id, "a_bexample_com-2");
    assert_eq!(third.id, "a_bxexample_com");
    assert_eq!(fourth.id, "a_bxexample_com-2");
    assert_eq!(password_of(&e, &cfg, &first.id), "first-pw", "the first account's password is untouched");
    assert_eq!(password_of(&e, &cfg, &second.id), "second-pw");

    let saved = AppConfig::load_existing(&e.config_path).unwrap().unwrap();
    assert_eq!(saved.accounts.len(), 4);
    assert_eq!(saved.account_by_id(&first.id).unwrap().email, "a.b@example.com");
}

#[test]
fn the_same_address_twice_is_refused_and_writes_nothing() {
    let e = env();
    let mut cfg = config(&e.root);
    let first = create(&e, &mut cfg, new("me@example.com", "original")).unwrap();
    let saved = std::fs::read_to_string(&e.config_path).unwrap();

    for again in ["me@example.com", "  ME@Example.com "] {
        let err = create(&e, &mut cfg, new(again, "replacement")).unwrap_err();
        assert!(matches!(err, Error::AccountExists(_)), "{:?}", err);
    }
    assert_eq!(cfg.accounts.len(), 1);
    assert_eq!(std::fs::read_to_string(&e.config_path).unwrap(), saved);
    assert_eq!(password_of(&e, &cfg, &first.id), "original");
}

#[test]
fn an_address_whose_live_account_is_gone_can_be_added_beside_its_archive() {
    let e = env();
    let mut cfg = config(&e.root);
    let live = create(&e, &mut cfg, new("me@example.com", "pw")).unwrap();
    // Retire it: what remains is a read-only archive with the same address
    let archive = cfg.account_by_id_mut(&live.id).unwrap();
    archive.id = format!("{}~archive-1", live.id);
    archive.storage_namespace = Some(live.id.clone());
    archive.credential_ref = Some(live.id.clone());
    archive.archive = Some(ArchiveInfo { archived_at: chrono::Utc::now(), retired_from: live.id.clone(), last_source: None });
    cfg.save(&e.config_path).unwrap();

    let again = create(&e, &mut cfg, new("me@example.com", "new-pw")).unwrap();
    assert_ne!(again.id, live.id, "the archive still owns the old namespace and credential name");
    assert_eq!(cfg.get_account("me@example.com").unwrap().id, again.id, "the address names the live account");
}

#[test]
fn names_used_anywhere_are_not_handed_out() {
    let e = env();
    let mut cfg = config(&e.root);
    // A folder in the data directory, catalog rows, a transition and a stored
    // password each make a name taken
    std::fs::create_dir_all(e.storage.base_dir().join("direxample_com")).unwrap();
    e.db.get_or_create_folder("rowsexample_com", "INBOX", "INBOX", Some(1)).unwrap();
    e.db.prepare_account_transition(&mailbackup_core::db::NewTransition {
        live_id: "liveexample_com",
        archive_id: "archexample_com",
        seq: 1,
        old_credential_ref: "oldexample_com",
        staged_credential_ref: "stagedexample_com",
    })
    .unwrap();
    e.credentials.set_password("credexample_com", "someone else's").unwrap();

    for (email, taken) in [
        ("dir@example.com", "direxample_com"),
        ("rows@example.com", "rowsexample_com"),
        ("live@example.com", "liveexample_com"),
        ("arch@example.com", "archexample_com"),
        ("old@example.com", "oldexample_com"),
        ("staged@example.com", "stagedexample_com"),
        ("cred@example.com", "credexample_com"),
    ] {
        let account = create(&e, &mut cfg, new(email, "pw")).unwrap();
        assert_eq!(account.id, format!("{}-2", taken), "{}", email);
    }
    assert_eq!(e.credentials.get_password("credexample_com").unwrap(), "someone else's");
}

#[test]
fn a_requested_id_that_is_taken_is_refused() {
    let e = env();
    let mut cfg = config(&e.root);
    create(&e, &mut cfg, new("me@example.com", "pw")).unwrap();
    let mut other = new("other@example.com", "pw");
    other.requested_id = Some("meexample_com".to_string());
    assert!(matches!(create(&e, &mut cfg, other).unwrap_err(), Error::AccountExists(_)));
}

#[test]
fn accounts_another_process_saved_are_respected() {
    let e = env();
    // Another process saved an account this process's copy doesn't know
    let mut theirs = config(&e.root);
    create(&e, &mut theirs, new("a.b@example.com", "theirs")).unwrap();

    let mut ours = config(&e.root);
    assert!(matches!(create(&e, &mut ours, new("a.b@example.com", "ours")).unwrap_err(), Error::AccountExists(_)));
    let account = create(&e, &mut ours, new("a_b@example.com", "ours")).unwrap();
    assert_eq!(account.id, "a_bexample_com-2");
    assert_eq!(e.credentials.get_password("a_bexample_com").unwrap(), "theirs");

    // Both accounts are in the file: the older copy didn't replace theirs
    let saved = AppConfig::load_existing(&e.config_path).unwrap().unwrap();
    let mut ids: Vec<_> = saved.accounts.iter().map(|a| a.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["a_bexample_com", "a_bexample_com-2"]);
    // and this process's copy now knows theirs too
    assert!(ours.account_by_id("a_bexample_com").is_some());
}

#[test]
fn a_creation_keeps_the_settings_another_process_saved() {
    let e = env();
    let mut theirs = config(&e.root);
    theirs.settings.web_port = 9999;
    theirs.save(&e.config_path).unwrap();

    let mut ours = config(&e.root);
    create(&e, &mut ours, new("me@example.com", "pw")).unwrap();
    let saved = AppConfig::load_existing(&e.config_path).unwrap().unwrap();
    assert_eq!(saved.settings.web_port, 9999, "their setting is kept");
    assert_eq!(saved.accounts.len(), 1);
}

#[test]
fn concurrent_creations_with_colliding_slugs_keep_both_passwords() {
    for _ in 0..10 {
        let e = Arc::new(env());
        let handles: Vec<_> = ["a.b@example.com", "a_b@example.com", "a b@example.com"]
            .into_iter()
            .map(|email| {
                let e = e.clone();
                std::thread::spawn(move || {
                    // Each its own copy of the config, as separate processes have
                    let mut cfg = config(&e.root);
                    create(&e, &mut cfg, new(email, &format!("pw of {}", email))).unwrap()
                })
            })
            .collect();
        let created: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let mut ids: Vec<_> = created.iter().map(|a| a.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3, "every creation got its own id: {:?}", ids);
        for account in &created {
            assert_eq!(e.credentials.get_account_password(account).unwrap(), format!("pw of {}", account.email));
        }
        // Every account survives in the file, whichever copy saved last
        let saved = AppConfig::load_existing(&e.config_path).unwrap().unwrap();
        let mut saved_ids: Vec<_> = saved.accounts.iter().map(|a| a.id.clone()).collect();
        saved_ids.sort();
        assert_eq!(saved_ids, ids, "all three accounts are in the saved config");
    }
}

#[cfg(unix)]
#[test]
fn a_failed_save_leaves_the_accounts_and_passwords_as_they_were() {
    let e = env();
    let mut cfg = config(&e.root);
    let first = create(&e, &mut cfg, new("a.b@example.com", "original")).unwrap();

    // The config is now a symlink to a folder that doesn't exist: reading it
    // finds nothing, writing it fails
    let broken = e.root.join("broken.yaml");
    std::os::unix::fs::symlink(e.root.join("missing").join("config.yaml"), &broken).unwrap();
    let err = accounts::create(&mut cfg, &broken, &e.db, &e.storage, &e.credentials, new("a_b@example.com", "new"));
    assert!(err.is_err());
    assert_eq!(cfg.accounts.len(), 1, "the in-memory config is unchanged");
    assert_eq!(password_of(&e, &cfg, &first.id), "original");
    assert!(e.credentials.get_password("a_bexample_com-2").unwrap_err().is_not_found(), "no stray password is left");
}

#[test]
fn csv_import_plans_against_existing_accounts_and_the_file_itself() {
    let e = env();
    let mut cfg = config(&e.root);
    create(&e, &mut cfg, new("old@example.com", "pw")).unwrap();
    let csv = "email,password\nold@example.com,pw\nnew@example.com,pw\ntwice@example.com,a\nTWICE@example.com,b\n";
    let report = parse_accounts_csv(csv);
    assert_eq!(report.valid_accounts.len(), 4);

    let (plan, errors) = accounts::plan_import(&cfg, &report.valid_accounts, false);
    assert_eq!(plan, vec![(1, ImportAction::Create)]);
    let lines: Vec<usize> = errors.iter().map(|e| e.line).collect();
    assert_eq!(lines, [2, 4, 5]);
    assert!(errors[0].error.contains("already exists"), "{}", errors[0].error);
    assert!(errors[1].error.contains("more than once"), "{}", errors[1].error);

    let (plan, errors) = accounts::plan_import(&cfg, &report.valid_accounts, true);
    assert_eq!(plan, vec![(0, ImportAction::Update("oldexample_com".to_string())), (1, ImportAction::Create)]);
    assert_eq!(errors.len(), 2, "duplicates within the file stay errors");
}

#[test]
fn a_csv_update_changes_only_what_the_row_may_change() {
    let e = env();
    let mut cfg = config(&e.root);
    let account = create(&e, &mut cfg, new("me@example.com", "old-pw")).unwrap();
    {
        let a = cfg.account_by_id_mut(&account.id).unwrap();
        a.storage_namespace = Some("kept-namespace".to_string());
        a.credential_ref = Some("kept-cred".to_string());
        a.trust_server_ids = true;
        a.enabled = false;
        a.folder_filter.exclude = vec!["Kept".to_string()];
    }
    let before = cfg.account_by_id(&account.id).unwrap().clone();
    let csv = "email,password,name,server,port,username,schedule\nme@example.com,new-pw,Renamed,mail.other.org,143,login,0 4 * * *\n";
    let row = &parse_accounts_csv(csv).valid_accounts[0];

    let updated = accounts::update_from_row(&mut cfg, &e.config_path, &e.credentials, &account.id, row).unwrap();
    assert_eq!(updated.name, "Renamed");
    assert_eq!((updated.imap_server.as_str(), updated.imap_port, updated.username.as_str()), ("mail.other.org", 143, "login"));
    assert_eq!(updated.schedule.as_deref(), Some("0 4 * * *"));
    assert_eq!(updated.storage_namespace, before.storage_namespace);
    assert_eq!(updated.credential_ref, before.credential_ref);
    assert_eq!(updated.trust_server_ids, before.trust_server_ids);
    assert_eq!(updated.enabled, before.enabled);
    assert_eq!(updated.folder_filter, before.folder_filter);
    assert_eq!(updated.id, before.id);
    // The new password is bound to the new connection
    assert_eq!(e.credentials.get_account_password(&updated).unwrap(), "new-pw");
    assert!(e.credentials.get_account_password(&before).is_err(), "not usable for the old server");
}

#[test]
fn a_csv_update_never_touches_an_archive() {
    let e = env();
    let mut cfg = config(&e.root);
    let account = create(&e, &mut cfg, new("me@example.com", "pw")).unwrap();
    cfg.account_by_id_mut(&account.id).unwrap().archive =
        Some(ArchiveInfo { archived_at: chrono::Utc::now(), retired_from: "x".into(), last_source: None });
    let row = &parse_accounts_csv("email,password\nme@example.com,other\n").valid_accounts[0];
    let err = accounts::update_from_row(&mut cfg, &e.config_path, &e.credentials, &account.id, row).unwrap_err();
    assert!(matches!(err, Error::AccountArchived(_)));
    // And the planner doesn't offer it: archives aren't live accounts
    let (plan, _) = accounts::plan_import(&cfg, std::slice::from_ref(row), true);
    assert_eq!(plan, vec![(0, ImportAction::Create)]);
}

#[test]
fn lookups_by_address_are_never_ambiguous() {
    let e = env();
    let mut cfg = config(&e.root);
    let one = create(&e, &mut cfg, new("one@example.com", "pw")).unwrap();
    // An account whose id is another account's address
    let mut tricky = new("two@example.com", "pw");
    tricky.requested_id = Some("one@example.com".to_string());
    let two = create(&e, &mut cfg, tricky).unwrap();
    assert_eq!(cfg.get_account("one@example.com").unwrap().id, two.id, "an id wins over an address");
    assert_eq!(cfg.account_by_id(&one.id).unwrap().email, "one@example.com");
    assert!(cfg.account_by_id("two@example.com").is_none(), "exact lookups don't match addresses");
}
