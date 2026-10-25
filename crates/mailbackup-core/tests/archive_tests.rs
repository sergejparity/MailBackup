//! Issue #31: "start a new archive" when an account moves to another server.

mod common;
use common::*;
use mailbackup_core::archive::{self, NewConnection};
use mailbackup_core::config::{AccountConfig, AppConfig};
use mailbackup_core::error::Error;
use mailbackup_core::keyring::{CredentialStore, NoKeyring};
use mailbackup_core::sync_gate::{self, SyncGate};
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct Setup {
    a: Archive,
    config_path: PathBuf,
    config: AppConfig,
    creds: Arc<CredentialStore>,
}

fn setup(server: &FakeImap, password: &str) -> Setup {
    let a = archive();
    let dir = a._dir.path();
    let config_path = dir.join("config.yaml");
    let config = AppConfig {
        data_dir: dir.join("data"),
        db_path: dir.join("catalog.db"),
        accounts: vec![account(server, "user")],
        ..Default::default()
    };
    config.save(&config_path).unwrap();
    let creds = Arc::new(
        CredentialStore::with_paths(dir.join(".credentials_store.json"), dir.join(".credentials_key"))
            .with_passphrase(None)
            .with_keyring(Arc::new(NoKeyring)),
    );
    creds.set_account_password(&config.accounts[0], password).unwrap();
    Setup { a, config_path, config, creds }
}

fn live(s: &Setup) -> AccountConfig {
    s.config.accounts.iter().find(|a| a.id == "acc").unwrap().clone()
}

fn on_disk(path: &Path) -> AppConfig {
    AppConfig::load_existing(path).unwrap().unwrap()
}

/// Subjects archived under `account_id`, sorted.
fn subjects_of(s: &Setup, account_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in s.a.db.get_folders(account_id).unwrap() {
        for m in s.a.db.get_messages_for_folder(&f.id).unwrap() {
            assert!(s.a.storage.read_eml(&m.relative_path).is_ok(), "{} readable", m.relative_path);
            out.push(m.subject.unwrap_or_default());
        }
    }
    out.sort();
    out
}

fn paths_of(s: &Setup, account_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in s.a.db.get_folders(account_id).unwrap() {
        out.extend(s.a.db.get_messages_for_folder(&f.id).unwrap().into_iter().map(|m| m.relative_path));
    }
    out
}

fn conn<'a>(server: &FakeImap, password: &'a str) -> NewConnection<'a> {
    NewConnection { server: "127.0.0.1", port: server.port, username: "user", password }
}

fn switch(s: &mut Setup, to: &FakeImap, password: &str) -> archive::Switched {
    let c = conn(to, password);
    archive::start_new_archive(&s.a.db, &s.creds, &mut s.config, &s.config_path, "acc", &c).unwrap()
}

#[tokio::test]
async fn a_b_a_gives_two_distinct_archives_and_a_fresh_live_account() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    server_b.set(Some(1), &[(1, &mail("B1"))]);
    let mut s = setup(&server_a, "pw-a");
    sync(&s.a, &server_a, &live(&s)).await;

    // A → B
    let first = switch(&mut s, &server_b, "pw-b");
    drop(first.gate);
    sync(&s.a, &server_b, &live(&s)).await;

    // B → A again, with A's mailbox having grown meanwhile
    server_a.set(Some(1), &[(1, &mail("A1")), (2, &mail("A2"))]);
    let second = switch(&mut s, &server_a, "pw-a2");
    drop(second.gate);
    sync(&s.a, &server_a, &live(&s)).await;

    let (arch1, arch2) = (first.archive.id.clone(), second.archive.id.clone());
    assert_ne!(arch1, arch2, "two archive epochs");
    assert!(arch1.ends_with("-1") && arch2.ends_with("-2"), "{} {}", arch1, arch2);
    assert_eq!(subjects_of(&s, &arch1), ["A1"]);
    assert_eq!(subjects_of(&s, &arch2), ["B1"]);
    assert_eq!(subjects_of(&s, "acc"), ["A1", "A2"], "the live account starts empty, then holds A again");

    // Distinct storage namespaces: nothing new lands in an archive's directory
    let live_now = live(&s);
    assert_eq!(live_now.storage_namespace(), "acc~2");
    assert!(paths_of(&s, &arch1).iter().all(|p| p.starts_with("acc/")));
    assert!(paths_of(&s, &arch2).iter().all(|p| p.starts_with("acc~1/")));
    assert!(paths_of(&s, "acc").iter().all(|p| p.starts_with("acc~2/")));

    // The config on disk agrees, archives are read-only and labelled honestly
    let disk = on_disk(&s.config_path);
    let a1 = disk.accounts.iter().find(|a| a.id == arch1).unwrap();
    let info = a1.archive.as_ref().unwrap();
    assert!(!a1.enabled && a1.retention_days.is_none() && a1.schedule.is_none());
    assert_eq!(info.retired_from, "acc");
    assert_eq!(info.last_source.as_deref(), Some(account(&server_a, "user").remote_identity().as_str()));

    // Only the current password is left, under its own reference
    assert_eq!(s.creds.get_account_password(&live_now).unwrap(), "pw-a2");
    assert!(s.creds.get_password("acc").unwrap_err().is_not_found(), "the first password is gone");
    assert!(s.creds.get_password("acc~cred-1").unwrap_err().is_not_found(), "so is the second");
}

#[tokio::test]
async fn a_failed_switch_changes_nothing_and_its_number_is_not_reused() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    let mut s = setup(&server_a, "pw-old");
    sync(&s.a, &server_a, &live(&s)).await;
    let before_disk = on_disk(&s.config_path);
    let before_mem = s.config.clone();

    let c = conn(&server_b, "pw-new");
    let err = archive::start_new_archive_with(
        &s.a.db, &s.creds, &mut s.config, &s.config_path, "acc", &c, chrono::Utc::now(),
        |_| Err(Error::Other("disk full".into())),
    )
    .err()
    .expect("fails");
    assert!(err.to_string().contains("disk full"));
    assert_eq!(s.config.accounts, before_mem.accounts, "in-memory config unchanged");
    assert_eq!(on_disk(&s.config_path).accounts, before_disk.accounts, "config on disk unchanged");
    assert_eq!(subjects_of(&s, "acc"), ["A1"], "the mail is back on the live account");
    assert_eq!(s.creds.get_account_password(&live(&s)).unwrap(), "pw-old", "the old connection still authenticates");
    assert!(s.creds.get_password("acc~cred-1").unwrap_err().is_not_found(), "nothing staged left");

    // The retry works and gets the next number
    let retried = switch(&mut s, &server_b, "pw-new");
    assert!(retried.archive.id.ends_with("-2"), "{}", retried.archive.id);
    assert_eq!(retried.live.storage_namespace(), "acc~2");
    assert_eq!(subjects_of(&s, &retried.archive.id), ["A1"]);
    drop(retried.gate);
    // And a later switch the one after
    let third = switch(&mut s, &server_a, "pw-third");
    assert!(third.archive.id.ends_with("-3"), "{}", third.archive.id);
}

/// A crash inside the switch, simulated by a panic at the config save: the
/// clean-up that a normal failure does is skipped, as in a real crash.
fn crash_at_save(s: &mut Setup, to: &FakeImap, password: &str, commit_first: bool) {
    let c = conn(to, password);
    let path = s.config_path.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        archive::start_new_archive_with(&s.a.db, &s.creds, &mut s.config, &s.config_path, "acc", &c, chrono::Utc::now(), |next| {
            if commit_first {
                next.save(&path).unwrap();
            }
            panic!("crash");
        })
    }));
    assert!(result.is_err(), "crashed");
}

#[tokio::test]
async fn a_crash_before_the_commit_is_rolled_back_with_the_old_password() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    let mut s = setup(&server_a, "pw-old");
    sync(&s.a, &server_a, &live(&s)).await;
    crash_at_save(&mut s, &server_b, "pw-new", false);
    assert_eq!(s.creds.get_password("acc~cred-1").unwrap(), "pw-new", "staged before the crash");

    // Next start: the config on disk has no archive, so the switch is undone
    let restarted = on_disk(&s.config_path);
    assert_eq!(archive::recover(&s.a.db, &s.creds, &s.config_path).unwrap(), 1);
    assert_eq!(subjects_of(&s, "acc"), ["A1"]);
    let acc = restarted.accounts.iter().find(|a| a.id == "acc").unwrap();
    assert_eq!(acc.imap_port, server_a.port, "still the old connection");
    assert_eq!(s.creds.get_account_password(acc).unwrap(), "pw-old", "which still authenticates");
    assert!(s.creds.get_password("acc~cred-1").unwrap_err().is_not_found(), "staged secret removed");
    assert_eq!(archive::recover(&s.a.db, &s.creds, &s.config_path).unwrap(), 0, "settled");
}

#[tokio::test]
async fn a_crash_after_the_commit_is_finished_with_the_new_password() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    let mut s = setup(&server_a, "pw-old");
    sync(&s.a, &server_a, &live(&s)).await;
    crash_at_save(&mut s, &server_b, "pw-new", true);

    let restarted = on_disk(&s.config_path);
    assert_eq!(archive::recover(&s.a.db, &s.creds, &s.config_path).unwrap(), 1);
    let acc = restarted.accounts.iter().find(|a| a.id == "acc").unwrap();
    assert_eq!(acc.imap_port, server_b.port, "the new connection stands");
    assert_eq!(s.creds.get_account_password(acc).unwrap(), "pw-new", "and authenticates");
    assert!(s.creds.get_password("acc").unwrap_err().is_not_found(), "the old secret is gone");
    let archive_id = restarted.accounts.iter().find(|a| a.is_archive()).unwrap().id.clone();
    assert_eq!(subjects_of(&s, &archive_id), ["A1"]);
    assert!(subjects_of(&s, "acc").is_empty());
}

#[tokio::test]
async fn a_process_already_running_settles_a_switch_another_one_crashed_in() {
    for commit_first in [false, true] {
        let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
        server_a.set(Some(1), &[(1, &mail("A1")), (2, &mail("A2"))]);
        server_b.set(Some(1), &[(1, &mail("B1"))]);
        let mut s = setup(&server_a, "pw-old");
        sync(&s.a, &server_a, &live(&s)).await;
        let snapshot = live(&s);
        // Another process crashes mid-switch; its lock dies with it, and no
        // restart (recovery) happens in this one
        crash_at_save(&mut s, &server_b, "pw-new", commit_first);

        // This process's next sync of the account settles the switch first
        let (gate, acc) = sync_gate::begin_account_sync(&s.a.db, &s.creds, &s.config_path, "acc").await.unwrap();
        assert!(s.a.db.prepared_transitions().unwrap().is_empty(), "commit_first={}: settled", commit_first);
        let password = s.creds.get_account_password(&acc).unwrap();
        drop(gate);
        let disk = on_disk(&s.config_path);
        if commit_first {
            assert_eq!((acc.imap_port, password.as_str()), (server_b.port, "pw-new"));
            sync(&s.a, &server_b, &acc).await;
            let archive_id = disk.accounts.iter().find(|a| a.is_archive()).unwrap().id.clone();
            assert_eq!(subjects_of(&s, &archive_id), ["A1", "A2"]);
            assert_eq!(subjects_of(&s, "acc"), ["B1"]);
        } else {
            assert_eq!(acc, snapshot, "the old account, as before the switch");
            assert_eq!(password, "pw-old");
            server_a.take_fetched();
            sync(&s.a, &server_a, &acc).await;
            assert!(server_a.take_fetched().is_empty(), "nothing downloaded again");
            assert_eq!(s.a.db.get_folders("acc").unwrap().len(), 1, "one INBOX, no duplicate folder");
            assert_eq!(subjects_of(&s, "acc"), ["A1", "A2"]);
            assert!(disk.accounts.iter().all(|a| !a.is_archive()));
        }
        // And a later switch starts clean
        s.config = disk;
        let next = switch(&mut s, if commit_first { &server_a } else { &server_b }, "pw-later");
        assert!(next.archive.id.ends_with("-2"), "{}", next.archive.id);
    }
}

#[tokio::test]
async fn a_switch_settles_one_another_process_crashed_in_first() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    let mut s = setup(&server_a, "pw-old");
    sync(&s.a, &server_a, &live(&s)).await;
    crash_at_save(&mut s, &server_b, "pw-new", false);

    let retried = switch(&mut s, &server_b, "pw-new");
    assert!(s.a.db.prepared_transitions().unwrap().is_empty());
    assert!(retried.archive.id.ends_with("-2"), "{}", retried.archive.id);
    assert_eq!(subjects_of(&s, &retried.archive.id), ["A1"]);
    assert!(subjects_of(&s, "acc").is_empty());
    assert!(s.creds.get_password("acc~cred-1").unwrap_err().is_not_found(), "the crashed attempt's secret is gone");
    assert_eq!(s.creds.get_account_password(&retried.live).unwrap(), "pw-new");
}

#[tokio::test]
async fn after_a_failed_switch_an_identical_new_copy_is_archived_as_well() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A"))]);
    let mut s = setup(&server_a, "pw-old");
    sync(&s.a, &server_a, &live(&s)).await;
    let c = conn(&server_b, "pw-new");
    archive::start_new_archive_with(
        &s.a.db, &s.creds, &mut s.config, &s.config_path, "acc", &c, chrono::Utc::now(),
        |_| Err(Error::Other("disk full".into())),
    )
    .err()
    .expect("fails");

    // The server gains a second, byte-identical copy at UID 2
    server_a.set(Some(1), &[(1, &mail("A")), (2, &mail("A"))]);
    server_a.take_fetched();
    sync(&s.a, &server_a, &live(&s)).await;
    assert_eq!(server_a.take_fetched(), [2], "only the new UID is downloaded");
    let rows = s.a.db.get_messages_for_folder(&inbox(&s.a).id).unwrap();
    let mut uids: Vec<u32> = rows.iter().map(|m| m.uid).collect();
    uids.sort();
    assert_eq!(uids, [1, 2], "both copies kept: UID 1 isn't re-bound to UID 2");
    assert_eq!(inbox(&s.a).last_synced_uid, 2);
}

#[tokio::test]
async fn a_sync_queued_behind_the_switch_uses_the_new_connection() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    server_b.set(Some(1), &[(1, &mail("B1"))]);
    let mut s = setup(&server_a, "pw-a");
    sync(&s.a, &server_a, &live(&s)).await;
    let logins_on_a = server_a.with(|mb| mb.connections);

    // While the switch holds the gate, a sync of the account starts and waits
    let c = conn(&server_b, "pw-b");
    let config_path = s.config_path.clone();
    let (db, creds) = (s.a.db.clone(), s.creds.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    let switched = archive::start_new_archive_with(
        &s.a.db, &s.creds, &mut s.config, &s.config_path, "acc", &c, chrono::Utc::now(),
        |next| {
            let path = config_path.clone();
            let (tx, db, creds) = (tx.clone(), db.clone(), creds.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let got = rt.block_on(sync_gate::begin_account_sync(&db, &creds, &path, "acc")).map(|(_, acc)| acc);
                tx.send(got).unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(300));
            next.save(&config_path)
        },
    )
    .unwrap();
    assert!(rx.try_recv().is_err(), "still waiting while the switch holds the gate");
    drop(switched.gate);
    let queued = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap().unwrap();
    assert_eq!(queued.imap_port, server_b.port, "it got the account as switched, not its old snapshot");
    sync(&s.a, &server_b, &queued).await;
    assert_eq!(subjects_of(&s, "acc"), ["B1"]);
    assert_eq!(server_a.with(|mb| mb.connections), logins_on_a, "the old server saw no connection after the switch");
}

#[tokio::test]
async fn syncs_of_archives_or_removed_accounts_are_refused_and_a_running_sync_blocks_the_switch() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    let mut s = setup(&server_a, "pw-a");

    // A sync holding the gate: the switch is refused, nothing changes
    let held = SyncGate::try_acquire(&s.config_path, "acc").unwrap().unwrap();
    let c = conn(&server_b, "pw-b");
    let err = archive::start_new_archive(&s.a.db, &s.creds, &mut s.config, &s.config_path, "acc", &c).err().unwrap();
    assert!(matches!(err, Error::AccountBusy(_)), "{}", err);
    assert!(s.config.accounts.iter().all(|a| !a.is_archive()));
    drop(held);

    let switched = switch(&mut s, &server_b, "pw-b");
    let archive_id = switched.archive.id.clone();
    drop(switched.gate);
    let refused = sync_gate::begin_account_sync(&s.a.db, &s.creds, &s.config_path, &archive_id).await.err().unwrap();
    assert!(matches!(refused, Error::AccountArchived(_)), "{}", refused);
    let gone = sync_gate::begin_account_sync(&s.a.db, &s.creds, &s.config_path, "nobody").await.err().unwrap();
    assert!(matches!(gone, Error::AccountNotFound(_)), "{}", gone);
}

#[tokio::test]
async fn a_session_that_selected_a_folder_before_the_switch_is_fenced() {
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("A1"))]);
    let mut s = setup(&server_a, "pw-a");
    sync(&s.a, &server_a, &live(&s)).await;
    let old = s.a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), &live(&s).remote_identity()).unwrap();

    let switched = switch(&mut s, &server_b, "pw-b");
    let stale = |r: mailbackup_core::error::Result<()>| matches!(r, Err(Error::StaleSync(_)));
    assert!(stale(s.a.db.update_folder_checkpoint(&old.folder.id, old.generation, 99)));
    assert!(stale(
        s.a.db
            .insert_message_in_generation(
                "acc", &old.folder.id, old.generation, 2, None, Some("late"), None, None, None, None, 1, "x.eml", "h", None, &[],
            )
            .map(|_| ())
    ));
    assert_eq!(subjects_of(&s, &switched.archive.id), ["A1"], "nothing written into the archive");
}

#[tokio::test]
async fn retention_of_the_live_account_never_touches_the_archive_and_the_archive_exports() {
    use mailbackup_core::mbox::MboxExporter;
    use mailbackup_core::retention::RetentionManager;
    let (server_a, server_b) = (FakeImap::start().await, FakeImap::start().await);
    server_a.set(Some(1), &[(1, &mail("Old1")), (2, &mail("Old2"))]);
    server_a.set_internal_dates(&[(1, "03-Mar-2020 10:00:00 +0000"), (2, "04-Mar-2020 10:00:00 +0000")]);
    let mut s = setup(&server_a, "pw-a");
    sync(&s.a, &server_a, &live(&s)).await;
    let switched = switch(&mut s, &server_b, "pw-b");
    drop(switched.gate);

    // The live account's retention (1 day) runs; the old archived mail stays
    let report = RetentionManager::new(&s.a.db, &s.a.storage).enforce_retention("acc", Some(1)).unwrap();
    assert_eq!(report.pruned_count, 0);
    assert_eq!(subjects_of(&s, &switched.archive.id), ["Old1", "Old2"]);

    // Exported like any account's mail
    let paths = paths_of(&s, &switched.archive.id);
    let mut mbox = Vec::new();
    assert_eq!(MboxExporter::new(&s.a.storage).export_to_writer(&paths, &mut mbox).unwrap(), 2);
    let text = String::from_utf8_lossy(&mbox);
    assert!(text.contains("Subject: Old1") && text.contains("Subject: Old2"));
    // And found by search
    assert_eq!(s.a.db.search_fts("Old1", 10).unwrap().len(), 1);
}
