//! Issue #17: when a folder's remote UIDs stop being comparable (new
//! UIDVALIDITY, another server or username), sync re-scans the folder, keeps
//! what was archived and doesn't store a message twice.
//!
//! The tests sync against a small in-process IMAP server (`common`) over
//! plain TCP, compressed with COMPRESS=DEFLATE as the server offers it.

mod common;
use common::*;

// --- Tests ---------------------------------------------------------------

#[tokio::test]
async fn a_new_uidvalidity_rescans_and_keeps_the_old_message() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A"]);

    // The mailbox is renumbered: UID 1 is now a different message
    server.set(Some(2), &[(1, &mail("B"))]);
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1], "UID 1 fetched again");
    assert_eq!(subjects(&a), ["A", "B"], "B archived, A kept");
    let all = archived(&a);
    assert_eq!(all[0].1, mail(all[0].0.subject.as_deref().unwrap()), "both files readable and intact");
    assert_eq!(all[1].1, mail(all[1].0.subject.as_deref().unwrap()));
    assert_ne!(all[0].0.relative_path, all[1].0.relative_path);
    let folder = inbox(&a);
    assert_eq!((folder.uid_generation, folder.uidvalidity), (1, Some(2)));
}

#[tokio::test]
async fn a_new_server_or_username_rescans_even_with_the_same_uidvalidity() {
    let (a, server) = (archive(), FakeImap::start().await);
    server.set(Some(1), &[(1, &mail("A"))]);
    sync(&a, &server, &account(&server, "old-user")).await;

    // Another mailbox behind the same numeric UIDVALIDITY
    server.set(Some(1), &[(1, &mail("B"))]);
    server.take_fetched();
    sync(&a, &server, &account(&server, "new-user")).await;
    assert_eq!(server.take_fetched(), [1]);
    assert_eq!(subjects(&a), ["A", "B"]);
    assert_eq!(inbox(&a).remote_identity.as_deref(), Some(account(&server, "new-user").remote_identity().as_str()));
}

#[tokio::test]
async fn a_rescan_recognizes_archived_messages_by_content() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("X"))]);
    sync(&a, &server, &acc).await;
    let a_id = archived(&a)[0].0.id.clone();
    assert_eq!(eml_files(&a), 2);

    server.set(Some(2), &[(7, &mail("A")), (8, &mail("C"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "C", "X"], "only C is new");
    assert_eq!(eml_files(&a), 3, "A isn't stored a second time");
    let rebound = archived(&a).into_iter().find(|(m, _)| m.id == a_id).unwrap().0;
    assert_eq!(rebound.uid, 7, "A's archived copy now stands for UID 7");

    // And nothing is fetched again on the next sync
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty());
}

#[tokio::test]
async fn identical_copies_keep_their_number() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "A"]);

    server.set(Some(2), &[(5, &mail("A")), (6, &mail("A")), (7, &mail("A"))]);
    sync(&a, &server, &acc).await;
    let uids: Vec<u32> = archived(&a).iter().map(|(m, _)| m.uid).collect();
    assert_eq!(uids, [5, 6, 7], "two copies re-bound, one new");
}

#[tokio::test]
async fn an_unchanged_mailbox_fetches_nothing_again() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1, 2]);

    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty());
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B")), (3, &mail("C"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [3], "incremental");
    assert_eq!(inbox(&a).uid_generation, 0);
}

#[tokio::test]
async fn a_first_reported_uidvalidity_rescans_once() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(None, &[(1, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(inbox(&a).uidvalidity, None);

    server.set(Some(9), &[(1, &mail("A")), (2, &mail("B"))]);
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1, 2], "re-scanned");
    assert_eq!(subjects(&a), ["A", "B"], "A recognized, not duplicated");
    let folder = inbox(&a);
    assert_eq!((folder.uid_generation, folder.uidvalidity), (1, Some(9)));

    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty(), "only once");
}

#[tokio::test]
async fn an_interrupted_rescan_resumes_without_gaps_or_duplicates() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    sync(&a, &server, &acc).await;

    let renumbered = [(11, mail("A")), (12, mail("B")), (13, mail("C")), (14, mail("D"))];
    let refs: Vec<(u32, &[u8])> = renumbered.iter().map(|(u, m)| (*u, m.as_slice())).collect();
    server.set(Some(2), &refs);
    server.fail_fetch_of(13);
    server.take_fetched();
    sync(&a, &server, &acc).await; // stops at UID 13
    assert_eq!(server.take_fetched(), [11, 12]);
    let generation = inbox(&a).uid_generation;

    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [13, 14], "resumed after the checkpoint");
    assert_eq!(inbox(&a).uid_generation, generation, "same generation");
    assert_eq!(subjects(&a), ["A", "B", "C", "D"]);
    let uids: Vec<u32> = archived(&a).iter().map(|(m, _)| m.uid).collect();
    assert_eq!(uids, [11, 12, 13, 14]);
}

#[tokio::test]
async fn folders_archived_before_generations_are_rescanned_once() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    // What 0.3.x left behind: a folder without an identity, holding A at UID 1
    let folder = a.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let stored = a.storage.store_eml("acc", "INBOX", 1, None, &mail("A")).unwrap();
    a.db.insert_message(
        "acc", &folder.id, 1, None, Some("A"), None, None, None, None, stored.size_bytes,
        &stored.relative_path.to_string_lossy(), &stored.sha256, None, &[],
    )
    .unwrap();
    a.db.update_folder_sync_state(&folder.id, 1).unwrap();
    assert_eq!(inbox(&a).remote_identity, None);

    // The config had since moved to another mailbox with the same UIDVALIDITY
    server.set(Some(1), &[(1, &mail("B"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1], "UID 1 not trusted to still be A");
    assert_eq!(subjects(&a), ["A", "B"]);

    // An empty legacy folder just adopts the identity
    let (b, server2) = (archive(), FakeImap::start().await);
    b.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    server2.set(Some(1), &[(1, &mail("A"))]);
    sync(&b, &server2, &account(&server2, "user")).await;
    assert_eq!(inbox(&b).uid_generation, 0);
    assert_eq!(server2.take_fetched(), [1]);
}

#[tokio::test]
async fn a_superseded_session_cannot_write() {
    let a = archive();
    // Session A begins on the old server, then the account moves and B begins
    let old = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "old:993:u").unwrap();
    let new = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "new:993:u").unwrap();
    assert_eq!(new.generation, old.generation + 1, "a connection change starts a new generation");
    assert!(stale_result(a.db.update_folder_checkpoint(&old.folder.id, old.generation, 1)));

    let stored = a.storage.store_eml("acc", "INBOX", 1, None, &mail("A")).unwrap();
    let path = stored.relative_path.to_string_lossy().to_string();
    a.db.insert_message_in_generation(
        "acc", &new.folder.id, new.generation, 1, None, Some("A"), None, None, None, None,
        stored.size_bytes, &path, &stored.sha256, None, &[],
    )
    .unwrap();
    let first = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "new:993:u").unwrap();
    let second = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "other:993:u").unwrap();
    assert_eq!(first.generation, new.generation, "same connection: same generation");
    assert_eq!(second.generation, first.generation + 1);
    a.db.update_folder_checkpoint(&second.folder.id, second.generation, 5).unwrap();

    // The first session wakes up and tries to write old-server UIDs
    assert!(stale_result(a.db.insert_message_in_generation(
        "acc", &first.folder.id, first.generation, 2, None, Some("old"), None, None, None, None,
        1, "x.eml", "deadbeef", None, &[],
    )));
    assert!(stale_result(a.db.rebind_message(&first.folder.id, first.generation, 9, &stored.sha256)));
    assert!(stale_result(a.db.update_folder_checkpoint(&first.folder.id, first.generation, 99)));

    let folder = inbox(&a);
    assert_eq!((folder.uid_generation, folder.last_synced_uid), (second.generation, 5), "B's state untouched");
    assert_eq!(subjects(&a), ["A"], "nothing written by the old session");
}

#[tokio::test]
async fn copies_never_share_a_file_that_retention_could_delete() {
    use mailbackup_core::retention::RetentionManager;
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    // A (no Date header, so dated by INTERNALDATE) archived at UID 2, early March
    server.set(Some(1), &[(2, &mail("A"))]);
    server.set_internal_dates(&[(2, "03-Mar-2026 10:00:00 +0000")]);
    sync(&a, &server, &acc).await;

    // Renumbered: identical A at UIDs 1 and 2, received later the same month.
    // UID 1 re-binds the archived copy (file named after the old UID 2);
    // UID 2 is a second copy and must get a file of its own
    server.set(Some(2), &[(1, &mail("A")), (2, &mail("A"))]);
    server.set_internal_dates(&[(1, "20-Mar-2026 10:00:00 +0000"), (2, "20-Mar-2026 10:00:00 +0000")]);
    sync(&a, &server, &acc).await;
    let rows = archived(&a);
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].0.relative_path, rows[1].0.relative_path, "each copy has its own file");

    // Retention as of 25 March, 10 days: the early-March row expires, the
    // later one is kept and must stay readable
    let report = RetentionManager::new(&a.db, &a.storage)
        .enforce_retention_as_of("acc", Some(10), chrono::DateTime::parse_from_rfc3339("2026-03-25T00:00:00Z").unwrap().into())
        .unwrap();
    assert_eq!(report.pruned_count, 1);
    let kept = archived(&a);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].1, mail("A"), "the kept copy's file is still there");
}

#[test]
fn retention_keeps_a_file_another_row_still_uses() {
    use mailbackup_core::retention::RetentionManager;
    // Two rows sharing one file (a safety net: nothing should create this
    // any more): only the expired row goes, and the file stays
    let a = archive();
    let folder = a.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let stored = a.storage.store_eml("acc", "INBOX", 2, None, &mail("A")).unwrap();
    let path = stored.relative_path.to_string_lossy().to_string();
    let date = |s: &str| Some(chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&chrono::Utc));
    for (uid, when) in [(1, "2026-03-03T10:00:00Z"), (2, "2026-03-20T10:00:00Z")] {
        a.db.insert_message(
            "acc", &folder.id, uid, None, Some("A"), None, None, None, date(when), stored.size_bytes, &path,
            &stored.sha256, None, &[],
        )
        .unwrap();
    }
    let report = RetentionManager::new(&a.db, &a.storage)
        .enforce_retention_as_of("acc", Some(10), date("2026-03-25T00:00:00Z").unwrap())
        .unwrap();
    assert_eq!((report.pruned_count, report.reclaimed_bytes), (1, 0), "row pruned, file kept");
    assert_eq!(archived(&a)[0].1, mail("A"));

    // Once the last row using it expires, the file goes too
    let report = RetentionManager::new(&a.db, &a.storage)
        .enforce_retention_as_of("acc", Some(1), date("2026-04-30T00:00:00Z").unwrap())
        .unwrap();
    assert_eq!((report.pruned_count, report.reclaimed_bytes), (1, stored.size_bytes));
    assert!(!stored.absolute_path.exists());
}
