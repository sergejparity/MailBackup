//! Retention counts from when MailBackup backed a message up (issue #73),
//! never from the date the mail claims or the server's INTERNALDATE.

mod common;
use common::*;
use mailbackup_core::retention::RetentionManager;

fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&chrono::Utc)
}

fn dated_mail(subject: &str, date: &str) -> Vec<u8> {
    format!("From: a@example.com\r\nSubject: {}\r\nDate: {}\r\n\r\nbody\r\n", subject, date).into_bytes()
}

#[tokio::test]
async fn a_back_dated_mail_is_kept_and_a_future_dated_one_still_expires() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    let old = dated_mail("from 1990", "Mon, 1 Jan 1990 00:00:00 +0000");
    let future = dated_mail("from 2090", "Sun, 1 Jan 2090 00:00:00 +0000");
    server.set(Some(1), &[(1, &old), (2, &future)]);
    sync(&a, &server, &acc).await;

    // Archived just now: a 30-day policy keeps both, whatever they claim
    let report = RetentionManager::new(&a.db, &a.storage).enforce_retention("acc", Some(30)).unwrap();
    assert_eq!(report.pruned_count, 0);
    assert_eq!(subjects(&a).len(), 2);

    // Archived long ago: both expire, the one dated 2090 too
    for (row, _) in archived(&a) {
        set_archived_at(&a, &row.id, "2026-01-01T00:00:00+00:00");
    }
    let report = RetentionManager::new(&a.db, &a.storage)
        .enforce_retention_as_of("acc", Some(30), at("2026-03-01T00:00:00Z"))
        .unwrap();
    assert_eq!(report.pruned_count, 2);
    assert_eq!(eml_files(&a), 0);
}

#[tokio::test]
async fn the_servers_internaldate_changes_nothing() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    // No Date header: dated by INTERNALDATE, old and in the future
    let (m1, m2) = (mail("old internaldate"), mail("future internaldate"));
    server.set(Some(1), &[(1, &m1), (2, &m2)]);
    server.set_internal_dates(&[(1, "01-Jan-1995 00:00:00 +0000"), (2, "01-Jan-2095 00:00:00 +0000")]);
    sync(&a, &server, &acc).await;
    let report = RetentionManager::new(&a.db, &a.storage).enforce_retention("acc", Some(1)).unwrap();
    assert_eq!(report.pruned_count, 0, "both were backed up just now");
}

#[tokio::test]
async fn a_re_bound_copy_keeps_its_archive_time() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(5, &mail("kept"))]);
    sync(&a, &server, &acc).await;
    let (row, _) = archived(&a).remove(0);
    set_archived_at(&a, &row.id, "2026-02-01T00:00:00+00:00");

    // A new UIDVALIDITY: the same content at another UID is re-bound, not archived again
    server.set(Some(2), &[(9, &mail("kept"))]);
    sync(&a, &server, &acc).await;
    let rebound = a.db.get_message_by_id(&row.id).unwrap().expect("the same row");
    assert_eq!(rebound.uid, 9, "re-bound to the new UID");
    assert_eq!(rebound.created_at, at("2026-02-01T00:00:00Z"), "archive time kept");
}

/// Issue #79: retention and an archiver re-using a file. The archiver
/// follows the engine's protocol (shared storage lock from choosing the
/// file until its row is committed); retention runs from a second catalog
/// handle, as another process would, and must wait.
#[test]
fn a_file_being_re_used_is_never_removed_under_the_new_row() {
    use mailbackup_core::db::Database;
    use std::sync::mpsc;
    use std::time::Duration;

    let a = archive();
    let folder = a.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let body = mail("shared");
    // The old row, archived long ago, about to expire
    let stored = a.storage.store_eml("acc", "INBOX", 1, None, &body).unwrap();
    let path = stored.relative_path.to_string_lossy().to_string();
    let old = a
        .db
        .insert_message("acc", &folder.id, 1, None, Some("old"), None, None, None, None, stored.size_bytes, &path, &stored.sha256, None, &[])
        .unwrap();
    set_archived_at(&a, &old, "2020-01-01T00:00:00+00:00");

    // The archiver chooses the same file again (identical content, same UID
    // and generation: `store_eml` finds it in place) and pauses before its insert
    let lock = a.storage.lock_shared().unwrap();
    let again = a.storage.store_eml("acc", "INBOX", 1, None, &body).unwrap();
    assert_eq!(again.relative_path, stored.relative_path, "the existing file is re-used");

    // Retention from another handle on the same catalog and data folder
    let (done_tx, done_rx) = mpsc::channel();
    let catalog = a._dir.path().join("catalog.db");
    let storage = a.storage.clone();
    let pruner = std::thread::spawn(move || {
        let db = Database::open(&catalog).unwrap();
        let report = RetentionManager::new(&db, &storage).enforce_retention("acc", Some(30)).unwrap();
        done_tx.send(report).unwrap();
    });
    assert!(done_rx.recv_timeout(Duration::from_millis(500)).is_err(), "retention waits for the archiver");
    assert!(stored.absolute_path.exists());

    // The archiver commits its row (a fresh one: retention keeps it) and releases
    let new = a
        .db
        .insert_message("acc", &folder.id, 2, None, Some("new"), None, None, None, None, again.size_bytes, &path, &again.sha256, None, &[])
        .unwrap();
    drop(lock);
    let report = done_rx.recv_timeout(Duration::from_secs(10)).expect("retention finishes");
    pruner.join().unwrap();

    assert_eq!(report.pruned_count, 1, "the old row expired");
    assert_eq!(report.reclaimed_bytes, 0, "its file is still named by the new row");
    let kept = a.db.get_message_by_id(&new).unwrap().expect("the new row");
    let bytes = a.storage.read_eml(&kept.relative_path).expect("its file exists");
    assert_eq!(mailbackup_core::storage::StorageEngine::compute_sha256(&bytes), kept.sha256_hash);
}

/// Pruning in batches removes the same rows and files as one at a time did.
#[test]
fn batched_pruning_removes_every_expired_row_and_its_file() {
    let a = archive();
    let folder = a.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let total = mailbackup_core::retention::BATCH + 37;
    for uid in 1..=total as u32 {
        let stored = a.storage.store_eml("acc", "INBOX", uid, None, &mail(&format!("m{}", uid))).unwrap();
        let id = a
            .db
            .insert_message(
                "acc", &folder.id, uid, None, None, None, None, None, None, stored.size_bytes,
                &stored.relative_path.to_string_lossy(), &stored.sha256, None, &[],
            )
            .unwrap();
        // Every other one expired
        if uid % 2 == 0 {
            set_archived_at(&a, &id, "2020-01-01T00:00:00+00:00");
        }
    }
    let report = RetentionManager::new(&a.db, &a.storage).enforce_retention("acc", Some(30)).unwrap();
    assert_eq!(report.pruned_count as usize, total / 2);
    assert_eq!(eml_files(&a), total - total / 2);
    assert_eq!(a.db.get_messages_for_folder(&folder.id).unwrap().len(), total - total / 2);
}

/// Issue #79: the storage statistics are cached, but never stale: a change
/// through this handle or through another connection (another process)
/// shows at once.
#[test]
fn cached_statistics_follow_every_change() {
    use mailbackup_core::db::Database;
    let a = archive();
    let folder = a.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let insert = |db: &Database, uid: u32| {
        let stored = a.storage.store_eml("acc", "INBOX", uid, None, &mail(&format!("m{}", uid))).unwrap();
        db.insert_message(
            "acc", &folder.id, uid, None, None, None, None, None, None, stored.size_bytes,
            &stored.relative_path.to_string_lossy(), &stored.sha256, None, &[],
        )
        .unwrap()
    };
    assert_eq!(a.db.get_storage_stats().unwrap().total_messages, 0);
    insert(&a.db, 1);
    assert_eq!(a.db.get_storage_stats().unwrap().total_messages, 1, "a change through this handle");
    assert_eq!(a.db.get_storage_stats().unwrap().total_messages, 1, "unchanged: from the cache");

    let other = Database::open(a._dir.path().join("catalog.db")).unwrap();
    insert(&other, 2);
    assert_eq!(a.db.get_storage_stats().unwrap().total_messages, 2, "a change by another connection");
    let id = insert(&a.db, 3);
    other.delete_message_record(&id).unwrap();
    assert_eq!(a.db.get_storage_stats().unwrap().total_messages, 2);
}
