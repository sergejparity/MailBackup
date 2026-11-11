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
