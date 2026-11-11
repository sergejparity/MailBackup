//! The paged folder list (issue #77): every order is total, every message
//! appears once, cursors are bound to their folder and order, and pages are
//! read from an index.

use mailbackup_core::db::{Database, ListSort};
use std::collections::HashSet;

const SORTS: [ListSort; 4] = [ListSort::Date, ListSort::Uid, ListSort::Sender, ListSort::Subject];

/// A folder with two UID generations (UIDs repeat), many equal dates, some
/// messages without a date, senders differing only in case, missing subjects.
fn folder(dir: &std::path::Path) -> (Database, String) {
    let db = Database::open(dir.join("catalog.db")).unwrap();
    let mut folder_id = String::new();
    for (generation, uidvalidity, count) in [(0u32, 1u32, 150u32), (1, 2, 60)] {
        let sync = db.begin_folder_sync("acc", "INBOX", "INBOX", Some(uidvalidity), "imap:993:me").unwrap();
        assert_eq!(sync.generation, generation);
        folder_id = sync.folder.id.clone();
        for uid in 1..=count {
            let date = (uid % 7 != 0).then(|| {
                chrono::DateTime::from_timestamp(1_780_000_000 + i64::from(uid / 10) * 3600, 0).unwrap()
            });
            let sender = ["alice@x", "Alice@x", "bob@x", "", "carol@x"][(uid % 5) as usize];
            let subject = (uid % 4 != 0).then(|| format!("subject {}", uid % 9));
            db.insert_message_in_generation(
                "acc", &folder_id, generation, uid, None, subject.as_deref(), (!sender.is_empty()).then_some(sender),
                None, None, date, u64::from(uid), &format!("g{}/{}", generation, uid), "h", None, &[],
            )
            .unwrap();
        }
    }
    (db, folder_id)
}

fn page_all(db: &Database, folder: &str, sort: ListSort, descending: bool, limit: u32) -> Vec<String> {
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = db.list_folder_messages(folder, sort, descending, limit, cursor.as_deref()).unwrap();
        assert!(page.messages.len() <= limit as usize);
        ids.extend(page.messages.into_iter().map(|m| m.id));
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return ids,
        }
    }
}

#[test]
fn every_order_pages_through_every_message_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let (db, folder) = folder(dir.path());
    let all: HashSet<String> = db.get_messages_for_folder(&folder).unwrap().into_iter().map(|m| m.id).collect();
    assert_eq!(all.len(), 210);
    for sort in SORTS {
        for descending in [false, true] {
            let whole = page_all(&db, &folder, sort, descending, 1000);
            assert_eq!(whole.len(), 210);
            for limit in [1, 7, 50] {
                let paged = page_all(&db, &folder, sort, descending, limit);
                assert_eq!(paged, whole, "{:?} desc={} limit={}: same order in pages as in one", sort, descending, limit);
            }
            assert_eq!(whole.iter().cloned().collect::<HashSet<_>>(), all, "{:?} desc={}", sort, descending);
            // Ascending is the exact reverse of descending
            let mut reversed = page_all(&db, &folder, sort, !descending, 1000);
            reversed.reverse();
            assert_eq!(reversed, whole, "{:?}", sort);
        }
    }
}

#[test]
fn messages_without_a_date_sort_as_the_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let (db, folder) = folder(dir.path());
    let newest_first = db.list_folder_messages(&folder, ListSort::Date, true, 1000, None).unwrap().messages;
    let first_undated = newest_first.iter().position(|m| m.date.is_none()).unwrap();
    assert!(newest_first[first_undated..].iter().all(|m| m.date.is_none()), "undated last when newest come first");
    assert!(newest_first[..first_undated].windows(2).all(|w| w[0].date >= w[1].date));
    let oldest_first = db.list_folder_messages(&folder, ListSort::Date, false, 1000, None).unwrap().messages;
    assert!(oldest_first[0].date.is_none(), "undated first when oldest come first");
}

#[test]
fn uid_order_separates_generations_and_text_orders_ignore_case() {
    let dir = tempfile::tempdir().unwrap();
    let (db, folder) = folder(dir.path());
    let by_uid = db.list_folder_messages(&folder, ListSort::Uid, false, 1000, None).unwrap().messages;
    let uids: Vec<u32> = by_uid.iter().map(|m| m.uid).collect();
    let mut expected: Vec<u32> = (1..=150).collect();
    expected.extend(1..=60);
    assert_eq!(uids, expected, "generation 0 first, then generation 1");

    let by_sender = db.list_folder_messages(&folder, ListSort::Sender, false, 1000, None).unwrap().messages;
    let senders: Vec<String> = by_sender.iter().map(|m| m.from_addr.clone().unwrap_or_default().to_lowercase()).collect();
    assert!(senders.windows(2).all(|w| w[0] <= w[1]), "case-insensitive: alice and Alice together");
}

#[test]
fn rows_present_throughout_appear_once_while_the_folder_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (db, folder) = folder(dir.path());
    let before: HashSet<String> = db.get_messages_for_folder(&folder).unwrap().into_iter().map(|m| m.id).collect();
    let first = db.list_folder_messages(&folder, ListSort::Date, true, 50, None).unwrap();
    let mut seen: Vec<String> = first.messages.iter().map(|m| m.id.clone()).collect();

    // Between pages: one not yet seen is deleted, two are added, one newer
    // than anything (before the cursor), one far older (after it)
    let not_seen = before.iter().find(|id| !seen.contains(id)).unwrap().clone();
    db.delete_message_record(&not_seen).unwrap();
    for (uid, ts) in [(500, 1_900_000_000), (501, 1_000_000_000)] {
        db.insert_message_in_generation(
            "acc", &folder, 1, uid, None, Some("new"), None, None, None,
            chrono::DateTime::from_timestamp(ts, 0), 1, &format!("n{}", uid), "h", None, &[],
        )
        .unwrap();
    }
    let mut cursor = first.next_cursor;
    while let Some(c) = cursor {
        let page = db.list_folder_messages(&folder, ListSort::Date, true, 50, Some(&c)).unwrap();
        seen.extend(page.messages.iter().map(|m| m.id.clone()));
        cursor = page.next_cursor;
    }
    let unique: HashSet<String> = seen.iter().cloned().collect();
    assert_eq!(unique.len(), seen.len(), "no message twice");
    for id in before.iter().filter(|id| **id != not_seen) {
        assert!(unique.contains(id), "a message present throughout is listed");
    }
    assert!(!unique.contains(&not_seen), "the deleted one is simply absent");
}

#[test]
fn a_cursor_only_works_for_its_own_folder_order_and_direction() {
    let dir = tempfile::tempdir().unwrap();
    let (db, folder) = folder(dir.path());
    let other = db.get_or_create_folder("acc", "Sent", "Sent", Some(1)).unwrap().id;
    let cursor = db.list_folder_messages(&folder, ListSort::Date, true, 10, None).unwrap().next_cursor.unwrap();
    let invalid = |r: mailbackup_core::Result<_>| matches!(r, Err(mailbackup_core::Error::InvalidInput(_)));
    assert!(invalid(db.list_folder_messages(&other, ListSort::Date, true, 10, Some(&cursor))));
    assert!(invalid(db.list_folder_messages(&folder, ListSort::Sender, true, 10, Some(&cursor))));
    assert!(invalid(db.list_folder_messages(&folder, ListSort::Date, false, 10, Some(&cursor))));
    assert!(invalid(db.list_folder_messages(&folder, ListSort::Date, true, 10, Some("not a cursor"))));
    assert!(db.list_folder_messages(&folder, ListSort::Date, true, 10, Some(&cursor)).is_ok());
}

#[test]
fn pages_are_read_from_an_index_without_sorting() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _folder) = folder(dir.path());
    for (sort, index) in [
        (ListSort::Date, "idx_messages_folder_date"),
        (ListSort::Sender, "idx_messages_folder_sender"),
        (ListSort::Subject, "idx_messages_folder_subject"),
        (ListSort::Uid, "sqlite_autoindex_messages_"),
    ] {
        for descending in [false, true] {
            for with_cursor in [false, true] {
                let plan = db.explain_folder_page(sort, descending, with_cursor).unwrap().join(" | ");
                assert!(plan.contains(index), "{:?} desc={} cursor={}: {}", sort, descending, with_cursor, plan);
                assert!(!plan.contains("TEMP B-TREE"), "{:?} desc={} cursor={}: sorted, not read in order: {}", sort, descending, with_cursor, plan);
            }
        }
    }
}
