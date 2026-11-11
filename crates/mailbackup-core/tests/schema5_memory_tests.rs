//! The schema-5 search index rebuild works one message at a time (review of
//! #92): its memory doesn't grow with the archive. This binary counts the
//! Rust heap (SQLite's own cache is bounded separately) and compares the
//! peak during the upgrade with the indexed text of the whole archive.

mod compat;
use compat::{copy_fixture, fixtures_root};
use mailbackup_core::db::Database;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const MESSAGES: usize = 48;
const BODY_BYTES: usize = 512 * 1024;

#[test]
fn the_index_rebuild_holds_one_message_at_a_time() {
    let dir = copy_fixture(&fixtures_root().join("catalog"));
    let path = dir.path().join("mailbackup.db");
    {
        // A schema-3 archive with 24 MB of indexed text; every fourth
        // message has two index rows, which the upgrade merges
        let conn = rusqlite::Connection::open(&path).unwrap();
        let (folder, account): (String, String) =
            conn.query_row("SELECT id, account_id FROM folders LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        let body: String = "lorem ipsum dolor sit amet ".repeat(BODY_BYTES / 27);
        let tx = conn.unchecked_transaction().unwrap();
        for i in 0..MESSAGES {
            let id = format!("big-{}", i);
            tx.execute(
                "INSERT INTO messages (id, account_id, folder_id, uid, size_bytes, relative_path, sha256_hash, created_at, uid_generation)
                 VALUES (?1, ?2, ?3, ?4, 1, 'p', 'h', '2026-01-01T00:00:00+00:00', 0)",
                rusqlite::params![id, account, folder, 100_000 + i as i64],
            )
            .unwrap();
            let rows = if i % 4 == 0 { 2 } else { 1 };
            for r in 0..rows {
                tx.execute(
                    "INSERT INTO messages_fts (message_id, account_id, subject, body_text) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![id, account, format!("subject {} {}", i, r), format!("{} copy{}", body, r)],
                )
                .unwrap();
            }
        }
        tx.commit().unwrap();
    }
    let indexed = MESSAGES * BODY_BYTES;

    let before = CURRENT.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let db = Database::open(&path).unwrap();
    let peak = PEAK.load(Ordering::SeqCst) - before;
    drop(db);

    println!("peak {} KB for {} MB of indexed text", peak >> 10, indexed >> 20);
    // A merged message holds its two rows and the merge: about 3 bodies
    assert!(peak < indexed / 4, "peak {} MB for {} MB of indexed text", peak >> 20, indexed >> 20);

    // Nothing was lost: the merged messages keep both copies
    let conn = rusqlite::Connection::open(&path).unwrap();
    let both: i64 = conn
        .query_row(
            "SELECT count(*) FROM messages m JOIN messages_fts f ON f.rowid = m.seq
             WHERE m.id = 'big-0' AND f.body_text LIKE '%copy0%' AND f.body_text LIKE '%copy1%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(both, 1);
}
