//! Catalog schema migration 0 → 1 (issue #17): UID generations.

use mailbackup_core::db::Database;
use rusqlite::{params, Connection};

/// The catalog schema of MailBackup 0.3.x, verbatim.
const V0_SCHEMA: &str = r#"
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                remote_name TEXT NOT NULL,
                local_slug TEXT NOT NULL,
                uidvalidity INTEGER,
                last_synced_uid INTEGER NOT NULL DEFAULT 0,
                message_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                UNIQUE(account_id, remote_name)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                folder_id TEXT NOT NULL,
                uid INTEGER NOT NULL,
                message_id TEXT,
                subject TEXT,
                from_addr TEXT,
                to_addrs TEXT,
                cc_addrs TEXT,
                date TEXT,
                size_bytes INTEGER NOT NULL,
                relative_path TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                is_remote_deleted INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE,
                UNIQUE(folder_id, uid)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_account ON messages(account_id);
            CREATE INDEX IF NOT EXISTS idx_messages_hash ON messages(sha256_hash);
            CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON messages(message_id);
            CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date);

            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
            );

            -- FTS5 Full-Text Search Table
            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                message_id UNINDEXED,
                account_id UNINDEXED,
                subject,
                from_addr,
                to_addrs,
                body_text,
                attachment_names,
                tokenize = 'porter unicode61'
            );

            CREATE TABLE IF NOT EXISTS sync_history (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                messages_downloaded INTEGER NOT NULL DEFAULT 0,
                bytes_downloaded INTEGER NOT NULL DEFAULT 0,
                error_message TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sync_history_account ON sync_history(account_id);
            "#;

/// A 0.3.x catalog holding one folder with one message (with an attachment
/// and a search entry).
fn v0_catalog(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(V0_SCHEMA).unwrap();
    conn.execute_batch(
        r#"
        INSERT INTO accounts VALUES ('acc', 'Test', 'me@example.com', 'custom', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
        INSERT INTO folders (id, account_id, remote_name, local_slug, uidvalidity, last_synced_uid, message_count, updated_at)
            VALUES ('f1', 'acc', 'INBOX', 'INBOX', 7, 42, 1, '2026-01-01T00:00:00Z');
        INSERT INTO messages (id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs,
                date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at)
            VALUES ('m1', 'acc', 'f1', 42, '<m1@x>', 'Quarterly invoice', 'a@x', 'b@x', NULL,
                '2026-01-01T00:00:00Z', 100, 'acc/INBOX/2026/01/42_abc.eml', 'abc', 0, '2026-01-01T00:00:00Z');
        INSERT INTO attachments VALUES ('att1', 'm1', 'invoice.pdf', 'application/pdf', 1234);
        INSERT INTO messages_fts (message_id, account_id, subject, from_addr, to_addrs, body_text, attachment_names)
            VALUES ('m1', 'acc', 'Quarterly invoice', 'a@x', 'b@x', 'please pay', 'invoice.pdf');
        "#,
    )
    .unwrap();
}

fn user_version(path: &std::path::Path) -> i64 {
    Connection::open(path).unwrap().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()
}

#[test]
fn a_v0_catalog_is_migrated_with_everything_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    v0_catalog(&path);
    assert_eq!(user_version(&path), 0);

    let db = Database::open(&path).unwrap();
    assert_eq!(user_version(&path), 1);

    let folder = &db.get_folders("acc").unwrap()[0];
    assert_eq!((folder.uidvalidity, folder.last_synced_uid, folder.uid_generation), (Some(7), 42, 0));
    assert_eq!(folder.remote_identity, None, "unknown until the next sync");
    let messages = db.get_messages_for_folder("f1").unwrap();
    assert_eq!(messages.len(), 1);
    let m = &messages[0];
    assert_eq!((m.id.as_str(), m.uid, m.subject.as_deref()), ("m1", 42, Some("Quarterly invoice")));
    assert!(db.message_exists_by_uid("f1", 42).unwrap(), "generation 0 is current");
    let hits = db.search_fts("invoice", 10).unwrap();
    assert_eq!(hits.len(), 1, "search index intact");
    drop(db);

    let conn = Connection::open(&path).unwrap();
    let attachments: i64 = conn.query_row("SELECT COUNT(*) FROM attachments WHERE message_id = 'm1'", [], |r| r.get(0)).unwrap();
    assert_eq!(attachments, 1);
    let broken: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0)).unwrap();
    assert_eq!(broken, 0);
    let indexes: i64 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'messages' AND name LIKE 'idx_%'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(indexes, 4, "indexes recreated");
    // Deleting the message still cascades to its attachment
    conn.execute_batch("PRAGMA foreign_keys = ON; DELETE FROM messages WHERE id = 'm1';").unwrap();
    let left: i64 = conn.query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0);
}

#[test]
fn uids_are_unique_per_generation_after_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    v0_catalog(&path);
    Database::open(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let insert = |id: &str, generation: u32| {
        conn.execute(
            r#"INSERT INTO messages (id, account_id, folder_id, uid, size_bytes, relative_path, sha256_hash,
                   created_at, uid_generation)
               VALUES (?1, 'acc', 'f1', 42, 1, 'x.eml', 'h', '2026-01-01T00:00:00Z', ?2)"#,
            params![id, generation],
        )
    };
    assert!(insert("m2", 1).is_ok(), "UID 42 again, in another generation");
    assert!(insert("m3", 1).is_err(), "but not twice in the same one");
}

#[test]
fn inserts_from_older_versions_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    v0_catalog(&path);
    Database::open(&path).unwrap();
    // The exact INSERT of 0.3.x: no uid_generation
    let conn = Connection::open(&path).unwrap();
    let err = conn
        .execute(
            r#"INSERT INTO messages (id, account_id, folder_id, uid, message_id, subject, from_addr,
                   to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at)
               VALUES ('old', 'acc', 'f1', 43, NULL, NULL, NULL, NULL, NULL, NULL, 1, 'y.eml', 'h', 0, '2026-01-01T00:00:00Z')"#,
            [],
        )
        .unwrap_err();
    assert!(err.to_string().contains("uid_generation"), "{}", err);
}

#[test]
fn reopening_is_a_no_op_and_fresh_catalogs_start_at_v1() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    v0_catalog(&path);
    Database::open(&path).unwrap();
    let db = Database::open(&path).unwrap();
    assert_eq!(db.get_messages_for_folder("f1").unwrap().len(), 1);
    assert_eq!(user_version(&path), 1);

    let fresh = dir.path().join("fresh.db");
    Database::open(&fresh).unwrap();
    assert_eq!(user_version(&fresh), 1);
}

#[test]
fn catalogs_from_newer_versions_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    Database::open(&path).unwrap();
    Connection::open(&path).unwrap().pragma_update(None, "user_version", 99).unwrap();
    let err = Database::open(&path).err().expect("refused");
    assert!(err.to_string().contains("newer MailBackup"), "{}", err);
    assert_eq!(user_version(&path), 99, "left as it was");
}
