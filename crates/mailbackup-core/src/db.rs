use crate::error::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderRecord {
    pub id: String,
    pub account_id: String,
    pub remote_name: String,
    pub local_slug: String,
    pub uidvalidity: Option<u32>,
    pub last_synced_uid: u32,
    pub message_count: u32,
    pub updated_at: DateTime<Utc>,
    /// Which remote mailbox (server, port, username) the folder's current
    /// UIDs come from; `None` for folders last synced before 0.4.0.
    #[serde(default)]
    pub remote_identity: Option<String>,
    /// Bumped whenever the remote UIDs stop being comparable (see
    /// [`Database::begin_folder_sync`]); each message records the generation
    /// its UID belongs to.
    #[serde(default)]
    pub uid_generation: u32,
}

const FOLDER_COLUMNS: &str =
    "id, account_id, remote_name, local_slug, uidvalidity, last_synced_uid, message_count, updated_at, remote_identity, uid_generation";

fn folder_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FolderRecord> {
    let updated_at_str: String = row.get(7)?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    Ok(FolderRecord {
        id: row.get(0)?,
        account_id: row.get(1)?,
        remote_name: row.get(2)?,
        local_slug: row.get(3)?,
        uidvalidity: row.get(4)?,
        last_synced_uid: row.get(5)?,
        message_count: row.get(6)?,
        updated_at,
        remote_identity: row.get(8)?,
        uid_generation: row.get(9)?,
    })
}

/// Catalog schema version (`PRAGMA user_version`). 1 added UID generations
/// (issue #17).
const SCHEMA_VERSION: i64 = 1;

/// `messages` as of schema version 1. `uid_generation` deliberately has no
/// default: binaries older than 0.4.0 don't know about generations, and their
/// inserts fail instead of mixing UIDs of different remote mailboxes.
fn messages_ddl(table: &str) -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {} (
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
                uid_generation INTEGER NOT NULL,
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE,
                UNIQUE(folder_id, uid_generation, uid)
            );"#,
        table
    )
}

const MESSAGES_INDEXES: &str = r#"
            CREATE INDEX IF NOT EXISTS idx_messages_account ON messages(account_id);
            CREATE INDEX IF NOT EXISTS idx_messages_hash ON messages(sha256_hash);
            CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON messages(message_id);
            CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date);
"#;

fn has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What [`Database::begin_folder_sync`] decided for a folder.
#[derive(Debug, Clone)]
pub struct FolderSync {
    pub folder: FolderRecord,
    /// The generation this sync session writes to; every write checks it is
    /// still the folder's current one.
    pub generation: u32,
    /// Why a new generation (a full re-scan) was started, if one was.
    pub rescan_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: String,
    pub account_id: String,
    pub folder_id: String,
    pub uid: u32,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub to_addrs: Option<String>,
    pub cc_addrs: Option<String>,
    pub date: Option<DateTime<Utc>>,
    pub size_bytes: u64,
    pub relative_path: String,
    pub sha256_hash: String,
    pub is_remote_deleted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRecord {
    pub id: String,
    pub message_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
}

/// Start/end highlight markers passed to FTS5 `snippet()`. Control characters
/// cannot be spoofed by HTML in the indexed text, unlike literal `<b>` tags.
const SNIPPET_MARK_START: char = '\u{2}';
const SNIPPET_MARK_END: char = '\u{3}';

/// Converts a raw FTS5 snippet into safe HTML: the (sender-controlled) text is
/// HTML-escaped, other control characters are dropped, and only the match
/// markers become `<b>`/`</b>`.
pub fn snippet_to_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 16);
    for c in raw.chars() {
        match c {
            SNIPPET_MARK_START => out.push_str("<b>"),
            SNIPPET_MARK_END => out.push_str("</b>"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub message_id: String,
    pub account_id: String,
    pub folder_name: String,
    pub subject: String,
    pub from_addr: String,
    pub to_addrs: String,
    pub date: Option<DateTime<Utc>>,
    pub relative_path: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvancedSearchFilter {
    pub query: Option<String>,
    pub exclude_words: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cc: Option<String>,
    pub subject: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub account_id: Option<String>,
    pub folder_id: Option<String>,
    pub has_attachments: Option<bool>,
    pub attachment_name: Option<String>,
    pub attachment_type: Option<String>,
    pub min_size_bytes: Option<u64>,
    pub include_deleted: Option<bool>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHistoryRecord {
    pub id: String,
    pub account_id: String,
    pub status: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub messages_downloaded: u32,
    pub bytes_downloaded: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_accounts: u32,
    pub total_folders: u32,
    pub total_messages: u64,
    pub total_bytes: u64,
}

/// A search date filter: `YYYY-MM-DD`, optionally followed by a time (`T…` or
/// a space, as in an ISO timestamp). Anything else is `Error::InvalidInput`.
pub fn parse_date_filter(input: &str) -> Result<chrono::NaiveDate> {
    let invalid = || crate::Error::InvalidInput(format!("Invalid date '{}': expected YYYY-MM-DD", input.escape_debug()));
    let input = input.trim();
    // Split by character: never slice a string by byte offset
    let mut chars = input.char_indices();
    let date_end = chars.nth(10).map(|(i, _)| i).unwrap_or(input.len());
    let (date, rest) = input.split_at(date_end);
    if !(rest.is_empty() || rest.starts_with('T') || rest.starts_with(' ')) {
        return Err(invalid());
    }
    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| invalid())
}

/// Makes the catalog owner-only before SQLite opens it. SQLite's unix VFS gives
/// the `-wal`/`-shm`/`-journal` files it creates the database file's mode, so
/// the file must be private first:
/// - a missing database is pre-created empty with mode 0600 (SQLite treats an
///   empty file as a new database), its missing parent folders owner-only;
/// - an existing database we own, and any sidecar files left from an earlier
///   run, lose group/other access before the connection and WAL are set up.
fn prepare_private_db_file(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        crate::private_fs::create_dir_all(parent)?;
    }
    match crate::private_fs::options().write(true).create_new(true).open(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let sidecars = ["-wal", "-shm", "-journal"].map(|s| PathBuf::from(format!("{}{}", path.display(), s)));
    for file in std::iter::once(path.to_path_buf()).chain(sidecars) {
        // A file we can't tighten (e.g. on a read-only volume) is still usable
        if let Err(e) = crate::private_fs::restrict(&file) {
            tracing::warn!("Could not make {} owner-only: {}", file.display(), e);
        }
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |r| {
        r.get::<_, i64>(0)
    })
    .map(|n| n > 0)
}

/// `Error::StaleSync` unless `generation` is still the folder's current one.
fn ensure_generation(conn: &Connection, folder_id: &str, generation: u32) -> Result<()> {
    let current: Option<u32> = conn
        .query_row("SELECT uid_generation FROM folders WHERE id = ?1", params![folder_id], |r| r.get(0))
        .optional()?;
    if current != Some(generation) {
        return Err(crate::Error::StaleSync(folder_id.to_string()));
    }
    Ok(())
}

/// Schema 0 → 1: UID generations. `folders` gains columns in place; `messages`
/// is rebuilt (SQLite can't change a UNIQUE constraint) following SQLite's
/// documented procedure: foreign keys off, one transaction, foreign key check
/// before commit. Existing rows become generation 0.
fn migrate_to_v1(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= 1 {
        return Ok(());
    }
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let result = (|| -> Result<()> {
        let tx = conn.transaction()?;
        if !has_column(&tx, "folders", "remote_identity")? {
            tx.execute_batch("ALTER TABLE folders ADD COLUMN remote_identity TEXT;")?;
        }
        if !has_column(&tx, "folders", "uid_generation")? {
            tx.execute_batch("ALTER TABLE folders ADD COLUMN uid_generation INTEGER NOT NULL DEFAULT 0;")?;
        }
        if !has_column(&tx, "messages", "uid_generation")? {
            tx.execute_batch(&messages_ddl("messages_v1"))?;
            tx.execute_batch(
                r#"
                INSERT INTO messages_v1 (
                    id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs,
                    date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at, uid_generation
                )
                SELECT id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs,
                    date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at, 0
                FROM messages;
                DROP TABLE messages;
                ALTER TABLE messages_v1 RENAME TO messages;
                "#,
            )?;
            tx.execute_batch(MESSAGES_INDEXES)?;
        }
        let violations: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
        if violations > 0 {
            return Err(crate::Error::Other(format!(
                "Catalog migration found {} broken references; the database was left unchanged",
                violations
            )));
        }
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
        Ok(())
    })();
    conn.pragma_update(None, "foreign_keys", "ON")?;
    result
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    current_path: Arc<Mutex<PathBuf>>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref().to_path_buf();
        prepare_private_db_file(&p)?;
        let conn = Connection::open(&p)?;
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()));
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            current_path: Arc::new(Mutex::new(p)),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            current_path: Arc::new(Mutex::new(PathBuf::from(":memory:"))),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Returns the current path to the SQLite database file
    pub fn path(&self) -> PathBuf {
        self.current_path.lock().unwrap().clone()
    }

    /// Relocates the SQLite database to a new file location in-place
    pub fn relocate(&self, new_path: impl AsRef<Path>, move_existing: bool) -> Result<()> {
        let new_p = new_path.as_ref();
        let old_p = self.path();

        if new_p == old_p {
            return Ok(());
        }

        if let Some(parent) = new_p.parent() {
            crate::private_fs::create_dir_all(parent)?;
        }

        {
            let mut conn_guard = self.conn.lock().unwrap();

            if move_existing && old_p.exists() && old_p.to_string_lossy() != ":memory:" {
                // Checkpoint WAL cleanly so main DB file has all data
                let _ = conn_guard.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

                // Copy main .db file
                crate::private_fs::copy(&old_p, new_p)?;

                // Also copy WAL and SHM if present
                let old_wal = format!("{}-wal", old_p.display());
                let new_wal = format!("{}-wal", new_p.display());
                if std::path::Path::new(&old_wal).exists() {
                    let _ = crate::private_fs::copy(Path::new(&old_wal), Path::new(&new_wal));
                }
                let old_shm = format!("{}-shm", old_p.display());
                let new_shm = format!("{}-shm", new_p.display());
                if std::path::Path::new(&old_shm).exists() {
                    let _ = crate::private_fs::copy(Path::new(&old_shm), Path::new(&new_shm));
                }
            }

            // Open new connection on relocated path
            prepare_private_db_file(new_p)?;
            let new_conn = Connection::open(new_p)?;
            let _ = new_conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()));
            new_conn.pragma_update(None, "synchronous", "NORMAL")?;
            new_conn.pragma_update(None, "foreign_keys", "ON")?;

            *conn_guard = new_conn;
            *self.current_path.lock().unwrap() = new_p.to_path_buf();
        }

        // Ensure schema and tables exist on the relocated connection
        self.init_schema()?;

        Ok(())
    }

    fn init_schema(&self) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(crate::Error::Other(format!(
                "The catalog database was created by a newer MailBackup (schema {}, this version knows {}). Update MailBackup, or restore a backup of the catalog made before upgrading.",
                version, SCHEMA_VERSION
            )));
        }
        let fresh = !table_exists(&conn, "messages")?;
        let schema = r#"
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
                remote_identity TEXT,
                uid_generation INTEGER NOT NULL DEFAULT 0,
                UNIQUE(account_id, remote_name)
            );

            {messages}
{indexes}
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
            "#
        .replace("{messages}", &messages_ddl("messages"))
        .replace("{indexes}", MESSAGES_INDEXES);
        if fresh {
            conn.execute_batch(&schema)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            return Ok(());
        }
        migrate_to_v1(&mut conn)?;
        // Tables added later than `messages` (no-ops when present)
        conn.execute_batch(&schema)?;
        Ok(())
    }

    pub fn upsert_account(&self, id: &str, name: &str, email: &str, provider: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            r#"
            INSERT INTO accounts (id, name, email, provider, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                email = excluded.email,
                provider = excluded.provider,
                updated_at = excluded.updated_at
            "#,
            params![id, name, email, provider, now],
        )?;
        Ok(())
    }

    pub fn get_or_create_folder(
        &self,
        account_id: &str,
        remote_name: &str,
        local_slug: &str,
        uidvalidity: Option<u32>,
    ) -> Result<FolderRecord> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        let existing = conn.query_row(
            r#"
            SELECT {}
            FROM folders
            WHERE account_id = ?1 AND remote_name = ?2
            "#.replace("{}", FOLDER_COLUMNS).as_str(),
            params![account_id, remote_name],
            folder_from_row,
        ).optional()?;

        if let Some(folder) = existing {
            // Check if UIDVALIDITY changed
            if let Some(new_uv) = uidvalidity {
                if folder.uidvalidity.is_some() && folder.uidvalidity != Some(new_uv) {
                    conn.execute(
                        "UPDATE folders SET uidvalidity = ?1, last_synced_uid = 0, updated_at = ?2 WHERE id = ?3",
                        params![new_uv, now, folder.id],
                    )?;
                    return Ok(FolderRecord {
                        uidvalidity: Some(new_uv),
                        last_synced_uid: 0,
                        updated_at: Utc::now(),
                        ..folder
                    });
                }
            }
            return Ok(folder);
        }

        let new_id = Uuid::new_v4().to_string();
        conn.execute(
            r#"
            INSERT INTO folders (id, account_id, remote_name, local_slug, uidvalidity, last_synced_uid, message_count, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6)
            "#,
            params![new_id, account_id, remote_name, local_slug, uidvalidity, now],
        )?;

        Ok(FolderRecord {
            id: new_id,
            account_id: account_id.to_string(),
            remote_name: remote_name.to_string(),
            local_slug: local_slug.to_string(),
            uidvalidity,
            last_synced_uid: 0,
            message_count: 0,
            updated_at: Utc::now(),
            remote_identity: None,
            uid_generation: 0,
        })
    }

    pub fn update_folder_sync_state(&self, folder_id: &str, last_synced_uid: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            r#"
            UPDATE folders
            SET last_synced_uid = ?1,
                message_count = (SELECT COUNT(*) FROM messages WHERE folder_id = ?2),
                updated_at = ?3
            WHERE id = ?2
            "#,
            params![last_synced_uid, folder_id, now],
        )?;
        Ok(())
    }

    pub fn get_folders(&self, account_id: &str) -> Result<Vec<FolderRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT {}
            FROM folders
            WHERE account_id = ?1
            ORDER BY remote_name ASC
            "#
            .replace("{}", FOLDER_COLUMNS)
            .as_str(),
        )?;

        let rows = stmt.query_map(params![account_id], folder_from_row)?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Whether `uid` of the folder's *current* generation is archived.
    pub fn message_exists_by_uid(&self, folder_id: &str, uid: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            r#"SELECT COUNT(*) FROM messages
               WHERE folder_id = ?1 AND uid = ?2
                 AND uid_generation = (SELECT uid_generation FROM folders WHERE id = ?1)"#,
            params![folder_id, uid],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Whether `uid` of `generation` is archived in the folder.
    pub fn message_exists_in_generation(&self, folder_id: &str, generation: u32, uid: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder_id = ?1 AND uid_generation = ?2 AND uid = ?3",
            params![folder_id, generation, uid],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Starts syncing a folder: creates it if new and decides which UID
    /// generation this session works in. A new generation (with the
    /// checkpoint back at 0, so the whole folder is re-scanned) starts when the
    /// UIDs already archived can't be trusted to mean the same messages:
    /// - the server reports a UIDVALIDITY different from the stored one;
    /// - the account's server, port or username (`remote_identity`) changed,
    ///   even if the new server reports the same UIDVALIDITY;
    /// - the folder has archived messages but no recorded identity (synced
    ///   before 0.4.0) or no recorded UIDVALIDITY while the server now reports
    ///   one: nothing ties the old UIDs to this mailbox.
    ///
    /// Archived messages are kept; a re-scan re-binds them by content (see
    /// [`Self::rebind_message`]).
    pub fn begin_folder_sync(
        &self,
        account_id: &str,
        remote_name: &str,
        local_slug: &str,
        uidvalidity: Option<u32>,
        remote_identity: &str,
    ) -> Result<FolderSync> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let existing = tx
            .query_row(
                &format!("SELECT {} FROM folders WHERE account_id = ?1 AND remote_name = ?2", FOLDER_COLUMNS),
                params![account_id, remote_name],
                folder_from_row,
            )
            .optional()?;

        let Some(folder) = existing else {
            let new_id = Uuid::new_v4().to_string();
            tx.execute(
                r#"INSERT INTO folders (id, account_id, remote_name, local_slug, uidvalidity, last_synced_uid,
                       message_count, updated_at, remote_identity, uid_generation)
                   VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?7, 0)"#,
                params![new_id, account_id, remote_name, local_slug, uidvalidity, now, remote_identity],
            )?;
            let folder = tx.query_row(
                &format!("SELECT {} FROM folders WHERE id = ?1", FOLDER_COLUMNS),
                params![new_id],
                folder_from_row,
            )?;
            tx.commit()?;
            return Ok(FolderSync { generation: 0, folder, rescan_reason: None });
        };

        let has_messages: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE folder_id = ?1)",
            params![folder.id],
            |r| r.get(0),
        )?;
        let rescan_reason = match (folder.uidvalidity, uidvalidity, folder.remote_identity.as_deref()) {
            (Some(old), Some(new), _) if old != new => {
                Some(format!("the server reports a new UIDVALIDITY ({} → {})", old, new))
            }
            (_, _, Some(old)) if old != remote_identity => {
                Some("the account's server, port or username changed".to_string())
            }
            (_, _, None) if has_messages => {
                Some("the folder was archived by an older version that didn't record which server its UIDs came from".to_string())
            }
            (None, Some(_), _) if has_messages => {
                Some("the server reports a UIDVALIDITY for the first time".to_string())
            }
            _ => None,
        };

        let generation = if rescan_reason.is_some() { folder.uid_generation + 1 } else { folder.uid_generation };
        if rescan_reason.is_some() {
            tx.execute(
                r#"UPDATE folders SET uid_generation = ?1, last_synced_uid = 0, uidvalidity = ?2,
                       remote_identity = ?3, updated_at = ?4
                   WHERE id = ?5"#,
                params![generation, uidvalidity, remote_identity, now, folder.id],
            )?;
        } else {
            // Same mailbox: record the identity and a newly reported UIDVALIDITY
            tx.execute(
                r#"UPDATE folders SET remote_identity = ?1, uidvalidity = COALESCE(?2, uidvalidity), updated_at = ?3
                   WHERE id = ?4"#,
                params![remote_identity, uidvalidity, now, folder.id],
            )?;
        }
        let folder = tx.query_row(
            &format!("SELECT {} FROM folders WHERE id = ?1", FOLDER_COLUMNS),
            params![folder.id],
            folder_from_row,
        )?;
        tx.commit()?;
        Ok(FolderSync { folder, generation, rescan_reason })
    }

    /// If the folder holds a message with this content that no UID of
    /// `generation` claims yet (archived under an older generation), binds it
    /// to `uid` of `generation` instead of storing it again, and returns its
    /// id. Each archived copy is re-bound at most once, so a mailbox holding
    /// the same message several times keeps as many copies.
    pub fn rebind_message(&self, folder_id: &str, generation: u32, uid: u32, sha256_hash: &str) -> Result<Option<String>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        ensure_generation(&tx, folder_id, generation)?;
        let candidate: Option<String> = tx
            .query_row(
                r#"SELECT id FROM messages
                   WHERE folder_id = ?1 AND sha256_hash = ?2 AND uid_generation < ?3
                   ORDER BY uid_generation, uid LIMIT 1"#,
                params![folder_id, sha256_hash, generation],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = &candidate {
            tx.execute(
                "UPDATE messages SET uid_generation = ?1, uid = ?2 WHERE id = ?3",
                params![generation, uid, id],
            )?;
        }
        tx.commit()?;
        Ok(candidate)
    }

    /// Advances the folder's checkpoint, unless a newer sync has started a
    /// new generation since this one began (`Error::StaleSync`).
    pub fn update_folder_checkpoint(&self, folder_id: &str, generation: u32, last_synced_uid: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let updated = conn.execute(
            r#"
            UPDATE folders
            SET last_synced_uid = ?1,
                message_count = (SELECT COUNT(*) FROM messages WHERE folder_id = ?2),
                updated_at = ?3
            WHERE id = ?2 AND uid_generation = ?4
            "#,
            params![last_synced_uid, folder_id, now, generation],
        )?;
        if updated == 0 {
            return Err(crate::Error::StaleSync(folder_id.to_string()));
        }
        Ok(())
    }

    pub fn find_existing_message_by_hash(&self, sha256_hash: &str) -> Result<Option<MessageRecord>> {
        let conn = self.conn.lock().unwrap();
        let msg = conn.query_row(
            r#"
            SELECT id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at
            FROM messages
            WHERE sha256_hash = ?1
            LIMIT 1
            "#,
            params![sha256_hash],
            |row| {
                let date_str: Option<String> = row.get(9)?;
                let date = date_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
                let created_str: String = row.get(14)?;
                let created_at = DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());

                Ok(MessageRecord {
                    id: row.get(0)?,
                    account_id: row.get(1)?,
                    folder_id: row.get(2)?,
                    uid: row.get(3)?,
                    message_id: row.get(4)?,
                    subject: row.get(5)?,
                    from_addr: row.get(6)?,
                    to_addrs: row.get(7)?,
                    cc_addrs: row.get(8)?,
                    date,
                    size_bytes: row.get(10)?,
                    relative_path: row.get(11)?,
                    sha256_hash: row.get(12)?,
                    is_remote_deleted: row.get::<_, i64>(13)? != 0,
                    created_at,
                })
            },
        ).optional()?;
        Ok(msg)
    }

    pub fn get_message_by_id(&self, message_id: &str) -> Result<Option<MessageRecord>> {
        let conn = self.conn.lock().unwrap();
        let msg = conn.query_row(
            r#"
            SELECT id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at
            FROM messages
            WHERE id = ?1
            LIMIT 1
            "#,
            params![message_id],
            |row| {
                let date_str: Option<String> = row.get(9)?;
                let date = date_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
                let created_str: String = row.get(14)?;
                let created_at = DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());

                Ok(MessageRecord {
                    id: row.get(0)?,
                    account_id: row.get(1)?,
                    folder_id: row.get(2)?,
                    uid: row.get(3)?,
                    message_id: row.get(4)?,
                    subject: row.get(5)?,
                    from_addr: row.get(6)?,
                    to_addrs: row.get(7)?,
                    cc_addrs: row.get(8)?,
                    date,
                    size_bytes: row.get(10)?,
                    relative_path: row.get(11)?,
                    sha256_hash: row.get(12)?,
                    is_remote_deleted: row.get::<_, i64>(13)? != 0,
                    created_at,
                })
            },
        ).optional()?;
        Ok(msg)
    }

    /// Inserts a message under the folder's current UID generation.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message(
        &self,
        account_id: &str,
        folder_id: &str,
        uid: u32,
        message_id: Option<&str>,
        subject: Option<&str>,
        from_addr: Option<&str>,
        to_addrs: Option<&str>,
        cc_addrs: Option<&str>,
        date: Option<DateTime<Utc>>,
        size_bytes: u64,
        relative_path: &str,
        sha256_hash: &str,
        body_text: Option<&str>,
        attachments: &[(&str, &str, u64)], // (filename, mime_type, size)
    ) -> Result<String> {
        let generation: u32 = {
            let conn = self.conn.lock().unwrap();
            conn.query_row("SELECT uid_generation FROM folders WHERE id = ?1", params![folder_id], |r| r.get(0))
                .optional()?
                .unwrap_or(0)
        };
        self.insert_message_in_generation(
            account_id, folder_id, generation, uid, message_id, subject, from_addr, to_addrs, cc_addrs, date,
            size_bytes, relative_path, sha256_hash, body_text, attachments,
        )
    }

    /// Inserts a message fetched as `uid` of `generation`, unless a newer
    /// sync has started a new generation since (`Error::StaleSync`, nothing
    /// written). The message, its attachments and its search entry are
    /// written together or not at all.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message_in_generation(
        &self,
        account_id: &str,
        folder_id: &str,
        generation: u32,
        uid: u32,
        message_id: Option<&str>,
        subject: Option<&str>,
        from_addr: Option<&str>,
        to_addrs: Option<&str>,
        cc_addrs: Option<&str>,
        date: Option<DateTime<Utc>>,
        size_bytes: u64,
        relative_path: &str,
        sha256_hash: &str,
        body_text: Option<&str>,
        attachments: &[(&str, &str, u64)], // (filename, mime_type, size)
    ) -> Result<String> {
        let mut conn = self.conn.lock().unwrap();
        let conn = conn.transaction()?;
        ensure_generation(&conn, folder_id, generation)?;
        let new_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let date_str = date.map(|d| d.to_rfc3339());

        conn.execute(
            r#"
            INSERT INTO messages (
                id, account_id, folder_id, uid, message_id, subject, from_addr,
                to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash,
                is_remote_deleted, created_at, uid_generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14, ?15)
            "#,
            params![
                new_id, account_id, folder_id, uid, message_id, subject, from_addr,
                to_addrs, cc_addrs, date_str, size_bytes as i64, relative_path, sha256_hash, now, generation
            ],
        )?;

        // Insert attachments
        let mut att_names = Vec::new();
        for (fname, mtype, sz) in attachments {
            let att_id = Uuid::new_v4().to_string();
            conn.execute(
                r#"
                INSERT INTO attachments (id, message_id, filename, mime_type, size_bytes)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![att_id, new_id, fname, mtype, *sz as i64],
            )?;
            att_names.push(*fname);
        }

        // Insert into FTS5 index
        let att_names_str = att_names.join(" ");
        conn.execute(
            r#"
            INSERT INTO messages_fts (message_id, account_id, subject, from_addr, to_addrs, body_text, attachment_names)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                new_id,
                account_id,
                subject.unwrap_or(""),
                from_addr.unwrap_or(""),
                to_addrs.unwrap_or(""),
                body_text.unwrap_or(""),
                att_names_str
            ],
        )?;

        conn.commit()?;
        Ok(new_id)
    }

    pub fn search_fts(&self, query: &str, limit: u32) -> Result<Vec<SearchResult>> {
        let filter = AdvancedSearchFilter {
            query: Some(query.to_string()),
            limit: Some(limit),
            ..Default::default()
        };
        self.search_advanced(&filter)
    }

    pub fn search_advanced(&self, filter: &AdvancedSearchFilter) -> Result<Vec<SearchResult>> {
        let conn = self.conn.lock().unwrap();
        let limit = filter.limit.unwrap_or(50).min(500);

        let query_trimmed = filter.query.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let has_fts = query_trimmed.is_some();

        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(q) = query_trimmed {
            let fts_query = if q.contains('"') {
                q.to_string()
            } else {
                let tokens: Vec<String> = q
                    .split_whitespace()
                    .filter(|w| !w.is_empty())
                    .map(|w| {
                        let clean = w.replace('"', "\"\"").replace('*', "");
                        format!("\"{}\"*", clean)
                    })
                    .collect();
                if tokens.is_empty() {
                    format!("\"{}\"", q.replace('"', "\"\""))
                } else {
                    tokens.join(" ")
                }
            };
            conditions.push("messages_fts MATCH ?".to_string());
            params.push(rusqlite::types::Value::Text(fts_query));
        }

        if let Some(from) = filter.from.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            for word in from.split_whitespace().filter(|w| !w.is_empty()) {
                conditions.push("m.from_addr LIKE ?".to_string());
                params.push(rusqlite::types::Value::Text(format!("%{}%", word)));
            }
        }

        if let Some(to) = filter.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            for word in to.split_whitespace().filter(|w| !w.is_empty()) {
                conditions.push("m.to_addrs LIKE ?".to_string());
                params.push(rusqlite::types::Value::Text(format!("%{}%", word)));
            }
        }

        if let Some(cc) = filter.cc.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            for word in cc.split_whitespace().filter(|w| !w.is_empty()) {
                conditions.push("m.cc_addrs LIKE ?".to_string());
                params.push(rusqlite::types::Value::Text(format!("%{}%", word)));
            }
        }

        if let Some(sub) = filter.subject.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            for word in sub.split_whitespace().filter(|w| !w.is_empty()) {
                conditions.push("m.subject LIKE ?".to_string());
                params.push(rusqlite::types::Value::Text(format!("%{}%", word)));
            }
        }

        if let Some(df) = filter.date_from.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let date = parse_date_filter(df)?;
            conditions.push("date(m.date) >= ?".to_string());
            params.push(rusqlite::types::Value::Text(date.format("%Y-%m-%d").to_string()));
        }

        if let Some(dt) = filter.date_to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let date = parse_date_filter(dt)?;
            conditions.push("date(m.date) <= ?".to_string());
            params.push(rusqlite::types::Value::Text(date.format("%Y-%m-%d").to_string()));
        }

        if let Some(acc) = filter.account_id.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "ALL") {
            conditions.push("m.account_id = ?".to_string());
            params.push(rusqlite::types::Value::Text(acc.to_string()));
        }

        if let Some(fld) = filter.folder_id.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "ALL") {
            conditions.push("m.folder_id = ?".to_string());
            params.push(rusqlite::types::Value::Text(fld.to_string()));
        }

        if filter.include_deleted != Some(true) {
            conditions.push("m.is_remote_deleted = 0".to_string());
        }

        if let Some(min_size) = filter.min_size_bytes {
            if min_size > 0 {
                conditions.push("m.size_bytes >= ?".to_string());
                params.push(rusqlite::types::Value::Integer(min_size as i64));
            }
        }

        if filter.has_attachments == Some(true) {
            conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id)".to_string());
        }

        if let Some(att_name) = filter.attachment_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND a.filename LIKE ?)".to_string());
            params.push(rusqlite::types::Value::Text(format!("%{}%", att_name)));
        }

        if let Some(att_type) = filter.attachment_type.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "all") {
            match att_type.to_lowercase().as_str() {
                "pdf" => {
                    conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND (a.mime_type LIKE '%pdf%' OR a.filename LIKE '%.pdf'))".to_string());
                }
                "image" => {
                    conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND (a.mime_type LIKE 'image/%' OR a.filename LIKE '%.png' OR a.filename LIKE '%.jpg' OR a.filename LIKE '%.jpeg' OR a.filename LIKE '%.gif' OR a.filename LIKE '%.webp'))".to_string());
                }
                "spreadsheet" => {
                    conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND (a.filename LIKE '%.xlsx' OR a.filename LIKE '%.xls' OR a.filename LIKE '%.csv'))".to_string());
                }
                "archive" => {
                    conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND (a.mime_type LIKE '%zip%' OR a.mime_type LIKE '%tar%' OR a.mime_type LIKE '%compressed%' OR a.filename LIKE '%.zip' OR a.filename LIKE '%.tar%' OR a.filename LIKE '%.gz' OR a.filename LIKE '%.7z' OR a.filename LIKE '%.rar'))".to_string());
                }
                "document" => {
                    conditions.push("EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND (a.filename LIKE '%.doc%' OR a.filename LIKE '%.docx' OR a.filename LIKE '%.odt' OR a.filename LIKE '%.rtf' OR a.filename LIKE '%.txt'))".to_string());
                }
                _ => {}
            }
        }

        if let Some(exc) = filter.exclude_words.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            for word in exc.split_whitespace() {
                if !word.is_empty() {
                    conditions.push("m.subject NOT LIKE ?".to_string());
                    params.push(rusqlite::types::Value::Text(format!("%{}%", word)));
                }
            }
        }

        let where_clause = if conditions.is_empty() {
            "".to_string()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        params.push(rusqlite::types::Value::Integer(limit as i64));

        let sql = if has_fts {
            format!(
                r#"
                SELECT 
                    m.id, m.account_id, f.remote_name, m.subject, m.from_addr, m.to_addrs, m.date, m.relative_path,
                    snippet(messages_fts, -1, char(2), char(3), '...', 15) as snip
                FROM messages_fts
                JOIN messages m ON m.id = messages_fts.message_id
                JOIN folders f ON f.id = m.folder_id
                {}
                ORDER BY messages_fts.rank, m.date DESC
                LIMIT ?
                "#,
                where_clause
            )
        } else {
            format!(
                r#"
                SELECT 
                    m.id, m.account_id, f.remote_name, m.subject, m.from_addr, m.to_addrs, m.date, m.relative_path,
                    '' as snip
                FROM messages m
                JOIN folders f ON f.id = m.folder_id
                {}
                ORDER BY m.date DESC
                LIMIT ?
                "#,
                where_clause
            )
        };

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(params), |row| {
            let date_str: Option<String> = row.get(6)?;
            let date = date_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));

            Ok(SearchResult {
                message_id: row.get(0)?,
                account_id: row.get(1)?,
                folder_name: row.get(2)?,
                subject: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                from_addr: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                to_addrs: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                date,
                relative_path: row.get(7)?,
                snippet: snippet_to_html(&row.get::<_, Option<String>>(8)?.unwrap_or_default()),
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    pub fn get_messages_older_than(
        &self,
        account_id: &str,
        cutoff_date: DateTime<Utc>,
    ) -> Result<Vec<MessageRecord>> {
        let conn = self.conn.lock().unwrap();
        let cutoff_str = cutoff_date.to_rfc3339();

        let mut stmt = conn.prepare(
            r#"
            SELECT id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at
            FROM messages
            WHERE account_id = ?1 AND date IS NOT NULL AND date < ?2
            ORDER BY date ASC
            "#,
        )?;

        let rows = stmt.query_map(params![account_id, cutoff_str], |row| {
            let date_str: Option<String> = row.get(9)?;
            let date = date_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
            let created_str: String = row.get(14)?;
            let created_at = DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());

            Ok(MessageRecord {
                id: row.get(0)?,
                account_id: row.get(1)?,
                folder_id: row.get(2)?,
                uid: row.get(3)?,
                message_id: row.get(4)?,
                subject: row.get(5)?,
                from_addr: row.get(6)?,
                to_addrs: row.get(7)?,
                cc_addrs: row.get(8)?,
                date,
                size_bytes: row.get(10)?,
                relative_path: row.get(11)?,
                sha256_hash: row.get(12)?,
                is_remote_deleted: row.get::<_, i64>(13)? != 0,
                created_at,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Whether any catalog row still points at this archived file.
    pub fn is_path_referenced(&self, relative_path: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE relative_path = ?1)",
            params![relative_path],
            |r| r.get(0),
        )?)
    }

    pub fn delete_message_record(&self, message_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM messages_fts WHERE message_id = ?1", params![message_id])?;
        conn.execute("DELETE FROM messages WHERE id = ?1", params![message_id])?;
        Ok(())
    }

    pub fn get_messages_for_folder(&self, folder_id: &str) -> Result<Vec<MessageRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, account_id, folder_id, uid, message_id, subject, from_addr, to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash, is_remote_deleted, created_at
            FROM messages
            WHERE folder_id = ?1
            ORDER BY uid ASC
            "#,
        )?;

        let rows = stmt.query_map(params![folder_id], |row| {
            let date_str: Option<String> = row.get(9)?;
            let date = date_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
            let created_str: String = row.get(14)?;
            let created_at = DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());

            Ok(MessageRecord {
                id: row.get(0)?,
                account_id: row.get(1)?,
                folder_id: row.get(2)?,
                uid: row.get(3)?,
                message_id: row.get(4)?,
                subject: row.get(5)?,
                from_addr: row.get(6)?,
                to_addrs: row.get(7)?,
                cc_addrs: row.get(8)?,
                date,
                size_bytes: row.get(10)?,
                relative_path: row.get(11)?,
                sha256_hash: row.get(12)?,
                is_remote_deleted: row.get::<_, i64>(13)? != 0,
                created_at,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn record_sync_start(&self, account_id: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            r#"
            INSERT INTO sync_history (id, account_id, status, start_time)
            VALUES (?1, ?2, 'running', ?3)
            "#,
            params![id, account_id, now],
        )?;
        Ok(id)
    }

    pub fn record_sync_finish(
        &self,
        history_id: &str,
        status: &str,
        downloaded_count: u32,
        downloaded_bytes: u64,
        error_msg: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            r#"
            UPDATE sync_history
            SET status = ?1,
                end_time = ?2,
                messages_downloaded = ?3,
                bytes_downloaded = ?4,
                error_message = ?5
            WHERE id = ?6
            "#,
            params![status, now, downloaded_count, downloaded_bytes as i64, error_msg, history_id],
        )?;
        Ok(())
    }

    pub fn get_storage_stats(&self) -> Result<StorageStats> {
        let conn = self.conn.lock().unwrap();
        let total_accounts: u32 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))?;
        let total_folders: u32 = conn.query_row("SELECT COUNT(*) FROM folders", [], |r| r.get(0))?;
        let total_messages: u64 = conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
        let total_bytes: u64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM messages",
            [],
            |r| r.get(0),
        )?;

        Ok(StorageStats {
            total_accounts,
            total_folders,
            total_messages,
            total_bytes,
        })
    }
}
