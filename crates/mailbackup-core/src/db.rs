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

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    current_path: Arc<Mutex<PathBuf>>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref().to_path_buf();
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
            std::fs::create_dir_all(parent)?;
        }

        {
            let mut conn_guard = self.conn.lock().unwrap();

            if move_existing && old_p.exists() && old_p.to_string_lossy() != ":memory:" {
                // Checkpoint WAL cleanly so main DB file has all data
                let _ = conn_guard.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

                // Copy main .db file
                std::fs::copy(&old_p, new_p)?;

                // Also copy WAL and SHM if present
                let old_wal = format!("{}-wal", old_p.display());
                let new_wal = format!("{}-wal", new_p.display());
                if std::path::Path::new(&old_wal).exists() {
                    let _ = std::fs::copy(&old_wal, &new_wal);
                }
                let old_shm = format!("{}-shm", old_p.display());
                let new_shm = format!("{}-shm", new_p.display());
                if std::path::Path::new(&old_shm).exists() {
                    let _ = std::fs::copy(&old_shm, &new_shm);
                }
            }

            // Open new connection on relocated path
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
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
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
            "#
        )?;
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
            SELECT id, account_id, remote_name, local_slug, uidvalidity, last_synced_uid, message_count, updated_at
            FROM folders
            WHERE account_id = ?1 AND remote_name = ?2
            "#,
            params![account_id, remote_name],
            |row| {
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
                })
            },
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
            SELECT id, account_id, remote_name, local_slug, uidvalidity, last_synced_uid, message_count, updated_at
            FROM folders
            WHERE account_id = ?1
            ORDER BY remote_name ASC
            "#,
        )?;

        let rows = stmt.query_map(params![account_id], |row| {
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
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn message_exists_by_uid(&self, folder_id: &str, uid: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid],
            |row| row.get(0),
        )?;
        Ok(count > 0)
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
        let conn = self.conn.lock().unwrap();
        let new_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let date_str = date.map(|d| d.to_rfc3339());

        conn.execute(
            r#"
            INSERT INTO messages (
                id, account_id, folder_id, uid, message_id, subject, from_addr,
                to_addrs, cc_addrs, date, size_bytes, relative_path, sha256_hash,
                is_remote_deleted, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14)
            "#,
            params![
                new_id, account_id, folder_id, uid, message_id, subject, from_addr,
                to_addrs, cc_addrs, date_str, size_bytes as i64, relative_path, sha256_hash, now
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
            let clean_df = if df.len() >= 10 { &df[..10] } else { df };
            conditions.push("date(m.date) >= ?".to_string());
            params.push(rusqlite::types::Value::Text(clean_df.to_string()));
        }

        if let Some(dt) = filter.date_to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let clean_dt = if dt.len() >= 10 { &dt[..10] } else { dt };
            conditions.push("date(m.date) <= ?".to_string());
            params.push(rusqlite::types::Value::Text(clean_dt.to_string()));
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
                    snippet(messages_fts, -1, '<b>', '</b>', '...', 15) as snip
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
                snippet: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
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
