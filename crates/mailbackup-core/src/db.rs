use crate::error::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
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
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()));
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
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
        let conn = self.conn.lock().unwrap();
        // Clean query for FTS5 (escape quotes if needed)
        let sanitized_query = query.replace('"', "\"\"");
        let fts_query = format!("\"{}\"", sanitized_query);

        let mut stmt = conn.prepare(
            r#"
            SELECT 
                m.id, m.account_id, f.remote_name, m.subject, m.from_addr, m.to_addrs, m.date, m.relative_path,
                snippet(messages_fts, -1, '<b>', '</b>', '...', 15) as snip
            FROM messages_fts
            JOIN messages m ON m.id = messages_fts.message_id
            JOIN folders f ON f.id = m.folder_id
            WHERE messages_fts MATCH ?1
            ORDER BY rank
            LIMIT ?2
            "#,
        )?;

        let rows = stmt.query_map(params![fts_query, limit], |row| {
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
