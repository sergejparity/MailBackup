//! A canonical dump of the catalog: schema version, schema, and every row of
//! the data tables (FTS through its virtual table, not its b-tree shadow
//! tables), in a stable order. Written next to the fixture by the generator;
//! the tests dump the database again after opening it with the current code
//! and compare.

use rusqlite::types::ValueRef;
use serde_json::{json, Map, Value};

const TABLES: [&str; 9] = [
    "accounts",
    "folders",
    "messages",
    "attachments",
    "sync_history",
    "account_transitions",
    "server_id_distrust",
    "server_id_disabled",
    "server_id_rebinds",
];

pub fn snapshot(conn: &rusqlite::Connection) -> Value {
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    let schema = rows(conn, "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name");
    let mut tables = Map::new();
    for table in TABLES {
        tables.insert(table.to_string(), rows(conn, &format!("SELECT * FROM {} ORDER BY rowid", table)));
    }
    // Schema 5 (issue #79) links the index by `messages.seq` instead of
    // keeping the message id in it: read it back by message id either way
    let old_shape = conn
        .prepare("SELECT message_id FROM messages_fts LIMIT 0")
        .is_ok();
    let fts = if old_shape {
        "SELECT rowid, message_id, account_id, subject, from_addr, to_addrs, body_text, attachment_names FROM messages_fts ORDER BY rowid"
    } else {
        "SELECT f.rowid AS rowid, m.id AS message_id, m.account_id AS account_id, f.subject, f.from_addr, f.to_addrs, f.body_text, f.attachment_names FROM messages_fts f JOIN messages m ON m.seq = f.rowid ORDER BY f.rowid"
    };
    tables.insert("messages_fts".to_string(), rows(conn, fts));
    json!({ "user_version": user_version, "schema": schema, "tables": tables })
}

fn rows(conn: &rusqlite::Connection, sql: &str) -> Value {
    let mut stmt = conn.prepare(sql).unwrap();
    let names: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let mut obj = Map::new();
        for (i, name) in names.iter().enumerate() {
            let value = match row.get_ref(i).unwrap() {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(n) => json!(n),
                ValueRef::Real(f) => json!(f),
                ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                ValueRef::Blob(b) => json!({ "blob_hex": hex::encode(b) }),
            };
            obj.insert(name.clone(), value);
        }
        out.push(Value::Object(obj));
    }
    Value::Array(out)
}
