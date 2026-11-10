//! Schema 5 (issue #79): numeric dates for filters.

use mailbackup_core::db::{AdvancedSearchFilter, Database};

fn catalog_with_dates(dates: &[(&str, &str)]) -> (tempfile::TempDir, Database) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    let db = Database::open(&path).unwrap();
    let folder = db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    for (i, (subject, _)) in dates.iter().enumerate() {
        db.insert_message(
            "acc", &folder.id, i as u32 + 1, None, Some(subject), None, None, None, None, 1, &format!("p{}", i), "h", None, &[],
        )
        .unwrap();
    }
    // Dates as older versions or other writers may have stored them: any
    // RFC 3339 spelling, with `date_ts` as the migration computes it
    let conn = rusqlite::Connection::open(&path).unwrap();
    for (subject, date) in dates {
        conn.execute("UPDATE messages SET date = ?1, date_ts = unixepoch(?1) WHERE subject = ?2", [date, subject]).unwrap();
    }
    (dir, db)
}

fn subjects(db: &Database, from: Option<&str>, to: Option<&str>) -> Vec<String> {
    let filter = AdvancedSearchFilter {
        date_from: from.map(str::to_string),
        date_to: to.map(str::to_string),
        limit: Some(100),
        ..Default::default()
    };
    let mut found: Vec<String> = db.search_advanced(&filter).unwrap().into_iter().map(|r| r.subject).collect();
    found.sort();
    found
}

#[test]
fn date_filters_compare_instants_at_exact_day_boundaries() {
    let (_dir, db) = catalog_with_dates(&[
        ("a-last-second-before", "2026-03-01T23:59:59Z"),
        ("b-first-second", "2026-03-02T00:00:00+00:00"),
        // 23:30 at -02:00 is 01:30 UTC on the 2nd
        ("c-offset-inside", "2026-03-01T23:30:00-02:00"),
        ("d-last-second", "2026-03-02T23:59:59.999999+00:00"),
        // 01:00 at +02:00 is 23:00 UTC on the 2nd
        ("e-offset-inside", "2026-03-03T01:00:00+02:00"),
        ("f-next-day", "2026-03-03T00:00:00Z"),
    ]);
    assert_eq!(
        subjects(&db, Some("2026-03-02"), Some("2026-03-02")),
        ["b-first-second", "c-offset-inside", "d-last-second", "e-offset-inside"]
    );
    assert_eq!(subjects(&db, None, Some("2026-03-01")), ["a-last-second-before"]);
    assert_eq!(subjects(&db, Some("2026-03-03"), None), ["f-next-day"]);
}

#[test]
fn new_messages_get_their_numeric_date() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    let db = Database::open(&path).unwrap();
    let folder = db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let date = chrono::DateTime::parse_from_rfc3339("2026-05-06T07:08:09+03:00").unwrap().with_timezone(&chrono::Utc);
    let id = db
        .insert_message("acc", &folder.id, 1, None, Some("s"), None, None, None, Some(date), 1, "p", "h", None, &[])
        .unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let ts: i64 = conn.query_row("SELECT date_ts FROM messages WHERE id = ?1", [&id], |r| r.get(0)).unwrap();
    assert_eq!(ts, date.timestamp());
}
