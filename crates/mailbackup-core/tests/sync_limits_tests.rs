//! Time and size limits of IMAP connections (issue #72): a server that goes
//! silent, trickles, or sends more than it announced ends the sync with an
//! error instead of holding it forever, keeps what was archived before, and
//! gets no further command on that session.

mod common;
use common::*;
use mailbackup_core::config::{AppConfig, GlobalSettings};
use mailbackup_core::error::Error;
use mailbackup_core::imap::{ImapSyncEngine, Limits, DEFAULT_LIMITS};
use std::time::{Duration, Instant};

fn engine(a: &Archive, limits: Limits) -> ImapSyncEngine {
    ImapSyncEngine::new(a.db.clone(), a.storage.clone()).with_limits(limits)
}

fn short(idle_secs: u64, command_secs: u64) -> Limits {
    Limits {
        connect: Duration::from_secs(1),
        idle: Duration::from_secs(idle_secs),
        command: Duration::from_secs(command_secs),
        // So a body fetch gets (almost) no extra time for its size
        min_rate: 100 * 1024 * 1024,
        ..DEFAULT_LIMITS
    }
}

fn logged_out(server: &FakeImap) -> bool {
    server.with(|m| m.raw_commands.iter().any(|(_, c)| c.to_ascii_uppercase().starts_with("LOGOUT")))
}

fn three_messages(server: &FakeImap) {
    let (m1, m2, m3) = (mail("one"), mail("two"), mail("three"));
    server.set(Some(1), &[(1, &m1), (2, &m2), (3, &m3)]);
}

#[tokio::test]
async fn a_server_that_goes_silent_mid_body_ends_the_sync_and_keeps_what_was_archived() {
    for compress in [Compress::Off, Compress::On] {
        let (a, server) = (archive(), FakeImap::start().await);
        server.set_compress(compress);
        three_messages(&server);
        server.with(|m| m.stall_body_of = Some(2));
        let acc = account(&server, "user");

        let started = Instant::now();
        let progress = sync_with_engine(engine(&a, short(1, 60)), &server, &acc).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}: ended by the idle timeout", compress);

        let error = progress.error.expect("the sync reports that it stopped");
        assert!(error.contains("idle"), "{:?}: {}", compress, error);
        assert_eq!(subjects(&a), ["one"], "{:?}: the message before the stall is kept", compress);
        assert_eq!(inbox(&a).last_synced_uid, 1, "{:?}: the checkpoint covers exactly what was stored", compress);
        assert!(!logged_out(&server), "{:?}: no further command on the timed-out session", compress);

        // The next sync picks up where it stopped
        server.with(|m| m.stall_body_of = None);
        let progress = sync_with_engine(engine(&a, short(1, 60)), &server, &acc).await.unwrap();
        assert!(progress.error.is_none(), "{:?}", progress.error);
        assert_eq!(subjects(&a).len(), 3);
    }
}

#[tokio::test]
async fn a_server_that_trickles_is_stopped_by_the_command_deadline() {
    let (a, server) = (archive(), FakeImap::start().await);
    server.set_compress(Compress::Off);
    three_messages(&server);
    // One byte every 50 ms: never idle for a second, but far too slow
    server.with(|m| m.trickle_body_of = Some((2, 50)));
    let acc = account(&server, "user");

    let started = Instant::now();
    let progress = sync_with_engine(engine(&a, short(1, 2)), &server, &acc).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    let error = progress.error.expect("stopped");
    assert!(error.contains("didn't complete within"), "{}", error);
    assert_eq!(inbox(&a).last_synced_uid, 1);
    assert!(!logged_out(&server));
}

#[tokio::test]
async fn a_command_without_an_answer_times_out() {
    let (a, server) = (archive(), FakeImap::start().await);
    three_messages(&server);
    server.with(|m| m.stall_on = Some("EXAMINE".to_string()));
    let acc = account(&server, "user");

    let started = Instant::now();
    // Idle much longer than the command deadline: the deadline must end it
    let progress = sync_with_engine(engine(&a, short(30, 1)), &server, &acc).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    let error = progress.error.expect("stopped");
    assert!(error.contains("Examining mailbox 'INBOX'") && error.contains("didn't complete"), "{}", error);
    assert_eq!(eml_files(&a), 0);
    assert!(!logged_out(&server));
}

#[tokio::test]
async fn a_body_larger_than_announced_is_refused_while_it_arrives() {
    for compress in [Compress::Off, Compress::On] {
        let (a, server) = (archive(), FakeImap::start().await);
        server.set_compress(compress);
        let mut big = mail("big");
        big.extend(std::iter::repeat_n(b'x', 512 * 1024));
        big.extend(b"\r\n");
        server.set(Some(1), &[(1, &big)]);
        // Announced as 100 bytes, sent as half a megabyte
        server.with(|m| {
            m.size_override.insert(1, 100);
        });
        let acc = account(&server, "user");

        let progress = sync_with_engine(engine(&a, DEFAULT_LIMITS), &server, &acc).await.unwrap();
        let error = progress.error.expect("stopped");
        assert!(error.contains("larger than"), "{:?}: {}", compress, error);
        assert!(archived(&a).is_empty(), "{:?}", compress);
        assert_eq!(inbox(&a).last_synced_uid, 0, "{:?}", compress);
        assert!(!logged_out(&server), "{:?}", compress);
    }
}

#[tokio::test]
async fn a_tls_handshake_without_an_answer_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accepts, then never says anything
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let a = archive();
    let mut acc = account(&FakeImap::start().await, "user");
    acc.imap_server = "127.0.0.1".to_string();
    acc.imap_port = port;

    let started = Instant::now();
    let err = engine(&a, short(30, 30)).connect_account(&acc, "pw").await.unwrap_err();
    assert!(matches!(err, Error::Timeout(_)), "{:?}", err);
    assert!(err.to_string().contains("TLS handshake"), "{}", err);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    holder.abort();
}

#[test]
fn limit_settings_are_validated_and_mapped() {
    let settings = GlobalSettings {
        imap_connect_timeout_secs: Some(10),
        imap_idle_timeout_secs: Some(45),
        imap_command_timeout_secs: Some(90),
        imap_max_message_mb: Some(100),
        ..GlobalSettings::default()
    };
    settings.validate().unwrap();
    let limits = Limits::from_settings(&settings);
    assert_eq!(limits.connect, Duration::from_secs(10));
    assert_eq!(limits.idle, Duration::from_secs(45));
    assert_eq!(limits.command, Duration::from_secs(90));
    assert_eq!(limits.max_message_bytes, 100 * 1024 * 1024);
    assert_eq!(Limits::from_settings(&GlobalSettings::default()), DEFAULT_LIMITS);

    for (field, value) in [
        ("imap_connect_timeout_secs", 0),
        ("imap_idle_timeout_secs", 0),
        ("imap_command_timeout_secs", 3601),
        ("imap_max_message_mb", 0),
        ("imap_max_message_mb", 501),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let yaml = format!(
            "data_dir: {}\ndb_path: {}\nsettings:\n  {}: {}\n",
            dir.path().join("data").display(),
            dir.path().join("c.db").display(),
            field,
            value
        );
        std::fs::write(&path, yaml).unwrap();
        let err = AppConfig::load_or_create(Some(&path)).unwrap_err().to_string();
        assert!(err.contains(field), "{} = {}: {}", field, value, err);
    }
}

// ---- Messages over the size limit ----------------------------------------

fn with_max(max_bytes: u64) -> Limits {
    Limits { max_message_bytes: max_bytes, ..DEFAULT_LIMITS }
}

fn big_mail(subject: &str, len: usize) -> Vec<u8> {
    let mut m = mail(subject);
    m.extend(std::iter::repeat_n(b'x', len));
    m.extend(b"\r\n");
    m
}

/// UID 1 and 3 small, UID 2 about 200 KB
fn one_big(server: &FakeImap) -> Vec<u8> {
    let big = big_mail("big", 200 * 1024);
    let (m1, m3) = (mail("one"), mail("three"));
    server.set(Some(1), &[(1, &m1), (2, &big), (3, &m3)]);
    big
}

/// The account's recorded syncs, oldest first: (status, reason).
fn history(a: &Archive) -> Vec<(String, Option<String>)> {
    let conn = rusqlite::Connection::open(a._dir.path().join("catalog.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT status, error_message FROM sync_history WHERE account_id = 'acc' ORDER BY start_time, rowid")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
}

fn body_fetches(server: &FakeImap) -> Vec<String> {
    server.with(|m| {
        m.raw_commands
            .iter()
            .map(|(_, c)| c.to_ascii_uppercase())
            .filter(|c| c.starts_with("UID FETCH") && c.contains("BODY.PEEK[]"))
            .collect()
    })
}

#[tokio::test]
async fn a_message_over_the_limit_is_recorded_not_fetched_and_never_counts_as_backed_up() {
    let (a, server) = (archive(), FakeImap::start().await);
    one_big(&server);
    let acc = account(&server, "user");

    let progress = sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    assert!(progress.error.is_none(), "{:?}", progress.error);
    assert_eq!(progress.skipped_messages, 1);
    let reason = progress.incomplete_reason().expect("an incomplete sync, not a success");
    assert!(reason.contains("1 message(s)"), "{}", reason);

    assert_eq!(subjects(&a), ["one", "three"]);
    assert!(!server.take_fetched().contains(&2), "the big body was never requested");
    assert_eq!(inbox(&a).last_synced_uid, 3, "the record lets the checkpoint pass it");
    let skipped = a.db.skipped_messages(Some("acc")).unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!((skipped[0].uid, skipped[0].reason.as_str()), (2, "over_size_limit"));
    assert!(skipped[0].size_bytes > 200 * 1024 && skipped[0].limit_bytes == 100 * 1024);

    // The next sync neither fetches it nor forgets it
    let progress = sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    assert!(server.take_fetched().is_empty());
    assert_eq!(progress.skipped_messages, 1);
    assert!(progress.incomplete_reason().is_some());
}

#[tokio::test]
async fn the_sync_history_records_a_skip_as_incomplete_until_it_is_recovered() {
    let (a, server) = (archive(), FakeImap::start().await);
    one_big(&server);
    let acc = account(&server, "user");
    // The skip, a sync with nothing new that still misses it, and the
    // recovery after the limit is raised
    sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    sync_with_engine(engine(&a, with_max(1024 * 1024)), &server, &acc).await.unwrap();

    let rows = history(&a);
    assert_eq!(rows.len(), 3, "{:?}", rows);
    for (status, reason) in &rows[..2] {
        assert_eq!(status, "incomplete");
        assert!(reason.as_deref().is_some_and(|r| r.contains("1 message(s)")), "{:?}", reason);
    }
    assert_eq!(rows[2], ("success".to_string(), None));
}

#[tokio::test]
async fn raising_the_limit_after_a_restart_recovers_the_message_with_one_fetch() {
    let (a, server) = (archive(), FakeImap::start().await);
    let big = one_big(&server);
    let acc = account(&server, "user");
    sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    server.take_fetched();

    // A restart: the catalog is opened again from disk
    let reopened = Archive {
        db: mailbackup_core::db::Database::open(a._dir.path().join("catalog.db")).unwrap(),
        storage: a.storage.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    server.with(|m| m.raw_commands.clear());
    let progress = sync_with_engine(engine(&reopened, with_max(1024 * 1024)), &server, &acc).await.unwrap();

    assert!(progress.incomplete_reason().is_none(), "{:?}", progress.incomplete_reason());
    assert_eq!(progress.skipped_messages, 0);
    assert_eq!(server.take_fetched(), [2], "only the skipped message is fetched");
    assert_eq!(body_fetches(&server), ["UID FETCH 2 (UID BODY.PEEK[] INTERNALDATE)"], "with a fetch of its own UID");
    let (_, body) = archived(&reopened).into_iter().find(|(m, _)| m.uid == 2).expect("archived");
    assert_eq!(body, big);
    assert!(reopened.db.skipped_messages(None).unwrap().is_empty());
}

#[tokio::test]
async fn a_requested_retry_fetches_the_message_whatever_the_limit() {
    let (a, server) = (archive(), FakeImap::start().await);
    one_big(&server);
    let acc = account(&server, "user");
    sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    server.take_fetched();

    assert_eq!(a.db.request_skipped_retry("acc").unwrap(), 1);
    let progress = sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    assert_eq!(server.take_fetched(), [2]);
    assert_eq!(progress.skipped_messages, 0);
    assert_eq!(subjects(&a).len(), 3);
}

#[tokio::test]
async fn a_skipped_message_deleted_on_the_server_loses_its_record() {
    let (a, server) = (archive(), FakeImap::start().await);
    one_big(&server);
    let acc = account(&server, "user");
    sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();

    server.with(|m| m.messages.retain(|(u, _)| *u != 2));
    let progress = sync_with_engine(engine(&a, with_max(1024 * 1024)), &server, &acc).await.unwrap();
    assert_eq!(progress.skipped_messages, 0);
    assert!(a.db.skipped_messages(None).unwrap().is_empty());
    assert_eq!(subjects(&a), ["one", "three"], "nothing is archived for it");
}

#[tokio::test]
async fn a_skip_is_not_applied_to_new_content_after_a_uidvalidity_change() {
    let (a, server) = (archive(), FakeImap::start().await);
    one_big(&server);
    let acc = account(&server, "user");
    sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    assert_eq!(a.db.skipped_messages(None).unwrap().len(), 1);

    // New UIDVALIDITY: UID 2 is now a different, small message
    let (m1, m2) = (mail("new one"), mail("new two"));
    server.set(Some(2), &[(1, &m1), (2, &m2)]);
    let progress = sync_with_engine(engine(&a, with_max(100 * 1024)), &server, &acc).await.unwrap();
    assert!(progress.incomplete_reason().is_none(), "{:?}", progress.incomplete_reason());
    assert!(subjects(&a).contains(&"new two".to_string()), "UID 2 of the new generation is archived");
    assert!(a.db.skipped_messages(None).unwrap().is_empty(), "the old record doesn't carry over");
}
