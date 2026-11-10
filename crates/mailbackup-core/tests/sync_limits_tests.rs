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
