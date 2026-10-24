//! Issue #32: cheaper transfers without weaker integrity. Sync compresses
//! when the server offers it, fetches bodies in batches, re-binds only on a
//! full-content match with an intact archived copy, and never moves its
//! checkpoint past a UID it hasn't archived (unless the server confirms the
//! UID is gone).

mod common;
use common::*;
use mailbackup_core::imap::ImapSyncEngine;

fn count(commands: &[String], name: &str) -> usize {
    commands.iter().filter(|c| *c == name).count()
}

/// A message whose body is `fill` repeated: compressible, fixed length.
fn sized_mail(subject: &str, fill: char, len: usize) -> Vec<u8> {
    let mut m = format!("From: a@example.com\r\nSubject: {}\r\nMessage-ID: <same@example.com>\r\n\r\n", subject).into_bytes();
    m.extend(std::iter::repeat_n(fill as u8, len));
    m.extend(b"\r\n");
    m
}

#[tokio::test]
async fn equal_headers_and_size_are_not_mistaken_for_the_same_message() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    // Identical raw headers, size, INTERNALDATE and Message-ID; the bodies
    // differ but have the same length
    let old = sized_mail("Same", 'x', 64);
    let new = sized_mail("Same", 'y', 64);
    assert_eq!(old.len(), new.len());
    server.set(Some(1), &[(1, &old)]);
    sync(&a, &server, &acc).await;

    server.set(Some(2), &[(1, &new)]);
    sync(&a, &server, &acc).await;
    let bodies: Vec<Vec<u8>> = archived(&a).into_iter().map(|(_, b)| b).collect();
    assert_eq!(bodies.len(), 2, "the new body is archived and the old one kept");
    assert!(bodies.contains(&old) && bodies.contains(&new));
}

#[tokio::test]
async fn a_damaged_archived_copy_is_not_re_bound() {
    for damage in ["missing", "corrupt"] {
        let (a, server) = (archive(), FakeImap::start().await);
        let acc = account(&server, "user");
        server.set(Some(1), &[(1, &mail("A"))]);
        sync(&a, &server, &acc).await;
        let (old_row, _) = archived(&a).remove(0);
        let file = a.storage.base_dir().join(&old_row.relative_path);
        match damage {
            "missing" => std::fs::remove_file(&file).unwrap(),
            _ => std::fs::write(&file, b"garbage").unwrap(),
        }

        server.set(Some(2), &[(5, &mail("A"))]);
        sync(&a, &server, &acc).await;
        let rows = a.db.get_messages_for_folder(&inbox(&a).id).unwrap();
        let fresh = rows.iter().find(|m| m.uid == 5).expect("UID 5 archived");
        assert_ne!(fresh.id, old_row.id, "{}: a new copy, not the damaged one", damage);
        assert_eq!(a.storage.read_eml(&fresh.relative_path).unwrap(), mail("A"), "{}", damage);
        assert!(rows.iter().any(|m| m.id == old_row.id), "{}: the damaged row isn't hidden", damage);
    }
}

#[tokio::test]
async fn a_uid_whose_body_never_arrives_holds_the_checkpoint() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B")), (3, &mail("C"))]);
    server.with(|mb| mb.omit_body_of.insert(2));
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "C"], "the rest is archived");
    assert_eq!(inbox(&a).last_synced_uid, 1, "but the checkpoint stays below UID 2");
    let commands = server.take_commands();
    assert_eq!(count(&commands, "BODY"), 2, "the batch, then UID 2 once more on its own");
    assert_eq!(count(&commands, "SEARCH"), 2, "the new-UID search, then the check that UID 2 still exists");

    // Next sync asks again for UID 2 only
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty());
    assert_eq!(inbox(&a).last_synced_uid, 1);

    // Once the server returns it, it's archived and the checkpoint moves on
    server.with(|mb| mb.omit_body_of.clear());
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [2]);
    assert_eq!(subjects(&a), ["A", "B", "C"]);
    assert_eq!(inbox(&a).last_synced_uid, 3);
}

#[tokio::test]
async fn a_uid_expunged_before_its_fetch_is_resolved() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B")), (3, &mail("C"))]);
    // Listed by the search, gone by the time it's fetched
    server.with(|mb| mb.expunge_on_fetch.insert(2));
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "C"]);
    assert_eq!(inbox(&a).last_synced_uid, 3, "confirmed absent: the checkpoint passes it");

    server.take_fetched();
    server.take_commands();
    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty(), "nothing asked again");
}

#[tokio::test]
async fn a_uid_without_a_size_is_still_fetched() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B")), (3, &mail("C"))]);
    server.with(|mb| mb.omit_size_of.insert(2));
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "B", "C"]);
    assert_eq!(inbox(&a).last_synced_uid, 3);
    // UID 2 (unknown size) is fetched on its own: [1], [2], [3]
    assert_eq!(count(&server.take_commands(), "BODY"), 3);
}

#[tokio::test]
async fn bodies_are_fetched_in_batches() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    let mails: Vec<(u32, Vec<u8>)> = (1..=120).map(|u| (u, mail(&format!("m{}", u)))).collect();
    let refs: Vec<(u32, &[u8])> = mails.iter().map(|(u, m)| (*u, m.as_slice())).collect();
    server.set(Some(1), &refs);
    sync(&a, &server, &acc).await;
    let commands = server.take_commands();
    assert_eq!((count(&commands, "SIZE"), count(&commands, "BODY")), (1, 3), "1 size query, batches of 50");
    assert_eq!(archived(&a).len(), 120);

    // Byte target: 3 messages of 400 bytes per 1000-byte batch → 2 + 1,
    // and a message over the target is fetched alone
    let (b, server2) = (archive(), FakeImap::start().await);
    let small = |s: &str| sized_mail(s, 'z', 300);
    let big = sized_mail("big", 'q', 5000);
    server2.set(Some(1), &[(1, &small("a")), (2, &small("b")), (3, &big), (4, &small("c"))]);
    let engine = ImapSyncEngine::new(b.db.clone(), b.storage.clone()).with_batch_limits(50, 1000);
    sync_with_engine(engine, &server2, &account(&server2, "user")).await.unwrap();
    assert_eq!(count(&server2.take_commands(), "BODY"), 3, "[1, 2], [3], [4]");
    assert_eq!(archived(&b).len(), 4);
}

#[tokio::test]
async fn compression_is_used_when_offered_and_saves_bytes() {
    let fixture: Vec<(u32, Vec<u8>)> = (1..=20).map(|u| (u, sized_mail(&format!("m{}", u), 'r', 20_000))).collect();
    let refs: Vec<(u32, &[u8])> = fixture.iter().map(|(u, m)| (*u, m.as_slice())).collect();
    let payload: usize = fixture.iter().map(|(_, m)| m.len()).sum();

    let mut wire = Vec::new();
    for mode in [Compress::On, Compress::Off] {
        let (a, server) = (archive(), FakeImap::start().await);
        server.set_compress(mode);
        server.set(Some(1), &refs);
        sync(&a, &server, &account(&server, "user")).await;
        assert_eq!(archived(&a).len(), 20, "{:?}", mode);
        let commands = server.take_commands();
        assert_eq!(count(&commands, "COMPRESS"), usize::from(mode == Compress::On), "{:?}", mode);
        assert_eq!(server.with(|mb| mb.compressed_sessions), usize::from(mode == Compress::On));
        wire.push(server.wire_bytes.load(std::sync::atomic::Ordering::SeqCst) as usize);
    }
    assert!(wire[1] > payload, "uncompressed carries the payload ({} bytes)", wire[1]);
    assert!(wire[0] * 10 < wire[1], "compressed: {} bytes vs {} uncompressed", wire[0], wire[1]);
}

#[tokio::test]
async fn a_failed_switch_to_compression_reconnects_uncompressed() {
    for mode in [Compress::Reject, Compress::Drop] {
        let (a, server) = (archive(), FakeImap::start().await);
        server.set_compress(mode);
        server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
        sync(&a, &server, &account(&server, "user")).await;
        assert_eq!(subjects(&a), ["A", "B"], "{:?}", mode);
        server.with(|mb| {
            assert_eq!(mb.connections, 2, "{:?}: a fresh connection after the failed switch", mode);
            assert_eq!(mb.compressed_sessions, 0, "{:?}", mode);
        });
    }
}
