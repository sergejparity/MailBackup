//! Issue #33: with the account's opt-in, same-server re-scans re-bind
//! archived copies by the server's message ids (EMAILID / X-GM-MSGID)
//! without downloading them, and fall back to downloading and verifying on
//! anything missing, malformed, inconsistent or from another source.

mod common;
use common::*;
use mailbackup_core::config::AccountConfig;
use mailbackup_core::db::IdRebind;
use mailbackup_core::server_ids::{ServerId, ServerIdKind, SourcedId};

fn trusting(server: &FakeImap) -> AccountConfig {
    AccountConfig { trust_server_ids: true, ..account(server, "user") }
}

#[derive(Debug)]
struct Row {
    id: String,
    uid: u32,
    generation: u32,
    bytes: Vec<u8>,
    server_id: Option<String>,
    source: Option<String>,
}

/// Every INBOX row, by generation and UID.
fn rows(a: &Archive) -> Vec<Row> {
    let conn = rusqlite::Connection::open(a._dir.path().join("catalog.db")).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, uid, uid_generation, relative_path, server_id, server_id_source FROM messages
             WHERE folder_id = ?1 ORDER BY uid_generation, uid",
        )
        .unwrap();
    let list: Vec<(Row, String)> = stmt
        .query_map([inbox(a).id], |r| {
            let row = Row {
                id: r.get(0)?,
                uid: r.get(1)?,
                generation: r.get(2)?,
                bytes: Vec::new(),
                server_id: r.get(4)?,
                source: r.get(5)?,
            };
            Ok((row, r.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    list.into_iter()
        .map(|(row, path)| Row { bytes: a.storage.read_eml(&path).unwrap_or_default(), ..row })
        .collect()
}

/// (UID, bytes) bound in INBOX's current generation.
fn current(a: &Archive) -> Vec<(u32, Vec<u8>)> {
    let generation = inbox(a).uid_generation;
    rows(a).into_iter().filter(|r| r.generation == generation).map(|r| (r.uid, r.bytes)).collect()
}

fn bodies_fetched(server: &FakeImap) -> usize {
    server.take_commands().iter().filter(|c| *c == "BODY").count()
}

fn asked_for_ids(commands: &[(usize, String)]) -> bool {
    commands.iter().any(|(_, c)| {
        let c = c.to_ascii_uppercase();
        c.contains("EMAILID") || c.contains("X-GM-MSGID")
    })
}

/// Archives `msgs` (UIDs 1..) under UIDVALIDITY 1 with EMAILIDs `ids`, then
/// lets the same server renumber them (UIDVALIDITY 2) to `new_uids`.
async fn archived_then_renumbered(
    a: &Archive,
    server: &FakeImap,
    acc: &AccountConfig,
    msgs: &[(u32, Vec<u8>, &str)],
    renumbered: &[(u32, Vec<u8>, &str)],
) {
    let set: Vec<(u32, &[u8])> = msgs.iter().map(|(u, m, _)| (*u, m.as_slice())).collect();
    server.set(Some(1), &set);
    server.set_email_ids(&msgs.iter().map(|(u, _, id)| (*u, *id)).collect::<Vec<_>>());
    sync(a, server, acc).await;
    let set: Vec<(u32, &[u8])> = renumbered.iter().map(|(u, m, _)| (*u, m.as_slice())).collect();
    server.set(Some(2), &set);
    server.set_email_ids(&renumbered.iter().map(|(u, _, id)| (*u, *id)).collect::<Vec<_>>());
    server.take_commands();
    server.take_fetched();
    server.take_raw_commands();
}

#[tokio::test]
async fn a_same_server_rescan_rebinds_by_emailid_without_bodies() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    let (m1, m2, m3) = (mail("A"), mail("B"), mail("C"));
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, m1.clone(), "M1"), (2, m2.clone(), "M2"), (3, m3.clone(), "M3")],
        &[(11, m1.clone(), "M1"), (12, m2.clone(), "M2"), (13, m3.clone(), "M3")],
    )
    .await;
    let before: Vec<String> = rows(&a).into_iter().map(|r| r.id).collect();
    assert!(rows(&a).iter().all(|r| r.source.as_deref() == Some(acc.remote_identity().as_str())));

    sync(&a, &server, &acc).await;
    assert_eq!(bodies_fetched(&server), 0, "no body downloaded");
    assert!(server.take_fetched().is_empty());
    assert_eq!(current(&a), [(11, m1), (12, m2), (13, m3)]);
    let after: Vec<String> = rows(&a).into_iter().map(|r| r.id).collect();
    assert_eq!(before, after, "the same rows, re-bound");
    assert_eq!(inbox(&a).last_synced_uid, 13);
    assert_eq!(eml_files(&a), 3, "the files are unchanged");
}

#[tokio::test]
async fn gmail_ids_above_the_signed_range_round_trip() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    let big = 18_446_744_073_709_551_000u64;
    assert!(big > i64::MAX as u64);
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    server.set_gmail_ids(&[(1, big), (2, u64::MAX)]);
    sync(&a, &server, &acc).await;
    let stored: Vec<Option<String>> = rows(&a).into_iter().map(|r| r.server_id).collect();
    assert_eq!(stored, [Some(big.to_string()), Some(u64::MAX.to_string())]);
    let first = rows(&a).remove(0);
    let (id, _) = a.db.message_server_id(&first.id).unwrap().unwrap();
    assert_eq!(id, ServerId::gmail_msg_id(big));

    server.set(Some(2), &[(7, &mail("A")), (8, &mail("B"))]);
    server.set_gmail_ids(&[(7, big), (8, u64::MAX)]);
    server.take_commands();
    sync(&a, &server, &acc).await;
    assert_eq!(bodies_fetched(&server), 0);
    assert_eq!(current(&a), [(7, mail("A")), (8, mail("B"))]);
}

#[tokio::test]
async fn an_id_with_another_size_is_downloaded_and_distrusts_the_source() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, mail("A"), "M1"), (2, mail("B"), "M2")],
        &[(11, mail("A"), "M1"), (12, mail("B"), "M2")],
    )
    .await;
    server.with(|mb| mb.size_override.insert(11, 9999));
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [11, 12], "downloaded and verified");
    assert!(a.db.server_id_distrusted("acc", &acc.remote_identity(), ServerIdKind::EmailId).unwrap());
    assert_eq!(current(&a), [(11, mail("A")), (12, mail("B"))]);

    // The next re-scan downloads everything too
    server.with(|mb| mb.size_override.clear());
    server.set(Some(3), &[(21, &mail("A")), (22, &mail("B"))]);
    server.set_email_ids(&[(21, "M1"), (22, "M2")]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [21, 22]);
}

#[tokio::test]
async fn an_id_whose_archived_file_is_damaged_is_downloaded() {
    for damage in ["missing", "corrupt"] {
        let (a, server) = (archive(), FakeImap::start().await);
        let acc = trusting(&server);
        archived_then_renumbered(
            &a,
            &server,
            &acc,
            &[(1, mail("A"), "M1"), (2, mail("B"), "M2")],
            &[(11, mail("A"), "M1"), (12, mail("B"), "M2")],
        )
        .await;
        let damaged = a.db.get_messages_for_folder(&inbox(&a).id).unwrap().into_iter().find(|m| m.uid == 1).unwrap();
        let file = a.storage.base_dir().join(&damaged.relative_path);
        match damage {
            "missing" => std::fs::remove_file(&file).unwrap(),
            _ => std::fs::write(&file, b"garbage").unwrap(),
        }
        sync(&a, &server, &acc).await;
        assert_eq!(server.take_fetched(), [11], "{}: only the damaged one", damage);
        assert_eq!(current(&a), [(11, mail("A")), (12, mail("B"))], "{}", damage);
        assert!(rows(&a).iter().any(|r| r.id == damaged.id), "{}: the damaged row is kept", damage);
    }
}

#[tokio::test]
async fn ids_from_another_source_are_never_used() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, mail("A"), "M1"), (2, mail("B"), "M2")],
        &[(1, mail("A"), "M1"), (2, mail("B"), "M2")],
    )
    .await;
    // Another username on the same server: same id strings, another store
    let other = AccountConfig { username: "user2".into(), ..acc.clone() };
    sync(&a, &server, &other).await;
    assert_eq!(server.take_fetched(), [1, 2], "everything downloaded");
    assert_eq!(current(&a), [(1, mail("A")), (2, mail("B"))]);
    assert!(rows(&a).iter().all(|r| r.source.as_deref() == Some(other.remote_identity().as_str())));
}

#[tokio::test]
async fn nothing_changes_without_the_opt_in_or_the_capability() {
    for case in ["opt-in off", "not offered"] {
        let (a, server) = (archive(), FakeImap::start().await);
        let acc = if case == "opt-in off" { account(&server, "user") } else { trusting(&server) };
        server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
        server.set_email_ids(&[(1, "M1"), (2, "M2")]);
        if case == "not offered" {
            server.with(|mb| mb.object_id = false);
        }
        sync(&a, &server, &acc).await;
        server.set(Some(2), &[(11, &mail("A")), (12, &mail("B"))]);
        server.set_email_ids(&[(11, "M1"), (12, "M2")]);
        if case == "not offered" {
            server.with(|mb| mb.object_id = false);
        }
        sync(&a, &server, &acc).await;
        assert!(!asked_for_ids(&server.take_raw_commands()), "{}: no id requested", case);
        assert_eq!(server.take_fetched(), [1, 2, 11, 12], "{}: every body downloaded", case);
        assert!(rows(&a).iter().all(|r| r.server_id.is_none()), "{}", case);
        assert_eq!(current(&a), [(11, mail("A")), (12, mail("B"))], "{}", case);
    }
}

#[tokio::test]
async fn emailids_are_case_sensitive() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    // Same size, ids differing only in case; renumbered in reverse order
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, mail("A"), "Mabc"), (2, mail("B"), "MABC")],
        &[(11, mail("B"), "MABC"), (12, mail("A"), "Mabc")],
    )
    .await;
    sync(&a, &server, &acc).await;
    assert_eq!(bodies_fetched(&server), 0);
    assert_eq!(current(&a), [(11, mail("B")), (12, mail("A"))]);
}

#[tokio::test]
async fn copies_sharing_an_id_are_rebound_one_to_one() {
    // Two archived copies, two UIDs: both re-bound
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, mail("A"), "Mdup"), (2, mail("A"), "Mdup")],
        &[(11, mail("A"), "Mdup"), (12, mail("A"), "Mdup")],
    )
    .await;
    sync(&a, &server, &acc).await;
    assert_eq!(bodies_fetched(&server), 0);
    assert_eq!(current(&a), [(11, mail("A")), (12, mail("A"))]);
    assert_eq!(rows(&a).len(), 2);

    // One archived copy, two UIDs: the second is downloaded
    let (b, server2) = (archive(), FakeImap::start().await);
    let acc2 = trusting(&server2);
    archived_then_renumbered(&b, &server2, &acc2, &[(1, mail("A"), "Mdup")], &[(11, mail("A"), "Mdup"), (12, mail("A"), "Mdup")])
        .await;
    sync(&b, &server2, &acc2).await;
    assert_eq!(server2.take_fetched(), [12]);
    assert_eq!(current(&b), [(11, mail("A")), (12, mail("A"))]);
    assert!(!b.db.server_id_distrusted("acc", &acc2.remote_identity(), ServerIdKind::EmailId).unwrap(), "the same content");
}

#[tokio::test]
async fn malformed_but_delimited_ids_fall_back_for_their_message_only() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    let long = "x".repeat(256);
    let subjects = ["A", "B", "C", "D"];
    let first: Vec<(u32, Vec<u8>, &str)> =
        subjects.iter().zip(["M1", "M2", "M3", "M4"]).zip(1..).map(|((s, id), u)| (u, mail(s), id)).collect();
    // Empty, a bad character, too long; then a valid one
    let again: Vec<(u32, Vec<u8>, &str)> =
        subjects.iter().zip(["", "bad.value", long.as_str(), "M4"]).zip(11..).map(|((s, id), u)| (u, mail(s), id)).collect();
    archived_then_renumbered(&a, &server, &acc, &first, &again).await;

    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [11, 12, 13], "the malformed ones are downloaded, M4 is re-bound");
    assert_eq!(current(&a).len(), 4);
    let ids: Vec<(u32, Option<String>)> =
        rows(&a).into_iter().filter(|r| r.generation == inbox(&a).uid_generation).map(|r| (r.uid, r.server_id)).collect();
    assert_eq!(ids, [(11, None), (12, None), (13, None), (14, Some("M4".into()))], "a malformed id is never stored");
    assert!(!a.db.server_id_distrusted("acc", &acc.remote_identity(), ServerIdKind::EmailId).unwrap());
}

#[tokio::test]
async fn an_unparseable_id_in_the_size_query_reconnects_without_ids() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, mail("A"), "M1"), (2, mail("B"), "M2"), (3, mail("C"), "M3")],
        &[(11, mail("A"), "M1"), (12, mail("B"), "M2"), (13, mail("C"), "M3")],
    )
    .await;
    server.with(|mb| mb.id_attrs.insert(12, "EMAILID NIL".into()));
    let broken_connection = server.with(|mb| mb.connections) + 1;
    sync(&a, &server, &acc).await;

    let commands = server.take_raw_commands();
    let on_broken: Vec<&String> = commands.iter().filter(|(c, _)| *c == broken_connection).map(|(_, l)| l).collect();
    let last = on_broken.last().unwrap().to_ascii_uppercase();
    assert!(last.contains("RFC822.SIZE EMAILID"), "nothing sent after the broken response: {:?}", on_broken);
    let after: Vec<(usize, String)> = commands.iter().filter(|(c, _)| *c > broken_connection).cloned().collect();
    assert!(!after.is_empty(), "a fresh connection");
    assert!(!asked_for_ids(&after), "which asks for no ids");
    assert_eq!(current(&a), [(11, mail("A")), (12, mail("B")), (13, mail("C"))]);
    assert_eq!(inbox(&a).last_synced_uid, 13);
    assert!(a.db.server_id_disabled("acc", &acc.remote_identity(), ServerIdKind::EmailId).unwrap());

    // And later syncs don't ask either
    server.set(Some(3), &[(21, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert!(!asked_for_ids(&server.take_raw_commands()));
}

#[tokio::test]
async fn an_unparseable_id_in_a_body_batch_keeps_what_arrived_before_it() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B")), (3, &mail("C"))]);
    server.set_email_ids(&[(1, "M1"), (3, "M3")]);
    server.with(|mb| mb.id_attrs.insert(2, "EMAILID M2".into()));
    sync(&a, &server, &acc).await;
    let fetched = server.take_fetched();
    assert_eq!(fetched.iter().filter(|u| **u == 1).count(), 1, "UID 1 kept from the broken batch: {:?}", fetched);
    assert_eq!(current(&a), [(1, mail("A")), (2, mail("B")), (3, mail("C"))]);
    let ids: Vec<Option<String>> = rows(&a).into_iter().map(|r| r.server_id).collect();
    assert_eq!(ids, [Some("M1".into()), None, None], "the retry asked for no ids");
    assert_eq!(inbox(&a).last_synced_uid, 3);
}

#[tokio::test]
async fn a_uidvalidity_change_before_the_reconnect_is_noticed() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    server.set_email_ids(&[(1, "M1")]);
    server.with(|mb| mb.id_attrs.insert(2, "EMAILID (unbalanced".into()));
    // The connection after the broken one sees another UIDVALIDITY
    let reconnect = server.with(|mb| mb.connections) + 2;
    server.with(|mb| mb.uidvalidity_on_connection = Some((reconnect, 7)));
    sync(&a, &server, &acc).await;
    assert_eq!(inbox(&a).uidvalidity, Some(7));
    assert_eq!(current(&a), [(1, mail("A")), (2, mail("B"))], "re-scanned under the new UIDVALIDITY");
    let generation = inbox(&a).uid_generation;
    assert!(rows(&a).iter().all(|r| r.generation == generation), "nothing left in the old generation: {:?}", rows(&a));
}

#[tokio::test]
async fn a_b_a_with_overlapping_id_strings() {
    let (a, server_a, server_b) = (archive(), FakeImap::start().await, FakeImap::start().await);
    let on_a = trusting(&server_a);
    let on_b = AccountConfig { imap_port: server_b.port, ..on_a.clone() };
    server_a.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    server_a.set_email_ids(&[(1, "M1"), (2, "M2")]);
    sync(&a, &server_a, &on_a).await;

    // B holds A's first message under another id, and its own messages
    // under A's id strings
    server_b.set(Some(1), &[(5, &mail("A")), (6, &mail("X")), (7, &mail("Y"))]);
    server_b.set_email_ids(&[(5, "X9"), (6, "M1"), (7, "M2")]);
    sync(&a, &server_b, &on_b).await;
    assert_eq!(server_b.take_fetched(), [5, 6, 7], "another source: everything downloaded");

    // Back on A (renumbered): only the row that still carries A's id is
    // re-bound by it
    server_a.set(Some(2), &[(21, &mail("A")), (22, &mail("B"))]);
    server_a.set_email_ids(&[(21, "M1"), (22, "M2")]);
    server_a.take_fetched();
    sync(&a, &server_a, &on_a).await;
    assert_eq!(server_a.take_fetched(), [21], "A's first message carries B's id now, so it is downloaded");
    assert_eq!(current(&a), [(21, mail("A")), (22, mail("B"))]);
    let all = rows(&a);
    assert_eq!(all.len(), 4, "A, B, X, Y");
    for r in &all {
        assert_eq!(r.bytes == mail("X") || r.bytes == mail("Y"), r.generation != inbox(&a).uid_generation);
    }
}

#[tokio::test]
async fn reused_ids_undo_the_rebinds_already_taken() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    // The server reuses M1: UID 11 has other content of the same size, UID 12
    // yet another
    archived_then_renumbered(&a, &server, &acc, &[(1, mail("A"), "M1")], &[(11, mail("Q"), "M1"), (12, mail("R"), "M1")]).await;
    assert_eq!(mail("A").len(), mail("Q").len());
    let original = rows(&a).remove(0);

    sync(&a, &server, &acc).await;
    assert!(a.db.server_id_distrusted("acc", &acc.remote_identity(), ServerIdKind::EmailId).unwrap());
    assert_eq!(server.take_fetched(), [12, 11], "UID 12 revealed it, then UID 11 was checked");
    assert_eq!(current(&a), [(11, mail("Q")), (12, mail("R"))]);
    let back = rows(&a).into_iter().find(|r| r.id == original.id).unwrap();
    assert_eq!((back.generation, back.uid, back.bytes), (original.generation, 1, mail("A")), "back where it was");
    assert!(a.db.pending_id_rebinds(&inbox(&a).id).unwrap().is_empty());
    assert_eq!(inbox(&a).last_synced_uid, 12);
}

#[tokio::test]
async fn an_unfinished_check_of_rebinds_resumes_at_the_next_sync() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    archived_then_renumbered(&a, &server, &acc, &[(1, mail("A"), "M1")], &[(11, mail("Q"), "M1"), (12, mail("R"), "M1")]).await;
    // The check's download of UID 11 fails
    server.fail_fetch_of(11);
    sync(&a, &server, &acc).await;
    assert_eq!(inbox(&a).last_synced_uid, 12, "the checkpoint had already passed it");
    assert_eq!(a.db.pending_id_rebinds(&inbox(&a).id).unwrap().len(), 1, "still to be checked");

    sync(&a, &server, &acc).await;
    assert!(a.db.pending_id_rebinds(&inbox(&a).id).unwrap().is_empty());
    assert_eq!(current(&a), [(11, mail("Q")), (12, mail("R"))]);
    assert!(rows(&a).iter().any(|r| r.uid == 1 && r.bytes == mail("A")));
}

#[tokio::test]
async fn an_interrupted_rescan_by_ids_resumes_without_loss() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = trusting(&server);
    archived_then_renumbered(
        &a,
        &server,
        &acc,
        &[(1, mail("A"), "M1"), (2, mail("B"), "M2")],
        &[(11, mail("A"), "M1"), (12, mail("N"), "M9"), (13, mail("B"), "M2")],
    )
    .await;
    server.fail_fetch_of(12);
    sync(&a, &server, &acc).await;
    assert_eq!(inbox(&a).last_synced_uid, 11, "held below the unfetched UID");

    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [12], "only the new message is downloaded");
    assert_eq!(current(&a), [(11, mail("A")), (12, mail("N")), (13, mail("B"))]);
    assert_eq!(rows(&a).len(), 3);
    assert_eq!(inbox(&a).last_synced_uid, 13);
}

#[tokio::test]
async fn distrust_lasts_until_reset_and_is_per_source() {
    let (a, server_a, server_b) = (archive(), FakeImap::start().await, FakeImap::start().await);
    let on_a = trusting(&server_a);
    let on_b = AccountConfig { imap_port: server_b.port, ..on_a.clone() };
    archived_then_renumbered(&a, &server_a, &on_a, &[(1, mail("A"), "M1")], &[(11, mail("A"), "M1")]).await;
    a.db.record_server_id_distrust("acc", &on_a.remote_identity(), ServerIdKind::EmailId, "test").unwrap();

    // A → B → A: still distrusted on A
    server_b.set(Some(1), &[(1, &mail("B"))]);
    server_b.set_email_ids(&[(1, "M1")]);
    sync(&a, &server_b, &on_b).await;
    assert!(!a.db.server_id_distrusted("acc", &on_b.remote_identity(), ServerIdKind::EmailId).unwrap(), "B has its own state");
    sync(&a, &server_a, &on_a).await;
    assert_eq!(server_a.take_fetched(), [11], "A's ids are still not trusted");

    // After an explicit reset, A's ids are used again
    assert_eq!(a.db.reset_server_id_state("acc", None).unwrap(), 1);
    server_a.set(Some(3), &[(31, &mail("A"))]);
    server_a.set_email_ids(&[(31, "M1")]);
    sync(&a, &server_a, &on_a).await;
    assert!(server_a.take_fetched().is_empty());
    assert_eq!(current(&a), [(31, mail("A"))]);
}

// --- Catalog rules, directly ----------------------------------------------

fn db_setup() -> (Archive, String, String) {
    let a = archive();
    let f1 = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "src").unwrap();
    let f2 = a.db.begin_folder_sync("acc", "Other", "Other", Some(1), "src").unwrap();
    (a, f1.folder.id, f2.folder.id)
}

fn insert_with_id(a: &Archive, folder: &str, generation: u32, uid: u32, id: &ServerId) -> String {
    a.db.insert_new_message(&mailbackup_core::db::NewMessage {
        account_id: "acc",
        folder_id: folder,
        generation,
        uid,
        message_id: None,
        subject: None,
        from_addr: None,
        to_addrs: None,
        cc_addrs: None,
        date: None,
        size_bytes: 10,
        relative_path: "x.eml",
        sha256_hash: "h",
        body_text: None,
        attachments: &[],
        server_id: Some(SourcedId { id, source: "src" }),
    })
    .unwrap()
}

#[test]
fn candidates_stay_within_their_folder_and_writes_are_fenced() {
    let (a, inbox_id, other_id) = db_setup();
    let id = ServerId::email_id("M1").unwrap();
    insert_with_id(&a, &other_id, 0, 1, &id);
    let next = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(2), "src").unwrap();
    let sourced = SourcedId { id: &id, source: "src" };
    assert_eq!(
        a.db.rebind_by_server_id_if("acc", &inbox_id, next.generation, 5, sourced, 10, |_, _| true).unwrap(),
        IdRebind::NoCandidate,
        "another folder's row is never a candidate"
    );

    // A stale session can't re-bind by id
    insert_with_id(&a, &inbox_id, next.generation, 1, &id);
    let stale = next.generation;
    a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(3), "src").unwrap();
    assert!(stale_result(a.db.rebind_by_server_id_if("acc", &inbox_id, stale, 6, sourced, 10, |_, _| true)));
}

#[test]
fn distrust_found_anywhere_makes_every_folder_check_its_rebinds() {
    let (a, inbox_id, other_id) = db_setup();
    let id = ServerId::email_id("M1").unwrap();
    insert_with_id(&a, &other_id, 0, 1, &id);
    let next = a.db.begin_folder_sync("acc", "Other", "Other", Some(2), "src").unwrap();
    let sourced = SourcedId { id: &id, source: "src" };
    assert!(matches!(
        a.db.rebind_by_server_id_if("acc", &other_id, next.generation, 9, sourced, 10, |_, _| true).unwrap(),
        IdRebind::Rebound(_)
    ));
    assert!(a.db.pending_id_rebinds(&other_id).unwrap().is_empty(), "trusted so far");
    // Found while syncing INBOX: Other's re-bind is now to be checked
    a.db.record_server_id_distrust("acc", "src", ServerIdKind::EmailId, "seen in INBOX").unwrap();
    let pending = a.db.pending_id_rebinds(&other_id).unwrap();
    assert_eq!(pending.iter().map(|p| p.uid).collect::<Vec<_>>(), [9]);
    assert!(a.db.pending_id_rebinds(&inbox_id).unwrap().is_empty());
}
