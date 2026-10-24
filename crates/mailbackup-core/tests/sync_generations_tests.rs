//! Issue #17: when a folder's remote UIDs stop being comparable (new
//! UIDVALIDITY, another server or username), sync re-scans the folder, keeps
//! what was archived and doesn't store a message twice.
//!
//! The tests sync against a small in-process IMAP server over plain TCP.

use mailbackup_core::config::{AccountConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::{Database, MessageRecord};
use mailbackup_core::imap::{ImapSyncEngine, SyncProgress};
use mailbackup_core::storage::StorageEngine;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// --- A scripted IMAP server: one mailbox, INBOX -----------------------------

#[derive(Default)]
struct Mailbox {
    uidvalidity: Option<u32>,
    /// (uid, raw message), ascending by uid
    messages: Vec<(u32, Vec<u8>)>,
    /// UIDs fetched so far
    fetched: Vec<u32>,
    /// Drop the connection instead of answering a fetch of this UID (once)
    fail_fetch_of: Option<u32>,
}

#[derive(Clone)]
struct FakeImap {
    port: u16,
    mailbox: Arc<Mutex<Mailbox>>,
}

impl FakeImap {
    async fn start() -> FakeImap {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mailbox = Arc::new(Mutex::new(Mailbox::default()));
        let shared = mailbox.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, shared.clone()));
            }
        });
        FakeImap { port, mailbox }
    }

    /// Replaces the mailbox's contents (keeps the fetch log).
    fn set(&self, uidvalidity: Option<u32>, messages: &[(u32, &[u8])]) {
        let mut mb = self.mailbox.lock().unwrap();
        mb.uidvalidity = uidvalidity;
        mb.messages = messages.iter().map(|(u, m)| (*u, m.to_vec())).collect();
    }

    fn take_fetched(&self) -> Vec<u32> {
        std::mem::take(&mut self.mailbox.lock().unwrap().fetched)
    }

    fn fail_fetch_of(&self, uid: u32) {
        self.mailbox.lock().unwrap().fail_fetch_of = Some(uid);
    }
}

async fn serve(stream: TcpStream, mailbox: Arc<Mutex<Mailbox>>) {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    if write.write_all(b"* OK fake IMAP ready\r\n").await.is_err() {
        return;
    }
    while let Ok(Some(line)) = lines.next_line().await {
        let mut parts = line.splitn(2, ' ');
        let tag = parts.next().unwrap_or("*").to_string();
        let command = parts.next().unwrap_or("").to_string();
        let upper = command.to_ascii_uppercase();
        let mut out: Vec<u8> = Vec::new();
        if upper.starts_with("LOGIN") {
            out.extend(format!("{} OK LOGIN completed\r\n", tag).bytes());
        } else if upper.starts_with("LIST") {
            out.extend(format!("* LIST () \"/\" INBOX\r\n{} OK LIST completed\r\n", tag).bytes());
        } else if upper.starts_with("EXAMINE") || upper.starts_with("SELECT") {
            let mb = mailbox.lock().unwrap();
            let next = mb.messages.last().map_or(1, |(u, _)| u + 1);
            out.extend(format!("* FLAGS ()\r\n* {} EXISTS\r\n* 0 RECENT\r\n", mb.messages.len()).bytes());
            if let Some(v) = mb.uidvalidity {
                out.extend(format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", v).bytes());
            }
            out.extend(format!("* OK [UIDNEXT {}] next\r\n{} OK [READ-ONLY] EXAMINE completed\r\n", next, tag).bytes());
        } else if upper.starts_with("UID SEARCH") {
            // "UID SEARCH UID <from>:*"; like real servers, n:* matches the
            // highest UID even when n is beyond it
            let from: u32 = command
                .rsplit(' ')
                .next()
                .and_then(|r| r.split(':').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
            let mb = mailbox.lock().unwrap();
            let mut uids: Vec<u32> = mb.messages.iter().map(|(u, _)| *u).filter(|u| *u >= from).collect();
            if uids.is_empty() {
                uids.extend(mb.messages.last().map(|(u, _)| *u));
            }
            let list: Vec<String> = uids.iter().map(u32::to_string).collect();
            out.extend(format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", list.join(" "), tag).bytes());
        } else if upper.starts_with("UID FETCH") {
            let uid: u32 = command.split(' ').nth(2).and_then(|u| u.parse().ok()).unwrap_or(0);
            let found = {
                let mut mb = mailbox.lock().unwrap();
                if mb.fail_fetch_of == Some(uid) {
                    mb.fail_fetch_of = None;
                    None
                } else {
                    mb.fetched.push(uid);
                    Some(mb.messages.iter().position(|(u, _)| *u == uid).map(|i| (i + 1, mb.messages[i].1.clone())))
                }
            };
            match found {
                None => return, // connection drops mid-sync
                Some(Some((seq, body))) => {
                    out.extend(
                        format!(
                            "* {} FETCH (UID {} INTERNALDATE \"24-Oct-2026 10:00:00 +0000\" BODY[] {{{}}}\r\n",
                            seq,
                            uid,
                            body.len()
                        )
                        .bytes(),
                    );
                    out.extend(&body);
                    out.extend(b")\r\n");
                }
                Some(None) => {}
            }
            out.extend(format!("{} OK FETCH completed\r\n", tag).bytes());
        } else if upper.starts_with("LOGOUT") {
            out.extend(format!("* BYE\r\n{} OK LOGOUT completed\r\n", tag).bytes());
            let _ = write.write_all(&out).await;
            return;
        } else {
            out.extend(format!("{} OK done\r\n", tag).bytes());
        }
        if write.write_all(&out).await.is_err() {
            return;
        }
    }
}

// --- Helpers -----------------------------------------------------------------

struct Archive {
    _dir: tempfile::TempDir,
    db: Database,
    storage: StorageEngine,
}

fn archive() -> Archive {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageEngine::new(dir.path().join("data"));
    Archive { db: Database::open(dir.path().join("catalog.db")).unwrap(), storage, _dir: dir }
}

fn account(server: &FakeImap, username: &str) -> AccountConfig {
    AccountConfig {
        id: "acc".into(),
        name: "Test".into(),
        email: "me@example.com".into(),
        provider: ProviderType::GenericImap,
        imap_server: "127.0.0.1".into(),
        imap_port: server.port,
        use_tls: false,
        auth_type: AuthType::Password,
        username: username.into(),
        schedule: None,
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: false,
        enabled: true,
    }
}

/// A message; A and B deliberately share a Message-ID, which must not make
/// them the same message.
fn mail(subject: &str) -> Vec<u8> {
    format!("From: a@example.com\r\nSubject: {}\r\nMessage-ID: <same@example.com>\r\n\r\nbody of {}\r\n", subject, subject)
        .into_bytes()
}

async fn sync(a: &Archive, server: &FakeImap, account: &AccountConfig) -> SyncProgress {
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    let session = async_imap::Client::new(tcp).login(&account.username, "pw").await.map_err(|(e, _)| e).unwrap();
    ImapSyncEngine::new(a.db.clone(), a.storage.clone())
        .sync_session(session, account, None::<fn(&SyncProgress)>)
        .await
        .unwrap()
}

fn inbox(a: &Archive) -> mailbackup_core::db::FolderRecord {
    a.db.get_folders("acc").unwrap().into_iter().find(|f| f.remote_name == "INBOX").unwrap()
}

/// Messages in INBOX with their archived bytes, by UID.
fn archived(a: &Archive) -> Vec<(MessageRecord, Vec<u8>)> {
    let mut list: Vec<_> = a
        .db
        .get_messages_for_folder(&inbox(a).id)
        .unwrap()
        .into_iter()
        .map(|m| {
            let bytes = a.storage.read_eml(&m.relative_path).unwrap();
            (m, bytes)
        })
        .collect();
    list.sort_by_key(|(m, _)| m.uid);
    list
}

fn subjects(a: &Archive) -> Vec<String> {
    let mut s: Vec<String> = archived(a).into_iter().map(|(m, _)| m.subject.unwrap_or_default()).collect();
    s.sort();
    s
}

fn eml_files(a: &Archive) -> usize {
    fn count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| {
                        let p = e.path();
                        if p.is_dir() {
                            count(&p)
                        } else {
                            usize::from(p.extension().is_some_and(|x| x == "eml"))
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    }
    count(&a.storage.base_dir())
}

fn stale_result<T>(r: mailbackup_core::error::Result<T>) -> bool {
    matches!(r, Err(mailbackup_core::error::Error::StaleSync(_)))
}

// --- Tests ---------------------------------------------------------------

#[tokio::test]
async fn a_new_uidvalidity_rescans_and_keeps_the_old_message() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A"]);

    // The mailbox is renumbered: UID 1 is now a different message
    server.set(Some(2), &[(1, &mail("B"))]);
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1], "UID 1 fetched again");
    assert_eq!(subjects(&a), ["A", "B"], "B archived, A kept");
    let all = archived(&a);
    assert_eq!(all[0].1, mail(all[0].0.subject.as_deref().unwrap()), "both files readable and intact");
    assert_eq!(all[1].1, mail(all[1].0.subject.as_deref().unwrap()));
    assert_ne!(all[0].0.relative_path, all[1].0.relative_path);
    let folder = inbox(&a);
    assert_eq!((folder.uid_generation, folder.uidvalidity), (1, Some(2)));
}

#[tokio::test]
async fn a_new_server_or_username_rescans_even_with_the_same_uidvalidity() {
    let (a, server) = (archive(), FakeImap::start().await);
    server.set(Some(1), &[(1, &mail("A"))]);
    sync(&a, &server, &account(&server, "old-user")).await;

    // Another mailbox behind the same numeric UIDVALIDITY
    server.set(Some(1), &[(1, &mail("B"))]);
    server.take_fetched();
    sync(&a, &server, &account(&server, "new-user")).await;
    assert_eq!(server.take_fetched(), [1]);
    assert_eq!(subjects(&a), ["A", "B"]);
    assert_eq!(inbox(&a).remote_identity.as_deref(), Some(account(&server, "new-user").remote_identity().as_str()));
}

#[tokio::test]
async fn a_rescan_recognizes_archived_messages_by_content() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("X"))]);
    sync(&a, &server, &acc).await;
    let a_id = archived(&a)[0].0.id.clone();
    assert_eq!(eml_files(&a), 2);

    server.set(Some(2), &[(7, &mail("A")), (8, &mail("C"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "C", "X"], "only C is new");
    assert_eq!(eml_files(&a), 3, "A isn't stored a second time");
    let rebound = archived(&a).into_iter().find(|(m, _)| m.id == a_id).unwrap().0;
    assert_eq!(rebound.uid, 7, "A's archived copy now stands for UID 7");

    // And nothing is fetched again on the next sync
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty());
}

#[tokio::test]
async fn identical_copies_keep_their_number() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(subjects(&a), ["A", "A"]);

    server.set(Some(2), &[(5, &mail("A")), (6, &mail("A")), (7, &mail("A"))]);
    sync(&a, &server, &acc).await;
    let uids: Vec<u32> = archived(&a).iter().map(|(m, _)| m.uid).collect();
    assert_eq!(uids, [5, 6, 7], "two copies re-bound, one new");
}

#[tokio::test]
async fn an_unchanged_mailbox_fetches_nothing_again() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1, 2]);

    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty());
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B")), (3, &mail("C"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [3], "incremental");
    assert_eq!(inbox(&a).uid_generation, 0);
}

#[tokio::test]
async fn a_first_reported_uidvalidity_rescans_once() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(None, &[(1, &mail("A"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(inbox(&a).uidvalidity, None);

    server.set(Some(9), &[(1, &mail("A")), (2, &mail("B"))]);
    server.take_fetched();
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1, 2], "re-scanned");
    assert_eq!(subjects(&a), ["A", "B"], "A recognized, not duplicated");
    let folder = inbox(&a);
    assert_eq!((folder.uid_generation, folder.uidvalidity), (1, Some(9)));

    sync(&a, &server, &acc).await;
    assert!(server.take_fetched().is_empty(), "only once");
}

#[tokio::test]
async fn an_interrupted_rescan_resumes_without_gaps_or_duplicates() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    server.set(Some(1), &[(1, &mail("A")), (2, &mail("B"))]);
    sync(&a, &server, &acc).await;

    let renumbered = [(11, mail("A")), (12, mail("B")), (13, mail("C")), (14, mail("D"))];
    let refs: Vec<(u32, &[u8])> = renumbered.iter().map(|(u, m)| (*u, m.as_slice())).collect();
    server.set(Some(2), &refs);
    server.fail_fetch_of(13);
    server.take_fetched();
    sync(&a, &server, &acc).await; // stops at UID 13
    assert_eq!(server.take_fetched(), [11, 12]);
    let generation = inbox(&a).uid_generation;

    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [13, 14], "resumed after the checkpoint");
    assert_eq!(inbox(&a).uid_generation, generation, "same generation");
    assert_eq!(subjects(&a), ["A", "B", "C", "D"]);
    let uids: Vec<u32> = archived(&a).iter().map(|(m, _)| m.uid).collect();
    assert_eq!(uids, [11, 12, 13, 14]);
}

#[tokio::test]
async fn folders_archived_before_generations_are_rescanned_once() {
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    // What 0.3.x left behind: a folder without an identity, holding A at UID 1
    let folder = a.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    let stored = a.storage.store_eml("acc", "INBOX", 1, None, &mail("A")).unwrap();
    a.db.insert_message(
        "acc", &folder.id, 1, None, Some("A"), None, None, None, None, stored.size_bytes,
        &stored.relative_path.to_string_lossy(), &stored.sha256, None, &[],
    )
    .unwrap();
    a.db.update_folder_sync_state(&folder.id, 1).unwrap();
    assert_eq!(inbox(&a).remote_identity, None);

    // The config had since moved to another mailbox with the same UIDVALIDITY
    server.set(Some(1), &[(1, &mail("B"))]);
    sync(&a, &server, &acc).await;
    assert_eq!(server.take_fetched(), [1], "UID 1 not trusted to still be A");
    assert_eq!(subjects(&a), ["A", "B"]);

    // An empty legacy folder just adopts the identity
    let (b, server2) = (archive(), FakeImap::start().await);
    b.db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1)).unwrap();
    server2.set(Some(1), &[(1, &mail("A"))]);
    sync(&b, &server2, &account(&server2, "user")).await;
    assert_eq!(inbox(&b).uid_generation, 0);
    assert_eq!(server2.take_fetched(), [1]);
}

#[tokio::test]
async fn a_superseded_session_cannot_write() {
    let a = archive();
    // Session A begins on the old server, then the account moves and B begins
    let old = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "old:993:u").unwrap();
    let new = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "new:993:u").unwrap();
    assert_eq!(new.generation, old.generation + 1, "a connection change starts a new generation");
    assert!(stale_result(a.db.update_folder_checkpoint(&old.folder.id, old.generation, 1)));

    let stored = a.storage.store_eml("acc", "INBOX", 1, None, &mail("A")).unwrap();
    let path = stored.relative_path.to_string_lossy().to_string();
    a.db.insert_message_in_generation(
        "acc", &new.folder.id, new.generation, 1, None, Some("A"), None, None, None, None,
        stored.size_bytes, &path, &stored.sha256, None, &[],
    )
    .unwrap();
    let first = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "new:993:u").unwrap();
    let second = a.db.begin_folder_sync("acc", "INBOX", "INBOX", Some(1), "other:993:u").unwrap();
    assert_eq!(first.generation, new.generation, "same connection: same generation");
    assert_eq!(second.generation, first.generation + 1);
    a.db.update_folder_checkpoint(&second.folder.id, second.generation, 5).unwrap();

    // The first session wakes up and tries to write old-server UIDs
    assert!(stale_result(a.db.insert_message_in_generation(
        "acc", &first.folder.id, first.generation, 2, None, Some("old"), None, None, None, None,
        1, "x.eml", "deadbeef", None, &[],
    )));
    assert!(stale_result(a.db.rebind_message(&first.folder.id, first.generation, 9, &stored.sha256)));
    assert!(stale_result(a.db.update_folder_checkpoint(&first.folder.id, first.generation, 99)));

    let folder = inbox(&a);
    assert_eq!((folder.uid_generation, folder.last_synced_uid), (second.generation, 5), "B's state untouched");
    assert_eq!(subjects(&a), ["A"], "nothing written by the old session");
}
