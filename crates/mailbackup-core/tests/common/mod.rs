//! Shared by the sync tests: a scripted in-process IMAP server (one mailbox,
//! INBOX, over plain TCP) and archive helpers.
#![allow(dead_code)]

use async_compression::tokio::bufread::DeflateDecoder;
use async_compression::tokio::write::DeflateEncoder;
use mailbackup_core::config::{AccountConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::{Database, MessageRecord};
use mailbackup_core::imap::{ImapSyncEngine, SyncProgress};
use mailbackup_core::storage::StorageEngine;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// --- A scripted IMAP server ----------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Compress {
    /// Not advertised
    Off,
    /// Advertised and accepted
    #[default]
    On,
    /// Advertised, but `COMPRESS DEFLATE` gets a tagged NO
    Reject,
    /// Advertised, but the connection drops on `COMPRESS DEFLATE`
    Drop,
}

#[derive(Default)]
pub struct Mailbox {
    pub uidvalidity: Option<u32>,
    /// (uid, raw message), ascending by uid
    pub messages: Vec<(u32, Vec<u8>)>,
    /// UIDs whose body was sent, in order
    pub fetched: Vec<u32>,
    /// Drop the connection instead of sending this UID's body (once)
    pub fail_fetch_of: Option<u32>,
    /// INTERNALDATE per UID (default 24-Oct-2026)
    pub internal_dates: HashMap<u32, String>,
    /// Never answer a body fetch for these UIDs (they still exist)
    pub omit_body_of: HashSet<u32>,
    /// Never answer a size query for these UIDs
    pub omit_size_of: HashSet<u32>,
    /// Expunge these UIDs when the next FETCH command arrives
    pub expunge_on_fetch: HashSet<u32>,
    pub compress: Compress,
    /// Commands received: "CAPABILITY", "COMPRESS", "SIZE", "BODY", "SEARCH", …
    pub commands: Vec<String>,
    pub connections: usize,
    /// Sessions that switched to compression
    pub compressed_sessions: usize,
    /// Advertise OBJECTID (RFC 8474) / X-GM-EXT-1 (Gmail)
    pub object_id: bool,
    pub gmail: bool,
    /// Per UID, the id attribute sent when a FETCH asks for EMAILID or
    /// X-GM-MSGID, verbatim (e.g. `EMAILID (Mabc)`, or something broken)
    pub id_attrs: HashMap<u32, String>,
    /// RFC822.SIZE to report instead of the real size
    pub size_override: HashMap<u32, usize>,
    /// Every command line received, with the number of its connection
    pub raw_commands: Vec<(usize, String)>,
    /// (connection number, UIDVALIDITY): switch to it when that connection
    /// arrives
    pub uidvalidity_on_connection: Option<(usize, u32)>,
}

#[derive(Clone)]
pub struct FakeImap {
    pub port: u16,
    pub mailbox: Arc<Mutex<Mailbox>>,
    /// Bytes the server wrote to the network (after compression)
    pub wire_bytes: Arc<AtomicU64>,
}

impl FakeImap {
    pub async fn start() -> FakeImap {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mailbox = Arc::new(Mutex::new(Mailbox::default()));
        let wire_bytes = Arc::new(AtomicU64::new(0));
        let (shared, counter) = (mailbox.clone(), wire_bytes.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let connection = {
                    let mut mb = shared.lock().unwrap();
                    mb.connections += 1;
                    if let Some((n, v)) = mb.uidvalidity_on_connection {
                        if n == mb.connections {
                            mb.uidvalidity = Some(v);
                        }
                    }
                    mb.connections
                };
                tokio::spawn(serve(stream, shared.clone(), counter.clone(), connection));
            }
        });
        FakeImap { port, mailbox, wire_bytes }
    }

    /// Replaces the mailbox's contents (keeps logs and settings).
    pub fn set(&self, uidvalidity: Option<u32>, messages: &[(u32, &[u8])]) {
        let mut mb = self.mailbox.lock().unwrap();
        mb.uidvalidity = uidvalidity;
        mb.messages = messages.iter().map(|(u, m)| (*u, m.to_vec())).collect();
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Mailbox) -> R) -> R {
        f(&mut self.mailbox.lock().unwrap())
    }

    pub fn take_fetched(&self) -> Vec<u32> {
        std::mem::take(&mut self.mailbox.lock().unwrap().fetched)
    }

    pub fn take_commands(&self) -> Vec<String> {
        std::mem::take(&mut self.mailbox.lock().unwrap().commands)
    }

    pub fn set_internal_dates(&self, dates: &[(u32, &str)]) {
        self.mailbox.lock().unwrap().internal_dates = dates.iter().map(|(u, d)| (*u, d.to_string())).collect();
    }

    pub fn fail_fetch_of(&self, uid: u32) {
        self.mailbox.lock().unwrap().fail_fetch_of = Some(uid);
    }

    pub fn set_compress(&self, mode: Compress) {
        self.mailbox.lock().unwrap().compress = mode;
    }

    /// Advertises OBJECTID and sends these EMAILIDs (well-formed or not).
    pub fn set_email_ids(&self, ids: &[(u32, &str)]) {
        let mut mb = self.mailbox.lock().unwrap();
        mb.object_id = true;
        mb.id_attrs = ids.iter().map(|(u, v)| (*u, format!("EMAILID ({})", v))).collect();
    }

    /// Advertises X-GM-EXT-1 and sends these X-GM-MSGIDs.
    pub fn set_gmail_ids(&self, ids: &[(u32, u64)]) {
        let mut mb = self.mailbox.lock().unwrap();
        mb.gmail = true;
        mb.id_attrs = ids.iter().map(|(u, v)| (*u, format!("X-GM-MSGID {}", v))).collect();
    }

    pub fn take_raw_commands(&self) -> Vec<(usize, String)> {
        std::mem::take(&mut self.mailbox.lock().unwrap().raw_commands)
    }
}

/// Counts bytes written to the network.
struct Counting<W> {
    inner: W,
    count: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Counting<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.count.fetch_add(*n as u64, Ordering::SeqCst);
        }
        poll
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum Next<R, W> {
    Close,
    Compress(R, W),
}

async fn serve(stream: TcpStream, mailbox: Arc<Mutex<Mailbox>>, wire: Arc<AtomicU64>, connection: usize) {
    let (read, write) = stream.into_split();
    let mut writer = Counting { inner: write, count: wire };
    if writer.write_all(b"* OK fake IMAP ready\r\n").await.is_err() {
        return;
    }
    if let Next::Compress(reader, writer) = session(BufReader::new(read), writer, &mailbox, connection).await {
        mailbox.lock().unwrap().compressed_sessions += 1;
        let reader = BufReader::new(DeflateDecoder::new(reader));
        let writer = DeflateEncoder::new(writer);
        session(reader, writer, &mailbox, connection).await;
    }
}

/// UIDs of `set` (`1,3:5,7:*`) that exist in the mailbox, ascending. With
/// `star_matches_last`, `n:*` beyond the last UID still matches the last one,
/// as on real servers.
fn select(set: &str, existing: &[u32], star_matches_last: bool) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for part in set.split(',') {
        let (from, to) = match part.split_once(':') {
            Some((a, "*")) => (a.parse().unwrap_or(1), u32::MAX),
            Some((a, b)) => (a.parse().unwrap_or(0), b.parse().unwrap_or(0)),
            None => {
                let n = part.parse().unwrap_or(0);
                (n, n)
            }
        };
        let (from, to) = (from.min(to), from.max(to));
        let mut hits: Vec<u32> = existing.iter().copied().filter(|u| (from..=to).contains(u)).collect();
        if hits.is_empty() && to == u32::MAX && star_matches_last {
            hits.extend(existing.last());
        }
        out.extend(hits);
    }
    out.sort_unstable();
    out.dedup();
    out
}

async fn session<R, W>(mut reader: R, mut writer: W, mailbox: &Arc<Mutex<Mailbox>>, connection: usize) -> Next<R, W>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return Next::Close,
            Ok(_) => {}
        }
        let line = line.trim_end();
        let mut parts = line.splitn(2, ' ');
        let tag = parts.next().unwrap_or("*").to_string();
        let command = parts.next().unwrap_or("").to_string();
        let upper = command.to_ascii_uppercase();
        mailbox.lock().unwrap().raw_commands.push((connection, command.clone()));
        let mut out: Vec<u8> = Vec::new();
        let mut close_after = false;
        if upper.starts_with("CAPABILITY") {
            let mut mb = mailbox.lock().unwrap();
            mb.commands.push("CAPABILITY".into());
            let mut extra = String::new();
            if mb.compress != Compress::Off {
                extra.push_str(" COMPRESS=DEFLATE");
            }
            if mb.object_id {
                extra.push_str(" OBJECTID");
            }
            if mb.gmail {
                extra.push_str(" X-GM-EXT-1");
            }
            out.extend(format!("* CAPABILITY IMAP4rev1{}\r\n{} OK CAPABILITY completed\r\n", extra, tag).bytes());
        } else if upper.starts_with("COMPRESS") {
            let mode = {
                let mut mb = mailbox.lock().unwrap();
                mb.commands.push("COMPRESS".into());
                mb.compress
            };
            match mode {
                Compress::On => {
                    if writer.write_all(format!("{} OK DEFLATE active\r\n", tag).as_bytes()).await.is_err()
                        || writer.flush().await.is_err()
                    {
                        return Next::Close;
                    }
                    return Next::Compress(reader, writer);
                }
                Compress::Drop => return Next::Close,
                Compress::Reject | Compress::Off => out.extend(format!("{} NO not now\r\n", tag).bytes()),
            }
        } else if upper.starts_with("LOGIN") {
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
            // "UID SEARCH UID <set>"
            let mut mb = mailbox.lock().unwrap();
            mb.commands.push("SEARCH".into());
            let set = command.rsplit(' ').next().unwrap_or("");
            let existing: Vec<u32> = mb.messages.iter().map(|(u, _)| *u).collect();
            let found: Vec<String> = select(set, &existing, true).iter().map(u32::to_string).collect();
            out.extend(format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", found.join(" "), tag).bytes());
        } else if upper.starts_with("UID FETCH") {
            // "UID FETCH <set> (<items>)"
            let set = command.split(' ').nth(2).unwrap_or("").to_string();
            let wants_body = upper.contains("BODY.PEEK[]");
            let wants_id = upper.contains("EMAILID") || upper.contains("X-GM-MSGID");
            let mut mb = mailbox.lock().unwrap();
            mb.commands.push(if wants_body { "BODY".into() } else { "SIZE".into() });
            let gone = std::mem::take(&mut mb.expunge_on_fetch);
            mb.messages.retain(|(u, _)| !gone.contains(u));
            let existing: Vec<u32> = mb.messages.iter().map(|(u, _)| *u).collect();
            for uid in select(&set, &existing, false) {
                let seq = existing.iter().position(|u| *u == uid).unwrap() + 1;
                let id_attr = match mb.id_attrs.get(&uid) {
                    Some(attr) if wants_id => format!(" {}", attr),
                    _ => String::new(),
                };
                if !wants_body {
                    if !mb.omit_size_of.contains(&uid) {
                        let size = mb.size_override.get(&uid).copied().unwrap_or(mb.messages[seq - 1].1.len());
                        out.extend(format!("* {} FETCH (UID {} RFC822.SIZE {}{})\r\n", seq, uid, size, id_attr).bytes());
                    }
                    continue;
                }
                if mb.fail_fetch_of == Some(uid) {
                    mb.fail_fetch_of = None;
                    close_after = true;
                    break;
                }
                if mb.omit_body_of.contains(&uid) {
                    continue;
                }
                mb.fetched.push(uid);
                let body = mb.messages[seq - 1].1.clone();
                let date = mb.internal_dates.get(&uid).cloned().unwrap_or_else(|| "24-Oct-2026 10:00:00 +0000".into());
                out.extend(
                    format!("* {} FETCH (UID {}{} INTERNALDATE \"{}\" BODY[] {{{}}}\r\n", seq, uid, id_attr, date, body.len())
                        .bytes(),
                );
                out.extend(&body);
                out.extend(b")\r\n");
            }
            if !close_after {
                out.extend(format!("{} OK FETCH completed\r\n", tag).bytes());
            }
        } else if upper.starts_with("LOGOUT") {
            out.extend(format!("* BYE\r\n{} OK LOGOUT completed\r\n", tag).bytes());
            close_after = true;
        } else {
            out.extend(format!("{} OK done\r\n", tag).bytes());
        }
        if writer.write_all(&out).await.is_err() || writer.flush().await.is_err() {
            return Next::Close;
        }
        if close_after {
            let _ = writer.shutdown().await;
            return Next::Close;
        }
    }
}

// --- Archive helpers ------------------------------------------------------

pub struct Archive {
    pub _dir: tempfile::TempDir,
    pub db: Database,
    pub storage: StorageEngine,
}

pub fn archive() -> Archive {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageEngine::new(dir.path().join("data"));
    Archive { db: Database::open(dir.path().join("catalog.db")).unwrap(), storage, _dir: dir }
}

pub fn account(server: &FakeImap, username: &str) -> AccountConfig {
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
        storage_namespace: None,
        credential_ref: None,
        archive: None,
        trust_server_ids: false,
    }
}

/// A message; A and B deliberately share a Message-ID, which must not make
/// them the same message.
pub fn mail(subject: &str) -> Vec<u8> {
    format!("From: a@example.com\r\nSubject: {}\r\nMessage-ID: <same@example.com>\r\n\r\nbody of {}\r\n", subject, subject)
        .into_bytes()
}

/// Syncs `account` the way `sync_account` does, over plain TCP: COMPRESS
/// when the server offers it, reconnecting if it fails.
pub async fn sync(a: &Archive, server: &FakeImap, account: &AccountConfig) -> SyncProgress {
    sync_with_engine(ImapSyncEngine::new(a.db.clone(), a.storage.clone()), server, account).await.unwrap()
}

pub async fn sync_with_engine(
    engine: ImapSyncEngine,
    server: &FakeImap,
    account: &AccountConfig,
) -> mailbackup_core::error::Result<SyncProgress> {
    let port = server.port;
    let user = account.username.clone();
    engine
        .sync_with(
            account,
            move || {
                let user = user.clone();
                async move {
                    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
                    async_imap::Client::new(tcp)
                        .login(&user, "pw")
                        .await
                        .map_err(|(e, _)| mailbackup_core::error::Error::Imap(e.to_string()))
                }
            },
            None::<fn(&SyncProgress)>,
        )
        .await
}

pub fn inbox(a: &Archive) -> mailbackup_core::db::FolderRecord {
    a.db.get_folders("acc").unwrap().into_iter().find(|f| f.remote_name == "INBOX").unwrap()
}

/// Messages in INBOX with their archived bytes, by UID.
pub fn archived(a: &Archive) -> Vec<(MessageRecord, Vec<u8>)> {
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

pub fn subjects(a: &Archive) -> Vec<String> {
    let mut s: Vec<String> = archived(a).into_iter().map(|(m, _)| m.subject.unwrap_or_default()).collect();
    s.sort();
    s
}

pub fn eml_files(a: &Archive) -> usize {
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

pub fn stale_result<T>(r: mailbackup_core::error::Result<T>) -> bool {
    matches!(r, Err(mailbackup_core::error::Error::StaleSync(_)))
}
