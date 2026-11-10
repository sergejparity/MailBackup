use crate::config::AccountConfig;
use crate::db::{Database, FolderSync, IdRebind, NewMessage};
use crate::error::{Error, Result};
use crate::server_ids::{ServerId, ServerIdKind, SourcedId};

mod absorbed_id;
pub mod guard;
use guard::{GuardState, Guarded};
use crate::storage::StorageEngine;
use async_imap::imap_proto::{AttributeValue, Response, Status};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use mail_parser::{AddressList, MessageParser};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    pub account_id: String,
    pub current_folder: String,
    pub total_messages: u32,
    pub processed_messages: u32,
    pub downloaded_bytes: u64,
    /// Messages of the account that are not backed up because they are
    /// larger than the size limit (see `Database::skipped_messages`)
    #[serde(default)]
    pub skipped_messages: u32,
    /// Why the sync stopped before it was done (a folder failed, a timeout);
    /// `None` when it finished. What was archived before it is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Most messages fetched with one command.
pub const BATCH_MAX_MESSAGES: usize = 50;
/// Target size of the messages fetched with one command; a single bigger
/// message is fetched on its own. A target, not a memory limit.
pub const BATCH_TARGET_BYTES: u64 = 16 * 1024 * 1024;
/// Most UIDs per size query.
const SIZE_QUERY_CHUNK: usize = 500;

/// Time and size limits of IMAP connections (issue #72). None of them bounds
/// a whole account sync: a large archive on a slow link still finishes, as
/// long as data keeps moving and each command completes in its time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Each of TCP connect, TLS handshake and greeting + login
    pub connect: std::time::Duration,
    /// No byte read (or a write blocked) for this long
    pub idle: std::time::Duration,
    /// Completion of one command; a body fetch also gets time for its size
    pub command: std::time::Duration,
    /// Slowest transfer a body fetch is given time for, in bytes per second
    pub min_rate: u64,
    /// Largest message fetched (see `GlobalSettings::imap_max_message_mb`)
    pub max_message_bytes: u64,
}

/// Default limits: 30 s per connection step, 120 s idle, 60 s per command
/// plus time for 4 KB/s, messages up to 256 MB.
pub const DEFAULT_LIMITS: Limits = Limits {
    connect: std::time::Duration::from_secs(30),
    idle: std::time::Duration::from_secs(120),
    command: std::time::Duration::from_secs(60),
    min_rate: 4 * 1024,
    max_message_bytes: 256 * 1024 * 1024,
};

/// `skipped_messages.reason` of a message over the size limit.
pub const SKIPPED_TOO_LARGE: &str = "over_size_limit";

/// Responses of commands that return no message bodies may be this large.
const SMALL_RESPONSE_BUDGET: u64 = 64 * 1024 * 1024;
/// Protocol overhead allowed per message of a body fetch, and per command.
const PER_MESSAGE_OVERHEAD: u64 = 4 * 1024;
const PER_COMMAND_OVERHEAD: u64 = 64 * 1024;

impl Default for Limits {
    fn default() -> Self {
        DEFAULT_LIMITS
    }
}

impl Limits {
    /// The limits the settings ask for; unset ones keep their defaults.
    pub fn from_settings(settings: &crate::config::GlobalSettings) -> Limits {
        let secs = std::time::Duration::from_secs;
        Limits {
            connect: settings.imap_connect_timeout_secs.map(secs).unwrap_or(DEFAULT_LIMITS.connect),
            idle: settings.imap_idle_timeout_secs.map(secs).unwrap_or(DEFAULT_LIMITS.idle),
            command: settings.imap_command_timeout_secs.map(secs).unwrap_or(DEFAULT_LIMITS.command),
            min_rate: DEFAULT_LIMITS.min_rate,
            max_message_bytes: settings
                .imap_max_message_mb
                .map(|mb| mb * 1024 * 1024)
                .unwrap_or(DEFAULT_LIMITS.max_message_bytes),
        }
    }

    /// Time a command reading about `bytes` may take.
    fn deadline_for(&self, bytes: u64) -> std::time::Duration {
        self.command + std::time::Duration::from_secs(bytes / self.min_rate.max(1))
    }

    /// Bytes a body fetch of messages of these sizes may read.
    fn body_budget(&self, sizes: impl IntoIterator<Item = Option<u32>>) -> u64 {
        PER_COMMAND_OVERHEAD
            + sizes
                .into_iter()
                .map(|s| s.map_or(self.max_message_bytes, u64::from) + PER_MESSAGE_OVERHEAD)
                .sum::<u64>()
    }
}

/// An error of an IMAP command as MailBackup reports it: a guard's idle
/// timeout is `Error::Timeout`, an oversized response `Error::ProtocolBroken`
/// (both end the session), anything else `Error::Imap` with `context`.
fn command_error(context: &str, e: impl std::fmt::Display) -> Error {
    let text = e.to_string();
    match guard::classify(&text) {
        Some(guard::Limit::Idle) => Error::Timeout(format!("{}: {}", context, text)),
        Some(guard::Limit::Budget) => Error::ProtocolBroken(format!("{}: {}", context, text)),
        None => Error::Imap(format!("{}: {}", context, text)),
    }
}

/// Runs `command` within `limit`; a command that doesn't finish in time is
/// `Error::Timeout`, after which the session must not be used again.
async fn within<T, E: std::fmt::Display>(
    what: &str,
    limit: std::time::Duration,
    command: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    match tokio::time::timeout(limit, command).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(command_error(what, e)),
        Err(_) => Err(Error::Timeout(format!("{} didn't complete within {} s", what, limit.as_secs()))),
    }
}

/// A TCP connection to `addr` (`host:port`), trying each address it
/// resolves to, with TCP keepalive on. Keepalive only adds OS-level
/// detection of dead peers; the guard's limits are what bound a sync.
async fn connect_tcp(addr: &str) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for socket_addr in tokio::net::lookup_host(addr).await? {
        let socket = if socket_addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
        if let Err(e) = socket.set_keepalive(true) {
            debug!("Couldn't enable TCP keepalive for {}: {}", addr, e);
        }
        match socket.connect(socket_addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("{} has no address", addr))))
}

/// Whether `e` leaves the session unusable: no further command may be sent.
fn ends_session(e: &Error) -> bool {
    matches!(e, Error::ProtocolBroken(_) | Error::Timeout(_))
}

/// The folder a sync session writes to.
#[derive(Clone, Copy)]
struct FolderTarget<'a> {
    account: &'a AccountConfig,
    folder_name: &'a str,
    folder_id: &'a str,
    generation: u32,
    /// The server id kind requested with bodies in this session, if any.
    id_kind: Option<ServerIdKind>,
    /// The account's remote identity: where this session's ids come from.
    source: &'a str,
}

/// How a session ended.
struct SessionOutcome {
    error: Option<String>,
    /// A response with server ids couldn't be parsed; the session was dropped
    /// and ids are no longer requested from this source.
    broken_by_ids: bool,
}

/// What one FETCH response said about a message.
struct Fetched<'a> {
    uid: Option<u32>,
    size: Option<u32>,
    body: Option<&'a [u8]>,
    internal_date: Option<DateTime<Utc>>,
    /// The server id, if it was requested, sent, and is valid.
    server_id: Option<ServerId>,
    /// An id attribute arrived (valid or not).
    id_sent: bool,
    /// The parser absorbed an attribute it couldn't parse (imap-proto's
    /// catch-all, e.g. for `EMAILID NIL`).
    unparsed: bool,
}

fn fetched_from<'a>(attrs: &'a [AttributeValue<'a>]) -> Fetched<'a> {
    let mut f = Fetched { uid: None, size: None, body: None, internal_date: None, server_id: None, id_sent: false, unparsed: false };
    for attr in attrs {
        match attr {
            AttributeValue::Uid(uid) => f.uid = Some(*uid),
            AttributeValue::Rfc822Size(size) => f.size = Some(*size),
            AttributeValue::BodySection { section: None, index: None, data: Some(body) }
            | AttributeValue::Rfc822(Some(body)) => f.body = Some(body.as_ref()),
            AttributeValue::InternalDate(date) => {
                f.internal_date = DateTime::parse_from_str(date, "%d-%b-%Y %H:%M:%S %z")
                    .ok()
                    .and_then(|dt| DateTime::from_timestamp(dt.timestamp(), 0));
            }
            // Delimited but not a valid objectid: ignored, so this message
            // takes the full-body path
            AttributeValue::EmailId(value) => {
                f.id_sent = true;
                f.server_id = ServerId::email_id(value);
            }
            AttributeValue::GmailMsgId(value) => {
                f.id_sent = true;
                f.server_id = Some(ServerId::gmail_msg_id(*value));
            }
            AttributeValue::Unknown => f.unparsed = true,
            _ => {}
        }
    }
    f
}

/// The parts of a message the catalog keeps besides its bytes.
struct ParsedMessage {
    message_id: Option<String>,
    subject: Option<String>,
    from_addr: Option<String>,
    to_addrs: Option<String>,
    cc_addrs: Option<String>,
    date: Option<DateTime<Utc>>,
    body_text: Option<String>,
    attachments: Vec<(String, String, u64)>,
}

fn parse_message(raw_body: &[u8], internal_date: Option<DateTime<Utc>>) -> ParsedMessage {
    let Some(p) = MessageParser::default().parse(raw_body) else {
        return ParsedMessage {
            message_id: None,
            subject: None,
            from_addr: None,
            to_addrs: None,
            cc_addrs: None,
            date: internal_date,
            body_text: None,
            attachments: Vec::new(),
        };
    };
    let attachments = crate::attachments::summaries(&p);
    ParsedMessage {
        message_id: p.message_id().map(|s| s.to_string()),
        subject: p.subject().map(|s| s.to_string()),
        from_addr: p.from().map(format_address),
        to_addrs: p.to().map(format_address),
        cc_addrs: p.cc().map(format_address),
        date: p.date().and_then(|d| DateTime::from_timestamp(d.to_timestamp(), 0)).or(internal_date),
        body_text: p.body_text(0).map(|s| s.to_string()),
        attachments,
    }
}

pub struct ImapSyncEngine {
    db: Database,
    storage: StorageEngine,
    batch_max_messages: usize,
    batch_target_bytes: u64,
    limits: Limits,
    /// Shared with the streams of this engine's connections
    guard: std::sync::Arc<GuardState>,
}

/// `uids` (ascending) as an IMAP sequence set, runs collapsed: `1:3,7,9:10`.
fn uid_set(uids: &[u32]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < uids.len() {
        let start = uids[i];
        let mut end = start;
        while i + 1 < uids.len() && uids[i + 1] == end + 1 {
            i += 1;
            end = uids[i];
        }
        parts.push(if start == end { start.to_string() } else { format!("{}:{}", start, end) });
        i += 1;
    }
    parts.join(",")
}

/// Splits `uids` (ascending) into fetch batches of at most `max_messages`
/// and about `target_bytes`. Sizes only shape batches: a UID whose size is
/// unknown, or bigger than the target, gets a batch of its own.
fn plan_batches(uids: &[u32], sizes: &HashMap<u32, u32>, max_messages: usize, target_bytes: u64) -> Vec<Vec<u32>> {
    let mut batches = Vec::new();
    let mut current: Vec<u32> = Vec::new();
    let mut bytes = 0u64;
    for &uid in uids {
        let size = sizes.get(&uid).map(|s| *s as u64);
        let alone = size.is_none_or(|s| s > target_bytes);
        if !current.is_empty() && (alone || current.len() >= max_messages || bytes + size.unwrap_or(0) > target_bytes) {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(uid);
        bytes += size.unwrap_or(0);
        if alone {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// The addresses of `list`, group members included, comma-separated.
fn format_address(list: AddressList<'_>) -> String {
    list.mailboxes().filter_map(|m| m.address()).collect::<Vec<_>>().join(", ")
}

impl ImapSyncEngine {
    pub fn new(db: Database, storage: StorageEngine) -> Self {
        Self {
            db,
            storage,
            batch_max_messages: BATCH_MAX_MESSAGES,
            batch_target_bytes: BATCH_TARGET_BYTES,
            limits: DEFAULT_LIMITS,
            guard: GuardState::new(DEFAULT_LIMITS.idle),
        }
    }

    /// Uses `limits` instead of [`DEFAULT_LIMITS`].
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self.guard = GuardState::new(limits.idle);
        self
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The limits this engine enforces, for a stream of a connection made
    /// outside it (see [`Self::sync_with`]): wrap the stream before logging
    /// in so idle connections and oversized responses are caught.
    pub fn guard_stream<S>(&self, stream: S) -> Guarded<S> {
        Guarded::new(stream, self.guard.clone())
    }

    /// Overrides [`BATCH_MAX_MESSAGES`] and [`BATCH_TARGET_BYTES`].
    pub fn with_batch_limits(mut self, max_messages: usize, target_bytes: u64) -> Self {
        self.batch_max_messages = max_messages.max(1);
        self.batch_target_bytes = target_bytes;
        self
    }

    fn create_tls_connector() -> Result<TlsConnector> {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Connects to the IMAP server via TLS and logs in, within the
    /// [`DEFAULT_LIMITS`].
    pub async fn connect(
        account: &AccountConfig,
        password: &str,
    ) -> Result<async_imap::Session<Guarded<TlsStream<TcpStream>>>> {
        Self::connect_with(account, password, &DEFAULT_LIMITS, GuardState::new(DEFAULT_LIMITS.idle)).await
    }

    /// Connects and logs in with this engine's limits.
    pub async fn connect_account(
        &self,
        account: &AccountConfig,
        password: &str,
    ) -> Result<async_imap::Session<Guarded<TlsStream<TcpStream>>>> {
        Self::connect_with(account, password, &self.limits, self.guard.clone()).await
    }

    /// [`Self::connect`] with `limits`: TCP connect, TLS handshake, and
    /// greeting plus login each within `limits.connect`; the stream is
    /// guarded by `guard` from the first byte.
    async fn connect_with(
        account: &AccountConfig,
        password: &str,
        limits: &Limits,
        guard: std::sync::Arc<GuardState>,
    ) -> Result<async_imap::Session<Guarded<TlsStream<TcpStream>>>> {
        let addr = format!("{}:{}", account.imap_server, account.imap_port);
        let step = |what: &str| format!("{} with {}", what, addr);
        let tcp_stream = match tokio::time::timeout(limits.connect, connect_tcp(&addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(Error::Imap(format!("Failed to connect to TCP {}: {}", addr, e))),
            Err(_) => return Err(Error::Timeout(format!("{} took longer than {} s", step("Connecting"), limits.connect.as_secs()))),
        };

        let server_name = rustls_pki_types::ServerName::try_from(account.imap_server.clone())
            .map_err(|e| Error::Tls(format!("Invalid TLS server name: {}", e)))?;

        let tls_connector = Self::create_tls_connector()?;
        let tls_stream = match tokio::time::timeout(limits.connect, tls_connector.connect(server_name, tcp_stream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(Error::Tls(format!("TLS handshake failed with {}: {}", addr, e))),
            Err(_) => {
                return Err(Error::Timeout(format!("{} took longer than {} s", step("The TLS handshake"), limits.connect.as_secs())));
            }
        };

        guard.set_budget(SMALL_RESPONSE_BUDGET);
        let client = async_imap::Client::new(Guarded::new(tls_stream, guard));
        let session = match tokio::time::timeout(limits.connect, client.login(&account.username, password)).await {
            Ok(Ok(session)) => session,
            Ok(Err((e, _))) => {
                return Err(match command_error("IMAP login", &e) {
                    Error::Imap(_) => Error::AuthFailed(account.id.clone(), format!("IMAP login failed: {}", e)),
                    other => other,
                });
            }
            Err(_) => {
                return Err(Error::Timeout(format!("{} took longer than {} s", step("Greeting and login"), limits.connect.as_secs())));
            }
        };

        info!("Successfully logged in to {} as {}", account.imap_server, account.username);
        Ok(session)
    }

    /// Synchronizes all matching folders for an account incrementally
    pub async fn sync_account<F>(
        &self,
        account: &AccountConfig,
        password: &str,
        progress_callback: Option<F>,
    ) -> Result<SyncProgress>
    where
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        self.sync_with(
            account,
            || self.connect_account(account, password),
            progress_callback,
        )
        .await
    }

    /// Syncs over sessions from `connect`, with COMPRESS=DEFLATE (RFC 4978)
    /// when the server offers it. If switching to compression fails in any
    /// way, that connection's state is uncertain (and the session is used up),
    /// so a fresh one from `connect` is used without compression. If a
    /// response carrying server ids can't be parsed, ids are no longer
    /// requested from that source and the sync goes on over a fresh
    /// connection (once).
    pub async fn sync_with<S, C, Fut, F>(
        &self,
        account: &AccountConfig,
        connect: C,
        progress_callback: Option<F>,
    ) -> Result<SyncProgress>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        C: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<async_imap::Session<S>>>,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let history_id = self.db.record_sync_start(&account.id)?;
        let mut progress = SyncProgress::new(account);
        let cb = progress_callback.as_ref();
        let mut outcome = self.open_and_run(account, &connect, &mut progress, cb).await;
        if matches!(outcome, Ok(SessionOutcome { broken_by_ids: true, .. })) {
            warn!("Reconnecting to {} to continue without server ids", account.id);
            outcome = self.open_and_run(account, &connect, &mut progress, cb).await;
        }
        match outcome {
            Ok(outcome) => {
                progress.error = outcome.error;
                progress.skipped_messages = self.db.skipped_messages(Some(&account.id))?.len() as u32;
                self.finish_history(&history_id, &progress);
                Ok(progress)
            }
            Err(e) => {
                let _ = self.db.record_sync_finish(&history_id, "failed", 0, 0, Some(&e.to_string()));
                Err(e)
            }
        }
    }

    /// One connection from `connect`: compression if offered, then the sync.
    async fn open_and_run<S, C, Fut, F>(
        &self,
        account: &AccountConfig,
        connect: &C,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<SessionOutcome>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        C: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<async_imap::Session<S>>>,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let mut session = connect().await?;

        self.guard.set_budget(SMALL_RESPONSE_BUDGET);
        let (offers_compress, offered_ids) = match within("CAPABILITY", self.limits.command, session.capabilities()).await {
            Ok(caps) => (caps.has_str("COMPRESS=DEFLATE"), ServerIdKind::offered(|c| caps.has_str(c))),
            Err(e) if ends_session(&e) => return Err(e),
            Err(e) => {
                warn!("CAPABILITY failed for {}: {}; not compressing", account.id, e);
                (false, None)
            }
        };
        if offers_compress {
            // The guard above the decompressor counts what responses expand to
            let guard = self.guard.clone();
            let compress = session.compress(move |stream| Guarded::new(stream, guard));
            match tokio::time::timeout(self.limits.command, compress).await.unwrap_or_else(|_| {
                Err(async_imap::error::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "COMPRESS timed out")))
            }) {
                Ok(compressed) => {
                    debug!("Using COMPRESS=DEFLATE for {}", account.id);
                    return self.run_session(compressed, account, offered_ids, progress, progress_callback).await;
                }
                Err(e) => {
                    warn!("COMPRESS=DEFLATE failed for {}: {}; reconnecting without compression", account.id, e);
                    session = connect().await?;
                }
            }
        }
        self.run_session(session, account, offered_ids, progress, progress_callback).await
    }

    /// Like [`Self::sync_account`] over an already logged-in session, e.g. a
    /// transport other than TLS.
    pub async fn sync_session<S, F>(
        &self,
        mut session: async_imap::Session<S>,
        account: &AccountConfig,
        progress_callback: Option<F>,
    ) -> Result<SyncProgress>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let history_id = self.db.record_sync_start(&account.id)?;
        let mut progress = SyncProgress::new(account);
        // Capabilities are only needed for server ids, which are opt-in
        let offered_ids = if account.trust_server_ids {
            match session.capabilities().await {
                Ok(caps) => ServerIdKind::offered(|c| caps.has_str(c)),
                Err(e) => {
                    warn!("CAPABILITY failed for {}: {}; not using server ids", account.id, e);
                    None
                }
            }
        } else {
            None
        };
        let outcome = self.run_session(session, account, offered_ids, &mut progress, progress_callback.as_ref()).await?;
        progress.error = outcome.error;
        progress.skipped_messages = self.db.skipped_messages(Some(&account.id))?.len() as u32;
        self.finish_history(&history_id, &progress);
        Ok(progress)
    }

    /// Records how the sync ended, from the finished `progress` (its error and
    /// skipped messages already filled in): `success` only when nothing is
    /// missing; messages left out for their size make it `incomplete`, with
    /// the same reason the caller reports (issue #72).
    fn finish_history(&self, history_id: &str, progress: &SyncProgress) {
        let reason = progress.incomplete_reason();
        let status = match (&progress.error, &reason) {
            (Some(_), _) => "partial_or_failed",
            (None, Some(_)) => "incomplete",
            (None, None) => "success",
        };
        let _ = self.db.record_sync_finish(
            history_id,
            status,
            progress.processed_messages,
            progress.downloaded_bytes,
            reason.as_deref(),
        );
    }

    async fn run_session<S, F>(
        &self,
        mut session: async_imap::Session<S>,
        account: &AccountConfig,
        offered_ids: Option<ServerIdKind>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<SessionOutcome>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let source = account.remote_identity();
        // Ids are requested only if the account opted in, the server offers
        // them, and this source's responses with them haven't broken before
        let id_kind = offered_ids.filter(|_| account.trust_server_ids).filter(|kind| {
            match self.db.server_id_disabled(&account.id, &source, *kind) {
                Ok(disabled) => !disabled,
                Err(e) => {
                    warn!("Couldn't read the server id state of {}: {}; not using server ids", account.id, e);
                    false
                }
            }
        });

        let mut folder_names = Vec::new();
        self.guard.set_budget(SMALL_RESPONSE_BUDGET);
        let listed = within("Listing mailboxes", self.limits.command, async {
            let mut mailbox_stream = session.list(None, Some("*")).await?;
            let mut names = Vec::new();
            while let Some(mb_result) = mailbox_stream.next().await {
                match mb_result {
                    Ok(mb) => names.push(mb.name().to_string()),
                    // A guard's error ends the listing (and the session)
                    Err(e) if guard::classify(&e.to_string()).is_some() => return Err(e),
                    Err(e) => warn!("Error reading mailbox: {}", e),
                }
            }
            Ok::<_, async_imap::error::Error>(names)
        })
        .await?;
        for name in listed {
            if self.should_sync_folder(account, &name) {
                folder_names.push(name);
            } else {
                debug!("Skipping folder based on filter: {}", name);
            }
        }

        info!("Found {} folders to sync for account {}", folder_names.len(), account.id);

        let mut outcome = SessionOutcome { error: None, broken_by_ids: false };
        let mut broken = false;
        for folder_name in &folder_names {
            progress.current_folder = folder_name.clone();
            if let Some(cb) = progress_callback {
                cb(progress);
            }

            if let Err(e) = self.sync_folder(&mut session, account, folder_name, id_kind, &source, progress, progress_callback).await {
                error!("Error syncing folder '{}': {}", folder_name, e);
                broken = ends_session(&e);
                outcome.broken_by_ids = broken
                    && id_kind.is_some_and(|kind| self.db.server_id_disabled(&account.id, &source, kind).unwrap_or(false));
                outcome.error = Some(e.to_string());
                break;
            }
        }

        // Safe logout; a session whose responses can't be parsed gets no
        // further command
        if !broken {
            self.guard.set_budget(SMALL_RESPONSE_BUDGET);
            let _ = within("LOGOUT", self.limits.command, session.logout()).await;
        }

        Ok(outcome)
    }

    fn should_sync_folder(&self, account: &AccountConfig, folder_name: &str) -> bool {
        // Exclusions take precedence
        for exc in &account.folder_filter.exclude {
            if folder_name.eq_ignore_ascii_case(exc) || folder_name.contains(exc) {
                return false;
            }
        }
        // Inclusions if specified
        if !account.folder_filter.include.is_empty() {
            return account.folder_filter.include.iter().any(|inc| {
                folder_name.eq_ignore_ascii_case(inc) || folder_name.contains(inc)
            });
        }
        true
    }

    /// Sync a single folder incrementally using EXAMINE (strictly read-only)
    #[allow(clippy::too_many_arguments)]
    async fn sync_folder<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        account: &AccountConfig,
        folder_name: &str,
        id_kind: Option<ServerIdKind>,
        source: &str,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        // Use EXAMINE for non-destructive read-only access
        self.guard.set_budget(SMALL_RESPONSE_BUDGET);
        let mailbox = within(&format!("Examining mailbox '{}'", folder_name), self.limits.command, session.examine(folder_name)).await?;

        let uidvalidity = mailbox.uid_validity;
        let local_slug = StorageEngine::sanitize_slug(folder_name);
        // This session reads and writes only `generation`; if a newer sync
        // starts a new one meanwhile, this session's writes are refused
        let FolderSync { folder: folder_rec, generation, rescan_reason } = self.db.begin_folder_sync(
            &account.id,
            folder_name,
            &local_slug,
            uidvalidity,
            source,
        )?;
        if let Some(reason) = &rescan_reason {
            warn!("Re-scanning folder '{}' of {}: {}", folder_name, account.id, reason);
            crate::event_log::log_event(
                "SYNC_RESCAN",
                &format!(
                    "Re-scanning folder '{}' of account '{}' because {}. Archived messages are kept; messages already archived are recognized by content.",
                    folder_name, account.id, reason
                ),
            );
        }
        let target = FolderTarget { account, folder_name, folder_id: &folder_rec.id, generation, id_kind, source };

        // Re-binds by id left unchecked when their source turned out
        // inconsistent (in an earlier sync, or another folder) come first
        self.reconcile_id_rebinds(session, &target, progress, progress_callback).await?;

        // Skipped messages: records of other generations name UIDs that mean
        // nothing now (this generation's scan evaluates every message again);
        // this generation's are tried again if they fit now or a retry was asked
        let dropped = self.db.delete_skipped_of_other_generations(&folder_rec.id, generation)?;
        if dropped > 0 {
            info!("Folder '{}': {} skipped-message records of an earlier UID generation dropped", folder_name, dropped);
        }
        self.retry_skipped(session, &target, progress, progress_callback).await?;

        let last_uid = folder_rec.last_synced_uid;
        debug!(
            "Folder '{}' (ID: {}): generation={}, last_synced_uid={}, uidvalidity={:?}",
            folder_name, folder_rec.id, generation, last_uid, uidvalidity
        );

        // Search for new UIDs: (last_uid + 1):*
        let search_query = format!("UID {}:*", last_uid + 1);
        self.guard.set_budget(SMALL_RESPONSE_BUDGET);
        let uids_set = within(&format!("UID search in '{}'", folder_name), self.limits.command, session.uid_search(&search_query)).await?;

        let mut uids: Vec<u32> = uids_set.into_iter().filter(|&u| u > last_uid).collect();
        uids.sort_unstable();

        if uids.is_empty() {
            debug!("Folder '{}' is up to date (no new UIDs)", folder_name);
            return Ok(());
        }

        // UIDs this generation already archived (an earlier, interrupted run)
        // need no fetch
        let mut resolved: HashSet<u32> = HashSet::new();
        let mut pending = Vec::new();
        for &uid in &uids {
            if self.db.message_exists_in_generation(&folder_rec.id, generation, uid)? {
                resolved.insert(uid);
            } else {
                pending.push(uid);
            }
        }

        info!("Folder '{}': {} new messages to download", folder_name, pending.len());
        progress.total_messages += pending.len() as u32;

        // Same-source copies from older generations with ids: try re-binding
        // by id before downloading
        let shortcut = match id_kind {
            Some(kind) if !pending.is_empty() => {
                !self.db.server_id_distrusted(&account.id, source, kind)?
                    && self.db.has_server_id_candidates(&folder_rec.id, generation, kind, source)?
            }
            _ => false,
        };
        let mut checkpoint = last_uid;
        let (sizes, ids) = self
            .fetch_meta(session, &target, &pending, shortcut)
            .await
            .map_err(|e| self.note_broken(&target, shortcut, e))?;
        if shortcut {
            self.rebind_by_ids(&target, &pending, &sizes, &ids, &mut resolved, progress, progress_callback)?;
            self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
            pending.retain(|u| !resolved.contains(u));
        }

        // Too large to fetch: recorded as not backed up, never fetched. The
        // record lets the checkpoint pass the UID; it stays until a retry
        // archives the message (see `retry_skipped`)
        let max = self.limits.max_message_bytes;
        let mut oversized = Vec::new();
        pending.retain(|uid| match sizes.get(uid) {
            Some(&size) if u64::from(size) > max => {
                oversized.push((*uid, size));
                false
            }
            _ => true,
        });
        for (uid, size) in oversized {
            if self.db.record_skipped(&account.id, &folder_rec.id, generation, uid, SKIPPED_TOO_LARGE, size.into(), max)? {
                warn!("Message UID {} in '{}' ({} bytes) is larger than the {} byte limit; not backed up", uid, folder_name, size, max);
                crate::event_log::log_event(
                    "MESSAGE_SKIPPED",
                    &format!(
                        "Account '{}': message UID {} in '{}' ({:.1} MB) is larger than the {:.0} MB limit and is not backed up",
                        account.id,
                        uid,
                        folder_name,
                        size as f64 / 1048576.0,
                        max as f64 / 1048576.0
                    ),
                );
            }
            resolved.insert(uid);
        }
        self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;

        for batch in plan_batches(&pending, &sizes, self.batch_max_messages, self.batch_target_bytes) {
            let outcome = self.fetch_batch(session, &target, &batch, &sizes, &mut resolved, progress, progress_callback).await;
            if let Err(e) = outcome {
                // Keep what was archived before the failure
                self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
                return Err(self.note_broken(&target, target.id_kind.is_some(), e));
            }
            for uid in batch.iter().copied().filter(|u| !resolved.contains(u)).collect::<Vec<_>>() {
                if let Err(e) = self.resolve_missing(session, &target, uid, &sizes, &mut resolved, progress, progress_callback).await {
                    self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
                    return Err(self.note_broken(&target, target.id_kind.is_some(), e));
                }
            }
            self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
        }

        // An inconsistency found during this scan also covers its earlier
        // re-binds by id
        self.reconcile_id_rebinds(session, &target, progress, progress_callback).await
    }

    /// Tries the folder's skipped messages again (see
    /// `Database::skipped_to_retry`), each with a fetch of its own UID: an
    /// archived message, or one the server no longer has, loses its record;
    /// any other stays recorded (and is not retried again until the limit or
    /// a new request says so). Never re-scans the folder.
    async fn retry_skipped<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let candidates = self.db.skipped_to_retry(target.folder_id, target.generation, self.limits.max_message_bytes)?;
        for skipped in candidates {
            let uid = skipped.uid;
            info!("Retrying skipped message UID {} in '{}' ({} bytes)", uid, target.folder_name, skipped.size_bytes);
            let sizes = HashMap::from([(uid, u32::try_from(skipped.size_bytes).unwrap_or(u32::MAX))]);
            let mut resolved = HashSet::new();
            self.fetch_batch(session, target, &[uid], &sizes, &mut resolved, progress, progress_callback).await?;
            if resolved.contains(&uid) {
                self.db.delete_skipped(target.folder_id, target.generation, uid)?;
                crate::event_log::log_event(
                    "MESSAGE_RECOVERED",
                    &format!("Account '{}': skipped message UID {} in '{}' is now backed up", target.account.id, uid, target.folder_name),
                );
                continue;
            }
            self.guard.set_budget(SMALL_RESPONSE_BUDGET);
            match within("UID SEARCH", self.limits.command, session.uid_search(format!("UID {}", uid))).await {
                Ok(found) if !found.contains(&uid) => {
                    self.db.delete_skipped(target.folder_id, target.generation, uid)?;
                    crate::event_log::log_event(
                        "MESSAGE_SKIPPED",
                        &format!(
                            "Account '{}': skipped message UID {} in '{}' was deleted on the server before it could be backed up",
                            target.account.id, uid, target.folder_name
                        ),
                    );
                }
                Err(e) if ends_session(&e) => return Err(e),
                _ => self.db.touch_skipped(target.folder_id, target.generation, uid)?,
            }
        }
        Ok(())
    }

    /// A response to a command that asked for server ids couldn't be parsed:
    /// never ask this source for them again (until an explicit reset).
    fn note_broken(&self, target: &FolderTarget<'_>, requested_ids: bool, e: Error) -> Error {
        if let (Error::ProtocolBroken(detail), true, Some(kind)) = (&e, requested_ids, target.id_kind) {
            let reason = format!("a response with {} couldn't be parsed: {}", kind.fetch_item(), detail);
            warn!("Server ids of {} disabled: {}", target.account.id, reason);
            crate::event_log::log_event(
                "SERVER_IDS_DISABLED",
                &format!(
                    "Account '{}': {} is no longer requested from {} because {}. Every message is downloaded instead.",
                    target.account.id,
                    kind.fetch_item(),
                    target.source,
                    reason
                ),
            );
            if let Err(db_error) = self.db.record_server_id_disabled(&target.account.id, target.source, kind, &reason) {
                warn!("Couldn't record that server ids are disabled: {}", db_error);
            }
        }
        e
    }

    /// Records that this session's source can't be trusted with ids of
    /// `kind`, if it isn't already.
    fn distrust(&self, target: &FolderTarget<'_>, kind: ServerIdKind, reason: &str) -> Result<()> {
        if !self.db.server_id_distrusted(&target.account.id, target.source, kind)? {
            warn!("Server ids of {} from {} are inconsistent: {}", target.account.id, target.source, reason);
            crate::event_log::log_event(
                "SERVER_IDS_DISTRUSTED",
                &format!(
                    "Account '{}': {} from {} are no longer trusted because {}. Messages re-bound by id are being downloaded and checked, and every message is downloaded from now on (until reset with `mailbackup account server-ids {} --reset`).",
                    target.account.id,
                    kind.fetch_item(),
                    target.source,
                    reason,
                    target.account.id
                ),
            );
        }
        self.db.record_server_id_distrust(&target.account.id, target.source, kind, reason)
    }

    /// Re-binds each pending UID whose id and size the server reported to a
    /// same-source copy with that id, without downloading it. Stops at the
    /// first sign that the source's ids are inconsistent.
    #[allow(clippy::too_many_arguments)]
    fn rebind_by_ids<F>(
        &self,
        target: &FolderTarget<'_>,
        pending: &[u32],
        sizes: &HashMap<u32, u32>,
        ids: &HashMap<u32, ServerId>,
        resolved: &mut HashSet<u32>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let usable = |path: &str, sha256: &str| {
            self.storage.read_eml(path).is_ok_and(|bytes| StorageEngine::compute_sha256(&bytes) == sha256)
        };
        // Re-binds choose existing files: retention mustn't remove them
        // before the new bindings are committed (issue #79)
        let _storage_lock = self.storage.lock_shared()?;
        let mut rebound = 0usize;
        for &uid in pending {
            let (Some(id), Some(size)) = (ids.get(&uid), sizes.get(&uid)) else {
                continue;
            };
            let sourced = SourcedId { id, source: target.source };
            match self.db.rebind_by_server_id_if(
                &target.account.id,
                target.folder_id,
                target.generation,
                uid,
                sourced,
                *size as u64,
                usable,
            )? {
                IdRebind::Rebound(_) => {
                    rebound += 1;
                    resolved.insert(uid);
                    progress.processed_messages += 1;
                    if let Some(cb) = progress_callback {
                        cb(progress);
                    }
                }
                IdRebind::NoCandidate => {}
                IdRebind::SizeMismatch => {
                    let reason = format!("{} {} was reported with another size than its archived copy", id.kind.fetch_item(), id.value);
                    self.distrust(target, id.kind, &reason)?;
                    break;
                }
            }
        }
        if rebound > 0 {
            info!("Folder '{}': {} messages re-bound by server id without downloading", target.folder_name, rebound);
        }
        Ok(())
    }

    /// Checks the folder's pending re-binds by id (see
    /// `Database::pending_id_rebinds`) by downloading their UIDs: a copy
    /// whose bytes match is verified; otherwise it goes back to where it was
    /// bound before and the downloaded body is archived for the UID (or
    /// nothing, if the UID is gone). Fails if any couldn't be checked; they
    /// stay pending for the next sync.
    async fn reconcile_id_rebinds<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let pending = self.db.pending_id_rebinds(target.folder_id)?;
        if pending.is_empty() {
            return Ok(());
        }
        warn!(
            "Folder '{}' of {}: checking {} messages re-bound by server id",
            target.folder_name, target.account.id, pending.len()
        );
        let by_uid: HashMap<u32, crate::db::PendingIdRebind> = pending.into_iter().map(|p| (p.uid, p)).collect();
        let mut uids: Vec<u32> = by_uid.keys().copied().collect();
        uids.sort_unstable();
        let mut checked: HashSet<u32> = HashSet::new();
        for chunk in uids.chunks(self.batch_max_messages) {
            let budget = self.limits.body_budget(chunk.iter().map(|_| None));
            self.fetch_raw(session, chunk, "(UID BODY.PEEK[] INTERNALDATE)", budget, |item| {
                let Some(uid) = item.uid.or(if chunk.len() == 1 { Some(chunk[0]) } else { None }) else {
                    return Ok(());
                };
                let (Some(p), Some(body)) = (by_uid.get(&uid), item.body) else {
                    return Ok(());
                };
                if !checked.insert(uid) {
                    return Ok(());
                }
                if StorageEngine::compute_sha256(body) == p.sha256_hash {
                    return self.db.mark_id_rebind_verified(&p.message_id);
                }
                warn!("UID {} in '{}' doesn't hold the copy it was re-bound to by id; archiving what it holds", uid, target.folder_name);
                let _storage_lock = self.storage.lock_shared()?;
                let (stored, parsed) = self.store_new(target, uid, body, item.internal_date)?;
                let rel_path = stored.relative_path.to_string_lossy().to_string();
                let att_refs: Vec<(&str, &str, u64)> =
                    parsed.attachments.iter().map(|(n, m, s)| (n.as_str(), m.as_str(), *s)).collect();
                let replacement = new_message(target, uid, &rel_path, &stored, &parsed, &att_refs, None);
                self.db.undo_id_rebind(target.folder_id, target.generation, &p.message_id, Some(&replacement))?;
                progress.downloaded_bytes += stored.size_bytes;
                if let Some(cb) = progress_callback {
                    cb(progress);
                }
                Ok(())
            })
            .await?;
        }
        let mut unchecked = 0;
        for uid in uids.into_iter().filter(|u| !checked.contains(u)) {
            self.guard.set_budget(SMALL_RESPONSE_BUDGET);
            match within("UID SEARCH", self.limits.command, session.uid_search(format!("UID {}", uid))).await {
                Ok(found) if !found.contains(&uid) => {
                    self.db.undo_id_rebind(target.folder_id, target.generation, &by_uid[&uid].message_id, None)?;
                }
                Err(e) if ends_session(&e) => return Err(e),
                _ => unchecked += 1,
            }
        }
        if unchecked > 0 {
            return Err(Error::Imap(format!(
                "{} messages in '{}' re-bound by server id couldn't be checked; they will be at the next sync",
                unchecked, target.folder_name
            )));
        }
        Ok(())
    }

    /// Runs `UID FETCH <uids> <items>` and hands each FETCH response for a
    /// UID that was asked for to `on_item`. Unlike async-imap's `uid_fetch`,
    /// this sees server ids. A response that can't be parsed leaves the
    /// stream unusable: `Error::ProtocolBroken`, and the caller must not send
    /// another command on this session.
    /// Runs `UID FETCH <uids> <items>`, handing each response to `on_item`.
    /// The responses may total at most `budget` bytes, and the command has
    /// the time `Limits::deadline_for(budget)`; exceeding either ends the
    /// session (`Error::ProtocolBroken` / `Error::Timeout`).
    async fn fetch_raw<S>(
        &self,
        session: &mut async_imap::Session<S>,
        uids: &[u32],
        items: &str,
        budget: u64,
        on_item: impl FnMut(Fetched<'_>) -> Result<()>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
    {
        let limit = self.limits.deadline_for(budget);
        self.guard.set_budget(budget);
        match tokio::time::timeout(limit, self.fetch_raw_unlimited(session, uids, items, on_item)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(format!(
                "UID FETCH {} didn't complete within {} s ({} bytes received)",
                uid_set(uids),
                limit.as_secs(),
                self.guard.used()
            ))),
        }
    }

    async fn fetch_raw_unlimited<S>(
        &self,
        session: &mut async_imap::Session<S>,
        uids: &[u32],
        items: &str,
        mut on_item: impl FnMut(Fetched<'_>) -> Result<()>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
    {
        let set = uid_set(uids);
        let upper = items.to_ascii_uppercase();
        let requested_kind = ServerIdKind::ALL.into_iter().find(|kind| upper.contains(kind.fetch_item()));
        let tag = session
            .run_command(format!("UID FETCH {} {}", set, items))
            .await
            .map_err(|e| command_error(&format!("Failed to send UID FETCH {}", set), e))?;
        loop {
            let response = match session.read_response().await {
                Ok(None) => return Err(Error::Imap(format!("The connection closed during UID FETCH {}", set))),
                // async-imap reports an unparseable response this way and
                // keeps the bytes in its buffer, so the stream can't go on
                Err(e) if e.kind() == std::io::ErrorKind::Other && e.to_string().contains("during parsing") => {
                    return Err(Error::ProtocolBroken(e.to_string()))
                }
                Err(e) => return Err(command_error(&format!("Reading UID FETCH {} failed", set), e)),
                Ok(Some(response)) => response,
            };
            match response.parsed() {
                Response::Done { tag: done, status, outcome } if *done == tag => {
                    if *status != Status::Ok {
                        // As with async-imap: what arrived is used, the rest
                        // counts as missing
                        warn!("UID FETCH {} ended with {:?}: {:?}", set, status, outcome.information);
                    }
                    return Ok(());
                }
                Response::Fetch(_, attrs) => {
                    let item = fetched_from(attrs);
                    // An id was asked for but imap-proto absorbed something
                    // instead: decide from the raw bytes, as the parser of
                    // releases up to 0.6.8 did (see `absorbed_id`)
                    if let Some(kind) = requested_kind.filter(|_| !item.id_sent && item.unparsed) {
                        let raw: &[u8] = response.borrow_owner();
                        let this = match async_imap::imap_proto::Response::parse(raw) {
                            Ok((rest, _)) => &raw[..raw.len() - rest.len()],
                            Err(_) => raw,
                        };
                        if absorbed_id::classify(this, kind) == absorbed_id::AbsorbedId::Malformed {
                            // The session is dropped after this, so the rest
                            // of the response needn't be read
                            return Err(Error::ProtocolBroken(format!(
                                "UID FETCH {}: the {} of {} couldn't be parsed",
                                set,
                                kind.fetch_item(),
                                item.uid.map_or("a message".to_string(), |uid| format!("UID {}", uid))
                            )));
                        }
                    }
                    if item.uid.is_none_or(|uid| uids.contains(&uid)) {
                        on_item(item)?;
                    }
                }
                _ => {}
            }
        }
    }

    /// `RFC822.SIZE` of `uids`, in bounded chunks, and with `with_ids` their
    /// valid server ids too. Sizes only shape fetch batches: UIDs without an
    /// answer stay in the work list.
    async fn fetch_meta<S>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        uids: &[u32],
        with_ids: bool,
    ) -> Result<(HashMap<u32, u32>, HashMap<u32, ServerId>)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
    {
        let items = match target.id_kind.filter(|_| with_ids) {
            Some(kind) => format!("(UID RFC822.SIZE {})", kind.fetch_item()),
            None => "(UID RFC822.SIZE)".to_string(),
        };
        let (mut sizes, mut ids) = (HashMap::new(), HashMap::new());
        for chunk in uids.chunks(SIZE_QUERY_CHUNK) {
            self.fetch_raw(session, chunk, &items, SMALL_RESPONSE_BUDGET, |item| {
                // A size query names each UID: one without it is ignored
                if let Some(uid) = item.uid {
                    if let Some(size) = item.size {
                        sizes.insert(uid, size);
                    }
                    if let Some(id) = item.server_id.filter(|id| Some(id.kind) == target.id_kind) {
                        ids.insert(uid, id);
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| match e {
                Error::Imap(msg) => Error::Imap(format!("Failed to fetch message sizes in '{}': {}", target.folder_name, msg)),
                other => other,
            })?;
        }
        Ok((sizes, ids))
    }

    /// Fetches the bodies of `batch` with one command (with this session's
    /// server ids, if any) and archives each one that arrives, adding it to
    /// `resolved`. UIDs without a body are left for [`Self::resolve_missing`].
    #[allow(clippy::too_many_arguments)]
    async fn fetch_batch<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        batch: &[u32],
        sizes: &HashMap<u32, u32>,
        resolved: &mut HashSet<u32>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        // What the server announced, and the maximum for a UID it didn't
        let budget = self.limits.body_budget(batch.iter().map(|uid| sizes.get(uid).copied()));
        // BODY.PEEK[] ensures read-only semantics (doesn't set \Seen flag on server)
        let items = match target.id_kind {
            Some(kind) => format!("(UID BODY.PEEK[] INTERNALDATE {})", kind.fetch_item()),
            None => "(UID BODY.PEEK[] INTERNALDATE)".to_string(),
        };
        self.fetch_raw(session, batch, &items, budget, |msg| {
            // A single-UID fetch can only be that UID; otherwise trust only
            // UIDs that were asked for
            let uid = match (msg.uid, batch) {
                (Some(uid), _) => uid,
                (None, [only]) => *only,
                _ => return Ok(()),
            };
            if resolved.contains(&uid) {
                return Ok(());
            }
            let Some(raw_body) = msg.body else {
                warn!("Message UID {} in '{}' returned empty body", uid, target.folder_name);
                return Ok(());
            };
            let server_id = msg.server_id.filter(|id| Some(id.kind) == target.id_kind);
            self.archive_message(target, uid, raw_body, msg.internal_date, server_id.as_ref(), progress)?;
            resolved.insert(uid);
            if let Some(cb) = progress_callback {
                cb(progress);
            }
            Ok(())
        })
        .await
        .map_err(|e| match e {
            Error::Imap(msg) => Error::Imap(format!("Failed to fetch messages {} in '{}': {}", uid_set(batch), target.folder_name, msg)),
            other => other,
        })
    }

    /// A UID of a batch that got no body: fetched once more on its own; if
    /// it still doesn't come, a completed `UID SEARCH` decides. A UID the
    /// server no longer lists was expunged and counts as resolved; one still
    /// listed (or an unanswered search) keeps holding the checkpoint, so the
    /// next sync asks for it again.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_missing<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        uid: u32,
        sizes: &HashMap<u32, u32>,
        resolved: &mut HashSet<u32>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        self.fetch_batch(session, target, &[uid], sizes, resolved, progress, progress_callback).await?;
        if resolved.contains(&uid) {
            return Ok(());
        }
        self.guard.set_budget(SMALL_RESPONSE_BUDGET);
        match within("UID SEARCH", self.limits.command, session.uid_search(format!("UID {}", uid))).await {
            Ok(found) if !found.contains(&uid) => {
                info!("Message UID {} in '{}' was expunged before it could be fetched", uid, target.folder_name);
                resolved.insert(uid);
            }
            Err(e) if ends_session(&e) => return Err(e),
            Ok(_) => warn!(
                "Server lists UID {} in '{}' but didn't return it; it will be fetched on the next sync",
                uid, target.folder_name
            ),
            Err(e) => warn!(
                "Couldn't check UID {} in '{}' ({}); it will be fetched on the next sync",
                uid, target.folder_name, e
            ),
        }
        Ok(())
    }

    /// Moves the checkpoint to the highest UID up to which every UID of this
    /// run is resolved (archived, already archived, or confirmed expunged).
    fn advance_checkpoint(
        &self,
        target: &FolderTarget<'_>,
        uids: &[u32],
        resolved: &HashSet<u32>,
        checkpoint: &mut u32,
    ) -> Result<()> {
        let reached = uids.iter().take_while(|u| resolved.contains(u)).last().copied();
        if let Some(uid) = reached.filter(|u| *u > *checkpoint) {
            self.db.update_folder_checkpoint(target.folder_id, target.generation, uid)?;
            *checkpoint = uid;
        }
        Ok(())
    }

    /// Archives one fetched message as `uid` of the target's generation: an
    /// archived copy with the same content whose file is intact is re-bound,
    /// anything else is stored. `server_id` is the id fetched with this body;
    /// it is kept with the row, and an archived copy with the same id from
    /// the same source but other content makes the source distrusted.
    fn archive_message(
        &self,
        target: &FolderTarget<'_>,
        uid: u32,
        raw_body: &[u8],
        internal_date: Option<DateTime<Utc>>,
        server_id: Option<&ServerId>,
        progress: &mut SyncProgress,
    ) -> Result<()> {
        let sha256 = StorageEngine::compute_sha256(raw_body);
        let sourced = server_id.map(|id| SourcedId { id, source: target.source });
        if let Some(s) = sourced
            && self.db.server_id_conflicts(target.folder_id, s, &sha256)? {
            let reason = format!("{} {} was seen with different content", s.id.kind.fetch_item(), s.id.value);
            self.distrust(target, s.id.kind, &reason)?;
        }

        // From choosing a file (an intact existing copy, or the one stored
        // below) until its row is committed, retention mustn't remove it
        // (issue #79)
        let _storage_lock = self.storage.lock_shared()?;

        // Already archived under an earlier generation: bind that copy to
        // this UID instead of storing the message again, if its file is intact
        let usable = |path: &str| {
            self.storage.read_eml(path).is_ok_and(|bytes| StorageEngine::compute_sha256(&bytes) == sha256)
        };
        if self
            .db
            .rebind_message_with_id_if(target.folder_id, target.generation, uid, &sha256, sourced, usable)?
            .is_some()
        {
            progress.processed_messages += 1;
            return Ok(());
        }

        let (stored, parsed) = self.store_new_hashed(target, uid, raw_body, &sha256, internal_date)?;
        let rel_path = stored.relative_path.to_string_lossy().to_string();
        let att_refs: Vec<(&str, &str, u64)> = parsed.attachments.iter().map(|(n, m, s)| (n.as_str(), m.as_str(), *s)).collect();
        self.db.insert_new_message(&new_message(target, uid, &rel_path, &stored, &parsed, &att_refs, sourced))?;

        progress.processed_messages += 1;
        progress.downloaded_bytes += stored.size_bytes;
        Ok(())
    }

    /// Stores the raw `.eml` for `uid` of the target's generation (atomically,
    /// under a name of its own) and parses what the catalog keeps.
    fn store_new(
        &self,
        target: &FolderTarget<'_>,
        uid: u32,
        raw_body: &[u8],
        internal_date: Option<DateTime<Utc>>,
    ) -> Result<(crate::storage::StoredMessageInfo, ParsedMessage)> {
        self.store_new_hashed(target, uid, raw_body, &StorageEngine::compute_sha256(raw_body), internal_date)
    }

    /// [`Self::store_new`] for a body whose SHA-256 is already known.
    fn store_new_hashed(
        &self,
        target: &FolderTarget<'_>,
        uid: u32,
        raw_body: &[u8],
        sha256: &str,
        internal_date: Option<DateTime<Utc>>,
    ) -> Result<(crate::storage::StoredMessageInfo, ParsedMessage)> {
        let parsed = parse_message(raw_body, internal_date);
        let stored = self.storage.store_eml_hashed(
            target.account.storage_namespace(),
            target.folder_name,
            uid,
            target.generation,
            parsed.date,
            raw_body,
            sha256,
        )?;
        Ok((stored, parsed))
    }
}

impl SyncProgress {
    fn new(account: &AccountConfig) -> Self {
        SyncProgress {
            account_id: account.id.clone(),
            current_folder: String::new(),
            total_messages: 0,
            processed_messages: 0,
            downloaded_bytes: 0,
            skipped_messages: 0,
            error: None,
        }
    }

    /// Why this sync didn't back up everything, if it didn't: it stopped
    /// part-way, or messages were left out for their size. A sync with a
    /// reason is never reported as a success.
    pub fn incomplete_reason(&self) -> Option<String> {
        let skipped = (self.skipped_messages > 0).then(|| {
            format!(
                "{} message(s) are larger than the size limit and are not backed up (settings.imap_max_message_mb; retry with `mailbackup account retry-skipped`)",
                self.skipped_messages
            )
        });
        match (&self.error, skipped) {
            (Some(e), Some(s)) => Some(format!("{}; {}", e, s)),
            (Some(e), None) => Some(e.clone()),
            (None, s) => s,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn new_message<'a>(
    target: &FolderTarget<'a>,
    uid: u32,
    relative_path: &'a str,
    stored: &'a crate::storage::StoredMessageInfo,
    parsed: &'a ParsedMessage,
    attachments: &'a [(&'a str, &'a str, u64)],
    server_id: Option<SourcedId<'a>>,
) -> NewMessage<'a> {
    NewMessage {
        account_id: &target.account.id,
        folder_id: target.folder_id,
        generation: target.generation,
        uid,
        message_id: parsed.message_id.as_deref(),
        subject: parsed.subject.as_deref(),
        from_addr: parsed.from_addr.as_deref(),
        to_addrs: parsed.to_addrs.as_deref(),
        cc_addrs: parsed.cc_addrs.as_deref(),
        date: parsed.date,
        size_bytes: stored.size_bytes,
        relative_path,
        sha256_hash: &stored.sha256,
        body_text: parsed.body_text.as_deref(),
        attachments,
        server_id,
    }
}
