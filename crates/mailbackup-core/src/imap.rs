use crate::config::AccountConfig;
use crate::db::{Database, FolderSync, IdRebind, NewMessage};
use crate::error::{Error, Result};
use crate::server_ids::{ServerId, ServerIdKind, SourcedId};
use crate::storage::StorageEngine;
use async_imap::imap_proto::{AttributeValue, Response, Status};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use mail_parser::{Address, MessageParser, MimeHeaders};
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
}

/// Most messages fetched with one command.
pub const BATCH_MAX_MESSAGES: usize = 50;
/// Target size of the messages fetched with one command; a single bigger
/// message is fetched on its own. A target, not a memory limit.
pub const BATCH_TARGET_BYTES: u64 = 16 * 1024 * 1024;
/// Most UIDs per size query.
const SIZE_QUERY_CHUNK: usize = 500;

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
}

fn fetched_from<'a>(attrs: &'a [AttributeValue<'a>]) -> Fetched<'a> {
    let mut f = Fetched { uid: None, size: None, body: None, internal_date: None, server_id: None };
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
            AttributeValue::EmailId(value) => f.server_id = ServerId::email_id(value),
            AttributeValue::GmailMsgId(value) => f.server_id = Some(ServerId::gmail_msg_id(*value)),
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
    let attachments = p
        .attachments()
        .map(|att| {
            let name = att.attachment_name().unwrap_or("unnamed");
            let mime = att.content_type().map(|c| c.ctype().to_string()).unwrap_or_else(|| "application/octet-stream".to_string());
            (name.to_string(), mime, att.contents().len() as u64)
        })
        .collect();
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

fn format_address(addr: &Address<'_>) -> String {
    match addr {
        Address::List(list) => list
            .iter()
            .filter_map(|a| a.address.as_deref())
            .collect::<Vec<_>>()
            .join(", "),
        Address::Group(groups) => groups
            .iter()
            .flat_map(|g| g.addresses.iter().filter_map(|a| a.address.as_deref()))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

impl ImapSyncEngine {
    pub fn new(db: Database, storage: StorageEngine) -> Self {
        Self { db, storage, batch_max_messages: BATCH_MAX_MESSAGES, batch_target_bytes: BATCH_TARGET_BYTES }
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

    /// Connects to the IMAP server via TLS
    pub async fn connect(
        account: &AccountConfig,
        password: &str,
    ) -> Result<async_imap::Session<TlsStream<TcpStream>>> {
        let addr = format!("{}:{}", account.imap_server, account.imap_port);
        let tcp_stream = TcpStream::connect(&addr).await.map_err(|e| {
            Error::Imap(format!("Failed to connect to TCP {}: {}", addr, e))
        })?;

        let server_name = rustls_pki_types::ServerName::try_from(account.imap_server.clone())
            .map_err(|e| Error::Tls(format!("Invalid TLS server name: {}", e)))?;

        let tls_connector = Self::create_tls_connector()?;
        let tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed with {}: {}", addr, e)))?;

        let client = async_imap::Client::new(tls_stream);
        let session = client.login(&account.username, password).await.map_err(|(e, _)| {
            Error::AuthFailed(account.id.clone(), format!("IMAP login failed: {}", e))
        })?;

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
        self.sync_with(account, || Self::connect(account, password), progress_callback).await
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
                self.finish_history(&history_id, &progress, outcome.error.as_deref());
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

        let (offers_compress, offered_ids) = match session.capabilities().await {
            Ok(caps) => (caps.has_str("COMPRESS=DEFLATE"), ServerIdKind::offered(|c| caps.has_str(c))),
            Err(e) => {
                warn!("CAPABILITY failed for {}: {}; not compressing", account.id, e);
                (false, None)
            }
        };
        if offers_compress {
            match session.compress(|stream| stream).await {
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
        self.finish_history(&history_id, &progress, outcome.error.as_deref());
        Ok(progress)
    }

    fn finish_history(&self, history_id: &str, progress: &SyncProgress, error: Option<&str>) {
        let status = if error.is_some() { "partial_or_failed" } else { "success" };
        let _ = self.db.record_sync_finish(history_id, status, progress.processed_messages, progress.downloaded_bytes, error);
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
        {
            let mut mailbox_stream = session.list(None, Some("*")).await.map_err(|e| {
                Error::Imap(format!("Failed to list mailboxes: {}", e))
            })?;

            while let Some(mb_result) = mailbox_stream.next().await {
                match mb_result {
                    Ok(mb) => {
                        let name = mb.name().to_string();
                        if self.should_sync_folder(account, &name) {
                            folder_names.push(name);
                        } else {
                            debug!("Skipping folder based on filter: {}", name);
                        }
                    }
                    Err(e) => warn!("Error reading mailbox: {}", e),
                }
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
                broken = matches!(e, Error::ProtocolBroken(_));
                outcome.broken_by_ids = broken
                    && id_kind.is_some_and(|kind| self.db.server_id_disabled(&account.id, &source, kind).unwrap_or(false));
                outcome.error = Some(e.to_string());
                break;
            }
        }

        // Safe logout; a session whose responses can't be parsed gets no
        // further command
        if !broken {
            let _ = session.logout().await;
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
        let mailbox = session.examine(folder_name).await.map_err(|e| {
            Error::Imap(format!("Failed to examine mailbox '{}': {}", folder_name, e))
        })?;

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

        let last_uid = folder_rec.last_synced_uid;
        debug!(
            "Folder '{}' (ID: {}): generation={}, last_synced_uid={}, uidvalidity={:?}",
            folder_name, folder_rec.id, generation, last_uid, uidvalidity
        );

        // Search for new UIDs: (last_uid + 1):*
        let search_query = format!("UID {}:*", last_uid + 1);
        let uids_set = session.uid_search(&search_query).await.map_err(|e| {
            Error::Imap(format!("UID search failed in '{}': {}", folder_name, e))
        })?;

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

        for batch in plan_batches(&pending, &sizes, self.batch_max_messages, self.batch_target_bytes) {
            let outcome = self.fetch_batch(session, &target, &batch, &mut resolved, progress, progress_callback).await;
            if let Err(e) = outcome {
                // Keep what was archived before the failure
                self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
                return Err(self.note_broken(&target, target.id_kind.is_some(), e));
            }
            for uid in batch.iter().copied().filter(|u| !resolved.contains(u)).collect::<Vec<_>>() {
                if let Err(e) = self.resolve_missing(session, &target, uid, &mut resolved, progress, progress_callback).await {
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
            self.fetch_raw(session, chunk, "(UID BODY.PEEK[] INTERNALDATE)", |item| {
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
            match session.uid_search(format!("UID {}", uid)).await {
                Ok(found) if !found.contains(&uid) => {
                    self.db.undo_id_rebind(target.folder_id, target.generation, &by_uid[&uid].message_id, None)?;
                }
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
    async fn fetch_raw<S>(
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
        let tag = session
            .run_command(format!("UID FETCH {} {}", set, items))
            .await
            .map_err(|e| Error::Imap(format!("Failed to send UID FETCH {}: {}", set, e)))?;
        loop {
            let response = match session.read_response().await {
                None => return Err(Error::Imap(format!("The connection closed during UID FETCH {}", set))),
                // async-imap reports an unparseable response this way and
                // keeps the bytes in its buffer, so the stream can't go on
                Some(Err(e)) if e.kind() == std::io::ErrorKind::Other && e.to_string().contains("during parsing") => {
                    return Err(Error::ProtocolBroken(e.to_string()))
                }
                Some(Err(e)) => return Err(Error::Imap(format!("Reading UID FETCH {} failed: {}", set, e))),
                Some(Ok(response)) => response,
            };
            match response.parsed() {
                Response::Done { tag: done, status, information, .. } if *done == tag => {
                    if *status != Status::Ok {
                        // As with async-imap: what arrived is used, the rest
                        // counts as missing
                        warn!("UID FETCH {} ended with {:?}: {:?}", set, status, information);
                    }
                    return Ok(());
                }
                Response::Fetch(_, attrs) => {
                    let item = fetched_from(attrs);
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
            self.fetch_raw(session, chunk, &items, |item| {
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
    async fn fetch_batch<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        batch: &[u32],
        resolved: &mut HashSet<u32>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        // BODY.PEEK[] ensures read-only semantics (doesn't set \Seen flag on server)
        let items = match target.id_kind {
            Some(kind) => format!("(UID BODY.PEEK[] INTERNALDATE {})", kind.fetch_item()),
            None => "(UID BODY.PEEK[] INTERNALDATE)".to_string(),
        };
        self.fetch_raw(session, batch, &items, |msg| {
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
    async fn resolve_missing<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        target: &FolderTarget<'_>,
        uid: u32,
        resolved: &mut HashSet<u32>,
        progress: &mut SyncProgress,
        progress_callback: Option<&F>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        self.fetch_batch(session, target, &[uid], resolved, progress, progress_callback).await?;
        if resolved.contains(&uid) {
            return Ok(());
        }
        match session.uid_search(format!("UID {}", uid)).await {
            Ok(found) if !found.contains(&uid) => {
                info!("Message UID {} in '{}' was expunged before it could be fetched", uid, target.folder_name);
                resolved.insert(uid);
            }
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
        if let Some(s) = sourced {
            if self.db.server_id_conflicts(target.folder_id, s, &sha256)? {
                let reason = format!("{} {} was seen with different content", s.id.kind.fetch_item(), s.id.value);
                self.distrust(target, s.id.kind, &reason)?;
            }
        }

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

        let (stored, parsed) = self.store_new(target, uid, raw_body, internal_date)?;
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
        let parsed = parse_message(raw_body, internal_date);
        let stored = self.storage.store_eml_in_generation(
            target.account.storage_namespace(),
            target.folder_name,
            uid,
            target.generation,
            parsed.date,
            raw_body,
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
