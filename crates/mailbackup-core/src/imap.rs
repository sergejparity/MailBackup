use crate::config::AccountConfig;
use crate::db::{Database, FolderSync};
use crate::error::{Error, Result};
use crate::storage::StorageEngine;
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
    /// so a fresh one from `connect` is used without compression.
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
        let failed = |e: Error| {
            let _ = self.db.record_sync_finish(&history_id, "failed", 0, 0, Some(&e.to_string()));
            e
        };
        let mut session = connect().await.map_err(failed)?;

        let offers_compress = match session.capabilities().await {
            Ok(caps) => caps.has_str("COMPRESS=DEFLATE"),
            Err(e) => {
                warn!("CAPABILITY failed for {}: {}; not compressing", account.id, e);
                false
            }
        };
        if offers_compress {
            match session.compress(|stream| stream).await {
                Ok(compressed) => {
                    debug!("Using COMPRESS=DEFLATE for {}", account.id);
                    return self.run_session(compressed, account, &history_id, progress_callback).await;
                }
                Err(e) => {
                    warn!("COMPRESS=DEFLATE failed for {}: {}; reconnecting without compression", account.id, e);
                    session = connect().await.map_err(failed)?;
                }
            }
        }
        self.run_session(session, account, &history_id, progress_callback).await
    }

    /// Like [`Self::sync_account`] over an already logged-in session, e.g. a
    /// transport other than TLS.
    pub async fn sync_session<S, F>(
        &self,
        session: async_imap::Session<S>,
        account: &AccountConfig,
        progress_callback: Option<F>,
    ) -> Result<SyncProgress>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let history_id = self.db.record_sync_start(&account.id)?;
        self.run_session(session, account, &history_id, progress_callback).await
    }

    async fn run_session<S, F>(
        &self,
        mut session: async_imap::Session<S>,
        account: &AccountConfig,
        history_id: &str,
        progress_callback: Option<F>,
    ) -> Result<SyncProgress>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
        F: Fn(&SyncProgress) + Send + Sync + 'static,
    {
        let mut progress = SyncProgress {
            account_id: account.id.clone(),
            current_folder: String::new(),
            total_messages: 0,
            processed_messages: 0,
            downloaded_bytes: 0,
        };

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

        let mut sync_error = None;
        for folder_name in &folder_names {
            progress.current_folder = folder_name.clone();
            if let Some(ref cb) = progress_callback {
                cb(&progress);
            }

            if let Err(e) = self.sync_folder(&mut session, account, folder_name, &mut progress, progress_callback.as_ref()).await {
                error!("Error syncing folder '{}': {}", folder_name, e);
                sync_error = Some(e.to_string());
                break;
            }
        }

        let status = if sync_error.is_some() { "partial_or_failed" } else { "success" };
        let _ = self.db.record_sync_finish(
            history_id,
            status,
            progress.processed_messages,
            progress.downloaded_bytes,
            sync_error.as_deref(),
        );

        // Safe logout
        let _ = session.logout().await;

        Ok(progress)
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
    async fn sync_folder<S, F>(
        &self,
        session: &mut async_imap::Session<S>,
        account: &AccountConfig,
        folder_name: &str,
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
            &account.remote_identity(),
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

        let target = FolderTarget { account, folder_name, folder_id: &folder_rec.id, generation };
        let mut checkpoint = last_uid;
        let sizes = self.fetch_sizes(session, folder_name, &pending).await?;
        for batch in plan_batches(&pending, &sizes, self.batch_max_messages, self.batch_target_bytes) {
            let outcome = self.fetch_batch(session, &target, &batch, &mut resolved, progress, progress_callback).await;
            if let Err(e) = outcome {
                // Keep what was archived before the failure
                self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
                return Err(e);
            }
            for uid in batch.iter().copied().filter(|u| !resolved.contains(u)).collect::<Vec<_>>() {
                if let Err(e) = self.resolve_missing(session, &target, uid, &mut resolved, progress, progress_callback).await {
                    self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
                    return Err(e);
                }
            }
            self.advance_checkpoint(&target, &uids, &resolved, &mut checkpoint)?;
        }

        Ok(())
    }

    /// `RFC822.SIZE` of `uids`, in bounded chunks. Only used to shape fetch
    /// batches: UIDs without an answer stay in the work list.
    async fn fetch_sizes<S>(
        &self,
        session: &mut async_imap::Session<S>,
        folder_name: &str,
        uids: &[u32],
    ) -> Result<HashMap<u32, u32>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
    {
        let mut sizes = HashMap::new();
        for chunk in uids.chunks(SIZE_QUERY_CHUNK) {
            let mut stream = session.uid_fetch(uid_set(chunk), "(UID RFC822.SIZE)").await.map_err(|e| {
                Error::Imap(format!("Failed to fetch message sizes in '{}': {}", folder_name, e))
            })?;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(f) => {
                        if let (Some(uid), Some(size)) = (f.uid, f.size) {
                            sizes.insert(uid, size);
                        }
                    }
                    Err(e) => warn!("Error reading message sizes in '{}': {}", folder_name, e),
                }
            }
        }
        Ok(sizes)
    }

    /// Fetches the bodies of `batch` with one command and archives each one
    /// that arrives, adding it to `resolved`. UIDs without a body are left
    /// for [`Self::resolve_missing`].
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
        let mut stream = session.uid_fetch(uid_set(batch), "(UID BODY.PEEK[] INTERNALDATE)").await.map_err(|e| {
            Error::Imap(format!("Failed to fetch messages {} in '{}': {}", uid_set(batch), target.folder_name, e))
        })?;
        while let Some(item) = stream.next().await {
            let msg = match item {
                Ok(m) => m,
                Err(e) => {
                    warn!("Error reading a message from '{}': {}", target.folder_name, e);
                    continue;
                }
            };
            // A single-UID fetch can only be that UID; otherwise trust only
            // UIDs that were asked for
            let uid = match (msg.uid, batch) {
                (Some(uid), _) if batch.contains(&uid) => uid,
                (None, [only]) => *only,
                _ => continue,
            };
            if resolved.contains(&uid) {
                continue;
            }
            let Some(raw_body) = msg.body() else {
                warn!("Message UID {} in '{}' returned empty body", uid, target.folder_name);
                continue;
            };
            let internal_date = msg.internal_date().map(|dt| {
                DateTime::from_timestamp(dt.timestamp(), 0).unwrap_or_else(Utc::now)
            });
            self.archive_message(target, uid, raw_body, internal_date, progress)?;
            resolved.insert(uid);
            if let Some(cb) = progress_callback {
                cb(progress);
            }
        }
        Ok(())
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
    /// anything else is stored.
    fn archive_message(
        &self,
        target: &FolderTarget<'_>,
        uid: u32,
        raw_body: &[u8],
        internal_date: Option<DateTime<Utc>>,
        progress: &mut SyncProgress,
    ) -> Result<()> {
        let FolderTarget { account, folder_name, folder_id, generation } = *target;
        // Already archived under an earlier generation: bind that copy to
        // this UID instead of storing the message again, if its file is intact
        let sha256 = StorageEngine::compute_sha256(raw_body);
        let usable = |path: &str| {
            self.storage.read_eml(path).is_ok_and(|bytes| StorageEngine::compute_sha256(&bytes) == sha256)
        };
        if self.db.rebind_message_if(folder_id, generation, uid, &sha256, usable)?.is_some() {
            progress.processed_messages += 1;
            return Ok(());
        }

        // Parse message with mail-parser
        let parsed = MessageParser::default().parse(raw_body);
        let (subject, from_addr, to_addrs, cc_addrs, date, body_text, attachments) = if let Some(ref p) = parsed {
            let subj = p.subject().map(|s| s.to_string());
            let from = p.from().map(format_address);
            let to = p.to().map(format_address);
            let cc = p.cc().map(format_address);

            let msg_date = p.date().and_then(|d| DateTime::from_timestamp(d.to_timestamp(), 0)).or(internal_date);
            let body = p.body_text(0).map(|s| s.to_string());

            let mut att_list = Vec::new();
            for att in p.attachments() {
                let name = att.attachment_name().unwrap_or("unnamed");
                let mime = att.content_type().map(|c| c.ctype().to_string()).unwrap_or_else(|| "application/octet-stream".to_string());
                let size = att.contents().len() as u64;
                att_list.push((name.to_string(), mime, size));
            }

            (subj, from, to, cc, msg_date, body, att_list)
        } else {
            (None, None, None, None, internal_date, None, Vec::new())
        };

        // Store atomic raw .eml
        let stored =
            self.storage.store_eml_in_generation(account.storage_namespace(), folder_name, uid, generation, date, raw_body)?;

        let rel_path_str = stored.relative_path.to_string_lossy().to_string();
        let att_refs: Vec<(&str, &str, u64)> = attachments
            .iter()
            .map(|(n, m, s)| (n.as_str(), m.as_str(), *s))
            .collect();

        let message_id_str = parsed.as_ref().and_then(|p| p.message_id()).map(|s| s.to_string());

        // Save to SQLite
        self.db.insert_message_in_generation(
            &account.id,
            folder_id,
            generation,
            uid,
            message_id_str.as_deref(),
            subject.as_deref(),
            from_addr.as_deref(),
            to_addrs.as_deref(),
            cc_addrs.as_deref(),
            date,
            stored.size_bytes,
            &rel_path_str,
            &stored.sha256,
            body_text.as_deref(),
            &att_refs,
        )?;

        progress.processed_messages += 1;
        progress.downloaded_bytes += stored.size_bytes;
        Ok(())
    }
}
