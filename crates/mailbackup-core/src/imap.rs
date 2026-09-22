use crate::config::AccountConfig;
use crate::db::Database;
use crate::error::{Error, Result};
use crate::storage::StorageEngine;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use mail_parser::{Address, MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};
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

pub struct ImapSyncEngine {
    db: Database,
    storage: StorageEngine,
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
        Self { db, storage }
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
        let history_id = self.db.record_sync_start(&account.id)?;
        let mut progress = SyncProgress {
            account_id: account.id.clone(),
            current_folder: String::new(),
            total_messages: 0,
            processed_messages: 0,
            downloaded_bytes: 0,
        };

        // Connect
        let mut session = match Self::connect(account, password).await {
            Ok(s) => s,
            Err(e) => {
                let err_str = e.to_string();
                let _ = self.db.record_sync_finish(&history_id, "failed", 0, 0, Some(&err_str));
                return Err(e);
            }
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
            &history_id,
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
        let folder_rec = self.db.get_or_create_folder(
            &account.id,
            folder_name,
            &local_slug,
            uidvalidity,
        )?;

        let last_uid = folder_rec.last_synced_uid;
        debug!("Folder '{}' (ID: {}): last_synced_uid={}, uidvalidity={:?}", folder_name, folder_rec.id, last_uid, uidvalidity);

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

        info!("Folder '{}': {} new messages to download", folder_name, uids.len());
        progress.total_messages += uids.len() as u32;

        let mut max_synced_uid = last_uid;

        // Fetch messages sequentially to allow smooth progress and backoff
        for &uid in &uids {
            // Check if already in DB
            if self.db.message_exists_by_uid(&folder_rec.id, uid)? {
                max_synced_uid = max_synced_uid.max(uid);
                continue;
            }

            // BODY.PEEK[] ensures read-only semantics (doesn't set \Seen flag on server)
            let fetch_stream = session.uid_fetch(uid.to_string(), "(BODY.PEEK[] INTERNALDATE)").await.map_err(|e| {
                Error::Imap(format!("Failed to fetch message UID {} in '{}': {}", uid, folder_name, e))
            })?;

            let mut stream = fetch_stream;
            while let Some(msg_result) = stream.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Error reading message UID {} from stream: {}", uid, e);
                        continue;
                    }
                };

                let raw_body = match msg.body() {
                    Some(b) => b,
                    None => {
                        warn!("Message UID {} in '{}' returned empty body", uid, folder_name);
                        continue;
                    }
                };

                let internal_date = msg.internal_date().map(|dt| {
                    DateTime::from_timestamp(dt.timestamp(), 0).unwrap_or_else(Utc::now)
                });

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
                let stored = self.storage.store_eml(
                    &account.id,
                    folder_name,
                    uid,
                    date,
                    raw_body,
                )?;

                let rel_path_str = stored.relative_path.to_string_lossy().to_string();
                let att_refs: Vec<(&str, &str, u64)> = attachments
                    .iter()
                    .map(|(n, m, s)| (n.as_str(), m.as_str(), *s))
                    .collect();

                let message_id_str = parsed.as_ref().and_then(|p| p.message_id()).map(|s| s.to_string());

                // Save to SQLite
                self.db.insert_message(
                    &account.id,
                    &folder_rec.id,
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
                max_synced_uid = max_synced_uid.max(uid);

                if let Some(ref cb) = progress_callback {
                    cb(progress);
                }
            }

            // Update folder state checkpoint
            self.db.update_folder_sync_state(&folder_rec.id, max_synced_uid)?;
        }

        Ok(())
    }
}
