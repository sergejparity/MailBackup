//! One-time writer of the compatibility fixtures (issue #40).
//!
//! The fixtures pin what the pre-upgrade code writes, so later dependency
//! upgrades (#41–#46) can prove they still read it. They must be written by
//! the *old* code, once: this generator is ignored, needs an explicit opt-in,
//! and refuses to touch an existing fixture directory. Never re-run it after
//! upgrading a dependency; add a new, separately versioned fixture set instead.
//!
//! ```text
//! MAILBACKUP_WRITE_COMPAT_FIXTURES=1 MAILBACKUP_FIXTURE_COMMIT=<sha> \
//!     cargo test -p mailbackup-core --test compat_generate -- --ignored
//! ```

mod compat;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use compat::*;
use mailbackup_core::config::{AppConfig, ArchiveInfo, GlobalSettings};
use mailbackup_core::db::{Database, NewMessage, NewTransition};
use mailbackup_core::keyring::{CredentialStore, NoKeyring};
use mailbackup_core::server_ids::{ServerId, ServerIdKind, SourcedId};
use mailbackup_core::storage::StorageEngine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[test]
#[ignore = "writes the committed fixtures; run once, explicitly (see the module docs)"]
fn generate_compat_fixtures() {
    if std::env::var("MAILBACKUP_WRITE_COMPAT_FIXTURES").as_deref() != Ok("1") {
        panic!("Set MAILBACKUP_WRITE_COMPAT_FIXTURES=1 to write the fixtures");
    }
    let commit = std::env::var("MAILBACKUP_FIXTURE_COMMIT").expect("set MAILBACKUP_FIXTURE_COMMIT to the writer's commit");
    let root = fixtures_root();
    assert!(!root.exists(), "{} already exists: fixtures are written once and never regenerated", root.display());

    credentials_key_file(&root.join("credentials").join("key-file"));
    credentials_keyring(&root.join("credentials").join("keyring"));
    credentials_passphrase(&root.join("credentials").join("passphrase"));
    credentials_legacy(&root.join("credentials").join("legacy"));
    keyring_namespace(&root.join("credentials").join("namespace.json"));
    let eml = eml_inputs(&root.join("eml"));
    catalog(&root.join("catalog"), &eml);
    config(&root.join("config"));

    write_json(
        &root.join("WRITER.json"),
        &json!({
            "mailbackup_version": env!("CARGO_PKG_VERSION"),
            "commit": commit,
            "written_at": chrono::Utc::now().to_rfc3339(),
            "note": "Written once by tests/compat_generate.rs with this version. Do not regenerate with upgraded dependencies."
        }),
    );
}

// --- Credential store ------------------------------------------------------

fn store_at(dir: &Path) -> CredentialStore {
    CredentialStore::with_paths(dir.join(".credentials_store.json"), dir.join(".credentials_key"))
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring))
}

/// Key-file mode (no keyring, as on a headless machine), with a legacy
/// `~/.mailbackup` location: passwords, bindings, a pre-binding password, a
/// staged archive-transition `credential_ref`, an adopted legacy secret
/// (`meta:migrated:`) and a deleted one (`meta:deleted:`).
fn credentials_key_file(dir: &Path) {
    let home = dir.join("home");
    let config = dir.join("config");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&config).unwrap();

    let legacy = store_at(&home);
    legacy.set_password(ADOPTED_ID, ADOPTED_PW).unwrap();
    legacy.set_password(DELETED_ID, DELETED_PW).unwrap();

    let store = store_at(&config)
        .with_legacy_store(home.join(".credentials_store.json"), home.join(".credentials_key"));
    store.set_account_password(&live_account(), LIVE_PW).unwrap();
    store.set_account_password(&staged_account(), STAGED_PW).unwrap();
    store.set_password(PRE_BINDING_ID, PRE_BINDING_PW).unwrap();
    assert_eq!(store.get_password(ADOPTED_ID).unwrap(), ADOPTED_PW); // adopts it
    store.delete_password(DELETED_ID).unwrap(); // leaves a deletion marker

    write_json(
        &dir.join("expected.json"),
        &json!({
            "config_store_entries": [
                format!("account:{}", "acct-live"),
                format!("account:{}:binding", "acct-live"),
                format!("account:{}", "acct-live~cred-1"),
                format!("account:{}:binding", "acct-live~cred-1"),
                format!("account:{}", PRE_BINDING_ID),
                format!("account:{}", ADOPTED_ID),
                format!("meta:migrated:account:{}", ADOPTED_ID),
                // Only for keys the legacy location held (it had no binding)
                format!("meta:deleted:account:{}", DELETED_ID),
            ],
            "legacy_store_entries": [format!("account:{}", ADOPTED_ID), format!("account:{}", DELETED_ID)],
        }),
    );
}

/// Keyring mode: the background service's disk storage wrote a password to
/// the local store (and the store's key to the keyring as
/// `master_encryption_key`); another password lives only in the keyring.
/// `keyring.json` holds the keyring's entries relative to the store's
/// namespace (`<namespace>:<key>`), which depends on the folder's path.
fn credentials_keyring(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let keyring = Arc::new(MemoryKeyring::default());
    let store = CredentialStore::with_paths(dir.join(".credentials_store.json"), dir.join(".credentials_key"))
        .with_passphrase(None)
        .with_keyring(keyring.clone())
        .with_disk_storage(true);
    store.set_account_password(&live_account(), LIVE_PW).unwrap();
    store.set_disk_storage(false);
    store
        .set_account_password(&account(KEYRING_ID, "imap.example.test", "kr@example.test", None), KEYRING_PW)
        .unwrap();

    let prefix = store.keyring_key("");
    let relative: BTreeMap<String, String> = keyring
        .snapshot()
        .into_iter()
        .map(|(k, v)| (k.strip_prefix(&prefix).expect("namespaced entry").to_string(), v))
        .collect();
    assert!(relative.contains_key("master_encryption_key"));
    write_json(&dir.join("keyring.json"), &serde_json::to_value(relative).unwrap());
}

/// Passphrase mode: Argon2id-derived key, parameters and salt in `kdf`.
fn credentials_passphrase(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let store = store_at(dir).with_passphrase(Some(PASSPHRASE.to_string()));
    store.set_account_password(&live_account(), LIVE_PW).unwrap();
    store.set_account_password(&staged_account(), STAGED_PW).unwrap();
    store.set_password(PRE_BINDING_ID, PRE_BINDING_PW).unwrap();
}

/// Formats written before 0.2.20, which today's code can only read: flat
/// maps, plaintext or AES-256-GCM (`enc:v1:<nonce>:<ct>`) with the key file's
/// key or the passphrase's unsalted SHA-256, possibly named without the dot.
/// Built here by hand, following that format.
fn credentials_legacy(dir: &Path) {
    let plain = dir.join("plaintext");
    std::fs::create_dir_all(&plain).unwrap();
    write_json(
        &plain.join(".credentials_store.json"),
        &json!({ format!("account:{}", "acct-plain"): "synthetic-plaintext-password" }),
    );

    let key_file = dir.join("key-file");
    std::fs::create_dir_all(&key_file).unwrap();
    let key: [u8; 32] = Sha256::digest(b"synthetic legacy key-file key").into();
    std::fs::write(key_file.join(".credentials_key"), hex::encode(key)).unwrap();
    write_json(
        &key_file.join(".credentials_store.json"),
        &json!({
            format!("account:{}", "acct-l1"): legacy_encrypt("synthetic-legacy-key-file-password", &key),
            format!("account:{}", "acct-l2"): "synthetic-legacy-plain-in-encrypted-store",
        }),
    );

    let passphrase = dir.join("sha256-passphrase-undotted");
    std::fs::create_dir_all(&passphrase).unwrap();
    let key: [u8; 32] = Sha256::digest(PASSPHRASE.as_bytes()).into();
    write_json(
        &passphrase.join("credentials_store.json"),
        &json!({ format!("account:{}", "acct-l3"): legacy_encrypt("synthetic-legacy-passphrase-password", &key) }),
    );
}

fn legacy_encrypt(secret: &str, key: &[u8; 32]) -> String {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).unwrap();
    let ct = cipher.encrypt(&aes_gcm::aead::Nonce::<Aes256Gcm>::from(nonce), secret.as_bytes()).unwrap();
    format!("enc:v1:{}:{}", hex::encode(nonce), hex::encode(ct))
}

/// The keyring namespace of a store at a fixed path (Unix only: the path
/// syntax differs on Windows). The folder doesn't exist, so it resolves
/// lexically below `/`.
fn keyring_namespace(path: &Path) {
    let folder = "/nonexistent-mailbackup-fixture/config";
    let store = CredentialStore::with_paths(
        Path::new(folder).join(".credentials_store.json"),
        Path::new(folder).join(".credentials_key"),
    )
    .with_keyring(Arc::new(NoKeyring));
    write_json(path, &json!({ "unix_store_folder": folder, "keyring_key_of_account_x": store.keyring_key("account:x") }));
}

// --- Archived mail ----------------------------------------------------------

/// Raw messages, byte for byte as a server could send them: CRLF, LF only,
/// 8-bit UTF-8 and no final newline, multipart with an attachment.
fn eml_inputs(dir: &Path) -> BTreeMap<&'static str, Vec<u8>> {
    let mut out = BTreeMap::new();
    out.insert(
        "m1",
        b"From: Alice <alice@example.test>\r\nTo: live@example.test\r\nSubject: Quarterly report zebrafish\r\nDate: Tue, 06 Oct 2026 09:15:00 +0000\r\nMessage-ID: <m1@example.test>\r\n\r\nThe zebrafish numbers are in.\r\n".to_vec(),
    );
    out.insert(
        "m2",
        b"From: Bob <bob@example.test>\nTo: live@example.test\nSubject: Budget attached\nDate: Wed, 07 Oct 2026 10:00:00 +0000\nMessage-ID: <m2@example.test>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"b1\"\n\n--b1\nContent-Type: text/plain; charset=utf-8\n\nSee the budget.\n--b1\nContent-Type: application/pdf; name=\"budget-2026.pdf\"\nContent-Disposition: attachment; filename=\"budget-2026.pdf\"\nContent-Transfer-Encoding: base64\n\nJVBERi0xLjQKJcfsj6IKc3ludGhldGljCg==\n--b1--\n".to_vec(),
    );
    out.insert(
        "m3",
        "From: Jürgen <juergen@example.test>\r\nTo: live@example.test\r\nSubject: =?utf-8?q?Gr=C3=BC=C3=9Fe_aus_K=C3=B6ln?=\r\nDate: Thu, 08 Oct 2026 18:30:00 +0200\r\nMessage-ID: <m3@example.test>\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGrüße aus Köln, ünïcödé quokka"
            .as_bytes()
            .to_vec(),
    );
    out.insert(
        "m5",
        b"From: Carol <carol@example.test>\r\nTo: live@example.test\r\nSubject: After the rescan\r\nDate: Mon, 02 Nov 2026 08:00:00 +0000\r\nMessage-ID: <m5@example.test>\r\n\r\nArrived after the UIDVALIDITY change.\r\n".to_vec(),
    );
    std::fs::create_dir_all(dir).unwrap();
    for (name, bytes) in &out {
        std::fs::write(dir.join(format!("{}.eml", name)), bytes).unwrap();
    }
    out
}

fn date(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc2822(s).unwrap().with_timezone(&chrono::Utc)
}

struct Writer<'a> {
    db: &'a Database,
    storage: &'a StorageEngine,
}

impl Writer<'_> {
    #[allow(clippy::too_many_arguments)]
    fn store(
        &self,
        account: &str,
        folder_id: &str,
        folder: &str,
        generation: u32,
        uid: u32,
        raw: &[u8],
        subject: &str,
        when: &str,
        body: &str,
        attachments: &[(&str, &str, u64)],
        server_id: Option<(&ServerId, &str)>,
    ) -> String {
        self.store_in(account, account, folder_id, folder, generation, uid, raw, subject, when, body, attachments, server_id)
    }

    /// [`Self::store`] with files under `namespace` (the account's storage
    /// namespace) instead of its id.
    #[allow(clippy::too_many_arguments)]
    fn store_in(
        &self,
        account: &str,
        namespace: &str,
        folder_id: &str,
        folder: &str,
        generation: u32,
        uid: u32,
        raw: &[u8],
        subject: &str,
        when: &str,
        body: &str,
        attachments: &[(&str, &str, u64)],
        server_id: Option<(&ServerId, &str)>,
    ) -> String {
        let stored = self.storage.store_eml_in_generation(namespace, folder, uid, generation, Some(date(when)), raw).unwrap();
        let path = stored.relative_path.to_string_lossy().replace('\\', "/");
        self.db
            .insert_new_message(&NewMessage {
                account_id: account,
                folder_id,
                generation,
                uid,
                message_id: None,
                subject: Some(subject),
                from_addr: Some("fixture@example.test"),
                to_addrs: Some("live@example.test"),
                cc_addrs: None,
                date: Some(date(when)),
                size_bytes: stored.size_bytes,
                relative_path: &path,
                sha256_hash: &stored.sha256,
                body_text: Some(body),
                attachments,
                server_id: server_id.map(|(id, source)| SourcedId { id, source }),
            })
            .unwrap()
    }
}

/// A catalog and data folder with everything later versions must keep
/// reading: two UID generations, duplicate copies, re-binds by content and by
/// server id (one verified, one marked `needs_check` by a distrust), a
/// disabled id source, a finished and an outstanding archive transition, the
/// FTS index, attachments and sync history.
fn catalog(dir: &Path, eml: &BTreeMap<&'static str, Vec<u8>>) {
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = Database::open(dir.join("mailbackup.db")).unwrap();
    let storage = StorageEngine::new(&data);
    let w = Writer { db: &db, storage: &storage };
    let m = |name: &str| eml[name].as_slice();
    let id = |v: &str| ServerId::email_id(v).unwrap();
    let (id1, id2, id3, id4, id5) = (id("M1aaaa"), id("M2bbbb"), id("M3cccc"), id("M4dddd"), id("M5eeee"));

    // acct-live, generation 0: INBOX holds m1 twice (a mailbox may), m2, m3;
    // Archive holds another copy of m1
    db.upsert_account("acct-live", "Fixture live", "acct-live@example.test", "generic_imap").unwrap();
    let inbox = db.begin_folder_sync("acct-live", "INBOX", "INBOX", Some(100), IDENTITY).unwrap();
    let f = inbox.folder.id.clone();
    let when1 = "Tue, 06 Oct 2026 09:15:00 +0000";
    w.store("acct-live", &f, "INBOX", 0, 1, m("m1"), "Quarterly report zebrafish", when1, "The zebrafish numbers are in.", &[], Some((&id1, IDENTITY)));
    let m2_id = w.store("acct-live", &f, "INBOX", 0, 2, m("m2"), "Budget attached", "Wed, 07 Oct 2026 10:00:00 +0000", "See the budget.", &[("budget-2026.pdf", "application/pdf", 22)], Some((&id2, IDENTITY)));
    let m3_id = w.store("acct-live", &f, "INBOX", 0, 3, m("m3"), "Grüße aus Köln", "Thu, 08 Oct 2026 16:30:00 +0000", "Grüße aus Köln, ünïcödé quokka", &[], Some((&id3, IDENTITY)));
    w.store("acct-live", &f, "INBOX", 0, 4, m("m1"), "Quarterly report zebrafish", when1, "The zebrafish numbers are in.", &[], Some((&id4, IDENTITY)));
    db.update_folder_checkpoint(&f, 0, 4).unwrap();
    let archive_folder = db.begin_folder_sync("acct-live", "Archive", "Archive", Some(7), IDENTITY).unwrap();
    w.store("acct-live", &archive_folder.folder.id, "Archive", 0, 1, m("m1"), "Quarterly report zebrafish", when1, "The zebrafish numbers are in.", &[], None);
    db.update_folder_checkpoint(&archive_folder.folder.id, 0, 1).unwrap();

    // Same server, new UIDVALIDITY: generation 1. uid 11 re-bound by content,
    // 12 and 13 by server id (13 then verified), 14 new
    let rescan = db.begin_folder_sync("acct-live", "INBOX", "INBOX", Some(200), IDENTITY).unwrap();
    assert_eq!(rescan.generation, 1);
    let sha1 = StorageEngine::compute_sha256(m("m1"));
    assert!(db.rebind_message(&f, 1, 11, &sha1).unwrap().is_some());
    let size = |name: &str| eml[name].len() as u64;
    let rebound2 = db.rebind_by_server_id_if("acct-live", &f, 1, 12, SourcedId { id: &id2, source: IDENTITY }, size("m2"), |_, _| true).unwrap();
    assert_eq!(rebound2, mailbackup_core::db::IdRebind::Rebound(m2_id));
    let rebound3 = db.rebind_by_server_id_if("acct-live", &f, 1, 13, SourcedId { id: &id3, source: IDENTITY }, size("m3"), |_, _| true).unwrap();
    assert_eq!(rebound3, mailbackup_core::db::IdRebind::Rebound(m3_id.clone()));
    db.mark_id_rebind_verified(&m3_id).unwrap();
    w.store("acct-live", &f, "INBOX", 1, 14, m("m5"), "After the rescan", "Mon, 02 Nov 2026 08:00:00 +0000", "Arrived after the UIDVALIDITY change.", &[], Some((&id5, IDENTITY)));
    db.update_folder_checkpoint(&f, 1, 14).unwrap();
    // The id source turned out inconsistent: the unverified re-bind (uid 12)
    // must be checked; Gmail ids from it are switched off
    db.record_server_id_distrust("acct-live", IDENTITY, ServerIdKind::EmailId, "synthetic: an id named other content").unwrap();
    db.record_server_id_disabled("acct-live", IDENTITY, ServerIdKind::GmailMsgId, "synthetic: unparseable response").unwrap();
    let history = db.record_sync_start("acct-live").unwrap();
    db.record_sync_finish(&history, "success", 1, size("m5"), None).unwrap();

    // acct-moved: archived under its old server, then "start a new archive"
    // (finished), then synced from the new server
    let moved_old = "old.example.test:993:moved@example.test";
    db.upsert_account("acct-moved", "Fixture moved", "acct-moved@example.test", "generic_imap").unwrap();
    let mf = db.begin_folder_sync("acct-moved", "INBOX", "INBOX", Some(5), moved_old).unwrap().folder.id;
    w.store("acct-moved", &mf, "INBOX", 0, 1, m("m2"), "Budget attached", "Wed, 07 Oct 2026 10:00:00 +0000", "See the budget.", &[("budget-2026.pdf", "application/pdf", 22)], None);
    db.update_folder_checkpoint(&mf, 0, 1).unwrap();
    let archive_id = "acct-moved~archive-20261104-1";
    db.upsert_account(archive_id, "Fixture moved (archived 2026-11-04)", "acct-moved~archive@example.test", "generic_imap").unwrap();
    let t = db
        .prepare_account_transition(&NewTransition {
            live_id: "acct-moved",
            archive_id,
            seq: 1,
            old_credential_ref: "acct-moved",
            staged_credential_ref: "acct-moved~cred-1",
        })
        .unwrap();
    db.finish_account_transition(t).unwrap();
    let nf = db.begin_folder_sync("acct-moved", "INBOX", "INBOX", Some(9), "new.example.test:993:moved@new.example.test").unwrap().folder.id;
    w.store_in("acct-moved", "acct-moved~1", &nf, "INBOX", 0, 1, m("m3"), "Grüße aus Köln", "Thu, 08 Oct 2026 16:30:00 +0000", "Grüße aus Köln, ünïcödé quokka", &[], None);
    db.update_folder_checkpoint(&nf, 0, 1).unwrap();

    // acct-pending: a transition prepared but neither finished nor undone
    // (the process stopped in between); recovery decides it at startup
    db.upsert_account("acct-pending", "Fixture pending", "acct-pending@example.test", "generic_imap").unwrap();
    let pf = db.begin_folder_sync("acct-pending", "INBOX", "INBOX", Some(3), "p.example.test:993:p@example.test").unwrap().folder.id;
    w.store("acct-pending", &pf, "INBOX", 0, 1, m("m5"), "After the rescan", "Mon, 02 Nov 2026 08:00:00 +0000", "Arrived after the UIDVALIDITY change.", &[], None);
    db.prepare_account_transition(&NewTransition {
        live_id: "acct-pending",
        archive_id: "acct-pending~archive-20261104-1",
        seq: 1,
        old_credential_ref: "acct-pending",
        staged_credential_ref: "acct-pending~cred-1",
    })
    .unwrap();
    drop(db);

    // What the writer left, for the tests to compare against
    let _ = std::fs::remove_dir_all(data.join(".staging"));
    let conn = rusqlite::Connection::open(dir.join("mailbackup.db")).unwrap();
    write_json(&dir.join("snapshot.json"), &compat::catalog::snapshot(&conn));
}

// --- Config -----------------------------------------------------------------

/// A config using every field (archive info, staged credential ref, storage
/// namespace, trusted server ids, filters, settings), as `AppConfig::save`
/// writes it.
fn config(dir: &Path) {
    let mut live = staged_account();
    live.storage_namespace = Some("acct-live~1".to_string());
    live.trust_server_ids = true;
    live.schedule = Some("0 */6 * * *".to_string());
    live.retention_days = Some(365);
    live.folder_filter.include = vec!["INBOX".to_string(), "Projects/*".to_string()];
    let mut archived = live_account();
    archived.id = "acct-live~archive-20261104-1".to_string();
    archived.name = "Fixture acct-live (archived 2026-11-04)".to_string();
    archived.enabled = false;
    archived.archive = Some(ArchiveInfo {
        archived_at: chrono::DateTime::parse_from_rfc3339("2026-11-04T07:00:00Z").unwrap().with_timezone(&chrono::Utc),
        retired_from: "acct-live".to_string(),
        last_source: Some(IDENTITY.to_string()),
    });
    let mut gmail = account("acct-gmail", "imap.gmail.com", "someone@gmail.test", None);
    gmail.provider = mailbackup_core::config::ProviderType::Gmail;
    gmail.gmail_smart_labels = false;
    let settings = GlobalSettings {
        allowed_hosts: vec!["backup.example.test".to_string()],
        approved_dirs: vec!["/srv/exports".into()],
        autostart: true,
        log_retention_days: None,
        ..GlobalSettings::default()
    };
    let config = AppConfig {
        data_dir: "/srv/mailbackup/data".into(),
        db_path: "/srv/mailbackup/mailbackup.db".into(),
        settings,
        accounts: vec![live, archived, gmail],
    };
    std::fs::create_dir_all(dir).unwrap();
    config.save(&dir.join("config.yaml")).unwrap();
}
