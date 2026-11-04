//! Compatibility fixtures (issue #40): files written once by the pre-upgrade
//! code (see `compat_generate.rs` and `fixtures/compat/WRITER.json`) that every
//! later version must keep reading the same way. Tests work on copies and
//! never regenerate a fixture.
//!
//! These pin today's behaviour. A dependency upgrade (#41–#46) must pass them
//! unchanged; a deliberate behaviour change updates the assertion, never the
//! fixture.

mod compat;

use compat::*;
use mailbackup_core::config::AppConfig;
use mailbackup_core::db::{AdvancedSearchFilter, Database};
use mailbackup_core::error::{CredentialErrorKind as Kind, Error};
use mailbackup_core::keyring::{CredentialStore, NoKeyring, SecretBackend};
use mailbackup_core::server_ids::ServerIdKind;
use mailbackup_core::storage::StorageEngine;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

// --- Credential store: helpers --------------------------------------------

fn store_in(dir: &Path, keyring: Arc<dyn SecretBackend>) -> CredentialStore {
    CredentialStore::with_paths(dir.join(".credentials_store.json"), dir.join(".credentials_key"))
        .with_passphrase(None)
        .with_keyring(keyring)
}

/// The key-file scenario's store with its legacy `~/.mailbackup` location.
fn key_file_store(root: &Path, keyring: Arc<dyn SecretBackend>) -> CredentialStore {
    let home = root.join("home");
    store_in(&root.join("config"), keyring)
        .with_legacy_store(home.join(".credentials_store.json"), home.join(".credentials_key"))
}

fn kind(e: Error) -> Option<Kind> {
    e.credential_kind()
}

fn entry_names(store_file: &Path) -> BTreeSet<String> {
    read_json(store_file)["entries"].as_object().unwrap().keys().cloned().collect()
}

fn strings(v: &serde_json::Value) -> BTreeSet<String> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

/// Runs `op`, which must fail with `expected`, and checks every file in
/// `dir` is byte-for-byte as before.
fn fails_without_change<T: std::fmt::Debug>(dir: &Path, expected: Kind, op: impl FnOnce() -> mailbackup_core::Result<T>) {
    let before = snapshot_data_files(dir);
    let err = op().expect_err("must fail");
    assert_eq!(kind(err), Some(expected));
    assert_eq!(snapshot_data_files(dir), before, "a failed operation changed files");
}

// --- Credential store: key-file mode ---------------------------------------

#[test]
fn key_file_store_has_the_v2_envelope_and_entry_names() {
    let fx = fixtures_root().join("credentials").join("key-file");
    let expected = read_json(&fx.join("expected.json"));
    let file = read_json(&fx.join("config").join(".credentials_store.json"));
    assert_eq!(file["version"], 2);
    assert!(file["kdf"].is_null());
    assert!(file["check"].as_str().unwrap().starts_with("enc:v1:"));
    for value in file["entries"].as_object().unwrap().values() {
        assert!(value.as_str().unwrap().starts_with("enc:v1:"), "every value is encrypted");
    }
    assert_eq!(entry_names(&fx.join("config").join(".credentials_store.json")), strings(&expected["config_store_entries"]));
    assert_eq!(entry_names(&fx.join("home").join(".credentials_store.json")), strings(&expected["legacy_store_entries"]));
}

#[test]
fn key_file_store_reads_every_secret_and_enforces_bindings() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    let store = key_file_store(dir.path(), Arc::new(NoKeyring));

    assert_eq!(store.get_account_password(&live_account()).unwrap(), LIVE_PW);
    assert_eq!(store.get_account_password(&staged_account()).unwrap(), STAGED_PW);
    assert_eq!(store.get_password(PRE_BINDING_ID).unwrap(), PRE_BINDING_PW);
    assert_eq!(store.get_password(ADOPTED_ID).unwrap(), ADOPTED_PW);
    // Deleted by this config: the legacy location still holds it, but the
    // marker keeps it from coming back
    assert_eq!(kind(store.get_password(DELETED_ID).unwrap_err()), Some(Kind::NotFound));

    // The stored binding is checked, not re-created: another server is refused
    let mut moved = live_account();
    moved.imap_server = "elsewhere.example.test".to_string();
    assert!(matches!(store.get_account_password(&moved), Err(Error::CredentialMismatch(_))));
}

#[test]
fn key_file_store_update_survives_a_restart() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    let key_before = std::fs::read(dir.path().join("config").join(".credentials_key")).unwrap();
    {
        let store = key_file_store(dir.path(), Arc::new(NoKeyring));
        store.set_account_password(&live_account(), "synthetic-new-live-password").unwrap();
        // A password from before bindings is bound on first use
        let old = account(PRE_BINDING_ID, "old.example.test", "old@example.test", None);
        assert_eq!(store.get_account_password(&old).unwrap(), PRE_BINDING_PW);
    }

    let store = key_file_store(dir.path(), Arc::new(NoKeyring)); // "restart"
    assert_eq!(store.get_account_password(&live_account()).unwrap(), "synthetic-new-live-password");
    assert_eq!(store.get_account_password(&staged_account()).unwrap(), STAGED_PW);
    assert_eq!(store.get_password(ADOPTED_ID).unwrap(), ADOPTED_PW);
    assert_eq!(kind(store.get_password(DELETED_ID).unwrap_err()), Some(Kind::NotFound));
    let mut old_moved = account(PRE_BINDING_ID, "old.example.test", "old@example.test", None);
    old_moved.imap_port = 143;
    assert!(matches!(store.get_account_password(&old_moved), Err(Error::CredentialMismatch(_))));

    let file = read_json(&dir.path().join("config").join(".credentials_store.json"));
    assert_eq!(file["version"], 2);
    assert!(file["kdf"].is_null());
    assert_eq!(std::fs::read(dir.path().join("config").join(".credentials_key")).unwrap(), key_before, "same key");
}

#[test]
fn deleting_an_adopted_secret_removes_both_copies_for_good() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    key_file_store(dir.path(), Arc::new(NoKeyring)).delete_password(ADOPTED_ID).unwrap();

    let store = key_file_store(dir.path(), Arc::new(NoKeyring));
    assert_eq!(kind(store.get_password(ADOPTED_ID).unwrap_err()), Some(Kind::NotFound));
    // The copy this config made came from there, so the old location loses it
    // too; the other legacy entry stays
    let legacy = entry_names(&dir.path().join("home").join(".credentials_store.json"));
    assert_eq!(legacy, BTreeSet::from([format!("account:{}", DELETED_ID)]));
}

// --- Credential store: keyring mode ----------------------------------------

/// The fixture's keyring entries under the namespace of a store at `dir`.
fn fixture_keyring(store: &CredentialStore, fx: &Path) -> Arc<MemoryKeyring> {
    let entries = read_json(&fx.join("keyring.json"));
    Arc::new(MemoryKeyring::with(
        entries.as_object().unwrap().iter().map(|(k, v)| (store.keyring_key(k), v.as_str().unwrap().to_string())),
    ))
}

#[test]
fn keyring_store_reads_keyring_and_local_entries() {
    let fx = fixtures_root().join("credentials").join("keyring");
    let dir = copy_fixture(&fx);
    let probe = store_in(dir.path(), Arc::new(NoKeyring));
    let keyring = fixture_keyring(&probe, &fx);
    let store = store_in(dir.path(), keyring.clone());

    let kr_account = account(KEYRING_ID, "imap.example.test", "kr@example.test", None);
    assert_eq!(store.get_account_password(&kr_account).unwrap(), KEYRING_PW);
    assert_eq!(store.get_account_password(&live_account()).unwrap(), LIVE_PW);

    // What the background service sees: files only, no keyring
    let fresh = copy_fixture(&fx);
    let service = store_in(fresh.path(), Arc::new(NoKeyring)).with_disk_storage(true);
    assert_eq!(service.get_account_password(&live_account()).unwrap(), LIVE_PW);
}

#[test]
fn keyring_master_key_unlocks_the_store_without_the_key_file() {
    let fx = fixtures_root().join("credentials").join("keyring");
    let dir = copy_fixture(&fx);
    std::fs::remove_file(dir.path().join(".credentials_key")).unwrap();
    let probe = store_in(dir.path(), Arc::new(NoKeyring));
    let store = store_in(dir.path(), fixture_keyring(&probe, &fx)).with_disk_storage(true);
    assert_eq!(store.get_account_password(&live_account()).unwrap(), LIVE_PW);
}

#[test]
fn a_locked_keyring_is_an_error_never_an_older_credential() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    // Not in this config's local store; the legacy location has a copy
    let kr_dir = dir.path().join("kr");
    std::fs::create_dir_all(&kr_dir).unwrap();
    let home = dir.path().join("home");
    let store = store_in(&kr_dir, Arc::new(FailingKeyring(Kind::Locked)))
        .with_legacy_store(home.join(".credentials_store.json"), home.join(".credentials_key"));
    fails_without_change(dir.path(), Kind::Locked, || store.get_password(ADOPTED_ID));
}

#[test]
fn without_any_keyring_the_legacy_location_is_still_read() {
    // Current behaviour: "no keyring on this machine" (Unavailable) is not an
    // access failure, so the legacy location is consulted (and adopted)
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    let kr_dir = dir.path().join("kr");
    std::fs::create_dir_all(&kr_dir).unwrap();
    let home = dir.path().join("home");
    let store = store_in(&kr_dir, Arc::new(FailingKeyring(Kind::Unavailable)))
        .with_legacy_store(home.join(".credentials_store.json"), home.join(".credentials_key"));
    assert_eq!(store.get_password(ADOPTED_ID).unwrap(), ADOPTED_PW);
}

// --- Credential store: failures leave everything unchanged -------------------

#[test]
fn a_wrong_key_file_fails_and_changes_nothing() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    std::fs::write(dir.path().join("config").join(".credentials_key"), "11".repeat(32)).unwrap();
    let store = key_file_store(dir.path(), Arc::new(NoKeyring));
    fails_without_change(dir.path(), Kind::WrongKey, || store.get_password("acct-live"));
    fails_without_change(dir.path(), Kind::WrongKey, || store.set_password("acct-live", "x"));
    fails_without_change(dir.path(), Kind::WrongKey, || store.delete_password("acct-live"));
}

#[test]
fn a_missing_key_fails_and_no_new_key_replaces_it() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    std::fs::remove_file(dir.path().join("config").join(".credentials_key")).unwrap();
    let store = key_file_store(dir.path(), Arc::new(NoKeyring));
    fails_without_change(dir.path(), Kind::NoKey, || store.get_password("acct-live"));
    fails_without_change(dir.path(), Kind::NoKey, || store.set_password("acct-live", "x"));
    assert!(!dir.path().join("config").join(".credentials_key").exists());
}

#[test]
fn a_damaged_key_file_is_reported_not_replaced() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    std::fs::write(dir.path().join("config").join(".credentials_key"), "not a key").unwrap();
    let store = key_file_store(dir.path(), Arc::new(NoKeyring));
    fails_without_change(dir.path(), Kind::Corrupt, || store.get_password("acct-live"));
    fails_without_change(dir.path(), Kind::Corrupt, || store.set_password("acct-live", "x"));
}

#[test]
fn a_damaged_entry_fails_and_changes_nothing() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
    let path = dir.path().join("config").join(".credentials_store.json");
    let mut file = read_json(&path);
    let entry = file["entries"]["account:acct-live"].as_str().unwrap().to_string();
    let last = entry.chars().last().unwrap();
    let flipped = format!("{}{}", &entry[..entry.len() - 1], if last == '0' { '1' } else { '0' });
    file["entries"]["account:acct-live"] = serde_json::Value::String(flipped);
    write_json(&path, &file);

    let store = key_file_store(dir.path(), Arc::new(NoKeyring));
    // Any read or write needs the whole store, so even other entries fail
    fails_without_change(dir.path(), Kind::Corrupt, || store.get_password(PRE_BINDING_ID));
    fails_without_change(dir.path(), Kind::Corrupt, || store.set_password(PRE_BINDING_ID, "x"));
}

#[test]
fn an_unreadable_or_unknown_store_fails_and_changes_nothing() {
    for content in [&b"{ \"version\": 2, \"entr"[..], br#"{"version": 3, "kdf": null, "check": "", "entries": {}}"#, b"[1, 2]"] {
        let dir = copy_fixture(&fixtures_root().join("credentials").join("key-file"));
        std::fs::write(dir.path().join("config").join(".credentials_store.json"), content).unwrap();
        let store = key_file_store(dir.path(), Arc::new(NoKeyring));
        fails_without_change(dir.path(), Kind::Corrupt, || store.get_password("acct-live"));
        fails_without_change(dir.path(), Kind::Corrupt, || store.set_password("acct-live", "x"));
    }
}

// --- Credential store: passphrase (Argon2id) mode ---------------------------

fn passphrase_store(dir: &Path, passphrase: Option<&str>) -> CredentialStore {
    store_in(dir, Arc::new(NoKeyring)).with_passphrase(passphrase.map(str::to_string))
}

#[test]
fn passphrase_store_reads_updates_and_keeps_its_kdf() {
    let fx = fixtures_root().join("credentials").join("passphrase");
    let dir = copy_fixture(&fx);
    let kdf_before = read_json(&fx.join(".credentials_store.json"))["kdf"].clone();
    assert_eq!(kdf_before["alg"], "argon2id");
    assert_eq!(kdf_before["version"], 19);
    {
        let store = passphrase_store(dir.path(), Some(PASSPHRASE));
        assert_eq!(store.get_account_password(&live_account()).unwrap(), LIVE_PW);
        assert_eq!(store.get_account_password(&staged_account()).unwrap(), STAGED_PW);
        assert_eq!(store.get_password(PRE_BINDING_ID).unwrap(), PRE_BINDING_PW);
        store.set_password(PRE_BINDING_ID, "synthetic-new-old-password").unwrap();
    }
    let store = passphrase_store(dir.path(), Some(PASSPHRASE));
    assert_eq!(store.get_password(PRE_BINDING_ID).unwrap(), "synthetic-new-old-password");
    assert_eq!(store.get_account_password(&live_account()).unwrap(), LIVE_PW);
    assert_eq!(store.get_account_password(&staged_account()).unwrap(), STAGED_PW);
    // Same salt and parameters: no re-derivation, no key change
    assert_eq!(read_json(&dir.path().join(".credentials_store.json"))["kdf"], kdf_before);
}

#[test]
fn a_wrong_or_missing_passphrase_fails_and_changes_nothing() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("passphrase"));
    let wrong = passphrase_store(dir.path(), Some("not the passphrase"));
    fails_without_change(dir.path(), Kind::WrongKey, || wrong.get_password("acct-live"));
    fails_without_change(dir.path(), Kind::WrongKey, || wrong.set_password("acct-live", "x"));
    let none = passphrase_store(dir.path(), None);
    fails_without_change(dir.path(), Kind::NoKey, || none.get_password("acct-live"));
    fails_without_change(dir.path(), Kind::NoKey, || none.set_password("acct-live", "x"));
}

#[test]
fn invalid_or_excessive_kdf_parameters_fail_before_any_derivation() {
    let changes: [(&str, serde_json::Value); 9] = [
        ("m_cost", serde_json::json!(4_194_304u32)), // 4 GiB
        ("m_cost", serde_json::json!(u32::MAX)),
        ("m_cost", serde_json::json!(4)),
        ("t_cost", serde_json::json!(1_000)),
        ("t_cost", serde_json::json!(0)),
        ("p_cost", serde_json::json!(64)),
        ("alg", serde_json::json!("argon2i")),
        ("version", serde_json::json!(16)),
        ("salt", serde_json::json!("00")),
    ];
    for (field, value) in changes {
        let dir = copy_fixture(&fixtures_root().join("credentials").join("passphrase"));
        let path = dir.path().join(".credentials_store.json");
        let mut file = read_json(&path);
        file["kdf"][field] = value.clone();
        write_json(&path, &file);
        let store = passphrase_store(dir.path(), Some(PASSPHRASE));
        let started = std::time::Instant::now();
        fails_without_change(dir.path(), Kind::Corrupt, || store.get_password("acct-live"));
        // Rejected up front: a derivation with these settings would take far
        // longer (or allocate gigabytes)
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "{} = {} wasn't rejected up front", field, value);
    }
}

// --- Credential store: legacy formats --------------------------------------

#[test]
fn legacy_formats_are_read_and_upgraded_to_v2() {
    let legacy = fixtures_root().join("credentials").join("legacy");
    let cases: [(&str, Option<&str>, &str, &str); 4] = [
        ("plaintext", None, "acct-plain", "synthetic-plaintext-password"),
        ("key-file", None, "acct-l1", "synthetic-legacy-key-file-password"),
        ("key-file", None, "acct-l2", "synthetic-legacy-plain-in-encrypted-store"),
        ("sha256-passphrase-undotted", Some(PASSPHRASE), "acct-l3", "synthetic-legacy-passphrase-password"),
    ];
    for (name, passphrase, id, secret) in cases {
        let dir = copy_fixture(&legacy.join(name));
        let store = passphrase_store(dir.path(), passphrase);
        assert_eq!(store.get_password(id).unwrap(), secret, "{}", name);
        // Upgraded in place to a version 2 store; a restart reads it again
        let file = read_json(&dir.path().join(".credentials_store.json"));
        assert_eq!(file["version"], 2, "{}", name);
        assert_eq!(file["kdf"].is_null(), passphrase.is_none(), "{}", name);
        assert!(!dir.path().join("credentials_store.json").exists(), "{}: the undotted file is removed", name);
        assert_eq!(passphrase_store(dir.path(), passphrase).get_password(id).unwrap(), secret, "{}", name);
    }
}

#[test]
fn a_legacy_store_with_the_wrong_passphrase_is_left_alone() {
    let dir = copy_fixture(&fixtures_root().join("credentials").join("legacy").join("sha256-passphrase-undotted"));
    let store = passphrase_store(dir.path(), Some("not the passphrase"));
    fails_without_change(dir.path(), Kind::NoKey, || store.get_password("acct-l3"));
}

// --- Credential store: keyring namespace ------------------------------------

#[cfg(unix)]
#[test]
fn keyring_namespace_of_a_config_folder_is_unchanged() {
    let pinned = read_json(&fixtures_root().join("credentials").join("namespace.json"));
    let folder = Path::new(pinned["unix_store_folder"].as_str().unwrap());
    let store = CredentialStore::with_paths(folder.join(".credentials_store.json"), folder.join(".credentials_key"))
        .with_keyring(Arc::new(NoKeyring));
    assert_eq!(store.keyring_key("account:x"), pinned["keyring_key_of_account_x"].as_str().unwrap());
}

// --- Catalog -------------------------------------------------------------------

fn open_catalog() -> (tempfile::TempDir, Database, StorageEngine) {
    let dir = copy_fixture(&fixtures_root().join("catalog"));
    let db = Database::open(dir.path().join("mailbackup.db")).unwrap();
    let storage = StorageEngine::new(dir.path().join("data"));
    (dir, db, storage)
}

#[test]
fn catalog_opens_with_every_row_as_written() {
    let (dir, db, _) = open_catalog();
    drop(db); // opened (and schema-checked) by the current code
    let conn = rusqlite::Connection::open(dir.path().join("mailbackup.db")).unwrap();
    let now = compat::catalog::snapshot(&conn);
    let written = read_json(&fixtures_root().join("catalog").join("snapshot.json"));
    assert_eq!(now["user_version"], written["user_version"]);
    assert_eq!(now["schema"], written["schema"]);
    for (table, rows) in written["tables"].as_object().unwrap() {
        assert_eq!(&now["tables"][table], rows, "table {}", table);
    }
}

#[test]
fn catalog_keeps_generations_rebinds_and_id_state() {
    let (_dir, db, _) = open_catalog();
    let folders = db.get_folders("acct-live").unwrap();
    let inbox = folders.iter().find(|f| f.remote_name == "INBOX").unwrap();
    let archive = folders.iter().find(|f| f.remote_name == "Archive").unwrap();
    assert_eq!(inbox.uidvalidity, Some(200));
    assert_eq!(inbox.last_synced_uid, 14);

    // Same server and UIDVALIDITY again: no new generation
    let again = db.begin_folder_sync("acct-live", "INBOX", "INBOX", Some(200), IDENTITY).unwrap();
    assert_eq!(again.generation, 1);
    assert!(again.rescan_reason.is_none());
    assert!(!db.message_exists_in_generation(&inbox.id, 1, 4).unwrap(), "uid 4 stays in generation 0");
    assert!(db.message_exists_in_generation(&inbox.id, 0, 4).unwrap());
    for uid in [11, 12, 13, 14] {
        assert!(db.message_exists_in_generation(&inbox.id, 1, uid).unwrap(), "uid {} in generation 1", uid);
    }

    // The unverified re-bind by id (uid 12) still needs its check; the
    // verified one (13) doesn't
    let pending = db.pending_id_rebinds(&inbox.id).unwrap();
    assert_eq!(pending.iter().map(|p| p.uid).collect::<Vec<_>>(), vec![12]);
    assert!(db.server_id_distrusted("acct-live", IDENTITY, ServerIdKind::EmailId).unwrap());
    assert!(db.server_id_disabled("acct-live", IDENTITY, ServerIdKind::GmailMsgId).unwrap());
    assert!(!db.server_id_distrusted("acct-live", IDENTITY, ServerIdKind::GmailMsgId).unwrap());
    let states = db.server_id_states("acct-live").unwrap();
    assert_eq!(states.len(), 2);

    // Duplicate copies: m1 three times (INBOX twice, Archive once)
    let m1 = std::fs::read(fixtures_root().join("eml").join("m1.eml")).unwrap();
    let sha1 = StorageEngine::compute_sha256(&m1);
    let count = |folder: &str| db.get_messages_for_folder(folder).unwrap().iter().filter(|m| m.sha256_hash == sha1).count();
    assert_eq!(count(&inbox.id), 2);
    assert_eq!(count(&archive.id), 1);
    assert!(db.find_existing_message_by_hash(&sha1).unwrap().is_some());
}

#[test]
fn catalog_keeps_archive_transitions() {
    let (_dir, db, _) = open_catalog();
    // Finished: the old rows belong to the archive, the live account has new ones
    assert_eq!(db.last_transition_seq("acct-moved").unwrap(), 1);
    let archived = db.get_folders("acct-moved~archive-20261104-1").unwrap();
    assert_eq!(archived.len(), 1);
    assert_eq!(db.get_messages_for_folder(&archived[0].id).unwrap().len(), 1);
    let live = db.get_folders("acct-moved").unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].remote_identity.as_deref(), Some("new.example.test:993:moved@new.example.test"));

    // Outstanding: still prepared, for recovery to decide at startup
    let prepared = db.prepared_transitions().unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].live_id, "acct-pending");
    assert_eq!(prepared[0].archive_id, "acct-pending~archive-20261104-1");
    assert_eq!(prepared[0].old_credential_ref, "acct-pending");
    assert_eq!(prepared[0].staged_credential_ref, "acct-pending~cred-1");
}

#[test]
fn catalog_search_finds_text_and_attachments() {
    let (_dir, db, _) = open_catalog();
    let subjects = |q: &str| {
        let mut s: Vec<String> = db.search_fts(q, 50).unwrap().into_iter().map(|r| r.subject).collect();
        s.sort();
        s
    };
    assert_eq!(subjects("zebrafish").len(), 3);
    assert_eq!(subjects("quokka"), vec!["Grüße aus Köln".to_string(); 2]);
    let with_pdf = db
        .search_advanced(&AdvancedSearchFilter { attachment_name: Some("budget".to_string()), ..Default::default() })
        .unwrap();
    assert_eq!(with_pdf.len(), 2);
    assert!(with_pdf.iter().all(|r| r.subject == "Budget attached"));
}

#[test]
fn every_catalogued_file_is_present_and_intact() {
    let (dir, db, storage) = open_catalog();
    drop(db);
    let conn = rusqlite::Connection::open(dir.path().join("mailbackup.db")).unwrap();
    let mut stmt = conn.prepare("SELECT relative_path, sha256_hash, size_bytes FROM messages").unwrap();
    let rows: Vec<(String, String, i64)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect();
    assert_eq!(rows.len(), 9);
    for (path, sha, size) in rows {
        assert!(storage.verify_checksum(&path, &sha).unwrap(), "{}", path);
        assert_eq!(storage.read_eml(&path).unwrap().len() as i64, size, "{}", path);
    }
}

// --- Archived mail bytes -----------------------------------------------------

#[test]
fn archived_files_are_the_raw_bytes_received() {
    let eml = fixtures_root().join("eml");
    let data = fixtures_root().join("catalog").join("data");
    for (input, archived) in [
        ("m1", "acct-live/INBOX/2026/10/1_"),
        ("m2", "acct-live/INBOX/2026/10/2_"),
        ("m3", "acct-live/INBOX/2026/10/3_"),
        ("m5", "acct-live/INBOX/2026/11/14_g1_"),
    ] {
        let raw = std::fs::read(eml.join(format!("{}.eml", input))).unwrap();
        let sha = StorageEngine::compute_sha256(&raw);
        let path = data.join(format!("{}{}.eml", archived, &sha[..12]));
        assert_eq!(std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e)), raw, "{}", input);
    }
}

#[test]
fn storing_a_message_keeps_its_bytes_and_path_layout() {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageEngine::new(dir.path());
    let date = chrono::DateTime::parse_from_rfc3339("2026-10-06T09:15:00Z").unwrap().with_timezone(&chrono::Utc);
    for name in ["m1", "m2", "m3", "m5"] {
        let raw = std::fs::read(fixtures_root().join("eml").join(format!("{}.eml", name))).unwrap();
        let sha = StorageEngine::compute_sha256(&raw);
        for generation in [0, 2] {
            let stored = storage.store_eml_in_generation("acct", "[Gmail]/All Mail", 7, generation, Some(date), &raw).unwrap();
            let file = if generation == 0 { format!("7_{}.eml", &sha[..12]) } else { format!("7_g2_{}.eml", &sha[..12]) };
            let expected: std::path::PathBuf = ["acct", "Gmail_All_Mail", "2026", "10", &file].iter().collect();
            assert_eq!(stored.relative_path, expected, "{}", name);
            assert_eq!(stored.sha256, sha);
            assert_eq!(stored.size_bytes, raw.len() as u64);
            assert_eq!(storage.read_eml(&stored.relative_path).unwrap(), raw, "{} is stored byte for byte", name);
        }
    }
}

// --- Config --------------------------------------------------------------------

#[test]
fn config_round_trips_byte_for_byte() {
    let fixture = fixtures_root().join("config").join("config.yaml");
    let config = AppConfig::load_existing(&fixture).unwrap().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("config.yaml");
    config.save(&out).unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), std::fs::read_to_string(&fixture).unwrap());

    let live = config.get_account("acct-live").unwrap();
    assert_eq!(live.credential_ref(), "acct-live~cred-1");
    assert_eq!(live.storage_namespace(), "acct-live~1");
    assert!(live.trust_server_ids);
    let archived = config.get_account("acct-live~archive-20261104-1").unwrap();
    assert!(archived.is_archive());
    assert_eq!(archived.credential_ref(), "acct-live~archive-20261104-1");
    assert_eq!(archived.archive.as_ref().unwrap().last_source.as_deref(), Some(IDENTITY));
    assert_eq!(config.settings.log_retention_days, None);
    assert!(config.settings.autostart);
}

// --- Folder locations --------------------------------------------------------------

/// The config folder is `<home>/.mailbackup`, where `<home>` is what the OS
/// reports for the user (`$HOME` on Unix, the profile folder on Windows). A
/// `dirs` upgrade must not move it.
#[test]
fn default_config_location_follows_the_home_folder() {
    #[cfg(unix)]
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE").map(std::path::PathBuf::from);
    let Some(home) = home.filter(|h| !h.as_os_str().is_empty()) else { return };
    assert_eq!(mailbackup_core::config::default_base_dir(), home.join(".mailbackup"));
    assert_eq!(mailbackup_core::config::default_config_path(), home.join(".mailbackup").join("config.yaml"));
}
