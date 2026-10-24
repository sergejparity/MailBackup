use super::*;
use std::collections::HashMap;

/// In-memory keyring shared by every store built with it (survives "restarts").
#[derive(Default)]
struct MemoryKeyring(Mutex<HashMap<String, String>>);

impl SecretBackend for MemoryKeyring {
    fn get(&self, key: &str) -> Result<String> {
        self.0.lock().unwrap().get(key).cloned().ok_or_else(|| not_found(key))
    }
    fn set(&self, key: &str, secret: &str) -> Result<()> {
        self.0.lock().unwrap().insert(key.to_string(), secret.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key).map(|_| ()).ok_or_else(|| not_found(key))
    }
}

/// A keyring that fails every call with `kind`, except reads of `allow`.
struct FailingKeyring {
    kind: Kind,
    allow: HashMap<String, String>,
}

impl FailingKeyring {
    fn new(kind: Kind) -> Self {
        Self { kind, allow: HashMap::new() }
    }
    fn error(&self) -> Error {
        Error::credential(self.kind, "keyring says no")
    }
}

impl SecretBackend for FailingKeyring {
    fn get(&self, key: &str) -> Result<String> {
        self.allow.get(key).cloned().ok_or_else(|| self.error())
    }
    fn set(&self, _: &str, _: &str) -> Result<()> {
        Err(self.error())
    }
    fn delete(&self, _: &str) -> Result<()> {
        Err(self.error())
    }
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap() }
    }
    fn store_path(&self) -> PathBuf {
        self.dir.path().join(".credentials_store.json")
    }
    fn key_path(&self) -> PathBuf {
        self.dir.path().join(".credentials_key")
    }
    /// A store with no keyring (as on headless Linux) and no passphrase.
    fn store(&self) -> CredentialStore {
        self.store_with(Arc::new(FailingKeyring::new(Kind::Unavailable)))
    }
    fn store_with(&self, keyring: Arc<dyn SecretBackend>) -> CredentialStore {
        CredentialStore::with_paths(self.store_path(), self.key_path()).with_passphrase(None).with_keyring(keyring)
    }
    fn store_with_passphrase(&self, passphrase: &str) -> CredentialStore {
        self.store().with_passphrase(Some(passphrase.to_string()))
    }
    fn raw(&self) -> String {
        std::fs::read_to_string(self.store_path()).unwrap()
    }
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.raw()).unwrap()
    }
    fn write_raw(&self, value: &serde_json::Value) {
        std::fs::write(self.store_path(), serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
}

fn kind(result: Result<impl std::fmt::Debug>) -> Kind {
    result.unwrap_err().credential_kind().expect("a credential error")
}

#[test]
fn new_store_is_a_version_2_envelope_with_a_private_key_file() {
    let fx = Fixture::new();
    let store = fx.store();
    store.set_password("acc", "hunter2").unwrap();
    assert_eq!(store.get_password("acc").unwrap(), "hunter2");

    let json = fx.json();
    assert_eq!(json["version"], 2);
    assert!(json["kdf"].is_null());
    assert!(json["check"].as_str().unwrap().starts_with(ENC_PREFIX));
    assert!(json["entries"]["account:acc"].as_str().unwrap().starts_with(ENC_PREFIX));
    assert!(!fx.raw().contains("hunter2"));
    assert!(parse_key(&std::fs::read_to_string(fx.key_path()).unwrap()).is_some());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [fx.store_path(), fx.key_path()] {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
        }
    }

    // A new process with the same files reads it back
    assert_eq!(fx.store().get_password("acc").unwrap(), "hunter2");
}

#[test]
fn missing_secrets_and_missing_store_are_not_found() {
    let fx = Fixture::new();
    let store = fx.store();
    assert_eq!(kind(store.get_password("nobody")), Kind::NotFound);
    store.delete_password("nobody").unwrap();
    assert!(!fx.store_path().exists(), "deleting from no store must not create one");
    store.set_password("acc", "pw").unwrap();
    assert_eq!(kind(store.get_password("other")), Kind::NotFound);
}

#[test]
fn passphrase_store_uses_argon2id_and_no_key_file() {
    let fx = Fixture::new();
    fx.store_with_passphrase("correct horse").set_password("acc", "pw").unwrap();
    let kdf = &fx.json()["kdf"];
    assert_eq!(kdf["alg"], "argon2id");
    assert_eq!(kdf["version"], 0x13);
    assert_eq!(kdf["m_cost"], ARGON2_M_COST_KIB);
    assert_eq!(kdf["t_cost"], ARGON2_T_COST);
    assert_eq!(kdf["p_cost"], ARGON2_P_COST);
    assert_eq!(hex::decode(kdf["salt"].as_str().unwrap()).unwrap().len(), SALT_LEN);
    assert!(!fx.key_path().exists());

    let reopened = fx.store_with_passphrase("correct horse");
    assert_eq!(reopened.get_password("acc").unwrap(), "pw");
    reopened.set_password("acc2", "pw2").unwrap();
    assert_eq!(fx.json()["kdf"]["salt"], kdf["salt"], "the salt is kept across writes");
}

#[test]
fn wrong_or_missing_passphrase_leaves_the_store_untouched() {
    let fx = Fixture::new();
    fx.store_with_passphrase("right").set_password("acc", "pw").unwrap();
    let before = fx.raw();

    let wrong = fx.store_with_passphrase("wrong");
    assert_eq!(kind(wrong.get_password("acc")), Kind::WrongKey);
    assert_eq!(kind(wrong.set_password("acc", "evil")), Kind::WrongKey);
    assert_eq!(kind(wrong.delete_password("acc")), Kind::WrongKey);
    assert_eq!(kind(fx.store().get_password("acc")), Kind::NoKey);
    assert_eq!(kind(fx.store().set_password("x", "y")), Kind::NoKey);
    assert_eq!(fx.raw(), before);
    assert!(!fx.key_path().exists());
}

#[test]
fn adding_a_passphrase_rekeys_a_key_file_store_on_the_next_write() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    let protected = fx.store_with_passphrase("now with passphrase");
    assert_eq!(protected.get_password("acc").unwrap(), "pw");
    assert!(fx.json()["kdf"].is_null(), "reading doesn't rewrite");
    protected.set_password("acc2", "pw2").unwrap();
    assert_eq!(fx.json()["kdf"]["alg"], "argon2id");
    assert_eq!(protected.get_password("acc").unwrap(), "pw");
}

#[test]
fn out_of_range_kdf_parameters_are_rejected_before_deriving() {
    let fx = Fixture::new();
    fx.store_with_passphrase("pw").set_password("acc", "secret").unwrap();
    let original = fx.json();
    for (field, value) in [
        ("m_cost", serde_json::json!(4_194_304)), // 4 GiB
        ("m_cost", serde_json::json!(1)),
        ("t_cost", serde_json::json!(0)),
        ("t_cost", serde_json::json!(1000)),
        ("p_cost", serde_json::json!(64)),
        ("alg", serde_json::json!("argon2i")),
        ("version", serde_json::json!(16)),
        ("salt", serde_json::json!("abcd")),
        ("salt", serde_json::json!("zz".repeat(16))),
    ] {
        let mut tampered = original.clone();
        tampered["kdf"][field] = value.clone();
        fx.write_raw(&tampered);
        let store = fx.store_with_passphrase("pw");
        assert_eq!(kind(store.get_password("acc")), Kind::Corrupt, "{} = {}", field, value);
        assert_eq!(kind(store.set_password("acc", "x")), Kind::Corrupt);
        assert_eq!(fx.json(), tampered, "left unchanged");
    }
}

#[test]
fn damaged_stores_are_reported_and_never_overwritten() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    let good = fx.json();

    let mut tampered_entry = good.clone();
    let entry = tampered_entry["entries"]["account:acc"].as_str().unwrap().to_string();
    tampered_entry["entries"]["account:acc"] = serde_json::json!(format!("{}00", &entry[..entry.len() - 2]));
    let mut plaintext_entry = good.clone();
    plaintext_entry["entries"]["account:acc"] = serde_json::json!("plain");
    let mut newer = good.clone();
    newer["version"] = serde_json::json!(3);
    let mut no_entries = good.clone();
    no_entries.as_object_mut().unwrap().remove("entries");

    for broken in [tampered_entry, plaintext_entry, newer, no_entries, serde_json::json!([1, 2]), serde_json::json!({"a": 1})] {
        fx.write_raw(&broken);
        let store = fx.store();
        assert_eq!(kind(store.get_password("acc")), Kind::Corrupt, "{}", broken);
        assert_eq!(kind(store.set_password("new", "pw")), Kind::Corrupt);
        assert_eq!(kind(store.delete_password("acc")), Kind::Corrupt);
        assert_eq!(fx.json(), broken);
    }

    std::fs::write(fx.store_path(), b"{ not json").unwrap();
    assert_eq!(kind(fx.store().set_password("new", "pw")), Kind::Corrupt);
    assert_eq!(std::fs::read(fx.store_path()).unwrap(), b"{ not json");
}

#[test]
fn a_replaced_key_file_is_a_wrong_key_not_an_empty_store() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    let before = fx.raw();
    std::fs::write(fx.key_path(), hex::encode([7u8; 32])).unwrap();
    let store = fx.store();
    assert_eq!(kind(store.get_password("acc")), Kind::WrongKey);
    assert_eq!(kind(store.set_password("other", "pw")), Kind::WrongKey);
    assert_eq!(fx.raw(), before);
}

#[test]
fn a_damaged_or_missing_key_file_is_never_replaced() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    let before = fx.raw();

    std::fs::write(fx.key_path(), b"not a key").unwrap();
    assert_eq!(kind(fx.store().get_password("acc")), Kind::Corrupt);
    assert_eq!(kind(fx.store().set_password("acc", "x")), Kind::Corrupt);
    assert_eq!(std::fs::read(fx.key_path()).unwrap(), b"not a key");

    std::fs::remove_file(fx.key_path()).unwrap();
    assert_eq!(kind(fx.store().get_password("acc")), Kind::NoKey);
    assert_eq!(kind(fx.store().set_password("acc", "x")), Kind::NoKey);
    assert!(!fx.key_path().exists(), "no new key may orphan the existing store");
    assert_eq!(fx.raw(), before);
}

#[test]
fn a_locked_keyring_holding_the_key_blocks_instead_of_starting_over() {
    let fx = Fixture::new();
    let keyring = Arc::new(MemoryKeyring::default());
    fx.store_with(keyring.clone()).with_disk_storage(true).set_password("acc", "pw").unwrap();
    // The key lives only in the keyring now, and the keyring gets locked
    std::fs::remove_file(fx.key_path()).unwrap();
    let before = fx.raw();

    let locked = fx.store_with(Arc::new(FailingKeyring::new(Kind::Locked)));
    assert_eq!(kind(locked.get_password("acc")), Kind::Locked);
    assert_eq!(kind(locked.set_password("acc", "x")), Kind::Locked);
    assert!(!fx.key_path().exists());
    assert_eq!(fx.raw(), before);

    // Unlocked again: everything is there and writable with the same key
    let unlocked = fx.store_with(keyring.clone());
    assert_eq!(unlocked.get_password("acc").unwrap(), "pw");
    unlocked.set_password("acc2", "pw2").unwrap();
    assert_eq!(fx.store_with(keyring).get_password("acc2").unwrap(), "pw2");
}

#[test]
fn binding_is_only_created_when_certainly_missing() {
    let fx = Fixture::new();
    let mut account = crate::config::AccountConfig {
        id: "acc".into(),
        name: "A".into(),
        email: "a@example.com".into(),
        provider: crate::config::ProviderType::GenericImap,
        imap_server: "imap.example.com".into(),
        imap_port: 993,
        use_tls: true,
        username: "a".into(),
        auth_type: crate::config::AuthType::Password,
        schedule: None,
        retention_days: None,
        folder_filter: Default::default(),
        gmail_smart_labels: true,
        enabled: true,
        storage_namespace: None,
        credential_ref: None,
        archive: None,
    };
    // The password is readable, the binding sits in a locked keyring
    let mut keyring = FailingKeyring::new(Kind::Locked);
    keyring.allow.insert("account:acc".into(), "pw".into());
    let store = fx.store_with(Arc::new(keyring));
    assert_eq!(kind(store.get_account_password(&account)), Kind::Locked);
    assert!(!fx.store_path().exists(), "no binding was invented");

    // Certainly missing: bound on first use
    account.id = "acc2".into();
    let plain = fx.store();
    plain.set_password("acc2", "pw2").unwrap();
    assert_eq!(plain.get_account_password(&account).unwrap(), "pw2");
    assert!(fx.json()["entries"]["account:acc2:binding"].is_string());
}

fn legacy_store(_fx: &Fixture, key: Option<&[u8; 32]>, entries: &[(&str, &str)]) -> serde_json::Value {
    let map: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(k, v)| {
            let value = match key {
                Some(key) => encrypt_secret(v, key).unwrap(),
                None => v.to_string(),
            };
            (k.to_string(), serde_json::json!(value))
        })
        .collect();
    serde_json::Value::Object(map)
}

#[test]
fn legacy_store_with_its_key_file_is_upgraded_in_place() {
    let fx = Fixture::new();
    let key = [3u8; 32];
    std::fs::write(fx.key_path(), hex::encode(key)).unwrap();
    fx.write_raw(&legacy_store(&fx, Some(&key), &[("account:a", "pw-a"), ("account:b", "pw-b")]));

    let store = fx.store();
    assert_eq!(store.get_password("a").unwrap(), "pw-a");
    assert_eq!(fx.json()["version"], 2, "upgraded on first read");
    assert_eq!(std::fs::read_to_string(fx.key_path()).unwrap(), hex::encode(key), "same key kept");
    assert_eq!(fx.store().get_password("b").unwrap(), "pw-b");
}

#[test]
fn legacy_path_derived_key_is_read_once_and_replaced_by_a_real_key() {
    let fx = Fixture::new();
    let weak = legacy_path_key(&fx.key_path());
    fx.write_raw(&legacy_store(&fx, Some(&weak), &[("account:a", "pw-a")]));

    assert_eq!(fx.store().get_password("a").unwrap(), "pw-a");
    let json = fx.json();
    assert_eq!(json["version"], 2);
    let real = parse_key(&std::fs::read_to_string(fx.key_path()).unwrap()).unwrap();
    assert_ne!(real, weak);
    assert!(decrypt_secret(json["check"].as_str().unwrap(), &weak).is_err(), "never written with the weak key");
    assert_eq!(fx.store().get_password("a").unwrap(), "pw-a");
}

#[test]
fn legacy_sha256_passphrase_store_moves_to_argon2() {
    let fx = Fixture::new();
    let old = legacy_passphrase_key("my passphrase");
    fx.write_raw(&legacy_store(&fx, Some(&old), &[("account:a", "pw-a")]));

    let store = fx.store_with_passphrase("my passphrase");
    assert_eq!(store.get_password("a").unwrap(), "pw-a");
    let json = fx.json();
    assert_eq!(json["version"], 2);
    assert_eq!(json["kdf"]["alg"], "argon2id");
    assert!(decrypt_secret(json["check"].as_str().unwrap(), &old).is_err());
    assert!(!fx.key_path().exists());
    assert_eq!(fx.store_with_passphrase("my passphrase").get_password("a").unwrap(), "pw-a");
}

#[test]
fn legacy_keys_are_never_tried_on_a_version_2_store() {
    let fx = Fixture::new();
    // A version 2 store whose key is the old path-derived one, and no key file
    let weak = legacy_path_key(&fx.key_path());
    let file = serde_json::json!({
        "version": 2, "kdf": null,
        "check": encrypt_secret(CHECK_VALUE, &weak).unwrap(),
        "entries": { "account:a": encrypt_secret("pw", &weak).unwrap() },
    });
    fx.write_raw(&file);
    assert_eq!(kind(fx.store().get_password("a")), Kind::NoKey);
    std::fs::write(fx.key_path(), hex::encode([9u8; 32])).unwrap();
    assert_eq!(kind(fx.store().get_password("a")), Kind::WrongKey);

    // Same with a passphrase store and the old SHA-256 of the passphrase
    let fx = Fixture::new();
    let old = legacy_passphrase_key("pw");
    let mut kdf = serde_json::to_value(KdfParams::generate()).unwrap();
    kdf["m_cost"] = serde_json::json!(64);
    kdf["t_cost"] = serde_json::json!(1);
    fx.write_raw(&serde_json::json!({
        "version": 2, "kdf": kdf,
        "check": encrypt_secret(CHECK_VALUE, &old).unwrap(),
        "entries": {},
    }));
    let before = fx.raw();
    assert_eq!(kind(fx.store_with_passphrase("pw").set_password("a", "x")), Kind::WrongKey);
    assert_eq!(fx.raw(), before);
}

#[test]
fn legacy_store_with_no_matching_key_is_left_untouched() {
    let fx = Fixture::new();
    fx.write_raw(&legacy_store(&fx, Some(&[5u8; 32]), &[("account:a", "pw")]));
    let before = fx.raw();
    assert_eq!(kind(fx.store().get_password("a")), Kind::NoKey);
    std::fs::write(fx.key_path(), hex::encode([6u8; 32])).unwrap();
    assert_eq!(kind(fx.store().get_password("a")), Kind::WrongKey);
    assert_eq!(kind(fx.store().set_password("b", "x")), Kind::WrongKey);
    assert_eq!(fx.raw(), before);
}

#[test]
fn legacy_store_with_one_damaged_entry_is_left_untouched() {
    let fx = Fixture::new();
    let key = [3u8; 32];
    std::fs::write(fx.key_path(), hex::encode(key)).unwrap();
    let mut legacy = legacy_store(&fx, Some(&key), &[("account:a", "pw-a"), ("account:b", "pw-b")]);
    legacy["account:b"] = serde_json::json!(encrypt_secret("pw-b", &[4u8; 32]).unwrap());
    fx.write_raw(&legacy);
    assert_eq!(kind(fx.store().get_password("a")), Kind::Corrupt);
    assert_eq!(fx.json(), legacy);
}

#[test]
fn failed_migration_keeps_the_legacy_store_readable() {
    let fx = Fixture::new();
    // The key file can't be created: its folder is a regular file
    let blocker = fx.dir.path().join("blocker");
    std::fs::write(&blocker, b"").unwrap();
    let key_path = blocker.join(".credentials_key");
    let weak = legacy_path_key(&key_path);
    let legacy = legacy_store(&fx, Some(&weak), &[("account:a", "pw-a")]);
    fx.write_raw(&legacy);

    let store = CredentialStore::with_paths(fx.store_path(), key_path)
        .with_passphrase(None)
        .with_keyring(Arc::new(FailingKeyring::new(Kind::Unavailable)));
    assert_eq!(store.get_password("a").unwrap(), "pw-a", "still readable");
    assert_eq!(fx.json(), legacy, "left as it was");
    assert!(store.set_password("b", "x").is_err(), "no write with the weak key");
    assert_eq!(fx.json(), legacy);
}

#[test]
fn legacy_plaintext_and_undotted_files_are_migrated() {
    let fx = Fixture::new();
    let undotted = fx.dir.path().join("credentials_store.json");
    std::fs::write(&undotted, serde_json::to_vec(&serde_json::json!({"account:a": "clear"})).unwrap()).unwrap();
    let store = fx.store();
    assert_eq!(store.get_password("a").unwrap(), "clear");
    assert!(!undotted.exists());
    assert!(!fx.raw().contains("clear"));
    assert_eq!(fx.json()["version"], 2);
}

#[test]
fn an_interrupted_replacement_leaves_the_old_store_and_is_cleaned_up() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    // A crash between writing the temp file and renaming it
    // (named like `private_fs` temp files: ".<name>.<uuid>.tmp")
    let stray = fx.dir.path().join(format!("..credentials_store.json.{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&stray, b"{ half written").unwrap();
    assert_eq!(crate::private_fs::stale_temp_files(&fx.store_path()), vec![stray.clone()]);

    assert_eq!(fx.store().get_password("acc").unwrap(), "pw");
    fx.store().set_password("acc2", "pw2").unwrap();
    assert!(!stray.exists());
    assert_eq!(fx.store().get_password("acc").unwrap(), "pw");
    assert_eq!(fx.store().get_password("acc2").unwrap(), "pw2");
}

#[test]
fn verification_failure_keeps_the_old_file() {
    let fx = Fixture::new();
    std::fs::write(fx.store_path(), b"old").unwrap();
    let result = crate::private_fs::write_atomic_verified(&fx.store_path(), b"new", |_| {
        Err(std::io::Error::other("nope"))
    });
    assert!(result.is_err());
    assert_eq!(std::fs::read(fx.store_path()).unwrap(), b"old");
    assert!(crate::private_fs::stale_temp_files(&fx.store_path()).is_empty());
}

#[test]
fn concurrent_first_writes_share_one_key_and_lose_nothing() {
    let fx = Fixture::new();
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let (store_path, key_path) = (fx.store_path(), fx.key_path());
            std::thread::spawn(move || {
                // Each thread is its own "process": separate store objects
                let store = CredentialStore::with_paths(store_path, key_path)
                    .with_passphrase(None)
                    .with_keyring(Arc::new(FailingKeyring::new(Kind::Unavailable)));
                for round in 0..5 {
                    store.set_password(&format!("acc{}", i), &format!("pw{}-{}", i, round)).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let store = fx.store();
    for i in 0..8 {
        assert_eq!(store.get_password(&format!("acc{}", i)).unwrap(), format!("pw{}-4", i));
    }
    assert!(crate::private_fs::stale_temp_files(&fx.store_path()).is_empty());
}

#[test]
fn concurrent_key_creation_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    let results: Vec<_> = (0..8u8)
        .map(|i| {
            let path = path.clone();
            std::thread::spawn(move || crate::private_fs::create_new_atomic(&path, &[i; 64]))
        })
        .map(|t| t.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results.iter().all(|r| r.as_ref().map(|_| true).unwrap_or_else(|e| e.kind() == std::io::ErrorKind::AlreadyExists)));
    let content = std::fs::read(&path).unwrap();
    assert_eq!(content.len(), 64, "never partially written");
    assert!(content.iter().all(|b| *b == content[0]));
}

#[test]
fn keyring_primary_storage_survives_a_restart() {
    let fx = Fixture::new();
    let keyring = Arc::new(MemoryKeyring::default());
    let store = fx.store_with(keyring.clone());
    store.set_password("acc", "pw").unwrap();
    assert_eq!(keyring.get(&fx.store().keyring_key("account:acc")).unwrap(), "pw");
    assert!(!fx.store_path().exists(), "nothing on disk while the keyring works");

    // "Restart": a new store object over the same keyring and files
    let restarted = fx.store_with(keyring.clone());
    assert_eq!(restarted.get_password("acc").unwrap(), "pw");
    restarted.delete_password("acc").unwrap();
    assert_eq!(kind(keyring.get(&fx.store().keyring_key("account:acc"))), Kind::NotFound);
    assert_eq!(kind(fx.store().get_password("acc")), Kind::NotFound);
}

#[test]
fn delete_keeps_the_keyring_copy_when_the_store_cannot_be_updated() {
    let fx = Fixture::new();
    let keyring = Arc::new(MemoryKeyring::default());
    let store = fx.store_with(keyring.clone());
    store.set_password("acc", "pw").unwrap();
    std::fs::write(fx.store_path(), b"{ damaged").unwrap();

    assert_eq!(kind(store.delete_password("acc")), Kind::Corrupt);
    assert_eq!(keyring.get(&fx.store().keyring_key("account:acc")).unwrap(), "pw", "the only readable copy survives");
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_lock_path_is_not_followed() {
    let fx = Fixture::new();
    let victim = fx.dir.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, fx.dir.path().join(".credentials_store.json.lock")).unwrap();

    assert!(fx.store().set_password("acc", "pw").is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    assert!(!fx.store_path().exists());
}

#[test]
fn saving_an_unchanged_password_still_applies_a_new_passphrase() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    let protected = fx.store_with_passphrase("now with passphrase");
    protected.set_password("acc", "pw").unwrap();
    assert_eq!(fx.json()["kdf"]["alg"], "argon2id");
    assert_eq!(kind(fx.store().get_password("acc")), Kind::NoKey, "the key file alone no longer opens it");
    assert_eq!(protected.get_password("acc").unwrap(), "pw");

    // Without a pending rekey, an unchanged save doesn't rewrite the file
    let before = fx.raw();
    protected.set_password("acc", "pw").unwrap();
    assert_eq!(fx.raw(), before);
}

// ---------------------------------------------------------------------------
// Keyring-primary storage and service transitions
// ---------------------------------------------------------------------------

/// A persistent fake keyring shared by every store built with it, whose state
/// can be switched: working, unavailable, locked, read-only (sets fail) or
/// returning wrong values.
#[derive(Default)]
struct FakeKeyring {
    /// The fixture store's keyring namespace, added by `seed` and `raw`.
    prefix: String,
    entries: Mutex<HashMap<String, String>>,
    fail: Mutex<Option<Kind>>,
    sets_fail: std::sync::atomic::AtomicBool,
    wrong_reads: std::sync::atomic::AtomicBool,
}

impl FakeKeyring {
    fn seed(&self, key: &str, value: &str) {
        self.entries.lock().unwrap().insert(format!("{}{}", self.prefix, key), value.to_string());
    }
    fn set_state(&self, fail: Option<Kind>) {
        *self.fail.lock().unwrap() = fail;
    }
    fn raw(&self, key: &str) -> Option<String> {
        self.entries.lock().unwrap().get(&format!("{}{}", self.prefix, key)).cloned()
    }
    fn check(&self) -> Result<()> {
        match *self.fail.lock().unwrap() {
            Some(kind) => Err(Error::credential(kind, format!("fake keyring is {:?}", kind))),
            None => Ok(()),
        }
    }
}

impl SecretBackend for FakeKeyring {
    fn get(&self, key: &str) -> Result<String> {
        self.check()?;
        let value = self.entries.lock().unwrap().get(key).cloned().ok_or_else(|| not_found(key))?;
        if self.wrong_reads.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(format!("{}-garbled", value));
        }
        Ok(value)
    }
    fn set(&self, key: &str, secret: &str) -> Result<()> {
        self.check()?;
        if self.sets_fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::credential(Kind::Unavailable, "fake keyring refuses writes"));
        }
        self.entries.lock().unwrap().insert(key.to_string(), secret.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.check()?;
        self.entries.lock().unwrap().remove(key).map(|_| ()).ok_or_else(|| not_found(key))
    }
}

impl Fixture {
    /// A fake keyring holding `entries` (secret keys, namespaced like this
    /// fixture's store does).
    fn fake(&self, entries: &[(&str, &str)]) -> Arc<FakeKeyring> {
        let fake = FakeKeyring { prefix: self.store().keyring_key(""), ..Default::default() };
        for (k, v) in entries {
            fake.seed(k, v);
        }
        Arc::new(fake)
    }

    /// The local entries as the background service would read them.
    fn local(&self) -> BTreeMap<String, String> {
        let reader = CredentialStore::with_paths(self.store_path(), self.key_path())
            .with_passphrase(None)
            .with_keyring(Arc::new(NoKeyring));
        let _lock = reader.lock().unwrap();
        reader.load().unwrap().map(|l| l.entries).unwrap_or_default()
    }
    fn service_reader(&self) -> CredentialStore {
        self.store_with(Arc::new(NoKeyring)).with_disk_storage(true)
    }
}

#[test]
fn local_secrets_move_into_a_working_keyring_on_first_use() {
    let fx = Fixture::new();
    // Saved while there was no keyring (or by an older version)
    fx.store().set_password("acc", "pw").unwrap();
    assert_eq!(fx.local().get("account:acc").map(String::as_str), Some("pw"));

    let keyring = fx.fake(&[]);
    assert_eq!(fx.store_with(keyring.clone()).get_password("acc").unwrap(), "pw");
    assert_eq!(keyring.raw("account:acc").as_deref(), Some("pw"));
    assert!(!fx.local().contains_key("account:acc"), "removed locally after the verified move");
    // A restarted process finds it in the keyring
    assert_eq!(fx.store_with(keyring).get_password("acc").unwrap(), "pw");
}

#[test]
fn a_move_that_does_not_read_back_keeps_the_local_copy() {
    let fx = Fixture::new();
    fx.store().set_password("acc", "pw").unwrap();
    let keyring = fx.fake(&[]);
    keyring.wrong_reads.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(fx.store_with(keyring).get_password("acc").unwrap(), "pw");
    assert_eq!(fx.local().get("account:acc").map(String::as_str), Some("pw"));
}

#[test]
fn unavailable_keyring_falls_back_to_the_local_store() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[]);
    keyring.set_state(Some(Kind::Unavailable));
    let store = fx.store_with(keyring.clone());
    store.set_password("acc", "pw").unwrap();
    assert_eq!(fx.local().get("account:acc").map(String::as_str), Some("pw"));
    assert_eq!(store.get_password("acc").unwrap(), "pw");

    // Once a keyring shows up, a save goes there and drops the local copy
    keyring.set_state(None);
    store.set_password("acc", "pw2").unwrap();
    assert_eq!(keyring.raw("account:acc").as_deref(), Some("pw2"));
    assert!(!fx.local().contains_key("account:acc"));
}

#[test]
fn locked_keyring_is_never_bypassed_by_writing_to_disk() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[("account:acc", "pw")]);
    keyring.set_state(Some(Kind::Locked));
    let store = fx.store_with(keyring.clone());
    assert_eq!(kind(store.set_password("acc", "new")), Kind::Locked);
    assert!(!fx.store_path().exists(), "nothing written to disk");
    assert_eq!(kind(store.get_password("acc")), Kind::Locked, "locked, not 'not found'");
    assert_eq!(kind(store.delete_password("acc")), Kind::Locked);

    keyring.set_state(None);
    assert_eq!(store.get_password("acc").unwrap(), "pw");
}

#[test]
fn disk_storage_reads_and_writes_the_local_store_first() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[("account:acc", "old")]);
    let store = fx.store_with(keyring.clone()).with_disk_storage(true);
    store.set_password("acc", "new").unwrap();
    assert_eq!(keyring.raw("account:acc").as_deref(), Some("old"), "keyring untouched");
    assert_eq!(store.get_password("acc").unwrap(), "new", "the disk copy wins");
    // Not on disk yet: the keyring still answers
    keyring.seed("account:other", "k");
    assert_eq!(store.get_password("other").unwrap(), "k");
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn enabling_the_service_copies_and_verifies_before_installing() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[
        ("account:a", "pw-a"),
        ("account:a:binding", "bind-a"),
        ("account:b", "pw-b"),
    ]);
    let store = fx.store_with(keyring.clone());
    let mut installed = false;
    let change = store
        .switch_to_disk_storage(&ids(&["a", "b", "c"]), || {
            // Everything is on disk before the service exists
            let local = fx.local();
            assert_eq!(local.get("account:a").map(String::as_str), Some("pw-a"));
            assert_eq!(local.get("account:b").map(String::as_str), Some("pw-b"));
            installed = true;
            Ok(())
        }, || true)
        .unwrap();
    assert!(installed);
    assert!(store.disk_storage());
    assert_eq!(change.skipped_accounts, ids(&["c"]));
    assert_eq!(fx.local().get("account:a:binding").map(String::as_str), Some("bind-a"));

    // The service process: no keyring, files only, after a "reboot"
    let service = fx.service_reader();
    assert_eq!(service.get_password("a").unwrap(), "pw-a");
    assert_eq!(service.get_password("b").unwrap(), "pw-b");
}

#[test]
fn a_failed_install_rolls_back_without_losing_the_only_copy() {
    let fx = Fixture::new();
    // "local" exists only on disk; the keyring can't take it
    fx.store().set_password("local", "pw-local").unwrap();
    let keyring = fx.fake(&[("account:a", "pw-a")]);
    keyring.sets_fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let store = fx.store_with(keyring.clone());

    let err = store
        .switch_to_disk_storage(&ids(&["a", "local"]), || Err(Error::Other("pkexec dismissed".into())), || true)
        .unwrap_err();
    assert_eq!(err.to_string(), "Generic error: pkexec dismissed");
    assert!(!store.disk_storage());
    let local = fx.local();
    assert!(!local.contains_key("account:a"), "copy of a keyring secret removed");
    assert_eq!(local.get("account:local").map(String::as_str), Some("pw-local"), "only copy kept");
    assert_eq!(keyring.raw("account:a").as_deref(), Some("pw-a"));
}

#[test]
fn enabling_the_service_is_refused_without_changes_when_secrets_cannot_be_read() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[("account:a", "pw-a")]);
    keyring.set_state(Some(Kind::Locked));
    let mut called = false;
    let err = fx.store_with(keyring).switch_to_disk_storage(&ids(&["a"]), || {
        called = true;
        Ok(())
    }, || true);
    assert_eq!(kind(err), Kind::Locked);
    assert!(!called && !fx.store_path().exists());

    // A passphrase store can't be opened by the service
    let mut called = false;
    let err = fx.store_with_passphrase("pw").switch_to_disk_storage(&ids(&["a"]), || {
        called = true;
        Ok(())
    }, || true);
    assert_eq!(kind(err), Kind::NoKey);
    assert!(!called);
}

#[test]
fn disabling_the_service_moves_verified_secrets_back_into_the_keyring() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[("account:a", "pw-a"), ("account:a:binding", "bind-a")]);
    let store = fx.store_with(keyring.clone());
    store.switch_to_disk_storage(&ids(&["a"]), || Ok(()), || true).unwrap();
    // Changed while the service ran: only on disk
    store.set_password("a", "pw-a2").unwrap();
    keyring.entries.lock().unwrap().clear();

    let mut uninstalled = false;
    let moved = store
        .switch_to_keyring_storage(
            || {
                uninstalled = true;
                Ok(())
            },
            || false,
        )
        .unwrap();
    assert!(uninstalled && !store.disk_storage());
    assert_eq!(moved.moved, ids(&["account:a", "account:a:binding"]));
    assert!(moved.kept.is_empty());
    assert_eq!(keyring.raw("account:a").as_deref(), Some("pw-a2"));
    assert!(fx.local().is_empty());
    assert_eq!(fx.store_with(keyring).get_password("a").unwrap(), "pw-a2");
}

#[test]
fn disabling_keeps_disk_secrets_the_keyring_cannot_take() {
    for state in [Some(Kind::Unavailable), Some(Kind::Locked), None] {
        let fx = Fixture::new();
        fx.store().with_disk_storage(true).set_password("a", "pw-a").unwrap();
        let keyring = fx.fake(&[]);
        keyring.set_state(state);
        // With a working keyring, make the read-back disagree
        keyring.wrong_reads.store(state.is_none(), std::sync::atomic::Ordering::SeqCst);
        let store = fx.store_with(keyring).with_disk_storage(true);
        let moved = store.switch_to_keyring_storage(|| Ok(()), || false).unwrap();
        assert!(moved.moved.is_empty(), "{:?}", state);
        assert_eq!(moved.kept, ids(&["account:a"]));
        assert_eq!(moved.reason.is_some(), state.is_some());
        assert_eq!(fx.local().get("account:a").map(String::as_str), Some("pw-a"));
        // Still readable afterwards
        assert_eq!(fx.service_reader().get_password("a").unwrap(), "pw-a");
    }
}

#[test]
fn disabling_stops_while_the_service_is_still_installed() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[("account:a", "pw-a")]);
    let store = fx.store_with(keyring.clone());
    store.switch_to_disk_storage(&ids(&["a"]), || Ok(()), || true).unwrap();
    keyring.entries.lock().unwrap().clear();

    let err = store.switch_to_keyring_storage(|| Ok(()), || true).unwrap_err();
    assert!(err.to_string().contains("still installed"));
    assert!(store.disk_storage());
    assert_eq!(fx.local().get("account:a").map(String::as_str), Some("pw-a"));
    assert!(keyring.raw("account:a").is_none());

    let err = store.switch_to_keyring_storage(|| Err(Error::Other("denied".into())), || false).unwrap_err();
    assert!(err.to_string().contains("denied"));
    assert!(store.disk_storage());
}

#[test]
fn legacy_location_is_read_migrated_and_cleaned_on_delete() {
    let fx = Fixture::new();
    let legacy_dir = fx.dir.path().join("home/.mailbackup");
    let legacy = CredentialStore::with_paths(legacy_dir.join(".credentials_store.json"), legacy_dir.join(".credentials_key"))
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring));
    legacy.set_password("custom", "pw-custom").unwrap();
    legacy.set_password("default", "pw-default").unwrap();

    let store = fx
        .store()
        .with_legacy_store(legacy_dir.join(".credentials_store.json"), legacy_dir.join(".credentials_key"));
    assert_eq!(store.get_password("custom").unwrap(), "pw-custom");
    assert_eq!(fx.local().get("account:custom").map(String::as_str), Some("pw-custom"), "copied to the config's store");
    assert_eq!(legacy.get_password("custom").unwrap(), "pw-custom", "the old copy is preserved");

    store.delete_password("custom").unwrap();
    assert_eq!(kind(store.get_password("custom")), Kind::NotFound, "doesn't come back from the legacy store");
    assert_eq!(legacy.get_password("default").unwrap(), "pw-default", "other entries untouched");

    // The default config's own password for an id this config also uses (a
    // different value) survives a delete here
    legacy.set_password("shared", "default-config-pw").unwrap();
    store.set_password("shared", "custom-config-pw").unwrap();
    store.delete_password("shared").unwrap();
    assert_eq!(legacy.get_password("shared").unwrap(), "default-config-pw");
}

#[test]
fn every_process_resolves_a_config_to_the_same_store() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("custom/config.yaml");
    let (store, key) = CredentialStore::paths_for_config(&config);
    let real = std::fs::canonicalize(tmp.path()).unwrap();
    assert_eq!(store, real.join("custom/.credentials_store.json"), "not created yet: resolved like it will be");
    assert_eq!(key, real.join("custom/.credentials_key"));
    std::fs::create_dir_all(tmp.path().join("custom")).unwrap();
    assert_eq!(CredentialStore::paths_for_config(&config).0, store);
    #[cfg(unix)]
    {
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(tmp.path().join("custom"), &link).unwrap();
        assert_eq!(CredentialStore::paths_for_config(&link.join("config.yaml")).0, store, "a symlinked folder");
    }

    // A relative --config from the config's folder resolves identically
    let cwd = std::env::current_dir().unwrap();
    let relative = pathdiff(&config, &cwd);
    assert_eq!(CredentialStore::paths_for_config(&relative).0, store);

    let settings = crate::config::GlobalSettings { run_as_service: true, ..Default::default() };
    let resolved = CredentialStore::for_config(&config, &settings);
    assert_eq!(resolved.store_paths().0, store.as_path());
    assert!(resolved.disk_storage(), "follows run_as_service");
    assert!(!CredentialStore::for_config(&config, &Default::default()).disk_storage());
}

/// `path` relative to `base` (both absolute), via `..` components.
fn pathdiff(path: &Path, base: &Path) -> PathBuf {
    let path: Vec<_> = path.components().collect();
    let base: Vec<_> = base.components().collect();
    let common = path.iter().zip(&base).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in common..base.len() {
        out.push("..");
    }
    for c in &path[common..] {
        out.push(c.as_os_str());
    }
    out
}

#[test]
fn configs_sharing_a_keyring_never_share_entries() {
    let (a, b) = (Fixture::new(), Fixture::new());
    let keyring = Arc::new(FakeKeyring::default());
    let store_a = a.store_with(keyring.clone());
    let store_b = b.store_with(keyring.clone());
    assert_ne!(store_a.keyring_key("account:acc"), store_b.keyring_key("account:acc"));

    store_a.set_password("acc", "pw-a").unwrap();
    store_b.set_password("acc", "pw-b").unwrap();
    assert_eq!(store_a.get_password("acc").unwrap(), "pw-a");
    store_b.delete_password("acc").unwrap();
    assert_eq!(store_a.get_password("acc").unwrap(), "pw-a", "deleting in B leaves A alone");
    assert_eq!(keyring.entries.lock().unwrap().len(), 1);
}

#[test]
fn every_process_uses_the_same_keyring_namespace_for_a_config() {
    let fx = Fixture::new();
    let config = fx.dir.path().join("config.yaml");
    let resolved = CredentialStore::for_config(&config, &Default::default());
    assert_eq!(resolved.keyring_key("account:x"), fx.store().keyring_key("account:x"));
}

#[test]
fn a_newer_disk_password_stays_authoritative_until_it_reaches_the_keyring() {
    let fx = Fixture::new();
    // The keyring still has the password from before the service was enabled
    let keyring = fx.fake(&[("account:a", "old")]);
    let store = fx.store_with(keyring.clone());
    store.switch_to_disk_storage(&ids(&["a"]), || Ok(()), || true).unwrap();
    store.set_password("a", "new").unwrap();
    assert_eq!(keyring.raw("account:a").as_deref(), Some("old"));

    // Disabling can't write to the keyring: the newer password stays on disk
    keyring.sets_fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let moved = store.switch_to_keyring_storage(|| Ok(()), || false).unwrap();
    assert_eq!(moved.kept, ids(&["account:a"]));
    assert_eq!(store.get_password("a").unwrap(), "new", "not the stale keyring value");
    // Also after a restart without disk storage
    assert_eq!(fx.store_with(keyring.clone()).get_password("a").unwrap(), "new");

    // Locked for a while: still the disk value
    keyring.set_state(Some(Kind::Locked));
    assert_eq!(fx.store_with(keyring.clone()).get_password("a").unwrap(), "new");

    // Once the keyring takes writes again, the next read moves it there
    keyring.set_state(None);
    keyring.sets_fail.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(fx.store_with(keyring.clone()).get_password("a").unwrap(), "new");
    assert_eq!(keyring.raw("account:a").as_deref(), Some("new"));
    assert!(!fx.local().contains_key("account:a"));
}

#[test]
fn a_deleted_legacy_password_does_not_come_back_with_a_working_keyring() {
    let fx = Fixture::new();
    let legacy_dir = fx.dir.path().join("home/.mailbackup");
    let (legacy_store, legacy_key) = (legacy_dir.join(".credentials_store.json"), legacy_dir.join(".credentials_key"));
    let legacy = CredentialStore::with_paths(legacy_store.clone(), legacy_key.clone())
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring));
    legacy.set_password("custom", "pw-custom").unwrap();
    legacy.set_password("other", "pw-other").unwrap();

    let keyring = fx.fake(&[]);
    let store = || fx.store_with(keyring.clone()).with_legacy_store(legacy_store.clone(), legacy_key.clone());
    assert_eq!(store().get_password("custom").unwrap(), "pw-custom");
    assert_eq!(keyring.raw("account:custom").as_deref(), Some("pw-custom"), "moved into the keyring");
    assert!(!fx.local().contains_key("account:custom"));

    store().delete_password("custom").unwrap();
    assert_eq!(kind(store().get_password("custom")), Kind::NotFound, "not resurrected");
    assert!(legacy.get_password("custom").is_err(), "the migrated copy is gone from the old location");
    assert_eq!(legacy.get_password("other").unwrap(), "pw-other");

    // An independent value in the old location (another config's) is never
    // deleted, but isn't read again for a secret this config deleted either
    legacy.set_password("custom", "default-config-pw").unwrap();
    assert_eq!(kind(store().get_password("custom")), Kind::NotFound);
    assert_eq!(legacy.get_password("custom").unwrap(), "default-config-pw");
    // Saving a new password for it works as usual
    store().set_password("custom", "fresh").unwrap();
    assert_eq!(store().get_password("custom").unwrap(), "fresh");
}

#[test]
fn bookkeeping_entries_stay_out_of_the_keyring() {
    let fx = Fixture::new();
    let legacy_dir = fx.dir.path().join("legacy");
    let legacy = CredentialStore::with_paths(legacy_dir.join(".credentials_store.json"), legacy_dir.join(".credentials_key"))
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring));
    legacy.set_password("x", "pw").unwrap();
    let keyring = fx.fake(&[]);
    keyring.set_state(Some(Kind::Unavailable));
    let store = fx
        .store_with(keyring.clone())
        .with_disk_storage(true)
        .with_legacy_store(legacy_dir.join(".credentials_store.json"), legacy_dir.join(".credentials_key"));
    assert_eq!(store.get_password("x").unwrap(), "pw");
    assert!(fx.local().keys().any(|k| k.starts_with(META_PREFIX)));

    keyring.set_state(None);
    let moved = store.switch_to_keyring_storage(|| Ok(()), || false).unwrap();
    assert_eq!(moved.moved, ids(&["account:x"]));
    assert!(keyring.entries.lock().unwrap().keys().all(|k| !k.contains(META_PREFIX)));
}

#[test]
fn a_partly_installed_service_keeps_its_disk_passwords() {
    let fx = Fixture::new();
    let keyring = fx.fake(&[("account:a", "pw-a")]);
    let store = fx.store_with(keyring.clone());
    let mut removal_tried = false;
    // The service got registered, then starting it failed and it couldn't be removed
    let err = store
        .switch_to_disk_storage(
            &ids(&["a"]),
            || Err(Error::Other("restart authorization dismissed".into())),
            || {
                removal_tried = true;
                false
            },
        )
        .unwrap_err();
    assert!(removal_tried);
    assert!(err.to_string().contains("may still be installed"), "{}", err);
    assert!(store.disk_storage(), "the remaining service must still find its passwords");
    assert_eq!(fx.local().get("account:a").map(String::as_str), Some("pw-a"));
    assert_eq!(fx.service_reader().get_password("a").unwrap(), "pw-a");

    // Removed after all: disk storage and the copies are undone
    let store = fx.store_with(keyring);
    let err = store
        .switch_to_disk_storage(&ids(&["a"]), || Err(Error::Other("failed".into())), || true)
        .unwrap_err();
    assert_eq!(err.to_string(), "Generic error: failed");
    assert!(!store.disk_storage());
}
