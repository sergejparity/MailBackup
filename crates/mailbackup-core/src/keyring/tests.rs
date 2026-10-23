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
    fx.store_with(keyring.clone()).set_password("acc", "pw").unwrap();
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
fn keyring_copy_and_restart_with_a_shared_keyring() {
    let fx = Fixture::new();
    let keyring = Arc::new(MemoryKeyring::default());
    let store = fx.store_with(keyring.clone());
    store.set_password("acc", "pw").unwrap();
    assert_eq!(keyring.get("account:acc").unwrap(), "pw");
    assert!(keyring.get(MASTER_KEY_ENTRY).is_ok());

    // "Restart": a new store object over the same keyring and files
    let restarted = fx.store_with(keyring.clone());
    assert_eq!(restarted.get_password("acc").unwrap(), "pw");
    restarted.delete_password("acc").unwrap();
    assert_eq!(kind(keyring.get("account:acc")), Kind::NotFound);
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
    assert_eq!(keyring.get("account:acc").unwrap(), "pw", "the only readable copy survives");
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
