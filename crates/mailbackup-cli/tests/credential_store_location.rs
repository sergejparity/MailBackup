//! The CLI, the server and the background service resolve a custom
//! `--config` to the same credential store, and credentials an older CLI kept
//! in `~/.mailbackup` for that config are still found.

use mailbackup_core::config::{AppConfig, GlobalSettings};
use mailbackup_core::keyring::{CredentialStore, NoKeyring};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

fn cli(home: &Path, cwd: &Path, args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_mailbackup"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("MAILBACKUP_KEYRING", "none")
        .env_remove("MAILBACKUP_MASTER_KEY")
        .env_remove("MAILBACKUP_ENCRYPTION_KEY")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}\n{}", args, String::from_utf8_lossy(&output.stderr));
}

fn add_args<'a>(config: &'a str, id: &'a str, password: &'a str) -> Vec<&'a str> {
    vec![
        "--config", config, "account", "add", "--id", id, "--name", id, "--email", "user@example.com",
        "--provider", "generic", "--server", "imap.example.com", "--port", "993", "--username", "user",
        "--password", password, "--retention-days", "30",
    ]
}

/// The store as the server (and the service, which is the server started with
/// `--config <same path>`) opens it.
fn server_view(config_path: &Path, run_as_service: bool) -> CredentialStore {
    let settings = GlobalSettings { run_as_service, ..Default::default() };
    CredentialStore::for_config(config_path, &settings).with_passphrase(None).with_keyring(Arc::new(NoKeyring))
}

#[test]
fn cli_server_and_service_share_the_store_of_a_custom_config() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let custom = tmp.path().join("work/custom");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&custom).unwrap();
    let config_path = custom.join("config.yaml");

    // Absolute --config, then a relative one from another folder
    cli(&home, tmp.path(), &add_args(config_path.to_str().unwrap(), "abs", "pw-abs"));
    cli(&home, &tmp.path().join("work"), &add_args("custom/config.yaml", "rel", "pw-rel"));

    assert!(custom.join(".credentials_store.json").exists(), "stored next to the config");
    assert!(!home.join(".mailbackup/.credentials_store.json").exists(), "not in ~/.mailbackup");

    let config = AppConfig::load_or_create(Some(&config_path)).unwrap();
    for run_as_service in [false, true] {
        let store = server_view(&config_path, run_as_service);
        for account in &config.accounts {
            let expected = if account.id == "abs" { "pw-abs" } else { "pw-rel" };
            assert_eq!(store.get_account_password(account).unwrap(), expected, "service mode: {}", run_as_service);
        }
    }

    // The service unit passes this same path to the server
    let unit = mailbackup_core::service::generate_linux_systemd(Path::new("/usr/bin/mailbackup-server"), &config_path, "user");
    assert!(unit.contains(&config_path.display().to_string()));
}

#[test]
fn credentials_an_older_cli_kept_in_the_home_folder_are_migrated() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let base = home.join(".mailbackup");
    let custom = tmp.path().join("custom");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(&custom).unwrap();
    let config_path = custom.join("config.yaml");

    // An older CLI: the account went into the custom config, its password into
    // ~/.mailbackup, next to a password of the default config
    cli(&home, tmp.path(), &add_args(config_path.to_str().unwrap(), "old", "placeholder"));
    std::fs::remove_file(custom.join(".credentials_store.json")).unwrap();
    std::fs::remove_file(custom.join(".credentials_key")).unwrap();
    let legacy = CredentialStore::with_paths(base.join(".credentials_store.json"), base.join(".credentials_key"))
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring));
    let config = AppConfig::load_or_create(Some(&config_path)).unwrap();
    legacy.set_account_password(&config.accounts[0], "pw-old").unwrap();
    legacy.set_password("default-account", "pw-default").unwrap();

    // Removing the account through the CLI finds and deletes its migrated copy
    let store = CredentialStore::for_config(&config_path, &GlobalSettings::default())
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring))
        .with_legacy_store(base.join(".credentials_store.json"), base.join(".credentials_key"));
    assert_eq!(store.get_account_password(&config.accounts[0]).unwrap(), "pw-old");
    assert!(custom.join(".credentials_store.json").exists(), "copied next to the config");
    assert_eq!(legacy.get_password("old").unwrap(), "pw-old", "the old copy is kept until the account goes");

    cli(&home, tmp.path(), &["--config", config_path.to_str().unwrap(), "account", "remove", "old"]);
    assert!(legacy.get_password("old").is_err(), "removed from the old location too");
    assert_eq!(legacy.get_password("default-account").unwrap(), "pw-default", "the default config keeps its password");
}
