//! `account add` takes the password from stdin or `MAILBACKUP_PASSWORD` for
//! scripts, and `--password` (visible in the process list) is deprecated.

use mailbackup_core::config::{AppConfig, GlobalSettings};
use mailbackup_core::keyring::{CredentialStore, NoKeyring};
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

struct Setup {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
}

fn setup() -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = tmp.path().join("config.yaml");
    Setup { _tmp: tmp, home, config }
}

/// Runs `mailbackup account add` for `id` with every setting given as a flag,
/// plus `extra`, feeding `stdin` and setting `env`.
fn add(s: &Setup, id: &str, extra: &[&str], stdin: &[u8], env: &[(&str, &OsStr)]) -> Output {
    let mut args: Vec<&str> = vec![
        "--config", s.config.to_str().unwrap(), "account", "add", "--id", id, "--name", id, "--email",
        "user@example.com", "--provider", "generic", "--server", "imap.example.com", "--port", "993", "--username",
        "user", "--retention-days", "30",
    ];
    args.extend_from_slice(extra);
    run(s, &args, stdin, env)
}

fn run(s: &Setup, args: &[&str], stdin: &[u8], env: &[(&str, &OsStr)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mailbackup"));
    command
        .args(args)
        .env("HOME", &s.home)
        .env("MAILBACKUP_KEYRING", "none")
        .env_remove("MAILBACKUP_PASSWORD")
        .env_remove("MAILBACKUP_MASTER_KEY")
        .env_remove("MAILBACKUP_ENCRYPTION_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    // The CLI may exit before reading all of it
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn ok(output: Output) -> Output {
    assert!(output.status.success(), "{}", stderr(&output));
    output
}

fn failed(output: Output) -> String {
    assert!(!output.status.success(), "should fail; stdout: {}", String::from_utf8_lossy(&output.stdout));
    stderr(&output)
}

/// The stored password of `id`, as the server would read it; `None` if the
/// account isn't configured.
fn stored(config: &Path, id: &str) -> Option<String> {
    let accounts = AppConfig::load_or_create(Some(config)).unwrap().accounts;
    let account = accounts.iter().find(|a| a.id == id)?;
    let store = CredentialStore::for_config(config, &GlobalSettings::default())
        .with_passphrase(None)
        .with_keyring(Arc::new(NoKeyring));
    Some(store.get_account_password(account).unwrap())
}

const STDIN: &[&str] = &["--password-stdin"];

#[test]
fn stdin_passwords_are_stored_exactly() {
    let s = setup();
    ok(add(&s, "lf", STDIN, b"secret\n", &[]));
    ok(add(&s, "crlf", STDIN, b"secret\r\n", &[]));
    ok(add(&s, "bare", STDIN, b"secret", &[]));
    ok(add(&s, "spaces", STDIN, b"  pass word  \n", &[]));
    assert_eq!(stored(&s.config, "lf").unwrap(), "secret");
    assert_eq!(stored(&s.config, "crlf").unwrap(), "secret");
    assert_eq!(stored(&s.config, "bare").unwrap(), "secret");
    assert_eq!(stored(&s.config, "spaces").unwrap(), "  pass word  ", "leading and trailing spaces kept");

    let max = vec![b'x'; 4096];
    ok(add(&s, "max", STDIN, &max, &[]));
    assert_eq!(stored(&s.config, "max").unwrap().len(), 4096);
}

#[test]
fn invalid_stdin_is_rejected_and_changes_nothing() {
    let s = setup();
    ok(add(&s, "acc", STDIN, b"original\n", &[]));
    let config_before = std::fs::read(&s.config).unwrap();

    let too_long = vec![b'x'; 4097];
    let cases: [(&[u8], &str); 5] = [
        (b"", "empty"),
        (b"\n", "empty"),
        (b"new\n\n", "more than one line"),
        (b"new\nline\n", "more than one line"),
        (&too_long, "longer than 4096 bytes"),
    ];
    for (input, message) in cases {
        let err = failed(add(&s, "acc", STDIN, input, &[]));
        assert!(err.contains(message), "{:?}: {}", String::from_utf8_lossy(input), err);
        assert_eq!(stored(&s.config, "acc").unwrap(), "original", "password unchanged");
        assert_eq!(std::fs::read(&s.config).unwrap(), config_before, "config unchanged");
        failed(add(&s, "new", STDIN, input, &[]));
        assert!(stored(&s.config, "new").is_none(), "no account saved");
    }
}

#[test]
fn the_environment_variable_is_used_with_a_notice() {
    let s = setup();
    let out = ok(add(&s, "env", &[], b"", &[("MAILBACKUP_PASSWORD", OsStr::new("from-env"))]));
    assert_eq!(stored(&s.config, "env").unwrap(), "from-env");
    let err = stderr(&out);
    assert!(err.contains("Using the password from MAILBACKUP_PASSWORD"), "{}", err);
    assert!(!err.contains("from-env") && !String::from_utf8_lossy(&out.stdout).contains("from-env"), "value not printed");
}

#[test]
fn invalid_environment_values_are_errors_not_skipped() {
    let s = setup();
    ok(add(&s, "acc", STDIN, b"original\n", &[]));
    let err = failed(add(&s, "acc", &[], b"", &[("MAILBACKUP_PASSWORD", OsStr::new(""))]));
    assert!(err.contains("MAILBACKUP_PASSWORD is empty"), "{}", err);
    let err = failed(add(&s, "acc", &[], b"", &[("MAILBACKUP_PASSWORD", OsStr::new("a\nb"))]));
    assert!(err.contains("more than one line"), "{}", err);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let err = failed(add(&s, "acc", &[], b"", &[("MAILBACKUP_PASSWORD", OsStr::from_bytes(b"\xff\xfe"))]));
        assert!(err.contains("not valid UTF-8"), "{}", err);
    }
    assert_eq!(stored(&s.config, "acc").unwrap(), "original");
}

#[test]
fn explicit_flags_override_the_environment() {
    let s = setup();
    let env = [("MAILBACKUP_PASSWORD", OsStr::new("from-env"))];
    let out = ok(add(&s, "stdin", STDIN, b"from-stdin\n", &env));
    assert_eq!(stored(&s.config, "stdin").unwrap(), "from-stdin");
    assert!(!stderr(&out).contains("Using the password from"), "env not used: {}", stderr(&out));
    ok(add(&s, "flag", &["--password", "from-flag"], b"", &env));
    assert_eq!(stored(&s.config, "flag").unwrap(), "from-flag");
    // Even an invalid environment value doesn't matter when a flag is given
    ok(add(&s, "flag2", STDIN, b"from-stdin\n", &[("MAILBACKUP_PASSWORD", OsStr::new(""))]));
}

#[test]
fn the_password_flag_still_works_with_a_deprecation_warning() {
    let s = setup();
    let out = ok(add(&s, "old", &["--password", "legacy"], b"", &[]));
    assert_eq!(stored(&s.config, "old").unwrap(), "legacy");
    assert!(stderr(&out).contains("--password is deprecated"), "{}", stderr(&out));

    let err = failed(add(&s, "both", &["--password", "x", "--password-stdin"], b"y\n", &[]));
    assert!(err.contains("cannot be used with"), "{}", err);
    assert!(stored(&s.config, "both").is_none());
}

#[test]
fn without_a_terminal_every_missing_setting_is_reported_at_once() {
    let s = setup();
    // stdin is a pipe here, so there is nobody to prompt
    let err = failed(add(&s, "nopw", &[], b"", &[]));
    assert!(err.contains("--password-stdin or MAILBACKUP_PASSWORD"), "{}", err);
    assert!(stored(&s.config, "nopw").is_none());

    let config = s.config.to_str().unwrap();
    let err = failed(run(&s, &["--config", config, "account", "add", "--password-stdin", "--email", "a@b.c"], b"pw\n", &[]));
    for flag in ["--provider", "--name", "--server", "--port", "--username", "--retention-days"] {
        assert!(err.contains(flag), "{} listed: {}", flag, err);
    }
    assert!(!err.contains("--email,"), "given flags aren't listed: {}", err);
    assert!(!err.contains("a password"), "stdin supplies the password: {}", err);
}
