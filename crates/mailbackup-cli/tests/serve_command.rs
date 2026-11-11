//! `mailbackup --config X serve` must start the sibling server on that config
//! and on the port it prints, not on `~/.mailbackup` and the default port.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A copy of the CLI next to a fake `mailbackup-server` that records its
/// arguments, so `serve` runs the fake instead of a real server.
fn cli_with_fake_server(dir: &Path, args_file: &Path) -> PathBuf {
    let cli = dir.join("mailbackup");
    std::fs::copy(env!("CARGO_BIN_EXE_mailbackup"), &cli).unwrap();
    let server = dir.join("mailbackup-server");
    std::fs::write(
        &server,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > '{}'\n",
            args_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o755)).unwrap();
    cli
}

fn run_serve(extra: &[&str], web_port: u16) -> (String, Vec<String>, PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bin = tmp.path().join("bin");
    let cfg_dir = tmp.path().join("cfg");
    for d in [&home, &bin, &cfg_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    let config_path = cfg_dir.join("other.yaml");
    std::fs::write(
        &config_path,
        format!(
            "data_dir: {}\ndb_path: {}\nsettings:\n  web_port: {}\n",
            tmp.path().join("data").display(),
            tmp.path().join("db/catalog.db").display(),
            web_port
        ),
    )
    .unwrap();
    let args_file = tmp.path().join("server-args");
    let cli = cli_with_fake_server(&bin, &args_file);

    let mut args = vec!["--config", config_path.to_str().unwrap(), "serve"];
    args.extend_from_slice(extra);
    let out = Command::new(cli)
        .args(&args)
        .env("HOME", &home)
        .env_remove("MAILBACKUP_MASTER_KEY")
        .env_remove("MAILBACKUP_ENCRYPTION_KEY")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let server_args = std::fs::read_to_string(&args_file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(
        !home.join(".mailbackup/config.yaml").exists(),
        "serve must not touch the default config"
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        server_args,
        config_path,
        tmp,
    )
}

#[test]
fn serve_uses_the_configs_web_port_by_default() {
    let (stdout, args, config, _tmp) = run_serve(&[], 8799);
    assert_eq!(
        args,
        ["--config", config.to_str().unwrap(), "--port", "8799"]
    );
    assert!(stdout.contains("http://127.0.0.1:8799"), "{stdout}");
}

#[test]
fn serve_port_flag_overrides_the_config() {
    let (stdout, args, config, _tmp) = run_serve(&["--port", "9123"], 8799);
    assert_eq!(
        args,
        ["--config", config.to_str().unwrap(), "--port", "9123"]
    );
    assert!(stdout.contains("http://127.0.0.1:9123"), "{stdout}");
}
