//! The GUI's check that a server is genuine (issue #10).

use mailbackup_server::runtime::{self, RuntimeInfo};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

/// Starts a real server for `config_dir` on `port` (0 = any free port) on its
/// own thread; returns what it reports once listening.
fn start_server(config_dir: &Path, port: u16) -> Result<u16, String> {
    let config_path = config_dir.join("config.yaml");
    if !config_path.exists() {
        let config = mailbackup_core::config::AppConfig {
            data_dir: config_dir.join("data"),
            db_path: config_dir.join("catalog.db"),
            ..Default::default()
        };
        config.save(&config_path).unwrap();
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let _ = rt.block_on(mailbackup_server::run_server(Some(port), Some(config_path), Some(tx)));
    });
    rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap()
}

/// A fake HTTP server that answers every request with `respond(request)`.
fn fake_server(respond: impl Fn(&str, u16) -> String + Send + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = stream.write_all(respond(&request, port).as_bytes());
        }
    });
    port
}

fn http(port: u16, request: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    out
}

fn get(port: u16, path: &str, host: &str) -> String {
    http(port, &format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host))
}

fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn runtime_of(dir: &Path, port: u16) -> RuntimeInfo {
    serde_json::from_slice(&std::fs::read(runtime::runtime_path(dir, port)).unwrap()).unwrap()
}

/// A leftover runtime file for `port`, e.g. from an earlier genuine run.
fn stale_file_for(dir: &Path, info: &RuntimeInfo, port: u16) -> PathBuf {
    let moved = RuntimeInfo { port, ..info.clone() };
    runtime::publish(dir, &moved).unwrap();
    runtime::runtime_path(dir, port)
}

fn nonce_of(request: &str) -> String {
    request.split("nonce=").nth(1).and_then(|r| r.get(..64)).unwrap_or("").to_string()
}

#[test]
fn a_genuine_server_is_verified_and_its_file_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let port = start_server(dir.path(), 0).unwrap();
    let info = runtime::verify_genuine(dir.path(), port).expect("genuine server verified");
    assert_eq!(info.port, port);
    assert_eq!(info.pid, std::process::id());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(runtime::runtime_path(dir.path(), port)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn the_handshake_needs_no_token_but_is_host_checked() {
    let dir = tempfile::tempdir().unwrap();
    let port = start_server(dir.path(), 0).unwrap();
    let nonce = "a".repeat(64);
    let host = format!("127.0.0.1:{}", port);
    let ok = get(port, &format!("/api/handshake?nonce={}", nonce), &host);
    assert!(ok.starts_with("HTTP/1.1 200"), "{}", ok);
    assert!(!ok.contains(&runtime_of(dir.path(), port).secret), "the secret is never sent");

    let rebinding = get(port, &format!("/api/handshake?nonce={}", nonce), "evil.example");
    assert!(rebinding.starts_with("HTTP/1.1 403"), "{}", rebinding);
    let bad_nonce = get(port, "/api/handshake?nonce=xyz", &host);
    assert!(bad_nonce.starts_with("HTTP/1.1 400"), "{}", bad_nonce);
    // Every other API route still needs the token
    let other = get(port, "/api/version", &host);
    assert!(other.starts_with("HTTP/1.1 401"), "{}", other);
}

#[test]
fn a_squatter_using_the_public_page_token_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let genuine = start_server(dir.path(), 0).unwrap();
    let info = runtime_of(dir.path(), genuine);

    // The API token anyone can read from the served page
    let page = get(genuine, "/", &format!("127.0.0.1:{}", genuine));
    let token = page
        .split("name=\"mailbackup-api-token\" content=\"")
        .nth(1)
        .and_then(|rest| rest.get(..64))
        .expect("token in page")
        .to_string();
    assert_ne!(token, info.secret);
    let token_copy = token.clone();

    // The squatter answers exactly as a server whose secret was that token would
    let fake = fake_server(move |request, port| {
        use hmac::{Hmac, Mac};
        let key = hex::decode(&token).unwrap();
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(format!("mailbackup-handshake:v1:{}:{}", port, nonce_of(request)).as_bytes());
        json_response(&format!(r#"{{"proof":"{}","port":{}}}"#, hex::encode(mac.finalize().into_bytes()), port))
    });
    stale_file_for(dir.path(), &info, fake);
    assert!(runtime::verify_genuine(dir.path(), fake).is_none());

    // Had the runtime file carried the page token as its secret, this squatter
    // would pass: the test above holds only because the secrets differ
    let leaked = RuntimeInfo { secret: token_copy.clone(), ..info.clone() };
    stale_file_for(dir.path(), &leaked, fake);
    assert!(runtime::verify_genuine(dir.path(), fake).is_some(), "control: the attack works against a token-keyed design");
}

#[test]
fn fakes_redirects_and_stale_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let genuine = start_server(dir.path(), 0).unwrap();
    let info = runtime_of(dir.path(), genuine);

    let always_ok = fake_server(|_, port| json_response(&format!(r#"{{"proof":"{}","port":{}}}"#, "0".repeat(64), port)));
    stale_file_for(dir.path(), &info, always_ok);
    assert!(runtime::verify_genuine(dir.path(), always_ok).is_none(), "200 to everything");

    // A redirect to the genuine server is not followed
    let redirect = fake_server(move |request, _| {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/api/handshake?nonce={}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            genuine,
            nonce_of(request)
        )
    });
    stale_file_for(dir.path(), &info, redirect);
    assert!(runtime::verify_genuine(dir.path(), redirect).is_none(), "redirect");

    // Nothing listening on a port with a leftover file
    let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    stale_file_for(dir.path(), &info, free);
    assert!(runtime::verify_genuine(dir.path(), free).is_none(), "nothing listening");

    // No file, or a garbled one
    let other = tempfile::tempdir().unwrap();
    assert!(runtime::verify_genuine(other.path(), genuine).is_none());
    std::fs::write(runtime::runtime_path(other.path(), genuine), b"{ not json").unwrap();
    assert!(runtime::verify_genuine(other.path(), genuine).is_none());

    // The genuine one still verifies
    assert!(runtime::verify_genuine(dir.path(), genuine).is_some());
}

#[test]
fn a_second_server_on_a_taken_port_leaves_the_first_instance_intact() {
    let dir = tempfile::tempdir().unwrap();
    let port = start_server(dir.path(), 0).unwrap();
    let before = runtime_of(dir.path(), port);

    let second = start_server(dir.path(), port);
    assert!(second.is_err(), "the bind fails: {:?}", second);
    assert_eq!(runtime_of(dir.path(), port), before, "file untouched");
    assert!(runtime::verify_genuine(dir.path(), port).is_some());
}

#[test]
fn an_exiting_instance_only_removes_its_own_file() {
    let dir = tempfile::tempdir().unwrap();
    let info = RuntimeInfo { instance_id: "mine".into(), pid: 1, port: 4242, version: "x".into(), secret: "00".repeat(32) };
    runtime::publish(dir.path(), &info).unwrap();
    runtime::unpublish(dir.path(), 4242, "someone-else");
    assert!(runtime::runtime_path(dir.path(), 4242).exists());
    runtime::unpublish(dir.path(), 4242, "mine");
    assert!(!runtime::runtime_path(dir.path(), 4242).exists());

    // Dropping the guard of a replaced instance leaves the newer file alone
    let identity = runtime::ServerIdentity::new(4243);
    let guard = runtime::PublishedRuntime::publish(dir.path(), &identity).unwrap();
    let newer = RuntimeInfo { instance_id: "newer".into(), port: 4243, ..info };
    runtime::publish(dir.path(), &newer).unwrap();
    drop(guard);
    assert_eq!(runtime_of(dir.path(), 4243).instance_id, "newer");
}
