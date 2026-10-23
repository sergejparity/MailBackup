//! Lets the desktop GUI make sure the server it is about to show is a genuine
//! MailBackup server started by the same user, not another process holding
//! the port.
//!
//! Each server process has a random handshake secret, separate from the API
//! token: the API token is embedded in the public `index.html`, so it can't
//! prove anything. Once its listener is bound, the server publishes
//! `<config folder>/.server-<port>.json` (owner-only) with the secret. A
//! client then sends a fresh nonce to `GET /api/handshake` (no credentials
//! needed or sent) and checks the HMAC the server answers with.
//!
//! Threat boundary: this keeps **another user's** process that squats the
//! port from being shown in the GUI. A process running as the same user can
//! read the runtime file. A challenge-response also doesn't authenticate the
//! transport against a live relay to a genuine server.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PROOF_CONTEXT: &str = "mailbackup-handshake:v1:";
const NONCE_HEX_LEN: usize = 64;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
/// The whole handshake (connect, request, response) must finish within this,
/// however the other end paces its bytes.
const DEADLINE: Duration = Duration::from_secs(2);

/// What a running server publishes about itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub instance_id: String,
    pub pid: u32,
    pub port: u16,
    pub version: String,
    /// Hex-encoded handshake secret.
    pub secret: String,
}

/// This process's identity, created at startup.
#[derive(Clone)]
pub struct ServerIdentity {
    pub instance_id: String,
    secret: [u8; 32],
    pub port: u16,
}

impl ServerIdentity {
    pub fn new(port: u16) -> Self {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("OS random number generator unavailable");
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).expect("OS random number generator unavailable");
        Self { instance_id: hex::encode(id), secret, port }
    }

    pub fn runtime_info(&self) -> RuntimeInfo {
        RuntimeInfo {
            instance_id: self.instance_id.clone(),
            pid: std::process::id(),
            port: self.port,
            version: env!("CARGO_PKG_VERSION").to_string(),
            secret: hex::encode(self.secret),
        }
    }

    /// The handshake answer for `nonce`, or `None` for a malformed nonce.
    pub fn proof(&self, nonce: &str) -> Option<String> {
        valid_nonce(nonce).then(|| proof(&self.secret, self.port, nonce))
    }
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == NONCE_HEX_LEN && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

fn proof(secret: &[u8], port: u16, nonce: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{}{}:{}", PROOF_CONTEXT, port, nonce.to_ascii_lowercase()).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// `<config folder>/.server-<port>.json`
pub fn runtime_path(config_dir: &Path, port: u16) -> PathBuf {
    config_dir.join(format!(".server-{}.json", port))
}

/// Publishes `info` for its port (atomically, owner-only). Call only once the
/// listener is bound, so a failed bind never replaces another instance's file.
pub fn publish(config_dir: &Path, info: &RuntimeInfo) -> std::io::Result<()> {
    mailbackup_core::private_fs::create_dir_all(config_dir)?;
    let data = serde_json::to_vec_pretty(info).map_err(std::io::Error::other)?;
    mailbackup_core::private_fs::write_atomic(&runtime_path(config_dir, info.port), &data)
}

/// Removes the runtime file for `port` only if it still belongs to
/// `instance_id`, so an exiting server never removes another instance's file.
pub fn unpublish(config_dir: &Path, port: u16, instance_id: &str) {
    let path = runtime_path(config_dir, port);
    if read_runtime(&path).map(|info| info.instance_id == instance_id).unwrap_or(false) {
        let _ = std::fs::remove_file(path);
    }
}

fn read_runtime(path: &Path) -> Option<RuntimeInfo> {
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

/// Removes this instance's runtime file when dropped.
pub struct PublishedRuntime {
    config_dir: PathBuf,
    port: u16,
    instance_id: String,
}

impl PublishedRuntime {
    pub fn publish(config_dir: &Path, identity: &ServerIdentity) -> std::io::Result<Self> {
        publish(config_dir, &identity.runtime_info())?;
        Ok(Self { config_dir: config_dir.to_path_buf(), port: identity.port, instance_id: identity.instance_id.clone() })
    }
}

impl Drop for PublishedRuntime {
    fn drop(&mut self) {
        unpublish(&self.config_dir, self.port, &self.instance_id);
    }
}

/// The published info for `port` if the server listening there proves it
/// holds the published secret; `None` on any doubt (no file, nothing
/// listening, wrong or malformed answer, redirect, timeout).
///
/// The request goes straight to `127.0.0.1:<port>` (no proxies), carries only
/// a fresh nonce, follows no redirects, and is bounded in time and size.
pub fn verify_genuine(config_dir: &Path, port: u16) -> Option<RuntimeInfo> {
    let info = read_runtime(&runtime_path(config_dir, port))?;
    if info.port != port {
        return None;
    }
    let secret = hex::decode(&info.secret).ok().filter(|s| s.len() == 32)?;
    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes).ok()?;
    let nonce = hex::encode(nonce_bytes);

    let body = handshake_request(port, &nonce)?;
    let answer: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let answered_port = answer.get("port")?.as_u64()?;
    let answered_proof = answer.get("proof")?.as_str()?;
    let expected = proof(&secret, port, &nonce);
    (answered_port == port as u64 && constant_time_eq(answered_proof.as_bytes(), expected.as_bytes())).then_some(info)
}

/// `GET /api/handshake?nonce=…` over a plain TCP connection; the body of a
/// `200` response with a `Content-Length`, else `None`. Gives up at
/// [`DEADLINE`] and stops reading once the declared body has arrived.
fn handshake_request(port: u16, nonce: &str) -> Option<Vec<u8>> {
    handshake_request_by(port, nonce, Instant::now() + DEADLINE)
}

fn handshake_request_by(port: u16, nonce: &str, deadline: Instant) -> Option<Vec<u8>> {
    let remaining = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, remaining()?).ok()?;
    stream.set_write_timeout(Some(remaining()?)).ok()?;
    let request = format!(
        "GET /api/handshake?nonce={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        nonce, port
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    // (end of headers, body length) once the headers are in
    let mut framing: Option<(usize, usize)> = None;
    loop {
        if let Some((header_end, length)) = framing {
            if response.len() >= header_end + 4 + length {
                break;
            }
        }
        // Each read may only wait for what is left of the deadline
        stream.set_read_timeout(Some(remaining()?)).ok()?;
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.len() > MAX_RESPONSE_BYTES {
            return None;
        }
        if framing.is_none() {
            if let Some(header_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                framing = Some((header_end, parse_head(&response[..header_end])?));
            }
        }
    }
    let (header_end, length) = framing?;
    let body = response.get(header_end + 4..)?;
    (body.len() == length).then(|| body.to_vec())
}

/// The `Content-Length` of a plain `200` response head; `None` for any other
/// status (redirects included), chunked bodies or a missing length.
fn parse_head(head: &[u8]) -> Option<usize> {
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?;
    if !(status.starts_with("HTTP/1.1 200 ") || status.starts_with("HTTP/1.0 200 ")) {
        return None;
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    length.filter(|&l| l <= MAX_RESPONSE_BYTES)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
