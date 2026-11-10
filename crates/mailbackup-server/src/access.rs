//! Logging in to the web UI (issue #70).
//!
//! The API token in `index.html` only stops other web origins; anyone who
//! could load the page used to get it. With `settings.require_login` (the
//! default), a browser must first present the access key
//! (`mailbackup_core::web_access`) and gets a session cookie for it. Only a
//! page served to a session carries the token, and every route but the few
//! the login page needs refuses requests without a session.
//!
//! - Sessions live in memory: a restart, an idle period ([`SESSION_IDLE`]),
//!   a logout or a new access key ends them. The key file is read on each
//!   check, so a key regenerated anywhere (CLI, another process) ends every
//!   session at once.
//! - Failed logins are limited per peer address ([`MAX_FAILURES`] per
//!   [`FAILURE_WINDOW`]).
//! - The desktop app logs in for the user with a single-use login ticket
//!   ([`TICKET_TTL`]) it gets for the key over loopback, after it verified
//!   the server; the key itself is never put in a URL.
//!
//! Requests the desktop window sends in-process need no session: they can't
//! come from the network.

use mailbackup_core::web_access;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SESSION_COOKIE: &str = "mailbackup_session";
pub const SESSION_IDLE: Duration = Duration::from_secs(12 * 3600);
pub const MAX_SESSIONS: usize = 256;
pub const MAX_FAILURES: u32 = 5;
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);
pub const TICKET_TTL: Duration = Duration::from_secs(60);
const MAX_TICKETS: usize = 64;
const MAX_TRACKED_PEERS: usize = 4096;

/// Why a login was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    WrongKey,
    /// Too many failures from this peer; try again after this long
    TooMany(Duration),
    /// The key file can't be read or created
    Unavailable(String),
}

#[derive(Default)]
struct Inner {
    /// The key the sessions were issued under
    key: Option<String>,
    /// SHA-256 of a session token -> last use
    sessions: HashMap<[u8; 32], Instant>,
    /// SHA-256 of a login ticket -> expiry
    tickets: HashMap<[u8; 32], Instant>,
    /// Peer -> (failures, start of the window)
    failures: HashMap<String, (u32, Instant)>,
}

pub struct Access {
    config_dir: PathBuf,
    inner: Mutex<Inner>,
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    hex::encode(bytes)
}

impl Access {
    pub fn new(config_dir: PathBuf) -> Self {
        Access { config_dir, inner: Mutex::new(Inner::default()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The key as the file has it now. A key that differs from the one the
    /// sessions were issued under ends them all. `create` makes a key if
    /// there is none (logins do; session checks don't).
    fn current_key(&self, inner: &mut Inner, create: bool) -> Result<Option<String>, String> {
        let key = if create {
            web_access::load_or_create_key(&self.config_dir).map(Some)
        } else {
            web_access::read_key(&self.config_dir)
        }
        .map_err(|e| e.to_string())?;
        if inner.key != key {
            inner.sessions.clear();
            inner.tickets.clear();
            inner.key = key.clone();
        }
        Ok(key)
    }

    /// The access key (created if missing), for showing to a logged-in user.
    pub fn key(&self) -> Result<String, String> {
        let mut inner = self.lock();
        Ok(self.current_key(&mut inner, true)?.expect("created"))
    }

    /// A new access key; every session and ticket ends.
    pub fn regenerate(&self) -> Result<String, String> {
        let mut inner = self.lock();
        let key = web_access::regenerate_key(&self.config_dir).map_err(|e| e.to_string())?;
        inner.sessions.clear();
        inner.tickets.clear();
        inner.key = Some(key.clone());
        Ok(key)
    }

    fn check_key(&self, inner: &mut Inner, peer: &str, presented: &str) -> Result<(), LoginError> {
        let now = Instant::now();
        if inner.failures.len() > MAX_TRACKED_PEERS {
            inner.failures.retain(|_, (_, since)| now.duration_since(*since) < FAILURE_WINDOW);
        }
        if let Some((count, since)) = inner.failures.get(peer).copied() {
            let elapsed = now.duration_since(since);
            if elapsed >= FAILURE_WINDOW {
                inner.failures.remove(peer);
            } else if count >= MAX_FAILURES {
                return Err(LoginError::TooMany(FAILURE_WINDOW - elapsed));
            }
        }
        let key = self.current_key(inner, true).map_err(LoginError::Unavailable)?.expect("created");
        if web_access::keys_equal(&key, presented) {
            inner.failures.remove(peer);
            Ok(())
        } else {
            let entry = inner.failures.entry(peer.to_string()).or_insert((0, now));
            entry.0 += 1;
            Err(LoginError::WrongKey)
        }
    }

    fn new_session(inner: &mut Inner) -> String {
        let now = Instant::now();
        inner.sessions.retain(|_, used| now.duration_since(*used) < SESSION_IDLE);
        if inner.sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = inner.sessions.iter().min_by_key(|(_, used)| **used).map(|(k, _)| *k) {
            inner.sessions.remove(&oldest);
        }
        let token = random_token();
        inner.sessions.insert(digest(&token), now);
        token
    }

    /// Logs in with `key` from `peer`: a new session token.
    pub fn login(&self, peer: &str, key: &str) -> Result<String, LoginError> {
        let mut inner = self.lock();
        self.check_key(&mut inner, peer, key)?;
        Ok(Self::new_session(&mut inner))
    }

    /// Like [`Self::login`], but a single-use login ticket valid for
    /// [`TICKET_TTL`] (for the desktop app; see the module docs).
    pub fn login_ticket(&self, peer: &str, key: &str) -> Result<String, LoginError> {
        let mut inner = self.lock();
        self.check_key(&mut inner, peer, key)?;
        let now = Instant::now();
        inner.tickets.retain(|_, expires| *expires > now);
        if inner.tickets.len() >= MAX_TICKETS {
            return Err(LoginError::TooMany(TICKET_TTL));
        }
        let ticket = random_token();
        inner.tickets.insert(digest(&ticket), now + TICKET_TTL);
        Ok(ticket)
    }

    /// Exchanges a login ticket for a session. The ticket is used up either way.
    pub fn redeem_ticket(&self, ticket: &str) -> Option<String> {
        let mut inner = self.lock();
        // A ticket issued under a key that has changed since is void
        self.current_key(&mut inner, false).ok()?;
        let expires = inner.tickets.remove(&digest(ticket))?;
        (expires > Instant::now()).then(|| Self::new_session(&mut inner))
    }

    /// Whether `token` is a live session (and marks it used).
    pub fn session_valid(&self, token: &str) -> bool {
        let mut inner = self.lock();
        if self.current_key(&mut inner, false).ok().flatten().is_none() {
            return false;
        }
        let now = Instant::now();
        match inner.sessions.get_mut(&digest(token)) {
            Some(used) if now.duration_since(*used) < SESSION_IDLE => {
                *used = now;
                true
            }
            Some(_) => {
                inner.sessions.remove(&digest(token));
                false
            }
            None => false,
        }
    }

    pub fn logout(&self, token: &str) {
        self.lock().sessions.remove(&digest(token));
    }
}

/// The session token in a `Cookie` header, if any.
pub fn session_from_cookies(header: &str) -> Option<&str> {
    header.split(';').map(str::trim).find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == SESSION_COOKIE).then_some(value.trim()).filter(|v| !v.is_empty())
    })
}

/// `Set-Cookie` for a session (`Secure` when the page was reached over HTTPS).
pub fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
        SESSION_COOKIE,
        token,
        SESSION_IDLE.as_secs(),
        if secure { "; Secure" } else { "" }
    )
}

/// `Set-Cookie` that removes the session cookie.
pub fn expired_cookie() -> String {
    format!("{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0", SESSION_COOKIE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> (tempfile::TempDir, Access) {
        let dir = tempfile::tempdir().unwrap();
        let access = Access::new(dir.path().to_path_buf());
        (dir, access)
    }

    #[test]
    fn the_key_gives_a_session_and_a_wrong_key_does_not() {
        let (_dir, access) = access();
        let key = access.key().unwrap();
        assert_eq!(access.login("p", "0".repeat(64).as_str()), Err(LoginError::WrongKey));
        let session = access.login("p", &key).unwrap();
        assert!(access.session_valid(&session));
        assert!(!access.session_valid("not a session"));
        access.logout(&session);
        assert!(!access.session_valid(&session));
    }

    #[test]
    fn failures_are_limited_per_peer() {
        let (_dir, access) = access();
        let key = access.key().unwrap();
        for _ in 0..MAX_FAILURES {
            assert_eq!(access.login("attacker", "wrong"), Err(LoginError::WrongKey));
        }
        assert!(matches!(access.login("attacker", &key), Err(LoginError::TooMany(_))), "even the right key waits");
        assert!(access.login("someone else", &key).is_ok(), "other peers aren't affected");
    }

    #[test]
    fn a_new_key_ends_every_session_whoever_wrote_it() {
        let (dir, access) = access();
        let key = access.key().unwrap();
        let a = access.login("p", &key).unwrap();
        let b = access.login("p", &key).unwrap();
        // Regenerated through this server
        access.regenerate().unwrap();
        assert!(!access.session_valid(&a) && !access.session_valid(&b));

        // Regenerated by another process (the CLI) writing the file
        let key = access.key().unwrap();
        let c = access.login("p", &key).unwrap();
        mailbackup_core::web_access::regenerate_key(dir.path()).unwrap();
        assert!(!access.session_valid(&c));
        assert!(access.login("p", &key).is_err(), "the old key no longer works");
    }

    #[test]
    fn a_login_ticket_is_single_use_and_dies_with_the_key() {
        let (dir, access) = access();
        let key = access.key().unwrap();
        let ticket = access.login_ticket("p", &key).unwrap();
        let session = access.redeem_ticket(&ticket).expect("redeemed once");
        assert!(access.session_valid(&session));
        assert!(access.redeem_ticket(&ticket).is_none(), "used up");

        let ticket = access.login_ticket("p", &key).unwrap();
        mailbackup_core::web_access::regenerate_key(dir.path()).unwrap();
        assert!(access.redeem_ticket(&ticket).is_none(), "issued under the old key");
    }

    #[test]
    fn a_missing_key_file_validates_no_session() {
        let (dir, access) = access();
        let key = access.key().unwrap();
        let session = access.login("p", &key).unwrap();
        std::fs::remove_file(mailbackup_core::web_access::key_path(dir.path())).unwrap();
        assert!(!access.session_valid(&session));
    }

    #[test]
    fn cookies_are_parsed_and_built() {
        assert_eq!(session_from_cookies("a=b; mailbackup_session=xyz; c=d"), Some("xyz"));
        assert_eq!(session_from_cookies("mailbackup_session="), None);
        assert_eq!(session_from_cookies("other=1"), None);
        let cookie = session_cookie("t", true);
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict") && cookie.ends_with("; Secure"));
        assert!(!session_cookie("t", false).contains("Secure"));
    }
}
