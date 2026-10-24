//! Single-use download tickets (issue #15).
//!
//! Plain download links can't send the `X-MailBackup-Token` header, so the UI
//! asks `POST /api/download-ticket` for a ticket right before each download
//! and appends it as `?ticket=`. A ticket:
//! - is valid for one `GET` of one complete target: the exact path and query
//!   it was issued for (see [`Target`]), so another message, account, folder
//!   or file needs a ticket of its own;
//! - expires after [`TICKET_TTL`];
//! - is removed from the store before it is checked, so it is used at most
//!   once even by concurrent requests, and a failed attempt burns it too.
//!
//! Tickets are only ever looked at for the [download routes](is_download_path),
//! so they can't authorize anything else.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const TICKET_TTL: Duration = Duration::from_secs(60);
/// Most live tickets at once; minting more is refused until some expire.
pub const MAX_LIVE_TICKETS: usize = 1024;
pub const TICKET_PARAM: &str = "ticket";

/// Paths a ticket may be issued for: the downloads the UI opens as plain links.
pub fn is_download_path(path: &str) -> bool {
    if matches!(path, "/api/export/mbox/download" | "/api/logs/download" | "/api/accounts/csv-template") {
        return true;
    }
    path.strip_prefix("/api/messages/")
        .and_then(|rest| rest.strip_suffix("/download"))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// One complete download target: path plus its query with empty pairs
/// dropped, pairs kept in their order and spelling. Two targets are the same
/// only if these strings are equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    path: String,
    query: String,
}

impl Target {
    /// The target a client asks a ticket for: a relative URL to a download
    /// route without a fragment or a `ticket` parameter.
    pub fn for_url(url: &str) -> Option<Target> {
        if url.contains('#') {
            return None;
        }
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        // Relative to this server only: no scheme, no `//host`
        if !path.starts_with('/') || path.starts_with("//") || !is_download_path(path) {
            return None;
        }
        let pairs: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
        if pairs.iter().any(|p| is_ticket_pair(p)) {
            return None;
        }
        Some(Target { path: path.to_string(), query: pairs.join("&") })
    }

    /// The target of a request carrying a ticket, and that ticket; `None`
    /// unless the query has exactly one `ticket=` pair.
    pub fn of_request(path: &str, query: Option<&str>) -> Option<(Target, String)> {
        let mut ticket = None;
        let mut rest = Vec::new();
        for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
            if is_ticket_pair(pair) {
                if ticket.is_some() {
                    return None;
                }
                ticket = Some(pair[TICKET_PARAM.len() + 1..].to_string());
            } else {
                rest.push(pair);
            }
        }
        Some((Target { path: path.to_string(), query: rest.join("&") }, ticket?))
    }
}

fn is_ticket_pair(pair: &str) -> bool {
    pair.split_once('=').map_or(pair, |(name, _)| name) == TICKET_PARAM
}

#[derive(Debug, PartialEq, Eq)]
pub enum MintError {
    TooMany,
}

struct Entry {
    target: Target,
    expires: Instant,
}

pub struct DownloadTickets {
    ttl: Duration,
    // Keyed by the ticket's SHA-256, so lookups reveal nothing about live tickets
    live: Mutex<HashMap<[u8; 32], Entry>>,
}

impl Default for DownloadTickets {
    fn default() -> Self {
        Self::with_ttl(TICKET_TTL)
    }
}

impl DownloadTickets {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { ttl, live: Mutex::new(HashMap::new()) }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// A new ticket (256 random bits, hex) for one use of `target`.
    pub fn mint(&self, target: Target) -> Result<String, MintError> {
        self.mint_at(target, Instant::now())
    }

    fn mint_at(&self, target: Target, now: Instant) -> Result<String, MintError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS random number generator unavailable");
        let ticket = hex::encode(bytes);
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|_, entry| entry.expires > now);
        if live.len() >= MAX_LIVE_TICKETS {
            return Err(MintError::TooMany);
        }
        live.insert(digest(&ticket), Entry { target, expires: now + self.ttl });
        Ok(ticket)
    }

    /// Uses up `ticket`: true if it was live, unexpired and issued for
    /// exactly `target`. The ticket is gone afterwards either way.
    pub fn redeem(&self, ticket: &str, target: &Target) -> bool {
        self.redeem_at(ticket, target, Instant::now())
    }

    fn redeem_at(&self, ticket: &str, target: &Target, now: Instant) -> bool {
        let entry = self.live.lock().unwrap_or_else(|e| e.into_inner()).remove(&digest(ticket));
        entry.is_some_and(|e| now < e.expires && e.target == *target)
    }
}

fn digest(ticket: &str) -> [u8; 32] {
    Sha256::digest(ticket.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> Target {
        Target::for_url(url).unwrap_or_else(|| panic!("{} is a download target", url))
    }

    fn redeem_url(tickets: &DownloadTickets, url: &str, now: Instant) -> bool {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        match Target::of_request(path, Some(query)) {
            Some((t, ticket)) => tickets.redeem_at(&ticket, &t, now),
            None => false,
        }
    }

    #[test]
    fn only_download_routes_are_targets() {
        for url in [
            "/api/messages/42/download",
            "/api/messages/a%2Fb/download",
            "/api/export/mbox/download?account_id=a&folder_id=b",
            "/api/logs/download",
            "/api/logs/download?file=events.log",
            "/api/accounts/csv-template",
        ] {
            assert!(Target::for_url(url).is_some(), "{}", url);
        }
        for url in [
            "/api/version",
            "/api/settings",
            "/api/logs/clear",
            "/api/download-ticket",
            "/api/messages//download",
            "/api/messages/1/2/download",
            "/api/messages/1",
            "/api/logs/download/",
            "api/logs/download",
            "//evil.example/api/logs/download",
            "http://127.0.0.1:8765/api/logs/download",
            "/api/logs/download#x",
            "/api/logs/download?ticket=abc",
            "/api/logs/download?file=a&ticket",
            "/",
            "",
        ] {
            assert!(Target::for_url(url).is_none(), "{}", url);
        }
    }

    #[test]
    fn a_ticket_works_once_for_exactly_its_target() {
        let tickets = DownloadTickets::default();
        let now = Instant::now();
        let url = "/api/export/mbox/download?account_id=a&folder_id=b";
        let t = tickets.mint_at(target(url), now).unwrap();
        assert_eq!(t.len(), 64);
        assert!(redeem_url(&tickets, &format!("{}&ticket={}", url, t), now));
        assert!(!redeem_url(&tickets, &format!("{}&ticket={}", url, t), now), "single use");

        // The ticket may sit anywhere in the query; empty pairs don't matter
        let t = tickets.mint_at(target(url), now).unwrap();
        let moved = format!("/api/export/mbox/download?ticket={}&account_id=a&&folder_id=b&", t);
        assert!(redeem_url(&tickets, &moved, now));
    }

    #[test]
    fn any_other_target_burns_the_ticket() {
        let tickets = DownloadTickets::default();
        let now = Instant::now();
        let url = "/api/export/mbox/download?account_id=a&folder_id=b";
        for other in [
            "/api/export/mbox/download?account_id=x&folder_id=b",
            "/api/export/mbox/download?account_id=a&folder_id=x",
            "/api/export/mbox/download?account_id=a",
            "/api/export/mbox/download?account_id=a&folder_id=b&extra=1",
            "/api/export/mbox/download?folder_id=b&account_id=a",
            "/api/export/mbox/download?account_id=a&folder_id=b&account_id=x",
            "/api/logs/download?account_id=a&folder_id=b",
        ] {
            let t = tickets.mint_at(target(url), now).unwrap();
            assert!(!redeem_url(&tickets, &format!("{}&ticket={}", other, t), now), "{}", other);
            assert!(!redeem_url(&tickets, &format!("{}&ticket={}", url, t), now), "burned by {}", other);
        }
    }

    #[test]
    fn exactly_one_ticket_parameter_is_accepted() {
        let tickets = DownloadTickets::default();
        let now = Instant::now();
        let t = tickets.mint_at(target("/api/logs/download"), now).unwrap();
        assert!(!redeem_url(&tickets, &format!("/api/logs/download?ticket={}&ticket={}", t, t), now));
        assert!(!redeem_url(&tickets, "/api/logs/download", now));
        assert!(!redeem_url(&tickets, "/api/logs/download?ticket=", now));
        assert!(redeem_url(&tickets, &format!("/api/logs/download?ticket={}", t), now), "untouched by the attempts");
    }

    #[test]
    fn tickets_expire() {
        let tickets = DownloadTickets::default();
        let now = Instant::now();
        let url = "/api/logs/download";
        let t = tickets.mint_at(target(url), now).unwrap();
        assert!(redeem_url(&tickets, &format!("{}?ticket={}", url, t), now + TICKET_TTL - Duration::from_millis(1)));
        let t = tickets.mint_at(target(url), now).unwrap();
        assert!(!redeem_url(&tickets, &format!("{}?ticket={}", url, t), now + TICKET_TTL), "expired at the TTL");
    }

    #[test]
    fn live_tickets_are_capped_and_expired_ones_pruned() {
        let tickets = DownloadTickets::default();
        let now = Instant::now();
        for _ in 0..MAX_LIVE_TICKETS {
            tickets.mint_at(target("/api/logs/download"), now).unwrap();
        }
        assert_eq!(tickets.mint_at(target("/api/logs/download"), now), Err(MintError::TooMany));
        assert!(tickets.mint_at(target("/api/logs/download"), now + TICKET_TTL).is_ok(), "expired ones pruned");
        assert_eq!(tickets.live.lock().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_redemptions_succeed_once() {
        let tickets = std::sync::Arc::new(DownloadTickets::default());
        let url = "/api/messages/7/download";
        let t = tickets.mint(target(url)).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (tickets, barrier, t) = (tickets.clone(), barrier.clone(), t.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    tickets.redeem(&t, &target(url))
                })
            })
            .collect();
        let wins = handles.into_iter().map(|h| h.join().unwrap()).filter(|&w| w).count();
        assert_eq!(wins, 1);
    }
}
