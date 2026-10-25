//! Server-guaranteed message ids (issue #33): RFC 8474 `EMAILID` and Gmail's
//! `X-GM-MSGID`. A server promises that such an id names one immutable
//! message within its mailbox store, so a re-scan of the *same* server can
//! re-bind an archived copy by id without downloading the body again, if
//! the account opted in (`AccountConfig::trust_server_ids`).
//!
//! Ids are only ever compared within one kind and one source (the account's
//! remote identity they were fetched from).

/// Which id namespace a [`ServerId`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerIdKind {
    /// RFC 8474 `EMAILID`, advertised as `OBJECTID`. Compared case-sensitively.
    EmailId,
    /// Gmail's `X-GM-MSGID`, advertised as `X-GM-EXT-1`. An unsigned 64-bit
    /// number, stored as its decimal text.
    GmailMsgId,
}

impl ServerIdKind {
    /// The name stored in the catalog.
    pub fn as_str(self) -> &'static str {
        match self {
            ServerIdKind::EmailId => "emailid",
            ServerIdKind::GmailMsgId => "gm-msgid",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "emailid" => Some(ServerIdKind::EmailId),
            "gm-msgid" => Some(ServerIdKind::GmailMsgId),
            _ => None,
        }
    }

    /// The capability that offers this kind.
    pub fn capability(self) -> &'static str {
        match self {
            ServerIdKind::EmailId => "OBJECTID",
            ServerIdKind::GmailMsgId => "X-GM-EXT-1",
        }
    }

    /// The FETCH item that asks for it.
    pub fn fetch_item(self) -> &'static str {
        match self {
            ServerIdKind::EmailId => "EMAILID",
            ServerIdKind::GmailMsgId => "X-GM-MSGID",
        }
    }

    /// The kind a server with these capabilities offers, `EMAILID` first.
    pub fn offered(has_capability: impl Fn(&str) -> bool) -> Option<Self> {
        [ServerIdKind::EmailId, ServerIdKind::GmailMsgId].into_iter().find(|k| has_capability(k.capability()))
    }
}

/// A server's id of one message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerId {
    pub kind: ServerIdKind,
    pub value: String,
}

impl ServerId {
    /// An `EMAILID` value, if it is a valid RFC 8474 `objectid`:
    /// 1–255 of `ALPHA / DIGIT / "_" / "-"`.
    pub fn email_id(value: &str) -> Option<Self> {
        let valid = (1..=255).contains(&value.len())
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        valid.then(|| ServerId { kind: ServerIdKind::EmailId, value: value.to_string() })
    }

    pub fn gmail_msg_id(value: u64) -> Self {
        ServerId { kind: ServerIdKind::GmailMsgId, value: value.to_string() }
    }
}

/// A server id together with the remote identity it was fetched from.
#[derive(Debug, Clone, Copy)]
pub struct SourcedId<'a> {
    pub id: &'a ServerId,
    pub source: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objectid_syntax() {
        assert!(ServerId::email_id("M6d99ac3275bb4e").is_some());
        assert!(ServerId::email_id("a-_9").is_some());
        assert!(ServerId::email_id(&"x".repeat(255)).is_some());
        for bad in ["", "bad.value", "a@b", "with space", "é", &"x".repeat(256)] {
            assert!(ServerId::email_id(bad).is_none(), "{:?}", bad);
        }
    }

    #[test]
    fn gmail_ids_keep_the_full_unsigned_range() {
        assert_eq!(ServerId::gmail_msg_id(u64::MAX).value, "18446744073709551615");
    }

    #[test]
    fn emailid_is_preferred_when_both_are_offered() {
        assert_eq!(ServerIdKind::offered(|_| true), Some(ServerIdKind::EmailId));
        assert_eq!(ServerIdKind::offered(|c| c == "X-GM-EXT-1"), Some(ServerIdKind::GmailMsgId));
        assert_eq!(ServerIdKind::offered(|_| false), None);
    }
}
