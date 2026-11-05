//! How a server wrote an id attribute that imap-proto couldn't parse.
//!
//! imap-proto 0.17 absorbs an attribute it can't parse into
//! `AttributeValue::Unknown` instead of failing the whole response. Up to
//! MailBackup 0.6.8 (a vendored imap-proto 0.16 with its own `EMAILID`
//! parser, issue #33) two cases were handled differently, and still are:
//!
//! - `EMAILID` with a delimited value, `"(" *<any char but SP ( ) " CTL> ")"`:
//!   only that message has no id and is downloaded in full;
//! - any other `EMAILID` form (`NIL`, no parentheses, a space or quote inside)
//!   or an `X-GM-MSGID` that isn't a number: the response counted as
//!   unparseable, and the source's ids are disabled.
//!
//! This scans one FETCH response's raw bytes for the requested id item,
//! skipping quoted strings and literals (message bodies), to tell which.

use crate::server_ids::ServerIdKind;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AbsorbedId {
    /// A delimited `EMAILID` value: fall back for this message only.
    Delimited,
    /// Any other form: the response counts as unparseable.
    Malformed,
    /// The id item isn't in the response; what was absorbed is something else.
    NotFound,
}

pub(super) fn classify(response: &[u8], kind: ServerIdKind) -> AbsorbedId {
    let Some(open) = find_fetch_list(response) else { return AbsorbedId::NotFound };
    let mut i = open + 1;
    let mut depth = 1usize;
    while i < response.len() && depth > 0 {
        match response[i] {
            b'"' => i = skip_quoted(response, i),
            b'{' => match skip_literal(response, i) {
                Some(next) => i = next,
                None => return AbsorbedId::NotFound,
            },
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
            }
            b' ' | b'\r' | b'\n' => i += 1,
            _ => {
                let start = i;
                i = skip_token(response, i);
                if depth == 1 && response[start..i].eq_ignore_ascii_case(kind.fetch_item().as_bytes()) {
                    return classify_value(&response[i..], kind);
                }
            }
        }
    }
    AbsorbedId::NotFound
}

/// The value after the item name (starting at its separating space).
fn classify_value(rest: &[u8], kind: ServerIdKind) -> AbsorbedId {
    if kind != ServerIdKind::EmailId {
        // X-GM-MSGID is a bare number; one that couldn't be parsed is malformed
        return AbsorbedId::Malformed;
    }
    let Some(value) = rest.strip_prefix(b" (") else { return AbsorbedId::Malformed };
    let end = value.iter().position(|&c| !is_lenient_objectid_char(c));
    match end {
        Some(end) if value[end] == b')' => AbsorbedId::Delimited,
        _ => AbsorbedId::Malformed,
    }
}

fn is_lenient_objectid_char(c: u8) -> bool {
    !matches!(c, b' ' | b'(' | b')' | b'"' | 0x00..=0x1f | 0x7f)
}

/// Index of the `(` opening the attribute list of `* <n> FETCH (`.
fn find_fetch_list(response: &[u8]) -> Option<usize> {
    let head = response.iter().position(|&c| c == b'(')?;
    let before = std::str::from_utf8(&response[..head]).ok()?;
    let mut words = before.split_ascii_whitespace();
    (words.next() == Some("*")
        && words.next().is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        && words.next().is_some_and(|w| w.eq_ignore_ascii_case("FETCH"))
        && words.next().is_none())
    .then_some(head)
}

fn skip_quoted(s: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// `{n}` or `{n+}`, CRLF, n bytes.
fn skip_literal(s: &[u8], i: usize) -> Option<usize> {
    let close = i + s[i..].iter().position(|&c| c == b'}')?;
    let digits = std::str::from_utf8(&s[i + 1..close]).ok()?.trim_end_matches('+');
    let n: usize = digits.parse().ok()?;
    let data = close + 1 + s[close + 1..].strip_prefix(b"\r\n").map(|_| 2)?;
    Some((data + n).min(s.len()))
}

/// An atom, including any `[...]` section (which may hold spaces and
/// parentheses, as in `BODY[HEADER.FIELDS (SUBJECT)]`) and `<n>` partial.
fn skip_token(s: &[u8], mut i: usize) -> usize {
    while i < s.len() {
        match s[i] {
            b'[' => {
                i = s[i..].iter().position(|&c| c == b']').map_or(s.len(), |p| i + p + 1);
            }
            b' ' | b'(' | b')' | b'"' | b'{' | b'\r' | b'\n' => break,
            _ => i += 1,
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch(attr: &str) -> Vec<u8> {
        format!("* 3 FETCH (UID 7 {} RFC822.SIZE 120)\r\n", attr).into_bytes()
    }

    #[test]
    fn delimited_emailid_values_fall_back_for_their_message_only() {
        for attr in ["EMAILID ()", "emailid (pct%x)", "EMAILID (star*x)", "EMAILID (back\\x)", "EMAILID (brace{x)"] {
            assert_eq!(classify(&fetch(attr), ServerIdKind::EmailId), AbsorbedId::Delimited, "{}", attr);
        }
    }

    #[test]
    fn other_emailid_forms_are_malformed() {
        for attr in ["EMAILID NIL", "EMAILID M1", "EMAILID (M1 M2)", "EMAILID (\"M1\")", "EMAILID (unbalanced"] {
            assert_eq!(classify(&fetch(attr), ServerIdKind::EmailId), AbsorbedId::Malformed, "{}", attr);
        }
    }

    #[test]
    fn an_absorbed_gmail_id_is_malformed() {
        assert_eq!(classify(&fetch("X-GM-MSGID abc"), ServerIdKind::GmailMsgId), AbsorbedId::Malformed);
    }

    #[test]
    fn something_else_absorbed_is_not_an_id() {
        assert_eq!(classify(&fetch("X-UNKNOWN (a b)"), ServerIdKind::EmailId), AbsorbedId::NotFound);
    }

    #[test]
    fn bodies_and_strings_are_never_read_as_attributes() {
        let body = "EMAILID NIL\r\n";
        let literal = format!("* 3 FETCH (UID 7 BODY[] {{{}}}\r\n{} X-X (1))\r\n", body.len(), body).into_bytes();
        assert_eq!(classify(&literal, ServerIdKind::EmailId), AbsorbedId::NotFound);
        let quoted = b"* 3 FETCH (UID 7 X-NOTE \"EMAILID NIL\" X-X (1))\r\n";
        assert_eq!(classify(quoted, ServerIdKind::EmailId), AbsorbedId::NotFound);
        let section = b"* 3 FETCH (BODY[HEADER.FIELDS (EMAILID)] {2}\r\nab EMAILID ())\r\n";
        assert_eq!(classify(section, ServerIdKind::EmailId), AbsorbedId::Delimited);
    }

    #[test]
    fn only_top_level_attributes_count() {
        let nested = b"* 3 FETCH (UID 7 X-X (EMAILID NIL))\r\n";
        assert_eq!(classify(nested, ServerIdKind::EmailId), AbsorbedId::NotFound);
    }
}
