//!
//! https://tools.ietf.org/html/rfc8474
//!
//! IMAP Extension for Object Identifiers
//!
//! Patched into this vendored copy for MailBackup (see PATCHES.md). Only the
//! `EMAILID` fetch attribute is parsed. The value is accepted leniently and
//! left for the caller to validate against `objectid`
//! (1*255(ALPHA / DIGIT / "_" / "-")), so a server sending a malformed but
//! delimited value doesn't make the whole response unparseable.

use nom::{
    bytes::streaming::{tag, tag_no_case, take_while},
    combinator::map,
    sequence::{delimited, preceded},
    IResult,
};

use crate::types::AttributeValue;

fn is_lenient_objectid_char(c: u8) -> bool {
    !matches!(c, b' ' | b'(' | b')' | b'"' | 0x00..=0x1f | 0x7f)
}

// [RFC8474 - 7. Formal Syntax - fetch-emailid-resp](https://tools.ietf.org/html/rfc8474#section-7)
pub(crate) fn msg_att_email_id(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        preceded(
            tag_no_case("EMAILID "),
            delimited(tag("("), take_while(is_lenient_objectid_char), tag(")")),
        ),
        |raw: &[u8]| AttributeValue::EmailId(String::from_utf8_lossy(raw)),
    )(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use crate::parser::parse_response;
    use crate::types::Response;

    #[test]
    fn parses_emailid_values_leniently() {
        for (input, value) in [
            (&b"EMAILID (M6d99ac3275bb4e) "[..], "M6d99ac3275bb4e"),
            (b"emailid (Mabc-_9) ", "Mabc-_9"),
            (b"EMAILID () ", ""),
            (b"EMAILID (bad.value@x) ", "bad.value@x"),
        ] {
            match msg_att_email_id(input) {
                Ok((_, AttributeValue::EmailId(v))) => assert_eq!(v, value),
                other => panic!("{:?}: {:?}", String::from_utf8_lossy(input), other),
            }
        }
    }

    #[test]
    fn rejects_undelimited_emailid_syntax() {
        for input in [&b"EMAILID NIL "[..], b"EMAILID M1 ", b"EMAILID (M1 M2) ", b"EMAILID (\"M1\") "] {
            assert!(
                !matches!(msg_att_email_id(input), Ok(_)),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn emailid_in_a_fetch_response() {
        let line = b"* 3 FETCH (UID 7 RFC822.SIZE 120 EMAILID (Mabc))\r\n";
        let (rest, resp) = parse_response(line).unwrap();
        assert!(rest.is_empty());
        match resp {
            Response::Fetch(3, attrs) => {
                assert!(attrs.contains(&AttributeValue::EmailId(Cow::Borrowed("Mabc"))));
                assert!(attrs.contains(&AttributeValue::Uid(7)));
            }
            other => panic!("{:?}", other),
        }
    }
}
