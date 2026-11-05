//! The attachments of a parsed message, as MailBackup lists them: every part
//! a user may want to save, with its name, MIME type and decoded size.
//!
//! mail-parser 1.x follows RFC 8621, which shows image, audio and video parts
//! marked inline in the message body and leaves them out of
//! `attachments()` (a photo pasted into a `multipart/mixed` mail, as Apple
//! Mail sends it). MailBackup has always listed those too, so they are added
//! back here, in document order.

use mail_parser::{Message, MessagePart, PartRole};

/// The attachment parts of `message`'s root message, in document order.
pub fn parts<'m>(message: &'m Message<'_>) -> impl Iterator<Item = MessagePart<'m>> {
    message.root().parts().filter(|part| part.is_attachment() || part.role() == PartRole::MediaBody)
}

/// `(name, MIME type, size in bytes)` of each attachment: the name is
/// `unnamed` when the part has none, the type is the top-level type only
/// (`image`, `application`, …), and the size is that of the decoded content.
pub fn summaries(message: &Message<'_>) -> Vec<(String, String, u64)> {
    parts(message)
        .map(|part| {
            let name = part.attachment_name().unwrap_or("unnamed").to_string();
            let mime = part.content_type().map(|c| c.ctype().to_string()).unwrap_or_else(|| "application/octet-stream".to_string());
            (name, mime, part.decoded().len() as u64)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MessageParser;

    fn summaries_of(raw: &str) -> Vec<(String, String, u64)> {
        summaries(&MessageParser::default().parse(raw.as_bytes()).unwrap())
    }

    #[test]
    fn inline_media_in_mixed_is_listed_with_real_attachments() {
        let raw = "From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nSee the photo\r\n\
                   --B\r\nContent-Type: image/jpeg; name=photo.jpg\r\nContent-Disposition: inline; filename=photo.jpg\r\nContent-Transfer-Encoding: base64\r\n\r\n/9j/4AAQ\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nSent from my phone\r\n\
                   --B\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0x\r\n\
                   --B--\r\n";
        assert_eq!(
            summaries_of(raw),
            vec![
                ("photo.jpg".to_string(), "image".to_string(), 6),
                ("report.pdf".to_string(), "application".to_string(), 6),
            ]
        );
    }

    #[test]
    fn body_parts_are_not_attachments() {
        let raw = "From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nplain\r\n\
                   --B\r\nContent-Type: text/html\r\n\r\n<b>html</b>\r\n\
                   --B--\r\n";
        assert!(summaries_of(raw).is_empty());
    }

    #[test]
    fn unnamed_parts_and_nested_messages() {
        let raw = "From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
                   --B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment\r\n\r\nraw\r\n\
                   --B\r\nContent-Type: message/rfc822\r\n\r\nFrom: inner@example.com\r\nSubject: inner\r\n\r\ninner body\r\n\
                   --B--\r\n";
        let found = summaries_of(raw);
        assert_eq!(found.len(), 2, "{:?}", found);
        assert_eq!(found[0], ("unnamed".to_string(), "application".to_string(), 3));
        assert_eq!((found[1].0.as_str(), found[1].1.as_str()), ("unnamed", "message"));
    }
}
