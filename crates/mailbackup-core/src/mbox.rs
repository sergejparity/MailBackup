//! Export to mbox files, in the byte-preserving mboxrd variant.
//!
//! Each message is written as an envelope line `From <sender> <date>\n`, the
//! message's own bytes, and one empty line `\n` as the separator. The bytes are
//! copied as stored (CRLF stays CRLF, 8-bit and binary content is untouched);
//! the only change is mboxrd quoting: every line matching `^>*From ` gets one
//! more `>`, so a reader that removes one `>` from such lines and the final
//! `\n` before each envelope gets the original message back. A message that
//! doesn't end in `\n` gets one first, since mbox can't represent that.
//!
//! This is deliberately not RFC 4155's strict default format (which asks for
//! local line endings and plain text): rewriting messages to satisfy it would
//! lose the bytes the archive exists to keep.

use crate::error::Result;
use crate::storage::StorageEngine;
use chrono::{DateTime, Utc};
use mail_parser::MessageParser;
use std::io::{BufWriter, Write};
use std::path::Path;
use tracing::info;

pub struct MboxExporter<'a> {
    storage: &'a StorageEngine,
}

impl<'a> MboxExporter<'a> {
    pub fn new(storage: &'a StorageEngine) -> Self {
        Self { storage }
    }

    /// Streams a list of relative .eml paths to `writer` as mboxrd (see
    /// [`write_message`]).
    pub fn export_to_writer<W: Write>(
        &self,
        eml_relative_paths: &[String],
        mut writer: W,
    ) -> Result<usize> {
        let mut count = 0;

        for rel_path in eml_relative_paths {
            let eml_bytes = match self.storage.read_eml(rel_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!("Skipping {}: {}", rel_path, e);
                    continue;
                }
            };
            write_message(&mut writer, &eml_bytes)?;
            count += 1;
        }

        writer.flush()?;
        Ok(count)
    }

    /// Exports a list of relative .eml paths to an mboxrd file
    pub fn export_to_mbox(
        &self,
        eml_relative_paths: &[String],
        output_path: impl AsRef<Path>,
    ) -> Result<usize> {
        self.export_to_mbox_with(eml_relative_paths, output_path, true)
    }

    /// Like [`Self::export_to_mbox`], but with `overwrite == false` the file is
    /// created exclusively and an existing file is an error.
    pub fn export_to_mbox_with(
        &self,
        eml_relative_paths: &[String],
        output_path: impl AsRef<Path>,
        overwrite: bool,
    ) -> Result<usize> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::private_fs::create_dir_all(parent)?;
            }
        }

        let mut options = crate::private_fs::options();
        options.write(true);
        if overwrite {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let file = options.open(output_path)?;
        let writer = BufWriter::new(file);
        let count = self.export_to_writer(eml_relative_paths, writer)?;
        info!("Exported {} messages to mbox: {}", count, output_path.display());
        Ok(count)
    }
}

/// Writes one message to an mboxrd stream (see the module docs).
pub fn write_message<W: Write>(writer: &mut W, eml: &[u8]) -> std::io::Result<()> {
    let (sender, date) = envelope(eml);
    writeln!(writer, "From {} {}", sender, date.format("%a %b %e %H:%M:%S %Y"))?;
    // Each line with its own ending; the last may have none
    for line in eml.split_inclusive(|&b| b == b'\n') {
        if is_from_line(line) {
            writer.write_all(b">")?;
        }
        writer.write_all(line)?;
    }
    if !eml.is_empty() && !eml.ends_with(b"\n") {
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"\n")
}

/// `^>*From ` — the lines mboxrd quotes.
fn is_from_line(line: &[u8]) -> bool {
    let unquoted = &line[line.iter().take_while(|&&b| b == b'>').count()..];
    unquoted.starts_with(b"From ")
}

/// The envelope sender and date: the From address and Date header, or
/// `MAILER-DAEMON` and now.
fn envelope(eml: &[u8]) -> (String, DateTime<Utc>) {
    let parsed = MessageParser::default().parse(eml);
    let address = parsed.as_ref().and_then(|m| match m.from()? {
        mail_parser::Address::List(list) => list.first()?.address.clone(),
        mail_parser::Address::Group(groups) => groups.first()?.addresses.first()?.address.clone(),
    });
    let date = parsed
        .as_ref()
        .and_then(|m| m.date())
        .and_then(|d| DateTime::from_timestamp(d.to_timestamp(), 0))
        .unwrap_or_else(Utc::now);
    (envelope_sender(address.as_deref().unwrap_or("")), date)
}

/// One printable-ASCII token, so the envelope line stays one line with the
/// sender and date where readers expect them.
fn envelope_sender(address: &str) -> String {
    let sender: String = address.chars().map(|c| if c.is_ascii_graphic() { c } else { '_' }).collect();
    if sender.is_empty() {
        "MAILER-DAEMON".to_string()
    } else {
        sender
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(messages: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in messages {
            write_message(&mut out, m).unwrap();
        }
        out
    }

    /// An mboxrd reader written independently of the writer: a line starting
    /// with `From ` opens a message, `>`+`>*From ` loses one `>`, and exactly
    /// one final `\n` (the separator) is removed from each message.
    fn read_mboxrd(mbox: &[u8]) -> Vec<Vec<u8>> {
        let mut messages: Vec<Vec<u8>> = Vec::new();
        for line in mbox.split_inclusive(|&b| b == b'\n') {
            if line.starts_with(b"From ") {
                assert!(line.ends_with(b"\n"), "envelope line ends the line");
                messages.push(Vec::new());
                continue;
            }
            let message = messages.last_mut().expect("nothing before the first envelope");
            let quotes = line.iter().take_while(|&&b| b == b'>').count();
            if quotes > 0 && line[quotes..].starts_with(b"From ") {
                message.extend_from_slice(&line[1..]);
            } else {
                message.extend_from_slice(line);
            }
        }
        for message in &mut messages {
            assert_eq!(message.pop(), Some(b'\n'), "one separator per message");
        }
        messages
    }

    fn round_trip(messages: &[&[u8]]) -> Vec<Vec<u8>> {
        read_mboxrd(&export(messages))
    }

    #[test]
    fn output_matches_a_handwritten_fixture() {
        let first: &[u8] = b"From: Alice <alice@example.com>\r\nDate: Fri, 01 Jan 2021 09:05:03 +0000\r\n\r\nFrom here\r\n>From there\r\n>>From everywhere\r\nFrom:x\r\n";
        let second: &[u8] = b"From: bob@example.com\nDate: Sun, 14 Feb 2021 23:59:59 +0000\n\nno newline at the end";
        let expected: &[u8] = b"From alice@example.com Fri Jan  1 09:05:03 2021\n\
From: Alice <alice@example.com>\r\n\
Date: Fri, 01 Jan 2021 09:05:03 +0000\r\n\
\r\n\
>From here\r\n\
>>From there\r\n\
>>>From everywhere\r\n\
From:x\r\n\
\n\
From bob@example.com Sun Feb 14 23:59:59 2021\n\
From: bob@example.com\n\
Date: Sun, 14 Feb 2021 23:59:59 +0000\n\
\n\
no newline at the end\n\
\n";
        assert_eq!(String::from_utf8_lossy(&export(&[first, second])), String::from_utf8_lossy(expected));
    }

    #[test]
    fn messages_round_trip_byte_for_byte() {
        let messages: Vec<&[u8]> = vec![
            b"From: a@x\r\nSubject: quoting\r\n\r\nFrom the start\r\n>From one\r\n>>From two\r\n>>>From x\r\nFrom \r\n",
            b"From: b@x\n\nFrom right after the headers\nmixed\r\nendings\nlone\rcr\r\n",
            b"From: c@x\r\nContent-Type: text/plain; charset=latin-1\r\n\r\ncaf\xe9 \xff\xfe \x00 nul\r\nFrom \xe9\r\n",
            b"From: d@x\r\n\r\nends on a From line\r\nFrom ",
        ];
        let back = round_trip(&messages);
        assert_eq!(back.len(), messages.len());
        for (original, read) in messages.iter().zip(&back).take(3) {
            assert_eq!(read.as_slice(), *original);
        }
        // The last one had no final line ending: exactly one \n is added
        assert_eq!(back[3], [messages[3], b"\n"].concat());
    }

    #[test]
    fn trailing_blank_lines_and_empty_messages_are_kept() {
        let messages: Vec<&[u8]> = vec![b"From: a@x\n\nbody\n\n\n", b"", b"From: b@x\r\n\r\nbody\r\n\r\n\r\n", b"\n", b"\r\n"];
        let back = round_trip(&messages);
        assert_eq!(back.len(), messages.len());
        for (original, read) in messages.iter().zip(&back) {
            assert_eq!(read.as_slice(), *original);
        }
    }

    #[test]
    fn a_final_lone_cr_gets_the_framing_lf() {
        let back = round_trip(&[b"From: a@x\r\n\r\nends in CR\r", b"From: b@x\n\nnext\n"]);
        assert_eq!(back[0], b"From: a@x\r\n\r\nends in CR\r\n", "the one added byte");
        assert_eq!(back[1], b"From: b@x\n\nnext\n");
    }

    #[test]
    fn many_from_lines_never_split_a_message() {
        let body = "From: a@x\n\n".to_string() + &"From me\n>From you\n\nFrom \n".repeat(50);
        let back = round_trip(&[body.as_bytes(), body.as_bytes(), body.as_bytes()]);
        assert_eq!(back.len(), 3);
        assert!(back.iter().all(|m| m == body.as_bytes()));
    }

    #[test]
    fn only_from_space_lines_are_quoted() {
        let message: &[u8] = b"From: a@x\nfrom lower\n From indented\n>From\n>>Fromage\nsay From \nFrom:\n\n";
        let out = export(&[message]);
        let body = &out[out.iter().position(|&b| b == b'\n').unwrap() + 1..];
        assert_eq!(body, [message, b"\n"].concat().as_slice(), "nothing quoted");
    }

    fn envelope_line(message: &[u8]) -> String {
        let out = export(&[message]);
        String::from_utf8(out[..out.iter().position(|&b| b == b'\n').unwrap()].to_vec()).unwrap()
    }

    /// `From <token> <Www Mmm dd hh:mm:ss yyyy>`
    fn assert_envelope_shape(line: &str) {
        let rest = line.strip_prefix("From ").unwrap_or_else(|| panic!("{:?}", line));
        let (sender, date) = rest.split_once(' ').unwrap();
        assert!(!sender.is_empty() && sender.chars().all(|c| c.is_ascii_graphic()), "{:?}", line);
        assert!(chrono::NaiveDateTime::parse_from_str(date, "%a %b %e %H:%M:%S %Y").is_ok(), "{:?}", line);
    }

    #[test]
    fn the_envelope_sender_is_one_safe_token() {
        assert_eq!(envelope_sender("alice@example.com"), "alice@example.com");
        assert_eq!(envelope_sender("a b\tc\r\nFrom evil@x"), "a_b_c__From_evil@x");
        assert_eq!(envelope_sender("josé@exämple.com"), "jos_@ex_mple.com");
        assert_eq!(envelope_sender(""), "MAILER-DAEMON");

        for message in [
            &b"From: \"a b\"@example.com\r\nDate: Fri, 01 Jan 2021 00:00:00 +0000\r\n\r\nx\r\n"[..],
            b"From: =?utf-8?q?x?= <j=C3=B6rg@example.com>\r\n\r\nx\r\n",
            b"Subject: no sender\r\n\r\nx\r\n",
            b"\xff\xfe not a message at all",
            b"",
        ] {
            assert_envelope_shape(&envelope_line(message));
        }
        assert!(envelope_line(b"Subject: none\r\n\r\nx\r\n").starts_with("From MAILER-DAEMON "));
        let quoted = envelope_line(b"From: Name <\"a b\"@example.com>\r\n\r\nx\r\n");
        assert!(quoted.contains("a_b"), "{:?}", quoted);
    }
}
