//! Preparing archived HTML mail for the web viewer.
//!
//! Inline images (`<img src="cid:…">`) refer to other MIME parts of the same
//! message. Browsers can't resolve `cid:` URLs, so they're replaced with
//! `data:` URIs of the matching image parts, within size limits. References
//! that can't be resolved stay `cid:`, which loads nothing.

use base64::Engine;
use mail_parser::{Message, MimeHeaders};
use std::collections::HashMap;

/// Largest single image inlined as a `data:` URI.
pub const MAX_INLINE_IMAGE_BYTES: usize = 5 * 1024 * 1024;
/// Largest total of inlined image data per message, counted for every
/// reference: an image referenced twice counts twice, so the generated HTML
/// stays bounded however often a mail repeats a reference.
pub const MAX_INLINE_TOTAL_BYTES: usize = 20 * 1024 * 1024;

/// `html` with `cid:` references to `message`'s image parts replaced by
/// `data:` URIs (see the module docs).
pub fn inline_cid_images(html: &str, message: &Message) -> String {
    let images: HashMap<String, (String, &[u8])> = message
        .parts
        .iter()
        .filter_map(|part| {
            let id = normalize_content_id(part.content_id()?);
            let ctype = part.content_type()?;
            if !ctype.ctype().eq_ignore_ascii_case("image") {
                return None;
            }
            let subtype = ctype.subtype()?;
            // Only plain image types; never something a browser could run
            if !subtype.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.') {
                return None;
            }
            let mime = format!("image/{}", subtype.to_ascii_lowercase());
            Some((id, (mime, part.contents())))
        })
        .collect();
    if images.is_empty() {
        return html.to_string();
    }
    inline_with(html, |id| images.get(&normalize_content_id(id)).map(|(m, b)| (m.as_str(), *b)))
}

/// Replaces each `cid:<id>` (case-insensitive scheme) for which `lookup`
/// returns an image, within the size limits. The id ends at a quote, `)`,
/// whitespace or `>`.
fn inline_with<'a>(html: &str, lookup: impl Fn(&str) -> Option<(&'a str, &'a [u8])>) -> String {
    let mut out = String::with_capacity(html.len());
    let mut total = 0usize;
    // id -> (data: URI, size of the image it holds)
    let mut encoded: HashMap<String, (String, usize)> = HashMap::new();
    let mut rest = html;
    while let Some(pos) = find_cid(rest) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 4..];
        let end = after
            .find(|c: char| c == '"' || c == '\'' || c == ')' || c == '>' || c.is_whitespace())
            .unwrap_or(after.len());
        let raw_id = &after[..end];
        let id = percent_decode(raw_id);
        if !encoded.contains_key(&id) {
            if let Some((mime, bytes)) = lookup(&id).filter(|(_, b)| b.len() <= MAX_INLINE_IMAGE_BYTES) {
                let uri = format!("data:{};base64,{}", mime, base64::engine::general_purpose::STANDARD.encode(bytes));
                encoded.insert(id.clone(), (uri, bytes.len()));
            }
        }
        // Every reference, repeated ones included, is charged to the budget
        match encoded.get(&id) {
            Some((uri, size)) if total + size <= MAX_INLINE_TOTAL_BYTES => {
                total += size;
                out.push_str(uri);
            }
            _ => out.push_str(&rest[pos..pos + 4 + end]),
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Byte offset of the next `cid:` (any case).
fn find_cid(s: &str) -> Option<usize> {
    s.as_bytes().windows(4).position(|w| w.eq_ignore_ascii_case(b"cid:"))
}

/// Content-IDs compare without the surrounding `<>` and case-insensitively.
fn normalize_content_id(id: &str) -> String {
    id.trim().trim_start_matches('<').trim_end_matches('>').to_ascii_lowercase()
}

/// `cid:` URLs are URL-encoded Content-IDs (RFC 2392).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = s.get(i + 1..i + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MessageParser;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake";

    fn message(parts: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut eml = String::from(
            "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"b\"\r\n\r\n\
             --b\r\nContent-Type: text/html\r\n\r\n<p>body</p>\r\n",
        );
        for (cid, ctype, body) in parts {
            eml.push_str(&format!(
                "--b\r\nContent-Type: {}\r\nContent-ID: {}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
                ctype,
                cid,
                base64::engine::general_purpose::STANDARD.encode(body)
            ));
        }
        eml.push_str("--b--\r\n");
        eml.into_bytes()
    }

    #[test]
    fn matching_image_parts_become_data_uris() {
        let raw = message(&[("<logo@x>", "image/png", PNG), ("pic@x", "image/JPEG", b"jpg")]);
        let msg = MessageParser::default().parse(&raw).unwrap();
        let html = r#"<img src="cid:logo@x"><img src='CID:Pic@X'><div style="background:url(cid:logo@x)"></div>"#;
        let out = inline_cid_images(html, &msg);
        let png = format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(PNG));
        assert_eq!(out.matches(&png).count(), 2, "{}", out);
        assert!(out.contains("src='data:image/jpeg;base64,anBn'"), "{}", out);
        assert!(!out.to_ascii_lowercase().contains("cid:"));
    }

    #[test]
    fn unknown_ids_and_non_images_stay_as_they_are() {
        let raw = message(&[("<doc@x>", "text/html", b"<script>alert(1)</script>"), ("<svg@x>", "image/svg+xml", b"<svg/>")]);
        let msg = MessageParser::default().parse(&raw).unwrap();
        let html = r#"<img src="cid:doc@x"><img src="cid:missing@x"><iframe src="cid:doc@x">"#;
        assert_eq!(inline_cid_images(html, &msg), html);
        // svg is an image type and inlined; as an <img> it can't run scripts
        let out = inline_cid_images(r#"<img src="cid:svg@x">"#, &msg);
        assert!(out.starts_with(r#"<img src="data:image/svg+xml;base64,"#), "{}", out);
    }

    #[test]
    fn size_limits_are_enforced() {
        let big = vec![0u8; MAX_INLINE_IMAGE_BYTES + 1];
        let out = inline_with(r#"<img src="cid:big">"#, |_| Some(("image/png", big.as_slice())));
        assert_eq!(out, r#"<img src="cid:big">"#);

        // 4.5 MiB each: four fit in the 20 MiB total, the fifth doesn't
        let chunk = vec![1u8; MAX_INLINE_IMAGE_BYTES * 9 / 10];
        let html = r#"<img src="cid:a"><img src="cid:b"><img src="cid:c"><img src="cid:d"><img src="cid:e"><img src="cid:a">"#;
        let out = inline_with(html, |_| Some(("image/png", chunk.as_slice())));
        assert_eq!(out.matches("data:image/png").count(), 4, "a, b, c, d");
        assert!(out.contains(r#"src="cid:e""#), "over the total");
        assert!(out.ends_with(r#"<img src="cid:a">"#), "a repeated reference counts toward the total too");
    }

    #[test]
    fn many_references_to_one_image_stay_bounded() {
        let image = vec![7u8; MAX_INLINE_IMAGE_BYTES];
        let html = r#"<img src="cid:one">"#.repeat(1000);
        let out = inline_with(&html, |_| Some(("image/png", image.as_slice())));
        let inlined = out.matches("data:image/png").count();
        assert_eq!(inlined, MAX_INLINE_TOTAL_BYTES / MAX_INLINE_IMAGE_BYTES);
        // Output stays within the budget (base64 is 4/3 of the raw size) plus the original HTML
        assert!(out.len() <= MAX_INLINE_TOTAL_BYTES / 3 * 4 + 64 * inlined + html.len(), "{} bytes", out.len());
        assert_eq!(out.matches(r#"src="cid:one""#).count(), 1000 - inlined);
    }

    #[test]
    fn ids_are_url_decoded_and_html_without_cids_is_unchanged() {
        let png = PNG;
        let out = inline_with(r#"<img src="cid:a%40b">"#, |id| (id == "a@b").then_some(("image/png", png)));
        assert!(out.contains("data:image/png;base64,"));
        let plain = "<p>no inline images, just cid in text: cid</p>";
        assert_eq!(inline_with(plain, |_| None), plain);
    }
}
