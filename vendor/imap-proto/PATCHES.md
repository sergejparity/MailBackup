# Vendored imap-proto 0.16.7: local patches

MailBackup uses this copy through `[patch.crates-io]` in the workspace
`Cargo.toml`, for issue #33 (server-guaranteed message ids). It is
imap-proto 0.16.7 from crates.io (MIT OR Apache-2.0, © Dirkjan Ochtman and
contributors; see `LICENSE-MIT` and `LICENSE-APACHE`) with only these changes:

1. `src/parser/rfc8474.rs` (new): parses the RFC 8474 `EMAILID (<value>)`
   fetch attribute. The value is accepted leniently: any run, possibly empty,
   of bytes other than SP, `(`, `)`, `"` and CTLs. The caller validates it
   against `objectid`, so a malformed but delimited value is rejected for
   that message alone instead of making the whole response unparseable.
2. `src/parser/rfc3501/mod.rs`: `msg_att` tries `msg_att_email_id`.
3. `src/parser/mod.rs`: declares the `rfc8474` module.
4. `src/types.rs`: `AttributeValue::EmailId(Cow<str>)` (and its
   `into_owned` arm), plus `Attribute::EmailId`.
5. `src/builders/command.rs`: `Attribute::EmailId` renders as `EMAILID`.
6. `Cargo.toml.orig` and `Cargo.lock` removed; `LICENSE-*` and this file added.

Without patch 1, a server's `EMAILID` in a FETCH response is a parse error,
and async-imap's stream can't get past it.

To be offered upstream (djc/tokio-imap). Remove this directory and the
`[patch.crates-io]` entry once an imap-proto release parses `EMAILID`.

Run the tests: `cargo test --manifest-path vendor/imap-proto/Cargo.toml`.
