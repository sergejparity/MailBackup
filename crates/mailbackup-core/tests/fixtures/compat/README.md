# Compatibility fixtures (issue #40)

Files written **once** by MailBackup itself, before the dependency upgrades
tracked in #39, so later versions can prove they still read them the same way.
`WRITER.json` records the version and commit that wrote them.

- `credentials/`: credential stores (version 2 in key-file, keyring and
  passphrase/Argon2id modes, plus pre-0.2.20 legacy formats) and the keyring
  namespace of a fixed folder. Synthetic secrets only.
- `catalog/`: a catalog database with its data folder (UID generations,
  duplicates, re-binds by content and server id, `needs_check`, an archive
  transition and an outstanding one, FTS, attachments), and `snapshot.json`,
  every row as written.
- `eml/`: the raw messages archived in `catalog/data`, byte for byte (CRLF, LF,
  8-bit, no final newline).
- `config/`: a `config.yaml` as `AppConfig::save` writes it.

Rules:

- Tests (`tests/compat_fixtures.rs`) work on copies and never write here.
- **Never regenerate** these with upgraded dependencies. The generator
  (`tests/compat_generate.rs`) refuses to overwrite them. If a format changes on
  purpose, add a new, separately versioned fixture set and keep this one.
- Git must not touch line endings here (see `.gitattributes`).
