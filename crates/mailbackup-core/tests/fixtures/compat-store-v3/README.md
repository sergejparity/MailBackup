# Version 3 credential store fixtures (issue #75)

Written **once** by `generate_store_v3_fixtures` in `tests/compat_generate.rs`
(see `WRITER.json`), with the same synthetic scenarios as
`../compat/credentials/key-file` and `../compat/credentials/passphrase`: the
first version whose values (`enc:v2:`) are bound to their entry and binding
with associated data.

- `key-file/`: key-file mode with a legacy `~/.mailbackup` location (`home/`).
- `passphrase/`: Argon2id passphrase mode.

Same rules as `../compat/README.md`: tests read copies, and these files are
never regenerated. A later format change adds another set.
