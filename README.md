<div align="center">
  <img src="assets/logo.png" alt="MailBackup Studio" width="440" />

  # MailBackup Studio 📬

  <p><strong>A high-performance, resilient, and non-destructive Email Backup Utility written in Rust.</strong></p>

  <p>
    <img src="https://img.shields.io/badge/rust-2021-orange.svg" alt="Rust Edition 2021" />
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue.svg" alt="Cross Platform" />
    <img src="https://img.shields.io/badge/storage-EML%20%2B%20SQLite%20FTS5-purple.svg" alt="Storage" />
    <img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-green.svg" alt="License" />
  </p>
</div>

Built with a modular architecture featuring:
- **CLI**: Rapid commands with Rich progress bars, interactive setup wizard, FTS5 search, and headless daemon.
- **Embedded Web UI**: Modern dark-mode SPA (HTML5, Vanilla CSS, JS) embedded directly in the binary with zero external runtime dependencies.
- **Desktop GUI**: Native desktop application with system tray integration and notifications via Tauri.
- **Raw Fidelity Storage**: Lossless `.eml` files (RFC 822/5322) preserving headers, attachments, and signatures bit-for-bit.
- **Mbox Export**: On-demand and scheduled export to standard RFC 4155 `.mbox` archives.
- **Strictly Non-Destructive**: Never deletes messages from remote mail servers (`EXAMINE` read-only IMAP mode).
- **SQLite Catalog & FTS5**: Sub-second full-text search across all accounts, subjects, senders, body texts, and attachment names.
- **Configurable Retention**: Automatic local pruning policy (e.g. retain 90 days, 1 year, or keep forever).
- **Security**: OS Keyring integration (macOS Keychain, Windows Credential Manager, Linux Secret Service) with secure local fallback.

---

## Workspace Structure

```
├── Cargo.toml                    # Root workspace configuration
├── crates
│   ├── mailbackup-core           # Core engine: IMAP, SQLite FTS5, Storage, Mbox, Retention, Scheduler
│   ├── mailbackup-cli            # Command-line interface binary (`mailbackup`)
│   ├── mailbackup-server         # REST API server & embedded Web UI (`mailbackup-server`)
│   └── mailbackup-gui            # Native Desktop GUI with System Tray (`mailbackup-gui`)
```

---

## Getting Started

### 1. Build All Binaries

```bash
cargo build --release --workspace
```

### 2. Using the CLI

```bash
# Add an account interactively
cargo run -p mailbackup-cli -- account add

# List configured accounts and storage stats
cargo run -p mailbackup-cli -- account list

# Test IMAP connection
cargo run -p mailbackup-cli -- account test <account_id>

# Run incremental backup
cargo run -p mailbackup-cli -- sync

# Search email archives with instant FTS5 matching
cargo run -p mailbackup-cli -- search "invoice"

# Export a folder or entire account to .mbox
cargo run -p mailbackup-cli -- export-mbox --account <id> --output ./archive.mbox

# Run background scheduled sync daemon
cargo run -p mailbackup-cli -- daemon

# Launch Web Studio
cargo run -p mailbackup-cli -- serve --port 8765
```

### 3. Launching the Web Studio

```bash
cargo run -p mailbackup-server
```

Open your browser at `http://127.0.0.1:8765` to access the full offline email browser, attachment previewer, and account manager.

**API access:** the server listens on `127.0.0.1` only. Every `/api/*` request must carry a random per-process token, which the server embeds in the page it serves, so other websites and DNS-rebinding attacks can't call the API. The token changes whenever the server restarts, so reload open browser tabs after a restart.

Network settings in `config.yaml`:

```yaml
settings:
  web_port: 8765
  # Interface to listen on. Default: 127.0.0.1 (this computer only).
  # Use 0.0.0.0 to reach the Web Studio from other devices or from outside a
  # container. Anyone who can reach the port still needs the token, which they
  # can only get by loading the page, so only do this on networks you trust.
  bind_address: 127.0.0.1
  # Host names (besides IP addresses and localhost) the UI may be opened by,
  # e.g. the domain of a reverse proxy in front of the server. Only list
  # names you control.
  allowed_hosts: []
```

**Upgrading from 0.2.4 or earlier:** older versions listened on all interfaces (`0.0.0.0`) and accepted API calls from anywhere without a token.
- The desktop app, the Windows/macOS/Linux background service and local browser access are unaffected, because they all use `127.0.0.1`.
- If you opened the Web Studio from another device, or run it in a container with a published port, set `bind_address: 0.0.0.0`.
- If you use a reverse proxy with its own domain name, add that name to `allowed_hosts`. The proxy must pass the `X-MailBackup-Token` header through.
- Scripts that called `/api/*` directly now need the token. It's printed nowhere and changes on every start, so the API is meant to be used through the web UI only.

**Reading HTML mail:** messages are shown in a sandboxed frame that can't run scripts, submit forms, open windows or reach the app.
- **Blocked by default:** remote images, stylesheets and fonts. Opening a mail doesn't tell the sender you read it and doesn't reveal your IP address.
- **Removed from every mail:** auto-refresh redirects, `<base>` and prefetch/preconnect hints.
- **Images sent inside the mail** (`cid:`) are shown, up to 5 MB per image and 20 MB per message.
- **Load remote content:** when a mail references remote content, a notice above it offers this button. It applies to that message only, until you open another.

**Export and storage locations (web UI):**
- `.mbox` exports, and moves of the archive folder or database, are limited to your Downloads, Documents and Desktop folders, your home folder, and folders you've chosen with **Browse…**. Browse adds the folder to `settings.approved_dirs` in `config.yaml`; remove entries there to revoke them.
- Exports must end in `.mbox`, can't go into hidden (`.`) folders, and never overwrite symlinks or folders.
- A new archive folder must be new or empty (macOS/Windows metadata files such as `.DS_Store` are ignored). An existing MailBackup archive, for example on an external drive, can be used in place with "Move existing backup files" unticked. A new database path must end in `.db`.
- The CLI (`export-mbox`) is not restricted.

**Account passwords are tied to their server:** each saved password is bound to the account's server, port and username.
- Changing any of these in the web UI requires entering the password again.
- If `config.yaml` is edited to point an account somewhere else, sync refuses to send the old password ("The saved password … belongs to a different server …") until it is re-entered.
- Passwords saved by older versions are bound to the current settings the first time they're used.

**Where passwords are kept:** in the OS keyring: the macOS Keychain, the Windows Credential Manager, or the Secret Service on Linux (GNOME Keyring, KWallet).
- **No keyring:** on a headless Linux machine, or with `MAILBACKUP_KEYRING=none`, passwords go to the local encrypted store instead: `.credentials_store.json` next to `config.yaml`.
- **Locked keyring:** if the keyring is locked or refuses access, MailBackup reports that. It never quietly writes the password to disk instead.
- **Moving into the keyring:** passwords saved by older versions are in the local store. Each one moves into the keyring the first time it's used, and the local copy is removed only after the keyring copy has been read back.
- **Separate per config:** each config's keyring entries are named after its folder, so two configs with the same account ID never overwrite each other.
- **Same store for every process:** the CLI, the web server and the background service use the same store for the same `config.yaml`, even with a custom `--config` path. Older CLI versions kept passwords for a custom `--config` in `~/.mailbackup`; they're still found there and copied over. Removing the account also removes that copy, and a removed password is never read from there again.

**Local credential store:** each password is encrypted with AES-256-GCM.
- **Key:** by default, a random key in `.credentials_key`. If `MAILBACKUP_MASTER_KEY` is set, the key is derived from that passphrase with Argon2id, using a random salt stored in the file.
- **Older files** are upgraded automatically the first time they're read. This also covers files that older versions protected with a weaker key.
- **Problems are reported, never papered over.** A store that can't be read is reported instead of being treated as empty, and it's never overwritten: a wrong passphrase, a missing or replaced key file, a locked keyring, or a damaged file.
- **Limit:** whoever can read both the store and its key file (your account or an administrator) can read the passwords. File permissions keep other users out.

**Background service:** Settings → "Run as OS Background Service" installs a service that starts at boot and runs **as your user account**, not as root/SYSTEM:
- Linux: a systemd unit with `User=`.
- macOS: a LaunchDaemon with `UserName`.
- Windows: a boot task with your account and S4U logon. This needs the "Log on as a batch job" right, which domain policy can remove.

The service starts at boot, before anyone logs in, when the keyring is locked or not there yet. So turning it on moves the passwords into the local encrypted store:
- **Turning it on:** all passwords and their server bindings are copied to the local store and read back, the way the service will read them, before the service is installed. If the install fails, the copies are removed again, but only those the keyring still holds.
- **While it's on:** new passwords are saved to the local store.
- **Turning it off:** the service is removed and confirmed gone, then the passwords move back into the keyring. Each one is read back before its local copy is removed. Any the keyring can't take (none available, or locked) stay in the local store, and that copy keeps winning over an older keyring value until it has been moved.
- A store protected by `MAILBACKUP_MASTER_KEY` can't be used by the service, which doesn't receive that variable. Enabling the service is refused until it's unset.

Installing and removing still ask for administrator authorization once, because the definitions live in system folders. On Linux this can be up to three prompts.

A service installed by version 0.2.12 or earlier runs with administrator rights. Settings shows "Admin rights: reinstall"; turn the option off and on again to reinstall it as your user. On Linux and macOS, every install also checks MailBackup's own files and hands any that aren't yours back to your user, so files left by the old root service keep working. That means the config, the credential store and key, the service logs, the catalog database with its `-wal`/`-shm` files, and the archive's own files and folders. The archive is checked against MailBackup's exact layout (`<account>/<folder>/<year>/<month>/<uid>_<hash>.eml`); anything else in the data folder, and any folder holding something else, is left alone. Nothing is changed recursively, and `chown -h` never follows symlinks.

**Files on disk are private to your user account (Linux/macOS).** MailBackup creates its folders as `0700` and its files as `0600`: the archived mail, the catalog database with its `-wal`/`-shm` files, `config.yaml`, the credential store, the event logs and `.mbox` exports. Existing folders it writes into, such as Documents or a custom database folder, are left as they are.

At startup, files left readable by older versions are tightened too: the sensitive files below before any command runs, and the archive in the background by the server and `mailbackup daemon`. Only MailBackup's own paths are changed:
- the config, the credential store and key, the catalog and its sidecar files, `~/.mailbackup` and its logs;
- archive entries that follow MailBackup's exact layout. A data folder that also holds other files keeps its own permissions, but the archive inside it is tightened.

Only files you own are changed, and symlinks are never followed, not even one swapped in while MailBackup is working. To share an archive with a group on purpose, set `settings.tighten_permissions: false` and manage the permissions yourself; new files are still created owner-only. On Windows, the permissions of your user profile folder apply.

### 4. Running the Desktop GUI

```bash
cargo run -p mailbackup-gui
```

---

## Running Automated Tests

```bash
cargo test --workspace
```

Browser test for the mail viewer (needs Node, Playwright and its Chromium):

```bash
cargo build -p mailbackup-server
NODE_PATH="$(npm root -g)" node scripts/browser-tests/remote-content.mjs
```
