//! Seeds a throwaway MailBackup install with one account and one mail with
//! attachments: an inline image in a `multipart/mixed` (no name), an HTML
//! file and a PDF with an RFC 2231 name. Used by
//! `scripts/browser-tests/ui-dialogs-attachments.mjs`.
//!
//! Usage: cargo run -p mailbackup-core --example seed_attachment_mail -- <dir>
//! Prints the message id.

use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::Database;
use mailbackup_core::storage::StorageEngine;

const EML: &str = "From: sender@example.com\r\nTo: me@example.com\r\nSubject: Files for you\r\nMIME-Version: 1.0\r\n\
    Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
    --B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThree files attached.\r\n\
    --B\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: base64\r\n\r\n\
    iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==\r\n\
    --B\r\nContent-Type: text/html; charset=utf-8\r\nContent-Disposition: attachment; filename=\"page.html\"\r\n\r\n\
    <script>document.title = 'attachment ran'</script><p>html attachment</p>\r\n\
    --B\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n\
    Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQKJcOkw7zDtsOfCg==\r\n\
    --B--\r\n";

fn main() -> mailbackup_core::Result<()> {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("dir"));

    // An account whose server doesn't exist: a sync of it starts and fails
    let account = AccountConfig {
        id: "acc".into(),
        name: "Test".into(),
        email: "me@example.com".into(),
        provider: ProviderType::GenericImap,
        imap_server: "127.0.0.1".into(),
        imap_port: 9,
        use_tls: false,
        auth_type: AuthType::Password,
        username: "me@example.com".into(),
        schedule: None,
        retention_days: None,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
        storage_namespace: None,
        credential_ref: None,
        archive: None,
        trust_server_ids: true,
    };
    let config = AppConfig {
        data_dir: dir.join("data"),
        db_path: dir.join("catalog.db"),
        accounts: vec![account],
        ..Default::default()
    };
    config.save(&dir.join("config.yaml"))?;
    let db = Database::open(&config.db_path)?;
    let storage = StorageEngine::new(&config.data_dir);

    db.upsert_account("acc", "Test", "me@example.com", "generic_imap")?;
    let folder = db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1))?;
    let stored = storage.store_eml("acc", "INBOX", 1, None, EML.as_bytes())?;
    let id = db.insert_message(
        "acc",
        &folder.id,
        1,
        Some("<files@example.com>"),
        Some("Files for you"),
        Some("sender@example.com"),
        Some("me@example.com"),
        None,
        None,
        stored.size_bytes,
        &stored.relative_path.to_string_lossy(),
        &stored.sha256,
        Some("Three files attached."),
        &[],
    )?;
    println!("{}", id);
    Ok(())
}
