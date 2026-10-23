//! Seeds a throwaway MailBackup install with one HTML mail that references
//! remote content (all pointing at `<tracker-url>`) and an inline `cid:`
//! image. Used by `scripts/browser-tests/remote-content.mjs`.
//!
//! Usage: cargo run -p mailbackup-core --example seed_html_mail -- <dir> <tracker-url>
//! Prints the message id.

use mailbackup_core::config::AppConfig;
use mailbackup_core::db::Database;
use mailbackup_core::storage::StorageEngine;

const PNG_1X1: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

fn main() -> mailbackup_core::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("dir"));
    let tracker = args.next().expect("tracker url");

    let config = AppConfig { data_dir: dir.join("data"), db_path: dir.join("catalog.db"), ..Default::default() };
    config.save(&dir.join("config.yaml"))?;
    let db = Database::open(&config.db_path)?;
    let storage = StorageEngine::new(&config.data_dir);

    let html = format!(
        r#"<!DOCTYPE html><html><head>
<meta http-equiv="refresh" content="1;url={t}/refresh">
<link rel="dns-prefetch" href="{t}/">
<link rel="preconnect" href="{t}/">
<link rel="prefetch" href="{t}/prefetch">
<link rel="stylesheet" href="{t}/style.css">
<base href="{t}/">
<style>@font-face {{ font-family: tracked; src: url({t}/font.woff); }} body {{ font-family: tracked; }}</style>
</head><body>
<p>Hello from a newsletter.</p>
<img id="remote-img" src="{t}/pixel.png" width="1" height="1">
<img id="srcset-img" srcset="{t}/srcset.png 1x">
<div id="bg" style="width:10px;height:10px;background:url({t}/bg.png)"></div>
<img id="cid-img" src="cid:logo@test">
<img id="relative-img" src="relative.png">
</body></html>"#,
        t = tracker
    );
    let eml = format!(
        "From: news@example.com\r\nTo: me@example.com\r\nSubject: Tracked newsletter\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/related; boundary=\"b\"\r\n\r\n\
         --b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n\
         --b\r\nContent-Type: image/png\r\nContent-ID: <logo@test>\r\nContent-Transfer-Encoding: base64\r\n\r\n{png}\r\n\
         --b--\r\n",
        html = html,
        png = PNG_1X1
    );

    db.upsert_account("acc", "Test", "me@example.com", "custom")?;
    let folder = db.get_or_create_folder("acc", "INBOX", "INBOX", Some(1))?;
    let stored = storage.store_eml("acc", "INBOX", 1, None, eml.as_bytes())?;
    let id = db.insert_message(
        "acc",
        &folder.id,
        1,
        Some("<news@example.com>"),
        Some("Tracked newsletter"),
        Some("news@example.com"),
        Some("me@example.com"),
        None,
        None,
        stored.size_bytes,
        &stored.relative_path.to_string_lossy(),
        &stored.sha256,
        Some("Hello from a newsletter."),
        &[],
    )?;
    println!("{}", id);
    Ok(())
}
