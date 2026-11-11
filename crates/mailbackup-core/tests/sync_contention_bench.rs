//! Issue #76: how much a running sync delays readers. Ignored by default;
//! run with
//!
//! ```text
//! MB_BENCH_MESSAGES=20000 cargo test --release -p mailbackup-core \
//!     --test sync_contention_bench -- --ignored --nocapture
//! ```
//!
//! While one account syncs `MB_BENCH_MESSAGES` messages (default 5000) from
//! the in-memory IMAP stub, a reader lists the folder's first page and runs a
//! search in a loop on the blocking pool (as the web UI's handlers do), and a ticker measures how
//! late a 5 ms timer fires on the same runtime (blocking work on the
//! runtime's workers shows up there). Reports median, p99 and worst case.

mod common;
use common::*;
use mailbackup_core::db::{AdvancedSearchFilter, ListSort};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn report(name: &str, mut samples: Vec<Duration>) {
    if samples.is_empty() {
        println!("{:<22} no samples", name);
        return;
    }
    samples.sort_unstable();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    println!(
        "{:<22} n={:<6} median={:>9.3?} p99={:>9.3?} max={:>9.3?}",
        name,
        samples.len(),
        at(0.5),
        at(0.99),
        samples[samples.len() - 1]
    );
}

fn bench_mail(i: usize) -> Vec<u8> {
    let mut m = format!(
        "From: sender{}@example.com\r\nTo: me@example.com\r\nSubject: Message number {}\r\nMessage-ID: <{}@bench>\r\nDate: Mon, 2 Mar 2026 10:{:02}:00 +0000\r\n\r\n",
        i % 50,
        i,
        i,
        i % 60
    )
    .into_bytes();
    for line in 0..30 {
        m.extend(format!("Line {} of message {}: lorem ipsum dolor sit amet, consectetur adipiscing elit.\r\n", line, i).bytes());
    }
    m
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
async fn sync_contention_benchmark() {
    let n: usize = std::env::var("MB_BENCH_MESSAGES").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
    let (a, server) = (archive(), FakeImap::start().await);
    let acc = account(&server, "user");
    let mails: Vec<Vec<u8>> = (0..n).map(bench_mail).collect();
    let list: Vec<(u32, &[u8])> = mails.iter().enumerate().map(|(i, m)| (i as u32 + 1, m.as_slice())).collect();
    server.set(Some(1), &list);

    // The folder exists before the readers start: sync one message first
    server.set(Some(1), &list[..1]);
    sync(&a, &server, &acc).await;
    server.set(Some(1), &list);
    let folder = inbox(&a).id;

    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let (db, done, folder) = (a.db.clone(), done.clone(), folder.clone());
        tokio::spawn(async move {
            let (mut lists, mut searches) = (Vec::new(), Vec::new());
            while !done.load(Ordering::Relaxed) {
                // On the blocking pool, as the server's handlers run them
                let (db1, f) = (db.clone(), folder.clone());
                let t = Instant::now();
                tokio::task::spawn_blocking(move || db1.list_folder_messages(&f, ListSort::Date, true, 200, None).unwrap())
                    .await
                    .unwrap();
                lists.push(t.elapsed());
                let db1 = db.clone();
                let t = Instant::now();
                tokio::task::spawn_blocking(move || {
                    let filter = AdvancedSearchFilter { query: Some("lorem".into()), limit: Some(50), ..Default::default() };
                    db1.search_advanced(&filter).unwrap()
                })
                .await
                .unwrap();
                searches.push(t.elapsed());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            (lists, searches)
        })
    };
    let ticker = {
        let done = done.clone();
        tokio::spawn(async move {
            let mut late = Vec::new();
            while !done.load(Ordering::Relaxed) {
                let t = Instant::now();
                tokio::time::sleep(Duration::from_millis(5)).await;
                late.push(t.elapsed().saturating_sub(Duration::from_millis(5)));
            }
            late
        })
    };

    let start = Instant::now();
    let progress = sync(&a, &server, &acc).await;
    let took = start.elapsed();
    done.store(true, Ordering::Relaxed);
    let (lists, searches) = reader.await.unwrap();
    let late = ticker.await.unwrap();

    assert_eq!(progress.processed_messages as usize, n - 1);
    println!("\nsynced {} messages in {:.2?} ({:.0} msg/s)", n - 1, took, (n - 1) as f64 / took.as_secs_f64());
    report("folder list (200)", lists);
    report("search", searches);
    report("timer lateness (5ms)", late);

    // The start-of-sync existence check over every UID of the folder: one
    // query per UID (before #76) against one query for all
    let uids: Vec<u32> = (1..=n as u32).collect();
    let t = Instant::now();
    let found = uids.iter().filter(|&&u| a.db.message_exists_in_generation(&folder, 0, u).unwrap()).count();
    let per_uid = t.elapsed();
    let t = Instant::now();
    let set = a.db.archived_uids_above(&folder, 0, 0).unwrap();
    let one_query = t.elapsed();
    assert_eq!(found, set.len());
    println!("existence check of {} UIDs: per UID {:.2?}, one query {:.2?}", n, per_uid, one_query);
}
