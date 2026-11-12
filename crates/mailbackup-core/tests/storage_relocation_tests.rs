//! Moving the data folder while archivers and pruning hold the storage
//! lifetime lock (issue #79, review of #91): a guarded operation never sees
//! two folders, and nothing stored under a guard is left behind.

use mailbackup_core::storage::{StorageEngine, STORAGE_LOCK_FILE};
use std::sync::mpsc;
use std::time::Duration;

const WAIT: Duration = Duration::from_millis(300);

#[test]
fn a_relocation_waits_for_an_archiver_and_takes_what_it_stored() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
    let storage = StorageEngine::new(&old);

    // An archiver holds the guard and has not stored its file yet
    let guard = storage.lock_shared().unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let mover = {
        let (storage, new) = (storage.clone(), new.clone());
        std::thread::spawn(move || done_tx.send(storage.relocate(&new, true).unwrap()).unwrap())
    };
    assert!(done_rx.recv_timeout(WAIT).is_err(), "the relocation waits for the archiver");
    assert_eq!(storage.base_dir(), old, "the archiver's folder doesn't change under it");
    let stored = storage.store_eml("acc", "INBOX", 1, None, b"Subject: x\r\n\r\nbody").unwrap();
    assert!(stored.absolute_path.starts_with(&old));
    drop(guard);

    assert_eq!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1, "its file is copied");
    mover.join().unwrap();
    assert_eq!(storage.base_dir(), new);
    assert_eq!(storage.read_eml(&stored.relative_path).unwrap(), b"Subject: x\r\n\r\nbody");
    assert!(!new.join(STORAGE_LOCK_FILE).exists(), "the old folder's lock file isn't copied");
}

#[test]
fn a_guard_asked_for_during_a_relocation_gets_the_new_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
    let storage = StorageEngine::new(&old);
    let first = storage.lock_shared().unwrap();

    let mover = {
        let (storage, new) = (storage.clone(), new.clone());
        std::thread::spawn(move || storage.relocate(&new, true).unwrap())
    };
    std::thread::sleep(WAIT); // the relocation is now waiting for `first`

    // Pruning (another handle on the same engine) asks for the lock now: it
    // must not start in the old folder while the move is pending
    let (seen_tx, seen_rx) = mpsc::channel();
    let pruner = {
        let storage = storage.clone();
        std::thread::spawn(move || {
            let _lock = storage.lock_exclusive().unwrap();
            seen_tx.send(storage.base_dir()).unwrap();
        })
    };
    assert!(seen_rx.recv_timeout(WAIT).is_err(), "it waits for the relocation");
    drop(first);
    assert_eq!(seen_rx.recv_timeout(Duration::from_secs(5)).unwrap(), new);
    mover.join().unwrap();
    pruner.join().unwrap();
}

#[test]
fn relocating_without_moving_switches_to_an_empty_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
    let storage = StorageEngine::new(&old);
    storage.store_eml("acc", "INBOX", 1, None, b"Subject: x\r\n\r\n").unwrap();
    assert_eq!(storage.relocate(&new, false).unwrap(), 0);
    assert_eq!(storage.base_dir(), new);
    assert!(new.is_dir());
}

/// Every path under `dir`, relative, sorted: what a folder holds.
fn listing(dir: &std::path::Path) -> Vec<String> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            out.push(path.strip_prefix(base).unwrap().to_string_lossy().to_string());
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    if dir.exists() {
        walk(dir, dir, &mut out);
    }
    out.sort();
    out
}

// Issue #76: a move whose client went away stops and leaves no copy behind
#[test]
fn a_cancelled_relocation_removes_its_copy_and_keeps_the_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("old");
    let storage = StorageEngine::new(&old);
    let stored = storage.store_eml("acc", "INBOX", 1, None, b"Subject: x\r\n\r\nbody").unwrap();
    // A target inside folders that don't exist yet, and one chosen as an
    // existing empty folder: each is left exactly as found
    for new in [tmp.path().join("a/b/new"), tmp.path().join("empty")] {
        let existed = new.exists() || new == tmp.path().join("empty");
        if existed {
            std::fs::create_dir_all(&new).unwrap();
        }
        let cancel = mailbackup_core::cancel::Cancel::new();
        cancel.cancel();
        let err = storage.relocate_until(&new, true, &cancel).unwrap_err();
        assert!(matches!(err, mailbackup_core::Error::Cancelled), "{}", err);
        assert_eq!(storage.base_dir(), old, "still the old folder");
        assert_eq!(storage.read_eml(&stored.relative_path).unwrap(), b"Subject: x\r\n\r\nbody");
        if existed {
            assert_eq!(listing(&new), Vec::<String>::new(), "the empty folder is empty again");
        } else {
            assert!(!tmp.path().join("a").exists(), "the folders it created are gone");
        }
    }
}

#[test]
fn a_relocation_that_fails_partway_removes_only_what_it_copied() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
    let storage = StorageEngine::new(&old);
    let mut stored = Vec::new();
    for uid in 1..=5 {
        stored.push(storage.store_eml("acc", "INBOX", uid, None, format!("Subject: {}\r\n\r\n", uid).as_bytes()).unwrap());
    }
    // Something already at one message's place in the target: the copy
    // stops there, whatever order it copies in
    let blocker = new.join(&stored[2].relative_path);
    std::fs::create_dir_all(blocker.parent().unwrap()).unwrap();
    std::fs::write(&blocker, b"not ours").unwrap();
    let before = listing(&new);

    assert!(storage.relocate(&new, true).is_err());
    assert_eq!(storage.base_dir(), old);
    assert_eq!(listing(&new), before, "only what was there before is left");
    assert_eq!(std::fs::read(&blocker).unwrap(), b"not ours", "never overwritten");
    for s in &stored {
        assert!(s.absolute_path.exists(), "the old folder is untouched");
    }
}

#[test]
fn os_metadata_files_in_both_folders_do_not_stop_a_move() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
    let storage = StorageEngine::new(&old);
    storage.store_eml("acc", "INBOX", 1, None, b"Subject: x\r\n\r\n").unwrap();
    std::fs::write(old.join(".DS_Store"), b"old").unwrap();
    std::fs::create_dir_all(&new).unwrap();
    std::fs::write(new.join(".DS_Store"), b"new").unwrap();
    assert_eq!(storage.relocate(&new, true).unwrap(), 1, "the message, not the metadata file");
    assert_eq!(std::fs::read(new.join(".DS_Store")).unwrap(), b"new", "the target's own is kept");
}
