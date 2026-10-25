//! mailbackup-core: Core library for resilient, incremental email backups in Rust.

pub mod config;
pub mod db;
pub mod keyring;
pub mod storage;
pub mod imap;
pub mod retention;
pub mod mbox;
pub mod scheduler;
pub mod sync_gate;
pub mod archive;
pub mod autostart;
pub mod service;
pub mod event_log;
pub mod error;
pub mod csv_import;
pub mod safe_paths;
pub mod private_fs;
pub mod html_view;

pub use error::{Error, Result};
