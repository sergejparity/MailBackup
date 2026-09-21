//! mailbackup-core: Core library for resilient, incremental email backups in Rust.

pub mod config;
pub mod db;
pub mod keyring;
pub mod storage;
pub mod imap;
pub mod retention;
pub mod mbox;
pub mod scheduler;
pub mod error;

pub use error::{Error, Result};
