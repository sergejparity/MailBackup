use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("IMAP error: {0}")]
    Imap(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Authentication failed for account '{0}': {1}")]
    AuthFailed(String, String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Folder not found: {0}")]
    FolderNotFound(String),

    #[error("Checksum mismatch for file '{0}': expected {1}, computed {2}")]
    ChecksumMismatch(String, String, String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Parsing error: {0}")]
    Parse(String),

    #[error("Generic error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
