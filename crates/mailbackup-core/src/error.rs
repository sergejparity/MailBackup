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

    /// A secret couldn't be read or written; `kind` says why, so callers can
    /// tell a missing secret from a store they must not overwrite.
    #[error("{message}")]
    Credential { kind: CredentialErrorKind, message: String },

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

    #[error("{0}")]
    InvalidPath(String),

    /// A request parameter is malformed (reported to API clients as 400).
    #[error("{0}")]
    InvalidInput(String),

    /// The requested item doesn't exist (reported to API clients as 404).
    #[error("{0}")]
    NotFound(String),

    #[error("The saved password for account '{0}' belongs to a different server, port or username. Enter the password again.")]
    CredentialMismatch(String),

    #[error("Parsing error: {0}")]
    Parse(String),

    /// A folder sync tried to write after a newer sync of that folder had
    /// started over (the server, account or UIDVALIDITY changed); nothing was
    /// written.
    #[error("Sync of folder '{0}' was superseded by a newer sync; stopping it")]
    StaleSync(String),

    #[error("Generic error: {0}")]
    Other(String),
}

/// Why a credential operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialErrorKind {
    /// No such secret (or no store yet). The only kind that means "empty".
    NotFound,
    /// The OS keyring exists but is locked or refused access.
    Locked,
    /// The OS keyring or the store can't be reached right now.
    Unavailable,
    /// The store or key file isn't readable/writable for this user.
    PermissionDenied,
    /// The store, an entry or the key file is damaged or has an unknown format.
    Corrupt,
    /// The store doesn't decrypt with the available key or passphrase.
    WrongKey,
    /// The store needs a key or passphrase that isn't available.
    NoKey,
}

impl Error {
    pub fn credential(kind: CredentialErrorKind, message: impl Into<String>) -> Self {
        Error::Credential { kind, message: message.into() }
    }

    /// The credential error kind, if this is one.
    pub fn credential_kind(&self) -> Option<CredentialErrorKind> {
        match self {
            Error::Credential { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    pub fn is_not_found(&self) -> bool {
        self.credential_kind() == Some(CredentialErrorKind::NotFound)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
