// opaq: error types and result aliases

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpaqError {
    // Store errors
    #[error("Store not found. Run `opaq init` first.")]
    StoreNotFound,

    #[error("Store is locked. Run `opaq unlock` first.")]
    StoreLocked,

    #[error("opaq is already initialized.\nUse 'opaq lock'/'unlock' for session management, or 'opaq init --force' to re-initialize (destroys existing store).")]
    StoreAlreadyExists,

    #[error("Failed to decrypt store: {0}")]
    DecryptionFailed(String),

    #[error("Failed to encrypt store: {0}")]
    EncryptionFailed(String),

    // Keychain errors
    #[error("Failed to access OS keychain: {0}")]
    KeychainError(String),

    // Validation errors (exit code 2)
    #[error("Invalid secret name '{0}'. Names must match ^[A-Z][A-Z0-9_]*$ (uppercase letters, digits, underscores; must start with a letter).")]
    InvalidName(String),

    #[error("Secret '{0}' already exists. Use `opaq edit` to modify it.")]
    DuplicateName(String),

    #[error("Secret '{0}' not found.")]
    SecretNotFound(String),

    // TTY errors (exit code 2)
    #[error("'{0}' requires an interactive terminal.\nSecret values cannot be provided via arguments or stdin for security reasons.")]
    TtyRequired(String),

    // I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    // Child process errors
    #[error("Failed to execute command: {0}")]
    CommandExecution(String),

    #[error("Unknown placeholder '{{{{{0}}}}}' is not a known opaq secret.")]
    UnknownPlaceholder(String),

    // Filter errors
    #[error("Failed to build output filter: {0}")]
    FilterBuild(String),

    // Passphrase errors
    #[error("Passphrases do not match.")]
    PassphraseMismatch,

    #[error("Invalid passphrase.")]
    InvalidPassphrase,
}

impl OpaqError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidName(_) | Self::TtyRequired(_) | Self::UnknownPlaceholder(_) => 2,
            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, OpaqError>;
