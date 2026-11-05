use thiserror::Error;

#[derive(Error, Debug)]
pub enum TetherError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Case '{0}' not found")]
    CaseNotFound(String),

    #[error("Invalid case transition from {from:?} to {to:?}: {reason}")]
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },

    #[error("Loop invariant violation: {0}")]
    InvariantViolation(String),

    #[error("Redaction failure: sensitive pattern detected after scrub: {0}")]
    RedactionFailure(String),

    #[error("Lockfile verification failed: {0}")]
    LockfileMismatch(String),

    #[error("Merkle ledger integrity failure: {0}")]
    LedgerCorruption(String),

    #[error("Model release gate failed: {0}")]
    GateBlocked(String),

    #[error("Subprocess runner execution failed: {0}")]
    RunnerFailed(String),

    #[error("General tether error: {0}")]
    General(String),
}
