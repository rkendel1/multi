/// AuthStateRepository: Narrow semantic boundary over FeltDB 0.10.0
///
/// This module provides a single semantic boundary between AuthPort and FeltDB.
/// The repository MUST NOT reimplement:
/// - storage or persistence
/// - transactions
/// - event logs
/// - outbox patterns
/// - deployment resolution
///
/// It consumes @feltdb/core exactly as provided and delegates all durability
/// to the real FeltDB implementation.
///
/// The architectural flow:
/// AuthPort semantics
///        │
///        ▼
/// AuthStateRepository
///        │
///        ▼
/// @feltdb/core 0.10.0
///        │
///        ▼
/// FeltDB deployment resolution

mod auth_state_repository;
pub use auth_state_repository::AuthStateRepository;

#[derive(Debug, Clone)]
pub struct FeltDBError {
    pub message: String,
}

impl FeltDBError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FeltDBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FeltDBError {}

/// Configuration for the FeltDB-backed state repository
#[derive(Debug, Clone)]
pub struct FeltDBConfig {
    /// The FeltDB deployment mode and configuration
    /// This is passed directly to @feltdb/core without modification
    pub deployment: FeltDBDeployment,
}

#[derive(Debug, Clone)]
pub enum FeltDBDeployment {
    /// Local durable FeltDB runtime
    Local {
        path: String,
    },
    /// Remote or self-hosted FeltDB server
    Remote {
        url: String,
        credentials: Option<String>,
    },
    /// Managed FeltDB (via AppBoundry or similar)
    Managed {
        endpoint: String,
    },
    /// Browser-backed FeltDB (IndexedDB)
    Browser,
}

/// The AuthStateRepository must fail closed.
/// If FeltDB cannot initialize with the configured deployment, startup fails.
/// There is NO fallback to in-memory state for production.
pub trait MustNotFallback: Send + Sync {
    fn validate_no_memory_fallback(&self) -> Result<(), FeltDBError>;
}
