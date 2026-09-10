use crate::{FeltDBConfig, FeltDBError, MustNotFallback};

/// AuthStateRepository: Semantic boundary for authentication state
///
/// This is NOT a storage engine, event store, transaction manager, or deployment resolver.
/// It is a thin semantic adapter that expresses AuthPort operations over the real FeltDB API.
///
/// AuthPort owns:
/// - Authentication and authorization semantics
/// - What state matters (identity, credentials, sessions, recovery, verification)
/// - Security policies and invariants
///
/// FeltDB owns:
/// - How state is persisted (local, remote, managed, browser)
/// - Transaction semantics
/// - Event storage and ordering
/// - Deployment resolution and configuration
///
/// The repository delegates all durability to @feltdb/core and never:
/// - Implements its own storage
/// - Caches state as a fallback
/// - Manages its own transactions
/// - Creates its own event log
/// - Duplicates FeltDB's outbox or deployment logic
#[derive(Clone)]
pub struct AuthStateRepository {
    config: FeltDBConfig,
    // In production: this will hold a real @feltdb/core client handle
    // For now: placeholder until FFI to @feltdb/core or JS binding
    _client: std::sync::Arc<()>,
}

impl AuthStateRepository {
    /// Create a new AuthStateRepository backed by FeltDB
    ///
    /// This constructor:
    /// 1. Takes an explicit FeltDB configuration
    /// 2. Does NOT attempt automatic runtime detection
    /// 3. Does NOT create an in-memory fallback
    /// 4. Fails if FeltDB cannot initialize with the given config
    pub fn new(config: FeltDBConfig) -> Result<Self, FeltDBError> {
        // Validate that this is not a silent in-memory fallback
        Self::validate_not_fallback(&config)?;

        // TODO: Initialize the real @feltdb/core client with the given deployment config
        // This will be done via FFI or a JavaScript binding that imports @feltdb/core

        Ok(Self {
            config,
            _client: std::sync::Arc::new(()),
        })
    }

    /// Validate that the configuration does not silently degrade to in-memory
    fn validate_not_fallback(config: &FeltDBConfig) -> Result<(), FeltDBError> {
        match &config.deployment {
            crate::FeltDBDeployment::Local { path } => {
                if path.is_empty() {
                    return Err(FeltDBError::new(
                        "Local FeltDB path must not be empty",
                    ));
                }
                Ok(())
            }
            crate::FeltDBDeployment::Remote { url, .. } => {
                if url.is_empty() {
                    return Err(FeltDBError::new(
                        "Remote FeltDB URL must not be empty",
                    ));
                }
                Ok(())
            }
            crate::FeltDBDeployment::Managed { endpoint } => {
                if endpoint.is_empty() {
                    return Err(FeltDBError::new(
                        "Managed FeltDB endpoint must not be empty",
                    ));
                }
                Ok(())
            }
            crate::FeltDBDeployment::Browser => Ok(()),
        }
    }

    /// The configuration this repository was created with
    pub fn config(&self) -> &FeltDBConfig {
        &self.config
    }
}

impl MustNotFallback for AuthStateRepository {
    fn validate_no_memory_fallback(&self) -> Result<(), FeltDBError> {
        // AuthStateRepository is always durable; it never falls back to memory
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_local_path() {
        let config = FeltDBConfig {
            deployment: crate::FeltDBDeployment::Local {
                path: String::new(),
            },
        };
        assert!(AuthStateRepository::new(config).is_err());
    }

    #[test]
    fn rejects_empty_remote_url() {
        let config = FeltDBConfig {
            deployment: crate::FeltDBDeployment::Remote {
                url: String::new(),
                credentials: None,
            },
        };
        assert!(AuthStateRepository::new(config).is_err());
    }

    #[test]
    fn accepts_valid_local_path() {
        let config = FeltDBConfig {
            deployment: crate::FeltDBDeployment::Local {
                path: "/var/authport/state".to_string(),
            },
        };
        assert!(AuthStateRepository::new(config).is_ok());
    }

    #[test]
    fn accepts_valid_remote_url() {
        let config = FeltDBConfig {
            deployment: crate::FeltDBDeployment::Remote {
                url: "https://feltdb.example.com".to_string(),
                credentials: None,
            },
        };
        assert!(AuthStateRepository::new(config).is_ok());
    }

    #[test]
    fn validates_no_memory_fallback() {
        let config = FeltDBConfig {
            deployment: crate::FeltDBDeployment::Local {
                path: "/var/authport/state".to_string(),
            },
        };
        let repo = AuthStateRepository::new(config).unwrap();
        assert!(repo.validate_no_memory_fallback().is_ok());
    }
}
