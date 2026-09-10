use std::collections::BTreeMap;
use std::sync::Mutex;

use appport_auth_mesh_dsl::PasswordPolicy;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand_core::OsRng;

use crate::catalog;
use crate::connector::{
    challenge_state, AuthChallenge, AuthConnector, AuthRequest, AuthResponse, ChallengeKind,
    ConnectorError, ConnectorMetadata, ExternalIdentity,
};

/// The one connector with real behaviour in this revision.
///
/// It authenticates against an in-process directory so the whole flow — begin,
/// challenge, authenticate, external identity — is deterministic and testable
/// without production credentials. The digest below is a stable non-secret
/// hash, not a password-storage scheme; a production credential connector
/// belongs behind the same trait with real key derivation.
pub struct LocalConnector {
    accounts: Mutex<BTreeMap<String, LocalAccount>>,
}

impl Default for LocalConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalConnector {
    pub const ID: &'static str = "local";

    pub fn new() -> Self {
        Self {
            accounts: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_account(mut self, account: LocalAccount) -> Self {
        self.accounts
            .get_mut()
            .expect("local account mutex should not be poisoned")
            .insert(account.username.clone(), account);
        self
    }

    pub fn register(&mut self, account: LocalAccount) -> Result<(), ConnectorError> {
        let accounts =
            self.accounts
                .get_mut()
                .map_err(|_| ConnectorError::PasswordHashingFailed {
                    connector: Self::ID.to_string(),
                })?;
        if accounts.contains_key(&account.username) {
            return Err(ConnectorError::InvalidRequest {
                connector: Self::ID.to_string(),
                message: format!("account `{}` already exists", account.username),
            });
        }
        accounts.insert(account.username.clone(), account);
        Ok(())
    }

    pub fn usernames(&self) -> Vec<String> {
        self.accounts
            .lock()
            .map(|accounts| accounts.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn account_attribute(&self, username: &str, key: &str) -> Option<String> {
        self.accounts
            .lock()
            .ok()?
            .get(username)?
            .attributes
            .get(key)
            .cloned()
    }

    fn invalid_credentials() -> ConnectorError {
        ConnectorError::InvalidCredentials {
            connector: Self::ID.to_string(),
        }
    }
}

impl AuthConnector for LocalConnector {
    fn id(&self) -> &str {
        Self::ID
    }

    fn metadata(&self) -> ConnectorMetadata {
        catalog::describe(Self::ID)
    }

    fn begin(&self, request: &AuthRequest) -> Result<AuthChallenge, ConnectorError> {
        if request.connector != Self::ID {
            return Err(ConnectorError::InvalidRequest {
                connector: Self::ID.to_string(),
                message: format!("request targets connector `{}`", request.connector),
            });
        }

        let username =
            request
                .parameter("username")
                .ok_or_else(|| ConnectorError::InvalidRequest {
                    connector: Self::ID.to_string(),
                    message: "missing `username`".to_string(),
                })?;

        // The challenge is issued without revealing whether the account exists.
        let mut parameters = BTreeMap::new();
        parameters.insert("username".to_string(), username.to_string());

        Ok(AuthChallenge {
            connector: Self::ID.to_string(),
            kind: ChallengeKind::Credentials,
            state: challenge_state(Self::ID, request.tenant.as_deref(), username),
            parameters,
        })
    }

    fn authenticate(&self, response: &AuthResponse) -> Result<ExternalIdentity, ConnectorError> {
        if response.connector != Self::ID {
            return Err(ConnectorError::InvalidRequest {
                connector: Self::ID.to_string(),
                message: format!("response targets connector `{}`", response.connector),
            });
        }

        let username =
            response
                .parameter("username")
                .ok_or_else(|| ConnectorError::InvalidRequest {
                    connector: Self::ID.to_string(),
                    message: "missing `username`".to_string(),
                })?;
        let password =
            response
                .parameter("password")
                .ok_or_else(|| ConnectorError::InvalidRequest {
                    connector: Self::ID.to_string(),
                    message: "missing `password`".to_string(),
                })?;

        let expected_state = challenge_state(Self::ID, response.tenant.as_deref(), username);
        if response.state != expected_state {
            return Err(ConnectorError::ChallengeMismatch {
                connector: Self::ID.to_string(),
            });
        }

        let accounts = self
            .accounts
            .lock()
            .map_err(|_| ConnectorError::PasswordHashingFailed {
                connector: Self::ID.to_string(),
            })?;
        let account = accounts
            .get(username)
            .ok_or_else(Self::invalid_credentials)?;
        if !account.verify_password(password) {
            return Err(Self::invalid_credentials());
        }

        let mut identity = ExternalIdentity::new(Self::ID, username);
        identity.attributes = account.attributes.clone();
        identity.attributes.insert(
            "password_changed_at".to_string(),
            account.password_changed_at.to_string(),
        );
        Ok(identity)
    }

    fn supports_password_management(&self) -> bool {
        true
    }

    fn recovery_address(&self, username: &str) -> Option<String> {
        self.accounts
            .lock()
            .ok()?
            .get(username)?
            .attributes
            .get("email")
            .cloned()
    }

    fn mark_email_verified(&self, username: &str) -> Result<(), ConnectorError> {
        let mut accounts =
            self.accounts
                .lock()
                .map_err(|_| ConnectorError::PasswordHashingFailed {
                    connector: Self::ID.to_string(),
                })?;
        let account = accounts
            .get_mut(username)
            .ok_or_else(Self::invalid_credentials)?;
        account
            .attributes
            .insert("email_verified".to_string(), "true".to_string());
        Ok(())
    }

    fn change_password(
        &self,
        _tenant_id: &str,
        username: &str,
        current_password: &str,
        new_password: &str,
        policy: &PasswordPolicy,
        now: i64,
    ) -> Result<(), ConnectorError> {
        let mut accounts =
            self.accounts
                .lock()
                .map_err(|_| ConnectorError::PasswordHashingFailed {
                    connector: Self::ID.to_string(),
                })?;
        let account = accounts
            .get_mut(username)
            .ok_or_else(Self::invalid_credentials)?;
        if !account.verify_password(current_password) {
            return Err(Self::invalid_credentials());
        }
        account.set_password(new_password, policy, now)
    }

    fn reset_password(
        &self,
        _tenant_id: &str,
        username: &str,
        new_password: &str,
        policy: &PasswordPolicy,
        now: i64,
    ) -> Result<(), ConnectorError> {
        let mut accounts =
            self.accounts
                .lock()
                .map_err(|_| ConnectorError::PasswordHashingFailed {
                    connector: Self::ID.to_string(),
                })?;
        let account = accounts
            .get_mut(username)
            .ok_or_else(Self::invalid_credentials)?;
        account.set_password(new_password, policy, now)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LocalAccount {
    pub username: String,
    password_hash: String,
    password_history: Vec<String>,
    password_changed_at: i64,
    pub attributes: BTreeMap<String, String>,
}

impl std::fmt::Debug for LocalAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAccount")
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field(
                "password_history",
                &format_args!("{} entries", self.password_history.len()),
            )
            .field("password_changed_at", &self.password_changed_at)
            .field("attributes", &self.attributes)
            .finish()
    }
}

impl LocalAccount {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        let password_hash = Self::hash_password(&password.into())
            .expect("argon2 password hashing should work for local test accounts");
        Self {
            username,
            password_hash,
            password_history: Vec::new(),
            password_changed_at: 0,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    fn verify_password(&self, password: &str) -> bool {
        PasswordHash::new(&self.password_hash)
            .ok()
            .and_then(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .ok()
            })
            .is_some()
    }

    fn set_password(
        &mut self,
        password: &str,
        policy: &PasswordPolicy,
        now: i64,
    ) -> Result<(), ConnectorError> {
        if self.matches_current_or_history(password, policy.password_history_count) {
            return Err(ConnectorError::PasswordReused {
                connector: LocalConnector::ID.to_string(),
            });
        }
        let previous = std::mem::replace(
            &mut self.password_hash,
            Self::hash_password(password).map_err(|_| ConnectorError::PasswordHashingFailed {
                connector: LocalConnector::ID.to_string(),
            })?,
        );
        self.password_history.insert(0, previous);
        self.password_history
            .truncate(policy.password_history_count);
        self.password_changed_at = now;
        Ok(())
    }

    fn matches_current_or_history(&self, password: &str, history_count: usize) -> bool {
        std::iter::once(&self.password_hash)
            .chain(self.password_history.iter().take(history_count))
            .any(|hash| {
                PasswordHash::new(hash)
                    .ok()
                    .and_then(|parsed| {
                        Argon2::default()
                            .verify_password(password.as_bytes(), &parsed)
                            .ok()
                    })
                    .is_some()
            })
    }

    fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    }
}
