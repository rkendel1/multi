use std::collections::BTreeMap;

use crate::catalog;
use crate::connector::{
    challenge_state, stable_hash, AuthChallenge, AuthConnector, AuthRequest, AuthResponse,
    ChallengeKind, ConnectorError, ConnectorMetadata, ExternalIdentity,
};

/// The one connector with real behaviour in this revision.
///
/// It authenticates against an in-process directory so the whole flow — begin,
/// challenge, authenticate, external identity — is deterministic and testable
/// without production credentials. The digest below is a stable non-secret
/// hash, not a password-storage scheme; a production credential connector
/// belongs behind the same trait with real key derivation.
pub struct LocalConnector {
    accounts: BTreeMap<String, LocalAccount>,
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
            accounts: BTreeMap::new(),
        }
    }

    pub fn with_account(mut self, account: LocalAccount) -> Self {
        self.accounts.insert(account.username.clone(), account);
        self
    }

    pub fn register(&mut self, account: LocalAccount) -> Result<(), ConnectorError> {
        if self.accounts.contains_key(&account.username) {
            return Err(ConnectorError::InvalidRequest {
                connector: Self::ID.to_string(),
                message: format!("account `{}` already exists", account.username),
            });
        }
        self.accounts.insert(account.username.clone(), account);
        Ok(())
    }

    pub fn usernames(&self) -> Vec<String> {
        self.accounts.keys().cloned().collect()
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

        let account = self
            .accounts
            .get(username)
            .ok_or_else(Self::invalid_credentials)?;
        if account.digest != LocalAccount::digest(username, password) {
            return Err(Self::invalid_credentials());
        }

        let mut identity = ExternalIdentity::new(Self::ID, username);
        identity.attributes = account.attributes.clone();
        Ok(identity)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccount {
    pub username: String,
    digest: u64,
    pub attributes: BTreeMap<String, String>,
}

impl LocalAccount {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        let digest = Self::digest(&username, &password.into());
        Self {
            username,
            digest,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    fn digest(username: &str, password: &str) -> u64 {
        stable_hash(format!("authport|local|{}|{}", username, password).as_bytes())
    }
}
