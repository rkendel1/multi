use std::collections::BTreeMap;

use appport_auth_mesh_dsl::PasswordPolicy;

/// The connector contract.
///
/// A connector proves an *external* identity. It never creates an AuthPort
/// principal: principal resolution is owned by the auth mesh, which is what
/// keeps the application — not Google, GitHub or an email provider — the source
/// of truth for application identity.
pub trait AuthConnector: Send + Sync {
    fn id(&self) -> &str;

    fn metadata(&self) -> ConnectorMetadata;

    /// Start an authentication attempt and describe what the caller must do
    /// next (present credentials, follow a redirect, check an inbox).
    fn begin(&self, request: &AuthRequest) -> Result<AuthChallenge, ConnectorError>;

    /// Complete an attempt, yielding proof of an external identity.
    fn authenticate(&self, response: &AuthResponse) -> Result<ExternalIdentity, ConnectorError>;

    fn supports_password_management(&self) -> bool {
        false
    }

    fn change_password(
        &self,
        _tenant_id: &str,
        _username: &str,
        _current_password: &str,
        _new_password: &str,
        _policy: &PasswordPolicy,
        _now: i64,
    ) -> Result<(), ConnectorError> {
        Err(ConnectorError::Unsupported {
            connector: self.id().to_string(),
        })
    }

    fn reset_password(
        &self,
        _tenant_id: &str,
        _username: &str,
        _new_password: &str,
        _policy: &PasswordPolicy,
        _now: i64,
    ) -> Result<(), ConnectorError> {
        Err(ConnectorError::Unsupported {
            connector: self.id().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthRequest {
    pub connector: String,
    pub tenant: Option<String>,
    pub parameters: BTreeMap<String, String>,
    pub redirect_uri: Option<String>,
}

impl AuthRequest {
    pub fn new(connector: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            ..Self::default()
        }
    }

    pub fn for_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    pub fn with_parameter(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    pub fn parameter(&self, key: &str) -> Option<&str> {
        self.parameters
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub connector: String,
    pub kind: ChallengeKind,
    /// Binds a `begin` to its `authenticate`. Deterministic here so the flow is
    /// testable; a production connector issues a single-use nonce.
    pub state: String,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeKind {
    /// The caller submits credentials directly.
    Credentials,
    /// The caller is sent to an external authorization endpoint.
    Redirect { url: String },
    /// The caller proves control of an out-of-band channel (email, SMS).
    OutOfBand { channel: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthResponse {
    pub connector: String,
    pub tenant: Option<String>,
    pub state: String,
    pub parameters: BTreeMap<String, String>,
}

impl AuthResponse {
    pub fn to_challenge(challenge: &AuthChallenge) -> Self {
        Self {
            connector: challenge.connector.clone(),
            tenant: None,
            state: challenge.state.clone(),
            parameters: BTreeMap::new(),
        }
    }

    pub fn for_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    pub fn with_parameter(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    pub fn parameter(&self, key: &str) -> Option<&str> {
        self.parameters
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }
}

/// Proof that an external system recognises a subject.
///
/// This is deliberately *not* a principal: `(tenant, connector, subject)` is
/// resolved to a principal by the auth mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub connector: String,
    pub subject: String,
    pub attributes: BTreeMap<String, String>,
}

impl ExternalIdentity {
    pub fn new(connector: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            subject: subject.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorMetadata {
    pub id: String,
    pub display_name: String,
    pub kind: ConnectorKind,
    pub status: ConnectorStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectorKind {
    Local,
    Password,
    Oauth,
    Email,
    MagicLink,
    EnterpriseSso,
    Token,
}

impl ConnectorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Password => "password",
            Self::Oauth => "oauth",
            Self::Email => "email",
            Self::MagicLink => "magic_link",
            Self::EnterpriseSso => "enterprise_sso",
            Self::Token => "token",
        }
    }
}

/// How much of a connector actually exists.
///
/// `Declared` connectors are part of the contract and are advertised in the
/// generated surface, but they fail closed until they are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectorStatus {
    Supported,
    Declared,
    Unknown,
}

impl ConnectorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Declared => "declared",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// The connector is not in the registry at all.
    UnknownConnector {
        connector: String,
    },
    /// The connector is declared by the contract but has no implementation.
    Unsupported {
        connector: String,
    },
    NotDeclared {
        connector: String,
    },
    DuplicateConnector {
        connector: String,
    },
    InvalidRequest {
        connector: String,
        message: String,
    },
    InvalidCredentials {
        connector: String,
    },
    ChallengeMismatch {
        connector: String,
    },
    PasswordReused {
        connector: String,
    },
    PasswordHashingFailed {
        connector: String,
    },
}

impl ConnectorError {
    pub fn connector(&self) -> &str {
        match self {
            Self::UnknownConnector { connector }
            | Self::Unsupported { connector }
            | Self::NotDeclared { connector }
            | Self::DuplicateConnector { connector }
            | Self::InvalidRequest { connector, .. }
            | Self::InvalidCredentials { connector }
            | Self::ChallengeMismatch { connector }
            | Self::PasswordReused { connector }
            | Self::PasswordHashingFailed { connector } => connector,
        }
    }
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownConnector { connector } => {
                write!(f, "unknown connector `{}`", connector)
            }
            Self::Unsupported { connector } => {
                write!(
                    f,
                    "connector `{}` is declared but not implemented",
                    connector
                )
            }
            Self::NotDeclared { connector } => {
                write!(f, "connector `{}` is not declared by `use auth`", connector)
            }
            Self::DuplicateConnector { connector } => {
                write!(f, "duplicate connector `{}`", connector)
            }
            Self::InvalidRequest { connector, message } => {
                write!(f, "connector `{}`: {}", connector, message)
            }
            Self::InvalidCredentials { connector } => {
                write!(f, "connector `{}`: invalid credentials", connector)
            }
            Self::ChallengeMismatch { connector } => {
                write!(
                    f,
                    "connector `{}`: challenge does not match response",
                    connector
                )
            }
            Self::PasswordReused { connector } => {
                write!(f, "connector `{}`: PASSWORD_REUSED", connector)
            }
            Self::PasswordHashingFailed { connector } => {
                write!(f, "connector `{}`: password hashing failed", connector)
            }
        }
    }
}

impl std::error::Error for ConnectorError {}

/// FNV-1a, used for deterministic non-secret derivation (challenge state,
/// account digests in the local connector). Not a security primitive.
pub(crate) fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub(crate) fn challenge_state(connector: &str, tenant: Option<&str>, subject: &str) -> String {
    let material = format!("{}|{}|{}", connector, tenant.unwrap_or(""), subject);
    format!("chal_{:016x}", stable_hash(material.as_bytes()))
}
