use std::collections::HashMap;
use crate::{IdentityId, TenantId};

/// A recovery or verification capability
///
/// Capabilities are durable, single-use tokens that enable specific actions:
/// - password_reset: allows password change for a specific identity
/// - email_verification: allows marking email as verified
///
/// Capabilities are consumed once to prevent replay attacks.
/// They are never transferred between identities.
///
/// Storage: FeltDB RecoveryCapability collection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCapability {
    pub id: CapabilityId,
    pub tenant_id: TenantId,
    pub identity_id: IdentityId,
    pub kind: CapabilityKind,
    pub created_at: i64,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityId(pub String);

impl CapabilityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityKind {
    PasswordReset,
    EmailVerification,
}

impl CapabilityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::EmailVerification => "email_verification",
        }
    }
}

impl RecoveryCapability {
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expires_at
    }

    pub fn is_valid(&self, now: i64) -> bool {
        !self.is_consumed() && !self.is_expired(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_validity() {
        let now = 1000;
        let cap = RecoveryCapability {
            id: CapabilityId::new("test"),
            tenant_id: TenantId::new("acme"),
            identity_id: IdentityId::new("user123"),
            kind: CapabilityKind::PasswordReset,
            created_at: 900,
            expires_at: 1900,
            consumed_at: None,
            metadata: HashMap::new(),
        };

        assert!(cap.is_valid(now));
        assert!(!cap.is_consumed());
        assert!(!cap.is_expired(now));
    }

    #[test]
    fn capability_expired() {
        let now = 2000;
        let cap = RecoveryCapability {
            id: CapabilityId::new("test"),
            tenant_id: TenantId::new("acme"),
            identity_id: IdentityId::new("user123"),
            kind: CapabilityKind::PasswordReset,
            created_at: 900,
            expires_at: 1900,
            consumed_at: None,
            metadata: HashMap::new(),
        };

        assert!(!cap.is_valid(now));
        assert!(cap.is_expired(now));
    }

    #[test]
    fn capability_consumed() {
        let now = 1000;
        let cap = RecoveryCapability {
            id: CapabilityId::new("test"),
            tenant_id: TenantId::new("acme"),
            identity_id: IdentityId::new("user123"),
            kind: CapabilityKind::PasswordReset,
            created_at: 900,
            expires_at: 1900,
            consumed_at: Some(950),
            metadata: HashMap::new(),
        };

        assert!(!cap.is_valid(now));
        assert!(cap.is_consumed());
    }
}
