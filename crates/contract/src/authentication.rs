use crate::{PrincipalId, SessionId, TenantId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationMethod {
    Password,
    ExternalIdentity,
    Passkey,
    Mfa,
    DeviceApproval,
    Qr,
    Recovery,
}

impl AuthenticationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ExternalIdentity => "external_identity",
            Self::Passkey => "passkey",
            Self::Mfa => "mfa",
            Self::DeviceApproval => "device_approval",
            Self::Qr => "qr",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthenticationAssurance {
    Anonymous,
    Basic,
    Strong,
    PhishingResistant,
}

impl AuthenticationAssurance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Basic => "basic",
            Self::Strong => "strong",
            Self::PhishingResistant => "phishing_resistant",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResult {
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub session: Option<SessionId>,
    pub method: AuthenticationMethod,
    pub provider: Option<String>,
    pub device: Option<DeviceId>,
    pub ceremony: Option<AuthenticationCeremonyId>,
    pub assurance: AuthenticationAssurance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationCeremonyId(pub String);

impl AuthenticationCeremonyId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationCeremony {
    pub id: AuthenticationCeremonyId,
    pub method: AuthenticationMethod,
    pub principal_hint: Option<String>,
    pub state: AuthenticationCeremonyState,
    pub created_at: i64,
    pub expires_at: i64,
}

impl AuthenticationCeremony {
    pub fn new(
        id: impl Into<String>,
        method: AuthenticationMethod,
        principal_hint: Option<String>,
        created_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            id: AuthenticationCeremonyId(id.into()),
            method,
            principal_hint,
            state: AuthenticationCeremonyState::Created,
            created_at,
            expires_at,
        }
    }

    pub fn transition(&mut self, next: AuthenticationCeremonyState) -> Result<(), String> {
        if self.state.can_transition_to(&next) {
            self.state = next;
            Ok(())
        } else {
            Err(format!(
                "cannot transition authentication ceremony from {} to {}",
                self.state.as_str(),
                next.as_str()
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationCeremonyState {
    Created,
    Challenged,
    AwaitingUser,
    Verified,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

impl AuthenticationCeremonyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Challenged => "challenged",
            Self::AwaitingUser => "awaiting_user",
            Self::Verified => "verified",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn can_transition_to(&self, next: &Self) -> bool {
        use AuthenticationCeremonyState::*;
        match (self, next) {
            (Created, Challenged | AwaitingUser | Failed | Expired | Cancelled) => true,
            (Challenged, AwaitingUser | Verified | Failed | Expired | Cancelled) => true,
            (AwaitingUser, Verified | Failed | Expired | Cancelled) => true,
            (Verified, Completed | Failed | Expired | Cancelled) => true,
            (Completed | Failed | Expired | Cancelled, _) => false,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    pub principal: PrincipalId,
    pub device_type: DeviceType,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceType {
    Browser,
    Mobile,
    Desktop,
    Cli,
    HardwareAuthenticator,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPortIdentityProfile {
    pub principal: PrincipalId,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub verified_identities: Vec<String>,
    pub avatar_url: Option<String>,
    pub application_profile_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryMethod {
    Email,
    Passkey,
    TrustedDevice,
    Administrator,
    Enterprise,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCeremony {
    pub ceremony: AuthenticationCeremony,
    pub method: RecoveryMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthExtension {
    pub id: String,
    pub extension_type: String,
    pub capabilities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{Claims, ContractVersion, Principal};

    use super::*;

    #[test]
    fn authentication_ceremony_has_explicit_lifecycle() {
        let mut ceremony = AuthenticationCeremony::new(
            "ceremony-1",
            AuthenticationMethod::Passkey,
            Some("alice@example.test".to_string()),
            100,
            160,
        );

        assert_eq!(ceremony.state, AuthenticationCeremonyState::Created);
        ceremony
            .transition(AuthenticationCeremonyState::Challenged)
            .unwrap();
        ceremony
            .transition(AuthenticationCeremonyState::AwaitingUser)
            .unwrap();
        ceremony
            .transition(AuthenticationCeremonyState::Verified)
            .unwrap();
        ceremony
            .transition(AuthenticationCeremonyState::Completed)
            .unwrap();

        assert!(ceremony
            .transition(AuthenticationCeremonyState::Verified)
            .unwrap_err()
            .contains("cannot transition"));
    }

    #[test]
    fn device_and_profile_do_not_replace_principal_authority() {
        let principal = Principal::human(
            PrincipalId("principal:alice".to_string()),
            TenantId("tenant-a".to_string()),
            Claims {
                values: HashMap::new(),
            },
            ContractVersion { major: 1, minor: 0 },
        );
        let device = Device {
            id: DeviceId("device:phone".to_string()),
            principal: principal.id.clone(),
            device_type: DeviceType::Mobile,
            name: "Alice phone".to_string(),
            created_at: 100,
            last_seen_at: Some(150),
            status: DeviceStatus::Active,
        };
        let profile = AuthPortIdentityProfile {
            principal: principal.id.clone(),
            display_name: Some("Alice".to_string()),
            email: Some("alice@example.test".to_string()),
            verified_identities: vec!["local:alice".to_string()],
            avatar_url: None,
            application_profile_ref: Some("app-profile:alice".to_string()),
        };

        assert_eq!(device.principal, principal.id);
        assert_ne!(device.id.as_str(), principal.id.as_str());
        assert_eq!(
            profile.application_profile_ref.as_deref(),
            Some("app-profile:alice")
        );
    }

    #[test]
    fn auth_extension_boundary_is_method_oriented() {
        let extension = AuthExtension {
            id: "passkey-extension".to_string(),
            extension_type: "authentication_method".to_string(),
            capabilities: vec![
                "begin".to_string(),
                "challenge".to_string(),
                "verify".to_string(),
            ],
        };

        assert_eq!(AuthenticationMethod::Passkey.as_str(), "passkey");
        assert_eq!(extension.extension_type, "authentication_method");
        assert!(extension.capabilities.contains(&"verify".to_string()));
    }
}
