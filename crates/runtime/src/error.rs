use appport_auth_mesh_authz::DenialReason;

/// Where in the auth lifecycle a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthLifecycleStage {
    TenantResolution,
    ConnectorResolution,
    ProviderAuthentication,
    IdentityResolution,
    PrincipalResolution,
    SessionValidation,
    ClaimsResolution,
    PolicyEvaluation,
    DelegationManagement,
    AgentLifecycle,
    RuntimeContext,
    Configuration,
}

impl AuthLifecycleStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TenantResolution => "tenant_resolution",
            Self::ConnectorResolution => "connector_resolution",
            Self::ProviderAuthentication => "provider_authentication",
            Self::IdentityResolution => "identity_resolution",
            Self::PrincipalResolution => "principal_resolution",
            Self::SessionValidation => "session_validation",
            Self::ClaimsResolution => "claims_resolution",
            Self::PolicyEvaluation => "policy_evaluation",
            Self::DelegationManagement => "delegation_management",
            Self::AgentLifecycle => "agent_lifecycle",
            Self::RuntimeContext => "runtime_context",
            Self::Configuration => "configuration",
        }
    }
}

/// Every failure is a denial.
///
/// There is no partially-authenticated state and no fallback path: a stage that
/// cannot complete produces an `AuthError` carrying the reason it denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    pub stage: AuthLifecycleStage,
    pub message: String,
    pub denial: DenialReason,
}

impl AuthError {
    pub fn new(
        stage: AuthLifecycleStage,
        message: impl Into<String>,
        denial: DenialReason,
    ) -> Self {
        Self {
            stage,
            message: message.into(),
            denial,
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthError {}
