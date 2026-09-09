use appport_auth_mesh_contract::{
    AuditEventId, Capability, ClaimValue, DelegationId, PolicyId, PrincipalId, TenantId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: PolicyId,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub capability: Capability,
    pub condition: Condition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    ClaimEquals {
        key: String,
        value: ClaimValue,
    },
    ClaimIn {
        key: String,
        values: Vec<ClaimValue>,
    },
    TimeBound {
        start: i64,
        end: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEnvelope {
    pub granted_capabilities: Vec<GrantedCapability>,
}

impl CapabilityEnvelope {
    pub fn empty() -> Self {
        Self {
            granted_capabilities: Vec::new(),
        }
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        self.granted_capabilities
            .iter()
            .map(|grant| grant.capability.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedCapability {
    pub capability: Capability,
    pub policy_id: PolicyId,
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub claim_basis: Vec<String>,
    pub delegation_id: Option<DelegationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow {
        grant: GrantedCapability,
        audit_event_id: Option<AuditEventId>,
    },
    Deny {
        reason: DenialReason,
        audit_event_id: Option<AuditEventId>,
    },
}

impl AuthorizationDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    UnknownTenant,
    UnknownPrincipal,
    TenantMismatch,
    MissingClaim,
    ClaimMismatch,
    PolicyNotFound,
    CapabilityNotGranted,
    ExpiredSession,
    RevokedSession,
    ExpiredDelegation,
    RevokedDelegation,
    InvalidDelegation,
    AgentRevoked,
    AgentSuspended,
}
