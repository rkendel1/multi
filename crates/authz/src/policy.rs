use appport_auth_mesh_contract::{
    AuditEventId, Capability, ClaimValue, DelegationId, PolicyId, PrincipalId, PrincipalKind,
    ResourceScope, RunId, TaskId, TenantId,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: PolicyId,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub capability: Capability,
    pub condition: Condition,
    pub resource: Option<ResourceSelector>,
    pub action: Option<Action>,
    pub effect: Effect,
}

impl Rule {
    pub fn allow(capability: impl Into<Capability>, condition: Condition) -> Self {
        Self {
            capability: capability.into(),
            condition,
            resource: None,
            action: None,
            effect: Effect::Allow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action(pub String);

impl Action {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Action {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for Action {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    pub resource_type: String,
    pub resource_id: String,
    pub tenant_id: TenantId,
}

impl ResourceRef {
    pub fn new(
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        tenant_id: impl Into<TenantId>,
    ) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            tenant_id: tenant_id.into(),
        }
    }

    pub fn opaque(&self) -> String {
        format!("{}:{}", self.resource_type, self.resource_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSelector {
    pub resource_type: String,
    pub resource_id: Option<String>,
}

impl ResourceSelector {
    pub fn any(resource_type: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: None,
        }
    }

    pub fn exact(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: Some(resource_id.into()),
        }
    }

    pub fn matches(&self, resource: &ResourceRef) -> bool {
        self.resource_type == resource.resource_type
            && self
                .resource_id
                .as_ref()
                .map(|id| id == "*" || id == &resource.resource_id)
                .unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceAttributes {
    pub tenant_id: Option<TenantId>,
    pub values: BTreeMap<String, ClaimValue>,
}

impl ResourceAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tenant(mut self, tenant_id: impl Into<TenantId>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn with_value(mut self, key: impl Into<String>, value: ClaimValue) -> Self {
        self.values.insert(key.into(), value);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorizationContext {
    pub values: BTreeMap<String, ClaimValue>,
    pub run_id: Option<RunId>,
    pub task_id: Option<TaskId>,
    pub agent_principal: Option<PrincipalId>,
    pub delegation_id: Option<DelegationId>,
    pub delegation_chain: Vec<DelegationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub capability: Capability,
    pub action: Action,
    pub resource: Option<ResourceRef>,
    pub context: AuthorizationContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationEvidence {
    pub decision_id: String,
    pub timestamp: i64,
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub capability: Capability,
    pub action: Option<Action>,
    pub resource: Option<ResourceRef>,
    pub policy_id: Option<PolicyId>,
    pub matched_rules: Vec<String>,
    pub conditions: Vec<ConditionEvidence>,
    pub authority: Option<AuthorityBasis>,
    pub delegated_by: Option<PrincipalId>,
    pub delegation_chain: Vec<DelegationId>,
    pub run_id: Option<RunId>,
    pub task_id: Option<TaskId>,
    pub agent_principal: Option<PrincipalId>,
    pub delegation_id: Option<DelegationId>,
    pub parent_run_id: Option<RunId>,
    pub execution_scope: Option<ResourceScope>,
    pub authority_revision: u64,
    pub contract_fingerprint: String,
    pub decision: AuthorizationOutcome,
    pub reason: DecisionReason,
    pub audit_event_id: Option<AuditEventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Allow,
    Deny,
}

impl AuthorizationOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionEvidence {
    pub condition: String,
    pub result: ConditionResult,
    pub fact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionResult {
    Pass,
    Fail,
}

impl ConditionResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

pub trait ResourceResolver {
    fn resolve(&self, resource: &ResourceRef, context: &AuthorizationContext)
        -> ResourceAttributes;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    Always,
    All(Vec<Condition>),
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
    TenantCurrent,
    ResourceAttributeEquals {
        key: String,
        value: ClaimValue,
    },
    ResourceAttributeIn {
        key: String,
        values: Vec<ClaimValue>,
    },
    RelationshipEquals {
        resource_attribute: String,
        principal: PrincipalAttribute,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalAttribute {
    Id,
    Tenant,
    Claim(String),
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

    pub fn grant(&self, capability: &Capability) -> Option<&GrantedCapability> {
        self.granted_capabilities
            .iter()
            .find(|grant| &grant.capability == capability)
    }

    pub fn allows(&self, capability: &Capability) -> bool {
        self.grant(capability).is_some()
    }

    /// Every grant, with its authority chain.
    pub fn explain(&self) -> String {
        self.granted_capabilities
            .iter()
            .map(|grant| grant.explain())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        self.granted_capabilities
            .iter()
            .map(|grant| grant.capability.clone())
            .collect()
    }
}

/// A capability grant that can explain itself.
///
/// Provenance is not decoration: it is the answer to "why was this principal
/// allowed to do this?", and it is retained identically for humans and agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedCapability {
    pub capability: Capability,
    pub policy_id: PolicyId,
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub principal_kind: PrincipalKind,
    pub authority: AuthorityBasis,
    pub claim_basis: Vec<String>,
    pub delegation_id: Option<DelegationId>,
    pub delegation_chain: Vec<DelegationId>,
    /// The human (or service) whose authority an agent is acting on. Never
    /// collapsed into `principal_id`.
    pub delegated_by: Option<PrincipalId>,
}

impl GrantedCapability {
    pub fn is_delegated(&self) -> bool {
        self.authority == AuthorityBasis::Delegated
    }

    /// Renders the authority chain behind a single grant.
    pub fn explain(&self) -> String {
        let mut out = format!("{}\n", self.capability);
        out.push_str(&format!(
            "  principal: {} ({})\n",
            self.principal_id,
            principal_kind_str(&self.principal_kind)
        ));
        out.push_str(&format!("  tenant: {}\n", self.tenant_id));
        out.push_str(&format!("  policy: {}\n", self.policy_id));
        out.push_str(&format!("  authority: {}\n", self.authority.as_str()));
        if let Some(delegation_id) = &self.delegation_id {
            out.push_str(&format!("  delegation: {}\n", delegation_id));
        }
        if !self.delegation_chain.is_empty() {
            out.push_str(&format!(
                "  delegation_chain: {}\n",
                self.delegation_chain
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ));
        }
        if let Some(delegated_by) = &self.delegated_by {
            out.push_str(&format!("  delegated_by: {}\n", delegated_by));
        }
        out.push_str("  basis:\n");
        for basis in &self.claim_basis {
            out.push_str(&format!("    {}\n", basis));
        }
        out
    }
}

/// Where a grant's authority comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityBasis {
    /// The principal's own claims satisfied a policy rule.
    Claim,
    /// The principal is acting on authority delegated by another principal.
    Delegated,
}

impl AuthorityBasis {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Delegated => "delegated",
        }
    }
}

fn principal_kind_str(kind: &PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Agent => "agent",
        PrincipalKind::Service => "service",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow {
        grant: GrantedCapability,
        resource: Option<ResourceRef>,
        action: Option<Action>,
        matched_rules: Vec<String>,
        conditions: Vec<ConditionEvidence>,
        audit_event_id: Option<AuditEventId>,
    },
    Deny {
        reason: DenialReason,
        capability: Option<Capability>,
        resource: Option<ResourceRef>,
        action: Option<Action>,
        policy_id: Option<PolicyId>,
        matched_rules: Vec<String>,
        conditions: Vec<ConditionEvidence>,
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
    DelegationMissing,
    DelegationScopeDenied,
    DelegationExceedsAuthority,
    RunNotFound,
    RunCancelled,
    RunExpired,
    RunScopeDenied,
    RunExceedsDelegation,
    ParentRunScopeDenied,
    AgentRevoked,
    AgentSuspended,
    UnknownCapability,
    UnsupportedConnector,
    InvalidSession,
    MissingCredential,
    PolicyDenied,
    ConditionFailed,
    /// The decision could not be durably recorded, so it is not a decision.
    AuditUnavailable,
}

impl DenialReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownTenant => "unknown_tenant",
            Self::UnknownPrincipal => "unknown_principal",
            Self::TenantMismatch => "tenant_mismatch",
            Self::MissingClaim => "missing_claim",
            Self::ClaimMismatch => "claim_mismatch",
            Self::PolicyNotFound => "policy_not_found",
            Self::CapabilityNotGranted => "capability_not_granted",
            Self::ExpiredSession => "expired_session",
            Self::RevokedSession => "revoked_session",
            Self::ExpiredDelegation => "delegation_expired",
            Self::RevokedDelegation => "delegation_revoked",
            Self::InvalidDelegation => "invalid_delegation",
            Self::DelegationMissing => "delegation_missing",
            Self::DelegationScopeDenied => "delegation_scope_denied",
            Self::DelegationExceedsAuthority => "delegation_exceeds_authority",
            Self::RunNotFound => "run_not_found",
            Self::RunCancelled => "run_cancelled",
            Self::RunExpired => "run_expired",
            Self::RunScopeDenied => "run_scope_denied",
            Self::RunExceedsDelegation => "run_exceeds_delegation",
            Self::ParentRunScopeDenied => "parent_run_scope_denied",
            Self::AgentRevoked => "agent_revoked",
            Self::AgentSuspended => "agent_suspended",
            Self::UnknownCapability => "unknown_capability",
            Self::UnsupportedConnector => "unsupported_connector",
            Self::InvalidSession => "invalid_session",
            Self::MissingCredential => "missing_credential",
            Self::PolicyDenied => "policy_denied",
            Self::ConditionFailed => "condition_failed",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    AllowedByPolicy,
    CapabilityMissing,
    PolicyDenied,
    TenantMismatch,
    ConditionFailed,
    ResourceResolutionFailed,
    PrincipalMissing,
    SessionInvalid,
    RouteUnprotected,
    AuthorityUnavailable,
    DelegationMissing,
    DelegationExpired,
    DelegationRevoked,
    DelegationScopeDenied,
    DelegationExceedsAuthority,
    RunNotFound,
    RunCancelled,
    RunExpired,
    RunScopeDenied,
    RunExceedsDelegation,
    ParentRunScopeDenied,
    AgentRevoked,
    AgentSuspended,
    FailClosed,
}

impl DecisionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowedByPolicy => "allowed_by_policy",
            Self::CapabilityMissing => "capability_missing",
            Self::PolicyDenied => "policy_denied",
            Self::TenantMismatch => "tenant_mismatch",
            Self::ConditionFailed => "condition_failed",
            Self::ResourceResolutionFailed => "resource_resolution_failed",
            Self::PrincipalMissing => "principal_missing",
            Self::SessionInvalid => "session_invalid",
            Self::RouteUnprotected => "route_unprotected",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::DelegationMissing => "delegation_missing",
            Self::DelegationExpired => "delegation_expired",
            Self::DelegationRevoked => "delegation_revoked",
            Self::DelegationScopeDenied => "delegation_scope_denied",
            Self::DelegationExceedsAuthority => "delegation_exceeds_authority",
            Self::RunNotFound => "run_not_found",
            Self::RunCancelled => "run_cancelled",
            Self::RunExpired => "run_expired",
            Self::RunScopeDenied => "run_scope_denied",
            Self::RunExceedsDelegation => "run_exceeds_delegation",
            Self::ParentRunScopeDenied => "parent_run_scope_denied",
            Self::AgentRevoked => "agent_revoked",
            Self::AgentSuspended => "agent_suspended",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl AuthorizationDecision {
    pub fn denial_reason(&self) -> Option<DenialReason> {
        match self {
            Self::Deny { reason, .. } => Some(reason.clone()),
            Self::Allow { .. } => None,
        }
    }

    pub fn grant(&self) -> Option<&GrantedCapability> {
        match self {
            Self::Allow { grant, .. } => Some(grant),
            Self::Deny { .. } => None,
        }
    }

    pub fn conditions(&self) -> &[ConditionEvidence] {
        match self {
            Self::Allow { conditions, .. } | Self::Deny { conditions, .. } => conditions,
        }
    }

    pub fn reason(&self) -> DecisionReason {
        match self {
            Self::Allow { .. } => DecisionReason::AllowedByPolicy,
            Self::Deny { reason, .. } => match reason {
                DenialReason::UnknownPrincipal => DecisionReason::PrincipalMissing,
                DenialReason::TenantMismatch | DenialReason::UnknownTenant => {
                    DecisionReason::TenantMismatch
                }
                DenialReason::PolicyNotFound | DenialReason::UnknownCapability => {
                    DecisionReason::AuthorityUnavailable
                }
                DenialReason::CapabilityNotGranted
                | DenialReason::MissingClaim
                | DenialReason::ClaimMismatch => DecisionReason::CapabilityMissing,
                DenialReason::ExpiredSession
                | DenialReason::RevokedSession
                | DenialReason::InvalidSession
                | DenialReason::MissingCredential => DecisionReason::SessionInvalid,
                DenialReason::PolicyDenied => DecisionReason::PolicyDenied,
                DenialReason::ConditionFailed => DecisionReason::ConditionFailed,
                DenialReason::DelegationMissing => DecisionReason::DelegationMissing,
                DenialReason::ExpiredDelegation => DecisionReason::DelegationExpired,
                DenialReason::RevokedDelegation => DecisionReason::DelegationRevoked,
                DenialReason::DelegationScopeDenied => DecisionReason::DelegationScopeDenied,
                DenialReason::DelegationExceedsAuthority => {
                    DecisionReason::DelegationExceedsAuthority
                }
                DenialReason::RunNotFound => DecisionReason::RunNotFound,
                DenialReason::RunCancelled => DecisionReason::RunCancelled,
                DenialReason::RunExpired => DecisionReason::RunExpired,
                DenialReason::RunScopeDenied => DecisionReason::RunScopeDenied,
                DenialReason::RunExceedsDelegation => DecisionReason::RunExceedsDelegation,
                DenialReason::ParentRunScopeDenied => DecisionReason::ParentRunScopeDenied,
                DenialReason::AgentRevoked => DecisionReason::AgentRevoked,
                DenialReason::AgentSuspended => DecisionReason::AgentSuspended,
                DenialReason::InvalidDelegation
                | DenialReason::UnsupportedConnector
                | DenialReason::AuditUnavailable => DecisionReason::FailClosed,
            },
        }
    }
}
