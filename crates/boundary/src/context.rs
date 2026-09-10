use appport_auth_mesh_authz::{AuthorizationDecision, CapabilityEnvelope};
use appport_auth_mesh_contract::{
    Capability, ClaimValue, Claims, Delegation, DelegationId, Principal, PrincipalId,
    PrincipalKind, TenantContext,
};
use appport_auth_mesh_runtime::RuntimeContext;
use appport_auth_mesh_storage::Session;

use crate::request::SessionCredential;

/// The authoritative request context.
///
/// ```text
/// Client AuthContext  = a projection of authority
/// Server AuthContext  = authority itself
/// ```
///
/// It has no public constructor, so no code outside this crate can manufacture
/// one: an `AuthContext` exists only because AuthPort verified a request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthContext {
    pub principal: Principal,
    pub tenant: TenantContext,
    pub session: Session,
    pub claims: Claims,
    pub capabilities: CapabilityEnvelope,
    pub decision: Option<AuthorizationDecision>,
    pub delegation: Option<DelegationContext>,
    runtime: RuntimeContext,
}

impl AuthContext {
    pub(crate) fn new(session: Session, runtime: RuntimeContext) -> Self {
        let delegation = runtime.delegation.clone().map(DelegationContext::new);
        Self {
            principal: runtime.principal.clone(),
            tenant: runtime.tenant.clone(),
            session,
            claims: runtime.claims.clone(),
            capabilities: runtime.capabilities.clone(),
            decision: None,
            delegation,
            runtime,
        }
    }

    pub(crate) fn with_decision(mut self, decision: AuthorizationDecision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// The authority view the policy engine evaluates against.
    pub fn runtime(&self) -> &RuntimeContext {
        &self.runtime
    }

    pub fn principal_id(&self) -> &PrincipalId {
        &self.principal.id
    }

    pub fn principal_kind(&self) -> &PrincipalKind {
        &self.principal.kind
    }

    pub fn is_agent(&self) -> bool {
        self.principal.kind == PrincipalKind::Agent
    }

    /// The human or service whose authority an agent is exercising.
    pub fn delegated_by(&self) -> Option<&PrincipalId> {
        self.delegation
            .as_ref()
            .map(|delegation| &delegation.delegated_by)
    }

    pub fn holds(&self, capability: &str) -> bool {
        self.capabilities
            .allows(&Capability(capability.to_string()))
    }

    pub fn credential(&self) -> SessionCredential {
        SessionCredential::new(self.tenant.tenant_id.to_string(), self.session.id.clone())
    }

    /// What may safely be handed to a browser.
    pub fn project(&self) -> ClientAuthContext {
        ClientAuthContext {
            authenticated: true,
            principal_id: self.principal.id.to_string(),
            principal_kind: principal_kind_str(&self.principal.kind).to_string(),
            tenant_id: self.tenant.tenant_id.to_string(),
            claims: self
                .claims
                .values
                .iter()
                .map(|(name, value)| (name.clone(), claim_string(value)))
                .collect(),
            capabilities: self
                .capabilities
                .capabilities()
                .iter()
                .map(|capability| capability.to_string())
                .collect(),
            session_expires_at: self.session.expires_at,
            delegation: self.delegation.as_ref().map(|delegation| ClientDelegation {
                id: delegation.delegation.id.to_string(),
                delegated_by: delegation.delegated_by.to_string(),
                capabilities: delegation
                    .delegation
                    .capabilities
                    .iter()
                    .map(|capability| capability.to_string())
                    .collect(),
            }),
        }
    }
}

/// The delegation an agent is acting under, alongside the delegator. The two
/// principals stay separate here exactly as they do in the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationContext {
    pub delegation: Delegation,
    pub delegated_by: PrincipalId,
}

impl DelegationContext {
    fn new(delegation: Delegation) -> Self {
        Self {
            delegated_by: delegation.delegator.clone(),
            delegation,
        }
    }

    pub fn id(&self) -> &DelegationId {
        &self.delegation.id
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.delegation.expires_at
    }
}

/// The client-side counterpart: a read-only description of what the server
/// already decided. Editing it in a browser changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthContext {
    pub authenticated: bool,
    pub principal_id: String,
    pub principal_kind: String,
    pub tenant_id: String,
    pub claims: Vec<(String, String)>,
    pub capabilities: Vec<String>,
    pub session_expires_at: i64,
    pub delegation: Option<ClientDelegation>,
}

impl ClientAuthContext {
    /// The shape `useAuth()` receives.
    pub fn to_json(&self) -> String {
        let claims = self
            .claims
            .iter()
            .map(|(name, value)| format!("\"{}\": \"{}\"", escape(name), escape(value)))
            .collect::<Vec<_>>()
            .join(", ");
        let capabilities = self
            .capabilities
            .iter()
            .map(|capability| format!("\"{}\"", escape(capability)))
            .collect::<Vec<_>>()
            .join(", ");
        let delegation = match &self.delegation {
            Some(delegation) => format!(
                "{{\"id\": \"{}\", \"delegated_by\": \"{}\", \"capabilities\": [{}]}}",
                escape(&delegation.id),
                escape(&delegation.delegated_by),
                delegation
                    .capabilities
                    .iter()
                    .map(|capability| format!("\"{}\"", escape(capability)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => "null".to_string(),
        };

        format!(
            "{{\"authenticated\": {}, \"principal\": {{\"id\": \"{}\", \"kind\": \"{}\"}}, \"tenant\": {{\"id\": \"{}\"}}, \"claims\": {{{}}}, \"capabilities\": [{}], \"session\": {{\"expires_at\": {}}}, \"delegation\": {}}}",
            self.authenticated,
            escape(&self.principal_id),
            escape(&self.principal_kind),
            escape(&self.tenant_id),
            claims,
            capabilities,
            self.session_expires_at,
            delegation
        )
    }

    /// What an unauthenticated browser sees: no authority at all.
    pub fn anonymous_json() -> String {
        "{\"authenticated\": false, \"principal\": null, \"tenant\": null, \"claims\": {}, \"capabilities\": [], \"session\": null, \"delegation\": null}"
            .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDelegation {
    pub id: String,
    pub delegated_by: String,
    pub capabilities: Vec<String>,
}

fn principal_kind_str(kind: &PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Agent => "agent",
        PrincipalKind::Service => "service",
    }
}

fn claim_string(value: &ClaimValue) -> String {
    match value {
        ClaimValue::Enum(value) | ClaimValue::String(value) => value.clone(),
        ClaimValue::Integer(value) => value.to_string(),
        ClaimValue::Boolean(value) => value.to_string(),
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
