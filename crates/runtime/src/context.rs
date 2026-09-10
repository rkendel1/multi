use appport_auth_mesh_contract::{
    AgentRun, Claims, Delegation, Principal, PrincipalId, PrincipalKind, SessionId, TenantContext,
};

use crate::capability_envelope::CapabilityEnvelope;

/// What the application sees for the current request.
///
/// `principal` is always the actor itself. When an agent acts on delegated
/// authority the delegator is reachable through `delegated_by()`, never by
/// substituting one principal for the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContext {
    pub principal: Principal,
    pub tenant: TenantContext,
    pub session_id: Option<SessionId>,
    pub delegation: Option<Delegation>,
    pub run: Option<AgentRun>,
    pub claims: Claims,
    pub capabilities: CapabilityEnvelope,
}

impl RuntimeContext {
    pub fn principal_kind(&self) -> &PrincipalKind {
        &self.principal.kind
    }

    pub fn is_agent(&self) -> bool {
        self.principal.kind == PrincipalKind::Agent
    }

    /// The principal whose authority is being exercised, when it is not the
    /// acting principal's own.
    pub fn delegated_by(&self) -> Option<&PrincipalId> {
        self.delegation
            .as_ref()
            .map(|delegation| &delegation.delegator)
    }

    pub fn holds(&self, capability: &appport_auth_mesh_contract::Capability) -> bool {
        self.capabilities.allows(capability)
    }

    pub fn with_run(mut self, run: AgentRun) -> Self {
        self.run = Some(run);
        self
    }

    /// Why this context holds what it holds.
    pub fn explain(&self) -> String {
        self.capabilities.explain()
    }
}
