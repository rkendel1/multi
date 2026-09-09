use appport_auth_mesh_contract::{Claims, Delegation, Principal, TenantContext};

use crate::capability_envelope::CapabilityEnvelope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContext {
    pub principal: Principal,
    pub tenant: TenantContext,
    pub delegation: Option<Delegation>,
    pub claims: Claims,
    pub capabilities: CapabilityEnvelope,
}
