use appport_auth_mesh_contract::{Claims, Identity, TenantContext};

use crate::capability_envelope::CapabilityEnvelope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContext {
    pub identity: Identity,
    pub tenant: TenantContext,
    pub session_id: String,
    pub claims: Claims,
    pub capability_envelope: CapabilityEnvelope,
}
