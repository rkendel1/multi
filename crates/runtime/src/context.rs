use appport_auth_mesh_contract::{Claims, Identity, Tenant};

use crate::capability_envelope::CapabilityEnvelope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContext {
    pub identity: Option<Identity>,
    pub tenant: Option<Tenant>,
    pub claims: Option<Claims>,
    pub capability_envelope: CapabilityEnvelope,
}
