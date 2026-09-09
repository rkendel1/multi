use crate::{Capability, DelegationId, PrincipalId, TenantId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub id: DelegationId,
    pub delegator: PrincipalId,
    pub delegate: PrincipalId,
    pub tenant_id: TenantId,
    pub capabilities: Vec<Capability>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

impl Delegation {
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.issued_at <= now && now < self.expires_at
    }
}
