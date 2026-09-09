use crate::{Claims, ContractVersion, PrincipalId, TenantId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    Human,
    Agent,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Created,
    Active,
    Suspended,
    Revoked,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub tenant_id: TenantId,
    pub claims: Claims,
    pub version: ContractVersion,
    pub agent_state: Option<AgentState>,
}

impl Principal {
    pub fn human(
        id: PrincipalId,
        tenant_id: TenantId,
        claims: Claims,
        version: ContractVersion,
    ) -> Self {
        Self {
            id,
            kind: PrincipalKind::Human,
            tenant_id,
            claims,
            version,
            agent_state: None,
        }
    }

    pub fn agent(
        id: PrincipalId,
        tenant_id: TenantId,
        claims: Claims,
        version: ContractVersion,
        state: AgentState,
    ) -> Self {
        Self {
            id,
            kind: PrincipalKind::Agent,
            tenant_id,
            claims,
            version,
            agent_state: Some(state),
        }
    }

    pub fn service(
        id: PrincipalId,
        tenant_id: TenantId,
        claims: Claims,
        version: ContractVersion,
    ) -> Self {
        Self {
            id,
            kind: PrincipalKind::Service,
            tenant_id,
            claims,
            version,
            agent_state: None,
        }
    }
}
