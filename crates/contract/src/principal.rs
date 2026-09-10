use crate::{AgentCredentialId, AgentId, Claims, ContractVersion, PrincipalId, TenantId};

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

pub type AgentStatus = AgentState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub id: AgentId,
    pub principal_id: PrincipalId,
    pub tenant_id: TenantId,
    pub name: String,
    pub status: AgentStatus,
    pub created_by: PrincipalId,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCredential {
    pub id: AgentCredentialId,
    pub agent: PrincipalId,
    pub tenant_id: TenantId,
    pub secret_hash: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

impl AgentCredential {
    pub fn is_valid_at(&self, agent: &Principal, now: i64) -> bool {
        agent.kind == PrincipalKind::Agent
            && agent.tenant_id == self.tenant_id
            && agent.id == self.agent
            && agent.agent_state == Some(AgentState::Active)
            && self
                .revoked_at
                .map(|revoked_at| now < revoked_at)
                .unwrap_or(true)
    }
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
