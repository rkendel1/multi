use crate::{
    Capability, DelegationId, ExecutionCredentialId, PrincipalId, ResourceScope, RunId, TaskId,
    TenantId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    pub id: TaskId,
    pub purpose: String,
    pub capabilities: Vec<Capability>,
    pub resource_scope: ResourceScope,
    pub expires_at: i64,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    Active,
    Completed,
    Cancelled,
    Expired,
    Failed,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRun {
    pub id: RunId,
    pub tenant_id: TenantId,
    pub agent_principal: PrincipalId,
    pub delegator: PrincipalId,
    pub delegation_id: DelegationId,
    pub delegation_chain: Vec<DelegationId>,
    pub task: TaskSpec,
    pub parent_run_id: Option<RunId>,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: RunStatus,
    pub authority_revision: u64,
    pub contract_fingerprint: String,
    pub capability_scope: Vec<Capability>,
    pub resource_scope: ResourceScope,
    pub execution_credential: ExecutionCredentialId,
    pub cancelled_at: Option<i64>,
}
