use appport_auth_mesh_contract::{
    AgentRun, ExecutionCredentialId, PrincipalId, RunId, TenantContext,
};

use crate::StorageError;

/// Durable run state for agent/task authority.
pub trait RunStore {
    fn put_run(&self, run: AgentRun) -> Result<AgentRun, StorageError>;

    fn get_run(
        &self,
        tenant: &TenantContext,
        run_id: &RunId,
    ) -> Result<Option<AgentRun>, StorageError>;

    fn list_runs_for_agent(
        &self,
        tenant: &TenantContext,
        agent: &PrincipalId,
    ) -> Result<Vec<AgentRun>, StorageError>;

    fn find_run_by_credential(
        &self,
        tenant: &TenantContext,
        credential: &ExecutionCredentialId,
    ) -> Result<Option<AgentRun>, StorageError>;

    fn update_run(&self, tenant: &TenantContext, run: AgentRun) -> Result<AgentRun, StorageError>;
}
