use appport_auth_mesh_contract::{
    AgentState, ExecutionCredentialId, Principal, PrincipalId, TenantContext,
};

use crate::StorageError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoreClass {
    Identity,
    Tenant,
    Session,
    Credential,
    Policy,
    Delegation,
    Agent,
    Run,
    Audit,
    Reporting,
}

impl StoreClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Tenant => "tenant",
            Self::Session => "session",
            Self::Credential => "credential",
            Self::Policy => "policy",
            Self::Delegation => "delegation",
            Self::Agent => "agent",
            Self::Run => "run",
            Self::Audit => "audit",
            Self::Reporting => "reporting",
        }
    }

    pub fn authority_classes() -> Vec<Self> {
        vec![
            Self::Identity,
            Self::Tenant,
            Self::Session,
            Self::Credential,
            Self::Policy,
            Self::Delegation,
            Self::Agent,
            Self::Run,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageCapability {
    Transactions,
    ConditionalWrite,
    AppendOnly,
    DurableCommit,
    Query,
    Indexes,
    Subscriptions,
    History,
    ExportImport,
}

impl StorageCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transactions => "transactions",
            Self::ConditionalWrite => "conditional_write",
            Self::AppendOnly => "append_only",
            Self::DurableCommit => "durable_commit",
            Self::Query => "query",
            Self::Indexes => "indexes",
            Self::Subscriptions => "subscriptions",
            Self::History => "history",
            Self::ExportImport => "export_import",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreDescriptor {
    pub class: StoreClass,
    pub provider: String,
    pub role: StoreRole,
    pub capabilities: Vec<StorageCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRole {
    Authority,
    Audit,
    AuditSink,
    ReportingProjection,
}

impl StoreRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authority => "authority_store",
            Self::Audit => "audit_store",
            Self::AuditSink => "audit_sink",
            Self::ReportingProjection => "reporting_projection",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageTopology {
    pub stores: Vec<StoreDescriptor>,
}

impl StorageTopology {
    pub fn authport_managed_feltdb() -> Self {
        let mut stores = StoreClass::authority_classes()
            .into_iter()
            .map(|class| StoreDescriptor {
                class,
                provider: "feltdb".to_string(),
                role: StoreRole::Authority,
                capabilities: feltdb_capabilities(class),
            })
            .collect::<Vec<_>>();
        stores.push(StoreDescriptor {
            class: StoreClass::Audit,
            provider: "feltdb".to_string(),
            role: StoreRole::Audit,
            capabilities: feltdb_capabilities(StoreClass::Audit),
        });
        stores.push(StoreDescriptor {
            class: StoreClass::Reporting,
            provider: "authboundry_projection".to_string(),
            role: StoreRole::ReportingProjection,
            capabilities: vec![StorageCapability::Query, StorageCapability::ExportImport],
        });
        Self { stores }
    }

    pub fn postgres_reference() -> Self {
        let mut stores = StoreClass::authority_classes()
            .into_iter()
            .map(|class| StoreDescriptor {
                class,
                provider: "postgresql".to_string(),
                role: StoreRole::Authority,
                capabilities: vec![
                    StorageCapability::Transactions,
                    StorageCapability::ConditionalWrite,
                    StorageCapability::DurableCommit,
                    StorageCapability::Query,
                    StorageCapability::Indexes,
                    StorageCapability::ExportImport,
                ],
            })
            .collect::<Vec<_>>();
        stores.push(StoreDescriptor {
            class: StoreClass::Audit,
            provider: "postgresql".to_string(),
            role: StoreRole::Audit,
            capabilities: vec![
                StorageCapability::Transactions,
                StorageCapability::AppendOnly,
                StorageCapability::DurableCommit,
                StorageCapability::Query,
                StorageCapability::Indexes,
                StorageCapability::ExportImport,
            ],
        });
        Self { stores }
    }

    pub fn split(authority: &str, audit: &str, reporting: &str) -> Self {
        let mut topology = Self::authport_managed_feltdb();
        for store in &mut topology.stores {
            store.provider = match store.role {
                StoreRole::Authority => authority.to_string(),
                StoreRole::Audit => audit.to_string(),
                StoreRole::ReportingProjection => reporting.to_string(),
                StoreRole::AuditSink => store.provider.clone(),
            };
        }
        topology
    }

    pub fn from_declaration(authority: &str, audit: &str, reporting: &str) -> Self {
        Self::split(authority, audit, reporting)
    }
}

impl Default for StorageTopology {
    fn default() -> Self {
        Self::authport_managed_feltdb()
    }
}

pub trait CredentialStore {
    fn revoke_credential(
        &self,
        tenant: &TenantContext,
        credential: &ExecutionCredentialId,
        revoked_at: i64,
    ) -> Result<(), StorageError>;
}

pub trait AgentStore {
    fn put_agent(&self, agent: Principal) -> Result<(), StorageError>;
    fn get_agent(
        &self,
        tenant: &TenantContext,
        agent: &PrincipalId,
    ) -> Result<Option<Principal>, StorageError>;
    fn set_agent_state(
        &self,
        tenant: &TenantContext,
        agent: &PrincipalId,
        state: AgentState,
    ) -> Result<(), StorageError>;
}

pub trait ReportingProjection {
    fn project(&self, event: &crate::AuditEvent) -> Result<(), StorageError>;
}

pub trait RecoveryCapabilityStore {
    /// Create a new recovery capability (e.g., for password reset or email verification)
    fn create_capability(
        &self,
        tenant: &TenantContext,
        identity_id: &appport_auth_mesh_contract::IdentityId,
        kind: appport_auth_mesh_contract::CapabilityKind,
        expires_at: i64,
    ) -> Result<appport_auth_mesh_contract::RecoveryCapability, StorageError>;

    /// Retrieve a capability by ID
    fn get_capability(
        &self,
        tenant: &TenantContext,
        capability_id: &appport_auth_mesh_contract::CapabilityId,
    ) -> Result<Option<appport_auth_mesh_contract::RecoveryCapability>, StorageError>;

    /// Mark a capability as consumed (one-time use)
    fn consume_capability(
        &self,
        tenant: &TenantContext,
        capability_id: &appport_auth_mesh_contract::CapabilityId,
        consumed_at: i64,
    ) -> Result<(), StorageError>;
}

fn feltdb_capabilities(class: StoreClass) -> Vec<StorageCapability> {
    let mut capabilities = vec![
        StorageCapability::Transactions,
        StorageCapability::ConditionalWrite,
        StorageCapability::DurableCommit,
        StorageCapability::Query,
        StorageCapability::Indexes,
        StorageCapability::History,
        StorageCapability::ExportImport,
    ];
    if class == StoreClass::Audit {
        capabilities.push(StorageCapability::AppendOnly);
        capabilities.push(StorageCapability::Subscriptions);
    }
    capabilities
}
