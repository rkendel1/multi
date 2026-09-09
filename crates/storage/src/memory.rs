use std::collections::HashMap;
use std::sync::Mutex;

use appport_auth_mesh_contract::{
    AgentState, AuditEventId, Claims, ContractVersion, Delegation, DelegationId, Identity,
    IdentityId, OfflineSemantics, Principal, PrincipalId, PrincipalKind, ProviderName,
    ProviderSubject, SessionId, StorageRootId, TenantContext, TenantId,
};

use crate::audit_log::{AuditEvent, AuditLog};
use crate::delegation_store::DelegationStore;
use crate::identity_store::IdentityStore;
use crate::principal_store::{ExternalBinding, PrincipalStore};
use crate::session_store::{Session, SessionStore};
use crate::tenant_root::TenantRootStore;
use crate::StorageError;

#[derive(Default)]
pub struct MemoryIdentityStore {
    identities: Mutex<HashMap<IdentityId, Identity>>,
    by_provider: Mutex<HashMap<(TenantId, ProviderName, ProviderSubject), IdentityId>>,
}

impl MemoryIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for MemoryIdentityStore {
    fn link_account(
        &self,
        tenant: &TenantContext,
        provider: &ProviderName,
        provider_subject: &ProviderSubject,
    ) -> Result<Identity, StorageError> {
        let key = (
            tenant.tenant_id.clone(),
            provider.clone(),
            provider_subject.clone(),
        );
        let mut by_provider = self.by_provider.lock().map_err(lock_error)?;
        if by_provider.contains_key(&key) {
            return Err(StorageError::new("duplicate identity"));
        }

        let id = IdentityId(format!(
            "{}:{}:{}",
            tenant.tenant_id, provider, provider_subject
        ));
        let identity = Identity {
            id: id.clone(),
            provider: provider.clone(),
            provider_subject: provider_subject.clone(),
            tenant_id: tenant.tenant_id.clone(),
            claims: Claims {
                values: HashMap::new(),
            },
            version: ContractVersion { major: 1, minor: 0 },
            offline: OfflineSemantics {
                max_age_seconds: 300,
                must_revalidate: true,
            },
        };

        self.identities
            .lock()
            .map_err(lock_error)?
            .insert(id.clone(), identity.clone());
        by_provider.insert(key, id);
        Ok(identity)
    }

    fn get_identity(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
    ) -> Result<Option<Identity>, StorageError> {
        let identity = self
            .identities
            .lock()
            .map_err(lock_error)?
            .get(identity_id)
            .cloned();

        match identity {
            Some(identity) if identity.tenant_id == tenant.tenant_id => Ok(Some(identity)),
            Some(_) => Err(StorageError::new("tenant mismatch")),
            None => Ok(None),
        }
    }

    fn find_identity(
        &self,
        tenant: &TenantContext,
        provider: &ProviderName,
        provider_subject: &ProviderSubject,
    ) -> Result<Option<Identity>, StorageError> {
        let key = (
            tenant.tenant_id.clone(),
            provider.clone(),
            provider_subject.clone(),
        );
        let id = self
            .by_provider
            .lock()
            .map_err(lock_error)?
            .get(&key)
            .cloned();
        match id {
            Some(id) => self.get_identity(tenant, &id),
            None => Ok(None),
        }
    }

    fn update_claims(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
        claims: Claims,
    ) -> Result<(), StorageError> {
        let mut identities = self.identities.lock().map_err(lock_error)?;
        let identity = identities
            .get_mut(identity_id)
            .ok_or_else(|| StorageError::new("unknown identity"))?;
        if identity.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        identity.claims = claims;
        Ok(())
    }
}

#[derive(Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<SessionId, Session>>,
    next_id: Mutex<u64>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn create_session(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
        expires_at: i64,
        _device_info: Option<String>,
    ) -> Result<Session, StorageError> {
        let mut next_id = self.next_id.lock().map_err(lock_error)?;
        *next_id += 1;
        let session = Session {
            id: SessionId(format!("session-{}", next_id)),
            identity_id: identity_id.clone(),
            tenant_id: tenant.tenant_id.clone(),
            created_at: 0,
            expires_at,
            revoked_at: None,
        };
        self.sessions
            .lock()
            .map_err(lock_error)?
            .insert(session.id.clone(), session.clone());
        Ok(session)
    }

    fn revoke_session(
        &self,
        tenant: &TenantContext,
        session_id: &SessionId,
        revoked_at: i64,
    ) -> Result<(), StorageError> {
        let mut sessions = self.sessions.lock().map_err(lock_error)?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| StorageError::new("unknown session"))?;
        if session.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        session.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate_session(
        &self,
        tenant: &TenantContext,
        session_id: &SessionId,
        now: i64,
    ) -> Result<Session, StorageError> {
        let session = self
            .sessions
            .lock()
            .map_err(lock_error)?
            .get(session_id)
            .cloned()
            .ok_or_else(|| StorageError::new("unknown session"))?;
        if session.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        if session.revoked_at.is_some() {
            return Err(StorageError::new("revoked session"));
        }
        if now >= session.expires_at {
            return Err(StorageError::new("expired session"));
        }
        Ok(session)
    }

    fn list_sessions(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
    ) -> Result<Vec<Session>, StorageError> {
        Ok(self
            .sessions
            .lock()
            .map_err(lock_error)?
            .values()
            .filter(|session| {
                session.tenant_id == tenant.tenant_id && &session.identity_id == identity_id
            })
            .cloned()
            .collect())
    }
}

#[derive(Default)]
pub struct MemoryAuditLog {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Result<Vec<AuditEvent>, StorageError> {
        Ok(self.events.lock().map_err(lock_error)?.clone())
    }
}

impl AuditLog for MemoryAuditLog {
    fn record_event(&self, tenant: &TenantContext, event: AuditEvent) -> Result<(), StorageError> {
        if event.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        self.events.lock().map_err(lock_error)?.push(event);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryTenantRoot {
    tenants: Mutex<HashMap<TenantId, TenantContext>>,
}

impl MemoryTenantRoot {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TenantRootStore for MemoryTenantRoot {
    fn put_tenant(&self, tenant: TenantContext) -> Result<(), StorageError> {
        self.tenants
            .lock()
            .map_err(lock_error)?
            .insert(tenant.tenant_id.clone(), tenant);
        Ok(())
    }

    fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<TenantContext>, StorageError> {
        Ok(self
            .tenants
            .lock()
            .map_err(lock_error)?
            .get(tenant_id)
            .cloned())
    }

    fn verify_storage_root(
        &self,
        tenant: &TenantContext,
        storage_root_id: &StorageRootId,
    ) -> Result<(), StorageError> {
        let stored = self
            .get_tenant(&tenant.tenant_id)?
            .ok_or_else(|| StorageError::new("unknown tenant"))?;
        if stored.storage_root_id != *storage_root_id || tenant.storage_root_id != *storage_root_id
        {
            return Err(StorageError::new("storage-root mismatch"));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryPrincipalStore {
    principals: Mutex<HashMap<PrincipalId, Principal>>,
    bindings: Mutex<HashMap<(TenantId, ProviderName, ProviderSubject), ExternalBinding>>,
}

impl MemoryPrincipalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PrincipalStore for MemoryPrincipalStore {
    fn put_principal(&self, principal: Principal) -> Result<(), StorageError> {
        self.principals
            .lock()
            .map_err(lock_error)?
            .insert(principal.id.clone(), principal);
        Ok(())
    }

    fn get_principal(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, StorageError> {
        let principal = self
            .principals
            .lock()
            .map_err(lock_error)?
            .get(principal_id)
            .cloned();
        match principal {
            Some(principal) if principal.tenant_id == tenant.tenant_id => Ok(Some(principal)),
            Some(_) => Err(StorageError::new("tenant mismatch")),
            None => Ok(None),
        }
    }

    fn list_principals(&self, tenant: &TenantContext) -> Result<Vec<Principal>, StorageError> {
        let mut principals = self
            .principals
            .lock()
            .map_err(lock_error)?
            .values()
            .filter(|principal| principal.tenant_id == tenant.tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        principals.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(principals)
    }

    fn set_agent_state(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
        state: AgentState,
    ) -> Result<(), StorageError> {
        let mut principals = self.principals.lock().map_err(lock_error)?;
        let principal = principals
            .get_mut(principal_id)
            .ok_or_else(|| StorageError::new("unknown principal"))?;
        if principal.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        if principal.kind != PrincipalKind::Agent {
            return Err(StorageError::new("principal is not an agent"));
        }
        principal.agent_state = Some(state);
        Ok(())
    }

    fn update_claims(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
        claims: Claims,
    ) -> Result<(), StorageError> {
        let mut principals = self.principals.lock().map_err(lock_error)?;
        let principal = principals
            .get_mut(principal_id)
            .ok_or_else(|| StorageError::new("unknown principal"))?;
        if principal.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        principal.claims = claims;
        Ok(())
    }

    fn bind_external_identity(
        &self,
        tenant: &TenantContext,
        connector: &ProviderName,
        external_subject: &ProviderSubject,
        principal_id: &PrincipalId,
        linked_at: i64,
    ) -> Result<ExternalBinding, StorageError> {
        if self.get_principal(tenant, principal_id)?.is_none() {
            return Err(StorageError::new("unknown principal"));
        }

        let key = (
            tenant.tenant_id.clone(),
            connector.clone(),
            external_subject.clone(),
        );
        let mut bindings = self.bindings.lock().map_err(lock_error)?;
        if let Some(existing) = bindings.get(&key) {
            if &existing.principal_id != principal_id {
                // (tenant, connector, external_subject) -> exactly one principal.
                return Err(StorageError::new(
                    "external identity is already bound to another principal",
                ));
            }
            return Ok(existing.clone());
        }

        let binding = ExternalBinding {
            tenant_id: tenant.tenant_id.clone(),
            connector: connector.clone(),
            external_subject: external_subject.clone(),
            principal_id: principal_id.clone(),
            linked_at,
        };
        bindings.insert(key, binding.clone());
        Ok(binding)
    }

    fn resolve_external_identity(
        &self,
        tenant: &TenantContext,
        connector: &ProviderName,
        external_subject: &ProviderSubject,
    ) -> Result<Option<PrincipalId>, StorageError> {
        let key = (
            tenant.tenant_id.clone(),
            connector.clone(),
            external_subject.clone(),
        );
        Ok(self
            .bindings
            .lock()
            .map_err(lock_error)?
            .get(&key)
            .map(|binding| binding.principal_id.clone()))
    }

    fn bindings_for(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
    ) -> Result<Vec<ExternalBinding>, StorageError> {
        let mut bindings = self
            .bindings
            .lock()
            .map_err(lock_error)?
            .values()
            .filter(|binding| {
                binding.tenant_id == tenant.tenant_id && &binding.principal_id == principal_id
            })
            .cloned()
            .collect::<Vec<_>>();
        bindings.sort_by(|a, b| {
            (&a.connector, &a.external_subject).cmp(&(&b.connector, &b.external_subject))
        });
        Ok(bindings)
    }
}

#[derive(Default)]
pub struct MemoryDelegationStore {
    delegations: Mutex<HashMap<DelegationId, Delegation>>,
}

impl MemoryDelegationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DelegationStore for MemoryDelegationStore {
    fn create_delegation(&self, delegation: Delegation) -> Result<Delegation, StorageError> {
        if delegation.capabilities.is_empty() {
            return Err(StorageError::new("delegation requires capabilities"));
        }
        if delegation.expires_at <= delegation.issued_at {
            return Err(StorageError::new("delegation must be time-bound"));
        }
        if delegation.delegator == delegation.delegate {
            return Err(StorageError::new("delegation requires two principals"));
        }

        let mut delegations = self.delegations.lock().map_err(lock_error)?;
        if delegations.contains_key(&delegation.id) {
            return Err(StorageError::new("duplicate delegation"));
        }
        delegations.insert(delegation.id.clone(), delegation.clone());
        Ok(delegation)
    }

    fn get_delegation(
        &self,
        tenant: &TenantContext,
        delegation_id: &DelegationId,
    ) -> Result<Option<Delegation>, StorageError> {
        let delegation = self
            .delegations
            .lock()
            .map_err(lock_error)?
            .get(delegation_id)
            .cloned();
        match delegation {
            Some(delegation) if delegation.tenant_id == tenant.tenant_id => Ok(Some(delegation)),
            Some(_) => Err(StorageError::new("tenant mismatch")),
            None => Ok(None),
        }
    }

    fn list_delegations_for_delegate(
        &self,
        tenant: &TenantContext,
        delegate: &PrincipalId,
    ) -> Result<Vec<Delegation>, StorageError> {
        let mut delegations = self
            .delegations
            .lock()
            .map_err(lock_error)?
            .values()
            .filter(|delegation| {
                delegation.tenant_id == tenant.tenant_id && &delegation.delegate == delegate
            })
            .cloned()
            .collect::<Vec<_>>();
        delegations.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(delegations)
    }

    fn revoke_delegation(
        &self,
        tenant: &TenantContext,
        delegation_id: &DelegationId,
        revoked_at: i64,
    ) -> Result<(), StorageError> {
        let mut delegations = self.delegations.lock().map_err(lock_error)?;
        let delegation = delegations
            .get_mut(delegation_id)
            .ok_or_else(|| StorageError::new("unknown delegation"))?;
        if delegation.tenant_id != tenant.tenant_id {
            return Err(StorageError::new("tenant mismatch"));
        }
        delegation.revoked_at = Some(revoked_at);
        Ok(())
    }
}

fn lock_error<T>(_: T) -> StorageError {
    StorageError::new("memory store lock poisoned")
}

pub fn audit_event_id(value: impl Into<String>) -> AuditEventId {
    AuditEventId(value.into())
}
