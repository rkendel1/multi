use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use appport_auth_mesh_authz::{
    evaluate_authorization_request, evaluate_capability, evaluate_with_delegations,
    AuthorizationDecision, AuthorizationEvidence, AuthorizationOutcome, AuthorizationRequest,
    CapabilityEnvelope, DenialReason, Policy, ResourceAttributes,
};
use appport_auth_mesh_authz::{Action, Condition, Effect, ResourceSelector, Rule};
use appport_auth_mesh_contract::{
    AgentRun, AgentState, AuditEventId, Capability, ClaimValue, Claims, Delegation, DelegationId,
    ExecutionCredentialId, Principal, PrincipalId, PrincipalKind, ResourceScope, RunId, RunStatus,
    SessionId, TaskId, TaskSpec, TenantContext, TenantId,
};
use appport_auth_mesh_dsl::{stable_hash, AuthConfig};
use appport_auth_mesh_providers::{
    AuthChallenge, AuthRequest, AuthResponse, ConnectorError, ConnectorRegistry, ExternalIdentity,
};
use appport_auth_mesh_storage::{
    AuditDurability, AuditEvent, AuditEventKind, AuditLog, DelegationStore, ExternalBinding,
    IdentityStore, PrincipalStore, RunStore, Session, SessionStore, StorageError, StorageTopology,
    TenantRootStore,
};
use appport_auth_mesh_surface::{render_text, AuthSurface};

use crate::claims::resolve_claims;
use crate::context::RuntimeContext;
use crate::error::{AuthError, AuthLifecycleStage};
use crate::policy_store::PolicyStore;
use crate::resolution::{
    link_external_identity, principal_id_for, provision_principal, resolve_principal,
};

pub const DEFAULT_SESSION_TTL_SECONDS: i64 = 3600;

/// The durable state the mesh owns on the application's behalf.
///
/// The application declares `use auth { ... }`; it does not declare session
/// tables, identity tables, token storage or tenant lookup.
#[derive(Clone)]
pub struct MeshStores {
    pub tenants: Arc<dyn TenantRootStore + Send + Sync>,
    pub identities: Arc<dyn IdentityStore + Send + Sync>,
    pub principals: Arc<dyn PrincipalStore + Send + Sync>,
    pub sessions: Arc<dyn SessionStore + Send + Sync>,
    pub delegations: Arc<dyn DelegationStore + Send + Sync>,
    pub runs: Arc<dyn RunStore + Send + Sync>,
    pub policies: Arc<dyn PolicyStore + Send + Sync>,
    pub audit: Arc<dyn AuditLog + Send + Sync>,
    pub topology: StorageTopology,
}

/// The auth capability.
///
/// One object holds the declaration, the derived surface, the connector
/// registry and the durable state, and every authority question — for humans
/// and for agents alike — is answered through it.
pub struct AuthMesh {
    config: AuthConfig,
    surface: AuthSurface,
    registry: ConnectorRegistry,
    stores: MeshStores,
    session_ttl: i64,
    audit_sequence: AtomicU64,
    run_sequence: AtomicU64,
    decisions: Mutex<Vec<AuthorizationEvidence>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub kind: PrincipalKind,
    pub claims: BTreeMap<String, String>,
}

impl Registration {
    pub fn human() -> Self {
        Self {
            kind: PrincipalKind::Human,
            claims: BTreeMap::new(),
        }
    }

    pub fn agent() -> Self {
        Self {
            kind: PrincipalKind::Agent,
            claims: BTreeMap::new(),
        }
    }

    pub fn service() -> Self {
        Self {
            kind: PrincipalKind::Service,
            claims: BTreeMap::new(),
        }
    }

    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(name.into(), value.into());
        self
    }
}

/// The result of a completed authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSession {
    pub session: Session,
    pub external: ExternalIdentity,
    pub context: RuntimeContext,
}

impl AuthenticatedSession {
    pub fn principal(&self) -> &Principal {
        &self.context.principal
    }
}

/// A request to delegate authority to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRequest {
    pub id: DelegationId,
    pub delegator: PrincipalId,
    pub delegate: PrincipalId,
    pub capabilities: Vec<Capability>,
    pub resource_scope: ResourceScope,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCreationRequest {
    pub id: Option<RunId>,
    pub task_id: TaskId,
    pub task_purpose: String,
    pub delegation_id: DelegationId,
    pub parent_run_id: Option<RunId>,
    pub capabilities: Vec<Capability>,
    pub resource_scope: ResourceScope,
    pub expires_at: i64,
    pub constraints: Vec<String>,
}

/// One entry in the authority audit trail.
struct AuditRecord<'r> {
    kind: AuditEventKind,
    principal_id: Option<&'r PrincipalId>,
    session_id: Option<&'r SessionId>,
    delegation_id: Option<&'r DelegationId>,
    metadata: Vec<(String, String)>,
}

impl<'r> AuditRecord<'r> {
    fn new(kind: AuditEventKind) -> Self {
        Self {
            kind,
            principal_id: None,
            session_id: None,
            delegation_id: None,
            metadata: Vec::new(),
        }
    }

    fn principal(mut self, principal_id: &'r PrincipalId) -> Self {
        self.principal_id = Some(principal_id);
        self
    }

    fn session(mut self, session_id: &'r SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    fn delegation(mut self, delegation_id: &'r DelegationId) -> Self {
        self.delegation_id = Some(delegation_id);
        self
    }

    fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }
}

impl AuthMesh {
    /// Build the capability from a declaration.
    ///
    /// Every declared provider must be resolvable through the registry: a
    /// contract the runtime cannot honour is a configuration failure, not
    /// something to discover at login time.
    pub fn new(
        config: AuthConfig,
        registry: ConnectorRegistry,
        stores: MeshStores,
    ) -> Result<Self, AuthError> {
        config.validate().map_err(|err| {
            AuthError::new(
                AuthLifecycleStage::Configuration,
                err.message,
                DenialReason::UnsupportedConnector,
            )
        })?;

        for provider in &config.providers {
            if !registry.contains(provider) {
                return Err(AuthError::new(
                    AuthLifecycleStage::Configuration,
                    format!("declared provider `{}` has no connector", provider),
                    DenialReason::UnsupportedConnector,
                ));
            }
        }

        let surface = AuthSurface::derive(&config);
        Ok(Self {
            config,
            surface,
            registry,
            stores,
            session_ttl: DEFAULT_SESSION_TTL_SECONDS,
            audit_sequence: AtomicU64::new(0),
            run_sequence: AtomicU64::new(0),
            decisions: Mutex::new(Vec::new()),
        })
    }

    pub fn with_session_ttl(mut self, seconds: i64) -> Self {
        self.session_ttl = seconds;
        self
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    pub fn surface(&self) -> &AuthSurface {
        &self.surface
    }

    pub fn registry(&self) -> &ConnectorRegistry {
        &self.registry
    }

    /// The durable state behind the mesh, for surfaces that read it directly
    /// (listing a tenant's agents, for instance). Every store is tenant-scoped.
    pub fn stores(&self) -> &MeshStores {
        &self.stores
    }

    pub fn audit_events(
        &self,
        tenant: &TenantContext,
        since: Option<i64>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, AuthError> {
        self.stores
            .audit
            .events(tenant, since, limit)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::RuntimeContext,
                    err.message,
                    DenialReason::TenantMismatch,
                )
            })
    }

    /// The developer-facing view of what this declaration generated.
    pub fn inspect(&self) -> String {
        render_text(&self.surface)
    }

    /// Start an authentication attempt through a declared connector.
    pub fn begin(
        &self,
        tenant_id: &str,
        request: &AuthRequest,
    ) -> Result<AuthChallenge, AuthError> {
        // The tenant is resolved before anything else: there is no implicit
        // tenant and no tenant-less authentication.
        let _tenant = self.tenant(tenant_id)?;
        let connector = self.connector(&request.connector)?;
        connector.begin(request).map_err(connector_error)
    }

    /// Sign in an already-linked external identity. Never provisions.
    pub fn sign_in(
        &self,
        tenant_id: &str,
        response: &AuthResponse,
        now: i64,
    ) -> Result<AuthenticatedSession, AuthError> {
        let tenant = self.tenant(tenant_id)?;
        let external = self.authenticate_external(&tenant, response)?;

        let resolved = resolve_principal(
            self.stores.identities.as_ref(),
            self.stores.principals.as_ref(),
            &tenant,
            &external,
        )?
        .ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::PrincipalResolution,
                format!(
                    "external identity `{}:{}` is not linked in this tenant",
                    external.connector, external.subject
                ),
                DenialReason::UnknownPrincipal,
            )
        })?;

        self.assert_principal_is_usable(&resolved.principal)?;

        let session = self.open_session(&tenant, &resolved.identity.id, now)?;
        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::Login)
                .principal(&resolved.principal.id)
                .session(&session.id)
                .meta("connector", &external.connector),
            now,
        )?;

        let context =
            self.context_for(&tenant, resolved.principal, Some(session.id.clone()), now)?;
        Ok(AuthenticatedSession {
            session,
            external,
            context,
        })
    }

    /// Register a new principal for a proven external identity.
    ///
    /// The principal — human, agent or service — is created by the mesh, not by
    /// the connector, and its claims are validated against the declared schema.
    pub fn sign_up(
        &self,
        tenant_id: &str,
        response: &AuthResponse,
        registration: Registration,
        now: i64,
    ) -> Result<AuthenticatedSession, AuthError> {
        let tenant = self.tenant(tenant_id)?;

        if registration.kind == PrincipalKind::Agent && !self.config.agents {
            return Err(AuthError::new(
                AuthLifecycleStage::AgentLifecycle,
                "agents are not declared by `use auth`",
                DenialReason::UnknownPrincipal,
            ));
        }

        let external = self.authenticate_external(&tenant, response)?;

        // An agent is not a human with a role. Its authority comes from a
        // delegation, so it never carries the application's claim schema.
        let claims = if registration.kind == PrincipalKind::Agent {
            if !registration.claims.is_empty() {
                return Err(AuthError::new(
                    AuthLifecycleStage::AgentLifecycle,
                    "agent authority comes from delegation, not from claims",
                    DenialReason::ClaimMismatch,
                ));
            }
            Claims {
                values: HashMap::new(),
            }
        } else {
            resolve_claims(&self.config, &registration.claims)?
        };

        let resolved = provision_principal(
            self.stores.identities.as_ref(),
            self.stores.principals.as_ref(),
            &tenant,
            &external,
            registration.kind.clone(),
            claims,
            now,
        )?;

        let session = self.open_session(&tenant, &resolved.identity.id, now)?;
        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::AccountLinked)
                .principal(&resolved.principal.id)
                .session(&session.id)
                .meta("connector", &external.connector),
            now,
        )?;

        let context =
            self.context_for(&tenant, resolved.principal, Some(session.id.clone()), now)?;
        Ok(AuthenticatedSession {
            session,
            external,
            context,
        })
    }

    /// Link a second proven external identity to an existing principal.
    pub fn link_account(
        &self,
        tenant_id: &str,
        principal_id: &PrincipalId,
        response: &AuthResponse,
        now: i64,
    ) -> Result<ExternalBinding, AuthError> {
        let tenant = self.tenant(tenant_id)?;
        let external = self.authenticate_external(&tenant, response)?;

        let binding = link_external_identity(
            self.stores.identities.as_ref(),
            self.stores.principals.as_ref(),
            &tenant,
            principal_id,
            &external,
            now,
        )?;

        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::AccountLinked)
                .principal(principal_id)
                .meta("connector", &external.connector),
            now,
        )?;
        Ok(binding)
    }

    pub fn logout(
        &self,
        tenant_id: &str,
        session_id: &SessionId,
        now: i64,
    ) -> Result<(), AuthError> {
        let tenant = self.tenant(tenant_id)?;
        self.stores
            .sessions
            .revoke_session(&tenant, session_id, now)
            .map_err(session_error)?;
        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::SessionRevoked).session(session_id),
            now,
        )
    }

    /// Rebuild the runtime context behind a live session.
    pub fn session_context(
        &self,
        tenant_id: &str,
        session_id: &SessionId,
        now: i64,
    ) -> Result<RuntimeContext, AuthError> {
        self.resolve_session(tenant_id, session_id, now)
            .map(|(_, context)| context)
    }

    /// The session record together with the authority derived from it.
    ///
    /// Nothing about the caller's request is carried through: the principal,
    /// the tenant, the claims and the capabilities are all read back from
    /// AuthPort's own state.
    pub fn resolve_session(
        &self,
        tenant_id: &str,
        session_id: &SessionId,
        now: i64,
    ) -> Result<(Session, RuntimeContext), AuthError> {
        let tenant = self.tenant(tenant_id)?;
        let session = self
            .stores
            .sessions
            .validate_session(&tenant, session_id, now)
            .map_err(session_error)?;

        let identity = self
            .stores
            .identities
            .get_identity(&tenant, &session.identity_id)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::IdentityResolution,
                    err.message,
                    DenialReason::UnknownPrincipal,
                )
            })?
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::IdentityResolution,
                    "session identity is unknown",
                    DenialReason::InvalidSession,
                )
            })?;

        let principal_id = self
            .stores
            .principals
            .resolve_external_identity(&tenant, &identity.provider, &identity.provider_subject)
            .map_err(principal_error)?
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::PrincipalResolution,
                    "session identity is not bound to a principal",
                    DenialReason::UnknownPrincipal,
                )
            })?;

        let principal = self.principal(&tenant, &principal_id)?;
        self.assert_principal_is_usable(&principal)?;
        let context = self.context_for(&tenant, principal, Some(session.id.clone()), now)?;
        Ok((session, context))
    }

    /// Delegate a subset of the delegator's own authority to an agent.
    ///
    /// A delegation can never widen authority: every capability must already be
    /// held by the delegator under this tenant's policy.
    pub fn delegate(
        &self,
        tenant_id: &str,
        request: DelegationRequest,
        now: i64,
    ) -> Result<Delegation, AuthError> {
        let tenant = self.tenant(tenant_id)?;

        if !self.config.agents {
            return Err(AuthError::new(
                AuthLifecycleStage::DelegationManagement,
                "delegation requires `agents = true`",
                DenialReason::InvalidDelegation,
            ));
        }
        if request.capabilities.is_empty() {
            return Err(delegation_error("delegation must be capability-scoped"));
        }
        if request
            .expires_at
            .map(|expires_at| expires_at <= request.issued_at || expires_at <= now)
            .unwrap_or(false)
        {
            return Err(delegation_error("delegation expires before it can be used"));
        }

        let delegator = self.principal(&tenant, &request.delegator)?;
        let delegate = self.principal(&tenant, &request.delegate)?;

        if delegate.kind == PrincipalKind::Human {
            return Err(delegation_error("delegation targets an agent or a service"));
        }
        self.assert_principal_is_usable(&delegate)?;

        let policy = self.policy(&tenant)?;
        let delegator_delegations = self.delegations_for(&tenant, &delegator.id)?;
        let delegator_envelope =
            evaluate_with_delegations(&policy, &delegator, &tenant, &delegator_delegations, now)
                .map_err(|err| {
                    AuthError::new(
                        AuthLifecycleStage::PolicyEvaluation,
                        err.message,
                        DenialReason::PolicyNotFound,
                    )
                })?;

        let mut chain = Vec::new();
        for capability in &request.capabilities {
            if !delegator_envelope.allows(capability) {
                return Err(AuthError::new(
                    AuthLifecycleStage::DelegationManagement,
                    format!(
                        "delegator `{}` does not hold `{}`",
                        request.delegator, capability
                    ),
                    DenialReason::DelegationExceedsAuthority,
                ));
            }
            if delegator.kind == PrincipalKind::Agent {
                let parent = delegator_delegations
                    .iter()
                    .find(|delegation| {
                        delegation.is_valid_at(now) && delegation.capabilities.contains(capability)
                    })
                    .ok_or_else(|| {
                        AuthError::new(
                            AuthLifecycleStage::DelegationManagement,
                            format!(
                                "delegator `{}` does not hold `{}`",
                                request.delegator, capability
                            ),
                            DenialReason::DelegationExceedsAuthority,
                        )
                    })?;
                if !request.resource_scope.is_subset_of(&parent.resource_scope) {
                    return Err(AuthError::new(
                        AuthLifecycleStage::DelegationManagement,
                        "delegation scope must narrow the delegator's authority",
                        DenialReason::DelegationScopeDenied,
                    ));
                }
                if chain.is_empty() {
                    chain = parent.chain.clone();
                    chain.push(parent.id.clone());
                }
            }
        }

        let delegation = self
            .stores
            .delegations
            .create_delegation(Delegation {
                id: request.id,
                delegator: request.delegator,
                delegate: request.delegate,
                tenant_id: tenant.tenant_id.clone(),
                capabilities: request.capabilities,
                resource_scope: request.resource_scope,
                issued_at: request.issued_at,
                expires_at: request.expires_at,
                revoked_at: None,
                chain,
            })
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::DelegationManagement,
                    err.message,
                    DenialReason::InvalidDelegation,
                )
            })?;

        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::DelegationCreated)
                .principal(&delegation.delegate)
                .delegation(&delegation.id)
                .meta("delegator", delegation.delegator.as_str()),
            now,
        )?;
        Ok(delegation)
    }

    pub fn revoke_delegation(
        &self,
        tenant_id: &str,
        delegation_id: &DelegationId,
        now: i64,
    ) -> Result<(), AuthError> {
        let tenant = self.tenant(tenant_id)?;
        self.stores
            .delegations
            .revoke_delegation(&tenant, delegation_id, now)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::DelegationManagement,
                    err.message,
                    DenialReason::InvalidDelegation,
                )
            })?;
        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::DelegationRevoked).delegation(delegation_id),
            now,
        )
    }

    pub fn delegations_for(
        &self,
        tenant: &TenantContext,
        delegate: &PrincipalId,
    ) -> Result<Vec<Delegation>, AuthError> {
        self.stores
            .delegations
            .list_delegations_for_delegate(tenant, delegate)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::DelegationManagement,
                    err.message,
                    DenialReason::InvalidDelegation,
                )
            })
    }

    pub fn create_agent_run(
        &self,
        tenant_id: &str,
        agent_id: &PrincipalId,
        request: RunCreationRequest,
        now: i64,
        authority_revision: u64,
        contract_fingerprint: String,
    ) -> Result<AgentRun, AuthError> {
        let tenant = self.tenant(tenant_id)?;
        if request.capabilities.is_empty() {
            return Err(run_error(
                "run task must request structured capabilities",
                DenialReason::RunExceedsDelegation,
            ));
        }
        if request.expires_at <= now {
            return Err(run_error(
                "run expires before it can be used",
                DenialReason::RunExpired,
            ));
        }

        let agent = self.principal(&tenant, agent_id)?;
        if agent.kind != PrincipalKind::Agent {
            return Err(run_error(
                "run principal must be an agent",
                DenialReason::RunNotFound,
            ));
        }
        self.assert_principal_is_usable(&agent)?;

        let delegation = self
            .stores
            .delegations
            .get_delegation(&tenant, &request.delegation_id)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::DelegationManagement,
                    err.message,
                    DenialReason::InvalidDelegation,
                )
            })?
            .ok_or_else(|| run_error("delegation not found", DenialReason::DelegationMissing))?;
        if delegation.delegate != *agent_id || delegation.tenant_id != tenant.tenant_id {
            return Err(run_error(
                "delegation does not belong to this agent",
                DenialReason::InvalidDelegation,
            ));
        }
        if delegation.revoked_at.is_some() {
            return Err(run_error(
                "delegation is revoked",
                DenialReason::RevokedDelegation,
            ));
        }
        if !delegation.is_valid_at(now) {
            return Err(run_error(
                "delegation is expired",
                DenialReason::ExpiredDelegation,
            ));
        }
        if delegation
            .expires_at
            .map(|expires_at| request.expires_at > expires_at)
            .unwrap_or(false)
        {
            return Err(run_error(
                "run expiration exceeds delegation lifetime",
                DenialReason::RunExceedsDelegation,
            ));
        }
        for capability in &request.capabilities {
            if !delegation.capabilities.contains(capability) {
                return Err(run_error(
                    format!("run requests `{}` outside delegation", capability),
                    DenialReason::RunExceedsDelegation,
                ));
            }
        }
        if !tenant_scope_holds(&request.resource_scope, &tenant.tenant_id) {
            return Err(run_error(
                "run resource scope crosses tenant boundary",
                DenialReason::RunExceedsDelegation,
            ));
        }
        if !request
            .resource_scope
            .is_subset_of(&delegation.resource_scope)
        {
            return Err(run_error(
                "run resource scope must narrow the delegation",
                DenialReason::RunExceedsDelegation,
            ));
        }

        let parent_run = match &request.parent_run_id {
            Some(parent_id) => Some(self.checked_run(&tenant, parent_id, now).map_err(|_| {
                run_error(
                    "parent run is not valid",
                    DenialReason::ParentRunScopeDenied,
                )
            })?),
            None => None,
        };
        if let Some(parent) = &parent_run {
            for capability in &request.capabilities {
                if !parent.capability_scope.contains(capability) {
                    return Err(run_error(
                        format!("child run requests `{}` outside parent run", capability),
                        DenialReason::ParentRunScopeDenied,
                    ));
                }
            }
            if !request.resource_scope.is_subset_of(&parent.resource_scope)
                || request.expires_at > parent.expires_at
            {
                return Err(run_error(
                    "child run must narrow the parent run",
                    DenialReason::ParentRunScopeDenied,
                ));
            }
        }

        let id = request.id.unwrap_or_else(|| self.next_run_id(&tenant));
        let credential = self.execution_credential(&tenant, &id);
        let task = TaskSpec {
            id: request.task_id,
            purpose: request.task_purpose,
            capabilities: request.capabilities.clone(),
            resource_scope: request.resource_scope.clone(),
            expires_at: request.expires_at,
            constraints: request.constraints,
        };
        let mut chain = delegation.chain.clone();
        chain.push(delegation.id.clone());
        let run = AgentRun {
            id: id.clone(),
            tenant_id: tenant.tenant_id.clone(),
            agent_principal: agent_id.clone(),
            delegator: delegation.delegator.clone(),
            delegation_id: delegation.id.clone(),
            delegation_chain: chain,
            task,
            parent_run_id: request.parent_run_id,
            created_at: now,
            expires_at: request.expires_at,
            status: RunStatus::Active,
            authority_revision,
            contract_fingerprint,
            capability_scope: request.capabilities,
            resource_scope: request.resource_scope,
            execution_credential: credential,
            cancelled_at: None,
        };
        self.stores
            .runs
            .put_run(run.clone())
            .map_err(|err| run_error(err.message, DenialReason::RunNotFound))?;
        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::AgentRunCreated)
                .principal(&run.agent_principal)
                .delegation(&run.delegation_id)
                .meta("run_id", run.id.as_str())
                .meta("task_id", run.task.id.as_str()),
            now,
        )?;
        Ok(run)
    }

    pub fn agent_runs(
        &self,
        tenant: &TenantContext,
        agent: &PrincipalId,
    ) -> Result<Vec<AgentRun>, AuthError> {
        self.stores
            .runs
            .list_runs_for_agent(tenant, agent)
            .map_err(|err| run_error(err.message, DenialReason::RunNotFound))
    }

    pub fn agent_run(
        &self,
        tenant: &TenantContext,
        run_id: &RunId,
    ) -> Result<Option<AgentRun>, AuthError> {
        self.stores
            .runs
            .get_run(tenant, run_id)
            .map_err(|err| run_error(err.message, DenialReason::RunNotFound))
    }

    pub fn agent_run_by_credential(
        &self,
        tenant: &TenantContext,
        credential: &ExecutionCredentialId,
    ) -> Result<Option<AgentRun>, AuthError> {
        self.stores
            .runs
            .find_run_by_credential(tenant, credential)
            .map_err(|err| run_error(err.message, DenialReason::RunNotFound))
    }

    pub fn cancel_agent_run(
        &self,
        tenant_id: &str,
        run_id: &RunId,
        now: i64,
    ) -> Result<AgentRun, AuthError> {
        let tenant = self.tenant(tenant_id)?;
        let mut run = self
            .agent_run(&tenant, run_id)?
            .ok_or_else(|| run_error("run not found", DenialReason::RunNotFound))?;
        run.status = RunStatus::Cancelled;
        run.cancelled_at = Some(now);
        let run = self
            .stores
            .runs
            .update_run(&tenant, run)
            .map_err(|err| run_error(err.message, DenialReason::RunNotFound))?;
        self.audit(
            &tenant,
            AuditRecord::new(AuditEventKind::AgentRunCancelled)
                .principal(&run.agent_principal)
                .delegation(&run.delegation_id)
                .meta("run_id", run.id.as_str())
                .meta("task_id", run.task.id.as_str()),
            now,
        )?;
        Ok(run)
    }

    pub fn suspend_agent(
        &self,
        tenant_id: &str,
        agent: &PrincipalId,
        now: i64,
    ) -> Result<(), AuthError> {
        self.set_agent_state(tenant_id, agent, AgentState::Suspended, now)
    }

    /// Revoking an agent removes its authority immediately, independently of
    /// whatever its delegator still holds.
    pub fn revoke_agent(
        &self,
        tenant_id: &str,
        agent: &PrincipalId,
        now: i64,
    ) -> Result<(), AuthError> {
        self.set_agent_state(tenant_id, agent, AgentState::Revoked, now)
    }

    pub fn retire_agent(
        &self,
        tenant_id: &str,
        agent: &PrincipalId,
        now: i64,
    ) -> Result<(), AuthError> {
        self.set_agent_state(tenant_id, agent, AgentState::Retired, now)
    }

    fn set_agent_state(
        &self,
        tenant_id: &str,
        agent: &PrincipalId,
        state: AgentState,
        now: i64,
    ) -> Result<(), AuthError> {
        let tenant = self.tenant(tenant_id)?;
        self.stores
            .principals
            .set_agent_state(&tenant, agent, state.clone())
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::AgentLifecycle,
                    err.message,
                    DenialReason::UnknownPrincipal,
                )
            })?;

        let kind = match state {
            AgentState::Suspended => AuditEventKind::AgentSuspended,
            AgentState::Revoked => AuditEventKind::AgentRevoked,
            _ => AuditEventKind::AgentCreated,
        };
        self.audit(&tenant, AuditRecord::new(kind).principal(agent), now)
    }

    /// The one authorization entry point, for every principal kind.
    pub fn authorize(
        &self,
        context: &RuntimeContext,
        capability: &Capability,
        now: i64,
    ) -> AuthorizationDecision {
        self.authorize_with_authority_revision(context, capability, now, 0)
    }

    pub fn authorize_with_authority_revision(
        &self,
        context: &RuntimeContext,
        capability: &Capability,
        now: i64,
        authority_revision: u64,
    ) -> AuthorizationDecision {
        let policy = match self.policy(&context.tenant) {
            Ok(policy) => policy,
            Err(_) => return deny(DenialReason::PolicyNotFound),
        };

        // The delegation considered is the one that actually covers this
        // capability for this principal, in this tenant.
        let delegations = match self.delegations_for(&context.tenant, &context.principal.id) {
            Ok(delegations) => delegations,
            Err(_) => return deny(DenialReason::InvalidDelegation),
        };
        let delegation = pick_delegation(&delegations, capability, now);

        let decision = evaluate_capability(
            Some(&policy),
            Some(&context.principal),
            Some(&context.tenant),
            delegation,
            capability,
            now,
        );

        match self.record_decision(context, capability, &decision, now) {
            Ok(audit_event_id) => self.remember_decision(
                context,
                capability,
                attach_audit_event(decision, audit_event_id),
                now,
                authority_revision,
            ),
            // An authorization that cannot be recorded is not an authorization.
            Err(_) => deny(DenialReason::AuditUnavailable),
        }
    }

    pub fn authorize_request(
        &self,
        context: &RuntimeContext,
        request: &AuthorizationRequest,
        resource_attributes: Option<&ResourceAttributes>,
        now: i64,
    ) -> AuthorizationDecision {
        self.authorize_request_with_authority_revision(
            context,
            request,
            resource_attributes,
            now,
            0,
        )
    }

    pub fn authorize_request_with_authority_revision(
        &self,
        context: &RuntimeContext,
        request: &AuthorizationRequest,
        resource_attributes: Option<&ResourceAttributes>,
        now: i64,
        authority_revision: u64,
    ) -> AuthorizationDecision {
        let policy = match self.policy(&context.tenant) {
            Ok(policy) => policy,
            Err(_) => return deny(DenialReason::PolicyNotFound),
        };
        let delegations = match self.delegations_for(&context.tenant, &context.principal.id) {
            Ok(delegations) => delegations,
            Err(_) => return deny(DenialReason::InvalidDelegation),
        };
        let delegation = pick_delegation(&delegations, &request.capability, now);
        let decision = evaluate_authorization_request(
            Some(&policy),
            Some(&context.principal),
            Some(&context.tenant),
            delegation,
            request,
            resource_attributes,
            now,
        );
        match self.record_decision(context, &request.capability, &decision, now) {
            Ok(audit_event_id) => self.remember_decision(
                context,
                &request.capability,
                attach_audit_event(decision, audit_event_id),
                now,
                authority_revision,
            ),
            Err(_) => deny(DenialReason::AuditUnavailable),
        }
    }

    pub fn authorize_run_request_with_authority_revision(
        &self,
        context: &RuntimeContext,
        run_id: &RunId,
        request: &AuthorizationRequest,
        resource_attributes: Option<&ResourceAttributes>,
        now: i64,
        authority_revision: u64,
    ) -> AuthorizationDecision {
        match self.checked_run_for_request(context, run_id, request, resource_attributes, now) {
            Ok(run) => {
                let run_context = context.clone().with_run(run.clone());
                let mut run_request = request.clone();
                run_request.context.run_id = Some(run.id.clone());
                run_request.context.task_id = Some(run.task.id.clone());
                run_request.context.agent_principal = Some(run.agent_principal.clone());
                run_request.context.delegation_id = Some(run.delegation_id.clone());
                run_request.context.delegation_chain = run.delegation_chain.clone();
                self.authorize_request_with_authority_revision(
                    &run_context,
                    &run_request,
                    resource_attributes,
                    now,
                    authority_revision,
                )
            }
            Err((reason, run)) => {
                let run_context = run
                    .clone()
                    .map(|run| context.clone().with_run(run))
                    .unwrap_or_else(|| context.clone());
                let decision = AuthorizationDecision::Deny {
                    reason,
                    capability: Some(request.capability.clone()),
                    resource: request.resource.clone(),
                    action: Some(request.action.clone()),
                    policy_id: self.policy(&context.tenant).ok().map(|policy| policy.id),
                    matched_rules: Vec::new(),
                    conditions: Vec::new(),
                    audit_event_id: None,
                };
                match self.record_decision(&run_context, &request.capability, &decision, now) {
                    Ok(audit_event_id) => self.remember_decision(
                        &run_context,
                        &request.capability,
                        attach_audit_event(decision, audit_event_id),
                        now,
                        authority_revision,
                    ),
                    Err(_) => deny(DenialReason::AuditUnavailable),
                }
            }
        }
    }

    pub fn recent_decisions(&self) -> Vec<AuthorizationEvidence> {
        self.decisions
            .lock()
            .map(|decisions| decisions.clone())
            .unwrap_or_default()
    }

    pub fn tenant(&self, tenant_id: &str) -> Result<TenantContext, AuthError> {
        if tenant_id.trim().is_empty() {
            return Err(AuthError::new(
                AuthLifecycleStage::TenantResolution,
                "missing tenant",
                DenialReason::UnknownTenant,
            ));
        }

        self.stores
            .tenants
            .get_tenant(&TenantId(tenant_id.to_string()))
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::TenantResolution,
                    err.message,
                    DenialReason::UnknownTenant,
                )
            })?
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::TenantResolution,
                    format!("unknown tenant `{}`", tenant_id),
                    DenialReason::UnknownTenant,
                )
            })
    }

    pub fn principal(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
    ) -> Result<Principal, AuthError> {
        self.stores
            .principals
            .get_principal(tenant, principal_id)
            .map_err(principal_error)?
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::PrincipalResolution,
                    format!("unknown principal `{}`", principal_id),
                    DenialReason::UnknownPrincipal,
                )
            })
    }

    pub fn principal_id_for(
        &self,
        tenant: &TenantContext,
        connector: &str,
        subject: &str,
    ) -> PrincipalId {
        principal_id_for(&tenant.tenant_id, connector, subject)
    }

    fn connector(
        &self,
        connector_id: &str,
    ) -> Result<std::sync::Arc<dyn appport_auth_mesh_providers::AuthConnector>, AuthError> {
        if !self.config.declares_provider(connector_id) {
            return Err(AuthError::new(
                AuthLifecycleStage::ConnectorResolution,
                format!("connector `{}` is not declared by `use auth`", connector_id),
                DenialReason::UnsupportedConnector,
            ));
        }
        self.registry.get(connector_id).map_err(connector_error)
    }

    fn authenticate_external(
        &self,
        tenant: &TenantContext,
        response: &AuthResponse,
    ) -> Result<ExternalIdentity, AuthError> {
        let connector = self.connector(&response.connector)?;

        // A response must be presented to the tenant it was issued for.
        if let Some(declared) = &response.tenant {
            if declared != tenant.tenant_id.as_str() {
                return Err(AuthError::new(
                    AuthLifecycleStage::ProviderAuthentication,
                    "authentication response targets a different tenant",
                    DenialReason::TenantMismatch,
                ));
            }
        }

        let external = connector.authenticate(response).map_err(connector_error)?;
        if external.connector != response.connector {
            return Err(AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                "connector returned an identity for a different connector",
                DenialReason::UnsupportedConnector,
            ));
        }
        if external.subject.trim().is_empty() {
            return Err(AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                "connector returned an empty subject",
                DenialReason::UnknownPrincipal,
            ));
        }
        Ok(external)
    }

    fn assert_principal_is_usable(&self, principal: &Principal) -> Result<(), AuthError> {
        if principal.kind != PrincipalKind::Agent {
            return Ok(());
        }
        match principal.agent_state {
            Some(AgentState::Active) => Ok(()),
            Some(AgentState::Suspended) => Err(AuthError::new(
                AuthLifecycleStage::AgentLifecycle,
                "agent is suspended",
                DenialReason::AgentSuspended,
            )),
            _ => Err(AuthError::new(
                AuthLifecycleStage::AgentLifecycle,
                "agent is not active",
                DenialReason::AgentRevoked,
            )),
        }
    }

    fn open_session(
        &self,
        tenant: &TenantContext,
        identity_id: &appport_auth_mesh_contract::IdentityId,
        now: i64,
    ) -> Result<Session, AuthError> {
        self.stores
            .sessions
            .create_session(tenant, identity_id, now + self.session_ttl, None)
            .map_err(session_error)
    }

    fn context_for(
        &self,
        tenant: &TenantContext,
        principal: Principal,
        session_id: Option<SessionId>,
        now: i64,
    ) -> Result<RuntimeContext, AuthError> {
        let policy = self.policy(tenant)?;
        let delegations = self.delegations_for(tenant, &principal.id)?;

        let capabilities: CapabilityEnvelope =
            evaluate_with_delegations(&policy, &principal, tenant, &delegations, now).map_err(
                |err| {
                    AuthError::new(
                        AuthLifecycleStage::PolicyEvaluation,
                        err.message,
                        DenialReason::TenantMismatch,
                    )
                },
            )?;

        // An agent acting under a delegation is never collapsed into its
        // delegator: both principals stay visible in the context.
        let delegation = capabilities
            .granted_capabilities
            .iter()
            .find_map(|grant| grant.delegation_id.clone())
            .and_then(|id| delegations.into_iter().find(|entry| entry.id == id));

        Ok(RuntimeContext {
            claims: principal.claims.clone(),
            principal,
            tenant: tenant.clone(),
            session_id,
            delegation,
            run: None,
            capabilities,
        })
    }

    fn policy(&self, tenant: &TenantContext) -> Result<Policy, AuthError> {
        self.stores
            .policies
            .policy_for(tenant)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::PolicyEvaluation,
                    err.message,
                    DenialReason::PolicyNotFound,
                )
            })?
            .or_else(|| Self::policy_from_config(&self.config, tenant))
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::PolicyEvaluation,
                    format!("tenant `{}` has no policy", tenant.tenant_id),
                    DenialReason::PolicyNotFound,
                )
            })
    }

    fn policy_from_config(config: &AuthConfig, tenant: &TenantContext) -> Option<Policy> {
        if config.policies.is_empty() {
            return None;
        }
        Some(Policy {
            id: tenant.policy_id.clone(),
            rules: config
                .policies
                .iter()
                .map(|policy| {
                    let mut conditions = Vec::new();
                    if policy.tenant_current {
                        conditions.push(Condition::TenantCurrent);
                    }
                    for claim in &policy.claims {
                        let values = claim
                            .values
                            .iter()
                            .map(|value| ClaimValue::Enum(value.clone()))
                            .collect::<Vec<_>>();
                        conditions.push(if values.len() == 1 {
                            Condition::ClaimEquals {
                                key: claim.claim.clone(),
                                value: values[0].clone(),
                            }
                        } else {
                            Condition::ClaimIn {
                                key: claim.claim.clone(),
                                values,
                            }
                        });
                    }
                    Rule {
                        capability: Capability(policy.capability.clone()),
                        condition: match conditions.len() {
                            0 => Condition::Always,
                            1 => conditions.remove(0),
                            _ => Condition::All(conditions),
                        },
                        resource: policy
                            .resource
                            .as_ref()
                            .map(|resource| ResourceSelector::any(resource.clone())),
                        action: policy.action.as_ref().map(|action| Action(action.clone())),
                        effect: Effect::Allow,
                    }
                })
                .collect(),
        })
    }

    fn record_decision(
        &self,
        context: &RuntimeContext,
        capability: &Capability,
        decision: &AuthorizationDecision,
        now: i64,
    ) -> Result<AuditEventId, AuthError> {
        let (kind, reason) = match decision {
            AuthorizationDecision::Allow { .. } => (AuditEventKind::AuthorizationGranted, None),
            AuthorizationDecision::Deny { reason, .. } => {
                (AuditEventKind::AuthorizationDenied, Some(reason.as_str()))
            }
        };

        let delegation_id = decision
            .grant()
            .and_then(|grant| grant.delegation_id.clone())
            .or_else(|| context.delegation.as_ref().map(|d| d.id.clone()));

        let mut record = AuditRecord::new(kind)
            .principal(&context.principal.id)
            .meta("capability", capability.as_str());
        if let Some(session_id) = context.session_id.as_ref() {
            record = record.session(session_id);
        }
        if let Some(run) = context.run.as_ref() {
            record = record
                .meta("run_id", run.id.as_str())
                .meta("task_id", run.task.id.as_str());
        }
        if let Some(delegation_id) = delegation_id.as_ref() {
            record = record.delegation(delegation_id);
        }
        if let Some(reason) = reason {
            record = record.meta("reason", reason);
        }
        match decision {
            AuthorizationDecision::Allow {
                resource, action, ..
            }
            | AuthorizationDecision::Deny {
                resource, action, ..
            } => {
                if let Some(resource) = resource {
                    let opaque = resource.opaque();
                    record = record
                        .meta("resource", &opaque)
                        .meta("resource_type", resource.resource_type.as_str())
                        .meta("resource_tenant", resource.tenant_id.as_str());
                }
                if let Some(action) = action {
                    record = record.meta("action", action.as_str());
                }
            }
        }

        self.audit(&context.tenant, record, now)?;

        Ok(self.last_audit_event_id(&context.tenant))
    }

    fn audit(
        &self,
        tenant: &TenantContext,
        record: AuditRecord<'_>,
        now: i64,
    ) -> Result<(), AuthError> {
        let decision = match &record.kind {
            AuditEventKind::AuthorizationGranted => Some("allow".to_string()),
            AuditEventKind::AuthorizationDenied => Some("deny".to_string()),
            _ => None,
        };
        let event = AuditEvent {
            event_id: self.next_audit_event_id(tenant),
            tenant_id: tenant.tenant_id.clone(),
            principal_id: record.principal_id.cloned(),
            delegator_id: record
                .metadata
                .iter()
                .find(|(key, _)| key == "delegator")
                .map(|(_, value)| PrincipalId(value.clone())),
            session_id: record.session_id.cloned(),
            delegation_id: record.delegation_id.cloned(),
            run_id: record
                .metadata
                .iter()
                .find(|(key, _)| key == "run_id")
                .map(|(_, value)| RunId(value.clone())),
            kind: record.kind,
            timestamp: now,
            action: record
                .metadata
                .iter()
                .find(|(key, _)| key == "action" || key == "capability")
                .map(|(_, value)| value.clone()),
            resource: record
                .metadata
                .iter()
                .find(|(key, _)| key == "resource")
                .map(|(_, value)| value.clone()),
            decision,
            reason: record
                .metadata
                .iter()
                .find(|(key, _)| key == "reason")
                .map(|(_, value)| value.clone()),
            authority_revision: record
                .metadata
                .iter()
                .find(|(key, _)| key == "authority_revision")
                .and_then(|(_, value)| value.parse().ok()),
            contract_fingerprint: Some(self.config.fingerprint()),
            durability: AuditDurability::Required,
            metadata: record.metadata.into_iter().collect::<HashMap<_, _>>(),
        };

        self.stores
            .audit
            .record_event(tenant, event)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::RuntimeContext,
                    err.message,
                    DenialReason::TenantMismatch,
                )
            })
    }

    fn next_audit_event_id(&self, tenant: &TenantContext) -> AuditEventId {
        let sequence = self.audit_sequence.fetch_add(1, Ordering::SeqCst);
        audit_event_id(tenant, sequence)
    }

    fn last_audit_event_id(&self, tenant: &TenantContext) -> AuditEventId {
        let sequence = self.audit_sequence.load(Ordering::SeqCst).saturating_sub(1);
        audit_event_id(tenant, sequence)
    }

    fn next_run_id(&self, tenant: &TenantContext) -> RunId {
        let sequence = self.run_sequence.fetch_add(1, Ordering::SeqCst);
        RunId(format!(
            "run_{:016x}",
            stable_hash(format!("{}|{}", tenant.tenant_id, sequence).as_bytes())
        ))
    }

    fn execution_credential(
        &self,
        tenant: &TenantContext,
        run_id: &RunId,
    ) -> ExecutionCredentialId {
        let material = format!(
            "{}|{}|{}",
            tenant.tenant_id,
            run_id,
            self.config.fingerprint()
        );
        ExecutionCredentialId(format!("exec_{:016x}", stable_hash(material.as_bytes())))
    }

    fn checked_run(
        &self,
        tenant: &TenantContext,
        run_id: &RunId,
        now: i64,
    ) -> Result<AgentRun, AuthError> {
        let run = self
            .agent_run(tenant, run_id)?
            .ok_or_else(|| run_error("run not found", DenialReason::RunNotFound))?;
        match run.status {
            RunStatus::Active => {}
            RunStatus::Cancelled => {
                return Err(run_error("run is cancelled", DenialReason::RunCancelled))
            }
            RunStatus::Expired => {
                return Err(run_error("run is expired", DenialReason::RunExpired))
            }
            RunStatus::Completed | RunStatus::Failed => {
                return Err(run_error(
                    "run is no longer active",
                    DenialReason::RunCancelled,
                ))
            }
        }
        if now >= run.expires_at {
            return Err(run_error("run is expired", DenialReason::RunExpired));
        }
        Ok(run)
    }

    fn checked_run_for_request(
        &self,
        context: &RuntimeContext,
        run_id: &RunId,
        request: &AuthorizationRequest,
        resource_attributes: Option<&ResourceAttributes>,
        now: i64,
    ) -> Result<AgentRun, (DenialReason, Option<AgentRun>)> {
        let run = match self.checked_run(&context.tenant, run_id, now) {
            Ok(run) => run,
            Err(err) => return Err((err.denial, None)),
        };
        if run.agent_principal != context.principal.id || run.tenant_id != context.tenant.tenant_id
        {
            return Err((DenialReason::RunNotFound, Some(run)));
        }
        if !run.capability_scope.contains(&request.capability) {
            return Err((DenialReason::RunScopeDenied, Some(run)));
        }
        if !resource_scope_matches(&run.resource_scope, request, resource_attributes) {
            return Err((DenialReason::RunScopeDenied, Some(run)));
        }
        Ok(run)
    }

    fn remember_decision(
        &self,
        context: &RuntimeContext,
        capability: &Capability,
        decision: AuthorizationDecision,
        now: i64,
        authority_revision: u64,
    ) -> AuthorizationDecision {
        let evidence = decision_evidence(
            context,
            capability,
            &decision,
            now,
            authority_revision,
            self.config.fingerprint(),
        );
        if let Ok(mut decisions) = self.decisions.lock() {
            decisions.push(evidence);
            if decisions.len() > 100 {
                decisions.remove(0);
            }
        }
        decision
    }
}

fn audit_event_id(tenant: &TenantContext, sequence: u64) -> AuditEventId {
    let material = format!("{}|{}", tenant.tenant_id, sequence);
    AuditEventId(format!("evt_{:016x}", stable_hash(material.as_bytes())))
}

fn pick_delegation<'d>(
    delegations: &'d [Delegation],
    capability: &Capability,
    now: i64,
) -> Option<&'d Delegation> {
    delegations
        .iter()
        .find(|delegation| {
            delegation.is_valid_at(now) && delegation.capabilities.contains(capability)
        })
        .or_else(|| {
            // Surfacing an expired or revoked delegation lets the evaluator
            // deny with the precise reason instead of a generic refusal.
            delegations
                .iter()
                .find(|delegation| delegation.capabilities.contains(capability))
        })
}

fn resource_scope_matches(
    scope: &ResourceScope,
    request: &AuthorizationRequest,
    resource_attributes: Option<&ResourceAttributes>,
) -> bool {
    if scope.is_unconstrained() {
        return true;
    }
    let Some(resource) = &request.resource else {
        return false;
    };
    if let Some(resource_type) = &scope.resource_type {
        if resource_type != &resource.resource_type {
            return false;
        }
    }
    if let Some(resource_id) = &scope.resource_id {
        if resource_id != "*" && resource_id != &resource.resource_id {
            return false;
        }
    }
    scope.attributes.iter().all(|(key, expected)| {
        if key == "tenant" || key == "tenant_id" {
            return matches_tenant(expected, resource.tenant_id.as_str());
        }
        resource_attributes.and_then(|attributes| attributes.values.get(key)) == Some(expected)
    })
}

fn tenant_scope_holds(scope: &ResourceScope, tenant_id: &TenantId) -> bool {
    scope
        .attributes
        .get("tenant")
        .or_else(|| scope.attributes.get("tenant_id"))
        .map(|value| matches_tenant(value, tenant_id.as_str()))
        .unwrap_or(true)
}

fn matches_tenant(value: &ClaimValue, tenant_id: &str) -> bool {
    match value {
        ClaimValue::Enum(value) | ClaimValue::String(value) => value == tenant_id,
        _ => false,
    }
}

fn attach_audit_event(
    decision: AuthorizationDecision,
    audit_event_id: AuditEventId,
) -> AuthorizationDecision {
    match decision {
        AuthorizationDecision::Allow {
            grant,
            resource,
            action,
            matched_rules,
            conditions,
            ..
        } => AuthorizationDecision::Allow {
            grant,
            resource,
            action,
            matched_rules,
            conditions,
            audit_event_id: Some(audit_event_id),
        },
        AuthorizationDecision::Deny {
            reason,
            capability,
            resource,
            action,
            policy_id,
            matched_rules,
            conditions,
            ..
        } => AuthorizationDecision::Deny {
            reason,
            capability,
            resource,
            action,
            policy_id,
            matched_rules,
            conditions,
            audit_event_id: Some(audit_event_id),
        },
    }
}

fn decision_evidence(
    context: &RuntimeContext,
    capability: &Capability,
    decision: &AuthorizationDecision,
    now: i64,
    authority_revision: u64,
    contract_fingerprint: String,
) -> AuthorizationEvidence {
    let run = context.run.as_ref();
    match decision {
        AuthorizationDecision::Allow {
            grant,
            resource,
            action,
            matched_rules,
            conditions,
            audit_event_id,
        } => AuthorizationEvidence {
            decision_id: audit_event_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| fallback_decision_id(context, capability, now)),
            timestamp: now,
            principal: context.principal.id.clone(),
            tenant: context.tenant.tenant_id.clone(),
            capability: grant.capability.clone(),
            action: action.clone(),
            resource: resource.clone(),
            policy_id: Some(grant.policy_id.clone()),
            matched_rules: matched_rules.clone(),
            conditions: conditions.clone(),
            authority: Some(grant.authority),
            delegated_by: grant.delegated_by.clone(),
            delegation_chain: grant.delegation_chain.clone(),
            run_id: run.map(|run| run.id.clone()),
            task_id: run.map(|run| run.task.id.clone()),
            agent_principal: run.map(|run| run.agent_principal.clone()),
            delegation_id: run.map(|run| run.delegation_id.clone()),
            parent_run_id: run.and_then(|run| run.parent_run_id.clone()),
            execution_scope: run.map(|run| run.resource_scope.clone()),
            authority_revision,
            contract_fingerprint,
            decision: AuthorizationOutcome::Allow,
            reason: decision.reason(),
            audit_event_id: audit_event_id.clone(),
        },
        AuthorizationDecision::Deny {
            capability: denied_capability,
            resource,
            action,
            policy_id,
            matched_rules,
            conditions,
            audit_event_id,
            ..
        } => AuthorizationEvidence {
            decision_id: audit_event_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| fallback_decision_id(context, capability, now)),
            timestamp: now,
            principal: context.principal.id.clone(),
            tenant: context.tenant.tenant_id.clone(),
            capability: denied_capability
                .clone()
                .unwrap_or_else(|| capability.clone()),
            action: action.clone(),
            resource: resource.clone(),
            policy_id: policy_id.clone(),
            matched_rules: matched_rules.clone(),
            conditions: conditions.clone(),
            authority: None,
            delegated_by: run.map(|run| run.delegator.clone()),
            delegation_chain: run
                .map(|run| run.delegation_chain.clone())
                .unwrap_or_default(),
            run_id: run.map(|run| run.id.clone()),
            task_id: run.map(|run| run.task.id.clone()),
            agent_principal: run.map(|run| run.agent_principal.clone()),
            delegation_id: run.map(|run| run.delegation_id.clone()),
            parent_run_id: run.and_then(|run| run.parent_run_id.clone()),
            execution_scope: run.map(|run| run.resource_scope.clone()),
            authority_revision,
            contract_fingerprint,
            decision: AuthorizationOutcome::Deny,
            reason: decision.reason(),
            audit_event_id: audit_event_id.clone(),
        },
    }
}

fn fallback_decision_id(context: &RuntimeContext, capability: &Capability, now: i64) -> String {
    let material = format!(
        "{}|{}|{}|{}",
        context.tenant.tenant_id, context.principal.id, capability, now
    );
    format!("decision_{:016x}", stable_hash(material.as_bytes()))
}

fn deny(reason: DenialReason) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
        capability: None,
        resource: None,
        action: None,
        policy_id: None,
        matched_rules: Vec::new(),
        conditions: Vec::new(),
        audit_event_id: None,
    }
}

fn connector_error(err: ConnectorError) -> AuthError {
    let denial = match err {
        ConnectorError::UnknownConnector { .. }
        | ConnectorError::Unsupported { .. }
        | ConnectorError::NotDeclared { .. }
        | ConnectorError::DuplicateConnector { .. } => DenialReason::UnsupportedConnector,
        ConnectorError::InvalidRequest { .. }
        | ConnectorError::InvalidCredentials { .. }
        | ConnectorError::ChallengeMismatch { .. } => DenialReason::UnknownPrincipal,
        ConnectorError::PasswordReused { .. } => DenialReason::PasswordReused,
        ConnectorError::PasswordHashingFailed { .. } => DenialReason::PolicyDenied,
    };
    let stage = match err {
        ConnectorError::UnknownConnector { .. }
        | ConnectorError::NotDeclared { .. }
        | ConnectorError::DuplicateConnector { .. } => AuthLifecycleStage::ConnectorResolution,
        _ => AuthLifecycleStage::ProviderAuthentication,
    };
    AuthError::new(stage, err.to_string(), denial)
}

fn session_error(err: StorageError) -> AuthError {
    let denial = match err.message.as_str() {
        "expired session" => DenialReason::ExpiredSession,
        "revoked session" => DenialReason::RevokedSession,
        "tenant mismatch" => DenialReason::TenantMismatch,
        _ => DenialReason::InvalidSession,
    };
    AuthError::new(AuthLifecycleStage::SessionValidation, err.message, denial)
}

fn principal_error(err: StorageError) -> AuthError {
    let denial = if err.message == "tenant mismatch" {
        DenialReason::TenantMismatch
    } else {
        DenialReason::UnknownPrincipal
    };
    AuthError::new(AuthLifecycleStage::PrincipalResolution, err.message, denial)
}

fn delegation_error(message: &str) -> AuthError {
    AuthError::new(
        AuthLifecycleStage::DelegationManagement,
        message,
        DenialReason::InvalidDelegation,
    )
}

fn run_error(message: impl Into<String>, denial: DenialReason) -> AuthError {
    AuthError::new(
        AuthLifecycleStage::DelegationManagement,
        message.into(),
        denial,
    )
}

/// Claims supplied by the application at registration time.
pub type ClaimInput = BTreeMap<String, String>;
