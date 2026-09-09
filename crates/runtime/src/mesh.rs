use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use appport_auth_mesh_authz::{
    evaluate_capability, evaluate_with_delegations, AuthorizationDecision, CapabilityEnvelope,
    DenialReason, Policy,
};
use appport_auth_mesh_contract::{
    AgentState, AuditEventId, Capability, Claims, Delegation, DelegationId, Principal, PrincipalId,
    PrincipalKind, SessionId, TenantContext, TenantId,
};
use appport_auth_mesh_dsl::{stable_hash, AuthConfig};
use appport_auth_mesh_providers::{
    AuthChallenge, AuthRequest, AuthResponse, ConnectorError, ConnectorRegistry, ExternalIdentity,
};
use appport_auth_mesh_storage::{
    AuditEvent, AuditEventKind, AuditLog, DelegationStore, ExternalBinding, IdentityStore,
    PrincipalStore, Session, SessionStore, StorageError, TenantRootStore,
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
    pub policies: Arc<dyn PolicyStore + Send + Sync>,
    pub audit: Arc<dyn AuditLog + Send + Sync>,
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
    pub issued_at: i64,
    pub expires_at: i64,
}

/// One entry in the authority audit trail.
struct AuditRecord<'r> {
    kind: AuditEventKind,
    principal_id: Option<&'r PrincipalId>,
    session_id: Option<&'r SessionId>,
    delegation_id: Option<&'r DelegationId>,
    metadata: Vec<(&'r str, &'r str)>,
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

    fn meta(mut self, key: &'r str, value: &'r str) -> Self {
        self.metadata.push((key, value));
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
        if request.expires_at <= request.issued_at || request.expires_at <= now {
            return Err(delegation_error("delegation must be time-bound"));
        }

        let delegator = self.principal(&tenant, &request.delegator)?;
        let delegate = self.principal(&tenant, &request.delegate)?;

        if delegate.kind == PrincipalKind::Human {
            return Err(delegation_error("delegation targets an agent or a service"));
        }
        self.assert_principal_is_usable(&delegate)?;

        let policy = self.policy(&tenant)?;
        let delegator_envelope = evaluate_with_delegations(&policy, &delegator, &tenant, &[], now)
            .map_err(|err| {
                AuthError::new(
                    AuthLifecycleStage::PolicyEvaluation,
                    err.message,
                    DenialReason::PolicyNotFound,
                )
            })?;

        for capability in &request.capabilities {
            if !delegator_envelope.allows(capability) {
                return Err(AuthError::new(
                    AuthLifecycleStage::DelegationManagement,
                    format!(
                        "delegator `{}` does not hold `{}`",
                        request.delegator, capability
                    ),
                    DenialReason::CapabilityNotGranted,
                ));
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
                issued_at: request.issued_at,
                expires_at: request.expires_at,
                revoked_at: None,
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
            Ok(audit_event_id) => attach_audit_event(decision, audit_event_id),
            // An authorization that cannot be recorded is not an authorization.
            Err(_) => deny(DenialReason::AuditUnavailable),
        }
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
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::PolicyEvaluation,
                    format!("tenant `{}` has no policy", tenant.tenant_id),
                    DenialReason::PolicyNotFound,
                )
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
        if let Some(delegation_id) = delegation_id.as_ref() {
            record = record.delegation(delegation_id);
        }
        if let Some(reason) = reason {
            record = record.meta("reason", reason);
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
        let event = AuditEvent {
            event_id: self.next_audit_event_id(tenant),
            tenant_id: tenant.tenant_id.clone(),
            principal_id: record.principal_id.cloned(),
            session_id: record.session_id.cloned(),
            delegation_id: record.delegation_id.cloned(),
            kind: record.kind,
            timestamp: now,
            metadata: record
                .metadata
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<_, _>>(),
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

fn attach_audit_event(
    decision: AuthorizationDecision,
    audit_event_id: AuditEventId,
) -> AuthorizationDecision {
    match decision {
        AuthorizationDecision::Allow { grant, .. } => AuthorizationDecision::Allow {
            grant,
            audit_event_id: Some(audit_event_id),
        },
        AuthorizationDecision::Deny { reason, .. } => AuthorizationDecision::Deny {
            reason,
            audit_event_id: Some(audit_event_id),
        },
    }
}

fn deny(reason: DenialReason) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
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

/// Claims supplied by the application at registration time.
pub type ClaimInput = BTreeMap<String, String>;
