use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use appport_auth_mesh_authz::{AuthorizationDecision, DenialReason};
use appport_auth_mesh_contract::{Capability, PrincipalKind};
use appport_auth_mesh_dsl::AuthConfig;
use appport_auth_mesh_providers::{
    AuthChallenge, AuthRequest, AuthResponse, ChallengeKind, ConnectorRegistry,
};
use appport_auth_mesh_runtime::{
    AuthError, AuthLifecycleStage, AuthMesh, MeshStores, Registration,
};
use appport_auth_mesh_surface::{AuthSurface, ProviderSurface};

use crate::boundary::{AuthBoundary, Requirement};
use crate::clock::{Clock, SystemClock};
use crate::context::AuthContext;
use crate::control::{
    apply_change, apply_revert_change, Approval, AuthorityChange, ChangeProposal,
    LiveAuthorityState, Preview, PreviewState, RouteId,
};
use crate::proposal_store::{
    ChangeRecord, MemoryProposalStore, ProposalMetadata, ProposalStatus, ProposalStore,
    StoredProposal,
};
use crate::request::{BoundaryRequest, Method, SessionCredential};

/// Where the boundary is placed.
///
/// It changes nothing about how authority is decided — it is recorded so a
/// deployment can be identified, and so the two placements can be proven
/// equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// AuthPort is bound to the application's own server.
    Embedded,
    /// AuthPort owns the server and the application sits behind it.
    Standalone,
}

impl BindingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Standalone => "standalone",
        }
    }
}

/// Whether the deployment lets callers register themselves.
///
/// Self-service registration with caller-supplied claims would be an
/// escalation, so the claims of a self-registered principal are fixed by the
/// deployment and the request cannot influence them. Closed is the default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RegistrationPolicy {
    #[default]
    Closed,
    SelfService {
        claims: BTreeMap<String, String>,
    },
}

impl RegistrationPolicy {
    pub fn self_service(claims: &[(&str, &str)]) -> Self {
        Self::SelfService {
            claims: claims
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
        }
    }
}

/// What a sign-in attempt produced.
///
/// The authenticated variant is much larger than the challenge one and is also
/// the common case, so it is left inline rather than boxed: a successful
/// sign-in should not need an allocation to be returned.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInOutcome {
    /// The connector proved an identity and a session was opened.
    Authenticated {
        context: AuthContext,
        credential: SessionCredential,
    },
    /// The connector needs the caller to go elsewhere first (an OAuth
    /// redirect, an emailed link). Nothing has been authenticated yet.
    Challenge(Box<AuthChallenge>),
}

/// The AuthPort runtime: the authoritative execution boundary.
///
/// It owns the contract, the mesh and the clock, and it is the only thing that
/// can produce an [`AuthContext`]. Embedded and standalone deployments both
/// hold one of these — there is no second implementation.
pub struct AuthPortRuntime {
    contract: AuthConfig,
    surface: AuthSurface,
    mesh: AuthMesh,
    mode: BindingMode,
    clock: Arc<dyn Clock>,
    registration: RegistrationPolicy,
    /// Live authority state overlays the immutable contract
    authority: Arc<RwLock<LiveAuthorityState>>,
    proposals: Arc<dyn ProposalStore>,
}

impl AuthPortRuntime {
    pub fn new(
        contract: AuthConfig,
        registry: ConnectorRegistry,
        stores: MeshStores,
        mode: BindingMode,
    ) -> Result<Self, AuthError> {
        let mesh = AuthMesh::new(contract.clone(), registry, stores)?;
        let surface = mesh.surface().clone();
        Ok(Self {
            contract,
            surface,
            mesh,
            mode,
            clock: Arc::new(SystemClock),
            registration: RegistrationPolicy::default(),
            authority: Arc::new(RwLock::new(LiveAuthorityState::new())),
            proposals: Arc::new(MemoryProposalStore::new()),
        })
    }

    pub fn embedded(
        contract: AuthConfig,
        registry: ConnectorRegistry,
        stores: MeshStores,
    ) -> Result<Self, AuthError> {
        Self::new(contract, registry, stores, BindingMode::Embedded)
    }

    pub fn standalone(
        contract: AuthConfig,
        registry: ConnectorRegistry,
        stores: MeshStores,
    ) -> Result<Self, AuthError> {
        Self::new(contract, registry, stores, BindingMode::Standalone)
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_registration(mut self, registration: RegistrationPolicy) -> Self {
        self.registration = registration;
        self
    }

    pub fn with_session_ttl(mut self, seconds: i64) -> Self {
        self.mesh = self.mesh.with_session_ttl(seconds);
        self
    }

    pub fn with_proposal_store(mut self, proposals: Arc<dyn ProposalStore>) -> Self {
        self.proposals = proposals;
        self
    }

    pub fn mode(&self) -> BindingMode {
        self.mode
    }

    pub fn contract(&self) -> &AuthConfig {
        &self.contract
    }

    pub fn surface(&self) -> &AuthSurface {
        &self.surface
    }

    pub fn mesh(&self) -> &AuthMesh {
        &self.mesh
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// The providers the UI may offer, from the one provider declaration.
    pub fn providers(&self) -> &[ProviderSurface] {
        &self.surface.providers
    }

    /// Resolve a request against what a route demands.
    ///
    /// This is the single enforcement path: an embedded middleware and the
    /// standalone server both call it, so they cannot drift apart.
    pub fn enforce(
        &self,
        request: &BoundaryRequest,
        requirement: &Requirement,
    ) -> Result<Option<AuthContext>, AuthError> {
        match requirement {
            // A public route needs no authority, so a stale cookie is simply
            // not a context — it is never an authorization decision.
            Requirement::Public => Ok(self.authenticate(request).ok()),
            Requirement::Authenticated => self.authenticate(request).map(Some),
            Requirement::Capability(capability) => {
                let context = self.authenticate(request)?;
                let decision = self.authorize(&context, capability)?;
                match decision {
                    AuthorizationDecision::Allow { .. } => Ok(Some(context)),
                    AuthorizationDecision::Deny { reason, .. } => Err(AuthError::new(
                        AuthLifecycleStage::PolicyEvaluation,
                        format!("`{}` is not granted to this principal", capability),
                        reason,
                    )),
                }
            }
        }
    }

    /// One complete authentication flow, driven by the connector.
    ///
    /// The caller supplies credentials; the connector issues the challenge and
    /// proves the external identity; the mesh resolves the principal and opens
    /// the session. The caller never supplies the principal.
    pub fn sign_in(&self, request: &BoundaryRequest) -> Result<SignInOutcome, AuthError> {
        let now = self.now();
        let tenant_id = self.required_field(request, "tenant")?;
        let connector = self.required_field(request, "connector")?;

        let parameters = connector_parameters(request);
        let mut auth_request = AuthRequest::new(connector.clone()).for_tenant(tenant_id.clone());
        auth_request.parameters = parameters.clone();

        let challenge = self.mesh.begin(&tenant_id, &auth_request)?;
        if !matches!(challenge.kind, ChallengeKind::Credentials) {
            // Redirect and out-of-band connectors complete elsewhere; nothing
            // is authenticated yet, and no session is opened.
            return Ok(SignInOutcome::Challenge(Box::new(challenge)));
        }

        let mut response = AuthResponse::to_challenge(&challenge).for_tenant(tenant_id.clone());
        response.parameters = parameters;

        let authenticated = self.mesh.sign_in(&tenant_id, &response, now)?;
        let context = AuthContext::new(authenticated.session, authenticated.context);
        let credential = context.credential();
        Ok(SignInOutcome::Authenticated {
            context,
            credential,
        })
    }

    /// Register a new principal, when the deployment allows it.
    ///
    /// The claims come from the deployment's policy, never from the request.
    pub fn sign_up(&self, request: &BoundaryRequest) -> Result<SignInOutcome, AuthError> {
        let claims = match &self.registration {
            RegistrationPolicy::Closed => {
                return Err(AuthError::new(
                    AuthLifecycleStage::Configuration,
                    "registration is closed for this deployment",
                    DenialReason::UnknownPrincipal,
                ))
            }
            RegistrationPolicy::SelfService { claims } => claims.clone(),
        };

        let now = self.now();
        let tenant_id = self.required_field(request, "tenant")?;
        let connector = self.required_field(request, "connector")?;

        let parameters = connector_parameters(request);
        let mut auth_request = AuthRequest::new(connector).for_tenant(tenant_id.clone());
        auth_request.parameters = parameters.clone();

        let challenge = self.mesh.begin(&tenant_id, &auth_request)?;
        if !matches!(challenge.kind, ChallengeKind::Credentials) {
            return Ok(SignInOutcome::Challenge(Box::new(challenge)));
        }

        let mut response = AuthResponse::to_challenge(&challenge).for_tenant(tenant_id.clone());
        response.parameters = parameters;

        let mut registration = Registration::human();
        registration.claims = claims;

        let authenticated = self
            .mesh
            .sign_up(&tenant_id, &response, registration, now)?;
        let context = AuthContext::new(authenticated.session, authenticated.context);
        let credential = context.credential();
        Ok(SignInOutcome::Authenticated {
            context,
            credential,
        })
    }

    /// End the session the request presented. Nothing else about the request
    /// decides whose session is ended.
    pub fn sign_out(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
        let context = self.authenticate(request)?;
        self.mesh.logout(
            context.tenant.tenant_id.as_str(),
            &context.session.id,
            self.now(),
        )
    }

    fn required_field(&self, request: &BoundaryRequest, name: &str) -> Result<String, AuthError> {
        request.field(name).map(str::to_string).ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                format!("missing `{}`", name),
                DenialReason::MissingCredential,
            )
        })
    }

    /// Get the current live authority state
    pub fn live_authority(&self) -> LiveAuthorityState {
        self.authority.read().unwrap().clone()
    }

    /// Propose a change to authority state
    pub fn propose_change(&self, change: AuthorityChange) -> Result<ChangeProposal, String> {
        let current = self.authority.read().unwrap().clone();
        let after = self.preview_authority_change(&current, &change)?;
        let id = self.proposals.allocate_proposal_id();

        let proposal = ChangeProposal {
            id: id.clone(),
            change,
            preview: Preview {
                before: PreviewState::from(&current),
                after: PreviewState::from(&after),
            },
            revision: current.revision,
        };

        self.proposals.store_proposal(StoredProposal {
            id,
            change: proposal.change.clone(),
            preview: proposal.preview.clone(),
            revision: proposal.revision,
            status: ProposalStatus::Pending,
            created_at: SystemTime::now(),
            applied_at: None,
            change_id: None,
            rejection_reason: None,
        })?;

        Ok(proposal)
    }

    /// Apply a proposed change with approval
    pub fn apply_change(&self, proposal: ChangeProposal, approval: Approval) -> Result<String, String> {
        // Verify the approval was created for this proposal
        if !approval.verify(&proposal) {
            return Err("approval token does not match proposal".to_string());
        }

        let mut authority = self.authority.write().unwrap();

        // The revision must match to prevent concurrent modification issues
        if proposal.revision != authority.revision {
            return Err("change conflicts with newer authority state".to_string());
        }

        let previous_state = authority.clone();
        let next = self.preview_authority_change(&authority, &proposal.change)?;
        let change_id = format!(
            "change-{}-rev{}",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            next.revision
        );

        *authority = next;
        let resulting_state = authority.clone();

        self.proposals.mark_applied(
            &proposal.id,
            change_id.clone(),
            resulting_state.revision,
        )?;
        self.proposals.store_change_record(ChangeRecord {
            change_id: change_id.clone(),
            proposal_id: proposal.id,
            reverted_change_id: match &proposal.change {
                AuthorityChange::Revert { change_id } => Some(change_id.clone()),
                _ => None,
            },
            change: proposal.change,
            previous_state,
            resulting_state,
            applied_at: SystemTime::now(),
            applied_by: None,
        })?;

        Ok(change_id)
    }

    pub fn retrieve_proposal(&self, proposal_id: &str) -> Result<StoredProposal, String> {
        self.proposals.retrieve_proposal(proposal_id)
    }

    pub fn list_proposals(&self, limit: usize, offset: usize) -> Result<Vec<ProposalMetadata>, String> {
        self.proposals.list_proposals(limit, offset)
    }

    pub fn apply_stored_proposal(
        &self,
        proposal_id: &str,
        approval: Approval,
    ) -> Result<(String, u64), String> {
        let stored = self.proposals.retrieve_proposal(proposal_id)?;
        if stored.status != ProposalStatus::Pending {
            return Err(format!("proposal `{}` is not pending", proposal_id));
        }
        let proposal = ChangeProposal {
            id: stored.id,
            change: stored.change,
            preview: stored.preview,
            revision: stored.revision,
        };
        let change_id = self.apply_change(proposal, approval)?;
        let revision = self.live_authority().revision;
        Ok((change_id, revision))
    }

    pub fn history(&self, limit: usize, offset: usize) -> Result<Vec<ChangeRecord>, String> {
        self.proposals.list_change_records(limit, offset)
    }

    fn preview_authority_change(
        &self,
        current: &LiveAuthorityState,
        change: &AuthorityChange,
    ) -> Result<LiveAuthorityState, String> {
        match change {
            AuthorityChange::Revert { change_id } => {
                let record = self.proposals.retrieve_change_record(change_id)?;
                apply_revert_change(current, change_id, &record)
            }
            _ => apply_change(current, change),
        }
    }

    /// Is a route currently protected?
    pub fn get_route_protection(&self, method: &Method, path: &str) -> Option<String> {
        let authority = self.authority.read().unwrap();
        let route_id = RouteId::new(method.clone(), path.to_string());
        authority
            .route_protection
            .get(&route_id)
            .and_then(|p| p.capability.clone())
    }

    /// Is a provider currently enabled?
    pub fn is_provider_enabled(&self, provider: &str) -> bool {
        let authority = self.authority.read().unwrap();
        authority
            .provider_state
            .get(provider)
            .map(|p| p.enabled)
            .unwrap_or(true) // Providers default to enabled if not explicitly disabled
    }
}

impl AuthBoundary for AuthPortRuntime {
    fn authenticate(&self, request: &BoundaryRequest) -> Result<AuthContext, AuthError> {
        let credential = request.credential().ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::SessionValidation,
                "no session credential",
                DenialReason::MissingCredential,
            )
        })?;

        // Everything below is read back from AuthPort's own state. The request
        // contributed a credential and nothing else.
        let (session, runtime_context) =
            self.mesh
                .resolve_session(&credential.tenant_id, &credential.session_id, self.now())?;

        // A caller may address a tenant explicitly, but only the one its
        // session actually belongs to.
        if let Some(hint) = request.tenant_hint() {
            if hint != runtime_context.tenant.tenant_id.as_str() {
                return Err(AuthError::new(
                    AuthLifecycleStage::TenantResolution,
                    "request addresses a tenant the session does not belong to",
                    DenialReason::TenantMismatch,
                ));
            }
        }

        Ok(AuthContext::new(session, runtime_context))
    }

    fn authorize(
        &self,
        context: &AuthContext,
        capability: &str,
    ) -> Result<AuthorizationDecision, AuthError> {
        if capability.trim().is_empty() {
            return Err(AuthError::new(
                AuthLifecycleStage::PolicyEvaluation,
                "no capability named",
                DenialReason::UnknownCapability,
            ));
        }

        // Humans, agents and services all arrive here. There is no second
        // authorization path, and an unrecordable decision denies.
        Ok(self.mesh.authorize(
            context.runtime(),
            &Capability(capability.to_string()),
            self.now(),
        ))
    }
}

/// Reserved fields select the flow; everything else is the connector's.
fn connector_parameters(request: &BoundaryRequest) -> BTreeMap<String, String> {
    request
        .body
        .iter()
        .chain(request.query.iter())
        .filter(|(name, _)| !matches!(name.as_str(), "tenant" | "connector"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Principal kinds the runtime distinguishes, for callers that want to branch.
pub fn principal_kind_str(kind: &PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Agent => "agent",
        PrincipalKind::Service => "service",
    }
}
