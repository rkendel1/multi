use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use appport_auth_mesh_authz::{
    evaluate_capability, Action, AuthorizationContext, AuthorizationDecision, AuthorizationRequest,
    DenialReason, ResourceAttributes, ResourceRef, ResourceResolver,
};
use appport_auth_mesh_contract::{
    AgentRun, Capability, ExecutionCredentialId, PrincipalId, PrincipalKind, RunId, TenantContext,
};
use appport_auth_mesh_dsl::AuthConfig;
use appport_auth_mesh_dsl::PasswordPolicy;
use appport_auth_mesh_providers::{
    AuthChallenge, AuthRequest, AuthResponse, ChallengeKind, ConnectorError, ConnectorRegistry,
};
use appport_auth_mesh_runtime::{
    AuthError, AuthLifecycleStage, AuthMesh, MeshStores, Registration, RunCreationRequest,
};
use appport_auth_mesh_storage::{AuditEvent, StorageTopology};
use appport_auth_mesh_surface::{AuthSurface, ProviderSurface};

use crate::boundary::{AuthBoundary, Requirement};
use crate::ceremony::{CeremonyKind, ChallengeStore, MailMessage, MailPort};
use crate::clock::{Clock, SystemClock};
use crate::context::AuthContext;
use crate::control::{
    apply_change, apply_revert_change, Approval, AuthorityChange, ChangeProposal,
    LiveAuthorityState, Preview, PreviewState, RouteId,
};
use crate::proposal_store::{
    ChangeRecord, MemoryProposalStore, ProposalMetadata, ProposalSource, ProposalStatus,
    ProposalStore, StoredProposal,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePasswordPolicy {
    pub policy: PasswordPolicy,
    pub authority_revision: u64,
    pub contract_fingerprint: String,
    pub policy_revision: u64,
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
    resource_resolver: Arc<dyn ResourceResolver + Send + Sync>,
    registration: RegistrationPolicy,
    /// Live authority state overlays the immutable contract
    authority: Arc<RwLock<LiveAuthorityState>>,
    proposals: Arc<dyn ProposalStore>,
    mail: Option<Arc<dyn MailPort>>,
    challenges: ChallengeStore,
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
            resource_resolver: Arc::new(NoResourceResolver),
            registration: RegistrationPolicy::default(),
            authority: Arc::new(RwLock::new(LiveAuthorityState::new())),
            proposals: Arc::new(MemoryProposalStore::new()),
            mail: None,
            challenges: ChallengeStore::default(),
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

    pub fn with_resource_resolver(
        mut self,
        resolver: Arc<dyn ResourceResolver + Send + Sync>,
    ) -> Self {
        self.resource_resolver = resolver;
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

    pub fn with_mail_port(mut self, mail: Arc<dyn MailPort>) -> Self {
        self.mail = Some(mail);
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

    pub fn storage_topology(&self) -> StorageTopology {
        StorageTopology::from_declaration(
            &self.contract.storage.authority,
            &self.contract.storage.audit,
            &self.contract.storage.reporting,
        )
    }

    pub fn audit_events(
        &self,
        tenant: &TenantContext,
        since: Option<i64>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, AuthError> {
        self.mesh.audit_events(tenant, since, limit)
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// The providers the UI may offer, from the one provider declaration.
    pub fn providers(&self) -> &[ProviderSurface] {
        &self.surface.providers
    }

    pub fn effective_password_policy(&self) -> EffectivePasswordPolicy {
        let authority = self.authority.read().unwrap();
        let policy = authority
            .password_policy
            .clone()
            .unwrap_or_else(|| self.contract.password_policy.clone());
        EffectivePasswordPolicy {
            policy_revision: authority.revision,
            authority_revision: authority.revision,
            contract_fingerprint: self.contract.fingerprint(),
            policy,
        }
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
                let decision = match authorization_request(context.runtime(), capability, request) {
                    Some(auth_request) => match self.run_id_from_request(&context, request)? {
                        Some(run_id) => {
                            self.authorize_run_resource(&context, &run_id, auth_request)?
                        }
                        None => self.authorize_resource(&context, auth_request)?,
                    },
                    None => self.authorize(&context, capability)?,
                };
                match decision {
                    AuthorizationDecision::Allow { .. } => {
                        Ok(Some(context.with_decision(decision)))
                    }
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
        self.ensure_password_not_expired(&authenticated.external, now)?;
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
        let self_service = matches!(self.registration, RegistrationPolicy::SelfService { .. });
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
        let connector_impl = self
            .mesh
            .registry()
            .get(&connector)
            .map_err(to_auth_error)?;
        if connector_impl.supports_password_management() {
            let password = self.required_field(request, "password")?;
            self.validate_password(&password)?;
        }

        let parameters = connector_parameters(request);
        let mut auth_request = AuthRequest::new(connector.clone()).for_tenant(tenant_id.clone());
        auth_request.parameters = parameters.clone();

        let challenge = self.mesh.begin(&tenant_id, &auth_request)?;
        if !matches!(challenge.kind, ChallengeKind::Credentials) {
            return Ok(SignInOutcome::Challenge(Box::new(challenge)));
        }

        let mut response = AuthResponse::to_challenge(&challenge).for_tenant(tenant_id.clone());
        response.parameters = parameters;

        if self_service && connector == "local" && connector_impl.authenticate(&response).is_err() {
            let username = self.required_field(request, "username")?;
            let password = self.required_field(request, "password")?;
            let mut attributes = BTreeMap::new();
            if let Some(email) = request
                .field("email")
                .or_else(|| username.contains('@').then_some(username.as_str()))
            {
                attributes.insert("email".to_string(), email.to_string());
            }
            connector_impl
                .create_account(&username, &password, attributes)
                .map_err(to_auth_error)?;
        }

        let mut registration = Registration::human();
        registration.claims = claims;

        let authenticated = self
            .mesh
            .sign_up(&tenant_id, &response, registration, now)?;
        if self.surface.features.email_verification {
            self.request_email_verification(request)?;
        }
        let context = AuthContext::new(authenticated.session, authenticated.context);
        let credential = context.credential();
        Ok(SignInOutcome::Authenticated {
            context,
            credential,
        })
    }

    /// Provision a local development identity and its authoritative principal.
    /// This is called by the repository-local Studio control surface, not by
    /// the public self-service signup route.
    pub fn create_local_user(
        &self,
        tenant_id: &str,
        username: &str,
        password: &str,
        email: Option<&str>,
        claims: BTreeMap<String, String>,
    ) -> Result<(), AuthError> {
        self.validate_password(password)?;
        let connector = self.mesh.registry().get("local").map_err(to_auth_error)?;
        let mut attributes = BTreeMap::new();
        if let Some(email) = email.or_else(|| username.contains('@').then_some(username)) {
            attributes.insert("email".to_string(), email.to_string());
        }
        connector
            .create_account(username, password, attributes)
            .map_err(to_auth_error)?;

        let challenge = connector
            .begin(
                &AuthRequest::new("local")
                    .for_tenant(tenant_id)
                    .with_parameter("username", username),
            )
            .map_err(to_auth_error)?;
        let response = AuthResponse::to_challenge(&challenge)
            .for_tenant(tenant_id)
            .with_parameter("username", username)
            .with_parameter("password", password);
        let mut registration = Registration::human();
        registration.claims = claims;
        self.mesh
            .sign_up(tenant_id, &response, registration, self.now())?;
        Ok(())
    }

    pub fn change_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
        let policy = self.effective_password_policy().policy;
        if !policy.allow_password_change {
            return Err(AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                "password changes are disabled",
                DenialReason::PolicyDenied,
            ));
        }
        let tenant_id = self.required_field(request, "tenant")?;
        let connector_id = self.required_field(request, "connector")?;
        let username = self.required_field(request, "username")?;
        let current_password = self.required_field(request, "current_password")?;
        let new_password = self.required_field(request, "new_password")?;
        self.validate_password_with(&new_password, &policy)?;
        let connector = self
            .mesh
            .registry()
            .get(&connector_id)
            .map_err(to_auth_error)?;
        connector
            .change_password(
                &tenant_id,
                &username,
                &current_password,
                &new_password,
                &policy,
                self.now(),
            )
            .map_err(to_auth_error)
    }

    pub fn forgot_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
        let policy = self.effective_password_policy().policy;
        if !policy.allow_password_reset {
            return Err(AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                "password resets are disabled",
                DenialReason::PolicyDenied,
            ));
        }
        self.require_mail_contract("password_reset")?;
        let tenant_id = self.required_field(request, "tenant")?;
        let connector_id = self.required_field(request, "connector")?;
        let username = self.required_field(request, "username")?;
        let connector = self
            .mesh
            .registry()
            .get(&connector_id)
            .map_err(to_auth_error)?;
        let Some(address) = connector.recovery_address(&username) else {
            // Account existence is deliberately not externally observable.
            return Ok(());
        };
        let Some(mail) = &self.mail else {
            return Err(AuthError::new(
                AuthLifecycleStage::Configuration,
                "MailPort is not configured",
                DenialReason::PolicyDenied,
            ));
        };
        let token = self
            .challenges
            .issue(
                CeremonyKind::PasswordReset,
                &tenant_id,
                &format!("{connector_id}\0{username}"),
                self.now() + 900,
            )
            .map_err(|message| {
                AuthError::new(
                    AuthLifecycleStage::RuntimeContext,
                    message,
                    DenialReason::PolicyDenied,
                )
            })?;
        let variables = HashMap::from([
            ("token".to_string(), token.clone()),
            (
                "reset_url".to_string(),
                format!("/auth/password/reset?token={token}"),
            ),
        ]);
        mail.send(MailMessage {
            template: "password_reset".to_string(),
            identity: "auth".to_string(),
            to: address,
            tenant: tenant_id,
            variables,
            idempotency_key: format!("password-reset:{}", token),
        })
        .map_err(|message| {
            AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                message,
                DenialReason::PolicyDenied,
            )
        })
    }

    pub fn reset_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
        let policy = self.effective_password_policy().policy;
        let token = self.required_field(request, "token")?;
        let new_password = self
            .required_field(request, "new_password")
            .or_else(|_| self.required_field(request, "password"))?;
        self.validate_password_with(&new_password, &policy)?;
        let (tenant_id, account) = self
            .challenges
            .consume(&token, CeremonyKind::PasswordReset, self.now())
            .map_err(|message| {
                AuthError::new(
                    AuthLifecycleStage::ProviderAuthentication,
                    message,
                    DenialReason::MissingCredential,
                )
            })?;
        let (connector_id, username) = account.split_once('\0').ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::RuntimeContext,
                "invalid recovery challenge",
                DenialReason::MissingCredential,
            )
        })?;
        let connector = self
            .mesh
            .registry()
            .get(connector_id)
            .map_err(to_auth_error)?;
        connector
            .reset_password(&tenant_id, &username, &new_password, &policy, self.now())
            .map_err(to_auth_error)
    }

    pub fn request_email_verification(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
        self.require_mail_contract("email_verification")?;
        let tenant = self.required_field(request, "tenant")?;
        let connector_id = self.required_field(request, "connector")?;
        let username = self.required_field(request, "username")?;
        let connector = self
            .mesh
            .registry()
            .get(&connector_id)
            .map_err(to_auth_error)?;
        let Some(address) = connector.recovery_address(&username) else {
            return Ok(());
        };
        let Some(mail) = &self.mail else {
            return Err(AuthError::new(
                AuthLifecycleStage::Configuration,
                "MailPort is not configured",
                DenialReason::PolicyDenied,
            ));
        };
        let token = self
            .challenges
            .issue(
                CeremonyKind::EmailVerification,
                &tenant,
                &format!("{connector_id}\0{username}"),
                self.now() + 3600,
            )
            .map_err(|message| {
                AuthError::new(
                    AuthLifecycleStage::RuntimeContext,
                    message,
                    DenialReason::PolicyDenied,
                )
            })?;
        mail.send(MailMessage {
            template: "email_verification".to_string(),
            identity: "auth".to_string(),
            to: address,
            tenant,
            variables: HashMap::from([
                ("token".to_string(), token.clone()),
                (
                    "verification_url".to_string(),
                    format!("/auth/email/verification?token={token}"),
                ),
            ]),
            idempotency_key: format!("email-verification:{token}"),
        })
        .map_err(|message| {
            AuthError::new(
                AuthLifecycleStage::ProviderAuthentication,
                message,
                DenialReason::PolicyDenied,
            )
        })
    }

    pub fn verify_email(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
        let token = self.required_field(request, "token")?;
        let (_tenant, account) = self
            .challenges
            .consume(&token, CeremonyKind::EmailVerification, self.now())
            .map_err(|message| {
                AuthError::new(
                    AuthLifecycleStage::ProviderAuthentication,
                    message,
                    DenialReason::MissingCredential,
                )
            })?;
        let (connector_id, username) = account.split_once('\0').ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::RuntimeContext,
                "invalid verification challenge",
                DenialReason::MissingCredential,
            )
        })?;
        self.mesh
            .registry()
            .get(connector_id)
            .map_err(to_auth_error)?
            .mark_email_verified(username)
            .map_err(to_auth_error)
    }

    /// Revoke an outstanding opaque ceremony token without revealing whether it existed.
    pub fn revoke_challenge(&self, token: &str) {
        self.challenges.revoke(token);
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

    fn require_mail_contract(&self, template: &str) -> Result<(), AuthError> {
        let mail = self.contract.mail.as_ref().ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::Configuration,
                "authentication email requires a `use mail` contract",
                DenialReason::PolicyDenied,
            )
        })?;
        if !mail.identities.contains_key("auth") || !mail.templates.contains_key(template) {
            return Err(AuthError::new(
                AuthLifecycleStage::Configuration,
                format!("MailPort contract does not declare `{template}`"),
                DenialReason::PolicyDenied,
            ));
        }
        Ok(())
    }

    fn validate_password(&self, password: &str) -> Result<(), AuthError> {
        self.validate_password_with(password, &self.effective_password_policy().policy)
    }

    fn validate_password_with(
        &self,
        password: &str,
        policy: &PasswordPolicy,
    ) -> Result<(), AuthError> {
        if password.chars().count() < policy.min_length {
            return Err(password_error(
                "PASSWORD_TOO_SHORT",
                DenialReason::PasswordTooShort,
            ));
        }
        if password.chars().count() > policy.max_length {
            return Err(password_error(
                "PASSWORD_TOO_LONG",
                DenialReason::PasswordTooLong,
            ));
        }
        if policy.require_uppercase && !password.chars().any(|ch| ch.is_ascii_uppercase()) {
            return Err(password_error(
                "PASSWORD_MISSING_UPPERCASE",
                DenialReason::PasswordMissingUppercase,
            ));
        }
        if policy.require_lowercase && !password.chars().any(|ch| ch.is_ascii_lowercase()) {
            return Err(password_error(
                "PASSWORD_MISSING_LOWERCASE",
                DenialReason::PasswordMissingLowercase,
            ));
        }
        if policy.require_number && !password.chars().any(|ch| ch.is_ascii_digit()) {
            return Err(password_error(
                "PASSWORD_MISSING_NUMBER",
                DenialReason::PasswordMissingNumber,
            ));
        }
        if policy.require_special_character
            && !password
                .chars()
                .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_whitespace())
        {
            return Err(password_error(
                "PASSWORD_MISSING_SPECIAL_CHARACTER",
                DenialReason::PasswordMissingSpecialCharacter,
            ));
        }
        Ok(())
    }

    fn ensure_password_not_expired(
        &self,
        external: &appport_auth_mesh_providers::ExternalIdentity,
        now: i64,
    ) -> Result<(), AuthError> {
        let policy = self.effective_password_policy().policy;
        let Some(days) = policy.password_expiration_days else {
            return Ok(());
        };
        let Some(changed_at) = external
            .attributes
            .get("password_changed_at")
            .and_then(|value| value.parse::<i64>().ok())
        else {
            return Ok(());
        };
        if now.saturating_sub(changed_at) > i64::from(days) * 86_400 {
            return Err(password_error(
                "PASSWORD_EXPIRED",
                DenialReason::PasswordExpired,
            ));
        }
        Ok(())
    }

    /// Get the current live authority state
    pub fn live_authority(&self) -> LiveAuthorityState {
        self.authority.read().unwrap().clone()
    }

    /// Propose a change to authority state
    pub fn propose_change(&self, change: AuthorityChange) -> Result<ChangeProposal, String> {
        self.propose_change_with_metadata(change, ProposalSource::Explicit, 0)
    }

    pub fn propose_change_with_metadata(
        &self,
        change: AuthorityChange,
        source: ProposalSource,
        discovery_revision: u64,
    ) -> Result<ChangeProposal, String> {
        let current = self.authority.read().unwrap().clone();
        let after = self.preview_authority_change(&current, &change)?;
        let id = self.proposals.allocate_proposal_id();
        let contract_fingerprint = self.contract.fingerprint();

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
            contract_fingerprint,
            discovery_revision,
            source,
            status: ProposalStatus::Pending,
            created_at: SystemTime::now(),
            applied_at: None,
            change_id: None,
            rejection_reason: None,
        })?;

        Ok(proposal)
    }

    pub fn ensure_proposal(
        &self,
        change: AuthorityChange,
        source: ProposalSource,
        discovery_revision: u64,
    ) -> Result<StoredProposal, String> {
        let contract_fingerprint = self.contract.fingerprint();
        if let Some(existing) =
            self.proposals
                .find_proposal(&change, &contract_fingerprint, discovery_revision)?
        {
            return Ok(existing);
        }
        let proposal = self.propose_change_with_metadata(change, source, discovery_revision)?;
        self.proposals.retrieve_proposal(&proposal.id)
    }

    pub fn approve_stored_proposal(&self, proposal_id: &str) -> Result<(), String> {
        let stored = self.proposals.retrieve_proposal(proposal_id)?;
        match stored.status {
            ProposalStatus::Pending => {}
            ProposalStatus::Approved => return Ok(()),
            ProposalStatus::Applied => {
                return Err(format!("proposal `{}` is already applied", proposal_id));
            }
            ProposalStatus::Rejected => {
                return Err(format!("proposal `{}` is rejected", proposal_id));
            }
            ProposalStatus::Active
            | ProposalStatus::Orphaned
            | ProposalStatus::Stale
            | ProposalStatus::Superseded => {
                return Err(format!(
                    "proposal `{}` is {} and requires reconciliation review",
                    proposal_id,
                    stored.status.as_str()
                ));
            }
        }
        self.verify_stored_proposal_is_current(&stored)?;
        self.proposals.mark_approved(proposal_id)
    }

    pub fn reject_stored_proposal(&self, proposal_id: &str, reason: String) -> Result<(), String> {
        let stored = self.proposals.retrieve_proposal(proposal_id)?;
        match stored.status {
            ProposalStatus::Applied => {
                return Err(format!("proposal `{}` is already applied", proposal_id));
            }
            ProposalStatus::Rejected => return Ok(()),
            ProposalStatus::Pending
            | ProposalStatus::Approved
            | ProposalStatus::Active
            | ProposalStatus::Orphaned
            | ProposalStatus::Stale
            | ProposalStatus::Superseded => {}
        }
        self.proposals.mark_rejected(proposal_id, reason)
    }

    /// Apply a proposed change with approval
    pub fn apply_change(
        &self,
        proposal: ChangeProposal,
        approval: Approval,
    ) -> Result<String, String> {
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

        self.proposals
            .mark_applied(&proposal.id, change_id.clone(), resulting_state.revision)?;
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

    pub fn list_proposals(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProposalMetadata>, String> {
        self.proposals.list_proposals(limit, offset)
    }

    pub fn apply_stored_proposal(
        &self,
        proposal_id: &str,
        approval: Approval,
    ) -> Result<(String, u64), String> {
        let stored = self.proposals.retrieve_proposal(proposal_id)?;
        if stored.status != ProposalStatus::Approved {
            return Err(format!("proposal `{}` is not approved", proposal_id));
        }
        self.verify_stored_proposal_is_current(&stored)?;
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

    pub fn apply_approved_stored_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<(String, u64), String> {
        let stored = self.proposals.retrieve_proposal(proposal_id)?;
        let approval = Approval::for_proposal(&ChangeProposal {
            id: stored.id.clone(),
            change: stored.change.clone(),
            preview: stored.preview.clone(),
            revision: stored.revision,
        });
        self.apply_stored_proposal(proposal_id, approval)
    }

    pub fn apply_approved_stored_proposals(
        &self,
        proposal_ids: &[String],
    ) -> Result<Vec<(String, String, u64)>, String> {
        if proposal_ids.is_empty() {
            return Ok(Vec::new());
        }
        let stored = proposal_ids
            .iter()
            .map(|id| self.proposals.retrieve_proposal(id))
            .collect::<Result<Vec<_>, _>>()?;
        for proposal in &stored {
            if proposal.status != ProposalStatus::Approved {
                return Err(format!("proposal `{}` is not approved", proposal.id));
            }
        }

        let mut authority = self.authority.write().unwrap();
        let contract_fingerprint = self.contract.fingerprint();
        let base_revision = authority.revision;
        let mut next = authority.clone();
        let mut records = Vec::new();
        for (index, proposal) in stored.iter().enumerate() {
            if proposal.contract_fingerprint != contract_fingerprint {
                return Err("STALE_AUTHORITY_PROPOSAL: contract fingerprint changed".to_string());
            }
            if proposal.revision != base_revision {
                return Err(format!(
                    "STALE_AUTHORITY_PROPOSAL: expected authority revision {}, current authority revision {}",
                    proposal.revision, base_revision
                ));
            }
            let before = next.clone();
            next = self.preview_authority_change(&next, &proposal.change)?;
            let change_id = format!(
                "change-{}-{}-rev{}",
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
                index,
                next.revision
            );
            records.push(ChangeRecord {
                change_id: change_id.clone(),
                proposal_id: proposal.id.clone(),
                reverted_change_id: match &proposal.change {
                    AuthorityChange::Revert { change_id } => Some(change_id.clone()),
                    _ => None,
                },
                change: proposal.change.clone(),
                previous_state: before,
                resulting_state: next.clone(),
                applied_at: SystemTime::now(),
                applied_by: None,
            });
        }

        *authority = next;
        let mut outcomes = Vec::new();
        for record in records {
            self.proposals.mark_applied(
                &record.proposal_id,
                record.change_id.clone(),
                record.resulting_state.revision,
            )?;
            self.proposals.store_change_record(record.clone())?;
            outcomes.push((
                record.proposal_id,
                record.change_id,
                record.resulting_state.revision,
            ));
        }
        Ok(outcomes)
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

    fn verify_stored_proposal_is_current(&self, proposal: &StoredProposal) -> Result<(), String> {
        let authority = self.authority.read().unwrap();
        if proposal.contract_fingerprint != self.contract.fingerprint() {
            return Err("STALE_AUTHORITY_PROPOSAL: contract fingerprint changed".to_string());
        }
        if proposal.revision != authority.revision {
            return Err(format!(
                "STALE_AUTHORITY_PROPOSAL: expected authority revision {}, current authority revision {}",
                proposal.revision, authority.revision
            ));
        }
        let _next = self.preview_authority_change(&authority, &proposal.change)?;
        Ok(())
    }

    /// Is a route currently protected?
    pub fn get_route_protection(&self, method: &Method, path: &str) -> Option<String> {
        let authority = self.authority.read().unwrap();
        let route_id = RouteId::new(*method, path.to_string());
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

fn password_error(message: &str, denial: DenialReason) -> AuthError {
    AuthError::new(
        AuthLifecycleStage::ProviderAuthentication,
        message.to_string(),
        denial,
    )
}

fn to_auth_error(err: ConnectorError) -> AuthError {
    let denial = match err {
        ConnectorError::PasswordReused { .. } => DenialReason::PasswordReused,
        ConnectorError::UnknownConnector { .. } | ConnectorError::Unsupported { .. } => {
            DenialReason::UnsupportedConnector
        }
        ConnectorError::InvalidCredentials { .. } | ConnectorError::ChallengeMismatch { .. } => {
            DenialReason::MissingCredential
        }
        ConnectorError::NotDeclared { .. }
        | ConnectorError::DuplicateConnector { .. }
        | ConnectorError::InvalidRequest { .. }
        | ConnectorError::PasswordHashingFailed { .. } => DenialReason::PolicyDenied,
    };
    AuthError::new(
        AuthLifecycleStage::ProviderAuthentication,
        err.to_string(),
        denial,
    )
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

        if let Some(policy) = self
            .authority
            .read()
            .unwrap()
            .capability_policies
            .get(capability)
            .cloned()
        {
            return Ok(evaluate_capability(
                Some(&policy),
                Some(&context.principal),
                Some(&context.tenant),
                context.delegation.as_ref().map(|value| &value.delegation),
                &Capability(capability.to_string()),
                self.now(),
            ));
        }

        // Humans, agents and services all arrive here. There is no second
        // authorization path, and an unrecordable decision denies.
        Ok(self.mesh.authorize_with_authority_revision(
            context.runtime(),
            &Capability(capability.to_string()),
            self.now(),
            self.live_authority().revision,
        ))
    }
}

impl AuthPortRuntime {
    pub fn authorize_resource(
        &self,
        context: &AuthContext,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, AuthError> {
        if request.capability.as_str().trim().is_empty() {
            return Err(AuthError::new(
                AuthLifecycleStage::PolicyEvaluation,
                "no capability named",
                DenialReason::UnknownCapability,
            ));
        }
        let attributes = request
            .resource
            .as_ref()
            .map(|resource| self.resource_resolver.resolve(resource, &request.context));
        Ok(self.mesh.authorize_request_with_authority_revision(
            context.runtime(),
            &request,
            attributes.as_ref(),
            self.now(),
            self.live_authority().revision,
        ))
    }

    pub fn create_agent_run(
        &self,
        tenant_id: &str,
        agent: &PrincipalId,
        request: RunCreationRequest,
    ) -> Result<AgentRun, AuthError> {
        self.mesh.create_agent_run(
            tenant_id,
            agent,
            request,
            self.now(),
            self.live_authority().revision,
            self.contract.fingerprint(),
        )
    }

    pub fn agent_runs(
        &self,
        tenant_id: &str,
        agent: &PrincipalId,
    ) -> Result<Vec<AgentRun>, AuthError> {
        let tenant = self.mesh.tenant(tenant_id)?;
        self.mesh.agent_runs(&tenant, agent)
    }

    pub fn agent_run(
        &self,
        tenant_id: &str,
        run_id: &RunId,
    ) -> Result<Option<AgentRun>, AuthError> {
        let tenant = self.mesh.tenant(tenant_id)?;
        self.mesh.agent_run(&tenant, run_id)
    }

    pub fn agent_run_by_credential(
        &self,
        tenant_id: &str,
        credential: &ExecutionCredentialId,
    ) -> Result<Option<AgentRun>, AuthError> {
        let tenant = self.mesh.tenant(tenant_id)?;
        self.mesh.agent_run_by_credential(&tenant, credential)
    }

    pub fn cancel_agent_run(&self, tenant_id: &str, run_id: &RunId) -> Result<AgentRun, AuthError> {
        self.mesh.cancel_agent_run(tenant_id, run_id, self.now())
    }

    pub fn authorize_run_resource(
        &self,
        context: &AuthContext,
        run_id: &RunId,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, AuthError> {
        if request.capability.as_str().trim().is_empty() {
            return Err(AuthError::new(
                AuthLifecycleStage::PolicyEvaluation,
                "no capability named",
                DenialReason::UnknownCapability,
            ));
        }
        let attributes = request
            .resource
            .as_ref()
            .map(|resource| self.resource_resolver.resolve(resource, &request.context));
        Ok(self.mesh.authorize_run_request_with_authority_revision(
            context.runtime(),
            run_id,
            &request,
            attributes.as_ref(),
            self.now(),
            self.live_authority().revision,
        ))
    }

    fn run_id_from_request(
        &self,
        context: &AuthContext,
        request: &BoundaryRequest,
    ) -> Result<Option<RunId>, AuthError> {
        if let Some(run_id) = request.field("run_id") {
            return Ok(Some(RunId(run_id.to_string())));
        }
        let Some(credential) = request
            .field("execution_credential")
            .or_else(|| request.field("run_credential"))
        else {
            return Ok(None);
        };
        let run = self.agent_run_by_credential(
            context.tenant.tenant_id.as_str(),
            &ExecutionCredentialId(credential.to_string()),
        )?;
        run.map(|run| Some(run.id)).ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::PolicyEvaluation,
                "run credential was not found",
                DenialReason::RunNotFound,
            )
        })
    }
}

struct NoResourceResolver;

impl ResourceResolver for NoResourceResolver {
    fn resolve(
        &self,
        resource: &ResourceRef,
        _context: &AuthorizationContext,
    ) -> ResourceAttributes {
        ResourceAttributes::new().with_tenant(resource.tenant_id.clone())
    }
}

fn authorization_request(
    context: &appport_auth_mesh_runtime::RuntimeContext,
    capability: &str,
    request: &BoundaryRequest,
) -> Option<AuthorizationRequest> {
    let (resource_type, resource_id, action) =
        infer_resource_target(request.method, &request.path)?;
    Some(AuthorizationRequest {
        principal: context.principal.id.clone(),
        tenant: context.tenant.tenant_id.clone(),
        capability: Capability(capability.to_string()),
        action,
        resource: Some(ResourceRef::new(
            resource_type,
            resource_id,
            context.tenant.tenant_id.clone(),
        )),
        context: AuthorizationContext::default(),
    })
}

fn infer_resource_target(method: Method, path: &str) -> Option<(String, String, Action)> {
    let segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() || matches!(segments[0], "auth" | "_authport") {
        return None;
    }
    let action = match method {
        Method::Get => "read",
        Method::Post => "create",
        Method::Put | Method::Patch => "update",
        Method::Delete => "delete",
        Method::Head | Method::Options => return None,
    };
    let resource_type = singular_resource(segments[0]);
    let resource_id = if segments.len() == 1 {
        "*".to_string()
    } else {
        segments[1].to_string()
    };
    Some((resource_type, resource_id, action.into()))
}

fn singular_resource(resource: &str) -> String {
    resource
        .strip_suffix("ies")
        .map(|prefix| format!("{}y", prefix))
        .or_else(|| resource.strip_suffix('s').map(str::to_string))
        .unwrap_or_else(|| resource.to_string())
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
