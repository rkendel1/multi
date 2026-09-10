use appport_auth_mesh_dsl::{
    stable_hash, AuthConfig, AuthExperienceCapability, AuthUiMode, AuthenticationAssurance,
    AuthenticationMethod, ClaimKind, ExperienceRenderer, ExperienceState, IsolationMode, UiScreen,
};
use appport_auth_mesh_providers::catalog;
use appport_auth_mesh_providers::{ConnectorKind, ConnectorStatus};

/// The application-facing auth surface, derived from the declaration.
///
/// Everything here is a function of [`AuthConfig`]: the same declaration always
/// produces the same routes, providers, claims and UI. Nothing in this module
/// maintains a second list of providers or features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSurface {
    pub routes: Vec<AuthRoute>,
    pub boundary: BoundarySurface,
    pub providers: Vec<ProviderSurface>,
    pub features: AuthFeatures,
    pub claims: Vec<ClaimSurface>,
    pub principals: Vec<PrincipalSurfaceKind>,
    pub agents: Option<AgentSurface>,
    pub ui: AuthUiSurface,
    pub experiences: Vec<ExperienceSurface>,
    pub multi_tenant: bool,
    pub isolation: IsolationMode,
    pub contract_fingerprint: String,
}

impl AuthSurface {
    pub fn derive(config: &AuthConfig) -> Self {
        let config = config.canonical();
        let features = AuthFeatures::derive(&config);

        Self {
            routes: AuthRoute::derive(&config, &features),
            boundary: BoundarySurface::derive(),
            providers: config
                .providers
                .iter()
                .map(|provider| ProviderSurface::derive(provider))
                .collect(),
            claims: config
                .claims
                .iter()
                .map(|claim| ClaimSurface {
                    name: claim.name.clone(),
                    kind: claim.kind.clone(),
                })
                .collect(),
            principals: PrincipalSurfaceKind::derive(&features),
            agents: features.agents.then(AgentSurface::derive),
            ui: AuthUiSurface::derive(&config, &features),
            experiences: ExperienceSurface::derive_all(&config, &features),
            multi_tenant: config.multi_tenant,
            isolation: config.isolation.clone(),
            contract_fingerprint: config.fingerprint(),
            features,
        }
    }

    /// Canonical paths and their aliases both resolve to the same route: there
    /// is one route table, however a caller spells it.
    pub fn route(&self, path: &str) -> Option<&AuthRoute> {
        self.routes.iter().find(|route| route.matches(path))
    }

    pub fn exposes(&self, path: &str) -> bool {
        self.route(path).is_some()
    }

    pub fn paths(&self) -> Vec<String> {
        self.routes.iter().map(|route| route.path.clone()).collect()
    }

    pub fn provider(&self, id: &str) -> Option<&ProviderSurface> {
        self.providers.iter().find(|provider| provider.id == id)
    }

    /// Stable over the whole derived surface, not just the declaration, so a
    /// change in how the surface is generated is visible downstream.
    pub fn fingerprint(&self) -> String {
        let mut material = String::new();
        material.push_str(&self.contract_fingerprint);
        material.push_str(&format!(
            ";tenant={};isolation={};",
            self.multi_tenant,
            self.isolation.as_str()
        ));
        for route in &self.routes {
            material.push_str(&route.path);
            for alias in &route.aliases {
                material.push('|');
                material.push_str(alias);
            }
            material.push('(');
            for method in &route.methods {
                material.push_str(method.as_str());
                material.push(',');
            }
            material.push_str(if route.requires_session { ")s;" } else { ");" });
        }
        for provider in &self.providers {
            material.push_str(&format!(
                "{}:{}:{};",
                provider.id,
                provider.kind.as_str(),
                provider.status.as_str()
            ));
        }
        for claim in &self.claims {
            material.push_str(&format!("{}={};", claim.name, claim.kind.describe()));
        }
        for principal in &self.principals {
            material.push_str(principal.as_str());
            material.push(';');
        }
        material.push_str(&self.features.canonical_string());
        material.push_str(&self.ui.canonical_string());
        for experience in &self.experiences {
            material.push_str(&experience.canonical_string());
        }
        material.push_str(&self.boundary.canonical_string());
        format!("{:016x}", stable_hash(material.as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRoute {
    pub path: String,
    /// Alternate spellings of the same operation (`/auth/sign-in` for
    /// `/auth/login`). Aliases are part of the contract, not server sugar.
    pub aliases: Vec<String>,
    pub methods: Vec<AuthMethod>,
    pub operation: AuthOperation,
    pub requires_session: bool,
    pub feature: AuthFeature,
}

impl AuthRoute {
    pub fn matches(&self, path: &str) -> bool {
        self.path == path || self.aliases.iter().any(|alias| alias == path)
    }

    pub fn allows(&self, method: AuthMethod) -> bool {
        self.methods.contains(&method)
    }
}

impl AuthRoute {
    fn new(
        path: &str,
        methods: &[AuthMethod],
        operation: AuthOperation,
        requires_session: bool,
        feature: AuthFeature,
    ) -> Self {
        Self {
            path: path.to_string(),
            aliases: Vec::new(),
            methods: methods.to_vec(),
            operation,
            requires_session,
            feature,
        }
    }

    fn with_alias(mut self, alias: &str) -> Self {
        self.aliases.push(alias.to_string());
        self
    }

    fn derive(config: &AuthConfig, features: &AuthFeatures) -> Vec<Self> {
        use AuthMethod::{Delete, Get, Post};

        let mut routes = Vec::new();
        if config.experience.enabled(AuthExperienceCapability::SignIn) {
            routes.push(
                // GET renders the generated UI, POST performs the sign-in.
                Self::new(
                    "/auth/login",
                    &[Get, Post],
                    AuthOperation::Login,
                    false,
                    AuthFeature::Login,
                )
                .with_alias("/auth/sign-in"),
            );
        }
        if config.experience.enabled(AuthExperienceCapability::SignUp) {
            routes.push(Self::new(
                "/auth/signup",
                &[Get, Post],
                AuthOperation::Signup,
                false,
                AuthFeature::Signup,
            ));
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::PasswordChange)
        {
            routes.push(Self::new(
                "/auth/password/change",
                &[Post],
                AuthOperation::PasswordChange,
                false,
                AuthFeature::Signup,
            ));
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::PasswordReset)
        {
            routes.push(Self::new(
                "/auth/password/forgot",
                &[Post],
                AuthOperation::PasswordForgot,
                false,
                AuthFeature::Signup,
            ));
            routes.push(Self::new(
                "/auth/password/reset",
                &[Get, Post],
                AuthOperation::PasswordReset,
                false,
                AuthFeature::Signup,
            ));
        }
        routes.extend([Self::new(
            "/_authboundry/password-policy",
            &[Get],
            AuthOperation::PasswordPolicy,
            false,
            AuthFeature::ControlPlane,
        )]);
        if config.experience.enabled(AuthExperienceCapability::SignOut) {
            routes.push(
                Self::new(
                    "/auth/logout",
                    &[Post],
                    AuthOperation::Logout,
                    true,
                    AuthFeature::Sessions,
                )
                .with_alias("/auth/sign-out"),
            );
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::SessionManagement)
        {
            routes.push(Self::new(
                "/auth/session",
                &[Get, Delete],
                AuthOperation::Session,
                true,
                AuthFeature::Sessions,
            ));
            routes.push(Self::new(
                "/auth/sessions",
                &[Get],
                AuthOperation::Sessions,
                true,
                AuthFeature::Sessions,
            ));
        }
        if config.experience.enabled(AuthExperienceCapability::Profile) {
            routes.push(Self::new(
                "/auth/profile",
                &[Get],
                AuthOperation::Profile,
                true,
                AuthFeature::Profile,
            ));
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::DeviceManagement)
        {
            routes.push(Self::new(
                "/auth/devices",
                &[Get],
                AuthOperation::Devices,
                true,
                AuthFeature::Devices,
            ));
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::EmailVerification)
        {
            routes.push(Self::new(
                "/auth/email/verification",
                &[Get, Post],
                AuthOperation::EmailVerification,
                false,
                AuthFeature::EmailVerification,
            ));
        }
        if config.experience.enabled(AuthExperienceCapability::Mfa) {
            routes.push(Self::new(
                "/auth/mfa",
                &[Get, Post],
                AuthOperation::Mfa,
                true,
                AuthFeature::Mfa,
            ));
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::Passkeys)
        {
            routes.push(Self::new(
                "/auth/passkeys",
                &[Get, Post],
                AuthOperation::Passkeys,
                true,
                AuthFeature::Passkeys,
            ));
        }
        if config
            .experience
            .enabled(AuthExperienceCapability::Recovery)
        {
            routes.push(Self::new(
                "/auth/recovery",
                &[Post],
                AuthOperation::Recovery,
                false,
                AuthFeature::Recovery,
            ));
        }
        if config.experience.enabled(AuthExperienceCapability::SignIn) {
            routes.push(Self::new(
                "/auth/providers",
                &[Get],
                AuthOperation::Providers,
                false,
                AuthFeature::Login,
            ));
        }
        routes.extend([
            // The boundary's own authority question, asked over HTTP: the
            // answer is derived server-side, never supplied by the caller.
            Self::new(
                "/auth/authorize",
                &[Post],
                AuthOperation::Authorize,
                true,
                AuthFeature::Sessions,
            ),
            Self::new(
                "/_authboundry/policies",
                &[Get],
                AuthOperation::Policies,
                true,
                AuthFeature::ControlPlane,
            ),
            Self::new(
                "/_authboundry/authorization/decisions",
                &[Get],
                AuthOperation::AuthorizationDecisions,
                true,
                AuthFeature::ControlPlane,
            ),
            Self::new(
                "/_authboundry/authorization/explain",
                &[Get],
                AuthOperation::AuthorizationExplain,
                true,
                AuthFeature::ControlPlane,
            ),
        ]);

        if features.account_linking
            && config
                .experience
                .enabled(AuthExperienceCapability::AccountLinking)
        {
            routes.push(Self::new(
                "/auth/account/links",
                &[Get, Post, Delete],
                AuthOperation::AccountLinks,
                true,
                AuthFeature::AccountLinking,
            ));
        }

        if features.tenants
            && config
                .experience
                .enabled(AuthExperienceCapability::TenantSwitching)
        {
            routes.push(Self::new(
                "/auth/tenant",
                &[Get],
                AuthOperation::CurrentTenant,
                true,
                AuthFeature::Tenants,
            ));
            routes.push(Self::new(
                "/auth/tenants",
                &[Get],
                AuthOperation::Tenants,
                true,
                AuthFeature::Tenants,
            ));
        }

        if features.agents {
            routes.push(Self::new(
                "/auth/agents",
                &[Get, Post, Delete],
                AuthOperation::Agents,
                true,
                AuthFeature::Agents,
            ));
        }

        if features.delegation {
            routes.push(Self::new(
                "/auth/delegations",
                &[Get, Post, Delete],
                AuthOperation::Delegations,
                true,
                AuthFeature::Delegation,
            ));
        }

        routes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Get,
    Post,
    Delete,
}

impl AuthMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "DELETE" => Some(Self::Delete),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOperation {
    Login,
    Signup,
    PasswordChange,
    PasswordForgot,
    PasswordReset,
    PasswordPolicy,
    Logout,
    Session,
    Sessions,
    Profile,
    Devices,
    EmailVerification,
    Mfa,
    Passkeys,
    Recovery,
    Providers,
    Authorize,
    Policies,
    AuthorizationDecisions,
    AuthorizationExplain,
    AccountLinks,
    CurrentTenant,
    Tenants,
    Agents,
    Delegations,
}

impl AuthOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Signup => "signup",
            Self::PasswordChange => "password_change",
            Self::PasswordForgot => "password_forgot",
            Self::PasswordReset => "password_reset",
            Self::PasswordPolicy => "password_policy",
            Self::Logout => "logout",
            Self::Session => "session",
            Self::Sessions => "sessions",
            Self::Profile => "profile",
            Self::Devices => "devices",
            Self::EmailVerification => "email_verification",
            Self::Mfa => "mfa",
            Self::Passkeys => "passkeys",
            Self::Recovery => "recovery",
            Self::Providers => "providers",
            Self::Authorize => "authorize",
            Self::Policies => "policies",
            Self::AuthorizationDecisions => "authorization_decisions",
            Self::AuthorizationExplain => "authorization_explain",
            Self::AccountLinks => "account_links",
            Self::CurrentTenant => "current_tenant",
            Self::Tenants => "tenants",
            Self::Agents => "agents",
            Self::Delegations => "delegations",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSurface {
    pub id: String,
    pub display_name: String,
    pub kind: ConnectorKind,
    pub status: ConnectorStatus,
}

impl ProviderSurface {
    fn derive(id: &str) -> Self {
        let metadata = catalog::describe(id);
        Self {
            id: metadata.id,
            display_name: metadata.display_name,
            kind: metadata.kind,
            status: metadata.status,
        }
    }

    /// Only a connector that can actually authenticate is offered to a user.
    pub fn is_actionable(&self) -> bool {
        self.status.is_supported()
    }

    pub fn marker(&self) -> &'static str {
        match self.status {
            ConnectorStatus::Supported => "✓",
            ConnectorStatus::Declared => "○",
            ConnectorStatus::Unknown => "✗",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSurface {
    pub name: String,
    pub kind: ClaimKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthFeatures {
    pub login: bool,
    pub signup: bool,
    pub sessions: bool,
    pub tenants: bool,
    pub account_linking: bool,
    pub profile: bool,
    pub devices: bool,
    pub email_verification: bool,
    pub mfa: bool,
    pub passkeys: bool,
    pub recovery: bool,
    pub agents: bool,
    pub delegation: bool,
    pub control_plane: bool,
}

impl AuthFeatures {
    fn derive(config: &AuthConfig) -> Self {
        Self {
            login: true,
            signup: true,
            sessions: true,
            tenants: config.multi_tenant,
            // Linking only means something once a principal can hold more than
            // one external identity.
            account_linking: config.providers.len() > 1,
            profile: config.experience.enabled(AuthExperienceCapability::Profile),
            devices: config
                .experience
                .enabled(AuthExperienceCapability::DeviceManagement),
            email_verification: config
                .experience
                .enabled(AuthExperienceCapability::EmailVerification),
            mfa: config.experience.enabled(AuthExperienceCapability::Mfa),
            passkeys: config
                .experience
                .enabled(AuthExperienceCapability::Passkeys),
            recovery: config
                .experience
                .enabled(AuthExperienceCapability::Recovery),
            agents: config.agents,
            delegation: config.agents,
            control_plane: true,
        }
    }

    pub fn enabled(&self, feature: AuthFeature) -> bool {
        match feature {
            AuthFeature::Login => self.login,
            AuthFeature::Signup => self.signup,
            AuthFeature::Sessions => self.sessions,
            AuthFeature::Tenants => self.tenants,
            AuthFeature::AccountLinking => self.account_linking,
            AuthFeature::Profile => self.profile,
            AuthFeature::Devices => self.devices,
            AuthFeature::EmailVerification => self.email_verification,
            AuthFeature::Mfa => self.mfa,
            AuthFeature::Passkeys => self.passkeys,
            AuthFeature::Recovery => self.recovery,
            AuthFeature::Agents => self.agents,
            AuthFeature::Delegation => self.delegation,
            AuthFeature::ControlPlane => self.control_plane,
        }
    }

    pub fn all() -> [AuthFeature; 14] {
        [
            AuthFeature::Login,
            AuthFeature::Signup,
            AuthFeature::Sessions,
            AuthFeature::Tenants,
            AuthFeature::AccountLinking,
            AuthFeature::Profile,
            AuthFeature::Devices,
            AuthFeature::EmailVerification,
            AuthFeature::Mfa,
            AuthFeature::Passkeys,
            AuthFeature::Recovery,
            AuthFeature::Agents,
            AuthFeature::Delegation,
            AuthFeature::ControlPlane,
        ]
    }

    fn canonical_string(&self) -> String {
        Self::all()
            .iter()
            .map(|feature| format!("{}={};", feature.as_str(), self.enabled(*feature)))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFeature {
    Login,
    Signup,
    Sessions,
    Tenants,
    AccountLinking,
    Profile,
    Devices,
    EmailVerification,
    Mfa,
    Passkeys,
    Recovery,
    Agents,
    Delegation,
    ControlPlane,
}

impl AuthFeature {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Signup => "signup",
            Self::Sessions => "sessions",
            Self::Tenants => "tenants",
            Self::AccountLinking => "account_linking",
            Self::Profile => "profile",
            Self::Devices => "devices",
            Self::EmailVerification => "email_verification",
            Self::Mfa => "mfa",
            Self::Passkeys => "passkeys",
            Self::Recovery => "recovery",
            Self::Agents => "agents",
            Self::Delegation => "delegation",
            Self::ControlPlane => "control_plane",
        }
    }
}

/// Principal kinds the *surface* admits.
///
/// The runtime always models human, agent and service as distinct principal
/// kinds; a declaration without `agents` simply never exposes agent principals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalSurfaceKind {
    Human,
    Agent,
    Service,
}

impl PrincipalSurfaceKind {
    fn derive(features: &AuthFeatures) -> Vec<Self> {
        let mut kinds = vec![Self::Human];
        if features.agents {
            kinds.push(Self::Agent);
        }
        kinds.push(Self::Service);
        kinds
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

/// Agent lifecycle and delegation, derived only when `agents = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSurface {
    pub operations: Vec<AgentOperation>,
}

impl AgentSurface {
    fn derive() -> Self {
        Self {
            operations: vec![
                AgentOperation::CreateAgent,
                AgentOperation::DescribeAgent,
                AgentOperation::ListAgents,
                AgentOperation::SuspendAgent,
                AgentOperation::RevokeAgent,
                AgentOperation::CreateDelegation,
                AgentOperation::ListDelegations,
                AgentOperation::RevokeDelegation,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOperation {
    CreateAgent,
    DescribeAgent,
    ListAgents,
    SuspendAgent,
    RevokeAgent,
    CreateDelegation,
    ListDelegations,
    RevokeDelegation,
}

impl AgentOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateAgent => "agent.create",
            Self::DescribeAgent => "agent.describe",
            Self::ListAgents => "agent.list",
            Self::SuspendAgent => "agent.suspend",
            Self::RevokeAgent => "agent.revoke",
            Self::CreateDelegation => "delegation.create",
            Self::ListDelegations => "delegation.list",
            Self::RevokeDelegation => "delegation.revoke",
        }
    }
}

/// Canonical registry entry shared by runtime, generated UI, embedded clients,
/// headless APIs, Studio and docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExperienceSurface {
    pub id: AuthExperienceCapability,
    pub purpose: String,
    pub required_capabilities: Vec<AuthExperienceCapability>,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub required_assurance: AuthenticationAssurance,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub state: ExperienceState,
    pub operation: Option<AuthOperation>,
}

impl ExperienceSurface {
    fn derive_all(config: &AuthConfig, features: &AuthFeatures) -> Vec<Self> {
        AuthExperienceCapability::all()
            .into_iter()
            .filter(|capability| match capability {
                AuthExperienceCapability::TenantSwitching => features.tenants,
                AuthExperienceCapability::AccountLinking => features.account_linking,
                _ => true,
            })
            .map(|capability| Self::derive(config, capability))
            .collect()
    }

    fn derive(config: &AuthConfig, id: AuthExperienceCapability) -> Self {
        let state = config.experience.state(id);
        let (purpose, methods, assurance, inputs, outputs, operation) = match id {
            AuthExperienceCapability::SignIn => (
                "authenticate a principal and open a session",
                vec![
                    AuthenticationMethod::Password,
                    AuthenticationMethod::ExternalIdentity,
                ],
                AuthenticationAssurance::Basic,
                vec!["tenant_hint", "provider", "credential"],
                vec!["principal", "session", "authentication_assurance"],
                Some(AuthOperation::Login),
            ),
            AuthExperienceCapability::SignUp => (
                "register an identity through the authoritative runtime",
                vec![
                    AuthenticationMethod::Password,
                    AuthenticationMethod::ExternalIdentity,
                ],
                AuthenticationAssurance::Basic,
                vec!["tenant_hint", "provider", "credential"],
                vec!["principal", "session"],
                Some(AuthOperation::Signup),
            ),
            AuthExperienceCapability::SignOut => (
                "revoke the current session",
                Vec::new(),
                AuthenticationAssurance::Basic,
                vec!["session"],
                vec!["session_revoked"],
                Some(AuthOperation::Logout),
            ),
            AuthExperienceCapability::Password => (
                "password authentication capability",
                vec![AuthenticationMethod::Password],
                AuthenticationAssurance::Basic,
                vec!["username", "password"],
                vec!["authentication_result"],
                None,
            ),
            AuthExperienceCapability::PasswordReset => (
                "recover access through a password reset ceremony",
                vec![AuthenticationMethod::Recovery],
                AuthenticationAssurance::Basic,
                vec!["principal_hint"],
                vec!["recovery_ceremony"],
                Some(AuthOperation::PasswordReset),
            ),
            AuthExperienceCapability::PasswordChange => (
                "change a known password through the public protocol",
                vec![AuthenticationMethod::Password],
                AuthenticationAssurance::Basic,
                vec!["current_password", "new_password"],
                vec!["password_changed"],
                Some(AuthOperation::PasswordChange),
            ),
            AuthExperienceCapability::ExternalIdentity => (
                "verify an identity through an external provider",
                vec![AuthenticationMethod::ExternalIdentity],
                AuthenticationAssurance::Basic,
                vec!["provider", "provider_response"],
                vec!["external_identity"],
                Some(AuthOperation::Providers),
            ),
            AuthExperienceCapability::AccountLinking => (
                "link another verified external identity to the same principal",
                vec![AuthenticationMethod::ExternalIdentity],
                AuthenticationAssurance::Basic,
                vec!["session", "provider_response"],
                vec!["identity_link"],
                Some(AuthOperation::AccountLinks),
            ),
            AuthExperienceCapability::EmailVerification => (
                "verify an email identity",
                vec![AuthenticationMethod::ExternalIdentity],
                AuthenticationAssurance::Basic,
                vec!["email", "verification_response"],
                vec!["verified_identity"],
                Some(AuthOperation::EmailVerification),
            ),
            AuthExperienceCapability::Mfa => (
                "perform or enroll a multi-factor authentication method",
                vec![AuthenticationMethod::Mfa],
                AuthenticationAssurance::Strong,
                vec!["session", "challenge_response"],
                vec!["authentication_assurance"],
                Some(AuthOperation::Mfa),
            ),
            AuthExperienceCapability::Passkeys => (
                "perform a passkey ceremony",
                vec![AuthenticationMethod::Passkey],
                AuthenticationAssurance::PhishingResistant,
                vec!["principal_hint", "ceremony_response"],
                vec!["authentication_result"],
                Some(AuthOperation::Passkeys),
            ),
            AuthExperienceCapability::DeviceManagement => (
                "manage authenticating devices without granting principal authority",
                vec![AuthenticationMethod::DeviceApproval],
                AuthenticationAssurance::Strong,
                vec!["session", "device"],
                vec!["device"],
                Some(AuthOperation::Devices),
            ),
            AuthExperienceCapability::SessionManagement => (
                "inspect or revoke sessions through public protocol APIs",
                Vec::new(),
                AuthenticationAssurance::Basic,
                vec!["session"],
                vec!["session"],
                Some(AuthOperation::Sessions),
            ),
            AuthExperienceCapability::Profile => (
                "read AuthBoundry identity profile data, not application domain profile data",
                Vec::new(),
                AuthenticationAssurance::Basic,
                vec!["session"],
                vec!["authboundry_identity_profile", "application_profile_ref"],
                Some(AuthOperation::Profile),
            ),
            AuthExperienceCapability::TenantSwitching => (
                "select among tenant identities authorized by AuthBoundry",
                Vec::new(),
                AuthenticationAssurance::Basic,
                vec!["session"],
                vec!["tenant"],
                Some(AuthOperation::Tenants),
            ),
            AuthExperienceCapability::Recovery => (
                "recover an account through a recovery ceremony independent of password reset",
                vec![AuthenticationMethod::Recovery],
                AuthenticationAssurance::Basic,
                vec!["principal_hint", "recovery_method"],
                vec!["recovery_ceremony"],
                Some(AuthOperation::Recovery),
            ),
        };
        Self {
            id,
            purpose: purpose.to_string(),
            required_capabilities: vec![id],
            authentication_methods: methods,
            required_assurance: assurance,
            inputs: inputs.into_iter().map(str::to_string).collect(),
            outputs: outputs.into_iter().map(str::to_string).collect(),
            state,
            operation,
        }
    }

    fn canonical_string(&self) -> String {
        let methods = self
            .authentication_methods
            .iter()
            .map(|method| method.as_str())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "experience={}:{}:{}:{};",
            self.id.as_str(),
            self.state.as_str(),
            self.required_assurance.as_str(),
            methods
        )
    }
}

/// The default UI, generated from the same contract as the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUiSurface {
    pub renderer: ExperienceRenderer,
    pub mode: AuthUiMode,
    pub theme: String,
    pub screens: Vec<UiScreenSurface>,
}

impl AuthUiSurface {
    fn derive(config: &AuthConfig, features: &AuthFeatures) -> Self {
        let mut screens = vec![
            UiScreenSurface::derive(config, UiScreen::Login),
            UiScreenSurface::derive(config, UiScreen::Signup),
            UiScreenSurface::derive(config, UiScreen::Account),
        ];
        if features.tenants {
            screens.push(UiScreenSurface::derive(config, UiScreen::Tenant));
        }
        if features.agents {
            screens.push(UiScreenSurface::derive(config, UiScreen::Agents));
        }

        Self {
            renderer: config.ui.renderer,
            mode: config.ui.mode.clone(),
            theme: config.ui.theme.name.clone(),
            screens,
        }
    }

    pub fn screen(&self, screen: UiScreen) -> Option<&UiScreenSurface> {
        self.screens.iter().find(|entry| entry.screen == screen)
    }

    fn canonical_string(&self) -> String {
        let mut out = format!(
            "ui={};{};{};",
            self.renderer.as_str(),
            self.mode.as_str(),
            self.theme
        );
        for screen in &self.screens {
            out.push_str(&format!(
                "{}:{}:",
                screen.screen.as_str(),
                screen.mode.as_str()
            ));
            for provider in &screen.providers {
                out.push_str(provider);
                out.push(',');
            }
            out.push(';');
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiScreenSurface {
    pub screen: UiScreen,
    pub mode: AuthUiMode,
    /// Provider buttons the default UI renders. Derived from the declaration,
    /// so a declared-but-unimplemented connector is never offered as a button.
    pub providers: Vec<String>,
}

impl UiScreenSurface {
    fn derive(config: &AuthConfig, screen: UiScreen) -> Self {
        let providers = match screen {
            UiScreen::Login | UiScreen::Signup | UiScreen::Account => config
                .providers
                .iter()
                .filter(|provider| catalog::describe(provider).status.is_supported())
                .cloned()
                .collect(),
            UiScreen::Tenant | UiScreen::Agents => Vec::new(),
        };

        Self {
            screen: screen.clone(),
            mode: config.ui.mode_for(screen),
            providers,
        }
    }
}

/// The runtime boundary the contract can be executed behind.
///
/// Embedded and standalone are two placements of one authority model, so this
/// is derived from the contract rather than configured per deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundarySurface {
    pub contract: String,
    pub modes: Vec<BindingModeSurface>,
    pub session_credential: String,
}

impl BoundarySurface {
    pub const CONTRACT: &'static str = "authboundry.boundary/v1";
    /// The cookie the boundary issues and reads. It is an opaque server-issued
    /// handle: nothing inside it is trusted without being re-verified.
    pub const SESSION_COOKIE: &'static str = "authboundry_session";

    fn derive() -> Self {
        Self {
            contract: Self::CONTRACT.to_string(),
            modes: vec![BindingModeSurface::Embedded, BindingModeSurface::Standalone],
            session_credential: format!("cookie:{}", Self::SESSION_COOKIE),
        }
    }

    fn canonical_string(&self) -> String {
        let modes = self
            .modes
            .iter()
            .map(|mode| mode.as_str())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "boundary={};{};{};",
            self.contract, modes, self.session_credential
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingModeSurface {
    Embedded,
    Standalone,
}

impl BindingModeSurface {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Standalone => "standalone",
        }
    }
}
