use appport_auth_mesh_dsl::{
    stable_hash, AuthConfig, AuthUiMode, ClaimKind, IsolationMode, UiScreen,
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
    pub providers: Vec<ProviderSurface>,
    pub features: AuthFeatures,
    pub claims: Vec<ClaimSurface>,
    pub principals: Vec<PrincipalSurfaceKind>,
    pub agents: Option<AgentSurface>,
    pub ui: AuthUiSurface,
    pub multi_tenant: bool,
    pub isolation: IsolationMode,
    pub contract_fingerprint: String,
}

impl AuthSurface {
    pub fn derive(config: &AuthConfig) -> Self {
        let config = config.canonical();
        let features = AuthFeatures::derive(&config);

        Self {
            routes: AuthRoute::derive(&features),
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
            multi_tenant: config.multi_tenant,
            isolation: config.isolation.clone(),
            contract_fingerprint: config.fingerprint(),
            features,
        }
    }

    pub fn route(&self, path: &str) -> Option<&AuthRoute> {
        self.routes.iter().find(|route| route.path == path)
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
        format!("{:016x}", stable_hash(material.as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRoute {
    pub path: String,
    pub methods: Vec<AuthMethod>,
    pub operation: AuthOperation,
    pub requires_session: bool,
    pub feature: AuthFeature,
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
            methods: methods.to_vec(),
            operation,
            requires_session,
            feature,
        }
    }

    fn derive(features: &AuthFeatures) -> Vec<Self> {
        use AuthMethod::{Delete, Get, Post};

        let mut routes = vec![
            Self::new(
                "/auth/login",
                &[Post],
                AuthOperation::Login,
                false,
                AuthFeature::Login,
            ),
            Self::new(
                "/auth/signup",
                &[Post],
                AuthOperation::Signup,
                false,
                AuthFeature::Signup,
            ),
            Self::new(
                "/auth/logout",
                &[Post],
                AuthOperation::Logout,
                true,
                AuthFeature::Sessions,
            ),
            Self::new(
                "/auth/session",
                &[Get, Delete],
                AuthOperation::Session,
                true,
                AuthFeature::Sessions,
            ),
            Self::new(
                "/auth/providers",
                &[Get],
                AuthOperation::Providers,
                false,
                AuthFeature::Login,
            ),
        ];

        if features.account_linking {
            routes.push(Self::new(
                "/auth/account/links",
                &[Get, Post, Delete],
                AuthOperation::AccountLinks,
                true,
                AuthFeature::AccountLinking,
            ));
        }

        if features.tenants {
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
    Logout,
    Session,
    Providers,
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
            Self::Logout => "logout",
            Self::Session => "session",
            Self::Providers => "providers",
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
    pub agents: bool,
    pub delegation: bool,
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
            agents: config.agents,
            delegation: config.agents,
        }
    }

    pub fn enabled(&self, feature: AuthFeature) -> bool {
        match feature {
            AuthFeature::Login => self.login,
            AuthFeature::Signup => self.signup,
            AuthFeature::Sessions => self.sessions,
            AuthFeature::Tenants => self.tenants,
            AuthFeature::AccountLinking => self.account_linking,
            AuthFeature::Agents => self.agents,
            AuthFeature::Delegation => self.delegation,
        }
    }

    pub fn all() -> [AuthFeature; 7] {
        [
            AuthFeature::Login,
            AuthFeature::Signup,
            AuthFeature::Sessions,
            AuthFeature::Tenants,
            AuthFeature::AccountLinking,
            AuthFeature::Agents,
            AuthFeature::Delegation,
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
    Agents,
    Delegation,
}

impl AuthFeature {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Signup => "signup",
            Self::Sessions => "sessions",
            Self::Tenants => "tenants",
            Self::AccountLinking => "account_linking",
            Self::Agents => "agents",
            Self::Delegation => "delegation",
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

/// The default UI, generated from the same contract as the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUiSurface {
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
            mode: config.ui.mode.clone(),
            theme: config.ui.theme.name.clone(),
            screens,
        }
    }

    pub fn screen(&self, screen: UiScreen) -> Option<&UiScreenSurface> {
        self.screens.iter().find(|entry| entry.screen == screen)
    }

    fn canonical_string(&self) -> String {
        let mut out = format!("ui={};{};", self.mode.as_str(), self.theme);
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
