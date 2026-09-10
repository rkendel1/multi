use std::collections::HashSet;

/// The declarative auth contract for an application.
///
/// This is what `use auth { ... }` produces. It describes *what* identity and
/// authority the application needs, never *how* authentication is implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub multi_tenant: bool,
    pub providers: Vec<String>,
    pub claims: Vec<ClaimDef>,
    pub isolation: IsolationMode,
    pub agents: bool,
    pub policies: Vec<PolicyDef>,
    pub ui: AuthUiConfig,
    pub password_policy: PasswordPolicy,
    pub storage: StorageConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            multi_tenant: false,
            providers: Vec::new(),
            claims: Vec::new(),
            isolation: IsolationMode::Strict,
            agents: false,
            policies: Vec::new(),
            ui: AuthUiConfig::default(),
            password_policy: PasswordPolicy::default(),
            storage: StorageConfig::default(),
        }
    }
}

impl AuthConfig {
    /// Canonical form: semantically identical declarations converge here.
    pub fn canonical(&self) -> Self {
        let mut providers = self.providers.clone();
        providers.sort();

        let mut claims = self.claims.clone();
        claims.sort_by(|a, b| a.name.cmp(&b.name));
        for claim in &mut claims {
            if let ClaimKind::Enum(values) = &mut claim.kind {
                values.sort();
            }
        }
        let mut policies = self.policies.clone();
        policies.sort_by(|a, b| a.capability.cmp(&b.capability));

        Self {
            multi_tenant: self.multi_tenant,
            providers,
            claims,
            isolation: self.isolation.clone(),
            agents: self.agents,
            policies,
            ui: self.ui.canonical(),
            password_policy: self.password_policy.clone(),
            storage: self.storage.clone(),
        }
    }

    pub fn fingerprint(&self) -> String {
        let canonical = self.canonical();
        let mut bytes = Vec::new();
        canonical.write_canonical(&mut bytes);
        format!("{:016x}", stable_hash(&bytes))
    }

    pub fn claim(&self, name: &str) -> Option<&ClaimDef> {
        self.claims.iter().find(|claim| claim.name == name)
    }

    pub fn declares_provider(&self, name: &str) -> bool {
        self.providers.iter().any(|provider| provider == name)
    }

    pub fn validate(&self) -> Result<(), AuthConfigError> {
        if self.providers.is_empty() {
            return Err(AuthConfigError {
                message: "missing providers".to_string(),
            });
        }

        reject_duplicates(&self.providers, "duplicate provider")?;

        for provider in &self.providers {
            if provider.trim().is_empty() {
                return Err(AuthConfigError {
                    message: "provider name cannot be empty".to_string(),
                });
            }
        }

        let mut claim_names = HashSet::new();
        for claim in &self.claims {
            if claim.name.trim().is_empty() {
                return Err(AuthConfigError {
                    message: "claim name cannot be empty".to_string(),
                });
            }
            if !claim_names.insert(claim.name.clone()) {
                return Err(AuthConfigError {
                    message: format!("duplicate claim `{}`", claim.name),
                });
            }
            if let ClaimKind::Enum(values) = &claim.kind {
                if values.is_empty() {
                    return Err(AuthConfigError {
                        message: format!("enum claim `{}` must have values", claim.name),
                    });
                }
                reject_duplicates(values, "duplicate enum value")?;
            }
        }

        let mut policy_names = HashSet::new();
        for policy in &self.policies {
            if policy.capability.trim().is_empty() {
                return Err(AuthConfigError {
                    message: "policy capability cannot be empty".to_string(),
                });
            }
            if !policy_names.insert(policy.capability.clone()) {
                return Err(AuthConfigError {
                    message: format!("duplicate policy `{}`", policy.capability),
                });
            }
        }

        self.ui.validate()?;
        self.password_policy.validate()?;
        self.storage.validate()?;

        Ok(())
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(format!("multi_tenant={};", self.multi_tenant).as_bytes());
        out.extend_from_slice(b"providers=");
        for provider in &self.providers {
            out.extend_from_slice(provider.as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(format!(";isolation={:?};claims=", self.isolation).as_bytes());
        for claim in &self.claims {
            out.extend_from_slice(claim.name.as_bytes());
            out.push(b':');
            match &claim.kind {
                ClaimKind::Enum(values) => {
                    out.extend_from_slice(b"enum[");
                    for value in values {
                        out.extend_from_slice(value.as_bytes());
                        out.push(b',');
                    }
                    out.push(b']');
                }
                ClaimKind::String => out.extend_from_slice(b"string"),
                ClaimKind::Integer => out.extend_from_slice(b"integer"),
                ClaimKind::Boolean => out.extend_from_slice(b"boolean"),
            }
            out.push(b';');
        }
        out.extend_from_slice(format!("agents={};", self.agents).as_bytes());
        out.extend_from_slice(b"policies=");
        for policy in &self.policies {
            out.extend_from_slice(policy.capability.as_bytes());
            out.push(b':');
            if policy.tenant_current {
                out.extend_from_slice(b"tenant=current;");
            }
            if let Some(resource) = &policy.resource {
                out.extend_from_slice(format!("resource={};", resource).as_bytes());
            }
            if let Some(action) = &policy.action {
                out.extend_from_slice(format!("action={};", action).as_bytes());
            }
            for condition in &policy.claims {
                out.extend_from_slice(condition.claim.as_bytes());
                out.push(b'=');
                for value in &condition.values {
                    out.extend_from_slice(value.as_bytes());
                    out.push(b',');
                }
                out.push(b';');
            }
        }
        self.ui.write_canonical(out);
        self.password_policy.write_canonical(out);
        self.storage.write_canonical(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfig {
    pub authority: String,
    pub audit: String,
    pub reporting: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            authority: "feltdb".to_string(),
            audit: "feltdb".to_string(),
            reporting: "authport_projection".to_string(),
        }
    }
}

impl StorageConfig {
    pub fn validate(&self) -> Result<(), AuthConfigError> {
        for (name, value) in [
            ("authority", &self.authority),
            ("audit", &self.audit),
            ("reporting", &self.reporting),
        ] {
            if value.trim().is_empty() {
                return Err(AuthConfigError {
                    message: format!("storage {} provider cannot be empty", name),
                });
            }
            if value.contains("://") || value.contains('@') {
                return Err(AuthConfigError {
                    message: format!(
                        "storage {} declares provider capability only, not credentials",
                        name
                    ),
                });
            }
        }
        Ok(())
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(
            format!(
                "storage=authority:{},audit:{},reporting:{};",
                self.authority, self.audit, self.reporting
            )
            .as_bytes(),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfigError {
    pub message: String,
}

impl std::fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthConfigError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClaimDef {
    pub name: String,
    pub kind: ClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimKind {
    Enum(Vec<String>),
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyDef {
    pub capability: String,
    pub tenant_current: bool,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub claims: Vec<PolicyClaimCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyClaimCondition {
    pub claim: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_number: bool,
    pub require_special_character: bool,
    pub password_expiration_days: Option<u32>,
    pub password_history_count: usize,
    pub allow_password_change: bool,
    pub allow_password_reset: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_number: false,
            require_special_character: false,
            password_expiration_days: None,
            password_history_count: 5,
            allow_password_change: true,
            allow_password_reset: true,
        }
    }
}

impl PasswordPolicy {
    pub fn validate(&self) -> Result<(), AuthConfigError> {
        if self.min_length == 0 {
            return Err(AuthConfigError {
                message: "password min_length must be at least 1".to_string(),
            });
        }
        if self.max_length < self.min_length {
            return Err(AuthConfigError {
                message: "password max_length must be greater than or equal to min_length"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub fn revision_fingerprint(&self) -> String {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes);
        format!("{:016x}", stable_hash(&bytes))
    }

    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(
            format!(
                "pwd_policy=min:{};max:{};upper:{};lower:{};number:{};special:{};expiration:{};history:{};change:{};reset:{};",
                self.min_length,
                self.max_length,
                self.require_uppercase,
                self.require_lowercase,
                self.require_number,
                self.require_special_character,
                self.password_expiration_days
                    .map(|days| days.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                self.password_history_count,
                self.allow_password_change,
                self.allow_password_reset
            )
            .as_bytes(),
        );
    }
}

impl ClaimKind {
    pub fn describe(&self) -> String {
        match self {
            Self::Enum(values) => values.join(" | "),
            Self::String => "string".to_string(),
            Self::Integer => "integer".to_string(),
            Self::Boolean => "boolean".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationMode {
    Strict,
    SharedStorageWithPolicy,
}

impl IsolationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::SharedStorageWithPolicy => "shared_storage_with_policy",
        }
    }
}

/// UI is an output of the auth contract, not a separately maintained surface.
///
/// The default requires zero configuration; customization narrows individual
/// screens without replacing the identity model underneath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUiConfig {
    pub mode: AuthUiMode,
    pub theme: UiTheme,
    pub screens: Vec<UiScreenOverride>,
}

impl Default for AuthUiConfig {
    fn default() -> Self {
        Self {
            mode: AuthUiMode::Default,
            theme: UiTheme::default(),
            screens: Vec::new(),
        }
    }
}

impl AuthUiConfig {
    pub fn canonical(&self) -> Self {
        let mut screens = self.screens.clone();
        screens.sort();
        screens.dedup();
        let mode = if screens
            .iter()
            .any(|screen| screen.mode == AuthUiMode::Custom)
        {
            AuthUiMode::Custom
        } else {
            AuthUiMode::Default
        };
        Self {
            mode,
            theme: self.theme.clone(),
            screens,
        }
    }

    pub fn mode_for(&self, screen: UiScreen) -> AuthUiMode {
        self.screens
            .iter()
            .find(|override_| override_.screen == screen)
            .map(|override_| override_.mode.clone())
            .unwrap_or(AuthUiMode::Default)
    }

    pub fn validate(&self) -> Result<(), AuthConfigError> {
        let mut seen = HashSet::new();
        for override_ in &self.screens {
            if !seen.insert(override_.screen.clone()) {
                return Err(AuthConfigError {
                    message: format!("duplicate ui screen `{}`", override_.screen.as_str()),
                });
            }
        }
        if self.theme.name.trim().is_empty() {
            return Err(AuthConfigError {
                message: "ui theme cannot be empty".to_string(),
            });
        }
        Ok(())
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(
            format!(
                "ui=mode:{};theme:{};screens:",
                self.mode.as_str(),
                self.theme.name
            )
            .as_bytes(),
        );
        for override_ in &self.screens {
            out.extend_from_slice(override_.screen.as_str().as_bytes());
            out.push(b'=');
            out.extend_from_slice(override_.mode.as_str().as_bytes());
            out.push(b',');
        }
        out.push(b';');
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthUiMode {
    Default,
    Custom,
}

impl AuthUiMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UiTheme {
    pub name: String,
}

impl Default for UiTheme {
    fn default() -> Self {
        Self {
            name: "authport-default".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UiScreenOverride {
    pub screen: UiScreen,
    pub mode: AuthUiMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UiScreen {
    Login,
    Signup,
    Account,
    Tenant,
    Agents,
}

impl UiScreen {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Signup => "signup",
            Self::Account => "account",
            Self::Tenant => "tenant",
            Self::Agents => "agents",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "login" => Some(Self::Login),
            "signup" => Some(Self::Signup),
            "account" => Some(Self::Account),
            "tenant" => Some(Self::Tenant),
            "agents" => Some(Self::Agents),
            _ => None,
        }
    }
}

fn reject_duplicates(values: &[String], message: &str) -> Result<(), AuthConfigError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(AuthConfigError {
                message: format!("{} `{}`", message, value),
            });
        }
    }
    Ok(())
}

/// FNV-1a. Stable across processes and platforms, which is what contract
/// fingerprints require; it is not a security primitive.
pub fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
