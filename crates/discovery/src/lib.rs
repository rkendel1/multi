//! Framework-neutral application discovery for AuthPort adoption.
//!
//! Discovery is intentionally read-only: it inspects manifests and likely
//! entrypoints, but never runs package scripts or binaries.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationCandidate {
    pub root: PathBuf,
    pub name: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub package_manager: Option<String>,
    pub entrypoints: Vec<EntrypointCandidate>,
    pub servers: Vec<ServerCandidate>,
    pub routes: Vec<RouteCandidate>,
    pub providers: Vec<ProviderCandidate>,
    pub existing_authport: ExistingAuthPort,
    pub confidence: DiscoveryConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrypointCandidate {
    pub path: PathBuf,
    pub kind: EntrypointKind,
    pub confidence: DiscoveryConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrypointKind {
    NodeScript,
    RustBinary,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCandidate {
    pub command: String,
    pub source: String,
    pub confidence: DiscoveryConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteCandidate {
    pub method: String,
    pub path: String,
    pub source: RouteSource,
    pub capability: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteSource {
    Express,
    Embedded,
    Standalone,
    Rust,
    Unknown,
}

impl RouteSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Express => "express",
            Self::Embedded => "embedded",
            Self::Standalone => "standalone",
            Self::Rust => "rust",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceKind {
    Capability,
}

impl InferenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inference {
    pub kind: InferenceKind,
    pub capability: String,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionState {
    Public,
    Protected,
    Unprotected,
}

impl ProtectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Protected => "protected",
            Self::Unprotected => "unprotected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDescription {
    pub id: String,
    pub method: String,
    pub path: String,
    pub source: RouteSource,
    pub capability: Option<String>,
    pub inference: Option<Inference>,
    pub protection: ProtectionState,
    pub protection_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRecommendation {
    pub method: String,
    pub path: String,
    pub action: RecommendationAction,
    pub capability: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationAction {
    NoChange,
    ProtectRoute,
}

impl RecommendationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoChange => "no_change",
            Self::ProtectRoute => "protect_route",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProposal {
    pub application: String,
    pub contract_fingerprint: String,
    pub live_revision: u64,
    pub routes: Vec<RouteDescription>,
    pub inferences: Vec<Inference>,
    pub recommendations: Vec<AuthorityRecommendation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCandidate {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryConfidence {
    Low,
    Medium,
    High,
}

impl DiscoveryConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExistingAuthPort {
    pub dependency: bool,
    pub initialization: bool,
    pub middleware: bool,
    pub configuration: bool,
    pub manifest: bool,
}

impl ExistingAuthPort {
    pub fn detected(&self) -> bool {
        self.dependency
            || self.initialization
            || self.middleware
            || self.configuration
            || self.manifest
    }
}

pub fn discover(root: impl AsRef<Path>) -> Option<ApplicationCandidate> {
    let root = root.as_ref();
    discover_node(root).or_else(|| discover_rust(root))
}

pub fn propose_authority(
    application: &ApplicationCandidate,
    contract_fingerprint: impl Into<String>,
    live_revision: u64,
    existing_mappings: &BTreeMap<(String, String), String>,
) -> AuthorityProposal {
    let mut routes = application
        .routes
        .iter()
        .map(|route| describe_route(route, existing_mappings))
        .collect::<Vec<_>>();
    routes.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.method.cmp(&b.method))
            .then_with(|| a.source.cmp(&b.source))
    });

    let inferences = routes
        .iter()
        .filter_map(|route| route.inference.clone())
        .collect::<Vec<_>>();
    let recommendations = routes
        .iter()
        .map(|route| {
            let action = if route.protection == ProtectionState::Unprotected
                && route.capability.is_none()
                && route
                    .inference
                    .as_ref()
                    .map(|inference| inference.confidence != Confidence::Unknown)
                    .unwrap_or(false)
                && route.method != "GET"
            {
                RecommendationAction::ProtectRoute
            } else {
                RecommendationAction::NoChange
            };
            AuthorityRecommendation {
                method: route.method.clone(),
                path: route.path.clone(),
                action,
                capability: route
                    .capability
                    .clone()
                    .or_else(|| route.inference.as_ref().map(|i| i.capability.clone())),
                reason: match action {
                    RecommendationAction::NoChange => {
                        "nothing is applied without approval".to_string()
                    }
                    RecommendationAction::ProtectRoute => {
                        "mutating route has a deterministic capability inference".to_string()
                    }
                },
            }
        })
        .collect::<Vec<_>>();

    AuthorityProposal {
        application: application
            .name
            .clone()
            .unwrap_or_else(|| "application".to_string()),
        contract_fingerprint: contract_fingerprint.into(),
        live_revision,
        routes,
        inferences,
        recommendations,
        warnings: Vec::new(),
    }
}

pub fn render_proposal_text(proposal: &AuthorityProposal) -> String {
    let mut out = String::new();
    out.push_str("AUTHORITY PROPOSAL\n");
    out.push_str(&format!("Application: {}\n", proposal.application));
    out.push_str(&format!("Observed routes: {}\n", proposal.routes.len()));
    out.push_str(&format!(
        "Inferred capabilities: {}\n",
        proposal.inferences.len()
    ));
    out.push_str(&format!(
        "Authority revision: {}\nContract fingerprint: {}\n",
        proposal.live_revision, proposal.contract_fingerprint
    ));

    for confidence in [Confidence::High, Confidence::Medium, Confidence::Low] {
        let matching = proposal
            .routes
            .iter()
            .filter(|route| {
                route
                    .inference
                    .as_ref()
                    .map(|inference| inference.confidence == confidence)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "{} CONFIDENCE\n",
            confidence.as_str().to_ascii_uppercase()
        ));
        for route in matching {
            let inference = route.inference.as_ref().unwrap();
            out.push_str(&format!(
                "{} {}\n  → {}\n",
                route.method, route.path, inference.capability
            ));
            out.push_str("  Reasons:\n");
            for reason in &inference.reasons {
                out.push_str(&format!("    {}\n", reason));
            }
        }
    }

    out.push_str("SAFE DEFAULTS\n");
    for route in &proposal.routes {
        let capability = route
            .capability
            .as_deref()
            .or_else(|| {
                route
                    .inference
                    .as_ref()
                    .map(|inference| inference.capability.as_str())
            })
            .unwrap_or("(none)");
        out.push_str(&format!(
            "{:<6} {:<24} {:<11} {}\n",
            route.method,
            route.path,
            route.protection.as_str(),
            capability
        ));
        out.push_str(&format!("  reason: {}\n", route.protection_reason));
    }

    out.push_str("RECOMMENDED PROTECTION\n");
    for recommendation in proposal
        .recommendations
        .iter()
        .filter(|item| item.action == RecommendationAction::ProtectRoute)
    {
        out.push_str(&format!(
            "{} {} -> {}\n",
            recommendation.method,
            recommendation.path,
            recommendation.capability.as_deref().unwrap_or("(review)")
        ));
    }

    out.push_str("NO CHANGE\n");
    for recommendation in proposal
        .recommendations
        .iter()
        .filter(|item| item.action == RecommendationAction::NoChange)
    {
        out.push_str(&format!(
            "{} {}\n",
            recommendation.method, recommendation.path
        ));
    }
    out.push_str("Nothing has been changed.\n");
    out
}

pub fn render_proposal_json(proposal: &AuthorityProposal) -> String {
    format!(
        "{{\n  \"application\": \"{}\",\n  \"contract_fingerprint\": \"{}\",\n  \"live_revision\": {},\n  \"routes\": [{}],\n  \"inferences\": [{}],\n  \"recommendations\": [{}],\n  \"warnings\": [{}]\n}}\n",
        escape(&proposal.application),
        escape(&proposal.contract_fingerprint),
        proposal.live_revision,
        proposal.routes.iter().map(route_json).collect::<Vec<_>>().join(", "),
        proposal.inferences.iter().map(inference_json).collect::<Vec<_>>().join(", "),
        proposal.recommendations.iter().map(recommendation_json).collect::<Vec<_>>().join(", "),
        proposal.warnings.iter().map(|warning| format!("\"{}\"", escape(warning))).collect::<Vec<_>>().join(", ")
    )
}

fn describe_route(
    route: &RouteCandidate,
    existing_mappings: &BTreeMap<(String, String), String>,
) -> RouteDescription {
    let key = (route.method.clone(), normalize_path(&route.path));
    let existing = existing_mappings.get(&key).cloned();
    let explicit = route.capability.clone();
    let capability = explicit.clone().or(existing);
    let inference = if capability.is_some() {
        None
    } else {
        infer_capability(&route.method, &route.path)
    };
    let (protection, protection_reason) =
        classify_protection(&route.method, &route.path, capability.as_ref());
    RouteDescription {
        id: format!("{} {}", route.method, normalize_path(&route.path)),
        method: route.method.clone(),
        path: normalize_path(&route.path),
        source: route.source,
        capability,
        inference,
        protection,
        protection_reason,
    }
}

pub fn infer_capability(method: &str, path: &str) -> Option<Inference> {
    let method = method.to_ascii_uppercase();
    let normalized = normalize_path(path);
    let segments = path_segments(&normalized);
    if segments.is_empty()
        || matches!(
            segments.first().copied(),
            Some("auth" | "health" | "healthz" | "ready" | "readyz" | "metrics")
        )
    {
        return None;
    }

    let (capability, confidence, mut reasons) = if segments.len() == 1 {
        let resource = segments[0];
        let singular = singular_resource(resource);
        let action = match method.as_str() {
            "GET" => "read",
            "POST" => "create",
            _ => return None,
        };
        let confidence = if is_plural(resource) {
            Confidence::High
        } else {
            Confidence::Low
        };
        (
            format!("{}.{}", singular, action),
            confidence,
            vec![
                format!("method is {}", method),
                format!("resource is {}", resource),
                "route is not parameterized".to_string(),
            ],
        )
    } else if segments.len() == 2 && is_parameter(segments[1]) {
        let resource = segments[0];
        let singular = singular_resource(resource);
        let action = match method.as_str() {
            "GET" => "read",
            "PUT" | "PATCH" => "update",
            "DELETE" => "delete",
            _ => return None,
        };
        (
            format!("{}.{}", singular, action),
            if is_plural(resource) {
                Confidence::High
            } else {
                Confidence::Low
            },
            vec![
                format!("method is {}", method),
                format!("resource is {}", resource),
                "route is parameterized".to_string(),
            ],
        )
    } else if segments.len() == 2 && !is_parameter(segments[0]) && !is_parameter(segments[1]) {
        let confidence = if method == "POST" {
            Confidence::High
        } else {
            Confidence::Medium
        };
        (
            format!("{}.{}", singular_resource(segments[0]), segments[1]),
            confidence,
            vec![
                format!("method is {}", method),
                format!("resource is {}", segments[0]),
                format!("action segment is {}", segments[1]),
            ],
        )
    } else {
        return Some(Inference {
            kind: InferenceKind::Capability,
            capability: format!("{}.review", singular_resource(segments[0])),
            confidence: Confidence::Low,
            reasons: vec!["route shape is ambiguous; review manually".to_string()],
        });
    };

    reasons.push("no explicit capability mapping exists".to_string());
    Some(Inference {
        kind: InferenceKind::Capability,
        capability,
        confidence,
        reasons,
    })
}

pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed == "/" {
        return "/".to_string();
    }
    let parts = trimmed
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .map(|part| {
            if part.starts_with(':')
                || part.starts_with('{') && part.ends_with('}')
                || part.starts_with('[') && part.ends_with(']')
            {
                ":param".to_string()
            } else {
                part.to_ascii_lowercase()
            }
        })
        .collect::<Vec<_>>();
    format!("/{}", parts.join("/"))
}

fn classify_protection(
    method: &str,
    path: &str,
    capability: Option<&String>,
) -> (ProtectionState, String) {
    if capability.is_some() {
        return (
            ProtectionState::Protected,
            "explicit or existing authority mapping".to_string(),
        );
    }
    let normalized = normalize_path(path);
    if matches!(
        normalized.as_str(),
        "/" | "/health" | "/healthz" | "/ready" | "/readyz"
    ) {
        return (
            ProtectionState::Public,
            "recognized safe infrastructure endpoint".to_string(),
        );
    }
    if normalized == "/metrics" {
        return (
            ProtectionState::Public,
            "recognized metrics endpoint".to_string(),
        );
    }
    if normalized == "/auth" || normalized.starts_with("/auth/") {
        return (
            ProtectionState::Public,
            "AuthPort-owned authentication endpoint".to_string(),
        );
    }
    (
        ProtectionState::Unprotected,
        if method.eq_ignore_ascii_case("GET") {
            "application route remains behaviorally compatible until approved".to_string()
        } else {
            "mutating application endpoint; protection is recommended, not applied".to_string()
        },
    )
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect()
}

fn is_parameter(segment: &str) -> bool {
    segment == ":param"
}

fn is_plural(resource: &str) -> bool {
    resource.ends_with('s') && !resource.ends_with("ss") && resource.len() > 1
}

fn singular_resource(resource: &str) -> String {
    if let Some(stem) = resource.strip_suffix("ies") {
        format!("{}y", stem)
    } else if resource.ends_with('s') && !resource.ends_with("ss") {
        resource.trim_end_matches('s').to_string()
    } else {
        resource.to_string()
    }
}

fn discover_node(root: &Path) -> Option<ApplicationCandidate> {
    let package = root.join("package.json");
    let package_json = fs::read_to_string(&package).ok()?;
    let entrypoints = node_entrypoints(root, &package_json);
    let files = readable_sources(root, &entrypoints);
    let framework = if package_json.contains("\"express\"")
        || files.iter().any(|(_, source)| source.contains("express()"))
    {
        Some("Express".to_string())
    } else {
        None
    };
    let mut routes = files
        .iter()
        .flat_map(|(_, source)| discover_js_routes(source))
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    Some(ApplicationCandidate {
        root: root.to_path_buf(),
        name: json_string_field(&package_json, "name"),
        language: Some("Node".to_string()),
        framework,
        package_manager: node_package_manager(root),
        entrypoints,
        servers: node_servers(&package_json),
        routes,
        providers: discover_providers(root, &files),
        existing_authport: existing_authport(root, &package_json, &files),
        confidence: DiscoveryConfidence::High,
    })
}

fn discover_rust(root: &Path) -> Option<ApplicationCandidate> {
    let manifest = root.join("Cargo.toml");
    let cargo = fs::read_to_string(&manifest).ok()?;
    let entrypoint = root.join("src").join("main.rs");
    let mut entrypoints = Vec::new();
    if entrypoint.exists() {
        entrypoints.push(EntrypointCandidate {
            path: entrypoint,
            kind: EntrypointKind::RustBinary,
            confidence: DiscoveryConfidence::High,
        });
    }
    let files = readable_sources(root, &entrypoints);
    Some(ApplicationCandidate {
        root: root.to_path_buf(),
        name: toml_name(&cargo),
        language: Some("Rust".to_string()),
        framework: None,
        package_manager: Some("cargo".to_string()),
        entrypoints,
        servers: vec![ServerCandidate {
            command: "cargo run".to_string(),
            source: "Cargo.toml".to_string(),
            confidence: DiscoveryConfidence::Medium,
        }],
        routes: Vec::new(),
        providers: discover_providers(root, &files),
        existing_authport: existing_authport(root, &cargo, &files),
        confidence: DiscoveryConfidence::Medium,
    })
}

fn node_entrypoints(root: &Path, package_json: &str) -> Vec<EntrypointCandidate> {
    let mut candidates = Vec::new();
    if let Some(main) = json_string_field(package_json, "main") {
        candidates.push(entrypoint(
            root.join(main),
            EntrypointKind::NodeScript,
            DiscoveryConfidence::High,
        ));
    }
    for path in [
        "src/server.ts",
        "src/server.js",
        "server.ts",
        "server.js",
        "src/index.ts",
        "src/index.js",
        "index.ts",
        "index.js",
        "app.js",
    ] {
        let path = root.join(path);
        if path.exists() && !candidates.iter().any(|candidate| candidate.path == path) {
            candidates.push(entrypoint(
                path,
                EntrypointKind::NodeScript,
                DiscoveryConfidence::Medium,
            ));
        }
    }
    candidates
}

fn entrypoint(
    path: PathBuf,
    kind: EntrypointKind,
    confidence: DiscoveryConfidence,
) -> EntrypointCandidate {
    EntrypointCandidate {
        path,
        kind,
        confidence,
    }
}

fn readable_sources(root: &Path, entrypoints: &[EntrypointCandidate]) -> Vec<(PathBuf, String)> {
    let mut files = entrypoints
        .iter()
        .filter_map(|candidate| {
            fs::read_to_string(&candidate.path)
                .ok()
                .map(|source| (candidate.path.clone(), source))
        })
        .collect::<Vec<_>>();
    for name in [".env", ".env.local"] {
        let path = root.join(name);
        if let Ok(source) = fs::read_to_string(&path) {
            files.push((path, source));
        }
    }
    files
}

fn node_package_manager(root: &Path) -> Option<String> {
    if root.join("pnpm-lock.yaml").exists() {
        Some("pnpm".to_string())
    } else if root.join("yarn.lock").exists() {
        Some("yarn".to_string())
    } else {
        Some("npm".to_string())
    }
}

fn node_servers(package_json: &str) -> Vec<ServerCandidate> {
    json_script(package_json, "start")
        .into_iter()
        .map(|command| ServerCandidate {
            command,
            source: "package.json scripts.start".to_string(),
            confidence: DiscoveryConfidence::High,
        })
        .collect()
}

fn existing_authport(root: &Path, manifest: &str, files: &[(PathBuf, String)]) -> ExistingAuthPort {
    ExistingAuthPort {
        dependency: manifest.contains("\"authport\"") || manifest.contains("appport-auth-mesh"),
        initialization: files.iter().any(|(_, source)| {
            source.contains("createAuthPort(") || source.contains("AuthPortRuntime::new")
        }),
        middleware: files.iter().any(|(_, source)| {
            source.contains("authport()")
                || source.contains("app.use(authport")
                || source.contains("AuthPortServer::new")
        }),
        configuration: [
            "authport.toml",
            "appport.auth",
            "appport.toml",
            "auth.appport",
        ]
        .iter()
        .any(|name| root.join(name).exists()),
        manifest: root.join(".authport").join("adoption.json").exists(),
    }
}

fn discover_providers(root: &Path, files: &[(PathBuf, String)]) -> Vec<ProviderCandidate> {
    let mut haystack = String::new();
    for (_, source) in files {
        haystack.push_str(source);
        haystack.push('\n');
    }
    for name in [".env", ".env.local"] {
        if let Ok(source) = fs::read_to_string(root.join(name)) {
            haystack.push_str(&source);
            haystack.push('\n');
        }
    }
    let mut providers = Vec::new();
    if haystack.contains("GOOGLE_CLIENT_ID") || haystack.contains("GOOGLE_CLIENT_SECRET") {
        providers.push(ProviderCandidate {
            id: "google".to_string(),
            display_name: "Google OAuth configuration".to_string(),
        });
    }
    if haystack.contains("GITHUB_CLIENT_ID") || haystack.contains("GITHUB_CLIENT_SECRET") {
        providers.push(ProviderCandidate {
            id: "github".to_string(),
            display_name: "GitHub OAuth configuration".to_string(),
        });
    }
    providers
}

fn discover_js_routes(source: &str) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    for method in ["get", "post", "put", "patch", "delete"] {
        for needle in [format!(".{}('", method), format!(".{}(\"", method)] {
            let quote = needle.chars().last().unwrap();
            let mut rest = source;
            while let Some(index) = rest.find(&needle) {
                let after = &rest[index + needle.len()..];
                if let Some(end) = after.find(quote) {
                    let path = &after[..end];
                    if path.starts_with('/') {
                        let tail = after[end + 1..]
                            .split(['\n', ';'])
                            .next()
                            .unwrap_or_default();
                        routes.push(RouteCandidate {
                            method: method.to_ascii_uppercase(),
                            path: path.to_string(),
                            source: RouteSource::Express,
                            capability: explicit_capability(tail),
                        });
                    }
                    rest = &after[end + 1..];
                } else {
                    break;
                }
            }
        }
    }
    routes
}

fn explicit_capability(source_after_path: &str) -> Option<String> {
    for needle in ["require('", "require(\"", "capability('", "capability(\""] {
        let quote = needle.chars().last().unwrap();
        if let Some(index) = source_after_path.find(needle) {
            let rest = &source_after_path[index + needle.len()..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn json_string_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let after = json[json.find(&needle)? + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn json_script(json: &str, script: &str) -> Option<String> {
    let scripts = json.split("\"scripts\"").nth(1)?;
    json_string_field(scripts, script)
}

fn toml_name(toml: &str) -> Option<String> {
    toml.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("name")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .map(str::trim)
            .and_then(|value| value.strip_prefix('"'))
            .and_then(|value| value.split('"').next())
            .map(str::to_string)
    })
}

fn route_json(route: &RouteDescription) -> String {
    format!(
        "{{\"id\": \"{}\", \"method\": \"{}\", \"path\": \"{}\", \"source\": \"{}\", \"capability\": {}, \"inference\": {}, \"protection\": \"{}\", \"protection_reason\": \"{}\"}}",
        escape(&route.id),
        escape(&route.method),
        escape(&route.path),
        route.source.as_str(),
        option_string_json(route.capability.as_deref()),
        route
            .inference
            .as_ref()
            .map(inference_json)
            .unwrap_or_else(|| "null".to_string()),
        route.protection.as_str(),
        escape(&route.protection_reason)
    )
}

fn inference_json(inference: &Inference) -> String {
    format!(
        "{{\"kind\": \"{}\", \"capability\": \"{}\", \"confidence\": \"{}\", \"reasons\": [{}]}}",
        inference.kind.as_str(),
        escape(&inference.capability),
        inference.confidence.as_str(),
        inference
            .reasons
            .iter()
            .map(|reason| format!("\"{}\"", escape(reason)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn recommendation_json(recommendation: &AuthorityRecommendation) -> String {
    format!(
        "{{\"method\": \"{}\", \"path\": \"{}\", \"action\": \"{}\", \"capability\": {}, \"reason\": \"{}\"}}",
        escape(&recommendation.method),
        escape(&recommendation.path),
        recommendation.action.as_str(),
        option_string_json(recommendation.capability.as_deref()),
        escape(&recommendation.reason)
    )
}

fn option_string_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("authport-discovery-{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovers_express_without_running_scripts_or_exposing_secrets() {
        let dir = temp_dir("express");
        fs::write(
            dir.join("package.json"),
            r#"{"name":"shop","scripts":{"start":"node src/server.js"},"dependencies":{"express":"latest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/health', handler);\napp.post(\"/invoices\", handler);\n",
        )
        .unwrap();
        fs::write(
            dir.join(".env"),
            "GOOGLE_CLIENT_ID=public\nGOOGLE_CLIENT_SECRET=super-secret\n",
        )
        .unwrap();

        let app = discover(&dir).expect("node app discovered");

        assert_eq!(app.name.as_deref(), Some("shop"));
        assert_eq!(app.framework.as_deref(), Some("Express"));
        assert_eq!(app.servers[0].command, "node src/server.js");
        assert!(app.routes.contains(&RouteCandidate {
            method: "GET".to_string(),
            path: "/health".to_string(),
            source: RouteSource::Express,
            capability: None,
        }));
        assert_eq!(app.providers[0].id, "google");
        assert!(!app.providers[0].display_name.contains("super-secret"));
    }

    #[test]
    fn infers_capabilities_and_normalizes_parameters_deterministically() {
        assert_eq!(
            normalize_path("/invoices/{id}"),
            normalize_path("/invoices/[id]")
        );
        assert_eq!(normalize_path("/invoices/:id"), "/invoices/:param");

        let read = infer_capability("GET", "/invoices/:id").unwrap();
        assert_eq!(read.capability, "invoice.read");
        assert_eq!(read.confidence, Confidence::High);

        let create = infer_capability("POST", "/customers").unwrap();
        assert_eq!(create.capability, "customer.create");
        assert_eq!(create.confidence, Confidence::High);

        let action = infer_capability("POST", "/billing/charge").unwrap();
        assert_eq!(action.capability, "billing.charge");
        assert_eq!(action.confidence, Confidence::High);

        let weak = infer_capability("POST", "/process").unwrap();
        assert_eq!(weak.capability, "process.create");
        assert_eq!(weak.confidence, Confidence::Low);

        let medium = infer_capability("GET", "/reports/summary").unwrap();
        assert_eq!(medium.confidence, Confidence::Medium);
    }

    #[test]
    fn proposal_preserves_explicit_mapping_and_recommends_without_applying() {
        let app = ApplicationCandidate {
            root: PathBuf::from("."),
            name: Some("billing-api".to_string()),
            language: Some("Node".to_string()),
            framework: Some("Express".to_string()),
            package_manager: Some("npm".to_string()),
            entrypoints: Vec::new(),
            servers: Vec::new(),
            routes: vec![
                RouteCandidate {
                    method: "GET".to_string(),
                    path: "/health".to_string(),
                    source: RouteSource::Express,
                    capability: None,
                },
                RouteCandidate {
                    method: "POST".to_string(),
                    path: "/invoices".to_string(),
                    source: RouteSource::Express,
                    capability: Some("invoice.write".to_string()),
                },
                RouteCandidate {
                    method: "POST".to_string(),
                    path: "/billing/charge".to_string(),
                    source: RouteSource::Express,
                    capability: None,
                },
            ],
            providers: Vec::new(),
            existing_authport: ExistingAuthPort::default(),
            confidence: DiscoveryConfidence::High,
        };

        let proposal = propose_authority(&app, "contract-1", 4, &BTreeMap::new());
        assert_eq!(proposal.contract_fingerprint, "contract-1");
        assert_eq!(proposal.live_revision, 4);
        let explicit = proposal
            .routes
            .iter()
            .find(|route| route.path == "/invoices")
            .unwrap();
        assert_eq!(explicit.capability.as_deref(), Some("invoice.write"));
        assert!(explicit.inference.is_none());
        assert_eq!(explicit.protection, ProtectionState::Protected);

        let charge = proposal
            .routes
            .iter()
            .find(|route| route.path == "/billing/charge")
            .unwrap();
        assert_eq!(
            charge.inference.as_ref().map(|i| i.capability.as_str()),
            Some("billing.charge")
        );
        assert_eq!(charge.protection, ProtectionState::Unprotected);
        assert!(proposal.recommendations.iter().any(|item| {
            item.path == "/billing/charge" && item.action == RecommendationAction::ProtectRoute
        }));

        let json = render_proposal_json(&proposal);
        assert!(json.contains("\"contract_fingerprint\": \"contract-1\""));
        assert!(json.contains("\"live_revision\": 4"));
        assert_eq!(json, render_proposal_json(&proposal));
    }
}
