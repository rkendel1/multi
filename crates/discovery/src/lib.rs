//! Framework-neutral application discovery for AuthBoundry adoption.
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
    pub existing_auth: Vec<ExistingAuthSystem>,
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
    PythonScript,
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
    Client,
    Python,
    Unknown,
}

impl RouteSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Express => "express",
            Self::Embedded => "embedded",
            Self::Standalone => "standalone",
            Self::Rust => "rust",
            Self::Client => "client",
            Self::Python => "python",
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
    pub resource: Option<ResourceInference>,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceInference {
    pub resource_type: String,
    pub resource_id: String,
    pub action: String,
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
    pub id: Option<String>,
    pub method: String,
    pub path: String,
    pub action: RecommendationAction,
    pub capability: Option<String>,
    pub status: ProposalReviewStatus,
    pub current_authority_state: String,
    pub proposed_authority_state: String,
    pub source: ProposalOrigin,
    pub discovery_revision: u64,
    pub authority_revision: u64,
    pub contract_fingerprint: String,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalReviewStatus {
    Recommended,
    Approved,
    Rejected,
    AlreadyProtected,
    AlreadyPublic,
    Stale,
}

impl ProposalReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recommended => "recommended",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::AlreadyProtected => "already_protected",
            Self::AlreadyPublic => "already_public",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalOrigin {
    Explicit,
    Inferred,
    Imported,
}

impl ProposalOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Inferred => "inferred",
            Self::Imported => "imported",
        }
    }
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
    pub discovery_revision: u64,
    pub live_revision: u64,
    pub routes: Vec<RouteDescription>,
    pub inferences: Vec<Inference>,
    pub recommendations: Vec<AuthorityRecommendation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDrift {
    NewRoute,
    RemovedRoute,
    RouteChanged,
    CapabilityConflict,
    OrphanedAuthority,
    StaleProposal,
}

impl AuthorityDrift {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewRoute => "new_route",
            Self::RemovedRoute => "removed_route",
            Self::RouteChanged => "route_changed",
            Self::CapabilityConflict => "capability_conflict",
            Self::OrphanedAuthority => "orphaned_authority",
            Self::StaleProposal => "stale_proposal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanedAuthority {
    pub method: String,
    pub path: String,
    pub capability: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedRoute {
    pub previous: RouteDescription,
    pub current: RouteDescription,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalHistoryItem {
    pub id: String,
    pub method: String,
    pub path: String,
    pub capability: String,
    pub status: String,
    pub discovery_revision: u64,
    pub authority_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDriftItem {
    pub kind: AuthorityDrift,
    pub route: String,
    pub previous_state: String,
    pub current_state: String,
    pub authority_state: String,
    pub recommended_action: String,
    pub discovery_revision: u64,
    pub authority_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationResult {
    pub application: String,
    pub contract_fingerprint: String,
    pub discovery_revision: u64,
    pub authority_revision: u64,
    pub reconciliation_revision: u64,
    pub new_routes: Vec<RouteDescription>,
    pub removed_routes: Vec<RouteDescription>,
    pub changed_routes: Vec<ChangedRoute>,
    pub unchanged_routes: Vec<RouteDescription>,
    pub equivalent_routes: Vec<ChangedRoute>,
    pub orphaned_authority: Vec<OrphanedAuthority>,
    pub new_authority_proposals: Vec<AuthorityRecommendation>,
    pub stale_proposals: Vec<ProposalHistoryItem>,
    pub warnings: Vec<String>,
    pub drift: Vec<AuthorityDriftItem>,
}

pub struct AuthorityReconciler;

impl AuthorityReconciler {
    pub fn reconcile(
        previous: Option<&ApplicationCandidate>,
        current: &ApplicationCandidate,
        contract_fingerprint: impl Into<String>,
        authority_revision: u64,
        live_authority: &BTreeMap<(String, String), String>,
        proposal_history: &[ProposalHistoryItem],
    ) -> ReconciliationResult {
        let contract_fingerprint = contract_fingerprint.into();
        let equivalent_keys = equivalent_route_keys(previous, current);
        let current_proposal = propose_authority(
            current,
            contract_fingerprint.clone(),
            authority_revision,
            live_authority,
        );
        let previous_routes = previous
            .map(|application| {
                propose_authority(
                    application,
                    contract_fingerprint.clone(),
                    authority_revision,
                    live_authority,
                )
                .routes
            })
            .unwrap_or_else(|| {
                live_authority
                    .iter()
                    .map(|((method, path), capability)| RouteDescription {
                        id: format!("{} {}", method, normalize_path(path)),
                        method: method.clone(),
                        path: normalize_path(path),
                        source: RouteSource::Unknown,
                        capability: Some(capability.clone()),
                        inference: None,
                        protection: ProtectionState::Protected,
                        protection_reason: "previously approved authority mapping".to_string(),
                    })
                    .collect()
            });
        reconcile_descriptions(
            current
                .name
                .clone()
                .unwrap_or_else(|| "application".to_string()),
            contract_fingerprint,
            authority_revision,
            previous_routes,
            current_proposal,
            live_authority,
            proposal_history,
            &equivalent_keys,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCandidate {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCoexistence {
    Bridge,
    Migrate,
}

impl AuthCoexistence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Migrate => "migrate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAuthSystem {
    pub id: String,
    pub display_name: String,
    pub credentials: bool,
    pub sessions: bool,
    pub profiles: bool,
    pub authorization: bool,
    pub coexistence: AuthCoexistence,
    pub evidence: Vec<String>,
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

/// Canonical public name for a previously installed AuthBoundry integration.
pub type ExistingAuthBoundry = ExistingAuthPort;

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
    discover_node(root)
        .or_else(|| discover_python(root))
        .or_else(|| discover_rust(root))
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
    let contract_fingerprint = contract_fingerprint.into();
    let discovery_revision = discovery_revision(&routes);
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
                id: None,
                method: route.method.clone(),
                path: route.path.clone(),
                action,
                capability: route
                    .capability
                    .clone()
                    .or_else(|| route.inference.as_ref().map(|i| i.capability.clone())),
                status: match route.protection {
                    ProtectionState::Public => ProposalReviewStatus::AlreadyPublic,
                    ProtectionState::Protected => ProposalReviewStatus::AlreadyProtected,
                    ProtectionState::Unprotected => match action {
                        RecommendationAction::ProtectRoute => ProposalReviewStatus::Recommended,
                        RecommendationAction::NoChange => ProposalReviewStatus::Recommended,
                    },
                },
                current_authority_state: route.protection.as_str().to_string(),
                proposed_authority_state: match action {
                    RecommendationAction::ProtectRoute => "protected".to_string(),
                    RecommendationAction::NoChange => route.protection.as_str().to_string(),
                },
                source: if route.capability.is_some() {
                    ProposalOrigin::Explicit
                } else {
                    ProposalOrigin::Inferred
                },
                discovery_revision,
                authority_revision: live_revision,
                contract_fingerprint: contract_fingerprint.clone(),
                confidence: route
                    .inference
                    .as_ref()
                    .map(|inference| inference.confidence)
                    .unwrap_or(Confidence::Unknown),
                reasons: route
                    .inference
                    .as_ref()
                    .map(|inference| inference.reasons.clone())
                    .unwrap_or_else(|| vec![route.protection_reason.clone()]),
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
        contract_fingerprint,
        discovery_revision,
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
        "{{\n  \"application\": \"{}\",\n  \"contract_fingerprint\": \"{}\",\n  \"discovery_revision\": {},\n  \"live_revision\": {},\n  \"routes\": [{}],\n  \"inferences\": [{}],\n  \"recommendations\": [{}],\n  \"warnings\": [{}]\n}}\n",
        escape(&proposal.application),
        escape(&proposal.contract_fingerprint),
        proposal.discovery_revision,
        proposal.live_revision,
        proposal.routes.iter().map(route_json).collect::<Vec<_>>().join(", "),
        proposal.inferences.iter().map(inference_json).collect::<Vec<_>>().join(", "),
        proposal.recommendations.iter().map(recommendation_json).collect::<Vec<_>>().join(", "),
        proposal.warnings.iter().map(|warning| format!("\"{}\"", escape(warning))).collect::<Vec<_>>().join(", ")
    )
}

pub fn render_reconciliation_text(result: &ReconciliationResult) -> String {
    let mut out = String::from("AuthBoundry Authority Reconciliation\n");
    out.push_str(&format!(
        "Contract: {}\nDiscovery: {}\nAuthority: {}\nReconciliation: {}\n",
        result.contract_fingerprint,
        result.discovery_revision,
        result.authority_revision,
        result.reconciliation_revision
    ));

    if !result.new_routes.is_empty() {
        out.push_str("NEW\n");
        for route in &result.new_routes {
            let capability = route
                .inference
                .as_ref()
                .map(|inference| inference.capability.as_str())
                .or(route.capability.as_deref())
                .unwrap_or("(review)");
            let confidence = route
                .inference
                .as_ref()
                .map(|inference| inference.confidence.as_str())
                .unwrap_or("unknown");
            out.push_str(&format!(
                "  {} {}\n  → {}\n  → {} confidence\n  → review required\n",
                route.method,
                route.path,
                capability,
                confidence.to_ascii_uppercase()
            ));
        }
    }
    if !result.orphaned_authority.is_empty() {
        out.push_str("REMOVED\n");
        for item in &result.orphaned_authority {
            out.push_str(&format!(
                "  {} {}\n  → {}\n  → orphaned authority\n",
                item.method, item.path, item.capability
            ));
        }
    }
    if !result.changed_routes.is_empty() {
        out.push_str("CHANGED\n");
        for item in &result.changed_routes {
            let capability = item
                .current
                .capability
                .as_deref()
                .or_else(|| {
                    item.current
                        .inference
                        .as_ref()
                        .map(|i| i.capability.as_str())
                })
                .unwrap_or("(review)");
            out.push_str(&format!(
                "  {} {} (was {} {})\n  → {}\n  → existing authority preserved\n",
                item.current.method,
                item.current.path,
                item.previous.method,
                item.previous.path,
                capability
            ));
        }
    }
    out.push_str(&format!(
        "UNCHANGED\n  {} routes\n",
        result.unchanged_routes.len()
    ));
    out.push_str("No authority was changed.\n");
    out
}

pub fn render_reconciliation_json(result: &ReconciliationResult) -> String {
    format!(
        "{{\n  \"application\": \"{}\",\n  \"contract_fingerprint\": \"{}\",\n  \"discovery_revision\": {},\n  \"authority_revision\": {},\n  \"reconciliation_revision\": {},\n  \"summary\": {{\"new_routes\": {}, \"removed_routes\": {}, \"changed_routes\": {}, \"unchanged_routes\": {}, \"orphaned_authority\": {}, \"capability_conflicts\": {}, \"stale_proposals\": {}, \"unsafe_automatic_changes\": 0}},\n  \"new_routes\": [{}],\n  \"removed_routes\": [{}],\n  \"changed_routes\": [{}],\n  \"unchanged_routes\": [{}],\n  \"equivalent_routes\": [{}],\n  \"orphaned_authority\": [{}],\n  \"new_authority_proposals\": [{}],\n  \"stale_proposals\": [{}],\n  \"warnings\": [{}],\n  \"drift\": [{}]\n}}\n",
        escape(&result.application),
        escape(&result.contract_fingerprint),
        result.discovery_revision,
        result.authority_revision,
        result.reconciliation_revision,
        result.new_routes.len(),
        result.removed_routes.len(),
        result.changed_routes.len(),
        result.unchanged_routes.len(),
        result.orphaned_authority.len(),
        result
            .drift
            .iter()
            .filter(|item| item.kind == AuthorityDrift::CapabilityConflict)
            .count(),
        result.stale_proposals.len(),
        result.new_routes.iter().map(route_json).collect::<Vec<_>>().join(", "),
        result.removed_routes.iter().map(route_json).collect::<Vec<_>>().join(", "),
        result.changed_routes.iter().map(changed_route_json).collect::<Vec<_>>().join(", "),
        result.unchanged_routes.iter().map(route_json).collect::<Vec<_>>().join(", "),
        result.equivalent_routes.iter().map(changed_route_json).collect::<Vec<_>>().join(", "),
        result.orphaned_authority.iter().map(orphaned_authority_json).collect::<Vec<_>>().join(", "),
        result.new_authority_proposals.iter().map(recommendation_json).collect::<Vec<_>>().join(", "),
        result.stale_proposals.iter().map(proposal_history_json).collect::<Vec<_>>().join(", "),
        result.warnings.iter().map(|warning| format!("\"{}\"", escape(warning))).collect::<Vec<_>>().join(", "),
        result.drift.iter().map(drift_item_json).collect::<Vec<_>>().join(", ")
    )
}

pub fn render_drift_json(result: &ReconciliationResult) -> String {
    format!(
        "{{\n  \"contract_fingerprint\": \"{}\",\n  \"discovery_revision\": {},\n  \"authority_revision\": {},\n  \"reconciliation_revision\": {},\n  \"drift\": [{}]\n}}\n",
        escape(&result.contract_fingerprint),
        result.discovery_revision,
        result.authority_revision,
        result.reconciliation_revision,
        result
            .drift
            .iter()
            .map(drift_item_json)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn equivalent_route_keys(
    previous: Option<&ApplicationCandidate>,
    current: &ApplicationCandidate,
) -> Vec<(String, String)> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let previous_raw = previous
        .routes
        .iter()
        .map(|route| {
            (
                (route.method.clone(), normalize_path(&route.path)),
                route.path.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut keys = current
        .routes
        .iter()
        .filter_map(|route| {
            let key = (route.method.clone(), normalize_path(&route.path));
            previous_raw
                .get(&key)
                .filter(|path| *path != &route.path)
                .map(|_| key)
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn reconcile_descriptions(
    application: String,
    contract_fingerprint: String,
    authority_revision: u64,
    mut previous_routes: Vec<RouteDescription>,
    current_proposal: AuthorityProposal,
    live_authority: &BTreeMap<(String, String), String>,
    proposal_history: &[ProposalHistoryItem],
    equivalent_keys: &[(String, String)],
) -> ReconciliationResult {
    previous_routes.sort_by(route_order);
    let mut current_routes = current_proposal.routes.clone();
    current_routes.sort_by(route_order);
    let discovery_revision = current_proposal.discovery_revision;

    let previous_keys = previous_routes
        .iter()
        .map(|route| (route_key(route), route.clone()))
        .collect::<BTreeMap<_, _>>();
    let current_keys = current_routes
        .iter()
        .map(|route| (route_key(route), route.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut unchanged_routes = Vec::new();
    let mut equivalent_routes = Vec::new();
    let mut removed_routes = Vec::new();
    let mut new_routes = Vec::new();

    for (key, current) in &current_keys {
        if let Some(previous) = previous_keys.get(key) {
            if equivalent_keys.contains(key) {
                equivalent_routes.push(ChangedRoute {
                    previous: previous.clone(),
                    current: current.clone(),
                    reason: "route parameter syntax normalized to the same authority route"
                        .to_string(),
                });
            }
            unchanged_routes.push(current.clone());
        } else {
            new_routes.push(current.clone());
        }
    }
    for (key, previous) in &previous_keys {
        if !current_keys.contains_key(key) {
            removed_routes.push(previous.clone());
        }
    }

    let mut changed_routes = Vec::new();
    let mut paired_new = Vec::new();
    let mut paired_removed = Vec::new();
    for (removed_index, removed) in removed_routes.iter().enumerate() {
        if let Some((new_index, new)) = new_routes.iter().enumerate().find(|(new_index, new)| {
            !paired_new.contains(new_index) && route_family(removed) == route_family(new)
        }) {
            paired_removed.push(removed_index);
            paired_new.push(new_index);
            changed_routes.push(ChangedRoute {
                previous: removed.clone(),
                current: new.clone(),
                reason: if removed.method != new.method {
                    "HTTP method changed".to_string()
                } else {
                    "route shape changed".to_string()
                },
            });
        }
    }
    new_routes = new_routes
        .into_iter()
        .enumerate()
        .filter_map(|(index, route)| (!paired_new.contains(&index)).then_some(route))
        .collect();
    removed_routes = removed_routes
        .into_iter()
        .enumerate()
        .filter_map(|(index, route)| (!paired_removed.contains(&index)).then_some(route))
        .collect();

    let mut orphaned_authority = live_authority
        .iter()
        .filter_map(|((method, path), capability)| {
            let key = (method.clone(), normalize_path(path));
            (!current_keys.contains_key(&key)).then(|| OrphanedAuthority {
                method: method.clone(),
                path: normalize_path(path),
                capability: capability.clone(),
                reason: "route no longer discovered; historical authority retained".to_string(),
            })
        })
        .collect::<Vec<_>>();
    orphaned_authority.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method)));

    let mut new_authority_proposals = current_proposal
        .recommendations
        .into_iter()
        .filter(|item| item.action == RecommendationAction::ProtectRoute)
        .collect::<Vec<_>>();
    new_authority_proposals
        .sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method)));

    let mut stale_proposals = proposal_history
        .iter()
        .filter(|proposal| {
            let key = (proposal.method.clone(), normalize_path(&proposal.path));
            proposal.status != "applied" && !current_keys.contains_key(&key)
        })
        .cloned()
        .collect::<Vec<_>>();
    stale_proposals.sort_by(|a, b| a.id.cmp(&b.id));

    let mut warnings = Vec::new();
    let mut drift = Vec::new();
    for route in &new_routes {
        drift.push(drift_item(
            AuthorityDrift::NewRoute,
            route,
            "absent",
            "discovered",
            route.protection.as_str(),
            "review",
            discovery_revision,
            authority_revision,
        ));
    }
    for route in &removed_routes {
        drift.push(drift_item(
            AuthorityDrift::RemovedRoute,
            route,
            "discovered",
            "absent",
            route.protection.as_str(),
            "review",
            discovery_revision,
            authority_revision,
        ));
    }
    for change in &changed_routes {
        drift.push(drift_item(
            AuthorityDrift::RouteChanged,
            &change.current,
            &format!("{} {}", change.previous.method, change.previous.path),
            &format!("{} {}", change.current.method, change.current.path),
            change.current.protection.as_str(),
            "review",
            discovery_revision,
            authority_revision,
        ));
    }
    for item in &orphaned_authority {
        drift.push(AuthorityDriftItem {
            kind: AuthorityDrift::OrphanedAuthority,
            route: format!("{} {}", item.method, item.path),
            previous_state: "protected".to_string(),
            current_state: "route_absent".to_string(),
            authority_state: format!("retained:{}", item.capability),
            recommended_action: "review".to_string(),
            discovery_revision,
            authority_revision,
        });
    }
    for proposal in &stale_proposals {
        drift.push(AuthorityDriftItem {
            kind: AuthorityDrift::StaleProposal,
            route: format!("{} {}", proposal.method, normalize_path(&proposal.path)),
            previous_state: proposal.status.clone(),
            current_state: "route_absent".to_string(),
            authority_state: format!("proposal:{}", proposal.id),
            recommended_action: "reject_or_supersede".to_string(),
            discovery_revision,
            authority_revision,
        });
    }
    for route in &current_routes {
        if let Some(inference) = infer_capability(&route.method, &route.path) {
            if let Some(existing) =
                live_authority.get(&(route.method.clone(), normalize_path(&route.path)))
            {
                if existing != &inference.capability {
                    warnings.push(format!(
                        "authority conflict for {} {}: existing explicit authority {} differs from inferred {}",
                        route.method, route.path, existing, inference.capability
                    ));
                    drift.push(AuthorityDriftItem {
                        kind: AuthorityDrift::CapabilityConflict,
                        route: format!("{} {}", route.method, route.path),
                        previous_state: existing.clone(),
                        current_state: inference.capability,
                        authority_state: "explicit authority preserved".to_string(),
                        recommended_action: "review".to_string(),
                        discovery_revision,
                        authority_revision,
                    });
                }
            }
        }
    }

    drift.sort_by(|a, b| {
        a.route
            .cmp(&b.route)
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
    });
    let reconciliation_revision = reconciliation_revision(
        discovery_revision,
        authority_revision,
        &contract_fingerprint,
        &drift,
    );

    ReconciliationResult {
        application,
        contract_fingerprint,
        discovery_revision,
        authority_revision,
        reconciliation_revision,
        new_routes,
        removed_routes,
        changed_routes,
        unchanged_routes,
        equivalent_routes,
        orphaned_authority,
        new_authority_proposals,
        stale_proposals,
        warnings,
        drift,
    }
}

fn route_order(a: &RouteDescription, b: &RouteDescription) -> std::cmp::Ordering {
    a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method))
}

fn route_key(route: &RouteDescription) -> (String, String) {
    (route.method.clone(), normalize_path(&route.path))
}

fn route_family(route: &RouteDescription) -> String {
    let normalized = normalize_path(&route.path);
    path_segments(&normalized)
        .into_iter()
        .find(|segment| !is_parameter(segment))
        .unwrap_or("")
        .to_string()
}

fn drift_item(
    kind: AuthorityDrift,
    route: &RouteDescription,
    previous_state: impl Into<String>,
    current_state: impl Into<String>,
    authority_state: impl Into<String>,
    recommended_action: impl Into<String>,
    discovery_revision: u64,
    authority_revision: u64,
) -> AuthorityDriftItem {
    AuthorityDriftItem {
        kind,
        route: format!("{} {}", route.method, route.path),
        previous_state: previous_state.into(),
        current_state: current_state.into(),
        authority_state: authority_state.into(),
        recommended_action: recommended_action.into(),
        discovery_revision,
        authority_revision,
    }
}

fn reconciliation_revision(
    discovery_revision: u64,
    authority_revision: u64,
    contract_fingerprint: &str,
    drift: &[AuthorityDriftItem],
) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    contract_fingerprint.hash(&mut hasher);
    discovery_revision.hash(&mut hasher);
    authority_revision.hash(&mut hasher);
    for item in drift {
        item.kind.as_str().hash(&mut hasher);
        item.route.hash(&mut hasher);
        item.previous_state.hash(&mut hasher);
        item.current_state.hash(&mut hasher);
        item.authority_state.hash(&mut hasher);
        item.recommended_action.hash(&mut hasher);
    }
    hasher.finish()
}

fn discovery_revision(routes: &[RouteDescription]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for route in routes {
        route.method.hash(&mut hasher);
        route.path.hash(&mut hasher);
        route.source.as_str().hash(&mut hasher);
        route.capability.hash(&mut hasher);
        if let Some(inference) = &route.inference {
            inference.capability.hash(&mut hasher);
            if let Some(resource) = &inference.resource {
                resource.resource_type.hash(&mut hasher);
                resource.resource_id.hash(&mut hasher);
                resource.action.hash(&mut hasher);
            }
            inference.confidence.as_str().hash(&mut hasher);
            inference.reasons.hash(&mut hasher);
        }
    }
    hasher.finish()
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
    let raw_segments = path_segments(path);
    if segments.is_empty()
        || matches!(
            segments.first().copied(),
            Some("auth" | "health" | "healthz" | "ready" | "readyz" | "metrics")
        )
    {
        return None;
    }

    let (capability, resource_inference, confidence, mut reasons) = if segments.len() == 1 {
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
            Some(ResourceInference {
                resource_type: singular,
                resource_id: "*".to_string(),
                action: action.to_string(),
            }),
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
            Some(ResourceInference {
                resource_type: singular,
                resource_id: raw_segments
                    .get(1)
                    .and_then(|segment| parameter_name(segment))
                    .or_else(|| parameter_name(segments[1]))
                    .map(|name| format!("{{{}}}", name))
                    .unwrap_or_else(|| "*".to_string()),
                action: action.to_string(),
            }),
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
            Some(ResourceInference {
                resource_type: singular_resource(segments[0]),
                resource_id: "*".to_string(),
                action: segments[1].to_string(),
            }),
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
            resource: Some(ResourceInference {
                resource_type: singular_resource(segments[0]),
                resource_id: "*".to_string(),
                action: "review".to_string(),
            }),
            confidence: Confidence::Low,
            reasons: vec!["route shape is ambiguous; review manually".to_string()],
        });
    };

    reasons.push("no explicit capability mapping exists".to_string());
    Some(Inference {
        kind: InferenceKind::Capability,
        capability,
        resource: resource_inference,
        confidence,
        reasons,
    })
}

fn parameter_name(segment: &str) -> Option<&str> {
    segment
        .strip_prefix(':')
        .or_else(|| segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
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
            "AuthBoundry-owned authority endpoint".to_string(),
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
    let framework = Some(detect_node_framework(root, &package_json, &files));
    let mut routes = files
        .iter()
        .flat_map(|(_, source)| discover_js_routes(source))
        .collect::<Vec<_>>();
    if root.join("index.html").exists() {
        routes.push(RouteCandidate {
            method: "GET".to_string(),
            path: "/".to_string(),
            source: RouteSource::Client,
            capability: None,
        });
    }
    routes.extend(discover_filesystem_routes(
        root,
        framework.as_deref().unwrap_or("Node.js"),
        &files,
    ));
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
        existing_auth: discover_existing_auth(root, &package_json, &files),
        existing_authport: existing_authport(root, &package_json, &files),
        confidence: DiscoveryConfidence::High,
    })
}

fn detect_node_framework(root: &Path, manifest: &str, files: &[(PathBuf, String)]) -> String {
    let source_contains = |needle: &str| files.iter().any(|(_, source)| source.contains(needle));
    let dependency = |name: &str| manifest.contains(&format!("\"{}\"", name));
    let config = |names: &[&str]| names.iter().any(|name| root.join(name).exists());

    let rules: &[(&str, &[&str], &[&str])] = &[
        ("FeltDB", &["feltdb"], &[]),
        (
            "Next.js",
            &["next"],
            &["next.config.js", "next.config.mjs", "next.config.ts"],
        ),
        (
            "Remix",
            &["@remix-run/react", "@remix-run/node"],
            &["remix.config.js"],
        ),
        ("Nuxt", &["nuxt"], &["nuxt.config.ts", "nuxt.config.js"]),
        ("SvelteKit", &["@sveltejs/kit"], &["svelte.config.js"]),
        ("Angular", &["@angular/core"], &["angular.json"]),
        (
            "Astro",
            &["astro"],
            &["astro.config.mjs", "astro.config.ts"],
        ),
        (
            "Gatsby",
            &["gatsby"],
            &["gatsby-config.js", "gatsby-config.ts"],
        ),
        ("NestJS", &["@nestjs/core"], &["nest-cli.json"]),
        ("RedwoodJS", &["@redwoodjs/core"], &["redwood.toml"]),
        (
            "SolidStart",
            &["@solidjs/start", "solid-start"],
            &["app.config.ts"],
        ),
        ("Qwik City", &["@builder.io/qwik-city"], &["vite.config.ts"]),
        ("AdonisJS", &["@adonisjs/core"], &["adonisrc.ts"]),
        ("Fastify", &["fastify"], &[]),
        ("Hono", &["hono"], &[]),
        ("Koa", &["koa"], &[]),
        ("Hapi", &["@hapi/hapi"], &[]),
        ("Express", &["express"], &[]),
        ("React Router", &["react-router", "react-router-dom"], &[]),
        ("Vue", &["vue"], &[]),
        ("React", &["react"], &[]),
        ("Vite", &["vite"], &["vite.config.js", "vite.config.ts"]),
    ];
    for (label, dependencies, configs) in rules {
        if dependencies.iter().any(|name| dependency(name)) || config(configs) {
            return (*label).to_string();
        }
    }
    if source_contains("express()") {
        "Express".to_string()
    } else if source_contains("fastify(") {
        "Fastify".to_string()
    } else {
        "Node.js".to_string()
    }
}

fn discover_filesystem_routes(
    root: &Path,
    framework: &str,
    files: &[(PathBuf, String)],
) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    for (path, source) in files {
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let text = relative.to_string_lossy().replace('\\', "/");
        let route = match framework {
            "Next.js" if text.starts_with("app/") && text.contains("/page.") => Some(
                text.trim_start_matches("app/")
                    .rsplit_once('/')
                    .map(|v| v.0)
                    .unwrap_or(""),
            ),
            "Next.js" if text.starts_with("pages/") && !text.starts_with("pages/api/") => text
                .strip_prefix("pages/")
                .and_then(|value| value.rsplit_once('.').map(|v| v.0)),
            "Nuxt" if text.starts_with("pages/") => text
                .strip_prefix("pages/")
                .and_then(|value| value.rsplit_once('.').map(|v| v.0)),
            "SvelteKit" if text.starts_with("src/routes/") && text.contains("/+page.") => Some(
                text.trim_start_matches("src/routes/")
                    .rsplit_once('/')
                    .map(|v| v.0)
                    .unwrap_or(""),
            ),
            "Astro" if text.starts_with("src/pages/") => text
                .strip_prefix("src/pages/")
                .and_then(|value| value.rsplit_once('.').map(|v| v.0)),
            "Remix" if text.starts_with("app/routes/") => text
                .strip_prefix("app/routes/")
                .and_then(|value| value.rsplit_once('.').map(|v| v.0)),
            _ => None,
        };
        if let Some(route) = route {
            let route = filesystem_route_path(route);
            routes.push(RouteCandidate {
                method: "GET".to_string(),
                path: route,
                source: RouteSource::Client,
                capability: None,
            });
        }
        if framework == "NestJS" {
            routes.extend(discover_decorator_routes(source));
        }
    }
    routes
}

fn filesystem_route_path(value: &str) -> String {
    let mut value = value
        .replace("/index", "")
        .replace('[', ":")
        .replace(']', "");
    if value.contains('.') {
        value = value.replace('.', "/");
    }
    let value = value.trim_matches('/');
    if value.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", value)
    }
}

fn discover_decorator_routes(source: &str) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    for (decorator, method) in [
        ("@Get(", "GET"),
        ("@Post(", "POST"),
        ("@Put(", "PUT"),
        ("@Patch(", "PATCH"),
        ("@Delete(", "DELETE"),
    ] {
        for quote in ['\'', '"'] {
            let needle = format!("{}{}", decorator, quote);
            let mut rest = source;
            while let Some(index) = rest.find(&needle) {
                let after = &rest[index + needle.len()..];
                if let Some(end) = after.find(quote) {
                    routes.push(RouteCandidate {
                        method: method.to_string(),
                        path: filesystem_route_path(&after[..end]),
                        source: RouteSource::Client,
                        capability: None,
                    });
                    rest = &after[end + 1..];
                } else {
                    break;
                }
            }
        }
    }
    routes
}

fn discover_python(root: &Path) -> Option<ApplicationCandidate> {
    let manifests = ["pyproject.toml", "requirements.txt", "Pipfile"];
    let manifest_path = manifests
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())?;
    let manifest = fs::read_to_string(&manifest_path).ok()?;
    let entrypoints = python_entrypoints(root);
    let files = readable_sources(root, &entrypoints);
    let framework = detect_python_framework(root, &manifest, &files);
    let mut routes = files
        .iter()
        .flat_map(|(_, source)| discover_python_routes(source))
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    let name =
        if manifest_path.file_name().and_then(|value| value.to_str()) == Some("pyproject.toml") {
            toml_name(&manifest)
        } else {
            root.file_name()
                .and_then(|value| value.to_str())
                .map(str::to_string)
        };
    Some(ApplicationCandidate {
        root: root.to_path_buf(),
        name,
        language: Some("Python".to_string()),
        framework: Some(framework.clone()),
        package_manager: Some(
            if root.join("poetry.lock").exists() {
                "poetry"
            } else if root.join("uv.lock").exists() {
                "uv"
            } else if root.join("Pipfile.lock").exists() {
                "pipenv"
            } else {
                "pip"
            }
            .to_string(),
        ),
        entrypoints,
        servers: python_servers(&framework, &files),
        routes,
        providers: discover_providers(root, &files),
        existing_auth: discover_existing_auth(root, &manifest, &files),
        existing_authport: existing_authport(root, &manifest, &files),
        confidence: DiscoveryConfidence::High,
    })
}

fn python_entrypoints(root: &Path) -> Vec<EntrypointCandidate> {
    [
        "main.py",
        "app.py",
        "server.py",
        "manage.py",
        "src/main.py",
        "src/app.py",
    ]
    .into_iter()
    .map(|path| root.join(path))
    .filter(|path| path.exists())
    .map(|path| {
        entrypoint(
            path,
            EntrypointKind::PythonScript,
            DiscoveryConfidence::Medium,
        )
    })
    .collect()
}

fn detect_python_framework(root: &Path, manifest: &str, files: &[(PathBuf, String)]) -> String {
    let haystack = format!(
        "{}\n{}",
        manifest.to_ascii_lowercase(),
        files
            .iter()
            .map(|(_, source)| source.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("\n")
    );
    for (needles, label) in [
        (
            &["fastapi", "from fastapi", "import fastapi"][..],
            "FastAPI",
        ),
        (&["django", "django.urls"][..], "Django"),
        (&["flask", "from flask"][..], "Flask"),
        (&["starlette", "from starlette"][..], "Starlette"),
        (&["litestar", "starlite"][..], "Litestar"),
        (&["sanic", "from sanic"][..], "Sanic"),
        (&["falcon", "import falcon"][..], "Falcon"),
        (&["quart", "from quart"][..], "Quart"),
        (&["tornado", "tornado.web"][..], "Tornado"),
        (&["bottle", "from bottle"][..], "Bottle"),
        (&["pyramid", "pyramid.config"][..], "Pyramid"),
    ] {
        if needles.iter().any(|needle| haystack.contains(needle)) {
            return label.to_string();
        }
    }
    if root.join("manage.py").exists() {
        "Django".to_string()
    } else {
        "Python".to_string()
    }
}

fn python_servers(framework: &str, files: &[(PathBuf, String)]) -> Vec<ServerCandidate> {
    let module = files
        .iter()
        .find(|(_, source)| source.contains("FastAPI(") || source.contains("Flask("))
        .and_then(|(path, _)| path.file_stem())
        .and_then(|value| value.to_str())
        .unwrap_or("main");
    let command = match framework {
        "FastAPI" | "Starlette" | "Litestar" => format!("uvicorn {}:app --reload", module),
        "Django" => "python manage.py runserver".to_string(),
        "Flask" | "Quart" => "flask --app app run --debug".to_string(),
        _ => format!("python {}.py", module),
    };
    vec![ServerCandidate {
        command,
        source: "framework convention".to_string(),
        confidence: DiscoveryConfidence::Medium,
    }]
}

fn discover_python_routes(source: &str) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    for (needle, method) in [
        (".get(\"", "GET"),
        (".get('", "GET"),
        (".post(\"", "POST"),
        (".post('", "POST"),
        (".put(\"", "PUT"),
        (".put('", "PUT"),
        (".patch(\"", "PATCH"),
        (".patch('", "PATCH"),
        (".delete(\"", "DELETE"),
        (".delete('", "DELETE"),
        ("Route(\"", "GET"),
        ("Route('", "GET"),
        ("path(\"", "GET"),
        ("path('", "GET"),
        ("re_path(\"", "GET"),
        ("re_path('", "GET"),
        ("add_route(\"", "GET"),
        ("add_route('", "GET"),
    ] {
        let quote = needle.chars().last().unwrap();
        let mut rest = source;
        while let Some(index) = rest.find(needle) {
            let after = &rest[index + needle.len()..];
            if let Some(end) = after.find(quote) {
                let raw = &after[..end];
                let path = if raw.starts_with('/') {
                    raw.to_string()
                } else if needle.starts_with("path(") {
                    filesystem_route_path(raw)
                } else {
                    String::new()
                };
                if !path.is_empty() {
                    routes.push(RouteCandidate {
                        method: method.to_string(),
                        path,
                        source: RouteSource::Python,
                        capability: None,
                    });
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    routes
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
    let framework = Some(detect_rust_framework(&cargo));
    let mut routes = files
        .iter()
        .flat_map(|(_, source)| discover_rust_routes(source))
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    Some(ApplicationCandidate {
        root: root.to_path_buf(),
        name: toml_name(&cargo),
        language: Some("Rust".to_string()),
        framework,
        package_manager: Some("cargo".to_string()),
        entrypoints,
        servers: vec![ServerCandidate {
            command: "cargo run".to_string(),
            source: "Cargo.toml".to_string(),
            confidence: DiscoveryConfidence::Medium,
        }],
        routes,
        providers: discover_providers(root, &files),
        existing_auth: discover_existing_auth(root, &cargo, &files),
        existing_authport: existing_authport(root, &cargo, &files),
        confidence: DiscoveryConfidence::Medium,
    })
}

fn detect_rust_framework(manifest: &str) -> String {
    for (dependency, label) in [
        ("axum", "Axum"),
        ("actix-web", "Actix Web"),
        ("rocket", "Rocket"),
        ("warp", "Warp"),
        ("poem", "Poem"),
        ("salvo", "Salvo"),
        ("tide", "Tide"),
    ] {
        if manifest.contains(dependency) {
            return label.to_string();
        }
    }
    "Rust".to_string()
}

fn discover_rust_routes(source: &str) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    for (needle, method) in [
        ("#[get(\"", "GET"),
        ("#[post(\"", "POST"),
        ("#[put(\"", "PUT"),
        ("#[patch(\"", "PATCH"),
        ("#[delete(\"", "DELETE"),
        (".route(\"", "GET"),
        (".at(\"", "GET"),
    ] {
        let mut rest = source;
        while let Some(index) = rest.find(needle) {
            let after = &rest[index + needle.len()..];
            if let Some(end) = after.find('"') {
                let path = &after[..end];
                if path.starts_with('/') {
                    routes.push(RouteCandidate {
                        method: method.to_string(),
                        path: path.to_string(),
                        source: RouteSource::Rust,
                        capability: None,
                    });
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    routes
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
        "src/main.tsx",
        "src/main.ts",
        "src/main.jsx",
        "src/main.js",
        "src/index.tsx",
        "src/index.jsx",
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
    collect_node_sources(root, root, &mut files, 0);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files.dedup_by(|left, right| left.0 == right.0);
    files
}

fn collect_node_sources(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(PathBuf, String)>,
    depth: usize,
) {
    if depth > 8 || files.len() >= 512 {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if !matches!(
                name,
                "node_modules" | ".git" | "dist" | "build" | ".next" | "coverage" | ".authboundry"
            ) {
                collect_node_sources(root, &path, files, depth + 1);
            }
            continue;
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if !matches!(
            extension,
            "js" | "jsx" | "ts" | "tsx" | "html" | "vue" | "svelte" | "astro" | "py" | "rs"
        ) {
            continue;
        }
        if let Ok(source) = fs::read_to_string(&path) {
            if source.len() <= 1_000_000 && path.starts_with(root) {
                files.push((path, source));
            }
        }
    }
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
    ["start", "dev"]
        .into_iter()
        .filter_map(|script| {
            json_script(package_json, script).map(|command| ServerCandidate {
                command,
                source: format!("package.json scripts.{}", script),
                confidence: DiscoveryConfidence::High,
            })
        })
        .collect()
}

fn discover_existing_auth(
    root: &Path,
    manifest: &str,
    files: &[(PathBuf, String)],
) -> Vec<ExistingAuthSystem> {
    let manifest = manifest.to_ascii_lowercase();
    let source = files
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    let mut systems = Vec::new();
    let products: &[(&str, &str, &[&str])] = &[
        ("clerk", "Clerk", &["@clerk/", "clerk_backend_api"]),
        ("auth0", "Auth0", &["@auth0/", "authlib"]),
        (
            "firebase",
            "Firebase Auth",
            &["firebase/auth", "firebase-admin"],
        ),
        (
            "supabase",
            "Supabase Auth",
            &["@supabase/", "supabase.auth"],
        ),
        (
            "next-auth",
            "Auth.js / NextAuth",
            &["next-auth", "@auth/core"],
        ),
        ("better-auth", "Better Auth", &["better-auth"]),
        ("lucia", "Lucia", &["\"lucia\""]),
        ("passport", "Passport", &["passport"]),
        (
            "django-auth",
            "Django authentication",
            &["django.contrib.auth"],
        ),
        (
            "fastapi-users",
            "FastAPI Users",
            &["fastapi-users", "fastapi_users"],
        ),
    ];
    for (id, display_name, needles) in products {
        let evidence = needles
            .iter()
            .filter(|needle| manifest.contains(**needle) || source.contains(**needle))
            .map(|needle| format!("detected `{}`", needle))
            .collect::<Vec<_>>();
        if !evidence.is_empty() {
            systems.push(ExistingAuthSystem {
                id: (*id).to_string(),
                display_name: (*display_name).to_string(),
                credentials: true,
                sessions: true,
                profiles: matches!(
                    *id,
                    "firebase" | "supabase" | "django-auth" | "fastapi-users"
                ),
                authorization: matches!(*id, "clerk" | "auth0" | "supabase" | "django-auth"),
                coexistence: AuthCoexistence::Bridge,
                evidence,
            });
        }
    }
    let custom_provider = root.join("src/auth/provider.ts").exists()
        || root.join("src/auth/provider.tsx").exists()
        || source.contains("derivepasswordhash(")
        || (source.contains("localstorage") && source.contains("signin("));
    if custom_provider && systems.is_empty() {
        systems.push(ExistingAuthSystem {
            id: "application-auth".to_string(),
            display_name: "Application-owned authentication".to_string(),
            credentials: true,
            sessions: true,
            profiles: source.contains("users") || source.contains("user"),
            authorization: source.contains("role") || source.contains("permission"),
            coexistence: AuthCoexistence::Migrate,
            evidence: vec!["application auth provider/session implementation detected".to_string()],
        });
    }
    systems
}

fn existing_authport(root: &Path, manifest: &str, files: &[(PathBuf, String)]) -> ExistingAuthPort {
    ExistingAuthPort {
        dependency: manifest.contains("\"@authboundry/core\"")
            || manifest.contains("\"authboundry\"")
            || manifest.contains("\"authport\"")
            || manifest.contains("appport-auth-mesh"),
        initialization: files.iter().any(|(_, source)| {
            source.contains("createAuthBoundry(") || source.contains("AuthPortRuntime::new")
        }),
        middleware: files.iter().any(|(_, source)| {
            source.contains("authboundry()")
                || source.contains("authport()")
                || source.contains("app.use(authboundry")
                || source.contains("AuthPortServer::new")
        }),
        configuration: [
            "authboundry.toml",
            "authport.toml",
            "appport.auth",
            "appport.toml",
            "auth.appport",
        ]
        .iter()
        .any(|name| root.join(name).exists()),
        manifest: root.join(".authboundry").join("adoption.json").exists()
            || root.join(".authport").join("adoption.json").exists(),
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
    for needle in [
        "path=\"", "path='", "path: \"", "path: '", "href=\"", "href='",
    ] {
        let quote = needle.chars().last().unwrap();
        let mut rest = source;
        while let Some(index) = rest.find(needle) {
            let after = &rest[index + needle.len()..];
            if let Some(end) = after.find(quote) {
                let path = &after[..end];
                if path.starts_with('/') && !path.starts_with("//") {
                    routes.push(RouteCandidate {
                        method: "GET".to_string(),
                        path: path.to_string(),
                        source: RouteSource::Client,
                        capability: None,
                    });
                }
                rest = &after[end + 1..];
            } else {
                break;
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
        "{{\"kind\": \"{}\", \"capability\": \"{}\", \"resource\": {}, \"confidence\": \"{}\", \"reasons\": [{}]}}",
        inference.kind.as_str(),
        escape(&inference.capability),
        inference
            .resource
            .as_ref()
            .map(resource_inference_json)
            .unwrap_or_else(|| "null".to_string()),
        inference.confidence.as_str(),
        inference
            .reasons
            .iter()
            .map(|reason| format!("\"{}\"", escape(reason)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn resource_inference_json(resource: &ResourceInference) -> String {
    format!(
        "{{\"type\": \"{}\", \"id\": \"{}\", \"action\": \"{}\"}}",
        escape(&resource.resource_type),
        escape(&resource.resource_id),
        escape(&resource.action)
    )
}

fn recommendation_json(recommendation: &AuthorityRecommendation) -> String {
    format!(
        "{{\"id\": {}, \"method\": \"{}\", \"path\": \"{}\", \"action\": \"{}\", \"capability\": {}, \"status\": \"{}\", \"current_authority_state\": \"{}\", \"proposed_authority_state\": \"{}\", \"source\": \"{}\", \"discovery_revision\": {}, \"authority_revision\": {}, \"contract_fingerprint\": \"{}\", \"confidence\": \"{}\", \"reasons\": [{}], \"reason\": \"{}\"}}",
        option_string_json(recommendation.id.as_deref()),
        escape(&recommendation.method),
        escape(&recommendation.path),
        recommendation.action.as_str(),
        option_string_json(recommendation.capability.as_deref()),
        recommendation.status.as_str(),
        escape(&recommendation.current_authority_state),
        escape(&recommendation.proposed_authority_state),
        recommendation.source.as_str(),
        recommendation.discovery_revision,
        recommendation.authority_revision,
        escape(&recommendation.contract_fingerprint),
        recommendation.confidence.as_str(),
        recommendation
            .reasons
            .iter()
            .map(|reason| format!("\"{}\"", escape(reason)))
            .collect::<Vec<_>>()
            .join(", "),
        escape(&recommendation.reason)
    )
}

fn changed_route_json(change: &ChangedRoute) -> String {
    format!(
        "{{\"previous\": {}, \"current\": {}, \"reason\": \"{}\"}}",
        route_json(&change.previous),
        route_json(&change.current),
        escape(&change.reason)
    )
}

fn orphaned_authority_json(item: &OrphanedAuthority) -> String {
    format!(
        "{{\"method\": \"{}\", \"path\": \"{}\", \"capability\": \"{}\", \"reason\": \"{}\"}}",
        escape(&item.method),
        escape(&item.path),
        escape(&item.capability),
        escape(&item.reason)
    )
}

fn proposal_history_json(item: &ProposalHistoryItem) -> String {
    format!(
        "{{\"id\": \"{}\", \"method\": \"{}\", \"path\": \"{}\", \"capability\": \"{}\", \"status\": \"{}\", \"discovery_revision\": {}, \"authority_revision\": {}}}",
        escape(&item.id),
        escape(&item.method),
        escape(&item.path),
        escape(&item.capability),
        escape(&item.status),
        item.discovery_revision,
        item.authority_revision
    )
}

fn drift_item_json(item: &AuthorityDriftItem) -> String {
    format!(
        "{{\"type\": \"{}\", \"route\": \"{}\", \"previous_state\": \"{}\", \"current_state\": \"{}\", \"authority_state\": \"{}\", \"recommended_action\": \"{}\", \"discovery_revision\": {}, \"authority_revision\": {}}}",
        item.kind.as_str(),
        escape(&item.route),
        escape(&item.previous_state),
        escape(&item.current_state),
        escape(&item.authority_state),
        escape(&item.recommended_action),
        item.discovery_revision,
        item.authority_revision
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
    fn detects_dev_script_when_start_is_absent() {
        let dir = temp_dir("dev-script");
        fs::write(
            dir.join("package.json"),
            r#"{"name":"dev-only","scripts":{"dev":"node src/server.js"},"dependencies":{"express":"latest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/health', handler);\n",
        )
        .unwrap();

        let app = discover(&dir).expect("node app discovered");

        assert_eq!(app.servers[0].command, "node src/server.js");
        assert_eq!(app.servers[0].source, "package.json scripts.dev");
    }

    #[test]
    fn discovers_nested_feltdb_vite_client_routes_and_login_pages() {
        let dir = temp_dir("feltdb-vite");
        fs::write(
            dir.join("package.json"),
            r#"{"name":"portal","scripts":{"dev":"feltdb dev"},"dependencies":{"feltdb":"latest","vite":"latest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("src/pages")).unwrap();
        fs::write(
            dir.join("src/main.tsx"),
            r#"<Routes><Route path="/" element={<Home />} /><Route path="/login" element={<Login />} /><a href="/sign-up">Create account</a></Routes>"#,
        )
        .unwrap();
        fs::write(
            dir.join("src/pages/Login.tsx"),
            "export function Login() {}",
        )
        .unwrap();

        let app = discover(&dir).expect("FeltDB Vite app discovered");
        assert_eq!(app.framework.as_deref(), Some("FeltDB"));
        assert_eq!(
            app.entrypoints
                .first()
                .and_then(|entry| entry.path.file_name()),
            Some(std::ffi::OsStr::new("main.tsx"))
        );
        for route in ["/", "/login", "/sign-up"] {
            assert!(
                app.routes.iter().any(|candidate| candidate.path == route),
                "missing {route}"
            );
        }
    }

    #[test]
    fn separates_application_owned_auth_from_profile_data_for_migration() {
        let dir = temp_dir("existing-application-auth");
        fs::write(
            dir.join("package.json"),
            r#"{"name":"portal","dependencies":{"react":"latest","vite":"latest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("src/auth")).unwrap();
        fs::write(
            dir.join("src/auth/provider.ts"),
            "const users = []; async function derivePasswordHash() {} function signIn() { localStorage.setItem('session', 'x'); } const role = 'admin';",
        )
        .unwrap();

        let app = discover(&dir).unwrap();
        assert_eq!(app.existing_auth.len(), 1);
        let auth = &app.existing_auth[0];
        assert_eq!(auth.display_name, "Application-owned authentication");
        assert_eq!(auth.coexistence, AuthCoexistence::Migrate);
        assert!(auth.credentials && auth.sessions && auth.profiles && auth.authorization);
    }

    #[test]
    fn recognizes_major_node_framework_families_from_package_evidence() {
        for (dependency, expected) in [
            ("next", "Next.js"),
            ("@remix-run/react", "Remix"),
            ("nuxt", "Nuxt"),
            ("@sveltejs/kit", "SvelteKit"),
            ("@angular/core", "Angular"),
            ("astro", "Astro"),
            ("gatsby", "Gatsby"),
            ("@nestjs/core", "NestJS"),
            ("fastify", "Fastify"),
            ("hono", "Hono"),
            ("koa", "Koa"),
            ("@hapi/hapi", "Hapi"),
            ("express", "Express"),
            ("react-router-dom", "React Router"),
            ("vue", "Vue"),
            ("react", "React"),
            ("vite", "Vite"),
        ] {
            let dir = temp_dir(&format!("framework-{}", expected.replace(' ', "-")));
            fs::write(
                dir.join("package.json"),
                format!(
                    r#"{{"name":"app","dependencies":{{"{}":"latest"}}}}"#,
                    dependency
                ),
            )
            .unwrap();
            assert_eq!(discover(&dir).unwrap().framework.as_deref(), Some(expected));
        }
    }

    #[test]
    fn derives_routes_from_filesystem_router_conventions() {
        let cases = [
            ("next", "app/invoices/[id]/page.tsx", "/invoices/:id"),
            ("nuxt", "pages/invoices/[id].vue", "/invoices/:id"),
            (
                "@sveltejs/kit",
                "src/routes/invoices/[id]/+page.svelte",
                "/invoices/:id",
            ),
            ("astro", "src/pages/invoices/[id].astro", "/invoices/:id"),
            (
                "@remix-run/react",
                "app/routes/invoices.$id.tsx",
                "/invoices/$id",
            ),
        ];
        for (dependency, file, expected) in cases {
            let dir = temp_dir(&format!(
                "filesystem-{}",
                dependency.replace(['/', '@'], "-")
            ));
            fs::write(
                dir.join("package.json"),
                format!(
                    r#"{{"name":"app","dependencies":{{"{}":"latest"}}}}"#,
                    dependency
                ),
            )
            .unwrap();
            let path = dir.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "export default function Page() {};").unwrap();
            let app = discover(&dir).unwrap();
            assert!(
                app.routes.iter().any(|route| route.path == expected),
                "{} missing {}",
                app.framework.unwrap(),
                expected
            );
        }
    }

    #[test]
    fn recognizes_rust_frameworks_and_route_macros() {
        let dir = temp_dir("rust-axum");
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"api\"\n[dependencies]\naxum = \"0.8\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/main.rs"),
            "Router::new().route(\"/users\", get(users));",
        )
        .unwrap();
        let app = discover(&dir).unwrap();
        assert_eq!(app.framework.as_deref(), Some("Axum"));
        assert!(app.routes.iter().any(|route| route.path == "/users"));
    }

    #[test]
    fn discovers_fastapi_application_and_decorator_routes() {
        let dir = temp_dir("python-fastapi");
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"accounts-api\"\ndependencies = [\"fastapi\", \"uvicorn\"]\n",
        )
        .unwrap();
        fs::write(
            dir.join("main.py"),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/login')\ndef login(): pass\n@app.post(\"/sessions\")\ndef session(): pass\n",
        )
        .unwrap();

        let app = discover(&dir).expect("FastAPI app discovered");
        assert_eq!(app.language.as_deref(), Some("Python"));
        assert_eq!(app.framework.as_deref(), Some("FastAPI"));
        assert_eq!(app.package_manager.as_deref(), Some("pip"));
        assert_eq!(app.servers[0].command, "uvicorn main:app --reload");
        assert!(app
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/login"));
        assert!(app
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/sessions"));
    }

    #[test]
    fn recognizes_major_python_framework_families() {
        for (dependency, expected) in [
            ("django", "Django"),
            ("flask", "Flask"),
            ("starlette", "Starlette"),
            ("litestar", "Litestar"),
            ("sanic", "Sanic"),
            ("falcon", "Falcon"),
            ("quart", "Quart"),
            ("tornado", "Tornado"),
            ("bottle", "Bottle"),
            ("pyramid", "Pyramid"),
        ] {
            let dir = temp_dir(&format!("python-framework-{expected}"));
            fs::write(dir.join("requirements.txt"), format!("{dependency}\n")).unwrap();
            fs::write(dir.join("app.py"), "# application\n").unwrap();
            assert_eq!(discover(&dir).unwrap().framework.as_deref(), Some(expected));
        }
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
        assert_eq!(
            read.resource,
            Some(ResourceInference {
                resource_type: "invoice".to_string(),
                resource_id: "{id}".to_string(),
                action: "read".to_string(),
            })
        );

        let create = infer_capability("POST", "/customers").unwrap();
        assert_eq!(create.capability, "customer.create");
        assert_eq!(create.confidence, Confidence::High);
        assert_eq!(create.resource.as_ref().unwrap().resource_id, "*");

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
            existing_auth: Vec::new(),
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

    fn app_with(routes: Vec<RouteCandidate>) -> ApplicationCandidate {
        ApplicationCandidate {
            root: PathBuf::from("."),
            name: Some("billing-api".to_string()),
            language: Some("Node".to_string()),
            framework: Some("Express".to_string()),
            package_manager: Some("npm".to_string()),
            entrypoints: Vec::new(),
            servers: Vec::new(),
            routes,
            providers: Vec::new(),
            existing_auth: Vec::new(),
            existing_authport: ExistingAuthPort::default(),
            confidence: DiscoveryConfidence::High,
        }
    }

    fn route(method: &str, path: &str) -> RouteCandidate {
        RouteCandidate {
            method: method.to_string(),
            path: path.to_string(),
            source: RouteSource::Express,
            capability: None,
        }
    }

    #[test]
    fn reconciliation_proposes_new_routes_without_mutating_authority() {
        let previous = app_with(vec![route("POST", "/invoices")]);
        let current = app_with(vec![route("POST", "/invoices"), route("POST", "/refunds")]);
        let mut authority = BTreeMap::new();
        authority.insert(
            ("POST".to_string(), "/invoices".to_string()),
            "invoice.create".to_string(),
        );

        let result = AuthorityReconciler::reconcile(
            Some(&previous),
            &current,
            "contract-1",
            7,
            &authority,
            &[],
        );

        assert_eq!(result.authority_revision, 7);
        assert_eq!(result.contract_fingerprint, "contract-1");
        assert_eq!(result.new_routes.len(), 1);
        assert_eq!(result.new_routes[0].path, "/refunds");
        assert_eq!(
            result.new_routes[0]
                .inference
                .as_ref()
                .map(|inference| inference.capability.as_str()),
            Some("refund.create")
        );
        assert_eq!(result.new_authority_proposals.len(), 1);
        assert_eq!(
            result.new_authority_proposals[0].current_authority_state,
            "unprotected"
        );
        assert_eq!(
            result.new_authority_proposals[0].proposed_authority_state,
            "protected"
        );
        assert!(result.drift.iter().any(|item| {
            item.kind == AuthorityDrift::NewRoute && item.route == "POST /refunds"
        }));
        assert!(render_reconciliation_text(&result).contains("No authority was changed."));
    }

    #[test]
    fn reconciliation_orphans_removed_authority_without_deleting_history() {
        let previous = app_with(vec![route("POST", "/billing/charge")]);
        let current = app_with(Vec::new());
        let mut authority = BTreeMap::new();
        authority.insert(
            ("POST".to_string(), "/billing/charge".to_string()),
            "billing.charge".to_string(),
        );

        let result = AuthorityReconciler::reconcile(
            Some(&previous),
            &current,
            "contract-1",
            3,
            &authority,
            &[],
        );

        assert_eq!(authority.len(), 1, "reconciliation is read-only");
        assert_eq!(result.orphaned_authority.len(), 1);
        assert_eq!(result.orphaned_authority[0].capability, "billing.charge");
        assert!(result.drift.iter().any(|item| {
            item.kind == AuthorityDrift::OrphanedAuthority
                && item.authority_state == "retained:billing.charge"
        }));
    }

    #[test]
    fn reconciliation_distinguishes_equivalent_and_meaningful_route_changes() {
        let equivalent_previous = app_with(vec![route("GET", "/invoices/{id}")]);
        let equivalent_current = app_with(vec![route("GET", "/invoices/[id]")]);
        let authority = BTreeMap::new();

        let equivalent = AuthorityReconciler::reconcile(
            Some(&equivalent_previous),
            &equivalent_current,
            "contract-1",
            0,
            &authority,
            &[],
        );
        assert_eq!(equivalent.equivalent_routes.len(), 1);
        assert!(equivalent.changed_routes.is_empty());
        assert!(equivalent.new_routes.is_empty());
        assert!(equivalent.removed_routes.is_empty());

        let changed_previous = app_with(vec![route("POST", "/invoices")]);
        let changed_current = app_with(vec![route("PATCH", "/invoices/:id")]);
        let changed = AuthorityReconciler::reconcile(
            Some(&changed_previous),
            &changed_current,
            "contract-1",
            0,
            &authority,
            &[],
        );
        assert_eq!(changed.changed_routes.len(), 1);
        assert_eq!(changed.changed_routes[0].reason, "HTTP method changed");
        assert!(changed
            .drift
            .iter()
            .any(|item| item.kind == AuthorityDrift::RouteChanged));
    }

    #[test]
    fn reconciliation_surfaces_conflicts_and_is_idempotent() {
        let app = app_with(vec![route("POST", "/invoices")]);
        let mut authority = BTreeMap::new();
        authority.insert(
            ("POST".to_string(), "/invoices".to_string()),
            "invoice.write".to_string(),
        );

        let first = AuthorityReconciler::reconcile(None, &app, "contract-1", 9, &authority, &[]);
        let second = AuthorityReconciler::reconcile(None, &app, "contract-1", 9, &authority, &[]);

        assert_eq!(first, second);
        assert!(first.new_authority_proposals.is_empty());
        assert!(first.drift.iter().any(|item| {
            item.kind == AuthorityDrift::CapabilityConflict
                && item.previous_state == "invoice.write"
                && item.current_state == "invoice.create"
                && item.authority_state == "explicit authority preserved"
        }));
    }
}
