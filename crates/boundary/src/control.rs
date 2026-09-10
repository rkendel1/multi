use crate::request::Method;
use appport_auth_mesh_authz::Policy;
use std::collections::BTreeMap;

/// Route identifier: (method, path) pair
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteId {
    pub method: Method,
    pub path: String,
}

impl RouteId {
    pub fn new(method: Method, path: String) -> Self {
        Self { method, path }
    }
}

/// What authorization is currently required for a route
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProtection {
    pub capability: Option<String>,
}

/// Current state of a provider (enabled/disabled)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderState {
    pub enabled: bool,
}

/// Live authority state: overlays the immutable contract
/// The contract defines what exists; this defines what is currently permitted
#[derive(Debug, Clone)]
pub struct LiveAuthorityState {
    /// Which routes require which capabilities
    pub route_protection: BTreeMap<RouteId, RouteProtection>,
    /// Current policy for each capability
    pub capability_policies: BTreeMap<String, Policy>,
    /// Current enabled/disabled state for each provider
    pub provider_state: BTreeMap<String, ProviderState>,
    /// Monotonic revision number; increments on each change
    pub revision: u64,
}

impl LiveAuthorityState {
    pub fn new() -> Self {
        Self {
            route_protection: BTreeMap::new(),
            capability_policies: BTreeMap::new(),
            provider_state: BTreeMap::new(),
            revision: 0,
        }
    }

    /// Create a new state with incremented revision
    fn next_revision(&self) -> u64 {
        self.revision + 1
    }
}

impl Default for LiveAuthorityState {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutations to live authority state (validated against immutable contract)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityChange {
    /// Add or update route protection
    ProtectRoute {
        method: Method,
        path: String,
        capability: String,
    },

    /// Remove route protection
    UnprotectRoute { method: Method, path: String },

    /// Set policy for a capability
    SetCapabilityPolicy { capability: String, policy: Policy },

    /// Enable or disable a provider
    SetProviderEnabled { provider: String, enabled: bool },

    /// Revert a previously applied change.
    Revert { change_id: String },
}

impl AuthorityChange {
    pub fn change_type(&self) -> &'static str {
        match self {
            Self::ProtectRoute { .. } => "protect_route",
            Self::UnprotectRoute { .. } => "unprotect_route",
            Self::SetCapabilityPolicy { .. } => "set_capability_policy",
            Self::SetProviderEnabled { .. } => "set_provider_enabled",
            Self::Revert { .. } => "revert",
        }
    }
}

/// Preview of what would change
#[derive(Debug, Clone)]
pub struct Preview {
    pub before: PreviewState,
    pub after: PreviewState,
}

/// Snapshot of authority state for display
#[derive(Debug, Clone)]
pub struct PreviewState {
    pub route_protection: BTreeMap<RouteId, RouteProtection>,
    pub capability_policies: BTreeMap<String, Policy>,
    pub provider_state: BTreeMap<String, ProviderState>,
}

impl From<&LiveAuthorityState> for PreviewState {
    fn from(state: &LiveAuthorityState) -> Self {
        Self {
            route_protection: state.route_protection.clone(),
            capability_policies: state.capability_policies.clone(),
            provider_state: state.provider_state.clone(),
        }
    }
}

/// Explicit approval for a change (not cryptographic yet; development token)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Deterministic token computed from proposal for this development phase
    pub token: String,
}

impl Approval {
    /// Create approval token from change proposal (deterministic for dev)
    pub fn for_proposal(proposal: &ChangeProposal) -> Self {
        // For now, use a stable hash of the proposal
        // In production, this would be a real cryptographic signature
        let token = format!("dev-approval-{}", stable_hash(&proposal.change));
        Self { token }
    }

    /// Verify that this approval was created for the given proposal
    pub fn verify(&self, proposal: &ChangeProposal) -> bool {
        let expected = Approval::for_proposal(proposal);
        self.token == expected.token
    }
}

/// Stable hash for deterministic approval tokens
fn stable_hash(change: &AuthorityChange) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    // Manually hash to ensure stability
    match change {
        AuthorityChange::ProtectRoute {
            method,
            path,
            capability,
        } => {
            "ProtectRoute".hash(&mut hasher);
            method.as_str().hash(&mut hasher);
            path.hash(&mut hasher);
            capability.hash(&mut hasher);
        }
        AuthorityChange::UnprotectRoute { method, path } => {
            "UnprotectRoute".hash(&mut hasher);
            method.as_str().hash(&mut hasher);
            path.hash(&mut hasher);
        }
        AuthorityChange::SetCapabilityPolicy { capability, policy } => {
            "SetCapabilityPolicy".hash(&mut hasher);
            capability.hash(&mut hasher);
            format!("{:?}", policy).hash(&mut hasher);
        }
        AuthorityChange::SetProviderEnabled { provider, enabled } => {
            "SetProviderEnabled".hash(&mut hasher);
            provider.hash(&mut hasher);
            enabled.hash(&mut hasher);
        }
        AuthorityChange::Revert { change_id } => {
            "Revert".hash(&mut hasher);
            change_id.hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// Proposed change with validation result
#[derive(Debug, Clone)]
pub struct ChangeProposal {
    pub id: String,
    pub change: AuthorityChange,
    pub preview: Preview,
    pub revision: u64,
}

/// Result of applying a change
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub change_id: String,
    pub applied_at: std::time::SystemTime,
    pub new_revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_token_is_deterministic() {
        let change = AuthorityChange::ProtectRoute {
            method: Method::Post,
            path: "/invoices".to_string(),
            capability: "invoice.create".to_string(),
        };

        let current_state = LiveAuthorityState::new();
        let after_state = apply_change(&current_state, &change).unwrap();

        let proposal = ChangeProposal {
            id: "proposal-test".to_string(),
            change,
            preview: Preview {
                before: PreviewState::from(&current_state),
                after: PreviewState::from(&after_state),
            },
            revision: 0,
        };

        let approval1 = Approval::for_proposal(&proposal);
        let approval2 = Approval::for_proposal(&proposal);

        assert_eq!(approval1, approval2);
        assert!(approval1.verify(&proposal));
    }
}

/// Apply a change to authority state (returns new state, immutable contract unchanged)
pub fn apply_change(
    current: &LiveAuthorityState,
    change: &AuthorityChange,
) -> Result<LiveAuthorityState, String> {
    let mut next = current.clone();
    next.revision = current.next_revision();

    match change {
        AuthorityChange::ProtectRoute {
            method,
            path,
            capability,
        } => {
            let route_id = RouteId::new(method.clone(), path.clone());
            next.route_protection.insert(
                route_id,
                RouteProtection {
                    capability: Some(capability.clone()),
                },
            );
        }
        AuthorityChange::UnprotectRoute { method, path } => {
            let route_id = RouteId::new(method.clone(), path.clone());
            next.route_protection.remove(&route_id);
        }
        AuthorityChange::SetCapabilityPolicy { capability, policy } => {
            next.capability_policies
                .insert(capability.clone(), policy.clone());
        }
        AuthorityChange::SetProviderEnabled { provider, enabled } => {
            next.provider_state
                .insert(provider.clone(), ProviderState { enabled: *enabled });
        }
        AuthorityChange::Revert { .. } => {
            return Err("revert requires an applied change record".to_string());
        }
    }

    Ok(next)
}

pub fn apply_revert_change(
    current: &LiveAuthorityState,
    change_id: &str,
    record: &crate::proposal_store::ChangeRecord,
) -> Result<LiveAuthorityState, String> {
    if record.change_id != change_id {
        return Err("revert change id does not match the stored record".to_string());
    }
    if current.revision < record.resulting_state.revision {
        return Err("cannot revert against an older authority state".to_string());
    }

    let mut next = record.previous_state.clone();
    next.revision = current.next_revision();
    Ok(next)
}
