use appport_auth_mesh_authz::AuthorizationDecision;
use appport_auth_mesh_runtime::AuthError;

use crate::context::AuthContext;
use crate::request::BoundaryRequest;

/// The framework-neutral backend boundary.
///
/// Nothing here knows about HTTP, Axum, Express or FastAPI. An adapter for any
/// of those turns its own request type into a [`BoundaryRequest`] and gets back
/// authority; the authority model itself stays uncoupled.
pub trait AuthBoundary {
    /// Reconstruct the authoritative context for a request, or refuse it.
    fn authenticate(&self, request: &BoundaryRequest) -> Result<AuthContext, AuthError>;

    /// Ask the one policy engine whether this context may do this thing.
    fn authorize(
        &self,
        context: &AuthContext,
        capability: &str,
    ) -> Result<AuthorizationDecision, AuthError>;
}

/// What a route demands of a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    /// No authority needed. A credential, if present, is resolved for
    /// convenience but never consulted for a decision.
    Public,
    /// A live session, whoever it belongs to.
    Authenticated,
    /// A live session that holds this capability.
    Capability(String),
}

impl Requirement {
    pub fn capability(name: impl Into<String>) -> Self {
        Self::Capability(name.into())
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Public => "public".to_string(),
            Self::Authenticated => "authenticated".to_string(),
            Self::Capability(capability) => capability.clone(),
        }
    }
}
