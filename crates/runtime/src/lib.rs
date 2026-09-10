//! The AuthPort auth runtime.
//!
//! ```text
//! use auth { ... }
//!      -> AuthConfig -> ConnectorRegistry -> ExternalIdentity
//!      -> Principal  -> Tenant -> Session -> Claims
//!      -> Authorization -> CapabilityEnvelope -> RuntimeContext
//! ```

pub mod capability_envelope;
pub mod claims;
pub mod context;
pub mod error;
pub mod injection;
pub mod memory_stores;
pub mod mesh;
pub mod policy_store;
pub mod resolution;

pub use context::RuntimeContext;
pub use error::{AuthError, AuthLifecycleStage};
pub use injection::{inject_auth_context, IncomingRequest};
pub use memory_stores::MemoryStores;
pub use mesh::{
    AuthMesh, AuthenticatedSession, DelegationRequest, MeshStores, Registration,
    RunCreationRequest, DEFAULT_SESSION_TTL_SECONDS,
};
pub use policy_store::{MemoryPolicyStore, PolicyStore};
pub use resolution::{principal_id_for, ResolvedPrincipal};
