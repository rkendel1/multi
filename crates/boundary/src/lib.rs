//! The AuthBoundry backend boundary.
//!
//! ```text
//! request
//!   -> credential -> AuthBoundry -> principal -> tenant -> claims
//!   -> delegation -> capabilities -> authorization -> application handler
//! ```
//!
//! One authority model, two placements: embed it when you own the application
//! server, run it in front of the application when you do not.

pub mod boundary;
pub mod ceremony;
pub mod clock;
pub mod context;
pub mod control;
pub mod proposal_store;
pub mod request;
pub mod runtime;

pub use boundary::{AuthBoundary, Requirement};
pub use ceremony::{CeremonyKind, MailMessage, MailPort, MemoryMailPort};
pub use clock::{Clock, SystemClock, TestClock};
pub use context::{AuthContext, ClientAuthContext, ClientDelegation, DelegationContext};
pub use control::{
    ApplyOutcome, Approval, AuthorityChange, ChangeProposal, LiveAuthorityState, Preview, RouteId,
    RouteProtection,
};
pub use proposal_store::{
    ChangeRecord, MemoryProposalStore, ProposalDecision, ProposalMetadata, ProposalSource,
    ProposalStatus, ProposalStore, StoredProposal,
};
pub use request::{BoundaryRequest, Method, SessionCredential, RESERVED_HEADER_PREFIX};
pub use runtime::{AuthPortRuntime, BindingMode, RegistrationPolicy, SignInOutcome};

/// Canonical public name for the AuthBoundry authority runtime.
///
/// `AuthPortRuntime` remains available as a compatibility alias.
pub type AuthBoundryRuntime = AuthPortRuntime;
