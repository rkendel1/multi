//! The AuthPort backend boundary.
//!
//! ```text
//! request
//!   -> credential -> AuthPort -> principal -> tenant -> claims
//!   -> delegation -> capabilities -> authorization -> application handler
//! ```
//!
//! One authority model, two placements: embed it when you own the application
//! server, run it in front of the application when you do not.

pub mod boundary;
pub mod clock;
pub mod context;
pub mod request;
pub mod runtime;

pub use boundary::{AuthBoundary, Requirement};
pub use clock::{Clock, SystemClock, TestClock};
pub use context::{AuthContext, ClientAuthContext, ClientDelegation, DelegationContext};
pub use request::{BoundaryRequest, Method, SessionCredential, RESERVED_HEADER_PREFIX};
pub use runtime::{AuthPortRuntime, BindingMode, RegistrationPolicy, SignInOutcome};
