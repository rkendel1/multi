//! The AuthPort auth declaration language.
//!
//! `use auth { ... }` is a statement of *what* identity and authority an
//! application needs. Sessions, tables, callbacks, middleware and delivery are
//! owned by the auth capability, never declared here.

pub mod model;
pub mod parser;

pub use model::{
    stable_hash, AuthConfig, AuthConfigError, AuthUiConfig, AuthUiMode, ClaimDef, ClaimKind,
    IsolationMode, UiScreen, UiScreenOverride, UiTheme,
};
pub use parser::{parse_auth_block, AuthDslError};
