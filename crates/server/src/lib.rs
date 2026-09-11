//! The AuthBoundry HTTP surface.
//!
//! ```text
//! Embedded:   application server -> AuthBoundryRuntime -> handlers
//! Standalone: browser -> AuthBoundry -> upstream application
//! ```
//!
//! Both placements dispatch through the same authority runtime, so an
//! authorization answer never depends on where the boundary is running.

pub mod client;
pub mod control_routes;
pub mod control_types;
pub mod http;
pub mod mailport;
pub mod proxy;
pub mod router;
pub mod server;
pub mod ui;
pub mod upstream;

pub use client::{cookie_value, send, send_upstream, ClientRequest};
pub use control_types::{ApplicationDescription, RouteDescription, RouteProtection};
pub use http::{HttpError, HttpRequest, HttpResponse, JsonValue};
pub use mailport::RemoteMailPort;
pub use proxy::UpstreamProxy;
pub use router::{
    AppHandler, AppRequest, ApplicationBinding, PathPattern, RouteOutcome, RoutePolicy, RouteRule,
    RouterApp,
};
pub use server::{
    serve, should_redirect_to_login, status_for, AuthPortServer, HttpHandler, ServerHandle,
    StudioController,
};

/// Canonical public name for the AuthBoundry HTTP server.
///
/// `AuthPortServer` remains available for compatibility.
pub type AuthBoundryServer = AuthPortServer;
pub use ui::{render_sign_in, CLIENT_JS};
pub use upstream::{ApplicationUpstream, UpstreamScheme};
