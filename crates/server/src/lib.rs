//! The AuthPort HTTP surface.
//!
//! ```text
//! Embedded:   application server -> AuthPortRuntime -> handlers
//! Standalone: browser -> AuthPort -> upstream application
//! ```
//!
//! Both placements dispatch through the same [`AuthPortRuntime`], so an
//! authorization answer never depends on where the boundary is running.

pub mod client;
pub mod http;
pub mod proxy;
pub mod router;
pub mod server;
pub mod ui;

pub use client::{cookie_value, send, ClientRequest};
pub use http::{HttpError, HttpRequest, HttpResponse};
pub use proxy::UpstreamProxy;
pub use router::{
    AppHandler, AppRequest, ApplicationBinding, PathPattern, RouteOutcome, RoutePolicy, RouteRule,
    RouterApp,
};
pub use server::{serve, status_for, AuthPortServer, HttpHandler, ServerHandle};
pub use ui::{render_sign_in, CLIENT_JS};
