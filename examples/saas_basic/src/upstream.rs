//! The application server, in standalone deployments.
//!
//! ```text
//! Browser -> AuthBoundry -> this
//! ```
//!
//! It has no connectors, no sessions, no policy and no user table. It reads the
//! context AuthBoundry injected and refuses anything that did not come through the
//! boundary.

use std::sync::Arc;

use appport_auth_mesh_boundary::Method;
use appport_auth_mesh_server::http::{parse_flat_json, HttpRequest, HttpResponse};
use appport_auth_mesh_server::HttpHandler;

use crate::app::{
    charge_response, create_invoice_response, list_invoices_response, profile_response,
    public_response, AppContext, Invoices,
};

pub struct UpstreamApp {
    invoices: Arc<Invoices>,
    secret: String,
}

impl UpstreamApp {
    pub fn new(invoices: Arc<Invoices>, secret: impl Into<String>) -> Self {
        Self {
            invoices,
            secret: secret.into(),
        }
    }

    fn context(&self, request: &HttpRequest) -> Option<AppContext> {
        AppContext::from_injected(&request.headers, &self.secret)
    }
}

impl HttpHandler for UpstreamApp {
    fn handle(&self, request: &HttpRequest) -> HttpResponse {
        match (request.method, request.path.as_str()) {
            (Method::Get, "/public") => public_response(),
            (Method::Get, "/profile") => match self.context(request) {
                Some(context) => profile_response(&context),
                None => unauthenticated(),
            },
            (Method::Get, "/invoices") => match self.context(request) {
                Some(context) => list_invoices_response(&self.invoices, &context),
                None => unauthenticated(),
            },
            (Method::Post, "/invoices") => match self.context(request) {
                Some(context) => {
                    let body = parse_flat_json(&String::from_utf8_lossy(&request.body));
                    let reference = body
                        .get("reference")
                        .map(String::as_str)
                        .unwrap_or("INV-1")
                        .to_string();
                    create_invoice_response(&self.invoices, &context, &reference)
                }
                None => unauthenticated(),
            },
            (Method::Post, "/billing/charge") => match self.context(request) {
                Some(context) => charge_response(&context),
                None => unauthenticated(),
            },
            _ => HttpResponse::denied(404, "no_route", "no such route"),
        }
    }
}

/// The application's only security rule: if AuthBoundry did not vouch for this
/// request, it is not served.
fn unauthenticated() -> HttpResponse {
    HttpResponse::denied(
        403,
        "no_authboundry_context",
        "this application is only reachable through AuthBoundry",
    )
}
