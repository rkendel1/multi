//! The application.
//!
//! Note what is absent: no session lookup, no tenant lookup, no claims
//! loading, no capability calculation, no delegation evaluation, no provider
//! code. Handlers receive an already-authoritative context and get on with the
//! application's own work.

use std::collections::BTreeMap;
use std::sync::Mutex;

use appport_auth_mesh_boundary::{AuthContext, Method, Requirement};
use appport_auth_mesh_server::http::escape;
use appport_auth_mesh_server::proxy::{headers, UpstreamProxy};
use appport_auth_mesh_server::{AppRequest, HttpResponse, RouterApp};

/// What a handler needs to know about the caller.
///
/// Embedded, it is read from the [`AuthContext`] the boundary constructed.
/// Standalone, it is read from the context AuthPort injected into the upstream
/// request. Same fields, same handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppContext {
    pub principal: String,
    pub kind: String,
    pub tenant: String,
    pub claims: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub delegated_by: Option<String>,
}

impl AppContext {
    pub fn from_auth(context: &AuthContext) -> Self {
        let projection = context.project();
        Self {
            principal: projection.principal_id,
            kind: projection.principal_kind,
            tenant: projection.tenant_id,
            claims: projection.claims.into_iter().collect(),
            capabilities: projection.capabilities,
            delegated_by: projection
                .delegation
                .map(|delegation| delegation.delegated_by),
        }
    }

    /// Read the context AuthPort injected, refusing anything unsigned.
    ///
    /// The proxy strips this header vocabulary from inbound requests, so the
    /// only way a signed context arrives here is from AuthPort itself.
    pub fn from_injected(request_headers: &BTreeMap<String, String>, secret: &str) -> Option<Self> {
        let context = request_headers.get(headers::CONTEXT)?;
        let signature = request_headers.get(headers::SIGNATURE)?;
        if !UpstreamProxy::verify(secret, context, signature) {
            return None;
        }

        Some(Self {
            principal: request_headers.get(headers::PRINCIPAL)?.clone(),
            kind: request_headers
                .get(headers::PRINCIPAL_KIND)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            tenant: request_headers.get(headers::TENANT)?.clone(),
            claims: request_headers
                .get(headers::CLAIMS)
                .map(|raw| {
                    raw.split(';')
                        .filter_map(|pair| pair.split_once('='))
                        .map(|(name, value)| (name.to_string(), value.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            capabilities: request_headers
                .get(headers::CAPABILITIES)
                .map(|raw| {
                    raw.split(',')
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            delegated_by: request_headers.get(headers::DELEGATED_BY).cloned(),
        })
    }

    fn to_json(&self) -> String {
        let claims = self
            .claims
            .iter()
            .map(|(name, value)| format!("\"{}\": \"{}\"", escape(name), escape(value)))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{{\"principal\": \"{}\", \"kind\": \"{}\", \"tenant\": \"{}\", \"claims\": {{{}}}, \"delegated_by\": {}}}",
            escape(&self.principal),
            escape(&self.kind),
            escape(&self.tenant),
            claims,
            match &self.delegated_by {
                Some(delegated_by) => format!("\"{}\"", escape(delegated_by)),
                None => "null".to_string(),
            }
        )
    }
}

/// The application's data, kept per tenant because the context says which
/// tenant — the application never resolves one itself.
#[derive(Default)]
pub struct Invoices {
    entries: Mutex<BTreeMap<String, Vec<String>>>,
}

impl Invoices {
    pub fn list(&self, tenant: &str) -> Vec<String> {
        self.entries
            .lock()
            .map(|entries| entries.get(tenant).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    pub fn create(&self, tenant: &str, reference: &str) -> usize {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return 0,
        };
        let tenant_invoices = entries.entry(tenant.to_string()).or_default();
        tenant_invoices.push(reference.to_string());
        tenant_invoices.len()
    }
}

pub fn public_response() -> HttpResponse {
    HttpResponse::json(
        200,
        "{\"public\": true, \"message\": \"anyone may read this\"}",
    )
}

pub fn profile_response(context: &AppContext) -> HttpResponse {
    HttpResponse::json(200, format!("{{\"profile\": {}}}", context.to_json()))
}

pub fn list_invoices_response(invoices: &Invoices, context: &AppContext) -> HttpResponse {
    let entries = invoices
        .list(&context.tenant)
        .iter()
        .map(|reference| format!("\"{}\"", escape(reference)))
        .collect::<Vec<_>>()
        .join(", ");
    HttpResponse::json(
        200,
        format!(
            "{{\"tenant\": \"{}\", \"invoices\": [{}]}}",
            escape(&context.tenant),
            entries
        ),
    )
}

pub fn create_invoice_response(
    invoices: &Invoices,
    context: &AppContext,
    reference: &str,
) -> HttpResponse {
    let count = invoices.create(&context.tenant, reference);
    HttpResponse::json(
        201,
        format!(
            "{{\"created\": \"{}\", \"tenant\": \"{}\", \"count\": {}, \"by\": \"{}\"}}",
            escape(reference),
            escape(&context.tenant),
            count,
            escape(&context.principal)
        ),
    )
}

pub fn charge_response(context: &AppContext) -> HttpResponse {
    HttpResponse::json(
        200,
        format!(
            "{{\"charged\": true, \"tenant\": \"{}\"}}",
            escape(&context.tenant)
        ),
    )
}

/// The application's routes and the authority each one needs — declared once,
/// and used by both deployment modes.
pub fn router(invoices: std::sync::Arc<Invoices>) -> RouterApp {
    let list = invoices.clone();
    let create = invoices;

    RouterApp::new()
        .public(Method::Get, "/public", Box::new(|_| public_response()))
        .authenticated(
            Method::Get,
            "/profile",
            Box::new(|request: &AppRequest<'_>| match request.context() {
                Some(context) => profile_response(&AppContext::from_auth(context)),
                None => HttpResponse::denied(401, "no_context", "no authenticated context"),
            }),
        )
        .require(
            Method::Get,
            "/invoices",
            "invoice.read",
            Box::new(move |request: &AppRequest<'_>| match request.context() {
                Some(context) => list_invoices_response(&list, &AppContext::from_auth(context)),
                None => HttpResponse::denied(401, "no_context", "no authenticated context"),
            }),
        )
        .require(
            Method::Post,
            "/invoices",
            "invoice.create",
            Box::new(move |request: &AppRequest<'_>| match request.context() {
                Some(context) => {
                    let reference = request.field("reference").unwrap_or("INV-1");
                    create_invoice_response(&create, &AppContext::from_auth(context), reference)
                }
                None => HttpResponse::denied(401, "no_context", "no authenticated context"),
            }),
        )
        .require(
            Method::Post,
            "/billing/charge",
            "billing.charge",
            Box::new(|request: &AppRequest<'_>| match request.context() {
                Some(context) => charge_response(&AppContext::from_auth(context)),
                None => HttpResponse::denied(401, "no_context", "no authenticated context"),
            }),
        )
}

/// The requirement table the standalone proxy enforces, taken from the same
/// route declarations the embedded router uses.
pub fn route_requirements(router: &RouterApp) -> Vec<(Method, String, Requirement)> {
    router
        .policy()
        .rules()
        .iter()
        .flat_map(|rule| {
            rule.methods.iter().map(move |method| {
                (
                    *method,
                    match &rule.pattern {
                        appport_auth_mesh_server::PathPattern::Exact(path) => path.clone(),
                        appport_auth_mesh_server::PathPattern::Prefix(prefix) => prefix.clone(),
                    },
                    rule.requirement.clone(),
                )
            })
        })
        .collect()
}
