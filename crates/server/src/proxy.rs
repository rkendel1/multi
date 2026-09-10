use std::collections::BTreeMap;
use std::net::SocketAddr;

use appport_auth_mesh_boundary::{AuthContext, BoundaryRequest, Method, RESERVED_HEADER_PREFIX};
use appport_auth_mesh_dsl::stable_hash;

use crate::client::{send, ClientRequest};
use crate::http::HttpResponse;
use crate::router::{ApplicationBinding, RouteOutcome, RoutePolicy};

/// Header names AuthPort injects into an upstream request.
pub mod headers {
    pub const PRINCIPAL: &str = "x-authboundry-principal";
    pub const PRINCIPAL_KIND: &str = "x-authboundry-principal-kind";
    pub const TENANT: &str = "x-authboundry-tenant";
    pub const CLAIMS: &str = "x-authboundry-claims";
    pub const CAPABILITIES: &str = "x-authboundry-capabilities";
    pub const DELEGATION: &str = "x-authboundry-delegation";
    pub const DELEGATED_BY: &str = "x-authboundry-delegated-by";
    pub const CONTEXT: &str = "x-authboundry-context";
    pub const SIGNATURE: &str = "x-authboundry-signature";
}

/// The standalone placement: AuthPort owns the socket and the application sits
/// behind it, implementing no authentication of its own.
///
/// ```text
/// Browser -> AuthPort -> Example Application
/// ```
///
/// Inbound requests are stripped of AuthPort's header vocabulary before they
/// are looked at, so a client cannot inject the context it wants; the context
/// forwarded upstream is the one the boundary derived.
pub struct UpstreamProxy {
    upstream: SocketAddr,
    policy: RoutePolicy,
    secret: String,
}

impl UpstreamProxy {
    pub fn new(upstream: SocketAddr, policy: RoutePolicy, secret: impl Into<String>) -> Self {
        Self {
            upstream,
            policy,
            secret: secret.into(),
        }
    }

    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// Sign the injected context.
    ///
    /// A keyed digest, not a MAC: it is enough to keep an upstream from
    /// accepting context that did not come from this proxy on a trusted
    /// network, and a production deployment replaces it with a real MAC or
    /// mutual TLS.
    pub fn sign(secret: &str, context: &str) -> String {
        format!(
            "{:016x}",
            stable_hash(format!("{}|{}", secret, context).as_bytes())
        )
    }

    /// For the upstream application: confirm the context came from AuthPort.
    pub fn verify(secret: &str, context: &str, signature: &str) -> bool {
        Self::sign(secret, context) == signature
    }

    fn injected_headers(&self, context: Option<&AuthContext>) -> Vec<(String, String)> {
        let Some(context) = context else {
            return Vec::new();
        };

        let projection = context.project();
        let serialized = projection.to_json();
        let mut headers = vec![
            (
                headers::PRINCIPAL.to_string(),
                projection.principal_id.clone(),
            ),
            (
                headers::PRINCIPAL_KIND.to_string(),
                projection.principal_kind.clone(),
            ),
            (headers::TENANT.to_string(), projection.tenant_id.clone()),
            (
                headers::CLAIMS.to_string(),
                projection
                    .claims
                    .iter()
                    .map(|(name, value)| format!("{}={}", name, value))
                    .collect::<Vec<_>>()
                    .join(";"),
            ),
            (
                headers::CAPABILITIES.to_string(),
                projection.capabilities.join(","),
            ),
            (
                headers::SIGNATURE.to_string(),
                Self::sign(&self.secret, &serialized),
            ),
            (headers::CONTEXT.to_string(), serialized),
        ];

        if let Some(delegation) = &projection.delegation {
            headers.push((headers::DELEGATION.to_string(), delegation.id.clone()));
            headers.push((
                headers::DELEGATED_BY.to_string(),
                delegation.delegated_by.clone(),
            ));
        }

        headers
    }
}

impl ApplicationBinding for UpstreamProxy {
    fn resolve(&self, method: Method, path: &str) -> RouteOutcome {
        self.policy.resolve(method, path)
    }

    fn handle(&self, request: &BoundaryRequest, context: Option<&AuthContext>) -> HttpResponse {
        let mut forwarded = ClientRequest::new(request.method, request.path.clone());

        // Rebuild the header set: everything the client sent except AuthPort's
        // own vocabulary, plus the context the boundary derived.
        for (name, value) in &request.headers {
            if name.starts_with(RESERVED_HEADER_PREFIX)
                || matches!(name.as_str(), "content-length" | "connection" | "host")
            {
                continue;
            }
            forwarded = forwarded.with_header(name, value.clone());
        }
        for (name, value) in self.injected_headers(context) {
            forwarded = forwarded.with_header(&name, value);
        }

        forwarded.body = encode_body(&request.body);
        if !forwarded.body.is_empty() && !request.headers.contains_key("content-type") {
            forwarded = forwarded.with_header("content-type", "application/json");
        }

        match send(self.upstream, &forwarded) {
            Ok(response) => response,
            Err(err) => HttpResponse::denied(502, "upstream_unavailable", &err.message),
        }
    }
}

fn encode_body(body: &BTreeMap<String, String>) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let fields = body
        .iter()
        .map(|(name, value)| {
            format!(
                "\"{}\": \"{}\"",
                crate::http::escape(name),
                crate::http::escape(value)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{}}}", fields).into_bytes()
}
