use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};

use appport_auth_mesh_boundary::{AuthContext, BoundaryRequest, Method, RESERVED_HEADER_PREFIX};
use appport_auth_mesh_dsl::stable_hash;

use crate::client::{send_upstream, ClientRequest};
use crate::http::{HttpRequest, HttpResponse};
use crate::router::{ApplicationBinding, RouteOutcome, RoutePolicy};
use crate::upstream::ApplicationUpstream;

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
    pub const PROXY_SIGNATURE: &str = "x-authboundry-proxy-signature";
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
    upstream: ApplicationUpstream,
    policy: RoutePolicy,
    secret: String,
}

impl UpstreamProxy {
    pub fn new(
        upstream: impl Into<ApplicationUpstream>,
        policy: RoutePolicy,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            upstream: upstream.into(),
            policy,
            secret: secret.into(),
        }
    }

    pub fn upstream(&self) -> &ApplicationUpstream {
        &self.upstream
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
        let mut headers = vec![(
            headers::PROXY_SIGNATURE.to_string(),
            Self::sign(&self.secret, "proxy"),
        )];
        let Some(context) = context else {
            return headers;
        };

        let projection = context.project();
        let serialized = projection.to_json();
        headers.extend([
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
        ]);

        if let Some(delegation) = &projection.delegation {
            headers.push((headers::DELEGATION.to_string(), delegation.id.clone()));
            headers.push((
                headers::DELEGATED_BY.to_string(),
                delegation.delegated_by.clone(),
            ));
        }

        headers
    }

    fn tunnel_websocket(
        &self,
        request: &HttpRequest,
        context: Option<&AuthContext>,
        mut client: TcpStream,
    ) -> Result<(), String> {
        if self.upstream.scheme != crate::upstream::UpstreamScheme::Http {
            return Err("WebSocket tunneling currently requires a local HTTP upstream".to_string());
        }
        let mut upstream = self.upstream.connect(std::time::Duration::from_secs(3))?;
        let mut head = format!(
            "{} {} HTTP/1.1\r\nhost: {}\r\n",
            request.method.as_str(),
            request.target,
            self.upstream.authority()
        );
        for (name, value) in &request.headers {
            if name.starts_with(RESERVED_HEADER_PREFIX)
                || matches!(name.as_str(), "host" | "content-length")
            {
                continue;
            }
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        for (name, value) in self.injected_headers(context) {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        head.push_str("\r\n");
        upstream
            .write_all(head.as_bytes())
            .and_then(|_| upstream.flush())
            .map_err(|err| format!("cannot open upstream WebSocket: {}", err))?;

        let mut response_head = Vec::new();
        let mut byte = [0u8; 1];
        while response_head.len() < 65_536 && !response_head.ends_with(b"\r\n\r\n") {
            upstream
                .read_exact(&mut byte)
                .map_err(|err| format!("cannot read upstream WebSocket response: {}", err))?;
            response_head.push(byte[0]);
        }
        if !response_head.starts_with(b"HTTP/1.1 101 ")
            && !response_head.starts_with(b"HTTP/1.0 101 ")
        {
            return Err("upstream refused the WebSocket upgrade".to_string());
        }
        client
            .write_all(&response_head)
            .and_then(|_| client.flush())
            .map_err(|err| format!("cannot confirm WebSocket upgrade: {}", err))?;

        let mut upstream_read = upstream
            .try_clone()
            .map_err(|err| format!("cannot clone upstream WebSocket: {}", err))?;
        let mut client_write = client
            .try_clone()
            .map_err(|err| format!("cannot clone client WebSocket: {}", err))?;
        let downstream = std::thread::spawn(move || {
            let _ = std::io::copy(&mut upstream_read, &mut client_write);
            let _ = client_write.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut client, &mut upstream);
        let _ = upstream.shutdown(Shutdown::Write);
        let _ = downstream.join();
        Ok(())
    }
}

impl ApplicationBinding for UpstreamProxy {
    fn resolve(&self, method: Method, path: &str) -> RouteOutcome {
        self.policy.resolve(method, path)
    }

    fn handle(&self, request: &BoundaryRequest, context: Option<&AuthContext>) -> HttpResponse {
        let mut target = request.path.clone();
        if !request.query.is_empty() {
            target.push('?');
            target.push_str(
                &request
                    .query
                    .iter()
                    .map(|(name, value)| {
                        format!("{}={}", percent_encode(name), percent_encode(value))
                    })
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        let mut forwarded = ClientRequest::new(request.method, target);

        // Rebuild the header set: everything the client sent except AuthPort's
        // own vocabulary, plus the context the boundary derived.
        for (name, value) in &request.headers {
            if name.starts_with(RESERVED_HEADER_PREFIX)
                || matches!(
                    name.as_str(),
                    "content-length"
                        | "connection"
                        | "host"
                        | "if-none-match"
                        | "if-modified-since"
                        | "if-match"
                        | "if-unmodified-since"
                        | "if-range"
                )
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

        match send_upstream(&self.upstream, &forwarded) {
            Ok(mut response) => {
                if request.path.starts_with("/src/")
                    || request.path.starts_with("/@vite/")
                    || request.path.starts_with("/node_modules/")
                {
                    response.headers.retain(|(name, _)| {
                        !matches!(name.as_str(), "etag" | "last-modified" | "cache-control")
                    });
                    response
                        .headers
                        .push(("cache-control".to_string(), "no-store".to_string()));
                }
                response
            }
            Err(err) => HttpResponse::denied(502, "upstream_unavailable", &err.message),
        }
    }

    fn upgrade(
        &self,
        request: &HttpRequest,
        context: Option<&AuthContext>,
        stream: TcpStream,
    ) -> bool {
        self.tunnel_websocket(request, context, stream).is_ok()
    }
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
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
