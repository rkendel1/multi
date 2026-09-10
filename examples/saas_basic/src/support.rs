//! Calling the application, however it is deployed.
//!
//! The same calls run against an embedded AuthBoundry (in process) and a
//! standalone one (over a socket), which is what makes the two modes
//! comparable.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use appport_auth_mesh_boundary::Method;
use appport_auth_mesh_server::http::{HttpRequest, HttpResponse};
use appport_auth_mesh_server::{cookie_value, send, AuthPortServer, ClientRequest};
use appport_auth_mesh_surface::BoundarySurface;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub method: Method,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Call {
    pub fn get(path: &str) -> Self {
        Self {
            method: Method::Get,
            path: path.to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    pub fn post(path: &str, body: &str) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            method: Method::Post,
            path: path.to_string(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .insert(name.to_ascii_lowercase(), value.to_string());
        self
    }

    pub fn with_session(self, credential: &str) -> Self {
        self.with_header(
            "cookie",
            &format!("{}={}", BoundarySurface::SESSION_COOKIE, credential),
        )
    }

    pub fn to_http(&self) -> HttpRequest {
        HttpRequest::assemble(
            self.method,
            self.path.clone(),
            self.headers.clone(),
            self.body.clone(),
        )
    }
}

/// How a caller reaches AuthBoundry.
pub trait Transport {
    fn call(&self, call: &Call) -> HttpResponse;
    fn label(&self) -> &'static str;
}

/// Embedded: AuthBoundry is bound to the application's own server, so the request
/// never leaves the process.
pub struct EmbeddedTransport(pub Arc<AuthPortServer>);

impl Transport for EmbeddedTransport {
    fn call(&self, call: &Call) -> HttpResponse {
        self.0.handle(&call.to_http())
    }

    fn label(&self) -> &'static str {
        "embedded"
    }
}

/// Standalone: AuthBoundry owns the socket and the application sits behind it.
pub struct HttpTransport(pub SocketAddr);

impl Transport for HttpTransport {
    fn call(&self, call: &Call) -> HttpResponse {
        let mut request = ClientRequest::new(call.method, call.path.clone());
        for (name, value) in &call.headers {
            request = request.with_header(name, value.clone());
        }
        request.body = call.body.clone();
        send(self.0, &request)
            .unwrap_or_else(|err| HttpResponse::denied(502, "transport_error", &err.message))
    }

    fn label(&self) -> &'static str {
        "standalone"
    }
}

/// Read a named field out of a JSON response body, at any depth.
///
/// Responses nest (`{"profile": {"tenant": ...}}`), and assertions read the
/// leaf they care about.
pub fn field(response: &HttpResponse, name: &str) -> Option<String> {
    let body = response.body_string();
    let needle = format!("\"{}\"", name);
    let mut from = 0usize;

    while let Some(offset) = body[from..].find(&needle) {
        let after_key = from + offset + needle.len();
        let rest = body[after_key..].trim_start();
        if let Some(value) = rest.strip_prefix(':') {
            let value = value.trim_start();
            return match value.strip_prefix('"') {
                Some(quoted) => quoted.find('"').map(|end| quoted[..end].to_string()),
                None => {
                    let end = value.find([',', '}', ']']).unwrap_or(value.len());
                    Some(value[..end].trim().to_string())
                }
            };
        }
        from = after_key;
    }

    None
}

pub fn reason(response: &HttpResponse) -> String {
    field(response, "reason").unwrap_or_default()
}

/// The session credential a sign-in issued.
pub fn session_credential(response: &HttpResponse) -> Option<String> {
    cookie_value(response, BoundarySurface::SESSION_COOKIE)
}

pub fn sign_in(
    transport: &dyn Transport,
    tenant: &str,
    username: &str,
    password: &str,
) -> HttpResponse {
    transport.call(&Call::post(
        "/auth/sign-in",
        &format!(
            "{{\"tenant\": \"{}\", \"connector\": \"local\", \"username\": \"{}\", \"password\": \"{}\"}}",
            tenant, username, password
        ),
    ))
}
