use std::collections::BTreeMap;

use appport_auth_mesh_contract::SessionId;
use appport_auth_mesh_surface::BoundarySurface;

/// Headers a client is never allowed to speak.
///
/// A standalone deployment injects the resolved context into the upstream
/// request using this prefix, so anything arriving from outside carrying it is
/// stripped before the request is looked at.
pub const RESERVED_HEADER_PREFIX: &str = "x-authboundry-";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            _ => None,
        }
    }
}

/// A request as the authority model sees it: framework-neutral, and carrying
/// nothing that is trusted on its own.
///
/// Everything here is a *hint*. The authoritative principal, tenant, claims and
/// capabilities are reconstructed from AuthPort's own state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryRequest {
    pub method: Method,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub body: BTreeMap<String, String>,
}

impl Default for BoundaryRequest {
    fn default() -> Self {
        Self {
            method: Method::Get,
            path: "/".to_string(),
            headers: BTreeMap::new(),
            cookies: BTreeMap::new(),
            query: BTreeMap::new(),
            body: BTreeMap::new(),
        }
    }
}

impl BoundaryRequest {
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            ..Self::default()
        }
    }

    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::Get, path)
    }

    pub fn post(path: impl Into<String>) -> Self {
        Self::new(Method::Post, path)
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.to_ascii_lowercase(), value.into());
        self
    }

    pub fn with_cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.cookies.insert(name.into(), value.into());
        self
    }

    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.body.insert(name.into(), value.into());
        self
    }

    pub fn with_credential(self, credential: &SessionCredential) -> Self {
        self.with_cookie(BoundarySurface::SESSION_COOKIE, credential.encode())
    }

    /// Drop anything the client tried to say in AuthPort's own vocabulary.
    pub fn sanitized(mut self) -> Self {
        self.headers
            .retain(|name, _| !name.starts_with(RESERVED_HEADER_PREFIX));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.body
            .get(name)
            .or_else(|| self.query.get(name))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }

    /// The session credential, from the cookie the boundary issued or from a
    /// bearer token carrying the same value.
    pub fn credential(&self) -> Option<SessionCredential> {
        let raw = self
            .cookies
            .get(BoundarySurface::SESSION_COOKIE)
            .cloned()
            .or_else(|| {
                self.header("authorization")
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .map(|value| value.to_string())
            })?;
        SessionCredential::parse(&raw)
    }

    /// A tenant the caller claims to be addressing. It is only ever checked
    /// against the tenant the session actually belongs to.
    pub fn tenant_hint(&self) -> Option<&str> {
        self.header("x-tenant-id").or_else(|| self.field("tenant"))
    }
}

/// The opaque handle the boundary issues at sign-in.
///
/// The tenant segment makes the session addressable without asking the client
/// which tenant it belongs to; it is re-verified against stored state on every
/// request, so presenting another tenant's session id is a denial rather than a
/// crossing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCredential {
    pub tenant_id: String,
    pub session_id: SessionId,
}

impl SessionCredential {
    pub const PREFIX: &'static str = "apt_";

    pub fn new(tenant_id: impl Into<String>, session_id: SessionId) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            session_id,
        }
    }

    pub fn encode(&self) -> String {
        format!("{}{}.{}", Self::PREFIX, self.tenant_id, self.session_id)
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let body = raw.trim().strip_prefix(Self::PREFIX)?;
        let (tenant_id, session_id) = body.split_once('.')?;
        if tenant_id.is_empty() || session_id.is_empty() {
            return None;
        }
        Some(Self {
            tenant_id: tenant_id.to_string(),
            session_id: SessionId(session_id.to_string()),
        })
    }
}
