use std::collections::BTreeMap;
use std::net::TcpStream;

use appport_auth_mesh_boundary::{AuthContext, BoundaryRequest, Method, Requirement};
use appport_auth_mesh_discovery::{RouteCandidate, RouteSource};

use crate::http::{HttpRequest, HttpResponse};

/// What the boundary should demand for a given request, and whether the
/// application has a route there at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    Matched(Requirement),
    MethodNotAllowed,
    NotFound,
    /// The path is not covered by any rule. It is refused rather than
    /// forwarded: an unlisted route is not a public one.
    NoPolicy,
}

/// How the deployment maps requests to required authority.
///
/// The same policy object drives an embedded router and a standalone proxy, so
/// the two placements cannot require different things.
#[derive(Debug, Clone, Default)]
pub struct RoutePolicy {
    rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub methods: Vec<Method>,
    pub pattern: PathPattern,
    pub requirement: Requirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPattern {
    Exact(String),
    Prefix(String),
}

impl PathPattern {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == path,
            Self::Prefix(prefix) => path.starts_with(prefix.as_str()),
        }
    }
}

impl RoutePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rule(
        mut self,
        methods: &[Method],
        pattern: PathPattern,
        requirement: Requirement,
    ) -> Self {
        self.rules.push(RouteRule {
            methods: methods.to_vec(),
            pattern,
            requirement,
        });
        self
    }

    pub fn public(self, methods: &[Method], path: &str) -> Self {
        self.rule(
            methods,
            PathPattern::Exact(path.to_string()),
            Requirement::Public,
        )
    }

    pub fn authenticated(self, methods: &[Method], path: &str) -> Self {
        self.rule(
            methods,
            PathPattern::Exact(path.to_string()),
            Requirement::Authenticated,
        )
    }

    pub fn capability(self, methods: &[Method], path: &str, capability: &str) -> Self {
        self.rule(
            methods,
            PathPattern::Exact(path.to_string()),
            Requirement::capability(capability),
        )
    }

    pub fn rules(&self) -> &[RouteRule] {
        &self.rules
    }

    pub fn resolve(&self, method: Method, path: &str) -> RouteOutcome {
        let mut path_matched = false;
        for rule in &self.rules {
            if !rule.pattern.matches(path) {
                continue;
            }
            path_matched = true;
            if rule.methods.contains(&method) {
                return RouteOutcome::Matched(rule.requirement.clone());
            }
        }

        if path_matched {
            RouteOutcome::MethodNotAllowed
        } else {
            RouteOutcome::NoPolicy
        }
    }
}

/// What the application sees. It never reconstructs identity: the context is
/// handed to it, already authoritative.
pub struct AppRequest<'r> {
    pub request: &'r BoundaryRequest,
    pub auth: Option<&'r AuthContext>,
}

impl AppRequest<'_> {
    pub fn context(&self) -> Option<&AuthContext> {
        self.auth
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.request.field(name)
    }
}

pub type AppHandler = Box<dyn Fn(&AppRequest<'_>) -> HttpResponse + Send + Sync>;

/// How the server reaches the application behind the boundary.
pub trait ApplicationBinding: Send + Sync {
    fn resolve(&self, method: Method, path: &str) -> RouteOutcome;

    fn handle(&self, request: &BoundaryRequest, context: Option<&AuthContext>) -> HttpResponse;

    fn upgrade(
        &self,
        _request: &HttpRequest,
        _context: Option<&AuthContext>,
        _stream: TcpStream,
    ) -> bool {
        false
    }

    fn observed_routes(&self) -> Vec<RouteCandidate> {
        Vec::new()
    }
}

/// An application whose handlers run in the same process as AuthBoundry.
///
/// This is the embedded placement: the developer registers routes with the
/// authority each one needs, and handlers receive the resolved context.
#[derive(Default)]
pub struct RouterApp {
    routes: Vec<(Method, String, Requirement)>,
    handlers: BTreeMap<(Method, String), AppHandler>,
}

impl RouterApp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route(
        mut self,
        method: Method,
        path: &str,
        requirement: Requirement,
        handler: AppHandler,
    ) -> Self {
        self.routes
            .push((method, path.to_string(), requirement.clone()));
        self.handlers.insert((method, path.to_string()), handler);
        self
    }

    /// `auth.require("invoice.read")` — the capability is checked by the
    /// boundary before the handler is ever called.
    pub fn require(
        self,
        method: Method,
        path: &str,
        capability: &str,
        handler: AppHandler,
    ) -> Self {
        self.route(method, path, Requirement::capability(capability), handler)
    }

    pub fn public(self, method: Method, path: &str, handler: AppHandler) -> Self {
        self.route(method, path, Requirement::Public, handler)
    }

    pub fn authenticated(self, method: Method, path: &str, handler: AppHandler) -> Self {
        self.route(method, path, Requirement::Authenticated, handler)
    }

    pub fn policy(&self) -> RoutePolicy {
        self.routes
            .iter()
            .fold(RoutePolicy::new(), |policy, (method, path, requirement)| {
                policy.rule(
                    &[*method],
                    PathPattern::Exact(path.clone()),
                    requirement.clone(),
                )
            })
    }
}

impl ApplicationBinding for RouterApp {
    fn resolve(&self, method: Method, path: &str) -> RouteOutcome {
        match self.policy().resolve(method, path) {
            // An unregistered path is simply absent here; the application is
            // never consulted, so nothing leaks by saying so.
            RouteOutcome::NoPolicy => RouteOutcome::NotFound,
            other => other,
        }
    }

    fn handle(&self, request: &BoundaryRequest, context: Option<&AuthContext>) -> HttpResponse {
        match self.handlers.get(&(request.method, request.path.clone())) {
            Some(handler) => handler(&AppRequest {
                request,
                auth: context,
            }),
            None => HttpResponse::denied(404, "no_route", "no such route"),
        }
    }

    fn observed_routes(&self) -> Vec<RouteCandidate> {
        self.routes
            .iter()
            .map(|(method, path, requirement)| RouteCandidate {
                method: method.as_str().to_string(),
                path: path.clone(),
                source: RouteSource::Embedded,
                capability: match requirement {
                    Requirement::Capability(capability) => Some(capability.clone()),
                    _ => None,
                },
            })
            .collect()
    }
}
