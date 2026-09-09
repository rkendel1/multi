use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use appport_auth_mesh_authz::{AuthorizationDecision, DenialReason};
use appport_auth_mesh_boundary::{
    AuthBoundary, AuthPortRuntime, BoundaryRequest, ClientAuthContext, Method, SignInOutcome,
};
use appport_auth_mesh_contract::PrincipalKind;
use appport_auth_mesh_dsl::UiScreen;
use appport_auth_mesh_runtime::AuthError;
use appport_auth_mesh_surface::{AuthMethod, AuthOperation, AuthRoute};

use crate::http::{escape, HttpRequest, HttpResponse};
use crate::router::{ApplicationBinding, RouteOutcome};
use crate::ui::{render_sign_in, serves_default_screen, CLIENT_JS};

/// The HTTP face of the boundary.
///
/// It translates requests into [`BoundaryRequest`]s, asks the runtime, and
/// renders the answer. It contains no authority logic of its own — every
/// decision here comes from [`AuthPortRuntime`].
pub struct AuthPortServer {
    runtime: Arc<AuthPortRuntime>,
    app: Arc<dyn ApplicationBinding>,
    tenants: Vec<String>,
}

impl AuthPortServer {
    pub fn new(runtime: Arc<AuthPortRuntime>, app: Arc<dyn ApplicationBinding>) -> Self {
        Self {
            runtime,
            app,
            tenants: Vec::new(),
        }
    }

    /// Tenants offered by the generated sign-in page. A hint for the form only:
    /// the session's tenant is always the one the boundary verified.
    pub fn with_tenants(mut self, tenants: &[&str]) -> Self {
        self.tenants = tenants.iter().map(|tenant| (*tenant).to_string()).collect();
        self
    }

    pub fn runtime(&self) -> &Arc<AuthPortRuntime> {
        &self.runtime
    }

    /// Serve one request. Pure: no sockets, so the same dispatch is exercised
    /// by in-process callers and by the listener below.
    pub fn handle(&self, http: &HttpRequest) -> HttpResponse {
        let request = http.to_boundary();

        if request.path == "/authport/client.js" {
            return HttpResponse::new(200, "application/javascript", CLIENT_JS.as_bytes().to_vec());
        }

        // Check for control plane routes
        if request.path.starts_with("/_authport/") {
            if let Some(response) = crate::control_routes::handle_control_route(&self.runtime, &request.path, http) {
                return response;
            }
        }

        if let Some(route) = self.runtime.surface().route(&request.path).cloned() {
            let method = AuthMethod::parse(request.method.as_str());
            if !method.map(|method| route.allows(method)).unwrap_or(false) {
                return HttpResponse::denied(405, "method_not_allowed", "unsupported method");
            }
            return self.handle_auth_route(&route, &request);
        }

        self.handle_application(&request)
    }

    fn handle_auth_route(&self, route: &AuthRoute, request: &BoundaryRequest) -> HttpResponse {
        match route.operation {
            AuthOperation::Login if request.method == Method::Get => {
                self.render_screen(UiScreen::Login)
            }
            AuthOperation::Signup if request.method == Method::Get => {
                self.render_screen(UiScreen::Signup)
            }
            AuthOperation::Login => self.complete(self.runtime.sign_in(request)),
            AuthOperation::Signup => self.complete(self.runtime.sign_up(request)),
            AuthOperation::Logout => match self.runtime.sign_out(request) {
                Ok(()) => {
                    HttpResponse::json(200, "{\"signed_out\": true}").clearing_session_cookie()
                }
                Err(err) => denial(&err),
            },
            AuthOperation::Session => match request.method {
                Method::Delete => match self.runtime.sign_out(request) {
                    Ok(()) => {
                        HttpResponse::json(200, "{\"signed_out\": true}").clearing_session_cookie()
                    }
                    Err(err) => denial(&err),
                },
                _ => match self.runtime.authenticate(request) {
                    Ok(context) => HttpResponse::json(200, context.project().to_json()),
                    // No session is not an error page: it is "you are nobody".
                    Err(_) => HttpResponse::json(401, ClientAuthContext::anonymous_json()),
                },
            },
            AuthOperation::Providers => HttpResponse::json(200, self.providers_json()),
            AuthOperation::Authorize => self.handle_authorize(request),
            AuthOperation::CurrentTenant => match self.runtime.authenticate(request) {
                Ok(context) => HttpResponse::json(
                    200,
                    format!(
                        "{{\"tenant\": {{\"id\": \"{}\", \"namespace\": \"{}\"}}}}",
                        escape(context.tenant.tenant_id.as_str()),
                        escape(&context.tenant.namespace)
                    ),
                ),
                Err(err) => denial(&err),
            },
            AuthOperation::Tenants => match self.runtime.authenticate(request) {
                // A principal is told about its own tenant and no other.
                Ok(context) => HttpResponse::json(
                    200,
                    format!(
                        "{{\"tenants\": [{{\"id\": \"{}\"}}]}}",
                        escape(context.tenant.tenant_id.as_str())
                    ),
                ),
                Err(err) => denial(&err),
            },
            AuthOperation::Agents => self.handle_agents(request),
            AuthOperation::Delegations => self.handle_delegations(request),
            AuthOperation::AccountLinks => HttpResponse::denied(
                501,
                "not_enabled",
                "account linking is not exposed by this deployment",
            ),
        }
    }

    fn handle_authorize(&self, request: &BoundaryRequest) -> HttpResponse {
        let context = match self.runtime.authenticate(request) {
            Ok(context) => context,
            Err(err) => return denial(&err),
        };
        let Some(capability) = request.field("capability") else {
            return HttpResponse::denied(400, "missing_capability", "no capability named");
        };

        match self.runtime.authorize(&context, capability) {
            Ok(AuthorizationDecision::Allow { grant, .. }) => HttpResponse::json(
                200,
                format!(
                    "{{\"allowed\": true, \"capability\": \"{}\", \"principal\": \"{}\", \"authority\": \"{}\", \"delegation\": {}}}",
                    escape(capability),
                    escape(grant.principal_id.as_str()),
                    grant.authority.as_str(),
                    match &grant.delegation_id {
                        Some(id) => format!("\"{}\"", escape(id.as_str())),
                        None => "null".to_string(),
                    }
                ),
            ),
            Ok(AuthorizationDecision::Deny { reason, .. }) => HttpResponse::json(
                200,
                format!(
                    "{{\"allowed\": false, \"capability\": \"{}\", \"reason\": \"{}\"}}",
                    escape(capability),
                    reason.as_str()
                ),
            ),
            Err(err) => denial(&err),
        }
    }

    fn handle_agents(&self, request: &BoundaryRequest) -> HttpResponse {
        let context = match self.runtime.authenticate(request) {
            Ok(context) => context,
            Err(err) => return denial(&err),
        };
        if request.method != Method::Get {
            return HttpResponse::denied(
                501,
                "not_enabled",
                "agent lifecycle changes are not exposed over HTTP by this deployment",
            );
        }

        let agents = self
            .runtime
            .mesh()
            .stores()
            .principals
            .list_principals(&context.tenant)
            .unwrap_or_default()
            .into_iter()
            .filter(|principal| principal.kind == PrincipalKind::Agent)
            .map(|principal| {
                format!(
                    "{{\"id\": \"{}\", \"state\": \"{}\"}}",
                    escape(principal.id.as_str()),
                    principal
                        .agent_state
                        .map(|state| format!("{:?}", state).to_lowercase())
                        .unwrap_or_else(|| "unknown".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        HttpResponse::json(200, format!("{{\"agents\": [{}]}}", agents))
    }

    fn handle_delegations(&self, request: &BoundaryRequest) -> HttpResponse {
        let context = match self.runtime.authenticate(request) {
            Ok(context) => context,
            Err(err) => return denial(&err),
        };
        if request.method != Method::Get {
            return HttpResponse::denied(
                501,
                "not_enabled",
                "delegation changes are not exposed over HTTP by this deployment",
            );
        }

        let delegations = self
            .runtime
            .mesh()
            .delegations_for(&context.tenant, &context.principal.id)
            .unwrap_or_default()
            .into_iter()
            .map(|delegation| {
                format!(
                    "{{\"id\": \"{}\", \"delegated_by\": \"{}\", \"expires_at\": {}, \"revoked\": {}}}",
                    escape(delegation.id.as_str()),
                    escape(delegation.delegator.as_str()),
                    delegation.expires_at,
                    delegation.revoked_at.is_some()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        HttpResponse::json(200, format!("{{\"delegations\": [{}]}}", delegations))
    }

    /// Application routes: the boundary resolves authority first, and the
    /// handler only ever runs on a request that already satisfied it.
    fn handle_application(&self, request: &BoundaryRequest) -> HttpResponse {
        let requirement = match self.app.resolve(request.method, &request.path) {
            RouteOutcome::Matched(requirement) => requirement,
            RouteOutcome::MethodNotAllowed => {
                return HttpResponse::denied(405, "method_not_allowed", "unsupported method")
            }
            RouteOutcome::NotFound => {
                return HttpResponse::denied(404, "no_route", "no such route")
            }
            // Not covered by policy: refused, never forwarded.
            RouteOutcome::NoPolicy => {
                return HttpResponse::denied(
                    403,
                    "no_route_policy",
                    "this path is not covered by an AuthPort route policy",
                )
            }
        };

        match self.runtime.enforce(request, &requirement) {
            Ok(context) => self.app.handle(request, context.as_ref()),
            Err(err) => denial(&err),
        }
    }

    fn complete(&self, outcome: Result<SignInOutcome, AuthError>) -> HttpResponse {
        match outcome {
            Ok(SignInOutcome::Authenticated {
                context,
                credential,
            }) => HttpResponse::json(200, context.project().to_json())
                .with_session_cookie(&credential.encode()),
            Ok(SignInOutcome::Challenge(challenge)) => HttpResponse::json(
                202,
                format!(
                    "{{\"challenge\": {{\"connector\": \"{}\", \"state\": \"{}\"}}}}",
                    escape(&challenge.connector),
                    escape(&challenge.state)
                ),
            ),
            Err(err) => denial(&err),
        }
    }

    fn render_screen(&self, screen: UiScreen) -> HttpResponse {
        if serves_default_screen(self.runtime.surface(), screen) {
            HttpResponse::html(200, render_sign_in(self.runtime.surface(), &self.tenants))
        } else {
            // The contract says the application owns this screen.
            HttpResponse::denied(404, "custom_ui", "this screen is served by the application")
        }
    }

    fn providers_json(&self) -> String {
        let providers = self
            .runtime
            .providers()
            .iter()
            .map(|provider| {
                format!(
                    "{{\"id\": \"{}\", \"display_name\": \"{}\", \"kind\": \"{}\", \"status\": \"{}\", \"actionable\": {}}}",
                    escape(&provider.id),
                    escape(&provider.display_name),
                    provider.kind.as_str(),
                    provider.status.as_str(),
                    provider.is_actionable()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{\"providers\": [{}]}}", providers)
    }
}

/// Failures map to a status, always as a refusal — never as access.
pub fn status_for(reason: &DenialReason) -> u16 {
    match reason {
        DenialReason::MissingCredential
        | DenialReason::InvalidSession
        | DenialReason::ExpiredSession
        | DenialReason::RevokedSession => 401,
        _ => 403,
    }
}

fn denial(err: &AuthError) -> HttpResponse {
    HttpResponse::denied(status_for(&err.denial), err.denial.as_str(), &err.message)
}

/// Anything that can answer an HTTP request.
///
/// The example application behind a standalone deployment implements this and
/// nothing else — no authentication, no session handling.
pub trait HttpHandler: Send + Sync {
    fn handle(&self, request: &HttpRequest) -> HttpResponse;
}

impl HttpHandler for AuthPortServer {
    fn handle(&self, request: &HttpRequest) -> HttpResponse {
        AuthPortServer::handle(self, request)
    }
}

/// A running standalone server.
pub struct ServerHandle {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Block until the process is interrupted.
    pub fn wait(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub fn serve(
    server: Arc<dyn HttpHandler>,
    address: impl ToSocketAddrs,
) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(address)?;
    let local = listener.local_addr()?;
    listener.set_nonblocking(true)?;

    let stop = Arc::new(AtomicBool::new(false));
    let loop_stop = stop.clone();

    let thread = std::thread::spawn(move || {
        while !loop_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    std::thread::spawn(move || handle_connection(server, stream));
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ServerHandle {
        address: local,
        stop,
        thread: Some(thread),
    })
}

fn handle_connection(server: Arc<dyn HttpHandler>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut writer = write_half;

    let response = match HttpRequest::read_from(&mut reader) {
        Ok(request) => server.handle(&request),
        Err(err) => HttpResponse::denied(400, "bad_request", &err.message),
    };
    let _ = response.write_to(&mut writer);
}
