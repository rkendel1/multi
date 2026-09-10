use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use appport_auth_mesh_authz::{
    Action, AuthorizationContext, AuthorizationDecision, AuthorizationRequest, DenialReason,
};
use appport_auth_mesh_boundary::{
    AuthBoundary, AuthPortRuntime, BoundaryRequest, ClientAuthContext, Method, SignInOutcome,
};
use appport_auth_mesh_contract::{Capability, ExecutionCredentialId, PrincipalKind, RunId};
use appport_auth_mesh_dsl::UiScreen;
use appport_auth_mesh_runtime::AuthError;
use appport_auth_mesh_surface::{AuthMethod, AuthOperation, AuthRoute};

use crate::http::{escape, HttpRequest, HttpResponse};
use crate::router::{ApplicationBinding, RouteOutcome};
use crate::ui::{render_sign_in, serves_default_screen, CLIENT_JS};

/// Repository-scoped Studio operations supplied by the CLI host. Keeping this
/// behind a narrow interface prevents the generic authority server from
/// acquiring filesystem authority.
pub trait StudioController: Send + Sync {
    fn handle(&self, request: &HttpRequest) -> Option<HttpResponse>;

    fn page(&self) -> Option<String> {
        None
    }
}

/// The HTTP face of the boundary.
///
/// It translates requests into [`BoundaryRequest`]s, asks the runtime, and
/// renders the answer. It contains no authority logic of its own — every
/// decision here comes from [`AuthPortRuntime`].
pub struct AuthPortServer {
    runtime: Arc<AuthPortRuntime>,
    app: Arc<dyn ApplicationBinding>,
    tenants: Vec<String>,
    studio_page: Option<String>,
    studio_controller: Option<Arc<dyn StudioController>>,
}

impl AuthPortServer {
    pub fn new(runtime: Arc<AuthPortRuntime>, app: Arc<dyn ApplicationBinding>) -> Self {
        Self {
            runtime,
            app,
            tenants: Vec::new(),
            studio_page: None,
            studio_controller: None,
        }
    }

    /// Add a read-only Studio landing page. The page is a projection of the
    /// repository contract and adoption state; it is not configuration state.
    pub fn with_studio_page(mut self, page: String) -> Self {
        self.studio_page = Some(page);
        self
    }

    pub fn with_studio_controller(mut self, controller: Arc<dyn StudioController>) -> Self {
        self.studio_controller = Some(controller);
        self
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

        if request.method == Method::Get && request.path == "/_authboundry/studio" {
            if let Some(page) = self
                .studio_controller
                .as_ref()
                .and_then(|controller| controller.page())
            {
                return HttpResponse::html(200, page);
            }
            if let Some(page) = &self.studio_page {
                return HttpResponse::html(200, page.clone());
            }
        }

        if request.path.starts_with("/_authboundry/application") {
            if let Some(controller) = &self.studio_controller {
                if let Some(response) = controller.handle(http) {
                    return response;
                }
            }
        }

        if request.path == "/authboundry/client.js" {
            return HttpResponse::new(200, "application/javascript", CLIENT_JS.as_bytes().to_vec());
        }

        // Check for control plane routes
        if request.path.starts_with("/_authboundry/") {
            if let Some(response) = crate::control_routes::handle_control_route(
                &self.runtime,
                self.app.as_ref(),
                &request.path,
                http,
            ) {
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
        if request.path.starts_with("/auth/") {
            return HttpResponse::denied(
                404,
                "unsupported_experience",
                "auth experience is not exposed by this contract",
            );
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
            AuthOperation::PasswordChange => match self.runtime.change_password(request) {
                Ok(()) => HttpResponse::json(200, "{\"changed\": true}"),
                Err(err) => denial(&err),
            },
            AuthOperation::PasswordReset => match self.runtime.reset_password(request) {
                Ok(()) => HttpResponse::json(200, "{\"reset\": true}"),
                Err(err) => denial(&err),
            },
            AuthOperation::PasswordPolicy => HttpResponse::json(
                200,
                crate::control_routes::password_policy_json(&self.runtime).to_string(),
            ),
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
            AuthOperation::Sessions => match self.runtime.authenticate(request) {
                Ok(context) => HttpResponse::json(
                    200,
                    format!(
                        "{{\"sessions\": [{{\"id\": \"{}\", \"principal\": \"{}\", \"tenant\": \"{}\"}}]}}",
                        escape(context.session.id.as_str()),
                        escape(context.principal.id.as_str()),
                        escape(context.tenant.tenant_id.as_str())
                    ),
                ),
                Err(err) => denial(&err),
            },
            AuthOperation::Profile => match self.runtime.authenticate(request) {
                Ok(context) => HttpResponse::json(
                    200,
                    format!(
                        "{{\"profile\": {{\"principal\": \"{}\", \"tenant\": \"{}\", \"application_profile_ref\": null}}}}",
                        escape(context.principal.id.as_str()),
                        escape(context.tenant.tenant_id.as_str())
                    ),
                ),
                Err(err) => denial(&err),
            },
            AuthOperation::Devices => match self.runtime.authenticate(request) {
                Ok(context) => HttpResponse::json(
                    200,
                    format!(
                        "{{\"devices\": [], \"principal\": \"{}\"}}",
                        escape(context.principal.id.as_str())
                    ),
                ),
                Err(err) => denial(&err),
            },
            AuthOperation::EmailVerification
            | AuthOperation::Mfa
            | AuthOperation::Passkeys
            | AuthOperation::Recovery => HttpResponse::denied(
                501,
                "not_enabled",
                "experience is modeled but no provider implementation is enabled",
            ),
            AuthOperation::Providers => HttpResponse::json(200, self.providers_json()),
            AuthOperation::Authorize => self.handle_authorize(request),
            AuthOperation::Policies
            | AuthOperation::AuthorizationDecisions
            | AuthOperation::AuthorizationExplain => {
                HttpResponse::denied(404, "no_route", "control-plane route was not handled")
            }
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

        let decision = match self.run_id_from_request(&context, request) {
            Ok(Some(run_id)) => self.runtime.authorize_run_resource(
                &context,
                &run_id,
                AuthorizationRequest {
                    principal: context.principal.id.clone(),
                    tenant: context.tenant.tenant_id.clone(),
                    capability: Capability(capability.to_string()),
                    action: Action("authorize".to_string()),
                    resource: None,
                    context: AuthorizationContext::default(),
                },
            ),
            Ok(None) => self.runtime.authorize(&context, capability),
            Err(err) => return denial(&err),
        };

        match decision {
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

    fn run_id_from_request(
        &self,
        context: &appport_auth_mesh_boundary::AuthContext,
        request: &BoundaryRequest,
    ) -> Result<Option<RunId>, AuthError> {
        if let Some(run_id) = request.field("run_id") {
            return Ok(Some(RunId(run_id.to_string())));
        }
        let Some(credential) = request
            .field("execution_credential")
            .or_else(|| request.field("run_credential"))
        else {
            return Ok(None);
        };
        let run = self.runtime.agent_run_by_credential(
            context.tenant.tenant_id.as_str(),
            &ExecutionCredentialId(credential.to_string()),
        )?;
        run.map(|run| Some(run.id)).ok_or_else(|| {
            AuthError::new(
                appport_auth_mesh_runtime::AuthLifecycleStage::PolicyEvaluation,
                "run credential was not found",
                DenialReason::RunNotFound,
            )
        })
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
                    delegation
                        .expires_at
                        .map(|expires_at| expires_at.to_string())
                        .unwrap_or_else(|| "null".to_string()),
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
        let mut requirement = match self.app.resolve(request.method, &request.path) {
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
                    "this path is not covered by an AuthBoundry route policy",
                )
            }
        };
        if let Some(capability) = self
            .runtime
            .get_route_protection(&request.method, &request.path)
        {
            requirement = appport_auth_mesh_boundary::Requirement::capability(capability);
        }

        match self.runtime.enforce(request, &requirement) {
            Ok(context) => self.app.handle(request, context.as_ref()),
            Err(_err)
                if request.method == Method::Get
                    && request
                        .headers
                        .get("accept")
                        .map(|value| value.contains("text/html"))
                        .unwrap_or(false) =>
            {
                let return_to = percent_encode_path(&request.path);
                HttpResponse::html(302, String::new())
                    .with_header("location", format!("/auth/login?return_to={}", return_to))
            }
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
            HttpResponse::html(
                200,
                render_sign_in(
                    self.runtime.surface(),
                    &self.runtime.effective_password_policy().policy,
                    &self.tenants,
                ),
            )
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

fn percent_encode_path(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' => {
                vec![byte as char]
            }
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
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

    fn upgrade(&self, _request: &HttpRequest, _stream: TcpStream) -> bool {
        false
    }
}

impl HttpHandler for AuthPortServer {
    fn handle(&self, request: &HttpRequest) -> HttpResponse {
        AuthPortServer::handle(self, request)
    }

    fn upgrade(&self, http: &HttpRequest, stream: TcpStream) -> bool {
        let request = http.to_boundary();
        let requirement = match self.app.resolve(request.method, &request.path) {
            RouteOutcome::Matched(requirement) => requirement,
            _ => return false,
        };
        match self.runtime.enforce(&request, &requirement) {
            Ok(context) => self.app.upgrade(http, context.as_ref(), stream),
            Err(_) => false,
        }
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
    if let Err(err) = stream.set_nonblocking(false) {
        eprintln!("AuthBoundry could not configure client connection: {}", err);
        return;
    }
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut writer = write_half;

    let response = match HttpRequest::read_from(&mut reader) {
        Ok(request)
            if request
                .header("upgrade")
                .map(|value| value.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false) =>
        {
            if server.upgrade(&request, reader.into_inner()) {
                return;
            }
            HttpResponse::denied(
                502,
                "websocket_upgrade_failed",
                "application WebSocket upgrade failed",
            )
        }
        Ok(request) => server.handle(&request),
        Err(err)
            if err.message.contains("temporarily unavailable")
                || err.message.contains("timed out") =>
        {
            // Browsers routinely open speculative connections without sending
            // a request. A read timeout is not an application request and must
            // not become a visible 400 response.
            return;
        }
        Err(err) => HttpResponse::denied(400, "bad_request", &err.message),
    };
    if let Err(err) = response.write_to(&mut writer) {
        eprintln!("AuthBoundry response write failed: {}", err);
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use crate::client::{send, ClientRequest};

    struct LargeResponse;

    impl HttpHandler for LargeResponse {
        fn handle(&self, _request: &HttpRequest) -> HttpResponse {
            HttpResponse::new(200, "text/javascript", vec![b'x'; 1_048_576])
        }
    }

    #[test]
    fn accepted_connections_deliver_responses_larger_than_the_socket_buffer() {
        let running = serve(Arc::new(LargeResponse), "127.0.0.1:0").unwrap();
        let response = send(running.address(), &ClientRequest::get("/large.js")).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), 1_048_576);
        assert!(response.body.iter().all(|byte| *byte == b'x'));
        running.shutdown();
    }
}
