//! One scenario, run against both deployment modes.
//!
//! The step list each mode produces is compared at the end: same requests,
//! same decisions, same reasons — which is the claim the two placements have
//! to earn.

use std::net::SocketAddr;
use std::sync::Arc;

use appport_auth_mesh_boundary::BindingMode;
use appport_auth_mesh_contract::DelegationId;
use appport_auth_mesh_runtime::AuthError;
use appport_auth_mesh_server::{serve, AuthPortServer, RoutePolicy, ServerHandle, UpstreamProxy};

use crate::app::{router, Invoices};
use crate::bootstrap::{bootstrap, Deployment};
use crate::support::{
    reason, session_credential, sign_in, Call, EmbeddedTransport, HttpTransport, Transport,
};
use crate::upstream::UpstreamApp;

pub const PROXY_SECRET: &str = "development-upstream-secret";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub name: String,
    pub status: u16,
    pub reason: String,
}

impl Step {
    fn describe(&self) -> String {
        if self.reason.is_empty() {
            format!("{:<44} {}", self.name, self.status)
        } else {
            format!("{:<44} {} {}", self.name, self.status, self.reason)
        }
    }
}

/// AuthBoundry bound to the application's own server.
pub fn embedded() -> Result<(Deployment, Arc<AuthPortServer>), AuthError> {
    let deployment = bootstrap(BindingMode::Embedded)?;
    let server = Arc::new(
        AuthPortServer::new(
            deployment.runtime.clone(),
            Arc::new(router(deployment.invoices.clone())),
        )
        .with_tenants(&["acme", "globex"]),
    );
    Ok((deployment, server))
}

/// AuthBoundry in front of an application that implements no authority system.
pub struct Standalone {
    pub deployment: Deployment,
    pub address: SocketAddr,
    _authport: ServerHandle,
    _upstream: ServerHandle,
}

pub fn standalone() -> Result<Standalone, AuthError> {
    let deployment = bootstrap(BindingMode::Standalone)?;

    let invoices = Arc::new(Invoices::default());
    let upstream = serve(
        Arc::new(UpstreamApp::new(invoices, PROXY_SECRET)),
        "127.0.0.1:0",
    )
    .expect("the application binds");

    // The requirement table comes from the application's own route
    // declarations, so both modes enforce the same thing.
    let policy = application_policy();
    let proxy = UpstreamProxy::new(upstream.address(), policy, PROXY_SECRET);
    let server = Arc::new(
        AuthPortServer::new(deployment.runtime.clone(), Arc::new(proxy))
            .with_tenants(&["acme", "globex"]),
    );
    let authport = serve(server, "127.0.0.1:0").expect("AuthBoundry binds");

    Ok(Standalone {
        address: authport.address(),
        deployment,
        _authport: authport,
        _upstream: upstream,
    })
}

pub fn application_policy() -> RoutePolicy {
    router(Arc::new(Invoices::default())).policy()
}

/// The scenario every mode must answer identically.
pub fn scenario(deployment: &Deployment, transport: &dyn Transport) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut step = |name: &str, response: &appport_auth_mesh_server::HttpResponse| {
        steps.push(Step {
            name: name.to_string(),
            status: response.status,
            reason: reason(response),
        });
    };

    // Public routes need no authority at all.
    step(
        "GET /public (anonymous)",
        &transport.call(&Call::get("/public")),
    );
    // Protected ones need it before the application is ever reached.
    step(
        "GET /invoices (anonymous)",
        &transport.call(&Call::get("/invoices")),
    );

    let alice_signin = sign_in(transport, "acme", "alice", "alice-secret");
    step("POST /auth/sign-in (alice)", &alice_signin);
    let alice = session_credential(&alice_signin).unwrap_or_default();

    step(
        "GET /auth/session (alice)",
        &transport.call(&Call::get("/auth/session").with_session(&alice)),
    );
    step(
        "GET /profile (alice)",
        &transport.call(&Call::get("/profile").with_session(&alice)),
    );
    step(
        "GET /invoices (alice)",
        &transport.call(&Call::get("/invoices").with_session(&alice)),
    );
    step(
        "POST /invoices (alice)",
        &transport
            .call(&Call::post("/invoices", "{\"reference\": \"INV-1001\"}").with_session(&alice)),
    );
    // Owning the tenant is not the same as being allowed to charge for it.
    step(
        "POST /billing/charge (alice)",
        &transport.call(&Call::post("/billing/charge", "{}").with_session(&alice)),
    );
    // A session addressed at another tenant is refused, not redirected.
    step(
        "GET /invoices (alice, tenant globex)",
        &transport.call(
            &Call::get("/invoices")
                .with_session(&alice)
                .with_header("x-tenant-id", "globex"),
        ),
    );

    // Bob lives in another tenant and sees only his own.
    let bob_signin = sign_in(transport, "globex", "bob", "bob-secret");
    let bob = session_credential(&bob_signin).unwrap_or_default();
    step(
        "GET /invoices (bob, tenant globex)",
        &transport.call(&Call::get("/invoices").with_session(&bob)),
    );
    step(
        "POST /auth/authorize billing.charge (bob)",
        &transport.call(
            &Call::post("/auth/authorize", "{\"capability\": \"billing.charge\"}")
                .with_session(&bob),
        ),
    );

    // The agent authenticates through the same boundary as the humans.
    let agent_signin = sign_in(transport, "acme", "invoice-agent", "agent-secret");
    let agent = session_credential(&agent_signin).unwrap_or_default();
    step("POST /auth/sign-in (agent)", &agent_signin);
    step(
        "GET /invoices (agent, delegated)",
        &transport.call(&Call::get("/invoices").with_session(&agent)),
    );
    step(
        "POST /invoices (agent, delegated)",
        &transport
            .call(&Call::post("/invoices", "{\"reference\": \"INV-1002\"}").with_session(&agent)),
    );
    // The agent cannot exceed what Alice delegated.
    step(
        "POST /billing/charge (agent)",
        &transport.call(&Call::post("/billing/charge", "{}").with_session(&agent)),
    );

    // Revoking the delegation takes the agent's authority away at once.
    deployment
        .runtime
        .mesh()
        .revoke_delegation(
            "acme",
            &DelegationId("delegation-invoices".to_string()),
            deployment.now(),
        )
        .expect("Alice revokes the delegation");
    step(
        "GET /invoices (agent, revoked delegation)",
        &transport.call(&Call::get("/invoices").with_session(&agent)),
    );
    step(
        "GET /invoices (alice, unaffected)",
        &transport.call(&Call::get("/invoices").with_session(&alice)),
    );

    // Signing out ends the session's authority immediately.
    step(
        "POST /auth/sign-out (alice)",
        &transport.call(&Call::post("/auth/sign-out", "{}").with_session(&alice)),
    );
    step(
        "GET /invoices (alice, revoked session)",
        &transport.call(&Call::get("/invoices").with_session(&alice)),
    );

    // An expired session is no session.
    deployment.advance(10_000);
    step(
        "GET /invoices (agent, expired session)",
        &transport.call(&Call::get("/invoices").with_session(&agent)),
    );

    steps
}

pub fn run() -> Result<String, AuthError> {
    let mut report = String::new();

    let (embedded_deployment, embedded_server) = embedded()?;
    report.push_str(&embedded_deployment.runtime.mesh().inspect());
    report.push('\n');

    let embedded_steps = scenario(
        &embedded_deployment,
        &EmbeddedTransport(embedded_server.clone()),
    );
    report.push_str("Embedded (AuthBoundry bound to the application server)\n");
    for step in &embedded_steps {
        report.push_str(&format!("  {}\n", step.describe()));
    }

    let standalone = standalone()?;
    let standalone_steps = scenario(&standalone.deployment, &HttpTransport(standalone.address));
    report.push_str("\nStandalone (browser -> AuthBoundry -> application)\n");
    for step in &standalone_steps {
        report.push_str(&format!("  {}\n", step.describe()));
    }

    report.push_str("\nEquivalence\n");
    report.push_str(&format!(
        "  embedded == standalone: {}\n",
        if embedded_steps == standalone_steps {
            "✓"
        } else {
            "✗"
        }
    ));
    report.push_str(&format!(
        "  audit events recorded:  {}\n",
        embedded_deployment.stores.audit_events().len()
    ));

    Ok(report)
}
