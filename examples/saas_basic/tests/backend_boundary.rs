//! The backend boundary, proven end to end.
//!
//! Every scenario here goes through the real HTTP surface — in process for the
//! embedded placement, over a socket for the standalone one.

use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use appport_auth_mesh_boundary::{
    AuthBoundary, BindingMode, BoundaryRequest, Method as BoundaryMethod, SessionCredential,
    TestClock,
};
use appport_auth_mesh_contract::{DelegationId, TenantContext};
use appport_auth_mesh_runtime::MemoryStores;
use appport_auth_mesh_server::http::{HttpRequest, HttpResponse};
use appport_auth_mesh_server::proxy::headers;
use appport_auth_mesh_server::{serve, AuthPortServer, HttpHandler, ServerHandle, UpstreamProxy};
use appport_auth_mesh_storage::memory::MemoryAuditLog;
use appport_auth_mesh_storage::{AuditEvent, AuditLog, StorageError};
use saas_basic::bootstrap::{bootstrap, bootstrap_with_stores, Deployment};
use saas_basic::demo::{
    application_policy, embedded, scenario, standalone, Standalone, PROXY_SECRET,
};
use saas_basic::support::{
    field, reason, session_credential, sign_in, Call, EmbeddedTransport, HttpTransport, Transport,
};

fn embedded_fixture() -> (Deployment, Box<dyn Transport>) {
    let (deployment, server) = embedded().expect("the embedded deployment builds");
    (deployment, Box::new(EmbeddedTransport(server)))
}

fn alice(transport: &dyn Transport) -> String {
    session_credential(&sign_in(transport, "acme", "alice", "alice-secret"))
        .expect("Alice's sign-in issues a session")
}

#[derive(Default)]
struct RecordingUpstream {
    calls: AtomicUsize,
    last: Mutex<Option<HttpRequest>>,
}

impl RecordingUpstream {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last(&self) -> HttpRequest {
        self.last
            .lock()
            .expect("recorded request lock")
            .clone()
            .expect("upstream received a request")
    }
}

impl HttpHandler for RecordingUpstream {
    fn handle(&self, request: &HttpRequest) -> HttpResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().expect("recorded request lock") = Some(request.clone());
        HttpResponse::json(200, "{\"upstream\": true}")
    }
}

struct RecordingStandalone {
    deployment: Deployment,
    address: SocketAddr,
    upstream: Arc<RecordingUpstream>,
    _authport: ServerHandle,
    _upstream: ServerHandle,
}

fn recording_standalone() -> RecordingStandalone {
    let deployment = bootstrap(BindingMode::Standalone).expect("deployment builds");
    let upstream = Arc::new(RecordingUpstream::default());
    let upstream_server = serve(upstream.clone(), "127.0.0.1:0").expect("upstream binds");
    let proxy = UpstreamProxy::new(
        upstream_server.address(),
        application_policy(),
        PROXY_SECRET,
    );
    let server = Arc::new(
        AuthPortServer::new(deployment.runtime.clone(), Arc::new(proxy))
            .with_tenants(&["acme", "globex"]),
    );
    let authport = serve(server, "127.0.0.1:0").expect("AuthBoundry binds");

    RecordingStandalone {
        deployment,
        address: authport.address(),
        upstream,
        _authport: authport,
        _upstream: upstream_server,
    }
}

fn agent(transport: &dyn Transport) -> String {
    session_credential(&sign_in(transport, "acme", "invoice-agent", "agent-secret"))
        .expect("the agent's sign-in issues a session")
}

fn bob(transport: &dyn Transport) -> String {
    session_credential(&sign_in(transport, "globex", "bob", "bob-secret"))
        .expect("Bob's sign-in issues a session")
}

fn allowed(response: &HttpResponse) -> Option<String> {
    field(response, "allowed")
}

// 1. An unauthenticated request never reaches the application.
#[test]
fn unauthenticated_requests_are_rejected() {
    let (_deployment, transport) = embedded_fixture();

    let public = transport.call(&Call::get("/public"));
    assert_eq!(public.status, 200);

    let protected = transport.call(&Call::get("/invoices"));
    assert_eq!(protected.status, 401);
    assert_eq!(reason(&protected), "missing_credential");

    let posted = transport.call(&Call::post("/invoices", "{\"reference\": \"INV-X\"}"));
    assert_eq!(posted.status, 401);

    // A path with no route policy is refused rather than passed through.
    let unlisted = transport.call(&Call::get("/admin/secrets"));
    assert!(matches!(unlisted.status, 403 | 404));
}

#[test]
fn standalone_rejects_unauthorized_requests_before_upstream() {
    let standalone = recording_standalone();
    let transport = HttpTransport(standalone.address);

    let missing = transport.call(&Call::get("/invoices"));
    assert_eq!(missing.status, 401);
    assert_eq!(reason(&missing), "missing_credential");

    let invalid = transport.call(&Call::get("/invoices").with_session("apt_acme.not-a-session"));
    assert_eq!(invalid.status, 401);
    assert_eq!(reason(&invalid), "invalid_session");

    assert_eq!(standalone.upstream.calls(), 0);
}

#[test]
fn standalone_strips_every_client_authority_header_and_injects_verified_context() {
    let standalone = recording_standalone();
    let transport = HttpTransport(standalone.address);
    let credential = alice(&transport);

    let response = transport.call(
        &Call::post("/invoices?source=test", "{\"reference\": \"INV-FORGED\"}")
            .with_session(&credential)
            .with_header(headers::PRINCIPAL, "attacker")
            .with_header(headers::PRINCIPAL_KIND, "service")
            .with_header(headers::TENANT, "attacker-tenant")
            .with_header(headers::CLAIMS, "role=admin")
            .with_header(headers::CAPABILITIES, "billing.charge")
            .with_header(headers::DELEGATION, "attacker-delegation")
            .with_header(headers::DELEGATED_BY, "attacker-delegator")
            .with_header(headers::CONTEXT, "{\"principal\":\"attacker\"}")
            .with_header(headers::SIGNATURE, "attacker-signature")
            .with_header(headers::PROXY_SIGNATURE, "attacker-proxy-signature"),
    );

    assert_eq!(response.status, 200);
    assert_eq!(standalone.upstream.calls(), 1);
    let upstream = standalone.upstream.last();

    assert_eq!(upstream.method, BoundaryMethod::Post);
    assert_eq!(upstream.path, "/invoices");
    assert_eq!(
        upstream.query.get("source").map(String::as_str),
        Some("test")
    );
    assert!(upstream.body.ends_with(b"INV-FORGED\"}"));

    assert_eq!(
        upstream.headers.get(headers::PRINCIPAL).map(String::as_str),
        Some(standalone.deployment.alice.as_str())
    );
    assert_eq!(
        upstream
            .headers
            .get(headers::PRINCIPAL_KIND)
            .map(String::as_str),
        Some("human")
    );
    assert_eq!(
        upstream.headers.get(headers::TENANT).map(String::as_str),
        Some("acme")
    );
    assert!(upstream
        .headers
        .get(headers::CLAIMS)
        .expect("verified claims")
        .contains("role=owner"));
    assert!(upstream
        .headers
        .get(headers::CAPABILITIES)
        .expect("verified capabilities")
        .contains("invoice.create"));
    assert!(!upstream.headers.contains_key(headers::DELEGATION));
    assert!(!upstream.headers.contains_key(headers::DELEGATED_BY));
    assert_ne!(
        upstream.headers.get(headers::CONTEXT).map(String::as_str),
        Some("{\"principal\":\"attacker\"}")
    );
    assert!(UpstreamProxy::verify(
        PROXY_SECRET,
        upstream.headers.get(headers::CONTEXT).expect("context"),
        upstream.headers.get(headers::SIGNATURE).expect("signature")
    ));
    assert_eq!(
        upstream.headers.get(headers::PROXY_SIGNATURE),
        Some(&UpstreamProxy::sign(PROXY_SECRET, "proxy"))
    );

    for forbidden in [
        "attacker",
        "service",
        "attacker-tenant",
        "role=admin",
        "billing.charge",
        "attacker-delegation",
        "attacker-delegator",
        "attacker-signature",
        "attacker-proxy-signature",
    ] {
        assert!(
            !upstream
                .headers
                .values()
                .any(|value| value.contains(forbidden)),
            "forged value `{forbidden}` reached upstream"
        );
    }
}

// 2, 3, 4. Sign-in works, the session yields authority, and the application is
// handed a context it did not assemble.
#[test]
fn signing_in_produces_an_authoritative_context_for_the_application() {
    let (_deployment, transport) = embedded_fixture();

    let response = sign_in(transport.as_ref(), "acme", "alice", "alice-secret");
    assert_eq!(response.status, 200);
    assert_eq!(field(&response, "authenticated").as_deref(), Some("true"));
    let credential = session_credential(&response).expect("a session cookie is issued");
    assert!(credential.starts_with(SessionCredential::PREFIX));

    // The session, not the request, is what the server reads back.
    let session = transport.call(&Call::get("/auth/session").with_session(&credential));
    assert_eq!(session.status, 200);
    assert_eq!(field(&session, "role").as_deref(), Some("owner"));

    // The application echoes what the boundary gave it.
    let profile = transport.call(&Call::get("/profile").with_session(&credential));
    assert_eq!(profile.status, 200);
    assert_eq!(field(&profile, "tenant").as_deref(), Some("acme"));
    assert_eq!(field(&profile, "kind").as_deref(), Some("human"));
    assert_eq!(field(&profile, "role").as_deref(), Some("owner"));

    // Bad credentials produce no session at all.
    let refused = sign_in(transport.as_ref(), "acme", "alice", "wrong-password");
    assert!(refused.status >= 400);
    assert!(session_credential(&refused).is_none());
}

// 5, 6. The capability the route requires is the one that decides.
#[test]
fn capabilities_gate_the_application() {
    let (_deployment, transport) = embedded_fixture();
    let credential = alice(transport.as_ref());

    let read = transport.call(&Call::get("/invoices").with_session(&credential));
    assert_eq!(read.status, 200);

    let create = transport
        .call(&Call::post("/invoices", "{\"reference\": \"INV-1\"}").with_session(&credential));
    assert_eq!(create.status, 201);
    assert_eq!(field(&create, "count").as_deref(), Some("1"));

    // Alice owns the tenant and still cannot charge it.
    let charge = transport.call(&Call::post("/billing/charge", "{}").with_session(&credential));
    assert_eq!(charge.status, 403);
    assert_eq!(reason(&charge), "condition_failed");
}

// 7. Tenants are isolated for humans.
#[test]
fn tenant_isolation_is_enforced() {
    let (deployment, transport) = embedded_fixture();
    let alice_session = alice(transport.as_ref());
    let bob_session = bob(transport.as_ref());

    transport
        .call(&Call::post("/invoices", "{\"reference\": \"ACME-1\"}").with_session(&alice_session));

    // Bob sees his own tenant's invoices, which are not Alice's.
    let bob_invoices = transport.call(&Call::get("/invoices").with_session(&bob_session));
    assert_eq!(bob_invoices.status, 200);
    assert_eq!(field(&bob_invoices, "tenant").as_deref(), Some("globex"));
    assert!(!bob_invoices.body_string().contains("ACME-1"));

    // Alice cannot address another tenant with her session.
    let crossed = transport.call(
        &Call::get("/invoices")
            .with_session(&alice_session)
            .with_header("x-tenant-id", "globex"),
    );
    assert_eq!(crossed.status, 403);
    assert_eq!(reason(&crossed), "tenant_mismatch");

    // Nor can a session id be re-addressed at another tenant.
    let stolen = SessionCredential::parse(&bob_session).unwrap();
    let smuggled = SessionCredential::new("acme", stolen.session_id).encode();
    let response = transport.call(&Call::get("/invoices").with_session(&smuggled));
    assert!(response.status >= 400);
    assert_ne!(reason(&response), "");

    let _ = deployment;
}

// 8. A revoked session stops working immediately.
#[test]
fn revoked_sessions_fail_closed() {
    let (_deployment, transport) = embedded_fixture();
    let credential = alice(transport.as_ref());

    assert_eq!(
        transport
            .call(&Call::get("/invoices").with_session(&credential))
            .status,
        200
    );

    let signed_out = transport.call(&Call::post("/auth/sign-out", "{}").with_session(&credential));
    assert_eq!(signed_out.status, 200);

    let after = transport.call(&Call::get("/invoices").with_session(&credential));
    assert_eq!(after.status, 401);
    assert_eq!(reason(&after), "revoked_session");
}

// 9. So does an expired one.
#[test]
fn expired_sessions_fail_closed() {
    let (deployment, transport) = embedded_fixture();
    let credential = alice(transport.as_ref());

    deployment.advance(10_000);

    let after = transport.call(&Call::get("/invoices").with_session(&credential));
    assert_eq!(after.status, 401);
    assert_eq!(reason(&after), "expired_session");
}

// 10, 11. An agent goes through the same boundary and gets exactly what was
// delegated to it — no more.
#[test]
fn agents_act_within_their_delegation() {
    let (deployment, transport) = embedded_fixture();
    let credential = agent(transport.as_ref());

    let read = transport.call(&Call::get("/invoices").with_session(&credential));
    assert_eq!(read.status, 200);

    let create = transport
        .call(&Call::post("/invoices", "{\"reference\": \"AGENT-1\"}").with_session(&credential));
    assert_eq!(create.status, 201);
    // The invoice was created by the agent, not by Alice.
    assert_eq!(
        field(&create, "by").as_deref(),
        Some(deployment.agent.as_str())
    );

    // The delegation did not include billing.
    let charge = transport.call(&Call::post("/billing/charge", "{}").with_session(&credential));
    assert_eq!(charge.status, 403);
    assert_eq!(reason(&charge), "delegation_missing");

    // The context keeps the two principals distinct.
    let profile = transport.call(&Call::get("/profile").with_session(&credential));
    assert_eq!(field(&profile, "kind").as_deref(), Some("agent"));
    assert_eq!(
        field(&profile, "principal").as_deref(),
        Some(deployment.agent.as_str())
    );
    assert_eq!(
        field(&profile, "delegated_by").as_deref(),
        Some(deployment.alice.as_str())
    );
}

// 12. Revoking the delegation removes the agent's authority, and only its own.
#[test]
fn revoking_a_delegation_takes_effect_immediately() {
    let (deployment, transport) = embedded_fixture();
    let agent_session = agent(transport.as_ref());
    let alice_session = alice(transport.as_ref());

    assert_eq!(
        transport
            .call(&Call::get("/invoices").with_session(&agent_session))
            .status,
        200
    );

    deployment
        .runtime
        .mesh()
        .revoke_delegation(
            "acme",
            &DelegationId("delegation-invoices".to_string()),
            deployment.now(),
        )
        .expect("Alice revokes the delegation");

    let after = transport.call(&Call::get("/invoices").with_session(&agent_session));
    assert_eq!(after.status, 403);
    assert_eq!(reason(&after), "delegation_revoked");

    // Alice is unaffected.
    assert_eq!(
        transport
            .call(&Call::get("/invoices").with_session(&alice_session))
            .status,
        200
    );
}

// 13. Revoking the agent itself works independently of the delegation.
#[test]
fn revoking_an_agent_takes_effect_immediately() {
    let (deployment, transport) = embedded_fixture();
    let agent_session = agent(transport.as_ref());

    deployment
        .runtime
        .mesh()
        .revoke_agent("acme", &deployment.agent, deployment.now())
        .expect("the agent is revoked");

    let after = transport.call(&Call::get("/invoices").with_session(&agent_session));
    assert_eq!(after.status, 403);
    assert_eq!(reason(&after), "agent_revoked");

    // It cannot sign in again either, though its delegation is still live.
    let signin = sign_in(transport.as_ref(), "acme", "invoice-agent", "agent-secret");
    assert!(signin.status >= 400);
    assert_eq!(reason(&signin), "agent_revoked");
}

// 14. The two deployment modes answer identically.
#[test]
fn embedded_and_standalone_agree() {
    let (embedded_deployment, embedded_server) = embedded().expect("embedded builds");
    let embedded_steps = scenario(&embedded_deployment, &EmbeddedTransport(embedded_server));

    let standalone: Standalone = standalone().expect("standalone builds");
    let standalone_steps = scenario(&standalone.deployment, &HttpTransport(standalone.address));

    assert_eq!(embedded_steps, standalone_steps);
    assert!(embedded_steps.len() >= 18);
    assert_eq!(embedded_deployment.runtime.mode(), BindingMode::Embedded);
    assert_eq!(
        standalone.deployment.runtime.mode(),
        BindingMode::Standalone
    );
}

// 15. Nothing a client says becomes authority.
#[test]
fn a_client_cannot_manufacture_backend_authority() {
    let (deployment, transport) = embedded_fixture();

    // A made-up credential is not a session.
    let forged = transport.call(&Call::get("/invoices").with_session("apt_acme.sess_deadbeef"));
    assert_eq!(forged.status, 401);
    assert_eq!(reason(&forged), "invalid_session");

    // Nor is a cookie in the wrong shape.
    let malformed = transport.call(&Call::get("/invoices").with_session("i-am-alice"));
    assert_eq!(malformed.status, 401);

    // Claims and capabilities asserted in headers are ignored: Bob signs in
    // honestly and remains Bob, in his own tenant, with his own claims.
    let bob_session = bob(transport.as_ref());
    let dressed_up = transport.call(
        &Call::get("/profile")
            .with_session(&bob_session)
            .with_header(headers::PRINCIPAL, deployment.alice.as_str())
            .with_header(headers::TENANT, "acme")
            .with_header(headers::CAPABILITIES, "billing.charge,invoice.create")
            .with_header(headers::CLAIMS, "role=owner;billing=manager"),
    );
    assert_eq!(dressed_up.status, 200);
    assert_eq!(field(&dressed_up, "tenant").as_deref(), Some("globex"));
    assert_eq!(
        field(&dressed_up, "principal").as_deref(),
        Some(deployment.bob.as_str())
    );
    assert_eq!(field(&dressed_up, "billing").as_deref(), Some("none"));

    // And the capability those headers asked for is still refused.
    let charge = transport.call(
        &Call::post("/billing/charge", "{}")
            .with_session(&bob_session)
            .with_header(headers::CAPABILITIES, "billing.charge"),
    );
    assert_eq!(charge.status, 403);
}

/// The demonstration the boundary exists for: the client asserts an identity
/// and a capability, and the server answers from its own state.
#[test]
fn the_client_says_yes_and_the_server_says_no() {
    let (deployment, transport) = embedded_fixture();
    let alice_session = alice(transport.as_ref());

    // client says: principal = Alice, capability = billing.charge
    let claim = transport.call(
        &Call::post(
            "/auth/authorize",
            "{\"capability\": \"billing.charge\", \"principal\": \"prn_whoever\", \"allowed\": true}",
        )
        .with_session(&alice_session)
        .with_header(headers::PRINCIPAL, deployment.alice.as_str())
        .with_header(headers::CAPABILITIES, "billing.charge"),
    );

    // server says: no
    assert_eq!(claim.status, 200);
    assert_eq!(allowed(&claim).as_deref(), Some("false"));
    assert_eq!(reason(&claim), "capability_not_granted");

    // ... and the route itself stays shut.
    let charge = transport.call(&Call::post("/billing/charge", "{}").with_session(&alice_session));
    assert_eq!(charge.status, 403);
}

/// An audit log that can be made to fail on demand.
struct ToggleAuditLog {
    inner: MemoryAuditLog,
    failing: AtomicBool,
}

impl ToggleAuditLog {
    fn new() -> Self {
        Self {
            inner: MemoryAuditLog::new(),
            failing: AtomicBool::new(false),
        }
    }

    fn fail(&self) {
        self.failing.store(true, Ordering::SeqCst);
    }
}

impl AuditLog for ToggleAuditLog {
    fn record_event(&self, tenant: &TenantContext, event: AuditEvent) -> Result<(), StorageError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(StorageError::new("audit log unavailable"));
        }
        self.inner.record_event(tenant, event)
    }
}

// 16. An authorization that cannot be recorded is not an authorization.
#[test]
fn an_unrecordable_decision_is_denied() {
    let audit = Arc::new(ToggleAuditLog::new());
    let deployment = bootstrap_with_stores(
        BindingMode::Embedded,
        Arc::new(TestClock::new(1_000)),
        MemoryStores::with_audit_log(audit.clone()),
    )
    .expect("the deployment builds while the audit log works");

    let server = Arc::new(appport_auth_mesh_server::AuthPortServer::new(
        deployment.runtime.clone(),
        Arc::new(saas_basic::app::router(deployment.invoices.clone())),
    ));
    let transport = EmbeddedTransport(server);
    let credential = alice(&transport);

    assert_eq!(
        transport
            .call(&Call::get("/invoices").with_session(&credential))
            .status,
        200
    );

    audit.fail();

    let after = transport.call(&Call::get("/invoices").with_session(&credential));
    assert_eq!(after.status, 403);
    assert_eq!(reason(&after), "audit_unavailable");
}

/// The standalone placement adds a hop, and the hop is not a way in.
#[test]
fn the_proxy_strips_client_supplied_context() {
    let standalone = standalone().expect("standalone builds");
    let transport = HttpTransport(standalone.address);

    // Straight at the application, with a fabricated context: refused, because
    // the signature is not AuthPort's.
    let direct = saas_basic::support::Call::get("/profile")
        .with_header(headers::PRINCIPAL, "prn_root")
        .with_header(headers::TENANT, "acme")
        .with_header(headers::CONTEXT, "{\"principal\": \"prn_root\"}")
        .with_header(headers::SIGNATURE, "not-a-signature");
    let response = transport.call(&direct);
    assert_eq!(response.status, 401);

    // Through AuthPort with a real session, the injected context is the one the
    // boundary derived — the client's version is dropped on the way in.
    let credential = alice(&transport);
    let profile = transport.call(
        &saas_basic::support::Call::get("/profile")
            .with_session(&credential)
            .with_header(headers::PRINCIPAL, "prn_root")
            .with_header(headers::TENANT, "globex"),
    );
    assert_eq!(profile.status, 200);
    assert_eq!(field(&profile, "tenant").as_deref(), Some("acme"));
    assert_eq!(
        field(&profile, "principal").as_deref(),
        Some(standalone.deployment.alice.as_str())
    );
}

/// The boundary is usable without HTTP at all: this is the interface a Node or
/// Python adapter would target.
#[test]
fn the_boundary_is_framework_neutral() {
    let deployment = bootstrap(BindingMode::Embedded).expect("deployment builds");
    let runtime = deployment.runtime.clone();

    let signed_in = runtime
        .sign_in(
            &BoundaryRequest::post("/auth/sign-in")
                .with_field("tenant", "acme")
                .with_field("connector", "local")
                .with_field("username", "alice")
                .with_field("password", "alice-secret"),
        )
        .expect("sign-in succeeds");

    let credential = match signed_in {
        appport_auth_mesh_boundary::SignInOutcome::Authenticated { credential, .. } => credential,
        _ => panic!("expected an authenticated outcome"),
    };

    let request =
        BoundaryRequest::new(BoundaryMethod::Get, "/invoices").with_credential(&credential);
    let context = runtime
        .authenticate(&request)
        .expect("the session resolves");

    assert_eq!(context.tenant.tenant_id.as_str(), "acme");
    assert_eq!(context.principal.id, deployment.alice);
    assert!(context.holds("invoice.create"));
    assert!(!context.holds("billing.charge"));
    assert!(runtime
        .authorize(&context, "billing.charge")
        .expect("the decision is made")
        .denial_reason()
        .is_some());
}
