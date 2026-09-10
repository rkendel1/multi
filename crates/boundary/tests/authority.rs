//! The invariants the boundary exists to hold.

use std::sync::Arc;

use appport_auth_mesh_authz::{
    Action, AuthorizationContext, Condition, DenialReason, Effect, Policy, ResourceAttributes,
    ResourceRef, ResourceResolver, ResourceSelector, Rule,
};
use appport_auth_mesh_boundary::{
    AuthBoundary, AuthPortRuntime, BindingMode, BoundaryRequest, MemoryMailPort, Method,
    RegistrationPolicy, Requirement, SessionCredential, SignInOutcome, TestClock,
    RESERVED_HEADER_PREFIX,
};
use appport_auth_mesh_contract::{Capability, ClaimValue, TenantContext};
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_providers::{AuthConnector, ConnectorRegistry, LocalAccount, LocalConnector};
use appport_auth_mesh_runtime::{MemoryStores, Registration};
use appport_auth_mesh_storage::TenantRootStore;

const DECLARATION: &str = r#"
use auth {
  providers = [local]
  tenant = true
  claims = {
    role = enum["owner", "member"]
  }
  agents = true
}
use mail
mail {
  identities { auth = "auth@example.com" }
  templates {
    password_reset = "./emails/password-reset.html"
    email_verification = "./emails/email-verification.html"
  }
}
"#;

const NOW: i64 = 1_000;

fn tenant(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.into(),
        namespace: id.to_string(),
        policy_id: format!("{}-policy", id).into(),
        storage_root_id: format!("{}-root", id).into(),
    }
}

fn stores() -> MemoryStores {
    let stores = MemoryStores::new();
    for name in ["acme", "globex"] {
        let context = tenant(name);
        stores.tenants.put_tenant(context.clone()).unwrap();
        stores
            .policies
            .put(Policy {
                id: context.policy_id.clone(),
                rules: vec![Rule::allow(
                    Capability("invoice.read".to_string()),
                    Condition::ClaimEquals {
                        key: "role".to_string(),
                        value: ClaimValue::Enum("owner".to_string()),
                    },
                )],
            })
            .unwrap();
    }
    stores
}

fn runtime(mode: BindingMode, stores: &MemoryStores) -> AuthPortRuntime {
    let config = parse_auth_block(DECLARATION).unwrap();
    let directory = LocalConnector::new()
        .with_account(LocalAccount::new("alice", "alice-secret"))
        .with_account(LocalAccount::new("mallory", "mallory-secret"));
    let registry = ConnectorRegistry::from_config_with(&config, vec![Arc::new(directory)]).unwrap();

    AuthPortRuntime::new(config, registry, stores.mesh_stores(), mode)
        .expect("the runtime builds")
        .with_clock(Arc::new(TestClock::new(NOW)))
}

fn sign_in_request(tenant: &str, username: &str, password: &str) -> BoundaryRequest {
    BoundaryRequest::post("/auth/sign-in")
        .with_field("tenant", tenant)
        .with_field("connector", "local")
        .with_field("username", username)
        .with_field("password", password)
}

fn issued(outcome: SignInOutcome) -> SessionCredential {
    match outcome {
        SignInOutcome::Authenticated { credential, .. } => credential,
        _ => panic!("expected an authenticated outcome"),
    }
}

fn seed_alice(runtime: &AuthPortRuntime, tenant: &str, role: &str) -> SessionCredential {
    let response = runtime
        .mesh()
        .sign_up(
            tenant,
            &connector_response(tenant, "alice", "alice-secret"),
            Registration::human().with_claim("role", role),
            NOW,
        )
        .expect("Alice is provisioned");
    SessionCredential::new(tenant, response.session.id)
}

struct InvoiceResolver;

impl ResourceResolver for InvoiceResolver {
    fn resolve(
        &self,
        resource: &ResourceRef,
        _context: &AuthorizationContext,
    ) -> ResourceAttributes {
        let tenant = if resource.resource_id == "globex-invoice" {
            "globex"
        } else {
            "acme"
        };
        ResourceAttributes::new().with_tenant(tenant)
    }
}

fn connector_response(
    tenant: &str,
    username: &str,
    password: &str,
) -> appport_auth_mesh_providers::AuthResponse {
    use appport_auth_mesh_providers::{AuthConnector, AuthRequest, AuthResponse};

    let challenge = LocalConnector::new()
        .begin(
            &AuthRequest::new("local")
                .for_tenant(tenant)
                .with_parameter("username", username),
        )
        .unwrap();
    AuthResponse::to_challenge(&challenge)
        .for_tenant(tenant)
        .with_parameter("username", username)
        .with_parameter("password", password)
}

/// An `AuthContext` has no public constructor: outside this crate the only way
/// to hold one is to have been given it by the runtime, after verification.
#[test]
fn a_context_exists_only_after_verification() {
    let stores = stores();
    let runtime = runtime(BindingMode::Embedded, &stores);
    let credential = seed_alice(&runtime, "acme", "owner");

    let context = runtime
        .authenticate(&BoundaryRequest::get("/invoices").with_credential(&credential))
        .expect("a real session resolves");
    assert_eq!(context.tenant.tenant_id.as_str(), "acme");
    assert!(context.holds("invoice.read"));

    // Anything else is refused.
    for forged in [
        "apt_acme.sess_0000",
        "apt_.sess_1",
        "sess_1",
        "apt_acme",
        "",
    ] {
        let request = BoundaryRequest::get("/invoices").with_cookie("authboundry_session", forged);
        assert!(
            runtime.authenticate(&request).is_err(),
            "`{forged}` must not authenticate"
        );
    }
}

#[test]
fn route_authorization_uses_resolved_resource_tenant() {
    let stores = stores();
    let acme = tenant("acme");
    stores
        .policies
        .put(Policy {
            id: acme.policy_id.clone(),
            rules: vec![Rule {
                capability: Capability("invoice.read".to_string()),
                condition: Condition::TenantCurrent,
                resource: Some(ResourceSelector::any("invoice")),
                action: Some(Action("read".to_string())),
                effect: Effect::Allow,
            }],
        })
        .unwrap();
    let runtime =
        runtime(BindingMode::Embedded, &stores).with_resource_resolver(Arc::new(InvoiceResolver));
    let credential = seed_alice(&runtime, "acme", "owner");

    let acme_invoice = BoundaryRequest::get("/invoices/acme-invoice").with_credential(&credential);
    let context = runtime
        .enforce(&acme_invoice, &Requirement::capability("invoice.read"))
        .expect("same-tenant resource is allowed")
        .expect("authorized requests receive context");
    assert!(context
        .decision
        .as_ref()
        .is_some_and(|decision| decision.is_allowed()));

    let globex_invoice =
        BoundaryRequest::get("/invoices/globex-invoice").with_credential(&credential);
    let denied = runtime
        .enforce(&globex_invoice, &Requirement::capability("invoice.read"))
        .expect_err("cross-tenant resource is denied");
    assert_eq!(denied.denial, DenialReason::TenantMismatch);
}

#[test]
fn a_session_credential_round_trips_and_rejects_nonsense() {
    let credential = SessionCredential::new("acme", "sess_abc".into());
    let encoded = credential.encode();
    assert_eq!(SessionCredential::parse(&encoded), Some(credential));

    for nonsense in ["", "apt_", "apt_acme", "acme.sess_abc", "apt_.x", "apt_x."] {
        assert_eq!(SessionCredential::parse(nonsense), None, "{nonsense}");
    }
}

#[test]
fn a_tenant_hint_must_agree_with_the_session() {
    let stores = stores();
    let runtime = runtime(BindingMode::Embedded, &stores);
    let credential = seed_alice(&runtime, "acme", "owner");

    let honest = BoundaryRequest::get("/invoices")
        .with_credential(&credential)
        .with_header("x-tenant-id", "acme");
    assert!(runtime.authenticate(&honest).is_ok());

    let crossed = BoundaryRequest::get("/invoices")
        .with_credential(&credential)
        .with_header("x-tenant-id", "globex");
    assert_eq!(
        runtime.authenticate(&crossed).unwrap_err().denial,
        DenialReason::TenantMismatch
    );

    // A session id re-addressed at another tenant is not that tenant's session.
    let smuggled = SessionCredential::new("globex", credential.session_id.clone());
    assert!(runtime
        .authenticate(&BoundaryRequest::get("/invoices").with_credential(&smuggled))
        .is_err());
}

#[test]
fn reserved_headers_never_reach_the_boundary() {
    let request = BoundaryRequest::get("/invoices")
        .with_header("x-authboundry-principal", "prn_root")
        .with_header("x-authboundry-capabilities", "billing.charge")
        .with_header("x-app-header", "kept")
        .sanitized();

    assert!(request
        .headers
        .keys()
        .all(|name| !name.starts_with(RESERVED_HEADER_PREFIX)));
    assert_eq!(request.header("x-app-header"), Some("kept"));
}

#[test]
fn a_public_route_neither_grants_nor_denies() {
    let stores = stores();
    let runtime = runtime(BindingMode::Embedded, &stores);
    let credential = seed_alice(&runtime, "acme", "owner");

    // A stale cookie on a public route is simply not a context.
    let stale =
        BoundaryRequest::get("/public").with_cookie("authboundry_session", "apt_acme.sess_x");
    assert!(runtime
        .enforce(&stale, &Requirement::Public)
        .expect("public routes do not deny")
        .is_none());

    // A live one is resolved, so handlers can personalise.
    let live = BoundaryRequest::get("/public").with_credential(&credential);
    assert!(runtime
        .enforce(&live, &Requirement::Public)
        .unwrap()
        .is_some());

    // Authenticated and capability requirements still refuse.
    assert!(runtime
        .enforce(&stale, &Requirement::Authenticated)
        .is_err());
    assert_eq!(
        runtime
            .enforce(&stale, &Requirement::capability("invoice.read"))
            .unwrap_err()
            .denial,
        DenialReason::InvalidSession
    );
}

#[test]
fn a_capability_requirement_is_decided_by_the_policy_engine() {
    let stores = stores();
    let runtime = runtime(BindingMode::Embedded, &stores);
    let credential = seed_alice(&runtime, "acme", "member");
    let request = BoundaryRequest::get("/invoices").with_credential(&credential);

    // `member` does not satisfy the rule, so the route stays shut.
    assert_eq!(
        runtime
            .enforce(&request, &Requirement::capability("invoice.read"))
            .unwrap_err()
            .denial,
        DenialReason::ConditionFailed
    );
    // ... and the session is still perfectly valid.
    assert!(runtime
        .enforce(&request, &Requirement::Authenticated)
        .is_ok());

    let context = runtime.authenticate(&request).unwrap();
    assert_eq!(
        runtime.authorize(&context, "").unwrap_err().denial,
        DenialReason::UnknownCapability
    );
    assert_eq!(
        runtime
            .authorize(&context, "nothing.declared")
            .unwrap()
            .denial_reason(),
        Some(DenialReason::CapabilityNotGranted)
    );
}

#[test]
fn registration_is_closed_unless_the_deployment_opens_it() {
    let stores = stores();
    let closed = runtime(BindingMode::Embedded, &stores);
    assert!(closed
        .sign_up(&sign_in_request("acme", "mallory", "mallory-secret"))
        .is_err());

    // Opened, the claims still come from the deployment — never the request.
    let open = runtime(BindingMode::Embedded, &stores)
        .with_registration(RegistrationPolicy::self_service(&[("role", "member")]));
    let outcome = open
        .sign_up(
            &sign_in_request("acme", "mallory", "mallory-secret")
                .with_field("role", "owner")
                .with_field("claims", "role=owner"),
        )
        .expect("self-service registration succeeds");

    let credential = issued(outcome);
    let context = open
        .authenticate(&BoundaryRequest::get("/invoices").with_credential(&credential))
        .unwrap();

    assert_eq!(
        context.claims.values.get("role"),
        Some(&ClaimValue::Enum("member".to_string()))
    );
    assert!(!context.holds("invoice.read"));
}

/// The invariant behind the whole PR: where the boundary runs changes nothing
/// about what it decides.
#[test]
fn embedded_and_standalone_decide_identically() {
    let stores = stores();
    let embedded = runtime(BindingMode::Embedded, &stores);
    let standalone = runtime(BindingMode::Standalone, &stores);
    assert_eq!(embedded.mode(), BindingMode::Embedded);
    assert_eq!(standalone.mode(), BindingMode::Standalone);

    // One contract, one surface, one registry.
    assert_eq!(embedded.contract(), standalone.contract());
    assert_eq!(embedded.surface(), standalone.surface());
    assert_eq!(
        embedded.surface().fingerprint(),
        standalone.surface().fingerprint()
    );

    let credential = seed_alice(&embedded, "acme", "owner");
    let request = BoundaryRequest::new(Method::Get, "/invoices").with_credential(&credential);

    for capability in ["invoice.read", "billing.charge"] {
        let from_embedded = embedded
            .authorize(&embedded.authenticate(&request).unwrap(), capability)
            .unwrap();
        let from_standalone = standalone
            .authorize(&standalone.authenticate(&request).unwrap(), capability)
            .unwrap();

        assert_eq!(
            from_embedded.is_allowed(),
            from_standalone.is_allowed(),
            "`{capability}` must be decided identically in both placements"
        );
        assert_eq!(
            from_embedded.denial_reason(),
            from_standalone.denial_reason()
        );
    }

    // A session opened in one placement is honoured by the other.
    let opened = issued(
        standalone
            .sign_in(&sign_in_request("acme", "alice", "alice-secret"))
            .expect("sign-in through the standalone runtime"),
    );
    assert!(embedded
        .authenticate(&BoundaryRequest::get("/invoices").with_credential(&opened))
        .is_ok());
}

#[test]
fn signing_in_requires_a_declared_connector_and_real_credentials() {
    let stores = stores();
    let runtime = runtime(BindingMode::Embedded, &stores);
    seed_alice(&runtime, "acme", "owner");

    assert_eq!(
        runtime
            .sign_in(&sign_in_request("acme", "alice", "wrong"))
            .unwrap_err()
            .denial,
        DenialReason::UnknownPrincipal
    );
    assert_eq!(
        runtime
            .sign_in(
                &BoundaryRequest::post("/auth/sign-in")
                    .with_field("tenant", "acme")
                    .with_field("connector", "google")
                    .with_field("username", "alice")
            )
            .unwrap_err()
            .denial,
        DenialReason::UnsupportedConnector
    );
    assert_eq!(
        runtime
            .sign_in(&BoundaryRequest::post("/auth/sign-in").with_field("connector", "local"))
            .unwrap_err()
            .denial,
        DenialReason::MissingCredential
    );
    assert_eq!(
        runtime
            .sign_in(&sign_in_request("nowhere", "alice", "alice-secret"))
            .unwrap_err()
            .denial,
        DenialReason::UnknownTenant
    );
}

#[test]
fn password_recovery_is_opaque_single_use_and_delivered_through_mailport() {
    let stores = stores();
    let config = parse_auth_block(DECLARATION).unwrap();
    let directory = Arc::new(LocalConnector::new().with_account(
        LocalAccount::new("alice", "alice-secret").with_attribute("email", "alice@example.com"),
    ));
    let connectors: Vec<Arc<dyn AuthConnector>> = vec![directory.clone()];
    let registry = ConnectorRegistry::from_config_with(&config, connectors).unwrap();
    let inbox = Arc::new(MemoryMailPort::default());
    let clock = Arc::new(TestClock::new(NOW));
    let runtime = AuthPortRuntime::new(
        config,
        registry,
        stores.mesh_stores(),
        BindingMode::Standalone,
    )
    .unwrap()
    .with_clock(clock.clone())
    .with_mail_port(inbox.clone());
    seed_alice(&runtime, "acme", "owner");

    let forgot = |username: &str| {
        BoundaryRequest::post("/auth/password/forgot")
            .with_field("tenant", "acme")
            .with_field("connector", "local")
            .with_field("username", username)
    };
    runtime.forgot_password(&forgot("nobody")).unwrap();
    assert!(inbox.messages().is_empty());
    runtime.forgot_password(&forgot("alice")).unwrap();
    let message = inbox
        .messages()
        .pop()
        .expect("MailPort receives reset mail");
    assert_eq!(message.template, "password_reset");
    assert_eq!(message.to, "alice@example.com");
    let token = message.variables.get("token").unwrap().clone();
    assert!(!token.contains("alice"));

    let reset = BoundaryRequest::post("/auth/password/reset")
        .with_field("token", &token)
        .with_field("new_password", "replacement-secret");
    runtime.reset_password(&reset).unwrap();
    assert!(
        runtime.reset_password(&reset).is_err(),
        "a challenge cannot be replayed"
    );
    assert!(runtime
        .sign_in(&sign_in_request("acme", "alice", "alice-secret"))
        .is_err());
    assert!(runtime
        .sign_in(&sign_in_request("acme", "alice", "replacement-secret"))
        .is_ok());

    runtime.forgot_password(&forgot("alice")).unwrap();
    let expired = inbox.messages().pop().unwrap().variables["token"].clone();
    clock.advance(901);
    assert!(runtime
        .reset_password(
            &BoundaryRequest::post("/auth/password/reset")
                .with_field("token", expired)
                .with_field("new_password", "another-replacement"),
        )
        .is_err());
}

#[test]
fn email_verification_uses_the_same_single_use_ceremony() {
    let stores = stores();
    let config = parse_auth_block(DECLARATION).unwrap();
    let directory = Arc::new(LocalConnector::new().with_account(
        LocalAccount::new("alice", "alice-secret").with_attribute("email", "alice@example.com"),
    ));
    let connectors: Vec<Arc<dyn AuthConnector>> = vec![directory.clone()];
    let registry = ConnectorRegistry::from_config_with(&config, connectors).unwrap();
    let inbox = Arc::new(MemoryMailPort::default());
    let runtime = AuthPortRuntime::new(
        config,
        registry,
        stores.mesh_stores(),
        BindingMode::Standalone,
    )
    .unwrap()
    .with_clock(Arc::new(TestClock::new(NOW)))
    .with_mail_port(inbox.clone());

    let request = BoundaryRequest::post("/auth/email/verification")
        .with_field("tenant", "acme")
        .with_field("connector", "local")
        .with_field("username", "alice");
    runtime.request_email_verification(&request).unwrap();
    let token = inbox.messages().pop().unwrap().variables["token"].clone();
    let verify = BoundaryRequest::post("/auth/email/verification").with_field("token", token);
    runtime.verify_email(&verify).unwrap();
    assert_eq!(
        directory
            .account_attribute("alice", "email_verified")
            .as_deref(),
        Some("true")
    );
    assert!(runtime.verify_email(&verify).is_err());
}
