//! The HTTP layer: it carries requests to the boundary and answers, and it
//! decides nothing on its own.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use appport_auth_mesh_authz::{
    Action, AuthorizationContext, AuthorizationRequest, CapabilityEnvelope, Condition,
    DenialReason, Policy, PrincipalAttribute, ResourceAttributes, ResourceRef, ResourceSelector,
    Rule,
};
use appport_auth_mesh_boundary::{
    AuthPortRuntime, AuthorityChange, BindingMode, BoundaryRequest, Method, Requirement,
    RESERVED_HEADER_PREFIX,
};
use appport_auth_mesh_contract::{
    AgentState, Capability, ClaimValue, Claims, ContractVersion, Principal, PrincipalId,
    PrincipalKind, TenantContext,
};
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_providers::ConnectorRegistry;
use appport_auth_mesh_runtime::{MemoryStores, RuntimeContext};
use appport_auth_mesh_server::http::{parse_flat_json, parse_form, HttpRequest, HttpResponse};
use appport_auth_mesh_server::{
    render_sign_in, status_for, AuthPortServer, PathPattern, RouteOutcome, RoutePolicy, RouterApp,
};
use appport_auth_mesh_storage::{PrincipalStore, TenantRootStore};
use appport_auth_mesh_surface::{AuthSurface, BoundarySurface};

fn request(method: Method, target: &str, headers: &[(&str, &str)], body: &str) -> HttpRequest {
    let headers = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_string()))
        .collect::<BTreeMap<_, _>>();
    HttpRequest::assemble(
        method,
        target.to_string(),
        headers,
        body.as_bytes().to_vec(),
    )
}

#[test]
fn requests_become_boundary_requests_without_their_reserved_headers() {
    let http = request(
        Method::Post,
        "/invoices?draft=true",
        &[
            ("content-type", "application/json"),
            ("cookie", "authport_session=apt_acme.sess_1; theme=dark"),
            ("x-authport-principal", "prn_root"),
            ("x-tenant-id", "acme"),
        ],
        "{\"reference\": \"INV-9\", \"amount\": 42, \"nested\": {\"ignored\": true}}",
    );

    let boundary: BoundaryRequest = http.to_boundary();

    assert_eq!(boundary.method, Method::Post);
    assert_eq!(boundary.path, "/invoices");
    assert_eq!(
        boundary.query.get("draft").map(String::as_str),
        Some("true")
    );
    assert_eq!(boundary.field("reference"), Some("INV-9"));
    assert_eq!(boundary.field("amount"), Some("42"));
    assert_eq!(boundary.tenant_hint(), Some("acme"));
    assert_eq!(
        boundary.credential().map(|credential| credential.tenant_id),
        Some("acme".to_string())
    );

    // The client's attempt to speak AuthPort's vocabulary is gone.
    assert!(boundary
        .headers
        .keys()
        .all(|name| !name.starts_with(RESERVED_HEADER_PREFIX)));
}

#[test]
fn bodies_parse_as_json_or_as_a_form() {
    assert_eq!(
        parse_form("tenant=acme&username=alice+b&password=p%40ss")
            .get("password")
            .map(String::as_str),
        Some("p@ss")
    );

    let json = parse_flat_json("{\"tenant\": \"acme\", \"count\": 3, \"ok\": true}");
    assert_eq!(json.get("tenant").map(String::as_str), Some("acme"));
    assert_eq!(json.get("count").map(String::as_str), Some("3"));
    assert_eq!(json.get("ok").map(String::as_str), Some("true"));

    // A form-encoded sign-in works the same as a JSON one.
    let form = request(
        Method::Post,
        "/auth/sign-in",
        &[("content-type", "application/x-www-form-urlencoded")],
        "tenant=acme&connector=local&username=alice&password=alice-secret",
    );
    assert_eq!(form.to_boundary().field("connector"), Some("local"));
}

#[test]
fn an_unlisted_path_is_refused_rather_than_forwarded() {
    let policy = RoutePolicy::new()
        .public(&[Method::Get], "/public")
        .capability(&[Method::Get], "/invoices", "invoice.read")
        .rule(
            &[Method::Get],
            PathPattern::Prefix("/reports/".to_string()),
            Requirement::Authenticated,
        );

    assert_eq!(
        policy.resolve(Method::Get, "/public"),
        RouteOutcome::Matched(Requirement::Public)
    );
    assert_eq!(
        policy.resolve(Method::Get, "/invoices"),
        RouteOutcome::Matched(Requirement::capability("invoice.read"))
    );
    assert_eq!(
        policy.resolve(Method::Get, "/reports/monthly"),
        RouteOutcome::Matched(Requirement::Authenticated)
    );

    // A method the rule does not cover is not a different route.
    assert_eq!(
        policy.resolve(Method::Post, "/invoices"),
        RouteOutcome::MethodNotAllowed
    );
    // Anything unlisted has no policy, and nothing unlisted is served.
    assert_eq!(
        policy.resolve(Method::Get, "/admin"),
        RouteOutcome::NoPolicy
    );
}

#[test]
fn denials_carry_a_status_and_a_reason() {
    assert_eq!(status_for(&DenialReason::MissingCredential), 401);
    assert_eq!(status_for(&DenialReason::ExpiredSession), 401);
    assert_eq!(status_for(&DenialReason::RevokedSession), 401);
    assert_eq!(status_for(&DenialReason::InvalidSession), 401);
    assert_eq!(status_for(&DenialReason::CapabilityNotGranted), 403);
    assert_eq!(status_for(&DenialReason::TenantMismatch), 403);
    assert_eq!(status_for(&DenialReason::AgentRevoked), 403);
    assert_eq!(status_for(&DenialReason::AuditUnavailable), 403);

    let denied = HttpResponse::denied(403, "capability_not_granted", "no");
    assert!(denied
        .body_string()
        .contains("\"reason\": \"capability_not_granted\""));

    let cookie = HttpResponse::json(200, "{}").with_session_cookie("apt_acme.sess_1");
    assert!(cookie
        .headers
        .iter()
        .any(|(name, value)| name == "set-cookie" && value.contains("HttpOnly")));

    let cleared = HttpResponse::json(200, "{}").clearing_session_cookie();
    assert!(cleared
        .headers
        .iter()
        .any(|(_, value)| value.contains("Max-Age=0")));
}

#[test]
fn control_plane_lists_shows_and_creates_agents() {
    let config =
        parse_auth_block("use auth { providers = [local] tenant = true agents = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let stores = MemoryStores::new();
    let tenant = TenantContext {
        tenant_id: "acme".into(),
        namespace: "acme".to_string(),
        policy_id: "acme-policy".into(),
        storage_root_id: "acme-root".into(),
    };
    stores.tenants.put_tenant(tenant.clone()).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            stores.mesh_stores(),
            BindingMode::Standalone,
        )
        .unwrap(),
    );
    stores
        .principals
        .put_principal(Principal::agent(
            PrincipalId("agent:invoice".to_string()),
            tenant.tenant_id.clone(),
            Claims {
                values: HashMap::new(),
            },
            ContractVersion { major: 1, minor: 0 },
            AgentState::Active,
        ))
        .unwrap();
    let server = AuthPortServer::new(runtime, Arc::new(NoApp));

    let listed = server.handle(&request(
        Method::Get,
        "/_authport/agents?tenant=acme",
        &[],
        "",
    ));
    assert_eq!(listed.status, 200);
    assert!(listed.body_string().contains("\"id\": \"agent:invoice\""));
    assert!(listed.body_string().contains("\"status\": \"active\""));

    let shown = server.handle(&request(
        Method::Get,
        "/_authport/agents/agent:invoice?tenant=acme",
        &[],
        "",
    ));
    assert_eq!(shown.status, 200);
    assert!(shown.body_string().contains("\"kind\": \"agent\""));

    let created = server.handle(&request(
        Method::Post,
        "/_authport/agents",
        &[("content-type", "application/json")],
        "{\"tenant\":\"acme\",\"name\":\"reports\",\"id\":\"agent:reports\"}",
    ));
    assert_eq!(created.status, 200);
    assert!(created.body_string().contains("\"id\": \"agent:reports\""));
}

#[test]
fn authorization_explain_endpoints_return_decision_evidence_by_id() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let stores = MemoryStores::new();
    let tenant = TenantContext {
        tenant_id: "acme".into(),
        namespace: "acme".to_string(),
        policy_id: "acme-policy".into(),
        storage_root_id: "acme-root".into(),
    };
    stores.tenants.put_tenant(tenant.clone()).unwrap();
    stores
        .policies
        .put(Policy {
            id: tenant.policy_id.clone(),
            rules: vec![Rule {
                capability: "invoice.update".into(),
                condition: Condition::All(vec![
                    Condition::TenantCurrent,
                    Condition::ClaimIn {
                        key: "role".to_string(),
                        values: vec![
                            ClaimValue::Enum("owner".to_string()),
                            ClaimValue::Enum("admin".to_string()),
                        ],
                    },
                    Condition::RelationshipEquals {
                        resource_attribute: "owner".to_string(),
                        principal: PrincipalAttribute::Id,
                    },
                ]),
                resource: Some(ResourceSelector::any("invoice")),
                action: Some(Action("update".to_string())),
                effect: appport_auth_mesh_authz::Effect::Allow,
            }],
        })
        .unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            stores.mesh_stores(),
            BindingMode::Standalone,
        )
        .unwrap(),
    );
    let mut claims = HashMap::new();
    claims.insert("role".to_string(), ClaimValue::Enum("admin".to_string()));
    let principal = Principal {
        id: PrincipalId("user:alice".to_string()),
        kind: PrincipalKind::Human,
        tenant_id: "acme".into(),
        claims: Claims {
            values: claims.clone(),
        },
        version: ContractVersion { major: 1, minor: 0 },
        agent_state: None,
    };
    let context = RuntimeContext {
        principal: principal.clone(),
        tenant: tenant.clone(),
        session_id: None,
        delegation: None,
        claims: Claims { values: claims },
        capabilities: CapabilityEnvelope::empty(),
    };
    let auth_request = AuthorizationRequest {
        principal: principal.id,
        tenant: tenant.tenant_id,
        capability: Capability("invoice.update".to_string()),
        action: Action("update".to_string()),
        resource: Some(ResourceRef::new("invoice", "8472", "acme")),
        context: AuthorizationContext::default(),
    };
    let attributes = ResourceAttributes::new()
        .with_tenant("acme")
        .with_value("owner", ClaimValue::String("user:bob".to_string()));
    let decision = runtime.mesh().authorize_request_with_authority_revision(
        &context,
        &auth_request,
        Some(&attributes),
        1234,
        runtime.live_authority().revision,
    );
    assert_eq!(
        decision.denial_reason(),
        Some(DenialReason::ConditionFailed)
    );

    let server = AuthPortServer::new(runtime, Arc::new(NoApp));
    let listed = server.handle(&request(
        Method::Get,
        "/_authport/authorization/decisions",
        &[],
        "",
    ));
    assert_eq!(listed.status, 200);
    let body = listed.body_string();
    assert!(body.contains("\"decision\": \"deny\""));
    assert!(body.contains("\"reason\": \"condition_failed\""));
    assert!(body.contains("\"condition\": \"resource.owner == principal.id\""));
    assert!(body.contains("\"result\": \"fail\""));
    assert!(body.contains("\"authority_revision\": 0"));
    assert!(body.contains("\"contract_fingerprint\""));
    let decision_id = json_string_field(&body, "decision_id").expect("decision id");

    let by_id = server.handle(&request(
        Method::Get,
        &format!("/_authport/authorization/decisions/{}", decision_id),
        &[],
        "",
    ));
    assert_eq!(by_id.status, 200);
    assert!(by_id
        .body_string()
        .contains("\"principal\": \"user:alice\""));

    let explained = server.handle(&request(
        Method::Get,
        &format!("/_authport/authorization/decisions/{}/explain", decision_id),
        &[],
        "",
    ));
    assert_eq!(explained.status, 200);
    assert!(explained.body_string().contains("\"summary\""));
}

#[test]
fn the_generated_ui_offers_only_connectors_that_work() {
    let surface = AuthSurface::derive(
        &parse_auth_block("use auth { providers = [local, google] tenant = true }").unwrap(),
    );

    let html = render_sign_in(&surface, &["acme".to_string(), "globex".to_string()]);

    // The one provider that can authenticate is offered...
    assert!(html.contains("<option value=\"local\">Local Directory</option>"));
    // ... the declared one is named honestly, not offered as a button.
    assert!(!html.contains("<option value=\"google\">"));
    assert!(html.contains("Google — declared, not configured"));

    // Tenancy is declared, so the form asks which tenant.
    assert!(html.contains("<select name=\"tenant\""));
    assert!(html.contains("<option value=\"acme\">"));

    // The page drives the same client library the JS package ships.
    assert!(html.contains("/authport/client.js"));
    assert!(html.contains("AuthPort.createAuthPort"));

    // A single-tenant contract does not ask the visitor to pick one.
    let single =
        AuthSurface::derive(&parse_auth_block("use auth { providers = [local] }").unwrap());
    let html = render_sign_in(&single, &["default".to_string()]);
    assert!(!html.contains("<select name=\"tenant\""));
    assert!(html.contains("name=\"tenant\" id=\"tenant\" value=\"default\""));
}

#[test]
fn the_session_cookie_is_the_one_the_contract_names() {
    assert_eq!(BoundarySurface::SESSION_COOKIE, "authport_session");

    let surface =
        AuthSurface::derive(&parse_auth_block("use auth { providers = [local] }").unwrap());
    assert_eq!(
        surface.boundary.session_credential,
        format!("cookie:{}", BoundarySurface::SESSION_COOKIE)
    );

    // Sign-in and login are one route, however a caller spells it.
    assert_eq!(
        surface.route("/auth/sign-in").map(|route| route.operation),
        surface.route("/auth/login").map(|route| route.operation)
    );
    assert_eq!(
        surface.route("/auth/sign-out").map(|route| route.operation),
        surface.route("/auth/logout").map(|route| route.operation)
    );
}

#[test]
fn control_plane_http_routes_store_apply_and_list_history() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Standalone,
        )
        .unwrap(),
    );
    let server = AuthPortServer::new(runtime, Arc::new(NoApp));

    let proposed = server.handle(&request(
        Method::Post,
        "/_authport/propose",
        &[("content-type", "application/json")],
        "{\"type\": \"protect_route\", \"method\": \"POST\", \"path\": \"/invoices\", \"capability\": \"invoice.create\"}",
    ));
    assert_eq!(proposed.status, 200);
    let body = proposed.body_string();
    let proposal_id = json_string_field(&body, "proposal_id").expect("proposal id");
    assert!(body.contains("\"route_protection\""));
    assert!(body.contains("\"approval_token\""));

    let listed = server.handle(&request(Method::Get, "/_authport/proposals", &[], ""));
    assert_eq!(listed.status, 200);
    assert!(listed.body_string().contains(&proposal_id));

    let approved = server.handle(&request(
        Method::Post,
        &format!("/_authport/authority-proposal/{}/approve", proposal_id),
        &[],
        "",
    ));
    assert_eq!(approved.status, 200);
    assert!(approved.body_string().contains("\"status\": \"approved\""));

    let applied = server.handle(&request(
        Method::Post,
        "/_authport/apply",
        &[("content-type", "application/json")],
        &format!("{{\"proposal_id\": \"{}\"}}", proposal_id),
    ));
    assert_eq!(applied.status, 200);
    let body = applied.body_string();
    assert!(body.contains("\"new_revision\": 1"));
    let change_id = json_string_field(&body, "applied_change_id").expect("change id");

    let history = server.handle(&request(Method::Get, "/_authport/history", &[], ""));
    assert_eq!(history.status, 200);
    assert!(history.body_string().contains(&change_id));
}

#[test]
fn control_plane_exposes_same_authority_proposal_without_applying_it() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Embedded,
        )
        .unwrap(),
    );
    let app = RouterApp::new()
        .public(
            Method::Get,
            "/health",
            Box::new(|_| HttpResponse::text(200, "ok")),
        )
        .public(
            Method::Post,
            "/invoices",
            Box::new(|_| HttpResponse::text(200, "created")),
        );
    let server = AuthPortServer::new(runtime.clone(), Arc::new(app));

    let proposed = server.handle(&request(
        Method::Get,
        "/_authport/authority-proposal",
        &[],
        "",
    ));

    assert_eq!(proposed.status, 200);
    let body = proposed.body_string();
    assert!(body.contains("\"contract_fingerprint\""));
    assert!(body.contains("\"live_revision\": 0"));
    assert!(body.contains("\"capability\": \"invoice.create\""));
    assert!(body.contains("\"action\": \"protect_route\""));
    assert!(
        runtime
            .get_route_protection(&Method::Post, "/invoices")
            .is_none(),
        "inference must not silently become authorization policy"
    );
}

#[test]
fn inferred_authority_proposals_can_be_rejected_or_approved_and_applied() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Embedded,
        )
        .unwrap(),
    );
    let app = RouterApp::new()
        .public(
            Method::Post,
            "/invoices",
            Box::new(|_| HttpResponse::text(200, "created")),
        )
        .public(
            Method::Post,
            "/billing/charge",
            Box::new(|_| HttpResponse::text(200, "charged")),
        );
    let server = AuthPortServer::new(runtime.clone(), Arc::new(app));

    let proposed = server.handle(&request(
        Method::Get,
        "/_authport/authority-proposal",
        &[],
        "",
    ));
    assert_eq!(proposed.status, 200);
    let body = proposed.body_string();
    assert!(body.contains("\"source\": \"inferred\""));
    assert!(body.contains("\"status\": \"recommended\""));
    assert!(body.contains("\"current_authority_state\": \"unprotected\""));
    assert!(body.contains("\"proposed_authority_state\": \"protected\""));
    assert!(body.contains("\"discovery_revision\""));
    let first_id = "proposal-1".to_string();

    let rejected = server.handle(&request(
        Method::Post,
        "/_authport/reject",
        &[("content-type", "application/json")],
        &format!(
            "{{\"proposal_id\": \"{}\", \"reason\": \"not this route\"}}",
            first_id
        ),
    ));
    assert_eq!(rejected.status, 200);

    let proposed_again = server.handle(&request(
        Method::Get,
        "/_authport/authority-proposal",
        &[],
        "",
    ));
    let body = proposed_again.body_string();
    assert!(body.contains("\"status\": \"rejected\""));

    let protected_id = "proposal-2".to_string();
    let approved = server.handle(&request(
        Method::Post,
        &format!("/_authport/authority-proposal/{}/approve", protected_id),
        &[],
        "",
    ));
    assert_eq!(approved.status, 200);
    let applied = server.handle(&request(
        Method::Post,
        &format!("/_authport/authority-proposal/{}/apply", protected_id),
        &[],
        "",
    ));
    assert_eq!(applied.status, 200);
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        Some("invoice.create".to_string())
    );

    let denied = server.handle(&request(Method::Post, "/invoices", &[], ""));
    assert_ne!(
        denied.status, 200,
        "live authority affects enforcement immediately"
    );
}

#[test]
fn approving_stale_proposals_returns_machine_readable_revision_error() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Standalone,
        )
        .unwrap(),
    );
    let server = AuthPortServer::new(runtime, Arc::new(NoApp));

    let stale = server.handle(&request(
        Method::Post,
        "/_authport/propose",
        &[("content-type", "application/json")],
        "{\"type\": \"protect_route\", \"method\": \"POST\", \"path\": \"/stale\", \"capability\": \"stale.write\"}",
    ));
    let stale_id = json_string_field(&stale.body_string(), "proposal_id").expect("stale id");

    let current = server.handle(&request(
        Method::Post,
        "/_authport/propose",
        &[("content-type", "application/json")],
        "{\"type\": \"protect_route\", \"method\": \"POST\", \"path\": \"/current\", \"capability\": \"current.write\"}",
    ));
    let current_id = json_string_field(&current.body_string(), "proposal_id").expect("current id");
    assert_eq!(
        server
            .handle(&request(
                Method::Post,
                &format!("/_authport/authority-proposal/{}/approve", current_id),
                &[],
                "",
            ))
            .status,
        200
    );
    assert_eq!(
        server
            .handle(&request(
                Method::Post,
                &format!("/_authport/authority-proposal/{}/apply", current_id),
                &[],
                "",
            ))
            .status,
        200
    );

    let stale_approval = server.handle(&request(
        Method::Post,
        &format!("/_authport/authority-proposal/{}/approve", stale_id),
        &[],
        "",
    ));
    assert_eq!(stale_approval.status, 400);
    let body = stale_approval.body_string();
    assert!(body.contains("\"error\": \"STALE_AUTHORITY_PROPOSAL\""));
    assert!(body.contains("\"current_authority_revision\": 1"));
}

#[test]
fn bulk_apply_adopts_compatible_approved_proposals_together() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Embedded,
        )
        .unwrap(),
    );
    let app = RouterApp::new()
        .public(
            Method::Post,
            "/invoices",
            Box::new(|_| HttpResponse::text(200, "created")),
        )
        .public(
            Method::Post,
            "/billing/charge",
            Box::new(|_| HttpResponse::text(200, "charged")),
        );
    let server = AuthPortServer::new(runtime.clone(), Arc::new(app));

    assert_eq!(
        server
            .handle(&request(
                Method::Get,
                "/_authport/authority-proposal",
                &[],
                "",
            ))
            .status,
        200
    );
    let approved = server.handle(&request(
        Method::Post,
        "/_authport/authority-proposals/approve",
        &[("content-type", "application/json")],
        "{\"proposal_ids\": [\"proposal-1\", \"proposal-2\"]}",
    ));
    assert_eq!(approved.status, 200);
    let applied = server.handle(&request(
        Method::Post,
        "/_authport/authority-proposals/apply",
        &[("content-type", "application/json")],
        "{\"proposal_ids\": [\"proposal-1\", \"proposal-2\"]}",
    ));
    assert_eq!(applied.status, 200);
    let body = applied.body_string();
    assert!(body.contains("\"new_revision\": 1"));
    assert!(body.contains("\"new_revision\": 2"));
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/billing/charge"),
        Some("billing.charge".to_string())
    );
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        Some("invoice.create".to_string())
    );
}

#[test]
fn control_plane_reconciliation_reports_drift_without_applying_authority() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Embedded,
        )
        .unwrap(),
    );
    let app = RouterApp::new().public(
        Method::Post,
        "/refunds",
        Box::new(|_| HttpResponse::text(200, "refunded")),
    );
    let server = AuthPortServer::new(runtime.clone(), Arc::new(app));

    let reconciled = server.handle(&request(
        Method::Post,
        "/_authport/authority-reconciliation/run",
        &[],
        "",
    ));
    assert_eq!(reconciled.status, 200);
    let body = reconciled.body_string();
    assert!(body.contains("\"new_routes\": 1"));
    assert!(body.contains("\"unsafe_automatic_changes\": 0"));
    assert!(body.contains("\"type\": \"new_route\""));
    assert!(body.contains("\"capability\": \"refund.create\""));
    assert!(body.contains("\"id\": \"proposal-1\""));
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/refunds"),
        None,
        "reconciliation must not silently grant authority"
    );

    let repeated = server.handle(&request(
        Method::Get,
        "/_authport/authority-reconciliation",
        &[],
        "",
    ));
    assert_eq!(repeated.status, 200);
    let repeated_body = repeated.body_string();
    assert!(repeated_body.contains("\"id\": \"proposal-1\""));
    assert!(!repeated_body.contains("\"id\": \"proposal-2\""));

    let drift = server.handle(&request(Method::Get, "/_authport/authority-drift", &[], ""));
    assert_eq!(drift.status, 200);
    assert!(drift.body_string().contains("\"type\": \"new_route\""));
}

#[test]
fn control_plane_reconciliation_reports_orphaned_authority() {
    let config = parse_auth_block("use auth { providers = [local] tenant = true }").unwrap();
    let registry = ConnectorRegistry::from_config(&config).unwrap();
    let runtime = Arc::new(
        AuthPortRuntime::new(
            config,
            registry,
            MemoryStores::new().mesh_stores(),
            BindingMode::Embedded,
        )
        .unwrap(),
    );
    let proposal = runtime
        .propose_change(AuthorityChange::ProtectRoute {
            method: Method::Post,
            path: "/billing/charge".to_string(),
            capability: "billing.charge".to_string(),
        })
        .expect("proposal");
    let approval = appport_auth_mesh_boundary::Approval::for_proposal(&proposal);
    runtime.apply_change(proposal, approval).expect("apply");
    let app = RouterApp::new().public(
        Method::Post,
        "/refunds",
        Box::new(|_| HttpResponse::text(200, "refunded")),
    );
    let server = AuthPortServer::new(runtime.clone(), Arc::new(app));

    let drift = server.handle(&request(Method::Get, "/_authport/authority-drift", &[], ""));
    assert_eq!(drift.status, 200);
    let body = drift.body_string();
    assert!(body.contains("\"type\": \"orphaned_authority\""));
    assert!(body.contains("POST /billing/charge"));
    assert!(body.contains("retained:billing.charge"));
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/billing/charge"),
        Some("billing.charge".to_string()),
        "historical authority must be retained"
    );
}

struct NoApp;

impl appport_auth_mesh_server::ApplicationBinding for NoApp {
    fn resolve(&self, _method: Method, _path: &str) -> RouteOutcome {
        RouteOutcome::NotFound
    }

    fn handle(
        &self,
        _request: &BoundaryRequest,
        _context: Option<&appport_auth_mesh_boundary::AuthContext>,
    ) -> HttpResponse {
        HttpResponse::denied(404, "no_application", "no application")
    }
}

fn json_string_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    let rest = json
        .get(json.find(&pattern)? + pattern.len()..)?
        .trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
