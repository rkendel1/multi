//! The HTTP layer: it carries requests to the boundary and answers, and it
//! decides nothing on its own.

use std::collections::BTreeMap;
use std::sync::Arc;

use appport_auth_mesh_authz::DenialReason;
use appport_auth_mesh_boundary::{
    AuthPortRuntime, BindingMode, BoundaryRequest, Method, Requirement, RESERVED_HEADER_PREFIX,
};
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_providers::ConnectorRegistry;
use appport_auth_mesh_runtime::MemoryStores;
use appport_auth_mesh_server::http::{parse_flat_json, parse_form, HttpRequest, HttpResponse};
use appport_auth_mesh_server::{
    render_sign_in, status_for, AuthPortServer, PathPattern, RouteOutcome, RoutePolicy,
};
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
